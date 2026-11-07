use crate::parser;
use crate::{Document, Error, Object, ObjectId, Result, Stream};
use std::collections::BTreeMap;
use std::num::TryFromIntError;
use std::str::FromStr;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// With the `rayon` feature, an object stream with fewer members is parsed on
/// the calling thread unless that thread is one of rayon's workers. Outside
/// the pool, handing a small stream to it costs more than it saves, as for a
/// small document in `Reader`. Inside, splitting is cheap and lets idle
/// workers share a stream that the rest of a parallel load waits for.
#[cfg(feature = "rayon")]
const MIN_PARALLEL_OBJECTS: usize = 32;

#[derive(Debug)]
pub struct ObjectStream {
    pub objects: BTreeMap<ObjectId, Object>,
    max_objects: usize,
    compression_level: u32,
}

#[derive(Debug, Clone)]
pub struct ObjectStreamBuilder {
    max_objects: usize,
    compression_level: u32,
}

#[derive(Debug, Clone)]
pub struct ObjectStreamConfig {
    pub max_objects_per_stream: usize,
    pub compression_level: u32,
}

impl Default for ObjectStreamConfig {
    fn default() -> Self {
        Self {
            max_objects_per_stream: 100,
            compression_level: 6,
        }
    }
}

impl ObjectStream {
    /// Parse an existing object stream without modifying its encoded content or
    /// filter dictionary.
    ///
    /// This decodes the stream without any size limit. For untrusted input,
    /// prefer [`ObjectStream::new_with_limit`] to guard against decompression
    /// bombs.
    pub fn new(stream: &Stream) -> Result<ObjectStream> {
        Self::new_with_limit(stream, None)
    }

    /// Parse an existing object stream without modifying it, rejecting the
    /// decoded content if it would exceed `max_decompressed_size` bytes. `None`
    /// means no limit (the behavior of [`ObjectStream::new`]).
    ///
    /// # Errors
    ///
    /// Returns a decompression error when decoding fails or exceeds the limit.
    /// Rejects invalid `/N`, `/First`, header counts, and non-increasing or
    /// out-of-bounds member offsets before allocating headers or member objects.
    pub fn new_with_limit(stream: &Stream, max_decompressed_size: Option<usize>) -> Result<ObjectStream> {
        Self::declared_count(stream)?;
        let content = match max_decompressed_size {
            Some(max) => stream.get_plain_content_with_limit(max)?,
            None => stream.get_plain_content()?,
        };
        Self::from_content(stream, &content, true, None)
    }

    pub(crate) fn declared_count(stream: &Stream) -> Result<usize> {
        usize::try_from(stream.dict.get(b"N")?.as_i64()?)
            .map_err(|e| Error::NumericCast(e.to_string()))
    }

    pub(crate) fn from_content(
        stream: &Stream, content: &[u8], allow_parallel: bool, reader: Option<&crate::Reader<'_>>,
    ) -> Result<ObjectStream> {
        let count = Self::declared_count(stream)?;
        let first_offset: usize = stream
            .dict
            .get(b"First")
            .and_then(Object::as_i64)?
            .try_into()
            .map_err(|e: TryFromIntError| Error::NumericCast(e.to_string()))?;
        let index_block = content.get(..first_offset).ok_or(Error::InvalidOffset(first_offset))?;
        // Each header pair needs at least two digits and separating whitespace.
        // Validate /N before allocating any header storage.
        if count > index_block.len() / 3 {
            return Err(Error::InvalidObjectStream("object count exceeds header length".into()));
        }
        let numbers_str = std::str::from_utf8(index_block)
            .map_err(|e| Error::InvalidObjectStream(e.to_string()))?;
        let parse_header = |numbers: &mut std::str::SplitWhitespace<'_>| -> Result<(u32, usize)> {
            let id = numbers.next().and_then(|n| u32::from_str(n).ok())
                .ok_or_else(|| Error::InvalidObjectStream("invalid object number".into()))?;
            let relative = numbers.next().and_then(|n| usize::from_str(n).ok())
                .ok_or_else(|| Error::InvalidObjectStream("invalid object offset".into()))?;
            let offset = first_offset.checked_add(relative).ok_or(Error::InvalidOffset(relative))?;
            Ok((id, offset))
        };
        // Validate every span in a first, allocation-free pass. Even malformed
        // headers cannot request a large vector before their offsets are checked.
        let mut numbers = numbers_str.split_whitespace();
        let mut previous = None;
        for _ in 0..count {
            let (_, offset) = parse_header(&mut numbers)?;
            if offset >= content.len() || previous.is_some_and(|previous| previous >= offset) {
                return Err(Error::InvalidOffset(offset));
            }
            previous = Some(offset);
        }
        if numbers.next().is_some() {
            return Err(Error::InvalidObjectStream("object count does not match header".into()));
        }
        let mut numbers = numbers_str.split_whitespace();
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push(parse_header(&mut numbers)?);
        }

        let parse_member = |index: usize| -> Result<Option<(ObjectId, Object)>> {
            let (id, start) = headers[index];
            let end = headers.get(index + 1).map_or(content.len(), |&(_, offset)| offset);
            let member = &content[start..end];
            let Some(start) = member.iter().position(|byte| !byte.is_ascii_whitespace()) else {
                return Ok(None);
            };
            let object = if let Some(reader) = reader {
                match reader.parse_direct_object(&member[start..]) {
                    Ok((_, object)) => Some(object),
                    Err(_) => {
                        reader.check_limits()?;
                        None
                    }
                }
            } else {
                parser::direct_object(&member[start..])
            };
            Ok(object.map(|object| ((id, 0), object)))
        };
        #[cfg(feature = "rayon")]
        let objects: Result<BTreeMap<_, _>> = if allow_parallel && (count >= MIN_PARALLEL_OBJECTS || rayon::current_thread_index().is_some()) {
            (0..count).into_par_iter().map(parse_member).filter_map(Result::transpose).collect()
        } else {
            (0..count).map(parse_member).filter_map(Result::transpose).collect()
        };
        #[cfg(not(feature = "rayon"))]
        let _ = allow_parallel;
        #[cfg(not(feature = "rayon"))]
        let objects: Result<BTreeMap<_, _>> = (0..count).map(parse_member).filter_map(Result::transpose).collect();

        Ok(ObjectStream {
            objects: objects?,
            max_objects: 100,
            compression_level: 6,
        })
    }

    /// Create a builder for constructing new object streams
    pub fn builder() -> ObjectStreamBuilder {
        ObjectStreamBuilder {
            max_objects: 100,
            compression_level: 6,
        }
    }

    /// Add an object to the stream
    pub fn add_object(&mut self, id: ObjectId, obj: Object) -> Result<()> {
        // Check if object can be added to stream
        if matches!(obj, Object::Stream(_)) {
            return Err(Error::InvalidObjectStream(
                "Stream objects cannot be stored in object streams".into(),
            ));
        }

        // Check capacity
        if self.objects.len() >= self.max_objects {
            return Err(Error::InvalidObjectStream(format!(
                "Object stream has reached maximum capacity of {} objects",
                self.max_objects
            )));
        }

        self.objects.insert(id, obj);
        Ok(())
    }

    /// Get the number of objects in the stream
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// The members in id order, each paired with its serialization: an object
    /// stream stores them sorted, and both the offset table and the body walk
    /// them in that order. The order comes from [`Self::sorted_object_ids`], so
    /// the body and the cross-reference indices cannot drift apart.
    fn sorted_serializations(&self) -> Result<Vec<(ObjectId, Vec<u8>)>> {
        self.sorted_object_ids()
            .into_iter()
            .map(|id| {
                let mut bytes = Vec::new();
                crate::writer::Writer::write_object(&mut bytes, &self.objects[&id])?;
                Ok((id, bytes))
            })
            .collect()
    }

    /// The contained object ids in the order [`Self::build_stream_content`]
    /// writes them, so a caller recording cross-reference entries can assign
    /// each object the index it actually occupies in the stream. This is the
    /// single source of that order.
    pub(crate) fn sorted_object_ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self.objects.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The `N M N M ...` header of object numbers and their offsets from the
    /// start of the body, which the `/First` entry records the length of.
    fn offset_table(members: &[(ObjectId, Vec<u8>)]) -> String {
        let mut entries = Vec::with_capacity(members.len());
        let mut current_offset = 0;

        for ((obj_num, _gen), bytes) in members {
            entries.push(format!("{obj_num} {current_offset}"));
            // +1 for the space separator written after each object
            current_offset += bytes.len() + 1;
        }

        // Joined with spaces and a trailing space, so the body starts on a
        // fresh token.
        entries.join(" ") + " "
    }

    /// Build the stream content in the format required by PDF spec
    pub fn build_stream_content(&self) -> Result<Vec<u8>> {
        self.build_body().map(|(content, _)| content)
    }

    /// The object stream body — the offset table followed by the serialized
    /// objects — together with the `/First` offset, which is where the table
    /// ends. Both are needed to build the stream, so they are produced together
    /// rather than by serializing the members twice.
    fn build_body(&self) -> Result<(Vec<u8>, usize)> {
        if self.objects.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let members = self.sorted_serializations()?;
        let table = Self::offset_table(&members);
        let first_offset = table.len();

        let mut content = Vec::new();
        content.extend_from_slice(table.as_bytes());

        for (_, bytes) in &members {
            content.extend_from_slice(bytes);
            content.push(b' '); // Space separator between objects
        }

        Ok((content, first_offset))
    }

    /// Convert to a Stream object ready for insertion into a PDF
    pub fn to_stream_object(&self) -> Result<Stream> {
        let (content, first_offset) = self.build_body()?;

        let dict = dictionary! {
            "Type" => "ObjStm",
            "N" => self.objects.len() as i64,
            "First" => first_offset as i64,
        };

        let mut stream = Stream::new(dict, content);

        // Apply compression - object streams should always be compressed
        if self.compression_level > 0 {
            let compressed = crate::object::zlib_compress(&stream.content, self.compression_level)?;
            stream.dict.set("Filter", "FlateDecode");
            stream.set_content(compressed);
        }

        Ok(stream)
    }

    /// Check if an object can be compressed into an object stream
    pub fn can_be_compressed(id: ObjectId, obj: &Object, doc: &Document) -> bool {
        // Rule 1: Stream objects cannot be compressed
        if matches!(obj, Object::Stream(_)) {
            return false;
        }

        // Rule 2: Objects with non-zero generation cannot be compressed
        if id.1 != 0 {
            return false;
        }

        // Rule 3: Only encryption dictionary cannot be compressed from trailer references
        if let Ok(Object::Reference(encrypt_ref)) = doc.trailer.get(b"Encrypt")
            && id == *encrypt_ref
        {
            return false;
        }

        // Rule 4: Specific object types that cannot be compressed
        if let Object::Dictionary(dict) = obj
            && let Ok(type_obj) = dict.get(b"Type")
            && let Ok(type_name) = type_obj.as_name()
        {
            match type_name {
                // Cross-reference streams and object streams cannot be compressed
                b"XRef" => return false,
                b"ObjStm" => return false,

                // Catalog can only be excluded in linearized PDFs
                b"Catalog" if Self::is_linearized(doc) => {
                    return false;
                }
                b"Catalog" => {}

                // Page, Pages, and all other types CAN be compressed
                _ => {}
            }
        }

        // Default: Allow compression
        true
    }

    /// Check if a PDF document is linearized
    fn is_linearized(doc: &Document) -> bool {
        // In a linearized PDF the first object is a linearization dictionary; we just look for
        // any object with a /Linearized entry.
        for obj in doc.objects.values() {
            if let Object::Dictionary(dict) = obj
                && dict.has(b"Linearized")
            {
                return true;
            }
        }
        false
    }
}

impl ObjectStreamBuilder {
    /// Set the maximum number of objects per stream
    pub fn max_objects(mut self, max: usize) -> Self {
        self.max_objects = max;
        self
    }

    /// Set the compression level (0-9)
    pub fn compression_level(mut self, level: u32) -> Self {
        self.compression_level = level;
        self
    }

    /// Build the ObjectStream
    pub fn build(self) -> ObjectStream {
        ObjectStream {
            objects: BTreeMap::new(),
            max_objects: self.max_objects,
            compression_level: self.compression_level,
        }
    }

    /// Get the current max_objects setting
    pub fn get_max_objects(&self) -> usize {
        self.max_objects
    }

    /// Get the current compression_level setting
    pub fn get_compression_level(&self) -> u32 {
        self.compression_level
    }
}
