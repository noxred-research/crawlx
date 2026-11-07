//! OCR of the pages of a PDF: finding the images a page draws, decoding them, and placing the
//! recognised paragraphs back in PDF user space.

use std::borrow::Cow;

use image::{DynamicImage, GrayImage, RgbImage};
use lopdf::content::Content;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use super::{image_io, Ocr, OcrPage, PdfRaster};
use crate::parse::pdf::{mul, Matrix, IDENTITY};

/// Deepest nesting of form XObjects followed.
const MAX_FORM_DEPTH: u8 = 4;
/// Most `Do` operators examined on one page.
const MAX_DO: u32 = 4_096;
/// Most images OCR'd on one page.
const MAX_IMAGES: usize = 32;
/// Images smaller than this are decoration, not scans.
const MIN_WIDTH: i64 = 32;
const MIN_HEIGHT: i64 = 16;

/// How a PDF asks for OCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PdfOcr {
    /// Text layer only.
    #[default]
    Off,
    /// OCR pages that have no text layer.
    Auto,
    /// OCR every page.
    Always,
}

/// A recognised paragraph in PDF user space.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlacedPara {
    pub text: String,
    /// `[x0, bottom, x1, top]`.
    pub bbox: [f32; 4],
    pub confidence: Option<f64>,
}

/// What OCR made of one page.
#[derive(Debug, Default)]
pub(crate) struct PageOutcome {
    pub paragraphs: Vec<PlacedPara>,
    pub warnings: Vec<String>,
    /// The paragraphs read a whole rendered page, so they replace the page's text layer.
    pub replaces_text: bool,
}

/// The OCR state of one document: the engine, the PDF and a lazily written copy for `pdftoppm`.
pub(crate) struct Session<'a> {
    ocr: &'a Ocr,
    doc: &'a Document,
    bytes: &'a [u8],
    raster: Option<Option<PdfRaster>>,
    /// Bytes of decompressed image data still allowed.
    budget: usize,
    pages_done: u32,
}

impl<'a> Session<'a> {
    pub(crate) fn new(ocr: &'a Ocr, doc: &'a Document, bytes: &'a [u8], budget: usize) -> Self {
        Self {
            ocr,
            doc,
            bytes,
            raster: None,
            budget,
            pages_done: 0,
        }
    }

    fn raster(&mut self) -> Result<Option<&PdfRaster>, super::OcrError> {
        if self.raster.is_none() {
            self.raster = Some(PdfRaster::new(self.ocr, self.bytes)?);
        }
        Ok(self.raster.as_ref().and_then(Option::as_ref))
    }

    /// OCR page `number` (`id`). `has_text`: the page has a text layer, which a page in
    /// [`PdfOcr::Always`] mode keeps when only embedded images can be read.
    pub(crate) fn page(&mut self, number: u32, id: ObjectId, mode: PdfOcr, has_text: bool) -> PageOutcome {
        let mut out = PageOutcome::default();
        if self.pages_done >= self.ocr.config.max_pdf_pages {
            if self.pages_done == self.ocr.config.max_pdf_pages {
                self.pages_done += 1;
                out.warnings.push(format!(
                    "OCR stopped before page {number}: ocr.maxPdfPages is {}",
                    self.ocr.config.max_pdf_pages
                ));
            }
            return out;
        }
        self.pages_done += 1;
        let rotation = page_rotation(self.doc, id);
        let size = page_box(self.doc, id);
        // `always` reads the whole rendered page when it can: vector text next to a scan is
        // then not lost; without a renderer the embedded images are all there is
        let render_first = mode == PdfOcr::Always && matches!(self.raster(), Ok(Some(_)));
        if !render_first {
            let images = self.images(id, rotation, &mut out.warnings);
            if !images.is_empty() {
                let mut found = false;
                for img in images {
                    match self.ocr.recognize(&img.pixels, img.dpi) {
                        Ok(page) => {
                            found = true;
                            place(&page, &img.map, &mut out.paragraphs);
                        }
                        Err(e) => out.warnings.push(format!("page {number}: OCR failed: {e}")),
                    }
                }
                if found {
                    return out;
                }
            }
        }
        // no usable image (or a page rendered on request): render the page
        let raster = match self.raster() {
            Ok(r) => r.map(|r| r.render(number, size.map(|s| (s.2 - s.0, s.3 - s.1)))),
            Err(e) => Some(Err(e)),
        };
        match raster {
            Some(Ok(img)) => match self.ocr.recognize(&img, Some(self.ocr.config.dpi)) {
                Ok(page) => {
                    let (x0, y0, x1, y1) = size.unwrap_or((0.0, 0.0, 612.0, 792.0));
                    let map = Mapping {
                        ctm: [x1 - x0, 0.0, 0.0, y1 - y0, x0, y0],
                        quarters: rotation,
                    };
                    place(&page, &map, &mut out.paragraphs);
                    out.replaces_text = true;
                }
                Err(e) => out.warnings.push(format!("page {number}: OCR failed: {e}")),
            },
            Some(Err(e)) => out
                .warnings
                .push(format!("page {number}: rendering for OCR failed: {e}")),
            None => {
                if out.warnings.is_empty() && !has_text {
                    out.warnings.push(format!(
                        "page {number}: no image to OCR and no rasteriser (install poppler-utils for pdftoppm)"
                    ));
                }
            }
        }
        out
    }

    /// The decoded images of a page, drawn order sorted top to bottom, rotated upright.
    fn images(&mut self, page: ObjectId, rotation: u8, warnings: &mut Vec<String>) -> Vec<Pixels> {
        let mut found: Vec<Found<'a>> = Vec::new();
        let doc = self.doc;
        let mut walk = Walk {
            doc,
            found: &mut found,
            budget: &mut self.budget,
            dos: 0,
        };
        if let Ok(content) = doc.get_page_content_with_limit(page, walk.budget_left()) {
            walk.content(&content, page_resources(doc, page), IDENTITY, 0);
        }
        found.sort_by(|a, b| {
            top(&b.ctm)
                .total_cmp(&top(&a.ctm))
                .then(a.ctm[4].total_cmp(&b.ctm[4]))
        });
        let mut out = Vec::new();
        for f in found.into_iter().take(MAX_IMAGES) {
            match decode_image(doc, f.stream, self.ocr.config.max_image_pixels, &mut self.budget) {
                Ok(pixels) => {
                    let quarters = (rotation + 4 - ctm_quarters(&f.ctm)) % 4;
                    // inches along the image's own x axis: its resolution
                    let inches = f.ctm[0].hypot(f.ctm[1]) / 72.0;
                    let dpi = (inches > 0.0).then(|| {
                        let d = (pixels.width() as f32 / inches).round().clamp(70.0, 600.0);
                        // clamped to 70..=600 above
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        {
                            d as u32
                        }
                    });
                    out.push(Pixels {
                        pixels: image_io::rotate_cw(pixels, quarters),
                        dpi,
                        map: Mapping { ctm: f.ctm, quarters },
                    });
                }
                Err(reason) => {
                    warnings.push(format!("an image on the page cannot be read for OCR: {reason}"))
                }
            }
        }
        out
    }
}

/// A decoded image with the placement that maps its pixels to user space.
struct Pixels {
    pixels: DynamicImage,
    dpi: Option<u32>,
    map: Mapping,
}

/// Pixels of an image that was turned `quarters` quarter turns clockwise, placed by `ctm`.
struct Mapping {
    ctm: Matrix,
    quarters: u8,
}

impl Mapping {
    /// User-space point of the normalised pixel position `(s, t)` (origin top left) of the
    /// recognised image.
    fn point(&self, s: f32, t: f32) -> (f32, f32) {
        // position in the unturned image's unit square (u right, v up)
        let (u, v) = match self.quarters % 4 {
            0 => (s, 1.0 - t),
            1 => (t, s),
            2 => (1.0 - s, t),
            _ => (1.0 - t, 1.0 - s),
        };
        let c = &self.ctm;
        (u * c[0] + v * c[2] + c[4], u * c[1] + v * c[3] + c[5])
    }
}

fn place(page: &OcrPage, map: &Mapping, out: &mut Vec<PlacedPara>) {
    let (w, h) = (page.width.max(1) as f32, page.height.max(1) as f32);
    for p in &page.paragraphs {
        let corners = [
            (p.bbox[0], p.bbox[1]),
            (p.bbox[2], p.bbox[1]),
            (p.bbox[0], p.bbox[3]),
            (p.bbox[2], p.bbox[3]),
        ]
        .map(|(x, y)| map.point((x as f32 / w).clamp(0.0, 1.0), (y as f32 / h).clamp(0.0, 1.0)));
        let xs = corners.map(|c| c.0);
        let ys = corners.map(|c| c.1);
        out.push(PlacedPara {
            text: p.text.clone(),
            bbox: [
                xs.iter().copied().fold(f32::INFINITY, f32::min),
                ys.iter().copied().fold(f32::INFINITY, f32::min),
                xs.iter().copied().fold(f32::NEG_INFINITY, f32::max),
                ys.iter().copied().fold(f32::NEG_INFINITY, f32::max),
            ],
            confidence: p.confidence,
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Page geometry
// ---------------------------------------------------------------------------------------------

/// Highest user-space y of an image placed by `m` (its unit square's corners).
fn top(m: &Matrix) -> f32 {
    m[5].max(m[3] + m[5]).max(m[1] + m[5]).max(m[1] + m[3] + m[5])
}

/// Quarter turns counter-clockwise (0..4) of an image's "up" edge in user space.
fn ctm_quarters(m: &Matrix) -> u8 {
    // the up edge of the unit square maps to (c, d)
    let (c, d) = (m[2], m[3]);
    if d.abs() >= c.abs() {
        if d >= 0.0 {
            0
        } else {
            2
        }
    } else if c < 0.0 {
        1
    } else {
        3
    }
}

/// `/Rotate` of a page (inherited), in quarter turns clockwise.
fn page_rotation(doc: &Document, page: ObjectId) -> u8 {
    let mut id = page;
    for _ in 0..16 {
        let Ok(dict) = doc.get_dictionary(id) else {
            return 0;
        };
        if let Ok(r) = dict.get_deref(b"Rotate", doc).and_then(Object::as_i64) {
            return u8::try_from((r / 90).rem_euclid(4)).unwrap_or(0);
        }
        match dict.get(b"Parent").and_then(Object::as_reference) {
            Ok(p) => id = p,
            Err(_) => return 0,
        }
    }
    0
}

/// `MediaBox` of a page (inherited) as `(x0, y0, x1, y1)`.
fn page_box(doc: &Document, page: ObjectId) -> Option<(f32, f32, f32, f32)> {
    let mut id = page;
    for _ in 0..16 {
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(obj) = dict.get_deref(b"MediaBox", doc) {
            let arr = obj.as_array().ok()?;
            let n: Vec<f32> = arr
                .iter()
                .filter_map(|o| doc.dereference(o).ok().and_then(|(_, o)| o.as_float().ok()))
                .collect();
            if let [a, b, c, d] = n[..] {
                let (x0, x1) = (a.min(c), a.max(c));
                let (y0, y1) = (b.min(d), b.max(d));
                return (x1 > x0 && y1 > y0).then_some((x0, y0, x1, y1));
            }
            return None;
        }
        id = dict.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

fn page_resources(doc: &Document, page: ObjectId) -> Option<&Dictionary> {
    let mut id = page;
    for _ in 0..16 {
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(obj) = dict.get_deref(b"Resources", doc) {
            return obj.as_dict().ok();
        }
        id = dict.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Finding the images of a page
// ---------------------------------------------------------------------------------------------

struct Found<'a> {
    ctm: Matrix,
    stream: &'a Stream,
}

struct Walk<'a, 'f> {
    doc: &'a Document,
    found: &'f mut Vec<Found<'a>>,
    budget: &'f mut usize,
    dos: u32,
}

impl<'a> Walk<'a, '_> {
    fn budget_left(&self) -> usize {
        *self.budget
    }

    /// Follow `Do` operators of a content stream, tracking the current transformation matrix.
    fn content(&mut self, bytes: &[u8], resources: Option<&'a Dictionary>, start: Matrix, depth: u8) {
        let Ok(content) = Content::decode(bytes) else {
            return;
        };
        let xobjects = resources.and_then(|r| r.get_deref(b"XObject", self.doc).ok()?.as_dict().ok());
        let mut ctm = start;
        let mut stack: Vec<Matrix> = Vec::new();
        for op in &content.operations {
            match op.operator.as_str() {
                "q" => {
                    if stack.len() < 64 {
                        stack.push(ctm);
                    }
                }
                "Q" => {
                    if let Some(m) = stack.pop() {
                        ctm = m;
                    }
                }
                "cm" if op.operands.len() == 6 => {
                    let mut m = [0.0f32; 6];
                    for (slot, o) in m.iter_mut().zip(&op.operands) {
                        *slot = o.as_float().ok().filter(|v| v.is_finite()).unwrap_or(0.0);
                    }
                    ctm = mul(&m, &ctm);
                }
                "Do" => {
                    self.dos += 1;
                    if self.dos > MAX_DO {
                        return;
                    }
                    let Some(name) = op.operands.first().and_then(|o| o.as_name().ok()) else {
                        continue;
                    };
                    let Some(stream) = xobjects.and_then(|x| {
                        let id = x.get(name).ok()?.as_reference().ok()?;
                        self.doc.get_object(id).ok()?.as_stream().ok()
                    }) else {
                        continue;
                    };
                    self.xobject(stream, resources, ctm, depth);
                }
                _ => {}
            }
        }
    }

    fn xobject(&mut self, stream: &'a Stream, parent: Option<&'a Dictionary>, ctm: Matrix, depth: u8) {
        let subtype = stream
            .dict
            .get_deref(b"Subtype", self.doc)
            .ok()
            .and_then(|o| o.as_name().ok());
        match subtype {
            Some(b"Image") => {
                let dim = |key: &[u8]| {
                    stream
                        .dict
                        .get_deref(key, self.doc)
                        .ok()
                        .and_then(|o| o.as_i64().ok())
                };
                if dim(b"Width").is_some_and(|w| w >= MIN_WIDTH)
                    && dim(b"Height").is_some_and(|h| h >= MIN_HEIGHT)
                {
                    self.found.push(Found { ctm, stream });
                }
            }
            Some(b"Form") if depth < MAX_FORM_DEPTH => {
                let Ok(bytes) = stream.decompressed_content_with_limit(*self.budget) else {
                    return;
                };
                *self.budget = self.budget.saturating_sub(bytes.len());
                let matrix = stream
                    .dict
                    .get_deref(b"Matrix", self.doc)
                    .ok()
                    .and_then(|o| o.as_array().ok())
                    .map(|a| {
                        let mut m = IDENTITY;
                        for (slot, o) in m.iter_mut().zip(a) {
                            *slot = o.as_float().ok().filter(|v| v.is_finite()).unwrap_or(0.0);
                        }
                        m
                    })
                    .unwrap_or(IDENTITY);
                let resources = stream
                    .dict
                    .get_deref(b"Resources", self.doc)
                    .ok()
                    .and_then(|o| o.as_dict().ok())
                    .or(parent);
                self.content(&bytes, resources, mul(&matrix, &ctm), depth + 1);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding one image XObject
// ---------------------------------------------------------------------------------------------

/// The codec filters: everything before them is a plain byte filter lopdf decodes.
const CODECS: [&[u8]; 4] = [b"DCTDecode", b"JPXDecode", b"CCITTFaxDecode", b"JBIG2Decode"];

fn int(doc: &Document, dict: &Dictionary, key: &[u8]) -> Option<i64> {
    dict.get_deref(key, doc).ok().and_then(|o| o.as_i64().ok())
}

fn flag(doc: &Document, dict: &Dictionary, key: &[u8]) -> Option<bool> {
    dict.get_deref(key, doc).ok().and_then(|o| o.as_bool().ok())
}

/// `DecodeParms` entry `index` of a stream.
fn parms<'a>(doc: &'a Document, stream: &'a Stream, index: usize) -> Option<&'a Dictionary> {
    match stream.dict.get_deref(b"DecodeParms", doc).ok()? {
        Object::Dictionary(d) if index == 0 => Some(d),
        Object::Array(a) => {
            let item = a.get(index)?;
            doc.dereference(item).ok()?.1.as_dict().ok()
        }
        _ => None,
    }
}

/// The stream bytes after the first `n` filters (those lopdf can run).
fn after_filters<'a>(
    doc: &Document,
    stream: &'a Stream,
    n: usize,
    budget: &mut usize,
) -> Result<Cow<'a, [u8]>, String> {
    if n == 0 {
        return Ok(Cow::Borrowed(&stream.content));
    }
    let filters = stream.filters().map_err(|e| e.to_string())?;
    let mut dict = Dictionary::new();
    dict.set(
        "Filter",
        Object::Array(filters.iter().take(n).map(|f| Object::Name(f.to_vec())).collect()),
    );
    let parms: Vec<Object> = (0..n)
        .map(|i| parms(doc, stream, i).map_or(Object::Null, |d| Object::Dictionary(d.clone())))
        .collect();
    dict.set("DecodeParms", Object::Array(parms));
    let tmp = Stream::new(dict, stream.content.clone());
    let bytes = tmp
        .decompressed_content_with_limit(*budget)
        .map_err(|e| format!("the image data cannot be decoded: {e}"))?;
    *budget = budget.saturating_sub(bytes.len());
    Ok(Cow::Owned(bytes))
}

/// Decode an image XObject to pixels.
fn decode_image(
    doc: &Document,
    stream: &Stream,
    max_pixels: u64,
    budget: &mut usize,
) -> Result<DynamicImage, String> {
    let dict = &stream.dict;
    let width = int(doc, dict, b"Width").ok_or("no /Width")?;
    let height = int(doc, dict, b"Height").ok_or("no /Height")?;
    let (w, h) = (
        u32::try_from(width).map_err(|_| "bad /Width")?,
        u32::try_from(height).map_err(|_| "bad /Height")?,
    );
    image_io::check_size(w, h, max_pixels).map_err(|e| e.to_string())?;
    let filters = stream.filters().unwrap_or_default();
    let codec = filters.iter().position(|f| CODECS.contains(f));
    let Some(at) = codec else {
        let data = after_filters(doc, stream, filters.len(), budget)?;
        return raw_image(doc, dict, &data, w, h);
    };
    let data = after_filters(doc, stream, at, budget)?;
    let invert_decode = decode_inverted(doc, dict);
    match filters[at] {
        b"DCTDecode" => {
            let mut img = image_io::decode(&data, max_pixels).map_err(|e| e.to_string())?;
            if invert_decode {
                img.invert();
            }
            Ok(img)
        }
        b"CCITTFaxDecode" => {
            let p = parms(doc, stream, at);
            let k = p.and_then(|p| int(doc, p, b"K")).unwrap_or(0);
            let columns = p.and_then(|p| int(doc, p, b"Columns")).unwrap_or(1728);
            let black_is_1 = p.and_then(|p| flag(doc, p, b"BlackIs1")).unwrap_or(false);
            let aligned = p.and_then(|p| flag(doc, p, b"EncodedByteAlign")).unwrap_or(false);
            let columns = u32::try_from(columns).map_err(|_| "bad CCITT /Columns")?;
            let tiff = ccitt_tiff(&data, columns, h, k, aligned);
            let mut img = image_io::decode(&tiff, max_pixels).map_err(|e| format!("CCITT data: {e}"))?;
            // `BlackIs1` and `/Decode [1 0]` each flip the meaning of a sample bit
            if black_is_1 ^ invert_decode {
                img.invert();
            }
            Ok(img)
        }
        b"JPXDecode" => Err("JPEG 2000 images are not decoded".to_owned()),
        _ => Err("JBIG2 images are not decoded".to_owned()),
    }
}

/// `/Decode [1 0 ...]` (the first pair is reversed).
fn decode_inverted(doc: &Document, dict: &Dictionary) -> bool {
    dict.get_deref(b"Decode", doc)
        .ok()
        .and_then(|o| o.as_array().ok())
        .is_some_and(|a| {
            let n: Vec<f32> = a.iter().filter_map(|o| o.as_float().ok()).collect();
            n.len() >= 2 && n[0] > n[1]
        })
}

/// A baseline TIFF around CCITT data, so the TIFF decoder can read it.
fn ccitt_tiff(data: &[u8], columns: u32, rows: u32, k: i64, aligned: bool) -> Vec<u8> {
    // (tag, type, value): type 3 = SHORT, 4 = LONG
    let compression: u32 = if k < 0 { 4 } else { 3 };
    let mut entries: Vec<(u16, u16, u32)> = vec![
        (256, 4, columns),
        (257, 4, rows),
        (258, 3, 1),
        (259, 3, compression),
        (262, 3, 0), // WhiteIsZero: runs of white are white
        (266, 3, 1),
    ];
    entries.push((273, 4, 0));
    entries.extend([(277, 3, 1), (278, 4, rows)]);
    entries.push((279, 4, u32::try_from(data.len()).unwrap_or(u32::MAX)));
    if k >= 0 {
        // T4Options: bit 0 two-dimensional (K > 0), bit 2 fill bits before EOL
        entries.push((292, 4, u32::from(k > 0) | (u32::from(aligned) << 2)));
    }
    entries.sort_by_key(|e| e.0);
    let ifd_len = 2 + entries.len() * 12 + 4;
    let data_offset = u32::try_from(8 + ifd_len).unwrap_or(u32::MAX);
    for e in &mut entries {
        if e.0 == 273 {
            e.2 = data_offset;
        }
    }
    let mut out = Vec::with_capacity(8 + ifd_len + data.len());
    out.extend_from_slice(b"II*\0");
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&u16::try_from(entries.len()).unwrap_or(0).to_le_bytes());
    for (tag, ty, value) in &entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        if *ty == 3 {
            out.extend_from_slice(&u16::try_from(*value).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
        } else {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// The colour model of raw samples.
#[derive(Clone)]
enum Space {
    Gray {
        invert: bool,
    },
    Rgb,
    Cmyk,
    Indexed {
        base: Box<Space>,
        hival: usize,
        lookup: Vec<u8>,
    },
}

impl Space {
    fn components(&self) -> usize {
        match self {
            Self::Gray { .. } | Self::Indexed { .. } => 1,
            Self::Rgb => 3,
            Self::Cmyk => 4,
        }
    }
}

fn name_space(name: &[u8]) -> Option<Space> {
    match name {
        b"DeviceGray" | b"CalGray" | b"G" => Some(Space::Gray { invert: false }),
        b"DeviceRGB" | b"CalRGB" | b"RGB" => Some(Space::Rgb),
        b"DeviceCMYK" | b"CMYK" => Some(Space::Cmyk),
        _ => None,
    }
}

fn colour_space(doc: &Document, obj: &Object, depth: u8) -> Option<Space> {
    if depth > 3 {
        return None;
    }
    let obj = doc.dereference(obj).ok()?.1;
    match obj {
        Object::Name(n) => name_space(n),
        Object::Array(a) => {
            let head = a
                .first()
                .and_then(|o| doc.dereference(o).ok()?.1.as_name().ok())?;
            match head {
                b"ICCBased" => {
                    let s = doc.dereference(a.get(1)?).ok()?.1.as_stream().ok()?;
                    match int(doc, &s.dict, b"N")? {
                        1 => Some(Space::Gray { invert: false }),
                        3 => Some(Space::Rgb),
                        4 => Some(Space::Cmyk),
                        _ => None,
                    }
                }
                b"Indexed" | b"I" => {
                    let base = colour_space(doc, a.get(1)?, depth + 1)?;
                    let hival = usize::try_from(doc.dereference(a.get(2)?).ok()?.1.as_i64().ok()?).ok()?;
                    let lookup = match doc.dereference(a.get(3)?).ok()?.1 {
                        Object::String(s, _) => s.clone(),
                        Object::Stream(s) => s.decompressed_content_with_limit(1 << 20).ok()?,
                        _ => return None,
                    };
                    Some(Space::Indexed {
                        base: Box::new(base),
                        hival,
                        lookup,
                    })
                }
                // one tint: 0 is no ink (paper), 1 is full ink
                b"Separation" => Some(Space::Gray { invert: true }),
                other => name_space(other),
            }
        }
        _ => None,
    }
}

fn unpack_bits(row: &[u8], bpc: usize, count: usize) -> impl Iterator<Item = u32> + '_ {
    (0..count).map(move |i| match bpc {
        8 => u32::from(row[i]),
        16 => u32::from(row[2 * i]) << 8 | u32::from(row[2 * i + 1]),
        _ => {
            let bit = i * bpc;
            let byte = row[bit / 8];
            let shift = 8 - bpc - (bit % 8);
            u32::from((byte >> shift) & ((1u8 << bpc) - 1))
        }
    })
}

fn scale(v: u32, bpc: usize) -> u8 {
    let max = (1u32 << bpc) - 1;
    u8::try_from((v * 255 + max / 2) / max).unwrap_or(255)
}

fn cmyk_to_rgb(c: u8, m: u8, y: u8, k: u8) -> [u8; 3] {
    let f = |v: u8| u8::try_from(u16::from(255 - v) * u16::from(255 - k) / 255).unwrap_or(0);
    [f(c), f(m), f(y)]
}

/// Raw (filter-decoded) samples to pixels.
fn raw_image(doc: &Document, dict: &Dictionary, data: &[u8], w: u32, h: u32) -> Result<DynamicImage, String> {
    let mask = flag(doc, dict, b"ImageMask").unwrap_or(false);
    let bpc = if mask {
        1
    } else {
        usize::try_from(int(doc, dict, b"BitsPerComponent").unwrap_or(8)).unwrap_or(0)
    };
    if !matches!(bpc, 1 | 2 | 4 | 8 | 16) {
        return Err(format!("{bpc} bits per component are not supported"));
    }
    let space = if mask {
        Space::Gray { invert: false }
    } else {
        let cs = dict.get_deref(b"ColorSpace", doc).map_err(|_| "no /ColorSpace")?;
        colour_space(doc, cs, 0).ok_or("an unsupported colour space")?
    };
    let comps = space.components();
    let (wu, hu) = (w as usize, h as usize);
    let row_bits = wu * comps * bpc;
    let row_bytes = row_bits.div_ceil(8);
    if data.len() < row_bytes.saturating_mul(hu) {
        return Err("the image data is shorter than its dimensions".to_owned());
    }
    let flip = decode_inverted(doc, dict);
    let rows = data.chunks_exact(row_bytes).take(hu);
    match &space {
        Space::Gray { invert } => {
            let invert = *invert ^ flip;
            let mut px = Vec::with_capacity(wu * hu);
            for row in rows {
                px.extend(unpack_bits(row, bpc, wu).map(|v| {
                    let g = scale(v, bpc);
                    if invert {
                        255 - g
                    } else {
                        g
                    }
                }));
            }
            GrayImage::from_raw(w, h, px)
                .map(DynamicImage::ImageLuma8)
                .ok_or_else(|| "inconsistent image size".to_owned())
        }
        Space::Rgb | Space::Cmyk | Space::Indexed { .. } => {
            let mut px = Vec::with_capacity(wu * hu * 3);
            for row in rows {
                let samples: Vec<u32> = unpack_bits(row, bpc, wu * comps).collect();
                for px_samples in samples.chunks_exact(comps) {
                    let rgb = match &space {
                        Space::Rgb => [0, 1, 2].map(|i| scale(px_samples[i], bpc)),
                        Space::Cmyk => {
                            let n = [0, 1, 2, 3].map(|i| scale(px_samples[i], bpc));
                            cmyk_to_rgb(n[0], n[1], n[2], n[3])
                        }
                        Space::Indexed { base, hival, lookup } => {
                            let idx = usize::try_from(px_samples[0]).unwrap_or(0).min(*hival);
                            let n = base.components();
                            let entry = lookup.get(idx * n..idx * n + n).unwrap_or(&[]);
                            match (&**base, entry) {
                                (Space::Rgb, [r, g, b]) => [*r, *g, *b],
                                (Space::Cmyk, [c, m, y, k]) => cmyk_to_rgb(*c, *m, *y, *k),
                                (Space::Gray { invert }, [g]) => {
                                    let g = if *invert { 255 - *g } else { *g };
                                    [g, g, g]
                                }
                                _ => [255, 255, 255],
                            }
                        }
                        Space::Gray { .. } => [255, 255, 255],
                    };
                    px.extend_from_slice(&rgb);
                }
            }
            let mut img = RgbImage::from_raw(w, h, px)
                .map(DynamicImage::ImageRgb8)
                .ok_or_else(|| "inconsistent image size".to_owned())?;
            if flip {
                img.invert();
            }
            Ok(img)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn unit_square_corners_follow_the_turn() {
        // an image placed unrotated on a 200x100 page at the origin
        let m = |q| Mapping {
            ctm: [200.0, 0.0, 0.0, 100.0, 0.0, 0.0],
            quarters: q,
        };
        assert_eq!(m(0).point(0.0, 0.0), (0.0, 100.0), "top left stays top left");
        assert_eq!(m(0).point(1.0, 1.0), (200.0, 0.0));
        // turned 90 degrees clockwise: the top-left pixel came from the bottom-left corner
        assert_eq!(m(1).point(0.0, 0.0), (0.0, 0.0));
        assert_eq!(m(1).point(1.0, 0.0), (0.0, 100.0));
        assert_eq!(m(2).point(0.0, 0.0), (200.0, 0.0));
        assert_eq!(m(3).point(0.0, 0.0), (200.0, 100.0));
    }

    #[test]
    fn quarters_of_a_matrix_are_counter_clockwise_turns_of_the_up_edge() {
        assert_eq!(ctm_quarters(&[10.0, 0.0, 0.0, 10.0, 0.0, 0.0]), 0);
        assert_eq!(ctm_quarters(&[0.0, 10.0, -10.0, 0.0, 0.0, 0.0]), 1);
        assert_eq!(ctm_quarters(&[-10.0, 0.0, 0.0, -10.0, 0.0, 0.0]), 2);
        assert_eq!(ctm_quarters(&[0.0, -10.0, 10.0, 0.0, 0.0, 0.0]), 3);
    }

    #[test]
    fn sample_unpacking_scales_to_eight_bits() {
        let row = [0b1010_0000u8];
        let v: Vec<u8> = unpack_bits(&row, 1, 4).map(|v| scale(v, 1)).collect();
        assert_eq!(v, [255, 0, 255, 0]);
        let row = [0b0001_1011u8];
        let v: Vec<u32> = unpack_bits(&row, 2, 4).collect();
        assert_eq!(v, [0, 1, 2, 3]);
        assert_eq!(scale(3, 2), 255);
        assert_eq!(cmyk_to_rgb(0, 0, 0, 0), [255, 255, 255]);
        assert_eq!(cmyk_to_rgb(0, 0, 0, 255), [0, 0, 0]);
    }

    #[test]
    fn the_ccitt_wrapper_is_a_well_formed_tiff_header() {
        let t = ccitt_tiff(&[1, 2, 3], 1728, 100, -1, false);
        assert_eq!(&t[..4], b"II*\0");
        assert_eq!(&t[t.len() - 3..], &[1, 2, 3]);
        // entry count then the 12-byte entries, tags ascending
        let n = u16::from_le_bytes([t[8], t[9]]) as usize;
        let tags: Vec<u16> = (0..n)
            .map(|i| u16::from_le_bytes([t[10 + i * 12], t[11 + i * 12]]))
            .collect();
        assert!(tags.windows(2).all(|w| w[0] < w[1]), "{tags:?}");
        assert!(!tags.contains(&292), "G4 has no T4Options");
    }
}
