//! Bounded ZIP/ZIP64 metadata admission before the ZIP library allocates its central directory.
//! Framing follows PKWARE APPNOTE 6.3.10 sections 4.3.12–4.3.16; no crawler source is used.

use super::{ArchiveError, Limits};
use std::io::{Read, Seek, SeekFrom};

fn short(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn wide(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
fn extra_safe(extra: &[u8], expected_zip64: usize) -> Result<bool, ArchiveError> {
    let mut position = 0usize;
    let mut safe = true;
    let mut seen_zip64 = false;
    while position < extra.len() {
        if extra.len() - position < 4 {
            return Err(ArchiveError::Invalid("malformed ZIP extra field"));
        }
        let kind = short(extra, position);
        let size = usize::from(short(extra, position + 2));
        position += 4;
        let end = position
            .checked_add(size)
            .ok_or(ArchiveError::Limit("ZIP extra field bytes"))?;
        if end > extra.len() {
            return Err(ArchiveError::Invalid("short ZIP extra field"));
        }
        if kind == 1 {
            if seen_zip64 {
                return Err(ArchiveError::Invalid("duplicate ZIP64 extra field"));
            }
            seen_zip64 = true;
            safe &= size == expected_zip64;
        } else {
            // Other extension data is valid format data, but needs a retention-aware container rewrite.
            safe = false;
        }
        position = end;
    }
    if expected_zip64 > 0 && !seen_zip64 {
        return Err(ArchiveError::Invalid("required ZIP64 extra field missing"));
    }
    Ok(safe)
}
fn zip64_values(header: &[u8; 46], extra: &[u8]) -> Result<(u64, u64, u64), ArchiveError> {
    let mut values = [
        u64::from(word(header, 24)),
        u64::from(word(header, 20)),
        u64::from(word(header, 42)),
    ];
    if values.iter().all(|value| *value != u64::from(u32::MAX)) {
        return Ok((values[0], values[1], values[2]));
    }
    let data = zip64_data(extra)?.ok_or(ArchiveError::Invalid("ZIP64 geometry missing"))?;
    let mut position = 0usize;
    for value in &mut values {
        if *value == u64::from(u32::MAX) {
            if position + 8 > data.len() {
                return Err(ArchiveError::Invalid("short ZIP64 geometry"));
            }
            *value = wide(data, position);
            position += 8;
        }
    }
    Ok((values[0], values[1], values[2]))
}

fn zip64_data(extra: &[u8]) -> Result<Option<&[u8]>, ArchiveError> {
    let mut position = 0usize;
    while position + 4 <= extra.len() {
        let kind = short(extra, position);
        let size = usize::from(short(extra, position + 2));
        position += 4;
        if position + size > extra.len() {
            return Err(ArchiveError::Invalid("short ZIP extra field"));
        }
        if kind == 1 {
            return Ok(Some(&extra[position..position + size]));
        }
        position += size;
    }
    Ok(None)
}

fn descriptor_size<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    boundary: u64,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    zip64: bool,
) -> Result<u64, ArchiveError> {
    let available = boundary
        .checked_sub(offset)
        .ok_or(ArchiveError::Invalid("ZIP data descriptor range invalid"))?
        .min(24);
    let size = usize::try_from(available).map_err(|_| ArchiveError::Limit("ZIP descriptor bytes"))?;
    let mut data = [0u8; 24];
    input.seek(SeekFrom::Start(offset))?;
    input.read_exact(&mut data[..size])?;
    for signature in [true, false] {
        let start = if signature { 4usize } else { 0 };
        let needed = start + if zip64 { 20 } else { 12 };
        if size < needed || (signature && data[..4] != *b"PK\x07\x08") || word(&data, start) != crc {
            continue;
        }
        let actual_compressed = if zip64 {
            wide(&data, start + 4)
        } else {
            u64::from(word(&data, start + 4))
        };
        let actual_uncompressed = if zip64 {
            wide(&data, start + 12)
        } else {
            u64::from(word(&data, start + 8))
        };
        if actual_compressed == compressed && actual_uncompressed == uncompressed {
            return Ok(needed as u64);
        }
    }
    Err(ArchiveError::Invalid(
        "ZIP data descriptor CRC or length mismatch",
    ))
}

/// Return whether raw ZIP metadata is within the conservative durable-copy profile.
pub(super) fn preflight<R: Read + Seek>(input: &mut R, limits: Limits) -> Result<bool, ArchiveError> {
    let length = input.seek(SeekFrom::End(0))?;
    if length > limits.total_bytes {
        return Err(ArchiveError::Limit("ZIP input bytes"));
    }
    if length < 22 {
        return Err(ArchiveError::Invalid("ZIP end record missing"));
    }
    let tail_size = usize::try_from(length.min(65_557)).map_err(|_| ArchiveError::Limit("ZIP tail bytes"))?;
    input.seek(SeekFrom::Start(length - tail_size as u64))?;
    let mut tail = vec![0u8; tail_size];
    input.read_exact(&mut tail)?;
    let (position, end) = tail
        .windows(22)
        .enumerate()
        .rev()
        .find(|(position, header)| {
            header[..4] == *b"PK\x05\x06" && position + 22 + usize::from(short(header, 20)) == tail.len()
        })
        .ok_or(ArchiveError::Invalid("ZIP end record or comment length invalid"))?;
    if short(end, 4) != 0 || short(end, 6) != 0 || short(end, 8) != short(end, 10) {
        return Err(ArchiveError::CapabilityUnavailable("multi_disk_zip_unavailable"));
    }
    let end_offset = length - tail_size as u64 + position as u64;
    let mut count = u64::from(short(end, 10));
    let mut central_size = u64::from(word(end, 12));
    let mut central_offset = u64::from(word(end, 16));
    let mut metadata_end = end_offset;
    let mut safe = short(end, 20) == 0;
    let mut locator = [0u8; 20];
    if end_offset >= 20 {
        input.seek(SeekFrom::Start(end_offset - 20))?;
        input.read_exact(&mut locator)?;
    }
    if locator[..4] == *b"PK\x06\x07" {
        if word(&locator, 4) != 0 || word(&locator, 16) != 1 {
            return Err(ArchiveError::CapabilityUnavailable(
                "multi_disk_zip64_unavailable",
            ));
        }
        let zip64_offset = wide(&locator, 8);
        if zip64_offset
            .checked_add(56)
            .is_none_or(|end| end > end_offset - 20)
        {
            return Err(ArchiveError::Invalid("ZIP64 end range invalid"));
        }
        input.seek(SeekFrom::Start(zip64_offset))?;
        let mut zip64 = [0u8; 56];
        input.read_exact(&mut zip64)?;
        if zip64[..4] != *b"PK\x06\x06" || wide(&zip64, 4) < 44 {
            return Err(ArchiveError::Invalid("ZIP64 end record invalid"));
        }
        let extension = wide(&zip64, 4) - 44;
        if extension > limits.header_bytes {
            return Err(ArchiveError::Limit("ZIP64 extensible metadata bytes"));
        }
        if zip64_offset
            .checked_add(56)
            .and_then(|value| value.checked_add(extension))
            != Some(end_offset - 20)
        {
            return Err(ArchiveError::Invalid("ZIP64 extensible metadata range invalid"));
        }
        safe &= extension == 0;
        if word(&zip64, 16) != 0 || word(&zip64, 20) != 0 || wide(&zip64, 24) != wide(&zip64, 32) {
            return Err(ArchiveError::CapabilityUnavailable(
                "multi_disk_zip64_unavailable",
            ));
        }
        let actual = wide(&zip64, 32);
        if count != u64::from(u16::MAX) && count != actual {
            return Err(ArchiveError::Invalid("ZIP64 entry count mismatch"));
        }
        count = actual;
        central_size = wide(&zip64, 40);
        central_offset = wide(&zip64, 48);
        metadata_end = zip64_offset;
    } else if count == u64::from(u16::MAX)
        || central_size == u64::from(u32::MAX)
        || central_offset == u64::from(u32::MAX)
    {
        return Err(ArchiveError::Invalid("ZIP64 locator missing"));
    }
    let max_count = u64::try_from(limits.resources)
        .map_err(|_| ArchiveError::Limit("ZIP resource count"))?
        .checked_add(2)
        .ok_or(ArchiveError::Limit("ZIP resource count"))?;
    if count > max_count {
        return Err(ArchiveError::Limit("ZIP resource count"));
    }
    if central_size > limits.record_bytes {
        return Err(ArchiveError::Limit("ZIP central metadata bytes"));
    }
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or(ArchiveError::Limit("ZIP central range"))?;
    if central_end > metadata_end {
        return Err(ArchiveError::Invalid("ZIP central range invalid"));
    }
    safe &= central_end == metadata_end;
    let mut cursor = central_offset;
    let mut local_metadata = 0u64;
    let mut physical_ranges = Vec::new();
    for _ in 0..count {
        if cursor.checked_add(46).is_none_or(|end| end > central_end) {
            return Err(ArchiveError::Invalid("short ZIP central header"));
        }
        input.seek(SeekFrom::Start(cursor))?;
        let mut header = [0u8; 46];
        input.read_exact(&mut header)?;
        if header[..4] != *b"PK\x01\x02" {
            return Err(ArchiveError::Invalid("ZIP central header invalid"));
        }
        let name_len = usize::from(short(&header, 28));
        let extra_len = usize::from(short(&header, 30));
        let comment_len = usize::from(short(&header, 32));
        if name_len == 0 || name_len > 1024 {
            return Err(ArchiveError::Limit("ZIP resource name bytes"));
        }
        let entry_size = 46u64 + name_len as u64 + extra_len as u64 + comment_len as u64;
        cursor = cursor
            .checked_add(entry_size)
            .ok_or(ArchiveError::Limit("ZIP central metadata bytes"))?;
        if cursor > central_end {
            return Err(ArchiveError::Invalid("ZIP central field range invalid"));
        }
        let mut name = vec![0u8; name_len];
        input.read_exact(&mut name)?;
        let mut extra = vec![0u8; extra_len];
        input.read_exact(&mut extra)?;
        let expected_central64 = (if word(&header, 24) == u32::MAX { 8 } else { 0 })
            + (if word(&header, 20) == u32::MAX { 8 } else { 0 })
            + (if word(&header, 42) == u32::MAX { 8 } else { 0 })
            + (if short(&header, 34) == u16::MAX { 4 } else { 0 });
        safe &= comment_len == 0 && extra_safe(&extra, expected_central64)?;
        let (uncompressed, compressed, local_offset) = zip64_values(&header, &extra)?;
        if local_offset
            .checked_add(30)
            .is_none_or(|end| end > central_offset)
        {
            return Err(ArchiveError::Invalid("ZIP local header range invalid"));
        }
        input.seek(SeekFrom::Start(local_offset))?;
        let mut local = [0u8; 30];
        input.read_exact(&mut local)?;
        if local[..4] != *b"PK\x03\x04" || usize::from(short(&local, 26)) != name_len {
            return Err(ArchiveError::Invalid("ZIP local name framing mismatch"));
        }
        let local_extra_len = usize::from(short(&local, 28));
        local_metadata = local_metadata
            .checked_add(30 + name_len as u64 + local_extra_len as u64)
            .ok_or(ArchiveError::Limit("ZIP local metadata bytes"))?;
        if local_metadata > limits.record_bytes {
            return Err(ArchiveError::Limit("ZIP local metadata bytes"));
        }
        if local_offset
            .checked_add(30 + name_len as u64 + local_extra_len as u64)
            .is_none_or(|end| end > central_offset)
        {
            return Err(ArchiveError::Invalid("ZIP local extra range invalid"));
        }
        let mut local_name = vec![0u8; name_len];
        input.read_exact(&mut local_name)?;
        if local_name != name {
            return Err(ArchiveError::Invalid("ZIP local and central names differ"));
        }
        let mut local_extra = vec![0u8; local_extra_len];
        input.read_exact(&mut local_extra)?;
        let expected_local64 = (if word(&local, 22) == u32::MAX { 8 } else { 0 })
            + (if word(&local, 18) == u32::MAX { 8 } else { 0 });
        safe &= extra_safe(&local_extra, expected_local64)?;
        if short(&local, 6) != short(&header, 8) || short(&local, 8) != short(&header, 10) {
            return Err(ArchiveError::Invalid("ZIP local flags or compression differ"));
        }
        let data_start = local_offset + 30 + name_len as u64 + local_extra_len as u64;
        let mut physical_end = data_start
            .checked_add(compressed)
            .ok_or(ArchiveError::Limit("ZIP compressed member bytes"))?;
        if physical_end > central_offset {
            return Err(ArchiveError::Invalid("ZIP compressed member range invalid"));
        }
        if short(&local, 6) & 8 != 0 {
            let zip64 = zip64_data(&local_extra)?.is_some() || zip64_data(&extra)?.is_some();
            let descriptor = descriptor_size(
                input,
                physical_end,
                central_offset,
                word(&header, 16),
                compressed,
                uncompressed,
                zip64,
            )?;
            physical_end = physical_end
                .checked_add(descriptor)
                .ok_or(ArchiveError::Limit("ZIP descriptor range"))?;
        } else {
            if word(&local, 14) != word(&header, 16)
                || (word(&local, 18) != u32::MAX && u64::from(word(&local, 18)) != compressed)
                || (word(&local, 22) != u32::MAX && u64::from(word(&local, 22)) != uncompressed)
            {
                return Err(ArchiveError::Invalid("ZIP local CRC or length mismatch"));
            }
            if let Some(data) = zip64_data(&local_extra)? {
                let mut position = 0usize;
                for (legacy, expected) in [(word(&local, 22), uncompressed), (word(&local, 18), compressed)] {
                    if legacy != u32::MAX {
                        continue;
                    }
                    if position + 8 > data.len() || wide(data, position) != expected {
                        return Err(ArchiveError::Invalid("ZIP64 local length mismatch"));
                    }
                    position += 8;
                }
            }
        }
        physical_ranges.push((local_offset, physical_end));
    }
    if cursor != central_end {
        if central_end - cursor < 6 {
            return Err(ArchiveError::Invalid("ZIP central trailing bytes invalid"));
        }
        input.seek(SeekFrom::Start(cursor))?;
        let mut signature = [0u8; 6];
        input.read_exact(&mut signature)?;
        if signature[..4] != *b"PK\x05\x05" || cursor + 6 + u64::from(short(&signature, 4)) != central_end {
            return Err(ArchiveError::Invalid("ZIP central count or signature mismatch"));
        }
        safe = false;
    }
    physical_ranges.sort_unstable();
    let mut physical_end = 0u64;
    for (start, end) in physical_ranges {
        if start < physical_end {
            return Err(ArchiveError::Invalid("overlapping ZIP members"));
        }
        safe &= start == physical_end;
        physical_end = end;
    }
    safe &= physical_end == central_offset;
    input.rewind()?;
    Ok(safe)
}
