//! Load-time budgets cover eager decoding, indirect lengths, and xref recovery.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Write;

use flate2::{Compression, write::ZlibEncoder};
use lopdf::{DecompressError, Document, Error, LoadOptions};

fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn xref_row(kind: u8, value: u32, index: u16) -> [u8; 7] {
    let mut row = [0; 7];
    row[0] = kind;
    row[1..5].copy_from_slice(&value.to_be_bytes());
    row[5..].copy_from_slice(&index.to_be_bytes());
    row
}

struct Pdf {
    bytes: Vec<u8>,
    entries: BTreeMap<u32, [u8; 7]>,
    decoded_bytes: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    decoded_bytes: usize,
}

impl Pdf {
    fn new() -> Self {
        let mut pdf = Self {
            bytes: b"%PDF-1.7\n".to_vec(),
            entries: BTreeMap::new(),
            decoded_bytes: 0,
        };
        pdf.object(1, b"<< /Type /Catalog /Pages 2 0 R >>");
        pdf.object(2, b"<< /Type /Pages /Kids [] /Count 0 >>");
        pdf
    }

    fn object(&mut self, number: u32, body: &[u8]) {
        let offset = u32::try_from(self.bytes.len()).unwrap();
        self.entries.insert(number, xref_row(1, offset, 0));
        write!(self.bytes, "{number} 0 obj\n").unwrap();
        self.bytes.extend_from_slice(body);
        self.bytes.extend_from_slice(b"\nendobj\n");
    }

    fn compressed_stream(&mut self, number: u32, dictionary: &str, decoded: &[u8]) {
        let compressed = deflate(decoded);
        let mut body = format!(
            "<< {dictionary} /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        )
        .into_bytes();
        body.extend_from_slice(&compressed);
        body.extend_from_slice(b"\nendstream");
        self.object(number, &body);
        self.decoded_bytes = self.decoded_bytes.checked_add(decoded.len()).unwrap();
    }

    fn object_stream(&mut self, number: u32, members: &[(u32, &[u8])], indexed: bool) {
        let mut header = Vec::new();
        let mut body = Vec::new();
        for (index, &(member, value)) in members.iter().enumerate() {
            write!(header, "{member} {} ", body.len()).unwrap();
            body.extend_from_slice(value);
            body.push(b' ');
            if indexed {
                self.entries.insert(member, xref_row(2, number, u16::try_from(index).unwrap()));
            }
        }
        let dictionary = format!("/Type /ObjStm /N {} /First {}", members.len(), header.len());
        header.extend_from_slice(&body);
        self.compressed_stream(number, &dictionary, &header);
    }

    fn finish_xref(mut self, number: u32, size: u32, broken_startxref: bool) -> Fixture {
        let offset = self.bytes.len();
        self.entries.insert(number, xref_row(1, u32::try_from(offset).unwrap(), 0));
        let mut rows = Vec::new();
        for id in 0..size {
            let row = self.entries.get(&id).copied().unwrap_or_else(|| xref_row(0, 0, 0));
            rows.extend_from_slice(&row);
        }
        self.compressed_stream(
            number,
            &format!("/Type /XRef /Size {size} /W [1 4 2] /Index [0 {size}] /Root 1 0 R"),
            &rows,
        );
        let startxref = if broken_startxref {
            self.bytes.len().checked_add(4096).unwrap()
        } else {
            offset
        };
        write!(self.bytes, "startxref\n{startxref}\n%%EOF\n").unwrap();
        Fixture {
            bytes: self.bytes,
            decoded_bytes: self.decoded_bytes,
        }
    }

    fn finish_classic(mut self, size: u32, broken_startxref: bool) -> Fixture {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n");
        for (number, row) in self.entries {
            assert_eq!(row[0], 1, "classic fixtures must not contain compressed xref entries");
            let object_offset = u32::from_be_bytes(row[1..5].try_into().unwrap());
            write!(self.bytes, "{number} 1\n{object_offset:010} 00000 n \n").unwrap();
        }
        let startxref = if broken_startxref {
            self.bytes.len().checked_add(4096).unwrap()
        } else {
            offset
        };
        write!(
            self.bytes,
            "trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n"
        )
        .unwrap();
        Fixture {
            bytes: self.bytes,
            decoded_bytes: self.decoded_bytes,
        }
    }
}

fn options(strict: bool, total: Option<usize>, objects: Option<usize>) -> LoadOptions {
    LoadOptions {
        strict,
        max_total_decompressed_size: total,
        max_objects: objects,
        ..Default::default()
    }
}

fn assert_limit(result: lopdf::Result<Document>) {
    match result {
        Err(Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => {}
        Err(other) => panic!("expected a load budget error, got {other:?}"),
        Ok(document) => panic!("budget was bypassed; retained {} objects", document.objects.len()),
    }
}

fn two_object_streams() -> Fixture {
    let mut pdf = Pdf::new();
    let mut first = b"(first)".to_vec();
    first.resize(1024, b' ');
    let mut second = b"(second)".to_vec();
    second.resize(1024, b' ');
    pdf.object_stream(3, &[(10, &first)], true);
    pdf.object_stream(4, &[(11, &second)], true);
    pdf.finish_xref(12, 13, false)
}

fn indirect_lengths() -> Fixture {
    let mut pdf = Pdf::new();
    let content = b"q Q";
    for number in [3, 4] {
        let mut stream = b"<< /Length 10 0 R >>\nstream\n".to_vec();
        stream.extend_from_slice(content);
        stream.extend_from_slice(b"\nendstream");
        pdf.object(number, &stream);
    }
    let mut padding = b"(padding)".to_vec();
    padding.resize(1024, b' ');
    pdf.object_stream(5, &[(10, b"3"), (11, &padding)], true);
    pdf.finish_xref(12, 13, false)
}

#[test]
fn new_load_budgets_default_to_unlimited() {
    let options = LoadOptions::default();
    assert_eq!(options.max_total_decompressed_size, None);
    assert_eq!(options.max_objects, None);
}

#[test]
fn ordinary_pdf_loads_with_zero_decoding_budget() {
    let mut pdf = Pdf::new();
    pdf.object(3, b"42");
    let fixture = pdf.finish_classic(4, false);
    for strict in [false, true] {
        let document = Document::load_mem_with_options(&fixture.bytes, options(strict, Some(0), Some(64))).unwrap();
        assert_eq!(document.get_object((3, 0)).unwrap().as_i64().unwrap(), 42);
        assert_eq!(document.catalog().unwrap().get(b"Pages").unwrap().as_reference().unwrap(), (2, 0));
    }
}

#[test]
fn compressed_pdf_loads_at_exact_total_decoding_budget() {
    let fixture = two_object_streams();
    for strict in [false, true] {
        let mut options = options(strict, Some(fixture.decoded_bytes), Some(1024));
        options.max_decompressed_size = Some(2048);
        let document = Document::load_mem_with_options(&fixture.bytes, options).unwrap();
        assert_eq!(document.get_object((10, 0)).unwrap().as_str().unwrap(), b"first");
        assert_eq!(document.get_object((11, 0)).unwrap().as_str().unwrap(), b"second");
    }
}

#[test]
fn separate_object_streams_share_total_decoding_budget_in_both_modes() {
    let fixture = two_object_streams();
    for strict in [false, true] {
        let mut options = options(strict, Some(1500), Some(1024));
        // Each ObjStm is below 2048 bytes, but both together exceed 1500 bytes.
        options.max_decompressed_size = Some(2048);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options));
    }
}

#[test]
fn indirect_compressed_length_cannot_bypass_stream_or_total_budget() {
    let fixture = indirect_lengths();
    for strict in [false, true] {
        let mut per_stream = options(strict, None, Some(1024));
        per_stream.max_decompressed_size = Some(512);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, per_stream));

        let mut cumulative = options(strict, Some(512), Some(1024));
        cumulative.max_decompressed_size = Some(2048);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, cumulative));
    }
}

#[test]
fn indirect_length_cache_hits_do_not_spend_decoding_budget_again() {
    let fixture = indirect_lengths();
    for strict in [false, true] {
        let document = Document::load_mem_with_options(
            &fixture.bytes,
            options(strict, Some(fixture.decoded_bytes), Some(1024)),
        )
        .unwrap();
        for number in [3, 4] {
            let stream = document.get_object((number, 0)).unwrap().as_stream().unwrap();
            assert_eq!(stream.content, b"q Q");
            assert_eq!(stream.dict.get(b"Length").unwrap().as_i64().unwrap(), 3);
        }
        assert_eq!(document.get_object((10, 0)).unwrap().as_i64().unwrap(), 3);
        assert_eq!(document.get_object((11, 0)).unwrap().as_str().unwrap(), b"padding");
    }
}

#[test]
fn huge_declared_object_stream_member_count_hits_object_budget() {
    let mut pdf = Pdf::new();
    pdf.compressed_stream(3, "/Type /ObjStm /N 1000000000 /First 5", b"10 0 7");
    let fixture = pdf.finish_classic(11, false);
    assert!(fixture.bytes.len() < 1024);
    for strict in [false, true] {
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options(strict, Some(1024), Some(128))));
    }
}

#[test]
fn unindexed_object_stream_members_still_spend_object_budget() {
    let mut pdf = Pdf::new();
    let members: Vec<(u32, &[u8])> = (100..228).map(|id| (id, b"7".as_slice())).collect();
    // Sparse xref cannot hide eagerly retained members from the object budget.
    pdf.object_stream(3, &members, false);
    let fixture = pdf.finish_classic(228, false);
    for strict in [false, true] {
        let document = Document::load_mem_with_options(&fixture.bytes, options(strict, Some(4096), Some(512))).unwrap();
        assert_eq!(document.get_object((100, 0)).unwrap().as_i64().unwrap(), 7);
        assert_eq!(document.get_object((227, 0)).unwrap().as_i64().unwrap(), 7);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options(strict, Some(4096), Some(64))));
    }
}

#[test]
fn compressed_xref_entry_count_is_bounded_even_for_free_entries() {
    let fixture = Pdf::new().finish_xref(3, 128, false);
    for strict in [false, true] {
        let document = Document::load_mem_with_options(&fixture.bytes, options(strict, Some(1024), Some(128))).unwrap();
        assert_eq!(document.catalog().unwrap().get(b"Type").unwrap().as_name().unwrap(), b"Catalog");
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options(strict, Some(1024), Some(64))));
    }
}

#[test]
fn xref_decoding_limit_is_not_swallowed_by_lenient_reconstruction() {
    let fixture = Pdf::new().finish_xref(3, 128, false);
    for strict in [false, true] {
        let mut options = options(strict, Some(128), Some(256));
        options.max_decompressed_size = Some(1024);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options));
    }
}

#[test]
fn classic_xref_and_reconstructed_objects_obey_object_budget() {
    for broken_startxref in [false, true] {
        let mut pdf = Pdf::new();
        for number in 3..100 {
            pdf.object(number, b"42");
        }
        let fixture = pdf.finish_classic(100, broken_startxref);
        let document = Document::load_mem_with_options(&fixture.bytes, options(false, Some(0), Some(512))).unwrap();
        assert_eq!(document.get_object((99, 0)).unwrap().as_i64().unwrap(), 42);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options(false, Some(0), Some(64))));
    }
}

#[test]
fn previous_xref_sections_share_object_budget() {
    let mut pdf = Pdf::new();
    pdf.object(3, b"42");
    let previous_xref = pdf.bytes.len();
    let mut fixture = pdf.finish_classic(4, false);
    let offset = fixture.bytes.len();
    fixture.bytes.extend_from_slice(b"4 0 obj\n99\nendobj\n");
    let xref = fixture.bytes.len();
    write!(fixture.bytes, "xref\n4 64\n{offset:010} 00000 n \n").unwrap();
    for _ in 0..63 {
        fixture.bytes.extend_from_slice(b"0000000000 00000 f \n");
    }
    write!(
        fixture.bytes,
        "trailer\n<< /Size 68 /Root 1 0 R /Prev {previous_xref} >>\nstartxref\n{xref}\n%%EOF\n"
    )
    .unwrap();
    for strict in [false, true] {
        // Neither section exceeds 64 entries, and only four objects are live.
        // The older section's four entries still make the cumulative total 68.
        let document = Document::load_mem_with_options(&fixture.bytes, options(strict, Some(0), Some(68))).unwrap();
        assert_eq!(document.get_object((4, 0)).unwrap().as_i64().unwrap(), 99);
        assert_limit(Document::load_mem_with_options(&fixture.bytes, options(strict, Some(0), Some(64))));
    }
}

#[test]
fn reconstructed_xref_stream_keeps_decoding_and_entry_limits() {
    let fixture = Pdf::new().finish_xref(3, 128, true);
    let document = Document::load_mem_with_options(&fixture.bytes, options(false, Some(1024), Some(128))).unwrap();
    assert_eq!(document.catalog().unwrap().get(b"Type").unwrap().as_name().unwrap(), b"Catalog");
    assert_limit(Document::load_mem_with_options(&fixture.bytes, options(false, Some(128), Some(256))));
    assert_limit(Document::load_mem_with_options(&fixture.bytes, options(false, Some(1024), Some(16))));
}

fn xref_with_dictionary_arrays(widths: &str, index: &str) -> Fixture {
    let mut pdf = Pdf::new();
    let xref_offset = pdf.bytes.len();
    let mut rows = Vec::new();
    for number in 0..4 {
        let row = if number == 3 {
            xref_row(1, u32::try_from(xref_offset).unwrap(), 0)
        } else {
            pdf.entries.get(&number).copied().unwrap_or_else(|| xref_row(0, 0, 0))
        };
        rows.extend_from_slice(&row);
    }
    pdf.compressed_stream(
        3,
        &format!("/Type /XRef /Size 4 /W [{widths}] /Index [{index}] /Root 1 0 R"),
        &rows,
    );
    write!(pdf.bytes, "startxref\n{xref_offset}\n%%EOF\n").unwrap();
    Fixture {
        bytes: pdf.bytes,
        decoded_bytes: pdf.decoded_bytes,
    }
}

#[test]
fn parser_budget_stops_xref_arrays_before_invalid_tail() {
    let oversized_index = format!("0 4 {}!", "0 0 ".repeat(32));
    let oversized_widths = format!("1 4 2 {}!", "0 ".repeat(64));
    let fixtures = [
        xref_with_dictionary_arrays("1 4 2", &oversized_index),
        xref_with_dictionary_arrays(&oversized_widths, "0 4"),
    ];
    for fixture in fixtures {
        for strict in [false, true] {
            // The invalid token lies after the member cap. A syntax error or
            // successful recovery means parsing reached input it should not read.
            assert_limit(Document::load_mem_with_options(
                &fixture.bytes,
                options(strict, Some(1024), Some(16)),
            ));
        }
    }
}

#[test]
fn parser_budget_bounds_valid_xref_index_before_expansion() {
    // All extra sections contain zero entries, so the decoded xref remains four
    // rows. Only the dictionary array itself exceeds the low member budget.
    let index = format!("0 4 {}", "0 0 ".repeat(32));
    let fixture = xref_with_dictionary_arrays("1 4 2", &index);
    for strict in [false, true] {
        let document = Document::load_mem_with_options(
            &fixture.bytes,
            options(strict, Some(1024), Some(512)),
        )
        .unwrap();
        assert_eq!(document.catalog().unwrap().get(b"Type").unwrap().as_name().unwrap(), b"Catalog");
        assert_limit(Document::load_mem_with_options(
            &fixture.bytes,
            options(strict, Some(1024), Some(16)),
        ));
    }
}

#[test]
fn parser_budget_bounds_valid_nested_array_members() {
    let mut pdf = Pdf::new();
    pdf.object(3, format!("[[{}]]", "0 ".repeat(64)).as_bytes());
    let fixture = pdf.finish_classic(4, false);
    for strict in [false, true] {
        let document = Document::load_mem_with_options(
            &fixture.bytes,
            options(strict, Some(0), Some(128)),
        )
        .unwrap();
        let outer = document.get_object((3, 0)).unwrap().as_array().unwrap();
        assert_eq!(outer.len(), 1);
        let inner = outer[0].as_array().unwrap();
        assert_eq!(inner.len(), 64);
        assert!(inner.iter().all(|value| value.as_i64().unwrap() == 0));
        assert_limit(Document::load_mem_with_options(
            &fixture.bytes,
            options(strict, Some(0), Some(16)),
        ));
    }
}
