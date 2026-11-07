//! Deterministic offline codec fixtures, including hostile input and actual member retrieval.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_storage::archive::{cdxj, validate_path, wacz, warc, ArchiveError, Limits};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

fn header(id: u8, kind: &str) -> warc::RecordHeader {
    let mut fields = BTreeMap::from([
        ("WARC-Type".into(), kind.into()),
        (
            "WARC-Record-ID".into(),
            format!("<urn:uuid:00000000-0000-8000-8000-{id:012}>"),
        ),
        ("WARC-Date".into(), "2026-11-04T12:34:56.789Z".into()),
        ("Content-Type".into(), "text/plain; charset=utf-8".into()),
    ]);
    if kind != "warcinfo" {
        fields.insert(
            "WARC-Target-URI".into(),
            "https://example.test/Case?Q=Value".into(),
        );
    }
    warc::RecordHeader {
        fields,
        payload_offset: 0,
    }
}
fn add(output: &mut Cursor<Vec<u8>>, id: u8, kind: &str, bytes: &[u8]) -> warc::RecordSummary {
    warc::write_record(
        output,
        &header(id, kind),
        &mut Cursor::new(bytes),
        bytes.len() as u64,
        Limits::default(),
    )
    .unwrap()
}
fn raw(kind: &str, id: u8, fields: &str, block: &[u8]) -> Vec<u8> {
    let target = if kind == "warcinfo" {
        ""
    } else {
        "WARC-Target-URI: https://example.test/Case?Q=Value\r\n"
    };
    let mut bytes = format!("WARC/1.1\r\nWARC-Type: {kind}\r\nWARC-Record-ID: <urn:uuid:00000000-0000-8000-8000-{id:012}>\r\nWARC-Date: 2026-11-04T12:34:56.789Z\r\n{target}Content-Type: text/plain\r\nContent-Length: {}\r\n{fields}\r\n", block.len()).into_bytes();
    bytes.extend_from_slice(block);
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes
}

#[test]
fn gzip_members_have_exact_ranges_fixity_and_deterministic_dates() {
    let make = || {
        let mut output = Cursor::new(Vec::new());
        let first = add(&mut output, 1, "resource", b"first actual payload");
        let second = add(&mut output, 2, "resource", b"second actual payload");
        (output.into_inner(), first, second)
    };
    let (bytes, first, second) = make();
    assert_eq!(bytes, make().0);
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    assert_eq!(first.offset, 0);
    assert_eq!(first.length, second.offset);
    assert_eq!(second.offset + second.length, bytes.len() as u64);
    let rows = warc::inspect(Cursor::new(&bytes), true, Limits::default()).unwrap();
    assert_eq!(rows[0].payload_digest, warc::digest(b"first actual payload"));
    assert_eq!(rows[1].date.to_rfc3339(), "2026-11-04T12:34:56.789+00:00");
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&bytes), &rows[1], true, Limits::default()).unwrap(),
        b"second actual payload"
    );
    let mut wrong = rows[1].clone();
    wrong.offset += 1;
    assert!(warc::payload_at(&mut Cursor::new(&bytes), &wrong, true, Limits::default()).is_err());
}

#[test]
fn warcinfo_has_no_synthetic_payload_digest_or_target() {
    let mut output = Cursor::new(Vec::new());
    add(&mut output, 1, "warcinfo", b"software: crawlx\r\n");
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(output.get_ref().as_slice())
        .read_to_string(&mut decoded)
        .unwrap();
    assert!(!decoded.to_lowercase().contains("warc-payload-digest:"));
    assert!(!decoded.to_lowercase().contains("warc-target-uri:"));
    assert!(warc::inspect(Cursor::new(output.into_inner()), true, Limits::default()).is_ok());
}

#[test]
fn http_response_digest_excludes_headers_and_preserves_target_status() {
    let body = b"HTTP/1.1 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nX-Repeat: one\r\nX-Repeat: two\r\n\r\nhello";
    let mut input = header(1, "response");
    input.payload_offset = (body.len() - 5) as u64;
    input
        .fields
        .insert("Content-Type".into(), "application/http; msgtype=response".into());
    let mut output = Cursor::new(Vec::new());
    let written = warc::write_record(
        &mut output,
        &input,
        &mut Cursor::new(body),
        body.len() as u64,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(written.status, Some(206));
    let records = warc::inspect(Cursor::new(output.get_ref()), true, Limits::default()).unwrap();
    assert_eq!(records[0].payload_digest, warc::digest(b"hello"));
    assert_eq!(records[0].status, Some(206));
    assert_eq!(
        warc::payload_at(
            &mut Cursor::new(output.get_ref()),
            &records[0],
            true,
            Limits::default()
        )
        .unwrap(),
        b"hello"
    );
}

#[test]
fn imports_decode_real_chunked_payload_without_claiming_wire_normalization() {
    let block = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3;ext=1\r\nllo\r\n0\r\n\r\n";
    let fields = format!(
        "WARC-Block-Digest: {}\r\nWARC-Payload-Digest: {}\r\n",
        warc::digest(block),
        warc::digest(b"hello")
    );
    let bytes = raw("response", 1, &fields, block);
    let records = warc::inspect(Cursor::new(&bytes), false, Limits::default()).unwrap();
    assert!(records[0].transfer_chunked);
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&bytes), &records[0], false, Limits::default()).unwrap(),
        b"hello"
    );
    let bad = raw(
        "response",
        1,
        "",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nshort\r\n0\r\n\r\n",
    );
    assert!(warc::inspect(Cursor::new(bad), false, Limits::default()).is_err());
}

#[test]
fn malformed_lengths_headers_digests_requests_and_gzip_fail_closed() {
    let valid = raw(
        "resource",
        1,
        &format!("WARC-Payload-Digest: {}\r\n", warc::digest(b"hello")),
        b"hello",
    );
    let text = String::from_utf8(valid.clone()).unwrap();
    for invalid in [
        text.replace("Content-Length: 5", "Content-Length: 6"),
        text.replace("Content-Length: 5", "Content-Length: 5\r\nContent-Length: 5"),
        text.replace("\r\n", "\n"),
        text.replace("hello", "jello"),
        text.replace("WARC-Date: 2026-11-04T12:34:56.789Z", "WARC-Date: nope"),
    ] {
        assert!(warc::inspect(Cursor::new(invalid), false, Limits::default()).is_err());
    }
    assert!(warc::inspect(
        Cursor::new(raw("request", 1, "", b"BAD METHOD / HTTP/1.1\r\n\r\n")),
        false,
        Limits::default()
    )
    .is_err());
    let mut output = Cursor::new(Vec::new());
    add(&mut output, 1, "resource", b"hello");
    let mut gzip = output.into_inner();
    let trailer = gzip.len() - 8;
    gzip[trailer] ^= 1;
    assert!(warc::inspect(Cursor::new(gzip), true, Limits::default()).is_err());
    let mut limits = Limits::default();
    limits.record_bytes = 4;
    assert!(matches!(
        warc::inspect(Cursor::new(valid), false, limits),
        Err(ArchiveError::Limit(_))
    ));
}

#[test]
fn unknown_records_are_classified_without_executing_or_silently_dropping_them() {
    let records = warc::inspect(
        Cursor::new(raw("vendor-custom", 1, "", b"do not execute me")),
        false,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, "vendor-custom");
    assert!(!records[0].known_type);
}

#[test]
fn revisit_requires_a_resolvable_baseline_and_matching_payload_digest() {
    let baseline = raw("resource", 1, "", b"hello");
    let fields = format!("WARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Refers-To: <urn:uuid:00000000-0000-8000-8000-000000000001>\r\nWARC-Payload-Digest: {}\r\n", warc::digest(b"hello"));
    let revisit = raw("revisit", 2, &fields, b"");
    assert!(warc::inspect(Cursor::new(&revisit), false, Limits::default()).is_err());
    let mut valid = baseline.clone();
    valid.extend_from_slice(&revisit);
    assert_eq!(
        warc::inspect(Cursor::new(valid), false, Limits::default())
            .unwrap()
            .len(),
        2
    );
    let mut wrong = baseline;
    wrong.extend_from_slice(&raw(
        "revisit",
        2,
        &fields.replace(&warc::digest(b"hello"), &warc::digest(b"other")),
        b"",
    ));
    assert!(warc::inspect(Cursor::new(wrong), false, Limits::default()).is_err());
}

#[test]
fn bounded_continuations_validate_order_logical_fixity_and_final_length() {
    let digest = warc::digest(b"abcdef");
    let first = raw(
        "resource",
        1,
        &format!("WARC-Segment-Number: 1\r\nWARC-Payload-Digest: {digest}\r\n"),
        b"abc",
    );
    let tail_fields = format!("WARC-Segment-Number: 2\r\nWARC-Segment-Origin-ID: <urn:uuid:00000000-0000-8000-8000-000000000001>\r\nWARC-Segment-Total-Length: 6\r\nWARC-Payload-Digest: {digest}\r\n");
    let mut full = first.clone();
    full.extend_from_slice(&raw("continuation", 2, &tail_fields, b"def"));
    assert_eq!(
        warc::inspect(Cursor::new(full), false, Limits::default())
            .unwrap()
            .len(),
        2
    );
    assert!(warc::inspect(Cursor::new(&first), false, Limits::default()).is_err());
    for tail in [
        tail_fields.replace("Number: 2", "Number: 3"),
        tail_fields.replace("Length: 6", "Length: 9"),
    ] {
        let mut invalid = first.clone();
        invalid.extend_from_slice(&raw("continuation", 2, &tail, b"def"));
        assert!(warc::inspect(Cursor::new(invalid), false, Limits::default()).is_err());
    }
}

#[test]
fn import_retention_classification_detects_binary_credentials_and_session_urls() {
    for (fields, body) in [
        ("", b"cookie=CANARY_COOKIE".as_slice()),
        ("", &[0xff, 0x00]),
        ("WARC-Extra-Token: CANARY_TOKEN\r\n", b"safe".as_slice()),
    ] {
        let records = warc::inspect(
            Cursor::new(raw("resource", 1, fields, body)),
            false,
            Limits::default(),
        )
        .unwrap();
        assert!(!records[0].retention_approved);
    }
    let input = String::from_utf8(raw("resource", 1, "", b"safe"))
        .unwrap()
        .replace("?Q=Value", "?SESSION=CANARY_SESSION");
    assert!(!warc::inspect(Cursor::new(input), false, Limits::default()).unwrap()[0].retention_approved);
}

fn package(index_mutation: bool) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let mut warc_output = Cursor::new(Vec::new());
    let record = add(&mut warc_output, 1, "resource", b"actual archived payload");
    let mut entry = cdxj::Entry::from_record(&record, "data.warc.gz").unwrap();
    if index_mutation {
        entry.offset += 1;
    }
    let inputs = [
        ("archive/data.warc.gz", warc_output.into_inner()),
        ("indexes/index.cdxj", entry.line(&record).unwrap().into_bytes()),
        ("pages/pages.jsonl", b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\"}\n{\"url\":\"https://example.test/Case?Q=Value\",\"ts\":\"2026-11-04T12:34:56.789Z\"}\n".to_vec()),
    ];
    let files = inputs
        .iter()
        .enumerate()
        .map(|(index, (name, bytes))| {
            let path = dir.path().join(index.to_string());
            std::fs::write(&path, bytes).unwrap();
            ((*name).to_owned(), path)
        })
        .collect::<Vec<_>>();
    wacz::write(
        Cursor::new(Vec::new()),
        &files,
        "2026-11-04T12:34:56.789Z",
        Limits::default(),
    )
    .unwrap()
    .into_inner()
}

#[test]
fn wacz_zip64_resources_manifest_last_and_payload_roundtrip_are_real() {
    let bytes = package(false);
    assert_eq!(bytes, package(false));
    let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let count = zip.len();
    assert_eq!(
        zip.by_index(count - 2).unwrap().name().unwrap(),
        "datapackage.json"
    );
    assert_eq!(
        zip.by_index(count - 1).unwrap().name().unwrap(),
        "datapackage-digest.json"
    );
    assert_eq!(
        zip.by_name("archive/data.warc.gz").unwrap().compression(),
        CompressionMethod::Stored
    );
    let inspection = wacz::inspect(Cursor::new(&bytes), Limits::default()).unwrap();
    assert_eq!(inspection.indexed, 1);
    assert_eq!(inspection.pages, 1);
    let record = &inspection.records["archive/data.warc.gz"][0];
    assert_eq!(
        wacz::payload(
            Cursor::new(&bytes),
            "archive/data.warc.gz",
            record,
            Limits::default()
        )
        .unwrap(),
        b"actual archived payload"
    );
    assert!(wacz::inspect(Cursor::new(package(true)), Limits::default()).is_err());
}

#[test]
fn cdx_sort_is_byte_ordered_without_mutating_record_urls_and_checks_ranges() {
    assert_eq!(
        cdxj::searchable_url("https://WWW.Example.test/Case?Q=Value").unwrap(),
        "test,example,www)/case?q=value"
    );
    let mut output = Cursor::new(Vec::new());
    let a = add(&mut output, 1, "resource", b"one");
    let b = add(&mut output, 2, "resource", b"two");
    let mut sorter = cdxj::Sorter::new().unwrap();
    let mut first = cdxj::Entry::from_record(&a, "data.warc.gz").unwrap();
    first.url = "https://z.test/Case".into();
    let mut second = cdxj::Entry::from_record(&b, "data.warc.gz").unwrap();
    second.url = "https://a.test/Case".into();
    sorter.push(first.line(&a).unwrap()).unwrap();
    sorter.push(second.line(&b).unwrap()).unwrap();
    let mut sorted = Vec::new();
    sorter.finish(&mut sorted).unwrap();
    let text = String::from_utf8(sorted).unwrap();
    assert!(text.starts_with("test,a)/case "));
    assert!(text.contains("https://a.test/Case"));
    let mut members = BTreeMap::new();
    members.insert(("data.warc.gz".into(), a.offset), a.clone());
    let entry = cdxj::Entry::from_record(&a, "data.warc.gz").unwrap();
    assert_eq!(
        cdxj::validate(Cursor::new(entry.line(&a).unwrap()), &members, Limits::default()).unwrap(),
        1
    );
    let mut wrong = entry;
    wrong.length += 1;
    assert!(cdxj::validate(Cursor::new(wrong.line(&a).unwrap()), &members, Limits::default()).is_err());
}

#[test]
fn zip_traversal_bombs_and_resource_fixity_corruption_are_rejected() {
    for path in [
        "../escape",
        "/absolute",
        "a/../b",
        "a\\b",
        "C:/file",
        "a//b",
        "./file",
    ] {
        assert!(validate_path(path).is_err());
    }
    let mut output = ZipWriter::new(Cursor::new(Vec::new()));
    output
        .start_file("../escape", SimpleFileOptions::default())
        .unwrap();
    output.write_all(b"evil").unwrap();
    assert!(wacz::inspect(
        Cursor::new(output.finish().unwrap().into_inner()),
        Limits::default()
    )
    .is_err());
    let bomb = wacz::inspect(Cursor::new(valid_expansion_bomb()), Limits::default());
    assert!(matches!(&bomb, Err(ArchiveError::Limit(_))), "{bomb:?}");
    let bytes = package(false);
    let mut source = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut output = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..source.len() {
        let mut entry = source.by_index(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        if name == "pages/pages.jsonl" {
            bytes[1] ^= 1;
        }
        output
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        output.write_all(&bytes).unwrap();
    }
    assert!(wacz::inspect(
        Cursor::new(output.finish().unwrap().into_inner()),
        Limits::default()
    )
    .is_err());
}

#[test]
fn count_and_expansion_limits_apply_before_unbounded_collection_growth() {
    let mut output = Cursor::new(Vec::new());
    add(&mut output, 1, "resource", b"aaaa");
    add(&mut output, 2, "resource", b"bbbb");
    let mut limits = Limits::default();
    limits.records = 1;
    assert!(warc::inspect(Cursor::new(output.get_ref()), true, limits).is_err());
    limits.records = 10;
    limits.expanded_bytes = 7;
    assert!(warc::inspect(Cursor::new(output.get_ref()), true, limits).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package.wacz");
    std::fs::write(&path, package(false)).unwrap();
    let mut limits = Limits::default();
    limits.resources = 1;
    assert!(wacz::inspect(File::open(path).unwrap(), limits).is_err());
}

#[test]
fn dependency_cycles_and_multiple_records_in_one_gzip_member_are_rejected() {
    let mut cycle = raw(
        "metadata",
        1,
        "WARC-Refers-To: <urn:uuid:00000000-0000-8000-8000-000000000002>\r\n",
        b"first",
    );
    cycle.extend_from_slice(&raw(
        "metadata",
        2,
        "WARC-Refers-To: <urn:uuid:00000000-0000-8000-8000-000000000001>\r\n",
        b"second",
    ));
    assert!(warc::inspect(Cursor::new(cycle), false, Limits::default()).is_err());
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw("resource", 1, "", b"first")).unwrap();
    encoder.write_all(&raw("resource", 2, "", b"second")).unwrap();
    assert!(warc::inspect(Cursor::new(encoder.finish().unwrap()), true, Limits::default()).is_err());
    let mut encoded = Cursor::new(Vec::new());
    add(&mut encoded, 1, "resource", b"actual");
    let records = warc::inspect(Cursor::new(encoded.get_ref()), true, Limits::default()).unwrap();
    let mut invalid_range = records[0].clone();
    invalid_range.length += 1;
    assert!(warc::payload_at(
        &mut Cursor::new(encoded.get_ref()),
        &invalid_range,
        true,
        Limits::default()
    )
    .is_err());
}

fn valid_expansion_bomb() -> Vec<u8> {
    let bomb = vec![b'a'; 4 * 1024 * 1024];
    let mut source = ZipArchive::new(Cursor::new(package(false))).unwrap();
    let mut manifest_bytes = Vec::new();
    source
        .by_name("datapackage.json")
        .unwrap()
        .read_to_end(&mut manifest_bytes)
        .unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    manifest["resources"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "name":"bomb.txt","path":"notes/bomb.txt","hash":warc::digest(&bomb),"bytes":bomb.len()
        }));
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let digest =
        serde_json::to_vec(&serde_json::json!({"path":"datapackage.json","hash":warc::digest(&manifest)}))
            .unwrap();
    let mut output = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..source.len() {
        let mut entry = source.by_index(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        let bytes = match name.as_str() {
            "datapackage.json" => manifest.as_slice(),
            "datapackage-digest.json" => digest.as_slice(),
            _ => bytes.as_slice(),
        };
        output
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        output.write_all(bytes).unwrap();
    }
    output
        .start_file(
            "notes/bomb.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    output.write_all(&bomb).unwrap();
    output.finish().unwrap().into_inner()
}

#[test]
fn zip_directory_counts_and_metadata_ranges_are_bounded_before_library_allocation() {
    let original = package(false);
    let end = original
        .windows(4)
        .rposition(|part| part == b"PK\x05\x06")
        .unwrap();
    let mut count = original.clone();
    count[end + 8..end + 10].copy_from_slice(&1000u16.to_le_bytes());
    count[end + 10..end + 12].copy_from_slice(&1000u16.to_le_bytes());
    assert!(matches!(
        wacz::inspect(Cursor::new(count), Limits::default()),
        Err(ArchiveError::Limit(_))
    ));
    let mut range = original.clone();
    range[end + 16..end + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        wacz::inspect(Cursor::new(range), Limits::default()),
        Err(ArchiveError::Invalid(_))
    ));
    // A ZIP comment is format-valid but not approved for byte-identical durable import.
    let mut commented = original;
    let comment = b"SESSION=CANARY_ZIP_SECRET";
    commented[end + 20..end + 22].copy_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
    commented.extend_from_slice(comment);
    assert!(
        !wacz::inspect(Cursor::new(commented), Limits::default())
            .unwrap()
            .zip_metadata_retention_approved
    );
}
