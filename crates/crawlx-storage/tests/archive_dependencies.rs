//! Logical payload materialization and explicit zero-network local dependency capabilities.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::archive::ArchiveManifestV1;
use crawlx_core::TenantId;
use crawlx_storage::archive::{
    cdxj,
    collection::{ApprovedLocalDependency, ArchiveCollection},
    wacz, warc, ArchiveError, Limits,
};
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::Path;

const DATE: &str = "2026-11-04T12:34:56.789Z";
fn id(number: u16) -> String {
    format!("<urn:uuid:00000000-0000-8000-8000-{number:012}>")
}
fn tenant(number: u16) -> TenantId {
    format!("00000000-0000-8000-8000-{number:012}").parse().unwrap()
}
fn record(number: u16, kind: &str, url: &str, extra: &str, block: &[u8]) -> Vec<u8> {
    let mime = if kind == "response" {
        "application/http; msgtype=response"
    } else {
        "text/plain"
    };
    let mut bytes = format!("WARC/1.1\r\nWARC-Type: {kind}\r\nWARC-Record-ID: {}\r\nWARC-Date: {DATE}\r\nWARC-Target-URI: {url}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nWARC-Block-Digest: {}\r\n{extra}\r\n", id(number), block.len(), warc::digest(block)).into_bytes();
    bytes.extend_from_slice(block);
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes
}
fn summary(bytes: &[u8]) -> warc::RecordSummary {
    let (mut summary, _) = warc::read_record(&mut Cursor::new(bytes), Limits::default()).unwrap();
    summary.offset = 0;
    summary.length = bytes.len() as u64;
    summary
}
fn segments(
    number: u16,
    kind: &str,
    url: &str,
    first: &[u8],
    tail: &[u8],
    payload: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let hash = warc::digest(payload);
    let start = record(
        number,
        kind,
        url,
        &format!("WARC-Segment-Number: 1\r\nWARC-Payload-Digest: {hash}\r\n"),
        first,
    );
    let end = record(number + 1, "continuation", url, &format!("WARC-Segment-Origin-ID: {}\r\nWARC-Segment-Number: 2\r\nWARC-Segment-Total-Length: {}\r\nWARC-Payload-Digest: {hash}\r\n", id(number), first.len() + tail.len()), tail);
    (start, end)
}
fn revisit(number: u16, baseline: u16, payload: &[u8]) -> Vec<u8> {
    record(number, "revisit", "https://example.test/revisit", &format!("WARC-Refers-To: {}\r\nWARC-Refers-To-Target-URI: https://example.test/source\r\nWARC-Refers-To-Date: {DATE}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Payload-Digest: {}\r\n", id(baseline), warc::digest(payload)), b"")
}
fn package(
    records: &[(&str, Vec<u8>)],
    indexes: &[(&str, warc::RecordSummary)],
    owner: Option<TenantId>,
) -> Vec<u8> {
    let scratch = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    for (index, (name, bytes)) in records.iter().enumerate() {
        let path = scratch.path().join(format!("record-{index}"));
        std::fs::write(&path, bytes).unwrap();
        files.push((format!("archive/{name}"), path));
    }
    let index_path = scratch.path().join("index.cdxj");
    let mut sorter = cdxj::Sorter::new().unwrap();
    let pages_path = scratch.path().join("pages.jsonl");
    let mut pages = File::create(&pages_path).unwrap();
    pages
        .write_all(b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\"}\n")
        .unwrap();
    for (filename, record) in indexes {
        sorter
            .push(
                cdxj::Entry::from_record(record, filename)
                    .unwrap()
                    .line(record)
                    .unwrap(),
            )
            .unwrap();
        serde_json::to_writer(
            &mut pages,
            &serde_json::json!({"url":record.target,"ts":warc::date(record.date)}),
        )
        .unwrap();
        pages.write_all(b"\n").unwrap();
    }
    pages.flush().unwrap();
    sorter.finish(&mut File::create(&index_path).unwrap()).unwrap();
    files.push(("indexes/index.cdxj".into(), index_path));
    files.push(("pages/pages.jsonl".into(), pages_path));
    if let Some(owner) = owner {
        let path = scratch.path().join("manifest.json");
        let manifest = ArchiveManifestV1::available(
            owner,
            "00000000-0000-8000-8000-000000000999".parse().unwrap(),
            chrono::DateTime::parse_from_rfc3339(DATE)
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        files.push(("crawlx/manifest.json".into(), path));
    }
    wacz::write(Cursor::new(Vec::new()), &files, DATE, Limits::default())
        .unwrap()
        .into_inner()
}

#[test]
fn standalone_continuations_materialize_actual_logical_bytes_and_revisits() {
    let (first, last) = segments(
        1,
        "resource",
        "https://example.test/source",
        b"abc",
        b"def",
        b"abcdef",
    );
    let mut file = first;
    file.extend_from_slice(&last);
    file.extend_from_slice(&revisit(3, 1, b"abcdef"));
    let rows = warc::inspect(Cursor::new(&file), false, Limits::default()).unwrap();
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&file), &rows[0], false, Limits::default()).unwrap(),
        b"abcdef"
    );
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&file), &rows[1], false, Limits::default()).unwrap(),
        b"abcdef"
    );
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&file), &rows[2], false, Limits::default()).unwrap(),
        b"abcdef"
    );
    let mut limits = Limits::default();
    limits.record_bytes = 4;
    assert!(matches!(
        warc::inspect(Cursor::new(&file), false, limits),
        Err(ArchiveError::Limit(_))
    ));
}

#[test]
fn split_http_headers_and_chunk_framing_materialize_before_payload_fixity() {
    let first = b"HTTP/1.1 200 OK\r\nContent-T";
    let tail = b"ype: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n";
    let (start, end) = segments(
        10,
        "response",
        "https://example.test/source",
        first,
        tail,
        b"hello",
    );
    let mut bytes = start;
    bytes.extend_from_slice(&end);
    let rows = warc::inspect(Cursor::new(&bytes), false, Limits::default()).unwrap();
    assert_eq!(rows[0].status, Some(200));
    assert_eq!(rows[0].mime, "text/plain");
    assert!(rows[0].transfer_chunked);
    assert_eq!(rows[0].payload_digest, warc::digest(b"hello"));
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&bytes), &rows[0], false, Limits::default()).unwrap(),
        b"hello"
    );
}

#[test]
fn logical_privacy_gate_sees_utf8_and_secret_values_across_segment_boundaries() {
    let (first, last) = segments(
        20,
        "resource",
        "https://example.test/source",
        b"caf\xc3",
        b"\xa9",
        "café".as_bytes(),
    );
    let mut input = first;
    input.extend_from_slice(&last);
    let records = warc::inspect(Cursor::new(&input), false, Limits::default()).unwrap();
    assert!(records.iter().all(|record| record.retention_approved));
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&input), &records[0], false, Limits::default()).unwrap(),
        "café".as_bytes()
    );
    let (first, last) = segments(
        22,
        "resource",
        "https://example.test/source",
        b"cook",
        b"ie=CANARY_SESSION",
        b"cookie=CANARY_SESSION",
    );
    let mut input = first;
    input.extend_from_slice(&last);
    assert!(warc::inspect(Cursor::new(input), false, Limits::default())
        .unwrap()
        .iter()
        .all(|record| !record.retention_approved));
}

#[test]
fn wacz_closure_spans_actual_local_warc_members_not_just_one_file() {
    let (start, end) = segments(
        30,
        "resource",
        "https://example.test/source",
        b"actual ",
        b"payload",
        b"actual payload",
    );
    let origin = summary(&start);
    let bytes = package(
        &[("start.warc", start), ("tail.warc", end)],
        &[("start.warc", origin)],
        None,
    );
    let inspected = wacz::inspect(Cursor::new(&bytes), Limits::default()).unwrap();
    let origin = &inspected.records["archive/start.warc"][0];
    assert_eq!(
        wacz::payload(
            Cursor::new(&bytes),
            "archive/start.warc",
            origin,
            Limits::default()
        )
        .unwrap(),
        b"actual payload"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_bundle_revisit_resolves_and_imported_wacz_is_self_contained() {
    let root = tempfile::tempdir().unwrap();
    let payload = b"actual baseline payload";
    let baseline = record(40, "resource", "https://example.test/source", "", payload);
    let baseline_summary = summary(&baseline);
    let dependency = package(
        &[("baseline.warc", baseline)],
        &[("baseline.warc", baseline_summary)],
        Some(tenant(1)),
    );
    let repeated = revisit(41, 40, payload);
    let repeated_summary = summary(&repeated);
    let primary = package(
        &[("revisit.warc", repeated)],
        &[("revisit.warc", repeated_summary)],
        Some(tenant(1)),
    );
    let dependency_path = root.path().join("baseline.wacz");
    let primary_path = root.path().join("primary.wacz");
    std::fs::write(&dependency_path, &dependency).unwrap();
    std::fs::write(&primary_path, &primary).unwrap();
    assert!(wacz::inspect(Cursor::new(&primary), Limits::default()).is_err());
    let approved = ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("baseline.wacz"),
        &warc::digest(&dependency),
        Limits::default(),
    )
    .unwrap();
    let mut collection =
        ArchiveCollection::open(&primary_path, Some(tenant(1)), vec![approved], Limits::default()).unwrap();
    assert_eq!(
        collection.source_sha256().collect::<Vec<_>>(),
        vec![warc::digest(&primary), warc::digest(&dependency)]
    );
    let resolved = collection.payload(&id(41)).unwrap();
    assert_eq!(resolved.bytes, payload);
    assert_eq!(resolved.requested.id, id(41));
    assert_eq!(resolved.source.id, id(40));
    assert_eq!(
        resolved.source.target.as_deref(),
        Some("https://example.test/source")
    );
    let closed = collection
        .write_closed_wacz(Cursor::new(Vec::new()))
        .unwrap()
        .into_inner();
    let inspected = wacz::inspect(Cursor::new(&closed), Limits::default()).unwrap();
    assert_eq!(inspected.tenant, Some(tenant(1)));
    assert_eq!(inspected.indexed, 2);
    let revisit = inspected.records["archive/data.warc.gz"]
        .iter()
        .find(|record| record.id == id(41))
        .unwrap();
    assert_eq!(
        wacz::payload(
            Cursor::new(&closed),
            "archive/data.warc.gz",
            revisit,
            Limits::default()
        )
        .unwrap(),
        payload
    );
    let mut snapshot =
        ArchiveCollection::from_snapshot(closed, Some(tenant(1)), vec![], Limits::default()).unwrap();
    assert_eq!(snapshot.payload(&id(41)).unwrap().bytes, payload);
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_bundle_can_supply_continuation_and_missing_source_never_refetches() {
    let root = tempfile::tempdir().unwrap();
    let (start, end) = segments(
        50,
        "resource",
        "https://example.test/source",
        b"before",
        b"after",
        b"beforeafter",
    );
    let origin = summary(&start);
    let primary = package(&[("start.warc", start)], &[("start.warc", origin)], None);
    let dependency = package(&[("end.warc", end)], &[], None);
    std::fs::write(root.path().join("primary.wacz"), &primary).unwrap();
    std::fs::write(root.path().join("tail.wacz"), &dependency).unwrap();
    assert!(ArchiveCollection::open(
        &root.path().join("primary.wacz"),
        Some(tenant(1)),
        vec![],
        Limits::default()
    )
    .is_err());
    let approved = ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("tail.wacz"),
        &warc::digest(&dependency),
        Limits::default(),
    )
    .unwrap();
    let mut collection = ArchiveCollection::open(
        &root.path().join("primary.wacz"),
        Some(tenant(1)),
        vec![approved],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(collection.payload(&id(50)).unwrap().bytes, b"beforeafter");
    assert!(matches!(
        ApprovedLocalDependency::open(
            tenant(1),
            root.path(),
            Path::new("https://outside.test/archive.wacz"),
            &warc::digest(&dependency),
            Limits::default()
        ),
        Err(ArchiveError::CapabilityUnavailable(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn dependency_capability_rejects_wrong_hash_tenant_traversal_symlinks_and_mutation() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let resource = record(60, "resource", "https://example.test/source", "", b"payload");
    let bytes = package(
        &[("data.warc", resource.clone())],
        &[("data.warc", summary(&resource))],
        Some(tenant(2)),
    );
    std::fs::write(root.path().join("foreign.wacz"), &bytes).unwrap();
    assert!(ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("foreign.wacz"),
        &warc::digest(&bytes),
        Limits::default()
    )
    .is_err());
    assert!(ApprovedLocalDependency::open(
        tenant(2),
        root.path(),
        Path::new("foreign.wacz"),
        &warc::digest(b"wrong"),
        Limits::default()
    )
    .is_err());
    assert!(ApprovedLocalDependency::open(
        tenant(2),
        root.path(),
        Path::new("../escape.wacz"),
        &warc::digest(&bytes),
        Limits::default()
    )
    .is_err());
    let outside_path = outside.path().join("outside.wacz");
    std::fs::write(&outside_path, &bytes).unwrap();
    std::os::unix::fs::symlink(&outside_path, root.path().join("link.wacz")).unwrap();
    assert!(ApprovedLocalDependency::open(
        tenant(2),
        root.path(),
        Path::new("link.wacz"),
        &warc::digest(&bytes),
        Limits::default()
    )
    .is_err());
    assert!(ArchiveCollection::open(
        &root.path().join("foreign.wacz"),
        Some(tenant(1)),
        vec![],
        Limits::default()
    )
    .is_err());
    let mut collection = ArchiveCollection::open(
        &root.path().join("foreign.wacz"),
        Some(tenant(2)),
        vec![],
        Limits::default(),
    )
    .unwrap();
    std::fs::write(root.path().join("foreign.wacz"), b"mutated source").unwrap();
    assert!(collection.payload(&id(60)).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn cross_bundle_cycles_duplicates_and_revisit_target_mismatch_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let a = revisit(70, 71, b"same");
    let b = record(71, "revisit", "https://example.test/source", &format!("WARC-Refers-To: {}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Payload-Digest: {}\r\n", id(70), warc::digest(b"same")), b"");
    let primary = package(&[("a.warc", a.clone())], &[("a.warc", summary(&a))], None);
    let dependency = package(&[("b.warc", b.clone())], &[("b.warc", summary(&b))], None);
    std::fs::write(root.path().join("a.wacz"), &primary).unwrap();
    std::fs::write(root.path().join("b.wacz"), &dependency).unwrap();
    let approved = ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("b.wacz"),
        &warc::digest(&dependency),
        Limits::default(),
    )
    .unwrap();
    assert!(ArchiveCollection::open(
        &root.path().join("a.wacz"),
        Some(tenant(1)),
        vec![approved],
        Limits::default()
    )
    .is_err());
    let approved = ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("a.wacz"),
        &warc::digest(&primary),
        Limits::default(),
    )
    .unwrap();
    assert!(ArchiveCollection::open(
        &root.path().join("a.wacz"),
        Some(tenant(1)),
        vec![approved],
        Limits::default()
    )
    .is_err());
    let baseline = record(71, "resource", "https://example.test/wrong-target", "", b"same");
    let dependency = package(
        &[("baseline.warc", baseline.clone())],
        &[("baseline.warc", summary(&baseline))],
        None,
    );
    std::fs::write(root.path().join("b.wacz"), &dependency).unwrap();
    let approved = ApprovedLocalDependency::open(
        tenant(1),
        root.path(),
        Path::new("b.wacz"),
        &warc::digest(&dependency),
        Limits::default(),
    )
    .unwrap();
    assert!(ArchiveCollection::open(
        &root.path().join("a.wacz"),
        Some(tenant(1)),
        vec![approved],
        Limits::default()
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_snapshot_has_exact_source_fixity_and_no_dependency_authority_by_default() {
    let bytes = record(
        80,
        "resource",
        "https://example.test/source",
        "",
        b"snapshot payload",
    );
    let hash = warc::digest(&bytes);
    let mut reader =
        ArchiveCollection::from_snapshot(bytes, Some(tenant(1)), vec![], Limits::default()).unwrap();
    assert_eq!(reader.primary_sha256(), hash);
    assert_eq!(reader.payload(&id(80)).unwrap().bytes, b"snapshot payload");
}

#[test]
fn target_date_revisit_and_not_modified_profile_resolve_without_invented_body() {
    let baseline = record(90, "resource", "https://example.test/source", "", b"real payload");
    let repeated = record(91, "revisit", "https://example.test/source",
        &format!("WARC-Refers-To-Target-URI: https://example.test/source\r\nWARC-Refers-To-Date: {DATE}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/server-not-modified\r\n"),
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n");
    let mut bytes = baseline.clone();
    bytes.extend_from_slice(&repeated);
    let rows = warc::inspect(Cursor::new(&bytes), false, Limits::default()).unwrap();
    assert_eq!(rows[1].status, Some(304));
    assert_eq!(rows[1].payload_digest, warc::digest(b"real payload"));
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&bytes), &rows[1], false, Limits::default()).unwrap(),
        b"real payload"
    );
    // An exact target/date pair must not silently choose among two representations.
    bytes.extend_from_slice(&record(
        92,
        "resource",
        "https://example.test/source",
        "",
        b"other payload",
    ));
    assert!(matches!(
        warc::inspect(Cursor::new(bytes), false, Limits::default()),
        Err(ArchiveError::Invalid(_))
    ));
    assert!(matches!(
        warc::inspect(Cursor::new(repeated), false, Limits::default()),
        Err(ArchiveError::CapabilityUnavailable(_))
    ));
}

#[test]
fn segmented_revisit_preserves_header_facts_and_rejects_hidden_stored_body() {
    let baseline = record(
        100,
        "resource",
        "https://example.test/source",
        "",
        b"real payload",
    );
    let fields = format!("WARC-Refers-To: {}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Payload-Digest: {}\r\nWARC-Segment-Number: 1\r\n", id(100), warc::digest(b"real payload"));
    let first = b"HTTP/1.1 200 OK\r\nContent-T";
    let tail = b"ype: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut bytes = baseline.clone();
    bytes.extend_from_slice(&record(
        101,
        "revisit",
        "https://example.test/source",
        &fields,
        first,
    ));
    bytes.extend_from_slice(&record(
        102,
        "continuation",
        "https://example.test/source",
        &format!(
            "WARC-Segment-Origin-ID: {}\r\nWARC-Segment-Number: 2\r\nWARC-Segment-Total-Length: {}\r\n",
            id(101),
            first.len() + tail.len()
        ),
        tail,
    ));
    let rows = warc::inspect(Cursor::new(&bytes), false, Limits::default()).unwrap();
    assert_eq!(rows[1].status, Some(200));
    assert_eq!(rows[1].mime, "text/plain");
    assert!(rows[1].transfer_chunked);
    assert_eq!(
        warc::payload_at(&mut Cursor::new(&bytes), &rows[1], false, Limits::default()).unwrap(),
        b"real payload"
    );
    let mut invalid = baseline;
    invalid.extend_from_slice(&record(103, "revisit", "https://example.test/source",
        &format!("WARC-Refers-To: {}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Payload-Digest: {}\r\n", id(100), warc::digest(b"real payload")),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhidden body"));
    let result = warc::inspect(Cursor::new(invalid), false, Limits::default());
    assert!(matches!(result, Err(ArchiveError::Invalid(_))), "{result:?}");
}

#[test]
fn unknown_revisit_profile_never_executes_and_encoded_session_url_is_not_approved() {
    let mut bytes = record(
        110,
        "resource",
        "https://example.test/source",
        "",
        b"real payload",
    );
    bytes.extend_from_slice(&record(
        111,
        "revisit",
        "https://example.test/source",
        &format!(
            "WARC-Refers-To: {}\r\nWARC-Profile: https://outside.test/execute\r\n",
            id(110)
        ),
        b"",
    ));
    assert!(matches!(
        warc::inspect(Cursor::new(bytes), false, Limits::default()),
        Err(ArchiveError::CapabilityUnavailable(_))
    ));
    let bytes = record(
        112,
        "resource",
        "https://example.test/source?%53ESSION=CANARY_SESSION",
        "",
        b"safe body",
    );
    assert!(!warc::inspect(Cursor::new(bytes), false, Limits::default()).unwrap()[0].retention_approved);
    assert!(warc::retention_safe_url(
        "https://example.test/source?ordinary=value"
    ));
}
