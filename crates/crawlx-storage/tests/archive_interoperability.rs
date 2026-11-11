//! Optional independent format-reader checks. No validator is installed or downloaded by this test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_storage::archive::{cdxj, wacz, warc, Limits};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Write as _};

// The reader package import is an explicit external tool contract, not a bundled renderer.
const READER: &str = r#"
import hashlib, importlib.metadata, io, json, sys, zipfile
from warcio.archiveiterator import ArchiveIterator  # wire-compat
assert importlib.metadata.version("warcio") == "1.8.2"  # wire-compat

expected = ["warcinfo", "request", "response", "resource", "metadata", "conversion", "revisit"]
def read_records(data):
    records = []
    for record in ArchiveIterator(io.BytesIO(data), check_digests=True):
        payload = record.content_stream().read()
        assert not record.digest_checker.problems, record.digest_checker.problems
        if record.rec_type != "revisit":
            assert record.digest_checker.passed is True
        records.append((record.rec_type, record.rec_headers.get_header("WARC-Record-ID"), payload))
    return records

with open(sys.argv[1], "rb") as source:
    records = read_records(source.read())
assert [r[0] for r in records] == expected
assert records[1][2] == b""
assert records[2][2] == b"response payload"
assert records[3][2] == b"resource payload"
assert records[5][2] == b"converted payload"
assert records[6][2] == b""

with zipfile.ZipFile(sys.argv[2]) as package:
    assert package.namelist()[-2:] == ["datapackage.json", "datapackage-digest.json"]
    assert package.testzip() is None
    manifest_bytes = package.read("datapackage.json")
    manifest = json.loads(manifest_bytes)
    fixity = json.loads(package.read("datapackage-digest.json"))
    assert fixity["hash"] == "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    assert manifest["wacz_version"] == "1.1.1"
    for resource in manifest["resources"]:
        data = package.read(resource["path"])
        assert len(data) == resource["bytes"]
        assert resource["hash"] == "sha256:" + hashlib.sha256(data).hexdigest()
        assert package.getinfo(resource["path"]).compress_type == zipfile.ZIP_STORED
        assert package.getinfo(resource["path"]).extract_version >= 45
    packed = read_records(package.read("archive/data.warc.gz"))
    assert packed == records
    lines = package.read("indexes/index.cdxj").splitlines()
    assert lines == sorted(lines)
    assert len(lines) == 6
    for line in lines:
        key, timestamp, entry = line.split(b" ", 2)
        assert key.startswith(b"test,example,archive)")
        assert len(timestamp) in (14, 17) and timestamp.isdigit()
        entry = json.loads(entry)
        data = package.read("archive/" + entry["filename"])
        member = data[entry["offset"]:entry["offset"] + entry["length"]]
        selected = read_records(member)
        assert len(selected) == 1
        assert selected[0] in records
        assert entry["url"].startswith("https://archive.example.test/")
    pages = package.read("pages/pages.jsonl").splitlines()
    assert len(pages) == 2
    assert json.loads(pages[1])["url"] == "https://archive.example.test/response"
print("independent WARC records, ZIP64 resources, package fixity and CDXJ member ranges verified")
"#;

#[test]
fn independent_reader_validates_record_matrix_zip64_fixity_and_member_ranges() {
    let Some(python) = std::env::var_os("CRAWLX_ARCHIVE_READER_PYTHON") else {
        eprintln!("skipping independent archive reader: CRAWLX_ARCHIVE_READER_PYTHON is absent");
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let warc_path = root.path().join("data.warc.gz");
    let index_path = root.path().join("index.cdxj");
    let pages_path = root.path().join("pages.jsonl");
    let mut output = File::create(&warc_path).unwrap();
    let mut index = cdxj::Sorter::new().unwrap();
    let response_headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nX-Fixture: one\r\nX-Fixture: two\r\n\r\n";
    let response = [response_headers.as_slice(), b"response payload"].concat();
    let request = b"GET /response HTTP/1.1\r\nHost: archive.example.test\r\n\r\n";
    let cases: [(&str, &[u8], u64); 7] = [
        (
            "warcinfo",
            b"software: CrawlX\r\nformat: WARC File Format 1.1\r\n",
            0,
        ),
        ("request", request, u64::try_from(request.len()).unwrap()),
        (
            "response",
            &response,
            u64::try_from(response_headers.len()).unwrap(),
        ),
        ("resource", b"resource payload", 0),
        ("metadata", b"fixture: metadata\r\n", 0),
        ("conversion", b"converted payload", 0),
        ("revisit", b"", 0),
    ];
    for (ordinal, (kind, body, payload_offset)) in cases.into_iter().enumerate() {
        let mut fields = BTreeMap::from([
            ("WARC-Type".into(), kind.into()),
            (
                "WARC-Record-ID".into(),
                format!("<urn:uuid:00000000-0000-8000-8000-{ordinal:012}>"),
            ),
            ("WARC-Date".into(), "2026-11-04T12:34:56.789Z".into()),
            ("Content-Type".into(), "text/plain".into()),
        ]);
        if kind != "warcinfo" {
            fields.insert(
                "WARC-Target-URI".into(),
                format!("https://archive.example.test/{kind}"),
            );
        }
        if matches!(kind, "request" | "response") {
            fields.insert("Content-Type".into(), format!("application/http; msgtype={kind}"));
        }
        if kind == "warcinfo" || kind == "metadata" {
            fields.insert("Content-Type".into(), "application/warc-fields".into());
        }
        if kind == "conversion" || kind == "revisit" {
            fields.insert(
                "WARC-Refers-To".into(),
                "<urn:uuid:00000000-0000-8000-8000-000000000003>".into(),
            );
        }
        if kind == "revisit" {
            fields.insert(
                "WARC-Profile".into(),
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest".into(),
            );
            fields.insert("WARC-Payload-Digest".into(), warc::digest(b"resource payload"));
        }
        let header = warc::RecordHeader {
            fields,
            payload_offset,
        };
        let record = warc::write_record(
            &mut output,
            &header,
            &mut Cursor::new(body),
            u64::try_from(body.len()).unwrap(),
            Limits::default(),
        )
        .unwrap();
        if kind != "warcinfo" {
            index
                .push(
                    cdxj::Entry::from_record(&record, "data.warc.gz")
                        .unwrap()
                        .line(&record)
                        .unwrap(),
                )
                .unwrap();
        }
    }
    output.flush().unwrap();
    index.finish(&mut File::create(&index_path).unwrap()).unwrap();
    std::fs::write(&pages_path, b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\"}\n{\"url\":\"https://archive.example.test/response\",\"ts\":\"2026-11-04T12:34:56.789Z\"}\n").unwrap();
    let package_path = root.path().join("fixture.wacz");
    wacz::write(
        File::create(&package_path).unwrap(),
        &[
            ("archive/data.warc.gz".into(), warc_path.clone()),
            ("indexes/index.cdxj".into(), index_path),
            ("pages/pages.jsonl".into(), pages_path),
        ],
        "2026-11-04T12:34:56.789Z",
        Limits::default(),
    )
    .unwrap();
    let result = std::process::Command::new(python)
        .arg("-c")
        .arg(READER)
        .arg(&warc_path)
        .arg(&package_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "reader failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("member ranges verified"));
}
