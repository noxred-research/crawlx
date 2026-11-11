#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Streaming feed rows: bounded memory, durable cursor, typed row outcomes, templates, no entity
//! expansion.

use crawlx_url::feed_stream::{
    prefix_digest, CsvTemplate, FeedRowStream, FeedStreamError, FeedTemplate, RowFault, RowOutcome,
    StreamCursor, StreamLimits, StreamRow, XmlField, XmlName, XmlTemplate,
};
use std::io::Read;

const ROWS: u64 = 100_000;

/// Produces a deterministic feed on demand so the test never holds the whole source.
struct Generated {
    next: u64,
    total: u64,
    line: fn(u64) -> String,
    footer: Vec<u8>,
    pending: Vec<u8>,
    pos: usize,
    footer_done: bool,
}

impl Generated {
    fn new(total: u64, header: &str, line: fn(u64) -> String, footer: &str) -> Self {
        Self {
            next: 0,
            total,
            pending: header.as_bytes().to_vec(),
            line,
            footer: footer.as_bytes().to_vec(),
            pos: 0,
            footer_done: false,
        }
    }
}

impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.pending.len() {
            self.pos = 0;
            if self.next < self.total {
                self.pending = (self.line)(self.next).into_bytes();
                self.next += 1;
            } else if !self.footer_done {
                self.footer_done = true;
                self.pending = self.footer.clone();
            } else {
                return Ok(0);
            }
        }
        let n = out.len().min(self.pending.len() - self.pos);
        out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn csv_line(index: u64) -> String {
    match index % 7 {
        0 => format!("{index},\"name, {index}\",\"he said \"\"hi\"\"\nline two\"\n"),
        1 => format!("{index},plain{index},\n"),
        _ => format!("{index},item {index},note-{index}\r\n"),
    }
}

fn xml_line(index: u64) -> String {
    format!(
        "<item><title>Title {index} &amp; more</title><link>https://example.test/a/{index}</link><guid isPermaLink=\"false\">g{index}</guid></item>\n"
    )
}

fn collect<R: Read>(stream: FeedRowStream<R>) -> Vec<StreamRow> {
    stream.map(|row| row.unwrap()).collect()
}

fn row(pairs: &[(&str, &str)]) -> RowOutcome {
    RowOutcome::Row(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

struct OneByte<'a>(&'a [u8]);

impl Read for OneByte<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.0.is_empty() || out.is_empty() {
            return Ok(0);
        }
        out[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

#[test]
fn csv_100k_rows_stream_with_bounded_buffers_and_exact_resume() {
    let template = FeedTemplate::Csv(CsvTemplate::with_header());
    let limits = StreamLimits::default();
    let source = || Generated::new(ROWS, "id,name,note\n", csv_line, "");

    let mut stream = FeedRowStream::new(source(), &template, limits).unwrap();
    let mut count = 0u64;
    let mut checkpoint: Option<StreamCursor> = None;
    let mut tail = Vec::new();
    for item in stream.by_ref() {
        let item = item.unwrap();
        assert_eq!(item.index, count);
        count += 1;
        if count == 50_000 {
            checkpoint = Some(item.cursor);
        } else if count > 50_000 {
            tail.push(item);
        }
    }
    assert_eq!(count, ROWS);
    let stats = stream.stats();
    assert_eq!(stats.rows, ROWS);
    assert_eq!(stats.malformed, 0);
    assert!(stats.bytes > 2_500_000, "source is large: {}", stats.bytes);
    assert!(
        stats.peak_buffered_bytes <= limits.read_chunk + 4 * 1024,
        "peak buffer {} bytes",
        stats.peak_buffered_bytes
    );

    let checkpoint = checkpoint.unwrap();
    assert_eq!(checkpoint.row_index, 50_000);
    // The token survives serialization.
    let token = checkpoint.to_string();
    let restored: StreamCursor = token.parse().unwrap();
    assert_eq!(restored, checkpoint);

    let resumed = FeedRowStream::resume(source(), &template, limits, &restored).unwrap();
    let resumed_rows = collect(resumed);
    assert_eq!(resumed_rows.len(), 50_000);
    assert_eq!(resumed_rows.first().unwrap().index, 50_000);
    assert_eq!(resumed_rows, tail);
}

#[test]
fn xml_100k_items_stream_with_bounded_buffers_and_exact_resume() {
    let template = FeedTemplate::rss_items();
    let limits = StreamLimits::default();
    let source = || {
        Generated::new(
            ROWS,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rss version=\"2.0\"><channel><title>t</title>\n",
            xml_line,
            "</channel></rss>",
        )
    };
    let mut stream = FeedRowStream::new(source(), &template, limits).unwrap();
    let mut count = 0u64;
    let mut checkpoint = None;
    let mut tail = Vec::new();
    let mut first = None;
    for item in stream.by_ref() {
        let item = item.unwrap();
        count += 1;
        if first.is_none() {
            first = Some(item.clone());
        }
        if count == 25_000 {
            checkpoint = Some(item.cursor);
        } else if count > 25_000 {
            tail.push(item);
        }
    }
    assert_eq!(count, ROWS);
    assert_eq!(
        first.unwrap().outcome,
        row(&[
            ("guid", "g0"),
            ("link", "https://example.test/a/0"),
            ("title", "Title 0 & more"),
        ])
    );
    let stats = stream.stats();
    assert!(stats.bytes > 10_000_000, "source is large: {}", stats.bytes);
    assert!(
        stats.peak_buffered_bytes <= limits.read_chunk + 4 * 1024,
        "peak buffer {} bytes",
        stats.peak_buffered_bytes
    );

    let checkpoint = checkpoint.unwrap();
    let resumed = collect(FeedRowStream::resume(source(), &template, limits, &checkpoint).unwrap());
    assert_eq!(resumed.len() as u64, ROWS - 25_000);
    assert_eq!(resumed, tail);
}

#[test]
fn cursor_digest_covers_exactly_the_consumed_prefix() {
    let doc =
        "<rss><channel>\n<item><title>a</title></item>\n<item><title>b</title></item>\n</channel></rss>";
    let template = FeedTemplate::rss_items();
    let rows = collect(FeedRowStream::new(doc.as_bytes(), &template, StreamLimits::default()).unwrap());
    assert_eq!(rows.len(), 2);
    for item in &rows {
        let offset = usize::try_from(item.cursor.byte_offset).unwrap();
        assert!(doc[..offset].ends_with("</item>"));
        assert_eq!(
            item.cursor.source_digest,
            prefix_digest(&doc.as_bytes()[..offset])
        );
        assert_eq!(item.cursor.row_index, item.index + 1);
    }

    let csv = "a,b\n1,2\n3,4\n";
    let rows = collect(
        FeedRowStream::new(
            csv.as_bytes(),
            &FeedTemplate::Csv(CsvTemplate::with_header()),
            StreamLimits::default(),
        )
        .unwrap(),
    );
    assert_eq!(rows[1].cursor.byte_offset, csv.len() as u64);
    assert_eq!(rows[0].cursor.source_digest, prefix_digest(b"a,b\n1,2\n"));
}

#[test]
fn resume_rejects_changed_prefix_and_short_sources() {
    let template = FeedTemplate::Csv(CsvTemplate::with_header());
    let limits = StreamLimits::default();
    let original = "a,b\n1,2\n3,4\n5,6\n";
    let rows = collect(FeedRowStream::new(original.as_bytes(), &template, limits).unwrap());
    let cursor = rows[1].cursor;

    let tail = collect(FeedRowStream::resume(original.as_bytes(), &template, limits, &cursor).unwrap());
    assert_eq!(tail, vec![rows[2].clone()]);

    let changed = "a,b\n1,9\n3,4\n5,6\n";
    let outcome: Vec<_> = FeedRowStream::resume(changed.as_bytes(), &template, limits, &cursor)
        .unwrap()
        .collect();
    assert!(matches!(
        outcome.as_slice(),
        [Err(FeedStreamError::CursorMismatch)]
    ));

    let short = "a,b\n1,2\n";
    let outcome: Vec<_> = FeedRowStream::resume(short.as_bytes(), &template, limits, &cursor)
        .unwrap()
        .collect();
    assert!(matches!(
        outcome.as_slice(),
        [Err(FeedStreamError::CursorMismatch)]
    ));

    // A source that grew after the cursor keeps the verified prefix valid.
    let grown = "a,b\n1,2\n3,4\n5,6\n7,8\n";
    assert_eq!(
        collect(FeedRowStream::resume(grown.as_bytes(), &template, limits, &cursor).unwrap()).len(),
        2
    );

    // Resuming a finished stream yields nothing.
    let last = rows.last().unwrap().cursor;
    assert!(
        collect(FeedRowStream::resume(original.as_bytes(), &template, limits, &last).unwrap()).is_empty()
    );

    // Start cursor equals a fresh stream; a forged row-0 cursor is rejected.
    let fresh = collect(
        FeedRowStream::resume(original.as_bytes(), &template, limits, &StreamCursor::start()).unwrap(),
    );
    assert_eq!(fresh, rows);
    let mut forged = StreamCursor::start();
    forged.byte_offset = 4;
    assert!(matches!(
        FeedRowStream::resume(original.as_bytes(), &template, limits, &forged),
        Err(FeedStreamError::CursorMismatch)
    ));
}

#[test]
fn cursor_tokens_parse_strictly() {
    let cursor = StreamCursor::start();
    assert_eq!(cursor.to_string().parse::<StreamCursor>().unwrap(), cursor);
    for bad in [
        "",
        "fs2:0:0:00",
        "fs1:x:0:00",
        "fs1:1:2",
        "fs1:1:2:zz",
        &format!("{cursor}:extra"),
    ] {
        assert!(
            matches!(bad.parse::<StreamCursor>(), Err(FeedStreamError::Cursor(_))),
            "{bad}"
        );
    }
}

#[test]
fn csv_malformed_rows_yield_typed_outcomes_and_processing_continues() {
    let template = FeedTemplate::Csv(CsvTemplate::with_header().require("id"));
    let source = "id,name\n1,ok\n2\n3,\"bad\"x\n,missing id\n4,a\"b\n5,fine\n\n6,\"never closed\n";
    let rows = collect(FeedRowStream::new(source.as_bytes(), &template, StreamLimits::default()).unwrap());
    let outcomes: Vec<_> = rows.iter().map(|row| row.outcome.clone()).collect();
    assert_eq!(
        outcomes,
        vec![
            row(&[("id", "1"), ("name", "ok")]),
            RowOutcome::Malformed(RowFault::FieldCount {
                expected: 2,
                found: 1
            }),
            RowOutcome::Malformed(RowFault::InvalidQuote),
            RowOutcome::Malformed(RowFault::MissingField("id".into())),
            RowOutcome::Malformed(RowFault::InvalidQuote),
            row(&[("id", "5"), ("name", "fine")]),
            RowOutcome::Malformed(RowFault::UnterminatedQuote),
        ]
    );
    assert_eq!(
        rows.iter().map(|row| row.index).collect::<Vec<_>>(),
        (0..7).collect::<Vec<_>>()
    );

    // Invalid UTF-8 and oversize rows are per-row outcomes as well.
    let mut limits = StreamLimits::default();
    limits.max_row_bytes = 16;
    let mut bytes = b"id,name\n1,\xff\xfe\n2,".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 64));
    bytes.extend_from_slice(b"\n3,ok\n");
    let rows = collect(FeedRowStream::new(bytes.as_slice(), &template, limits).unwrap());
    let outcomes: Vec<_> = rows.into_iter().map(|row| row.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            RowOutcome::Malformed(RowFault::InvalidUtf8),
            RowOutcome::Malformed(RowFault::RowTooLarge { limit: 16 }),
            row(&[("id", "3"), ("name", "ok")]),
        ]
    );
}

#[test]
fn csv_template_quoting_header_mapping_and_dialects() {
    // Quoted delimiter, doubled quotes, embedded CRLF/LF, BOM, column rename, dropped column.
    let source = "\u{feff}SKU;Product Name;Internal\r\nA-1;\"Cup; large\";x\r\nB-2;\"Say \"\"hi\"\"\r\nsecond line\";y\r\n";
    let template = FeedTemplate::Csv(
        CsvTemplate::with_header()
            .delimiter(b';')
            .map_column("SKU", "sku")
            .map_column("Product Name", "name")
            .require("sku"),
    );
    let rows = collect(FeedRowStream::new(source.as_bytes(), &template, StreamLimits::default()).unwrap());
    assert_eq!(rows[0].outcome, row(&[("name", "Cup; large"), ("sku", "A-1")]));
    assert_eq!(
        rows[1].outcome,
        row(&[("name", "Say \"hi\"\r\nsecond line"), ("sku", "B-2")])
    );
    assert_eq!(rows.len(), 2);

    // Positional columns without a header row, custom quote byte.
    let template = FeedTemplate::Csv(CsvTemplate::positional(&["a", "b"]).unwrap().quote(b'\''));
    let rows =
        collect(FeedRowStream::new("'x,1',2\n3,4".as_bytes(), &template, StreamLimits::default()).unwrap());
    assert_eq!(rows[0].outcome, row(&[("a", "x,1"), ("b", "2")]));
    assert_eq!(rows[1].outcome, row(&[("a", "3"), ("b", "4")]));

    // A mapped header that is absent is a stream-level error, not a row outcome.
    let template = FeedTemplate::Csv(CsvTemplate::with_header().map_column("Nope", "n"));
    let outcome: Vec<_> = FeedRowStream::new("a,b\n1,2\n".as_bytes(), &template, StreamLimits::default())
        .unwrap()
        .collect();
    assert!(matches!(outcome.as_slice(), [Err(FeedStreamError::Header(_))]));

    // Invalid templates are rejected up front.
    assert!(CsvTemplate::positional(&[]).is_err());
    assert!(CsvTemplate::positional(&["a", "a"]).is_err());
    assert!(CsvTemplate::with_header().delimiter(b'"').validate().is_err());
    assert!(CsvTemplate::with_header().delimiter(b'\n').validate().is_err());
}

#[test]
fn chunk_size_does_not_change_rows_or_cursors() {
    let csv = (0..40).map(csv_line).collect::<String>();
    let csv = format!("id,name,note\n{csv}");
    let xml = format!(
        "<rss><channel>{}</channel></rss>",
        (0..40).map(xml_line).collect::<String>()
    );
    for (template, bytes) in [
        (FeedTemplate::Csv(CsvTemplate::with_header()), csv.as_bytes()),
        (FeedTemplate::rss_items(), xml.as_bytes()),
    ] {
        let reference = collect(FeedRowStream::new(bytes, &template, StreamLimits::default()).unwrap());
        assert_eq!(reference.len(), 40);
        let mut small = StreamLimits::default();
        small.read_chunk = 64;
        assert_eq!(
            collect(FeedRowStream::new(bytes, &template, small).unwrap()),
            reference
        );
        assert_eq!(
            collect(FeedRowStream::new(OneByte(bytes), &template, StreamLimits::default()).unwrap()),
            reference
        );
    }
}

#[test]
fn xml_namespaced_rows_attributes_and_prefix_aliases() {
    let atom = r#"<?xml version="1.0"?>
<f:feed xmlns:f="http://www.w3.org/2005/Atom">
  <f:entry><f:id>urn:1</f:id><f:title type="text"> One &lt;1&gt; </f:title>
    <f:link rel="alternate" href="https://example.test/1?a=1&amp;b=2"/><f:link href="https://example.test/other"/></f:entry>
  <f:entry><f:id>urn:2</f:id><f:title><![CDATA[Two & <b>]]></f:title><f:link href="https://example.test/2"/></f:entry>
  <entry xmlns="urn:other"><id>not atom</id></entry>
</f:feed>"#;
    let rows = collect(
        FeedRowStream::new(
            atom.as_bytes(),
            &FeedTemplate::atom_entries(),
            StreamLimits::default(),
        )
        .unwrap(),
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].outcome,
        row(&[
            ("id", "urn:1"),
            ("link", "https://example.test/1?a=1&b=2"),
            ("title", "One <1>"),
        ])
    );
    assert_eq!(
        rows[1].outcome,
        row(&[
            ("id", "urn:2"),
            ("link", "https://example.test/2"),
            ("title", "Two & <b>")
        ])
    );

    let catalog = r#"<catalog xmlns:x="urn:x" xmlns:l="urn:link">
  <x:product sku="S1" l:ref="R1"><x:name>Cup</x:name><x:price currency="EUR">9.50</x:price></x:product>
  <x:product sku="S2" ref="no-namespace"><x:name>Mug</x:name></x:product>
  <x:product><x:name>no sku</x:name></x:product>
</catalog>"#;
    let x = |local: &str| XmlName::namespaced("urn:x", local);
    let template = FeedTemplate::Xml(
        XmlTemplate::new(
            x("product"),
            vec![
                XmlField::attribute("sku", vec![], XmlName::local("sku")).required(),
                XmlField::attribute("ref", vec![], XmlName::namespaced("urn:link", "ref")),
                XmlField::element("name", vec![x("name")]),
                XmlField::element("price", vec![x("price")]),
                XmlField::attribute("currency", vec![x("price")], XmlName::local("currency")),
            ],
        )
        .unwrap(),
    );
    let rows = collect(FeedRowStream::new(catalog.as_bytes(), &template, StreamLimits::default()).unwrap());
    assert_eq!(
        rows[0].outcome,
        row(&[
            ("currency", "EUR"),
            ("name", "Cup"),
            ("price", "9.50"),
            ("ref", "R1"),
            ("sku", "S1")
        ])
    );
    assert_eq!(rows[1].outcome, row(&[("name", "Mug"), ("sku", "S2")]));
    assert_eq!(
        rows[2].outcome,
        RowOutcome::Malformed(RowFault::MissingField("sku".into()))
    );

    // Invalid XML templates are rejected up front.
    assert!(XmlTemplate::new(x("p"), vec![]).is_err());
    assert!(XmlTemplate::new(
        x("p"),
        vec![
            XmlField::element("a", vec![x("n")]),
            XmlField::element("b", vec![x("n")])
        ]
    )
    .is_err());
    assert!(XmlTemplate::new(
        x("p"),
        vec![
            XmlField::element("a", vec![x("n")]),
            XmlField::element("a", vec![x("m")])
        ]
    )
    .is_err());
}

fn link_template() -> FeedTemplate {
    FeedTemplate::Xml(
        XmlTemplate::new(
            XmlName::local("item"),
            vec![
                XmlField::element("title", vec![XmlName::local("title")]),
                XmlField::element("link", vec![XmlName::local("link")]).required(),
            ],
        )
        .unwrap(),
    )
}

#[test]
fn xml_malformed_rows_yield_typed_outcomes_and_processing_continues() {
    let source = "<rss><channel>\
        <item><title>ok</title><link>https://e.test/1</link></item>\
        <item><title>no link</title></item>\
        <item><title>&unknown;</title><link>https://e.test/3</link></item>\
        <item><title>&#65;&#x42;&lt;</title><link>https://e.test/4</link></item>\
        </channel></rss>";
    let rows =
        collect(FeedRowStream::new(source.as_bytes(), &link_template(), StreamLimits::default()).unwrap());
    let outcomes: Vec<_> = rows.iter().map(|row| row.outcome.clone()).collect();
    assert_eq!(
        outcomes,
        vec![
            row(&[("link", "https://e.test/1"), ("title", "ok")]),
            RowOutcome::Malformed(RowFault::MissingField("link".into())),
            RowOutcome::Malformed(RowFault::InvalidReference),
            row(&[("link", "https://e.test/4"), ("title", "AB<")]),
        ]
    );

    // Cumulative oversize row: typed outcome, next row unaffected.
    let filler = "<x>aaaaaaaaaa</x>".repeat(20);
    let source = format!(
        "<rss><item><title>t</title><link>l</link>{filler}</item><item><title>t</title><link>l</link></item></rss>"
    );
    let mut limits = StreamLimits::default();
    limits.max_row_bytes = 128;
    let rows = collect(FeedRowStream::new(source.as_bytes(), &link_template(), limits).unwrap());
    assert_eq!(
        rows[0].outcome,
        RowOutcome::Malformed(RowFault::RowTooLarge { limit: 128 })
    );
    assert_eq!(rows[1].outcome, row(&[("link", "l"), ("title", "t")]));
    assert_eq!(rows.len(), 2);

    // One event larger than the limit cannot be skipped safely: rows so far, then one error.
    let source = format!(
        "<rss><item><link>l</link></item><item><link>{}</link></item><item><link>z</link></item></rss>",
        "y".repeat(200)
    );
    limits.max_row_bytes = 64;
    let items: Vec<_> = FeedRowStream::new(source.as_bytes(), &link_template(), limits)
        .unwrap()
        .collect();
    assert_eq!(items.len(), 2);
    assert!(items[0].is_ok());
    assert!(matches!(items[1], Err(FeedStreamError::Limit("xml_event_bytes"))));

    // Truncated document: complete rows first, then one error, then the stream is over.
    let source = "<rss><item><link>a</link></item><item><link>b";
    let items: Vec<_> = FeedRowStream::new(source.as_bytes(), &link_template(), StreamLimits::default())
        .unwrap()
        .collect();
    assert_eq!(items.len(), 2);
    assert!(items[0].is_ok());
    assert!(matches!(
        items[1],
        Err(FeedStreamError::Structure(_) | FeedStreamError::Xml(_))
    ));

    // Mismatched end tag is a structural error.
    let items: Vec<_> = FeedRowStream::new(
        "<rss><item><link>a</item></rss>".as_bytes(),
        &link_template(),
        StreamLimits::default(),
    )
    .unwrap()
    .collect();
    assert!(matches!(items.as_slice(), [Err(FeedStreamError::Xml(_))]));

    // Nesting limit and non-UTF-8 declarations.
    limits = StreamLimits::default();
    limits.max_nesting = 3;
    let items: Vec<_> = FeedRowStream::new(
        "<a><b><c><d><item/></d></c></b></a>".as_bytes(),
        &link_template(),
        limits,
    )
    .unwrap()
    .collect();
    assert!(matches!(
        items.as_slice(),
        [Err(FeedStreamError::Limit("xml_nesting"))]
    ));
    let items: Vec<_> = FeedRowStream::new(
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><rss/>".as_bytes(),
        &link_template(),
        StreamLimits::default(),
    )
    .unwrap()
    .collect();
    assert!(matches!(items.as_slice(), [Err(FeedStreamError::Encoding)]));
}

/// Counts bytes pulled from the owned source; the stream has no other input channel.
struct Counting<'a> {
    data: &'a [u8],
    served: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.data.len() - self.served);
        out[..n].copy_from_slice(&self.data[self.served..self.served + n]);
        self.served += n;
        Ok(n)
    }
}

#[test]
fn entity_declarations_are_never_expanded_or_fetched() {
    let attacks = [
        r#"<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><item><title>&xxe;</title><link>l</link></item></rss>"#,
        r#"<!DOCTYPE rss SYSTEM "http://127.0.0.1:9/evil.dtd"><rss><item><link>l</link></item></rss>"#,
        r#"<!DOCTYPE rss [<!ENTITY % p SYSTEM "http://127.0.0.1:9/p.dtd">%p;]><rss><item><link>l</link></item></rss>"#,
        r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><lolz><item><link>&lol2;</link></item></lolz>"#,
    ];
    for attack in attacks {
        let mut source = Counting {
            data: attack.as_bytes(),
            served: 0,
        };
        let items: Vec<_> = FeedRowStream::new(&mut source, &link_template(), StreamLimits::default())
            .unwrap()
            .collect();
        assert!(
            matches!(items.as_slice(), [Err(FeedStreamError::Doctype)]),
            "{attack}"
        );
        assert!(source.served <= attack.len());
    }

    // Undefined entity references (no declaration possible) mark the row malformed, with no
    // expansion and no effect on neighbours.
    let source = "<rss><item><link>&xxe;</link></item><item><link>&amp;ok</link></item></rss>";
    let rows =
        collect(FeedRowStream::new(source.as_bytes(), &link_template(), StreamLimits::default()).unwrap());
    assert_eq!(rows[0].outcome, RowOutcome::Malformed(RowFault::InvalidReference));
    assert_eq!(rows[1].outcome, row(&[("link", "&ok")]));

    // Attribute values obey the same rule.
    let source = r#"<rss><item><link href="&xxe;">a</link></item></rss>"#;
    let template = FeedTemplate::Xml(
        XmlTemplate::new(
            XmlName::local("item"),
            vec![XmlField::attribute(
                "href",
                vec![XmlName::local("link")],
                XmlName::local("href"),
            )],
        )
        .unwrap(),
    );
    let rows = collect(FeedRowStream::new(source.as_bytes(), &template, StreamLimits::default()).unwrap());
    assert_eq!(rows[0].outcome, RowOutcome::Malformed(RowFault::InvalidReference));
}
