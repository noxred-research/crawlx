//! Streaming export of version-one generic JSON-object items from stdin or an authenticated API.
//!
//! Input is UTF-8 JSONL, one object per line, with no executable object-graph decoding.
//! JSON/JSONL retain all fields in sorted order; XML uses the shared typed item schema.
//! CSV uses an explicit field projection or freezes the first object's sorted fields. Inferred
//! columns reject later extra fields; missing fields produce empty cells. Empty input emits no CSV
//! header. All formats use shared item limits and explicit safe serializer policies. Only one
//! bounded input row or metadata page and parsed object are retained, never the whole collection.
//! Stdin mode initializes no clients. API mode requires paired run/dataset selection, uses
//! authenticated same-origin artifact reads and refuses redirects. Redirecting stdout to disk is
//! an operator retention choice, not a zero-retention guarantee. Failed streams may be partial.

use anyhow::{bail, Context};
use clap::{Args, ValueEnum};
use crawlx_extract::{
    item_export::{write_item_with, CsvFormulaPolicy, ItemExportOptions, XmlControlPolicy, XmlTextMode},
    serialize::ItemFormat,
};
use serde_json::Value;
use std::{collections::BTreeSet, io::Write, process::ExitCode};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

#[path = "dataset_export_remote.rs"]
mod remote;

const XML_DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
const MAX_ROW_BYTES: u32 = 16_777_216;

/// Export bounded generic JSONL objects from stdin or an explicitly selected API dataset.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct DatasetExportArgs {
    /// UTF-8 wire format; executable object formats are not supported.
    #[arg(long, value_enum, default_value = "jsonl")]
    pub format: DatasetExportFormat,
    /// CSV projection and fixed column order. Omit to infer sorted first-row columns.
    /// Explicit projections omit unlisted fields; inferred columns reject new fields.
    #[arg(long, value_delimiter = ',', num_args = 1)]
    pub csv_fields: Vec<String>,
    /// Maximum bytes per input row, including its optional CRLF/LF ending.
    #[arg(long, default_value_t = 1_048_576, value_parser = clap::value_parser!(u32).range(1..=16_777_216))]
    pub max_row_bytes: u32,
    /// Export committed items from this run instead of reading stdin.
    #[arg(long, requires = "dataset")]
    pub run: Option<crawlx_core::CrawlRunId>,
    /// Declared generic dataset namespace; requires --run.
    #[arg(long, requires = "run")]
    pub dataset: Option<String>,
    /// Maximum committed-item metadata records per authenticated API page.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
    pub page_size: u16,
    /// API target and bearer key; used only with --run and --dataset.
    #[command(flatten)]
    pub api: crate::authz::ApiTarget,
}

/// Supported version-one generic item wire formats; no opaque object ABI is loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum DatasetExportFormat {
    /// One JSON array, including an empty array for empty input.
    Json,
    /// One compact JSON object per line.
    Jsonl,
    /// Quoted, formula-neutralized CSV with one header and fixed columns.
    Csv,
    /// One XML items root containing typed version-one item elements.
    Xml,
}

impl From<DatasetExportFormat> for ItemFormat {
    fn from(format: DatasetExportFormat) -> Self {
        match format {
            DatasetExportFormat::Json => Self::Json,
            DatasetExportFormat::Jsonl => Self::Jsonl,
            DatasetExportFormat::Csv => Self::Csv,
            DatasetExportFormat::Xml => Self::Xml,
        }
    }
}

// Strip only the shared serializer's document framing, not its item serialization. JSON
// strings never contain literal LF bytes, so the serializer's final LF is unambiguous.
struct ItemFraming<'a> {
    out: &'a mut dyn Write,
    prefix: &'static [u8],
    omit_lf: bool,
}

impl Write for ItemFraming<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let skipped = self.prefix.len().min(bytes.len());
        if bytes[..skipped] != self.prefix[..skipped] {
            return Err(std::io::Error::other("unexpected item serializer framing"));
        }
        self.prefix = &self.prefix[skipped..];
        let body = &bytes[skipped..];
        if !(self.omit_lf && body == b"\n") {
            self.out.write_all(body)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

async fn next_row(
    reader: &mut (impl AsyncBufRead + Unpin),
    row: &mut Vec<u8>,
    limit: usize,
) -> anyhow::Result<bool> {
    row.clear();
    loop {
        let available = reader.fill_buf().await.context("reading item input")?;
        if available.is_empty() {
            return Ok(!row.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index.saturating_add(1));
        if count > limit.saturating_sub(row.len()) {
            bail!("item input row byte limit exceeded");
        }
        row.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

fn export_options(args: &DatasetExportArgs) -> anyhow::Result<ItemExportOptions> {
    if args.run.is_some() != args.dataset.is_some() {
        bail!("--run and --dataset must be supplied together");
    }
    if !(1..=1000).contains(&args.page_size) {
        bail!("dataset page size must be between 1 and 1000");
    }
    if !(1..=MAX_ROW_BYTES).contains(&args.max_row_bytes) {
        bail!("item input row byte limit must be between 1 and 16777216");
    }
    if !args.csv_fields.is_empty() && args.format != DatasetExportFormat::Csv {
        bail!("--csv-fields requires --format csv");
    }
    let mut names = BTreeSet::new();
    if args.csv_fields.len() > 256
        || args
            .csv_fields
            .iter()
            .any(|name| name.is_empty() || !names.insert(name))
    {
        bail!("CSV fields must be 1 to 256 distinct nonempty names");
    }
    let mut options = ItemExportOptions::default();
    options.csv_formula = CsvFormulaPolicy::PrefixEscape;
    options.xml_control = XmlControlPolicy::Reject;
    options.xml_text = XmlTextMode::Escaped;
    options.csv_header = true;
    if !args.csv_fields.is_empty() {
        options.csv_columns = Some(args.csv_fields.clone());
    }
    Ok(options)
}

struct ItemStream<'a> {
    out: &'a mut dyn Write,
    format: DatasetExportFormat,
    options: ItemExportOptions,
    infer_columns: bool,
    first: bool,
    started: bool,
}

impl<'a> ItemStream<'a> {
    fn new(args: &DatasetExportArgs, out: &'a mut dyn Write) -> anyhow::Result<Self> {
        Ok(Self {
            out,
            format: args.format,
            options: export_options(args)?,
            infer_columns: args.format == DatasetExportFormat::Csv && args.csv_fields.is_empty(),
            first: true,
            started: false,
        })
    }

    fn start(&mut self) -> anyhow::Result<()> {
        if !self.started {
            match self.format {
                DatasetExportFormat::Json => self.out.write_all(b"[")?,
                DatasetExportFormat::Xml => {
                    self.out.write_all(XML_DECLARATION)?;
                    self.out.write_all(b"<items version=\"1\">\n")?;
                }
                DatasetExportFormat::Jsonl | DatasetExportFormat::Csv => {}
            }
            self.started = true;
        }
        Ok(())
    }

    fn push(&mut self, item: &Value) -> anyhow::Result<()> {
        let fields = item.as_object().context("row must be a JSON object")?;
        if self.infer_columns {
            if self.first {
                let mut columns: Vec<_> = fields.keys().cloned().collect();
                columns.sort_unstable();
                self.options.csv_columns = Some(columns);
            }
            if self
                .options
                .csv_columns
                .as_ref()
                .is_some_and(|columns| fields.keys().any(|key| columns.binary_search(key).is_err()))
            {
                bail!("CSV input field lies outside first-row schema; declare --csv-fields for a projection");
            }
        }
        self.start()?;
        if self.format == DatasetExportFormat::Json && !self.first {
            self.out.write_all(b",")?;
        }
        let mut framed = ItemFraming {
            out: &mut *self.out,
            prefix: if self.format == DatasetExportFormat::Xml {
                XML_DECLARATION
            } else {
                b""
            },
            omit_lf: self.format == DatasetExportFormat::Json,
        };
        write_item_with(&mut framed, item, self.format.into(), &self.options)
            .context("serializing generic item")?;
        self.options.csv_header = false;
        self.first = false;
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<()> {
        self.start()?;
        match self.format {
            DatasetExportFormat::Json => self.out.write_all(b"]\n")?,
            DatasetExportFormat::Xml => self.out.write_all(b"</items>\n")?,
            DatasetExportFormat::Jsonl | DatasetExportFormat::Csv => {}
        }
        self.out.flush().context("flushing generic item export")?;
        Ok(())
    }
}

async fn export_reader(
    args: &DatasetExportArgs,
    mut reader: impl AsyncBufRead + Unpin,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut stream = ItemStream::new(args, out)?;
    stream.start()?;
    let mut row = Vec::new();
    let mut number = 0_u64;
    // Row numbers count input lines from one, so a rejected row can be found in the source.
    while next_row(&mut reader, &mut row, usize::try_from(args.max_row_bytes)?)
        .await
        .with_context(|| format!("input row {}", number.saturating_add(1)))?
    {
        number = number.saturating_add(1);
        let item: Value = serde_json::from_slice(&row)
            .with_context(|| format!("input row {number} must be a UTF-8 JSON object"))?;
        stream
            .push(&item)
            .with_context(|| format!("input row {number}"))?;
    }
    stream.finish()
}

/// Stream generic items from stdin or a selected committed dataset through shared exporters.
///
/// # Errors
/// Returns input, authentication, retention, schema, row/serializer bound or output errors.
/// Unsupported executable object formats are rejected, never decoded or approximated.
pub async fn run(args: DatasetExportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    if args.run.is_some() || args.dataset.is_some() {
        remote::export(&args, out).await?;
    } else {
        export_reader(&args, BufReader::new(tokio::io::stdin()), out).await?;
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::Parser;
    use tokio::io::AsyncWriteExt;

    fn args(format: DatasetExportFormat) -> DatasetExportArgs {
        DatasetExportArgs {
            format,
            csv_fields: Vec::new(),
            max_row_bytes: 1_048_576,
            run: None,
            dataset: None,
            page_size: 100,
            api: crate::authz::ApiTarget {
                api_url: "http://127.0.0.1:8080".into(),
                api_key: None,
            },
        }
    }

    async fn output(format: DatasetExportFormat, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        export_reader(&args(format), BufReader::new(input), &mut out)
            .await
            .unwrap();
        out
    }

    #[tokio::test]
    async fn rejected_rows_report_their_one_based_input_line() {
        for (format, input, reason) in [
            (DatasetExportFormat::Jsonl, "{\"a\":1}\nno\n", "UTF-8 JSON object"),
            (DatasetExportFormat::Jsonl, "{\"a\":1}\n[]\n", "JSON object"),
            (
                DatasetExportFormat::Csv,
                "{\"a\":1}\n{\"b\":2}\n",
                "first-row schema",
            ),
            (
                DatasetExportFormat::Xml,
                "{\"a\":1}\n{\"a\":\"\\u0001\"}\n",
                "forbidden scalar",
            ),
        ] {
            let error = export_reader(&args(format), BufReader::new(input.as_bytes()), &mut Vec::new())
                .await
                .unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("input row 2"), "{message}");
            assert!(message.contains(reason), "{message}");
        }
        let mut limited = args(DatasetExportFormat::Jsonl);
        limited.max_row_bytes = 3;
        let error = export_reader(&limited, BufReader::new(&b"{}\n{\"a\":1}\n"[..]), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("input row 2"));
    }

    #[tokio::test]
    async fn exact_json_and_jsonl_are_sorted_unicode_preserving_and_collection_framed() {
        let input = "{\"z\":\"雪\",\"a\":{\"y\":2,\"b\":1}}\r\n{\"a\":null}\n".as_bytes();
        assert_eq!(
            output(DatasetExportFormat::Json, input).await,
            "[{\"a\":{\"b\":1,\"y\":2},\"z\":\"雪\"},{\"a\":null}]\n".as_bytes()
        );
        assert_eq!(
            output(DatasetExportFormat::Jsonl, input).await,
            "{\"a\":{\"b\":1,\"y\":2},\"z\":\"雪\"}\n{\"a\":null}\n".as_bytes()
        );
        assert_eq!(output(DatasetExportFormat::Json, b"").await, b"[]\n");
    }

    #[tokio::test]
    async fn exact_csv_header_is_once_and_inferred_schema_never_drops_new_fields() {
        assert_eq!(
            output(
                DatasetExportFormat::Csv,
                b"{\"z\":\"=1\",\"a\":{\"x\":true}}\n{\"a\":null}\n"
            )
            .await,
            b"\"a\",\"z\"\n\"{\"\"x\"\":true}\",\"'=1\"\n\"null\",\n"
        );
        let mut out = Vec::new();
        assert!(export_reader(
            &args(DatasetExportFormat::Csv),
            BufReader::new(&b"{\"a\":1}\n{\"b\":2}\n"[..]),
            &mut out
        )
        .await
        .is_err());
        assert_eq!(out, b"\"a\"\n\"1\"\n");
        let mut projected = args(DatasetExportFormat::Csv);
        projected.csv_fields = vec!["z".into(), "a".into(), "missing".into()];
        out.clear();
        export_reader(
            &projected,
            BufReader::new(&b"{\"a\":null,\"z\":\"\",\"omit\":1}\n"[..]),
            &mut out,
        )
        .await
        .unwrap();
        assert_eq!(out, b"\"z\",\"a\",\"missing\"\n\"\",\"null\",\n");
    }

    #[tokio::test]
    async fn exact_xml_has_one_declaration_and_typed_escaped_items() {
        assert_eq!(output(DatasetExportFormat::Xml,
            b"{\"x\":\"<&\\t\\n\\r\"}\n{\"a\":[null,true]}\n").await,
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items version=\"1\">\n<item version=\"1\"><object><field name=\"x\"><string>&lt;&amp;&#9;&#10;&#13;</string></field></object></item>\n<item version=\"1\"><object><field name=\"a\"><array><entry><null/></entry><entry><boolean>true</boolean></entry></array></field></object></item>\n</items>\n");
        let mut out = Vec::new();
        assert!(export_reader(
            &args(DatasetExportFormat::Xml),
            BufReader::new(&b"{\"x\":\"\\u0001\"}\n"[..]),
            &mut out
        )
        .await
        .is_err());
        assert_eq!(
            out,
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items version=\"1\">\n"
        );
    }

    #[derive(Debug, Parser)]
    struct Command {
        #[command(flatten)]
        args: DatasetExportArgs,
    }

    #[tokio::test]
    async fn opaque_formats_graph_bytes_and_nonobjects_are_refused() {
        for format in ["pickle", "marshal", "tei"] {
            assert!(Command::try_parse_from(["export", "--format", format]).is_err());
        }
        for input in [
            &b"\x80\x04N."[..],
            &b"[{}]\n"[..],
            &b"null\n"[..],
            &b"\n"[..],
            &b"{\"x\":\"\xff\"}\n"[..],
        ] {
            let mut out = Vec::new();
            assert!(
                export_reader(&args(DatasetExportFormat::Jsonl), BufReader::new(input), &mut out)
                    .await
                    .is_err()
            );
            assert!(out.is_empty());
        }
    }

    #[tokio::test]
    async fn row_bounds_fields_and_empty_streams_are_explicit() {
        let mut bounded = args(DatasetExportFormat::Jsonl);
        bounded.max_row_bytes = 8;
        let mut out = Vec::new();
        export_reader(
            &bounded,
            BufReader::with_capacity(1, &b"{\"x\":1}\n"[..]),
            &mut out,
        )
        .await
        .unwrap();
        bounded.max_row_bytes = 7;
        out.clear();
        assert!(export_reader(
            &bounded,
            BufReader::with_capacity(1, &b"{\"x\":1}\n"[..]),
            &mut out
        )
        .await
        .is_err());
        assert!(out.is_empty());
        assert_eq!(output(DatasetExportFormat::Csv, b"").await, b"");
        assert_eq!(output(DatasetExportFormat::Jsonl, b"").await, b"");
        assert_eq!(
            output(DatasetExportFormat::Xml, b"").await,
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items version=\"1\">\n</items>\n"
        );
        for fields in [vec!["a".into(), "a".into()], vec![String::new()]] {
            let mut invalid = args(DatasetExportFormat::Csv);
            invalid.csv_fields = fields;
            assert!(export_options(&invalid).is_err());
        }
    }

    #[derive(Default)]
    struct CountOutput {
        bytes: usize,
        lines: usize,
    }

    impl Write for CountOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes += bytes.len();
            self.lines += bytes.iter().filter(|byte| **byte == b'\n').count();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn streams_one_hundred_thousand_items_through_bounded_pipe() {
        let (mut producer, consumer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            for _ in 0..100_000 {
                producer.write_all(b"{\"x\":1}\n").await.unwrap();
            }
        });
        let mut out = CountOutput::default();
        export_reader(
            &args(DatasetExportFormat::Jsonl),
            BufReader::with_capacity(32, consumer),
            &mut out,
        )
        .await
        .unwrap();
        task.await.unwrap();
        assert_eq!(out.lines, 100_000);
        assert_eq!(out.bytes, 800_000);
    }
}
