//! Native declarative feed selection, parameters and bounded terminal fragment aggregation.

use super::*;
use crawlx_core::dataset::feed_key_component as key_component;
use crawlx_core::dataset::{
    AcceptedItemV1, DatasetContentV1, DeliveryRangeV1, EmptyFeedPolicyV1, FeedBatchingV1, FeedCompressionV1,
    FeedDeclarationV1, FeedPredicateV1,
};
use crawlx_extract::item_export::{write_item_with, ItemExportOptions};
use crawlx_extract::serialize::ItemFormat;
use serde::Serialize;

#[cfg(test)]
#[path = "feed_policy_tests.rs"]
mod tests;

pub(super) fn codec(feed: &FeedDeclarationV1) -> FeedCompressionV1 {
    if feed.batching == FeedBatchingV1::Terminal {
        FeedCompressionV1::None
    } else {
        feed.compression
    }
}

pub(crate) fn take_fragments(
    run: &CrawlRun,
    item: &mut AcceptedItemV1,
    batches: Vec<DeliveryBatchV1>,
) -> Vec<DeliveryBatchV1> {
    let mut immediate = Vec::new();
    for batch in batches {
        if run
            .config
            .datasets
            .feeds
            .iter()
            .any(|feed| feed.id == batch.feed && feed.batching == FeedBatchingV1::Terminal)
        {
            item.feed_fragments.push(batch);
        } else {
            immediate.push(batch);
        }
    }
    immediate
}

pub(super) fn article_matches(feed: &FeedDeclarationV1, document: &crawlx_extract::Document) -> bool {
    feed.item_filter.all.iter().all(|predicate| {
        let field = match predicate {
            FeedPredicateV1::Present { field } | FeedPredicateV1::Equals { field, .. } => field,
            _ => return false,
        };
        let value = match field.as_str() {
            "text" => Some(document.text.as_str()),
            "comments" => Some(document.comments.as_str()),
            "title" => document
                .article
                .as_ref()
                .and_then(|article| article.metadata.title.value.as_deref()),
            _ => None,
        };
        match predicate {
            FeedPredicateV1::Present { .. } => value.is_some(),
            FeedPredicateV1::Equals { value: expected, .. } => value == expected.as_str(),
            _ => false,
        }
    })
}

fn item_format(serializer: &str) -> Result<ItemFormat, StoreError> {
    match serializer {
        "json" => Ok(ItemFormat::Json),
        "jsonl" => Ok(ItemFormat::Jsonl),
        "csv" => Ok(ItemFormat::Csv),
        "xml" => Ok(ItemFormat::Xml),
        _ => Err(StoreError::Conflict("generic feed serializer unavailable".into())),
    }
}

fn write_generic(
    output: &mut LimitedOutput,
    value: &Value,
    feed: &FeedDeclarationV1,
) -> Result<(), StoreError> {
    if feed.serializer == "json" && feed.parameters.json_indent > 0 {
        let spaces = [b' '; 8];
        let formatter = serde_json::ser::PrettyFormatter::with_indent(
            &spaces[..usize::from(feed.parameters.json_indent)],
        );
        value
            .serialize(&mut serde_json::Serializer::with_formatter(
                &mut *output,
                formatter,
            ))
            .map_err(|_| output.serialization_error("feed JSON serialization failed"))?;
        output
            .write_all(b"\n")
            .map_err(|_| output.serialization_error("feed JSON framing failed"))?;
    } else {
        let mut options = ItemExportOptions::default();
        if !feed.parameters.csv_columns.is_empty() {
            options.csv_columns = Some(feed.parameters.csv_columns.clone());
        }
        write_item_with(output, value, item_format(&feed.serializer)?, &options)
            .map_err(|_| output.serialization_error("feed item serialization failed"))?;
    }
    Ok(())
}

pub(super) fn article_parameters(
    output: &mut LimitedOutput,
    document: &crawlx_extract::Document,
    source: &str,
    feed: &FeedDeclarationV1,
    cpu: &CpuPool,
) -> Result<bool, StoreError> {
    if feed.parameters.csv_columns.is_empty() {
        return Ok(false);
    }
    let article = document
        .article
        .as_ref()
        .ok_or_else(|| StoreError::RetentionDenied("article envelope missing".into()))?;
    // Project only declared, serializer-consumed fields. Never copy an omitted document body.
    let mut reservations = Vec::new();
    let mut fields = serde_json::Map::new();
    let mut bytes = 0usize;
    for field in &feed.parameters.csv_columns {
        let value = match field.as_str() {
            "source" => source,
            "title" => article.metadata.title.value.as_deref().unwrap_or(""),
            "source_url" => "",
            "text" => &document.text,
            "comments" => &document.comments,
            _ => continue,
        };
        bytes = bytes
            .checked_add(value.len())
            .ok_or_else(|| StoreError::Conflict("article CSV source overflow".into()))?;
        if bytes > output.maximum {
            return Err(StoreError::RetentionDenied(
                "article CSV source byte limit".into(),
            ));
        }
        let working = value
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(512))
            .ok_or_else(|| StoreError::Conflict("article CSV reservation overflow".into()))?;
        reservations.push(cpu.try_reserve_article_output(working)?);
        fields.insert(field.clone(), Value::String(value.to_owned()));
    }
    let value = Value::Object(fields);
    write_generic(output, &value, feed)?;
    Ok(true)
}
pub(super) fn pretty_json(
    output: LimitedOutput,
    feed: &FeedDeclarationV1,
    maximum: usize,
    cpu: &CpuPool,
) -> Result<LimitedOutput, StoreError> {
    if feed.parameters.json_indent == 0 {
        return Ok(output);
    }
    let _reservation = cpu.try_reserve_article_output(
        output
            .bytes
            .len()
            .checked_mul(64)
            .ok_or_else(|| StoreError::Conflict("article JSON parameter reservation overflow".into()))?,
    )?;
    let value: Value = serde_json::from_slice(&output.bytes)
        .map_err(|_| StoreError::Serialization("feed JSON framing invalid".into()))?;
    let mut pretty = LimitedOutput::new(maximum);
    write_generic(&mut pretty, &value, feed)?;
    Ok(pretty)
}

pub(super) async fn prepare_generic(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    dataset: &str,
    artifact: &crawlx_core::ArtifactRef,
    approved_json: Redacted<Vec<u8>>,
) -> Result<Vec<DeliveryBatchV1>, StoreError> {
    let size = u64::try_from(approved_json.as_ref().len())
        .map_err(|_| StoreError::Conflict("feed length overflow".into()))?;
    if size > MAX_VALUE_BYTES {
        return Err(StoreError::RetentionDenied("feed source byte limit".into()));
    }
    let original = artifacts.dataset_content(run.id, page, artifact, size).await?;
    let deadline = original
        .expires_at()
        .or_else(|| article_deadline(run, None))
        .ok_or_else(|| StoreError::RetentionDenied("feed deadline unavailable".into()))?;
    let mut parsed = None;
    let mut owned_input = Some(approved_json);
    let mut batches = Vec::new();
    for feed in run
        .config
        .datasets
        .feeds
        .iter()
        .filter(|feed| feed.source == dataset)
    {
        let direct = codec(feed) == FeedCompressionV1::None
            && matches!(feed.serializer.as_str(), "json" | "jsonl")
            && feed.parameters == Default::default()
            && feed.item_filter.all.is_empty();
        let (content, length) =
            if direct {
                (original.clone(), size)
            } else {
                if parsed.is_none() {
                    let input = owned_input
                        .take()
                        .ok_or_else(|| StoreError::Serialization("feed source ownership missing".into()))?;
                    let reservation =
                        cpu.try_reserve_article_output(input.as_ref().len().checked_mul(64).ok_or_else(
                            || StoreError::Conflict("feed source reservation overflow".into()),
                        )?)?;
                    parsed = Some(
                        cpu.run(move || {
                            Redactor::new().check_canonical(input.as_ref())?;
                            let value: Value = serde_json::from_slice(input.as_ref())
                                .map_err(|_| StoreError::Serialization("feed item JSON invalid".into()))?;
                            Ok::<_, StoreError>((value, reservation))
                        })
                        .await
                        .map_err(|_| StoreError::Backend("feed source CPU task failed".into()))??,
                    );
                }
                let source = parsed
                    .take()
                    .ok_or_else(|| StoreError::Serialization("feed source missing".into()))?;
                if !feed.item_filter.matches(&source.0) {
                    parsed = Some(source);
                    continue;
                }
                let maximum = usize::try_from(feed.max_batch_bytes)
                    .map_err(|_| StoreError::Conflict("feed byte limit overflow".into()))?;
                let codec = codec(feed);
                let reservation =
                    cpu.try_reserve_article_output(compression::reservation_bytes(codec, maximum)?)?;
                let owned_feed = feed.clone();
                let (source, approved, reservation) = cpu
                    .run(move || {
                        let mut output = LimitedOutput::new(maximum);
                        write_generic(&mut output, &source.0, &owned_feed)?;
                        let approved = Redactor::new().verify_canonical_owned(output.bytes)?;
                        let approved = compression::encode_approved(approved, codec, maximum)?;
                        Ok::<_, StoreError>((source, approved, reservation))
                    })
                    .await
                    .map_err(|_| StoreError::Backend("feed item CPU task failed".into()))??;
                parsed = Some(source);
                let output = (approved, reservation);
                let mime = compression::media_type(codec, mime(feed))?;
                let reference = put_approved(
                    artifacts,
                    run,
                    page,
                    &format!("feed.{}", key_component(&feed.id)),
                    mime,
                    &output.0,
                    Some(deadline),
                )
                .await?;
                let length = u64::try_from(output.0.as_ref().len())
                    .map_err(|_| StoreError::Conflict("feed length overflow".into()))?;
                let content = artifacts
                    .dataset_content(run.id, page, &reference, length)
                    .await?;
                (content, length)
            };
        if length > feed.max_batch_bytes {
            return Err(StoreError::RetentionDenied("feed byte limit".into()));
        }
        batches.push(DeliveryBatchV1::for_request(
            feed.id.clone(),
            format!("request.{page}.{}", key_component(&feed.id)),
            content,
            length,
            deadline,
        ));
    }
    Ok(batches)
}

fn mime(feed: &FeedDeclarationV1) -> &'static str {
    match feed.serializer.as_str() {
        "json" | "search_json" => "application/json",
        "jsonl" => "application/x-ndjson",
        "csv" => "text/csv",
        "xml" | "tei" => "application/xml",
        "html" => "text/html",
        _ => "text/plain",
    }
}

fn write_bytes(output: &mut LimitedOutput, bytes: &[u8]) -> Result<(), StoreError> {
    output
        .write_all(bytes)
        .map_err(|_| output.serialization_error("feed framing byte limit"))
}

struct Framing<'a> {
    prefix: &'a [u8],
    body: &'a [u8],
    suffix: &'a [u8],
    separator: &'a [u8],
}

fn framing<'a>(feed: &FeedDeclarationV1, article: bool, bytes: &'a [u8]) -> Result<Framing<'a>, StoreError> {
    let invalid = || StoreError::Serialization("immutable feed fragment framing invalid".into());
    let (prefix, body, suffix, separator): (&[u8], &[u8], &[u8], &[u8]) = match feed.serializer.as_str() {
        "json" => {
            let body = if article {
                bytes
                    .strip_prefix(b"[\n")
                    .and_then(|body| body.strip_suffix(b"\n]\n"))
                    .ok_or_else(invalid)?
            } else {
                bytes.trim_ascii()
            };
            (b"[\n", body, b"\n]\n", b",\n")
        }
        "csv" => {
            let end = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or_else(invalid)?
                .checked_add(1)
                .ok_or_else(invalid)?;
            (&bytes[..end], &bytes[end..], b"", b"")
        }
        "xml" if article => {
            let prefix = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<articles version=\"1\">\n";
            let suffix = b"</articles>\n";
            (
                prefix,
                bytes
                    .strip_prefix(prefix)
                    .and_then(|body| body.strip_suffix(suffix))
                    .ok_or_else(invalid)?,
                suffix,
                b"",
            )
        }
        "xml" => {
            let body = bytes
                .strip_prefix(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
                .ok_or_else(invalid)?;
            (
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items version=\"1\">\n",
                body,
                b"</items>\n",
                b"",
            )
        }
        "html" => {
            let prefix = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Offline article collection</title></head><body>\n";
            let suffix = b"</body></html>\n";
            (
                prefix,
                bytes
                    .strip_prefix(prefix)
                    .and_then(|body| body.strip_suffix(suffix))
                    .ok_or_else(invalid)?,
                suffix,
                b"",
            )
        }
        "tei" => {
            let end = bytes
                .windows(b"</teiHeader>\n".len())
                .position(|part| part == b"</teiHeader>\n")
                .and_then(|start| start.checked_add(b"</teiHeader>\n".len()))
                .ok_or_else(invalid)?;
            (
                &bytes[..end],
                bytes[end..].strip_suffix(b"</teiCorpus>\n").ok_or_else(invalid)?,
                b"</teiCorpus>\n",
                b"",
            )
        }
        // Direct generic fragments reuse canonical JSON artifacts, which need not end in a
        // newline. Own record separators here instead of relying on fragment trailing bytes.
        "jsonl" => (b"", bytes.strip_suffix(b"\n").unwrap_or(bytes), b"\n", b"\n"),
        "text" | "markdown" | "search_json" => (b"", bytes, b"", b""),
        _ => return Err(invalid()),
    };
    Ok(Framing {
        prefix,
        body,
        suffix,
        separator,
    })
}

#[derive(Clone, Copy)]
struct RecordSpan {
    start: usize,
    end: usize,
    ordinal: u64,
    deadline: crawlx_core::Timestamp,
}

struct Accumulator {
    output: LimitedOutput,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    first: u64,
    last: u64,
    count: u16,
    deadline: crawlx_core::Timestamp,
    records: Vec<RecordSpan>,
}

impl Accumulator {
    fn new(maximum: usize, deadline: crawlx_core::Timestamp) -> Self {
        Self {
            output: LimitedOutput::new(maximum),
            prefix: Vec::new(),
            suffix: Vec::new(),
            first: 0,
            last: 0,
            count: 0,
            deadline,
            records: Vec::new(),
        }
    }

    fn push(
        &mut self,
        feed: &FeedDeclarationV1,
        article: bool,
        ordinal: u64,
        bytes: &[u8],
        deadline: crawlx_core::Timestamp,
    ) -> Result<bool, StoreError> {
        let frame = framing(feed, article, bytes)?;
        let max_items = if feed.serializer == "search_json" {
            1
        } else {
            feed.max_batch_items
        };
        if self.count > 0 && (self.count >= max_items || self.last.checked_add(1) != Some(ordinal)) {
            return Ok(false);
        }
        if self.count > 0 && self.prefix != frame.prefix {
            return Ok(false);
        }
        let extra = if self.count == 0 {
            frame.prefix.len()
        } else {
            frame.separator.len()
        };
        let indent = if !article && feed.serializer == "json" {
            usize::from(feed.parameters.json_indent)
        } else {
            0
        };
        let indent_bytes = if indent == 0 {
            0
        } else {
            frame
                .body
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                .checked_add(1)
                .and_then(|lines| lines.checked_mul(indent))
                .ok_or_else(|| StoreError::Conflict("feed indentation overflow".into()))?
        };
        let wanted = self
            .output
            .bytes
            .len()
            .checked_add(extra)
            .and_then(|n| n.checked_add(frame.body.len()))
            .and_then(|n| n.checked_add(indent_bytes))
            .and_then(|n| n.checked_add(frame.suffix.len()))
            .ok_or_else(|| StoreError::Conflict("feed batch length overflow".into()))?;
        if u64::try_from(wanted)
            .ok()
            .is_none_or(|wanted| wanted > feed.max_batch_bytes)
        {
            if self.count > 0 {
                return Ok(false);
            }
            return Err(StoreError::RetentionDenied(
                "one feed item exceeds batch byte quota".into(),
            ));
        }
        if self.count == 0 {
            self.first = ordinal;
            self.prefix.extend_from_slice(frame.prefix);
            self.suffix.extend_from_slice(frame.suffix);
            write_bytes(&mut self.output, frame.prefix)?;
        } else {
            write_bytes(&mut self.output, frame.separator)?;
        }
        let start = self.output.bytes.len();
        if indent == 0 {
            write_bytes(&mut self.output, frame.body)?;
        } else {
            let spaces = [b' '; 8];
            for line in frame.body.split_inclusive(|byte| *byte == b'\n') {
                write_bytes(&mut self.output, &spaces[..indent])?;
                write_bytes(&mut self.output, line)?;
            }
        }
        self.records.push(RecordSpan {
            start,
            end: self.output.bytes.len(),
            ordinal,
            deadline,
        });
        self.last = ordinal;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("feed batch count overflow".into()))?;
        self.deadline = self.deadline.min(deadline);
        Ok(true)
    }

    fn segment(&self, records: &[RecordSpan]) -> Result<Self, StoreError> {
        let first = records
            .first()
            .ok_or_else(|| StoreError::Conflict("feed split is empty".into()))?;
        let last = records
            .last()
            .ok_or_else(|| StoreError::Conflict("feed split is empty".into()))?;
        let mut output = Self::new(self.output.maximum, first.deadline);
        output.prefix.clone_from(&self.prefix);
        output.suffix.clone_from(&self.suffix);
        write_bytes(&mut output.output, &self.prefix)?;
        write_bytes(&mut output.output, &self.output.bytes[first.start..last.end])?;
        for record in records {
            output.records.push(RecordSpan {
                start: record.start - first.start + self.prefix.len(),
                end: record.end - first.start + self.prefix.len(),
                ..*record
            });
            output.deadline = output.deadline.min(record.deadline);
        }
        output.first = first.ordinal;
        output.last = last.ordinal;
        output.count = u16::try_from(records.len())
            .map_err(|_| StoreError::Conflict("feed split count overflow".into()))?;
        Ok(output)
    }

    fn split(&self) -> Result<(Self, Self), StoreError> {
        if self.records.len() < 2 {
            return Err(StoreError::RetentionDenied(
                "one encoded feed item exceeds batch byte quota".into(),
            ));
        }
        let middle = self.records.len() / 2;
        Ok((
            self.segment(&self.records[..middle])?,
            self.segment(&self.records[middle..])?,
        ))
    }
}

async fn load_fragment(
    stores: &Stores,
    run: &CrawlRun,
    fragment: &DeliveryBatchV1,
) -> Result<Vec<u8>, StoreError> {
    let bytes = match &fragment.content {
        DatasetContentV1::Durable { artifact } => {
            stores
                .artifacts
                .read_archive_content(run.tenant, run.id, artifact, fragment.size_bytes)
                .await?
        }
        DatasetContentV1::Volatile { page, artifact, .. } => {
            stores
                .artifacts
                .dataset_content(run.id, *page, artifact, fragment.size_bytes)
                .await?;
            stores.artifacts.get(artifact).await?
        }
        _ => {
            return Err(StoreError::RetentionDenied(
                "unsupported feed fragment content".into(),
            ));
        }
    };
    if u64::try_from(bytes.len()).ok() != Some(fragment.size_bytes) {
        return Err(StoreError::RetentionDenied("feed fragment size mismatch".into()));
    }
    Ok(bytes)
}

fn terminal_page(run: &CrawlRun, feed: &FeedDeclarationV1, first: u64) -> Result<i64, StoreError> {
    // Volatile page custody shares one deadline across renditions. Partition the reserved
    // negative namespace by immutable feed order so one destination cannot shorten another.
    const ORDINAL_BITS: u32 = 50;
    if first >= (1u64 << ORDINAL_BITS) {
        return Err(StoreError::RetentionDenied(
            "feed source namespace exhausted".into(),
        ));
    }
    let index = run
        .config
        .datasets
        .feeds
        .iter()
        .position(|candidate| candidate.id == feed.id)
        .filter(|index| *index < 64)
        .ok_or_else(|| StoreError::Conflict("undeclared terminal feed".into()))?;
    i64::try_from(index)
        .ok()
        .and_then(|index| index.checked_shl(ORDINAL_BITS))
        .and_then(|offset| offset.checked_add(i64::try_from(first).ok()?))
        .and_then(|offset| (i64::MIN / 4).checked_add(offset))
        .ok_or_else(|| StoreError::Conflict("feed page overflow".into()))
}

type ReservedAccumulator = (Accumulator, crawlx_core::parser_memory::BytePermit);

fn encoding_limit(codec: FeedCompressionV1, maximum: usize) -> Result<usize, StoreError> {
    if codec == FeedCompressionV1::None {
        return Ok(maximum);
    }
    maximum
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1024 * 1024))
        .ok_or_else(|| StoreError::Conflict("feed encoding workspace overflow".into()))
}

fn batch_reservation(codec: FeedCompressionV1, maximum: usize) -> Result<usize, StoreError> {
    let buffers = if codec == FeedCompressionV1::None {
        0
    } else {
        maximum
            .checked_mul(2)
            .ok_or_else(|| StoreError::Conflict("feed split workspace overflow".into()))?
    };
    compression::reservation_bytes(codec, encoding_limit(codec, maximum)?)?
        .checked_add(buffers)
        .and_then(|bytes| bytes.checked_add(128 * 1024))
        .ok_or_else(|| StoreError::Conflict("feed split reservation overflow".into()))
}

fn accumulator(
    cpu: &CpuPool,
    feed: &FeedDeclarationV1,
    deadline: crawlx_core::Timestamp,
) -> Result<ReservedAccumulator, StoreError> {
    let maximum = usize::try_from(feed.max_batch_bytes)
        .map_err(|_| StoreError::Conflict("feed batch byte overflow".into()))?;
    Ok((
        Accumulator::new(maximum, deadline),
        cpu.try_reserve_article_output(batch_reservation(feed.compression, maximum)?)?,
    ))
}

async fn publish(
    stores: &Stores,
    cpu: &CpuPool,
    run: &CrawlRun,
    feed: &FeedDeclarationV1,
    source: ReservedAccumulator,
) -> Result<(), StoreError> {
    let maximum = usize::try_from(feed.max_batch_bytes)
        .map_err(|_| StoreError::Conflict("feed batch byte overflow".into()))?;
    let codec = feed.compression;
    let wire_limit = encoding_limit(codec, maximum)?;
    let jsonl = feed.serializer == "jsonl";
    let (initial, mut reservation) = source;
    let mut queue = vec![initial];
    while let Some(mut accumulator) = queue.pop() {
        let (first, last, deadline) = (accumulator.first, accumulator.last, accumulator.deadline);
        let (result, returned_credit) = cpu
            .run(move || {
                let mut plaintext = LimitedOutput::new(maximum);
                if codec == FeedCompressionV1::None {
                    plaintext.bytes = std::mem::take(&mut accumulator.output.bytes);
                } else {
                    // Keep plaintext only while testing encoded size, so an expanded batch can split
                    // deterministically at record boundaries instead of failing otherwise valid items.
                    write_bytes(&mut plaintext, &accumulator.output.bytes)?;
                }
                write_bytes(&mut plaintext, &accumulator.suffix)?;
                let redactor = Redactor::new();
                let approved = if jsonl {
                    redactor.verify_canonical_jsonl_owned(plaintext.bytes)?
                } else {
                    redactor.verify_canonical_owned(plaintext.bytes)?
                };
                let approved = compression::encode_approved(approved, codec, wire_limit)?;
                let result = if approved.as_ref().len() > maximum {
                    let (left, right) = accumulator.split()?;
                    Err((left, right))
                } else {
                    Ok(approved)
                };
                Ok::<_, StoreError>((result, reservation))
            })
            .await
            .map_err(|_| StoreError::Backend("feed batch CPU task failed".into()))??;
        reservation = returned_credit;
        let approved = match result {
            Ok(approved) => approved,
            Err((left, right)) => {
                queue.push(right);
                queue.push(left);
                continue;
            }
        };
        let key = format!("terminal.{}.{}.{}", key_component(&feed.id), first, last);
        let range = DeliveryRangeV1::Committed { first, last };
        let size = u64::try_from(approved.as_ref().len())
            .map_err(|_| StoreError::Conflict("feed batch size overflow".into()))?;
        if let Some(staged) = stores
            .request_commits
            .staged_feed_batch(run.id, &feed.id, &key)
            .await?
        {
            // Sealed writes mint new artifact IDs. Resume the original approved manifest,
            // but never let a changed serializer or retention deadline reuse its identity.
            if staged.range != range
                || staged.size_bytes != size
                || staged.content.artifact().digest
                    != crawlx_core::hash::Digest::of("crawlx/artifact/v1", approved.as_ref())
                || staged.expires_at > deadline
            {
                return Err(StoreError::Conflict("staged feed batch content changed".into()));
            }
            continue;
        }
        let page = terminal_page(run, feed, first)?;
        let reference = put_approved(
            stores.artifacts.as_ref(),
            run,
            page,
            &format!("terminal.{}", key_component(&feed.id)),
            compression::media_type(codec, mime(feed))?,
            &approved,
            Some(deadline),
        )
        .await?;
        let content = stores
            .artifacts
            .dataset_content(run.id, page, &reference, size)
            .await?;
        let deadline = content
            .expires_at()
            .map_or(deadline, |expiry| expiry.min(deadline));
        let mut batch = DeliveryBatchV1::for_request(feed.id.clone(), key, content, size, deadline);
        batch.range = range;
        stores
            .request_commits
            .stage_feed_batches(run.id, &[batch])
            .await?;
    }
    Ok(())
}

async fn terminal_batches(
    stores: &Stores,
    cpu: &CpuPool,
    run: &CrawlRun,
    feed: &FeedDeclarationV1,
) -> Result<(), StoreError> {
    let article = run
        .config
        .datasets
        .stores
        .iter()
        .any(|store| store.name == feed.source && store.schema_version == "document_v1");
    let deadline = article_deadline(run, None).unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC);
    let mut pending = accumulator(cpu, feed, deadline)?;
    let mut after = 0;
    loop {
        let rows = stores.datasets.items(run.id, &feed.source, after, 128).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.ordinal;
            let (bytes, expiry, input_credit) = if let Some(fragment) = row
                .item
                .feed_fragments
                .iter()
                .find(|fragment| fragment.feed == feed.id)
            {
                let credit = cpu.try_reserve_article_output(
                    usize::try_from(fragment.size_bytes)
                        .map_err(|_| StoreError::Conflict("feed fragment byte overflow".into()))?,
                )?;
                (
                    load_fragment(stores, run, fragment).await?,
                    fragment.expires_at,
                    credit,
                )
            } else if row.item.schema_version == "json_object_v1" {
                let maximum = usize::try_from(feed.max_batch_bytes)
                    .map_err(|_| StoreError::Conflict("feed byte overflow".into()))?;
                let credit = cpu.try_reserve_article_output(
                    usize::try_from(row.item.size_bytes)
                        .ok()
                        .and_then(|n| n.checked_mul(64))
                        .and_then(|n| n.checked_add(maximum))
                        .ok_or_else(|| StoreError::Conflict("feed source reservation overflow".into()))?,
                )?;
                let expiry = row
                    .item
                    .expires_at
                    .ok_or_else(|| StoreError::RetentionDenied("feed source deadline unavailable".into()))?;
                let input = DeliveryBatchV1::for_request(
                    feed.id.clone(),
                    "source".into(),
                    row.item.content.clone(),
                    row.item.size_bytes,
                    expiry,
                );
                let bytes = load_fragment(stores, run, &input).await?;
                let options = feed.clone();
                let (bytes, credit) = cpu
                    .run(move || {
                        Redactor::new().check_canonical(&bytes)?;
                        let value: Value = serde_json::from_slice(&bytes)
                            .map_err(|_| StoreError::Serialization("accepted JSON object invalid".into()))?;
                        if !options.item_filter.matches(&value) {
                            return Ok::<_, StoreError>((None, credit));
                        }
                        let mut output = LimitedOutput::new(maximum);
                        write_generic(&mut output, &value, &options)?;
                        Ok::<_, StoreError>((Some(output.bytes), credit))
                    })
                    .await
                    .map_err(|_| StoreError::Backend("feed source CPU task failed".into()))??;
                let Some(bytes) = bytes else {
                    continue;
                };
                (bytes, expiry, credit)
            } else {
                continue;
            };
            let options = feed.clone();
            let ordinal = row.ordinal;
            let (returned, bytes, credit, accepted) = cpu
                .run(move || {
                    let mut pending = pending;
                    let accepted = pending.0.push(&options, article, ordinal, &bytes, expiry)?;
                    Ok::<_, StoreError>((pending, bytes, input_credit, accepted))
                })
                .await
                .map_err(|_| StoreError::Backend("feed aggregation CPU task failed".into()))??;
            pending = returned;
            if !accepted {
                publish(stores, cpu, run, feed, pending).await?;
                pending = accumulator(cpu, feed, deadline)?;
                let options = feed.clone();
                pending = cpu
                    .run(move || {
                        let mut pending = pending;
                        if !pending.0.push(&options, article, ordinal, &bytes, expiry)? {
                            return Err(StoreError::Conflict("feed batch cannot accept first item".into()));
                        }
                        drop(credit);
                        Ok::<_, StoreError>(pending)
                    })
                    .await
                    .map_err(|_| StoreError::Backend("feed aggregation CPU task failed".into()))??;
            }
        }
    }
    if pending.0.count > 0 {
        publish(stores, cpu, run, feed, pending).await?;
    }
    Ok(())
}

fn empty_bytes(feed: &FeedDeclarationV1, article: bool) -> Result<Vec<u8>, StoreError> {
    if feed.serializer == "csv" && !feed.parameters.csv_columns.is_empty() {
        let mut output = LimitedOutput::new(
            usize::try_from(feed.max_batch_bytes)
                .map_err(|_| StoreError::Conflict("empty CSV byte overflow".into()))?,
        );
        write_generic(&mut output, &Value::Object(serde_json::Map::new()), feed)?;
        let end = output
            .bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| StoreError::Serialization("empty CSV header missing".into()))?;
        output.bytes.truncate(end);
        return Ok(output.bytes);
    }
    let bytes: &[u8] = match feed.serializer.as_str() {
        "json" => b"[]\n",
        "csv" if article => b"source,title,source_url,text,comments\r\n",
        "xml" if article => b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<articles version=\"1\"></articles>\n",
        "xml" => b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items version=\"1\"></items>\n",
        "tei" => return Err(StoreError::Conflict("TEI corpus requires at least one accepted document".into())),
        "html" => b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Offline article collection</title></head><body></body></html>\n",
        "csv" | "jsonl" | "text" | "markdown" | "search_json" => b"",
        _ => return Err(StoreError::Conflict("empty feed serializer unavailable".into())),
    };
    Ok(bytes.to_vec())
}

/// Lifetime of one finalizer claim; the holder renews it every third of this.
const FINALIZER_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Renew the claim until it cannot be renewed; resolves only with the error that ended it.
async fn keep_finalizer_live(
    repo: &dyn crawlx_core::orchestration::RequestCommitRepo,
    lease: &crawlx_core::custody::CustodyLease,
) -> StoreError {
    let mut ticks = tokio::time::interval(FINALIZER_TTL / 3);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        if let Err(error) = repo.renew_feed_finalizer(lease, FINALIZER_TTL).await {
            return error;
        }
    }
}

/// How long a busy claim is polled before its owner is presumed stuck.
const CLAIM_WAIT: std::time::Duration = std::time::Duration::from_secs(120);
const CLAIM_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Claim the finalizer of `run`, waiting out a live claim of another worker.
///
/// `None` means the finalization already completed elsewhere, so there is nothing left to seal.
async fn claim_finalizer(
    stores: &Stores,
    run: crawlx_core::CrawlRunId,
    worker: crawlx_core::WorkerId,
) -> Result<Option<crawlx_core::custody::CustodyLease>, StoreError> {
    let give_up = tokio::time::Instant::now() + CLAIM_WAIT;
    loop {
        match stores
            .request_commits
            .claim_feed_finalizer(run, worker, FINALIZER_TTL)
            .await
        {
            Ok(lease) => return Ok(Some(lease)),
            Err(StoreError::LeaseLost) => return Ok(None),
            Err(StoreError::Conflict(_)) if tokio::time::Instant::now() < give_up => {
                tokio::time::sleep(CLAIM_POLL).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Seal the terminal feed artifacts of `run` and end its feed finalization.
///
/// Terminal batches are sealed artifacts, so they are written under the run's claimed
/// finalizer lease ([`crawlx_core::orchestration::RequestCommitRepo::claim_feed_finalizer`]) and
/// its run-wide secret check. A run without terminal or empty-emit feeds writes nothing and
/// needs no claim. A failed attempt releases its claim so recovery can take over at once.
pub(crate) async fn finalize_feeds(
    stores: &Stores,
    run: &CrawlRun,
    reason: crawlx_core::counters::TerminalReason,
    cpu: &CpuPool,
    worker: crawlx_core::WorkerId,
) -> Result<(), StoreError> {
    let seals = run.config.datasets.feeds.iter().any(|feed| {
        feed.batching == FeedBatchingV1::Terminal || feed.empty_policy == EmptyFeedPolicyV1::Emit
    });
    if !seals {
        return publish_terminal_feeds(stores, run, reason, cpu).await;
    }
    // Another worker may be finalizing the same run right now; wait for it to finish or for its
    // claim to expire, rather than failing a run that is already being finished.
    let Some(lease) = claim_finalizer(stores, run.id, worker).await? else {
        return Ok(());
    };
    let work = async {
        let publish = publish_terminal_feeds(stores, run, reason, cpu);
        tokio::pin!(publish);
        tokio::select! {
            biased;
            outcome = &mut publish => outcome,
            error = keep_finalizer_live(stores.request_commits.as_ref(), &lease) => Err(error),
        }
    };
    let outcome = crawlx_core::custody::with_producer(
        lease.clone(),
        crate::custody_renewal::with_custody_renewal(stores.secret_authority.clone(), lease.clone(), work),
    )
    .await;
    if outcome.is_err() {
        if let Err(error) = stores.request_commits.release_feed_finalizer(&lease).await {
            tracing::warn!(run = %run.id, %error, "feed finalizer claim not released");
        }
    }
    outcome
}

async fn publish_terminal_feeds(
    stores: &Stores,
    run: &CrawlRun,
    reason: crawlx_core::counters::TerminalReason,
    cpu: &CpuPool,
) -> Result<(), StoreError> {
    for feed in &run.config.datasets.feeds {
        if feed.batching == FeedBatchingV1::Terminal {
            terminal_batches(stores, cpu, run, feed).await?;
        }
    }
    let mut empty = Vec::new();
    for feed in &run.config.datasets.feeds {
        if feed.empty_policy != EmptyFeedPolicyV1::Emit {
            continue;
        }
        let article = run
            .config
            .datasets
            .stores
            .iter()
            .any(|store| store.name == feed.source && store.schema_version == "document_v1");
        let maximum = usize::try_from(feed.max_batch_bytes)
            .map_err(|_| StoreError::Conflict("empty feed byte overflow".into()))?;
        let reservation =
            cpu.try_reserve_article_output(compression::reservation_bytes(feed.compression, maximum)?)?;
        let options = feed.clone();
        // An archive completion feed delivers the committed export's hash and size instead of
        // an empty body; every other feed keeps its empty serialization.
        let notice =
            crate::delivery::archive_completion_notice(stores, run, feed, &crawlx_core::time::SystemClock)
                .await?;
        let (approved, reservation) = cpu
            .run(move || {
                let bytes = match notice {
                    Some(bytes) => bytes,
                    None => empty_bytes(&options, article)?,
                };
                let approved = Redactor::new().verify_canonical_owned(bytes)?;
                Ok::<_, StoreError>((
                    compression::encode_approved(approved, options.compression, maximum)?,
                    reservation,
                ))
            })
            .await
            .map_err(|_| StoreError::Backend("empty feed CPU task failed".into()))??;
        let output = (approved, reservation);
        let page = terminal_page(run, feed, 0)?;
        let reference = put_approved(
            stores.artifacts.as_ref(),
            run,
            page,
            &format!("empty.{}", key_component(&feed.id)),
            compression::media_type(feed.compression, mime(feed))?,
            &output.0,
            None,
        )
        .await?;
        let size = u64::try_from(output.0.as_ref().len())
            .map_err(|_| StoreError::Conflict("empty feed size overflow".into()))?;
        let content = stores
            .artifacts
            .dataset_content(run.id, page, &reference, size)
            .await?;
        let deadline = content
            .expires_at()
            .or_else(|| article_deadline(run, None))
            .ok_or_else(|| StoreError::RetentionDenied("empty feed deadline unavailable".into()))?;
        let mut batch = DeliveryBatchV1::for_request(
            feed.id.clone(),
            format!("terminal.empty.{}", key_component(&feed.id)),
            content,
            size,
            deadline,
        );
        batch.range = DeliveryRangeV1::Empty;
        empty.push(batch);
    }
    stores
        .request_commits
        .finalize_run_feeds(run.id, crate::run::status_for(reason), reason, &empty)
        .await
}
