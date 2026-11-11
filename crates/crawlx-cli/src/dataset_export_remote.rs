//! Authenticated bounded keyset source for the generic item exporter.
//!
//! Metadata pages are capped at one MiB and content at the selected row-byte ceiling (at most
//! sixteen MiB). Artifact capabilities must match the selected run and committed artifact ID;
//! neither same-origin alternate paths nor redirects may choose another authenticated resource.
//! Article schemas remain owned by the article serializers. HTTP failures are reported by status
//! only, never by echoing content, credentials, response bodies or bearer-bearing request URLs.

use super::{DatasetExportArgs, ItemStream};
use anyhow::{bail, Context};
use crawlx_core::{
    dataset::{validate_identifier, DatasetDeclarationV1, DatasetItemV1},
    CrawlRunId,
};
#[allow(
    clippy::disallowed_types,
    reason = "authenticated dataset download imports the raw reqwest client"
)]
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use std::{io::Write, time::Duration};
use url::Url;

const MAX_METADATA_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
struct Declarations {
    data: Vec<DatasetDeclarationV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    item: DatasetItemV1,
    content_url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    data: Vec<Entry>,
    next_cursor: Option<String>,
}

fn endpoint(args: &DatasetExportArgs, run: CrawlRunId) -> anyhow::Result<Url> {
    let mut url = Url::parse(&args.api.api_url).context("invalid dataset API URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("dataset API URL must be HTTP(S) without credentials, query or fragment");
    }
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid dataset API path"))?
        .pop_if_empty()
        .extend(["v1", "crawls", &run.to_string(), "datasets"]);
    Ok(url)
}

fn artifact_url(endpoint: &Url, run: CrawlRunId, entry: &Entry) -> anyhow::Result<Url> {
    let url = endpoint
        .join(&entry.content_url)
        .context("invalid dataset artifact URL")?;
    let expected = format!(
        "/v1/crawls/{run}/artifacts/{}",
        entry.item.item.content.artifact().id
    );
    if url.origin() != endpoint.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != expected
    {
        bail!("dataset artifact capability does not match selected run and committed item");
    }
    Ok(url)
}

#[allow(
    clippy::disallowed_types,
    reason = "authenticated dataset download takes the raw reqwest client"
)]
async fn bytes(http: &Client, url: Url, key: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut response = http
        .get(url)
        .bearer_auth(key)
        .send()
        .await
        .map_err(|error| error.without_url())?;
    if !response.status().is_success() {
        bail!(
            "dataset API rejected export with status {}",
            response.status().as_u16()
        );
    }
    if response
        .content_length()
        .is_some_and(|size| size > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        bail!("dataset API response byte limit exceeded");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| value.trim() != "application/json")
    {
        bail!("dataset API response must contain JSON");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.without_url())? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            bail!("dataset API response byte limit exceeded");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[allow(
    clippy::disallowed_types,
    reason = "authenticated dataset download takes the raw reqwest client"
)]
async fn metadata<T: DeserializeOwned>(http: &Client, url: Url, key: &str) -> anyhow::Result<T> {
    let body = bytes(http, url, key, MAX_METADATA_BYTES).await?;
    serde_json::from_slice(&body).context("invalid dataset API metadata")
}

fn validate_page(page: &Page, after: u64, limit: u16, schema: &str) -> anyhow::Result<()> {
    if page.data.len() > usize::from(limit) {
        bail!("dataset API exceeded requested page size");
    }
    let mut ordinal = after;
    for entry in &page.data {
        if entry.item.ordinal <= ordinal || entry.item.item.schema_version != schema {
            bail!("dataset API returned unordered items or a conflicting item schema");
        }
        ordinal = entry.item.ordinal;
    }
    let next = page
        .next_cursor
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .context("invalid dataset API cursor")?;
    if next.is_some() != (page.data.len() == usize::from(limit))
        || next.is_some_and(|next| next != ordinal || next <= after)
    {
        bail!("dataset API cursor does not match committed page boundary");
    }
    Ok(())
}

#[allow(
    clippy::disallowed_types,
    reason = "authenticated dataset download builds the raw reqwest client"
)]
pub(super) async fn export(args: &DatasetExportArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    // Validate all serializer and source arguments before issuing a request or writing framing.
    let mut stream = ItemStream::new(args, out)?;
    let run = args.run.context("dataset API export requires --run")?;
    let dataset = args
        .dataset
        .as_deref()
        .context("dataset API export requires --dataset")?;
    validate_identifier(dataset)?;
    let key = args
        .api
        .api_key
        .as_deref()
        .filter(|key| !key.is_empty())
        .context("dataset API export requires a bearer key with crawls:read scope")?;
    let endpoint = endpoint(args, run)?;
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let declarations: Declarations = metadata(&http, endpoint.clone(), key).await?;
    let declaration = declarations
        .data
        .iter()
        .find(|entry| entry.name == dataset)
        .context("dataset API export requires a declared dataset")?;
    let schema = declaration.schema_version.as_str();
    if !matches!(schema, "json_object_v1" | "document_item_v1") {
        bail!("dataset schema is not a generic JSON object; article exports require article serializers");
    }
    let mut items = endpoint.clone();
    items
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid dataset API path"))?
        .extend([dataset, "items"]);
    let limit = usize::try_from(args.max_row_bytes)?;
    let redactor = crawlx_core::secret::Redactor::new();
    let mut after = 0_u64;
    loop {
        items
            .query_pairs_mut()
            .clear()
            .append_pair("limit", &args.page_size.to_string())
            .append_pair("cursor", &after.to_string());
        let page: Page = metadata(&http, items.clone(), key).await?;
        validate_page(&page, after, args.page_size, schema)?;
        for entry in page.data {
            if entry.item.item.size_bytes > u64::try_from(limit)? {
                bail!("committed dataset item exceeds row byte limit");
            }
            let content = bytes(&http, artifact_url(&endpoint, run, &entry)?, key, limit).await?;
            if u64::try_from(content.len())? != entry.item.item.size_bytes {
                bail!("dataset artifact length differs from committed item metadata");
            }
            redactor
                .check_canonical(&content)
                .context("dataset artifact failed canonical privacy validation")?;
            let item: Value = serde_json::from_slice(&content)
                .context("dataset artifact must contain a UTF-8 JSON object")?;
            // The artifact route applies current tenant/scope/retention authority before these
            // bytes arrive. Never turn an unavailable artifact into an empty or fake item.
            stream.push(&item)?;
        }
        match page.next_cursor {
            Some(next) => after = next.parse().context("invalid dataset API cursor")?,
            None => break,
        }
    }
    stream.finish()
}

#[cfg(test)]
#[path = "dataset_export_remote_tests.rs"]
mod tests;
