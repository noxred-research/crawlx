//! Link and media scoring (`link_media_score_v1`) and head-metadata preview intents.
//!
//! Every link and media reference of a parsed page is scored from two separately retained
//! groups of components, all integer permille (0..=1000):
//!
//! * the **intrinsic** score reads only the reference itself: anchor text quality, URL shape
//!   (scheme, depth, query, tracking and session parameters) and `rel` hints for links; alt text,
//!   declared dimensions and file format for media;
//! * the **contextual** score reads where the reference sits: page region (`main`/`article` against
//!   navigation, header, footer, sidebar), the link density of its nearest block container, its
//!   position in document order and its heading proximity for links; region, figure context and
//!   position for media.
//!
//! The combined score is the plain mean of the two totals. Links also carry an internal /
//! subdomain / external class against the page host (a leading `www.` is ignored).
//!
//! Preview intents are the extraction side of head previews: the best-scoring links become
//! [`PreviewIntentV1`] values, a request for the worker to fulfil under its own scope, robots,
//! egress and budget decisions. Targets that [`PreviewIntentV1`] refuses (private, loopback,
//! link-local, local names, credentials) never become intents and are reported in
//! [`LinkMediaReport::refused_previews`]. This module never fetches. [`project_head`] turns the
//! head bytes a worker obtained for an intent into a bounded [`HeadProjection`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crawlx_core::extraction::{PreviewIntentV1, PreviewPurposeV1, PreviewRefusalV1};
use ego_tree::NodeId;
use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::document::ExtractedLink;
use crate::dom::{collapse_ws, resolve, srcset_urls, walk};
use crate::media::{kind_from_extension, MediaKind};
use crate::metadata::effective_base;
use crate::ExtractError;

/// Schema version of the report and of every weight below.
pub const LINK_MEDIA_SCHEMA: &str = "link_media_score_v1";
/// Most links scored per page.
pub const MAX_SCORED_LINKS: usize = 2_000;
/// Most images and audio/video elements scored per page (each).
pub const MAX_SCORED_MEDIA: usize = 1_000;
/// Most preview intents a request may ask for.
pub const MAX_PREVIEWS: usize = 32;
/// Most refused preview targets reported.
const MAX_REFUSED: usize = 32;
/// Characters of container text examined for the link density of one block.
const DENSITY_TEXT_CAP: usize = 20_000;

const GENERIC_ANCHORS: [&str; 10] = [
    "click here",
    "here",
    "read more",
    "more",
    "learn more",
    "link",
    "this",
    "continue",
    "details",
    "click",
];
const TRACKING_PARAMS: [&str; 10] = [
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "ref", "ref_src", "igshid", "yclid", "_ga",
];
const SESSION_PARAMS: [&str; 5] = ["sessionid", "phpsessid", "jsessionid", "sid", "session_id"];
const BLOCK_CONTAINERS: [&str; 17] = [
    "p",
    "li",
    "td",
    "th",
    "dd",
    "dt",
    "blockquote",
    "figcaption",
    "div",
    "section",
    "article",
    "main",
    "aside",
    "nav",
    "header",
    "footer",
    "body",
];

/// Options of [`score`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct LinkMediaOptions {
    /// Preview intents to create for the best links; 0 (default) creates none, at most 32.
    pub max_previews: usize,
    /// Combined score (permille) a link needs to be previewed.
    pub min_preview_score: u32,
}

impl Default for LinkMediaOptions {
    fn default() -> Self {
        Self {
            max_previews: 0,
            min_preview_score: 600,
        }
    }
}

impl LinkMediaOptions {
    /// Options that also ask for up to `max_previews` preview intents.
    #[must_use]
    pub fn with_previews(max_previews: usize) -> Self {
        Self {
            max_previews,
            ..Self::default()
        }
    }
}

/// Relation of a link target to the page host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LinkClass {
    /// Same host (ignoring a leading `www.`).
    Internal,
    /// A strict subdomain of the page host.
    Subdomain,
    /// Any other host.
    External,
}

/// Components that depend on the link alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IntrinsicLinkScore {
    /// Anchor text quality: empty or generic text scores low, short descriptive text high.
    pub text: u32,
    /// URL shape: https, shallow path, no query, tracking or session parameters.
    pub url: u32,
    /// `rel` hints: `nofollow`, `sponsored` and `ugc` score low.
    pub rel: u32,
    /// Weighted total (text 400, url 400, rel 200).
    pub total: u32,
}

/// Components that depend on where the link sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContextualLinkScore {
    /// Page region: `main`/`article` high, sidebar, header, navigation and footer low.
    pub region: u32,
    /// One minus the link density of the nearest block container.
    pub container_density: u32,
    /// Earlier distinct links score higher (floor 100).
    pub position: u32,
    /// Inside a heading: `h1`-`h3` high, `h4`-`h6` upper-middle, otherwise neutral.
    pub heading: u32,
    /// Weighted total (region 400, container density 300, position 150, heading 150).
    pub total: u32,
}

/// One scored link. `link_index` is the position in `Document::links`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ScoredLink {
    /// Index into the document's link list.
    pub link_index: usize,
    /// Link target.
    pub url: Url,
    /// Relation to the page host.
    pub class: LinkClass,
    /// Anchors that point at this URL.
    pub occurrences: usize,
    /// Intrinsic components.
    pub intrinsic: IntrinsicLinkScore,
    /// Contextual components of the first occurrence.
    pub contextual: ContextualLinkScore,
    /// Mean of the two totals.
    pub combined: u32,
}

/// Kind of a scored media reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MediaScoreKind {
    /// `<img>`.
    Image,
    /// `<audio>`.
    Audio,
    /// `<video>`.
    Video,
}

/// Components that depend on the media reference alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IntrinsicMediaScore {
    /// Alt text (images) or title/`aria-label` (audio, video); an explicit empty alt is decorative.
    pub description: u32,
    /// Declared pixel dimensions; icons and tracking pixels score zero.
    pub dimensions: u32,
    /// File format by extension (or declared type).
    pub format: u32,
    /// Weighted total (description 400, dimensions 350, format 250).
    pub total: u32,
}

/// Components that depend on where the media sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContextualMediaScore {
    /// Page region, as for links.
    pub region: u32,
    /// Inside a `figure` (with a `figcaption` scores highest).
    pub figure: u32,
    /// Earlier media of the same group score higher (floor 100).
    pub position: u32,
    /// Weighted total (region 400, figure 350, position 250).
    pub total: u32,
}

/// One scored media reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ScoredMedia {
    /// Absolute media URL.
    pub url: Url,
    /// Image, audio or video.
    pub kind: MediaScoreKind,
    /// Elements that reference this URL.
    pub occurrences: usize,
    /// Intrinsic components.
    pub intrinsic: IntrinsicMediaScore,
    /// Contextual components of the first occurrence.
    pub contextual: ContextualMediaScore,
    /// Mean of the two totals.
    pub combined: u32,
}

/// A link target that was refused as a preview target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RefusedPreview {
    /// The refused target.
    pub url: Url,
    /// Why.
    pub reason: PreviewRefusalV1,
}

/// Scores and preview intents of one page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LinkMediaReport {
    /// Schema version ([`LINK_MEDIA_SCHEMA`]).
    pub schema: String,
    /// Scored links in document order.
    pub links: Vec<ScoredLink>,
    /// Scored images in document order.
    pub images: Vec<ScoredMedia>,
    /// Scored audio and video elements in document order.
    pub media: Vec<ScoredMedia>,
    /// Preview requests for the worker to fulfil; the extractor never fetches.
    pub previews: Vec<PreviewIntentV1>,
    /// Link targets refused at intent creation.
    pub refused_previews: Vec<RefusedPreview>,
    /// A cap on scored links or media was hit.
    pub truncated: bool,
}

fn mean(a: u32, b: u32) -> u32 {
    (a + b) / 2
}

fn weighted(parts: &[(u32, u32)]) -> u32 {
    parts.iter().map(|(w, v)| w * v).sum::<u32>() / 1_000
}

fn region_score(el: ElementRef<'_>) -> u32 {
    for anc in el.ancestors().filter_map(ElementRef::wrap) {
        let v = anc.value();
        match v.name() {
            "main" | "article" => return 1_000,
            "nav" => return 150,
            "footer" => return 100,
            "aside" => return 250,
            "header" => return 300,
            _ => {}
        }
        match v.attr("role").map(str::to_ascii_lowercase).as_deref() {
            Some("main" | "article") => return 1_000,
            Some("navigation") => return 150,
            Some("contentinfo") => return 100,
            Some("complementary") => return 250,
            Some("banner") => return 300,
            _ => {}
        }
    }
    600
}

fn heading_score(el: ElementRef<'_>) -> u32 {
    for anc in std::iter::once(el).chain(el.ancestors().filter_map(ElementRef::wrap)) {
        match anc.value().name() {
            "h1" | "h2" | "h3" => return 1_000,
            "h4" | "h5" | "h6" => return 800,
            _ => {}
        }
    }
    500
}

fn non_space_chars(texts: impl Iterator<Item = impl AsRef<str>>, cap: usize) -> usize {
    let mut n = 0;
    for t in texts {
        n += t.as_ref().chars().filter(|c| !c.is_whitespace()).count();
        if n >= cap {
            return cap;
        }
    }
    n
}

/// Permille of the container's text that sits inside anchors, memoized per container.
fn container_link_density(el: ElementRef<'_>, cache: &mut HashMap<NodeId, u32>) -> u32 {
    let Some(block) = el
        .ancestors()
        .filter_map(ElementRef::wrap)
        .find(|a| BLOCK_CONTAINERS.contains(&a.value().name()))
    else {
        return 0;
    };
    if let Some(v) = cache.get(&block.id()) {
        return *v;
    }
    let total = non_space_chars(block.text(), DENSITY_TEXT_CAP);
    let mut linked = 0;
    for a in block
        .descendants()
        .filter_map(ElementRef::wrap)
        .filter(|d| d.value().name() == "a")
    {
        linked += non_space_chars(a.text(), DENSITY_TEXT_CAP);
        if linked >= total {
            break;
        }
    }
    let density = (linked.min(total) * 1_000)
        .checked_div(total)
        .map_or(500, |d| u32::try_from(d.min(1_000)).unwrap_or(1_000));
    cache.insert(block.id(), density);
    density
}

fn text_score(text: &str) -> u32 {
    let words = text.split_whitespace().count();
    let lowered = text
        .trim()
        .trim_end_matches(['.', '!', '›', '»', '→'])
        .to_lowercase();
    if words == 0 {
        0
    } else if GENERIC_ANCHORS.contains(&lowered.as_str()) {
        200
    } else if words == 1 {
        600
    } else if words <= 12 {
        1_000
    } else {
        700
    }
}

fn url_score(u: &Url) -> u32 {
    let mut s: i64 = 1_000;
    if u.scheme() != "https" {
        s -= 100;
    }
    let depth = u
        .path_segments()
        .map_or(0, |p| p.filter(|x| !x.is_empty()).count());
    if depth > 5 {
        s -= 200;
    }
    let (mut query, mut tracking, mut session) = (false, false, false);
    for (k, _) in u.query_pairs() {
        query = true;
        let k = k.to_ascii_lowercase();
        tracking |= k.starts_with("utm_") || TRACKING_PARAMS.contains(&k.as_str());
        session |= SESSION_PARAMS.contains(&k.as_str());
    }
    if query {
        s -= 100;
    }
    if tracking {
        s -= 300;
    }
    if session {
        s -= 300;
    }
    u32::try_from(s.clamp(0, 1_000)).unwrap_or(0)
}

fn classify(page: &Url, link: &Url) -> LinkClass {
    let (Some(p), Some(l)) = (page.host_str(), link.host_str()) else {
        return LinkClass::External;
    };
    let norm = |h: &str| {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        h.strip_prefix("www.").map_or(h.clone(), str::to_owned)
    };
    match crawlx_url::host_relation(&norm(p), &norm(l)) {
        crawlx_url::HostRelation::Same => LinkClass::Internal,
        crawlx_url::HostRelation::Subdomain => LinkClass::Subdomain,
        crawlx_url::HostRelation::External => LinkClass::External,
    }
}

struct RawLink {
    link_index: usize,
    url: Url,
    occurrences: usize,
    intrinsic: IntrinsicLinkScore,
    region: u32,
    density: u32,
    heading: u32,
}

#[derive(Clone)]
struct RawMedia {
    url: Url,
    kind: MediaScoreKind,
    occurrences: usize,
    intrinsic: IntrinsicMediaScore,
    region: u32,
    figure: u32,
}

fn position(index: usize, count: usize) -> u32 {
    if count <= 1 {
        return 1_000;
    }
    let v = 1_000 - index.min(count) * 1_000 / count;
    u32::try_from(v.max(100)).unwrap_or(100)
}

fn dimension(el: &scraper::node::Element, name: &str) -> Option<u64> {
    let raw = el.attr(name)?.trim().trim_end_matches("px").trim();
    raw.parse::<u64>().ok()
}

fn dimension_score(el: &scraper::node::Element) -> u32 {
    match (dimension(el, "width"), dimension(el, "height")) {
        (Some(w), Some(h)) => {
            let area = w.saturating_mul(h);
            if w < 64 || h < 64 || area < 4_096 {
                0
            } else if area < 15_000 {
                400
            } else if area >= 60_000 {
                1_000
            } else {
                700
            }
        }
        (Some(v), None) | (None, Some(v)) => {
            if v < 64 {
                0
            } else {
                600
            }
        }
        (None, None) => 500,
    }
}

fn image_format_score(u: &Url) -> u32 {
    let ext = u
        .path_segments()
        .and_then(|mut s| s.next_back())
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("jpg" | "jpeg" | "png" | "webp" | "avif") => 1_000,
        Some("gif") => 600,
        Some("svg") => 500,
        Some("ico") => 100,
        _ => 600,
    }
}

fn figure_score(el: ElementRef<'_>) -> u32 {
    for anc in el.ancestors().filter_map(ElementRef::wrap) {
        if anc.value().name() == "figure" {
            let captioned = anc
                .descendants()
                .filter_map(ElementRef::wrap)
                .any(|d| d.value().name() == "figcaption");
            return if captioned { 1_000 } else { 700 };
        }
    }
    400
}

fn first_url(base: &Url, el: &scraper::node::Element) -> Option<Url> {
    let candidates = ["src", "data-src", "data-original", "data-lazy-src"]
        .iter()
        .filter_map(|n| el.attr(n))
        .chain(
            ["srcset", "data-srcset"]
                .iter()
                .filter_map(|n| el.attr(n))
                .flat_map(|s| srcset_urls(s).into_iter().take(1)),
        );
    for raw in candidates {
        if let Some(mut u) = resolve(base, raw) {
            if matches!(u.scheme(), "http" | "https") {
                u.set_fragment(None);
                return Some(u);
            }
        }
    }
    None
}

fn av_url(base: &Url, el: ElementRef<'_>) -> Option<Url> {
    let direct = el.value().attr("src").map(str::to_owned);
    let child = || {
        el.children()
            .filter_map(ElementRef::wrap)
            .filter(|c| c.value().name() == "source")
            .find_map(|c| c.value().attr("src").map(str::to_owned))
    };
    let raw = direct.or_else(child)?;
    let mut u = resolve(base, &raw)?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.set_fragment(None);
    Some(u)
}

fn collect_links(doc: &Html, base: &Url, links: &[ExtractedLink], truncated: &mut bool) -> Vec<RawLink> {
    let index: HashMap<&str, usize> = links
        .iter()
        .enumerate()
        .map(|(i, l)| (l.url.as_str(), i))
        .collect();
    let mut out: Vec<RawLink> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut cache: HashMap<NodeId, u32> = HashMap::new();
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "script" | "style" | "template" => return false,
            "a" | "area" => {}
            _ => return true,
        }
        let Some(href) = v.attr("href").map(str::trim) else {
            return true;
        };
        if href.is_empty() || href.starts_with('#') {
            return true;
        }
        let Some(mut url) = resolve(base, href) else {
            return true;
        };
        if !matches!(url.scheme(), "http" | "https") {
            return true;
        }
        url.set_fragment(None);
        let Some(&link_index) = index.get(url.as_str()) else {
            return true;
        };
        if let Some(&i) = seen.get(url.as_str()) {
            out[i].occurrences += 1;
            return true;
        }
        if out.len() >= MAX_SCORED_LINKS {
            *truncated = true;
            return true;
        }
        let rel = v.attr("rel").unwrap_or("").to_ascii_lowercase();
        let weak_rel = rel
            .split_whitespace()
            .any(|r| matches!(r, "nofollow" | "sponsored" | "ugc"));
        let text = collapse_ws(&links[link_index].text);
        let intrinsic_text = text_score(&text);
        let intrinsic_url = url_score(&url);
        let intrinsic_rel = if weak_rel { 200 } else { 1_000 };
        let intrinsic = IntrinsicLinkScore {
            text: intrinsic_text,
            url: intrinsic_url,
            rel: intrinsic_rel,
            total: weighted(&[(400, intrinsic_text), (400, intrinsic_url), (200, intrinsic_rel)]),
        };
        seen.insert(url.as_str().to_owned(), out.len());
        out.push(RawLink {
            link_index,
            url,
            occurrences: 1,
            intrinsic,
            region: region_score(el),
            density: 1_000 - container_link_density(el, &mut cache),
            heading: heading_score(el),
        });
        true
    });
    out
}

fn collect_media(
    doc: &Html,
    base: &Url,
    allowed: Option<&BTreeSet<String>>,
    truncated: &mut bool,
) -> Vec<RawMedia> {
    let mut out: Vec<RawMedia> = Vec::new();
    let mut seen: HashMap<(MediaScoreKind, String), usize> = HashMap::new();
    let mut per_kind = [0usize; 3];
    walk(doc.tree.root(), |el| {
        let v = el.value();
        let (kind, url) = match v.name() {
            "script" | "style" | "template" => return false,
            "img" => (MediaScoreKind::Image, first_url(base, v)),
            "video" => (MediaScoreKind::Video, av_url(base, el)),
            "audio" => (MediaScoreKind::Audio, av_url(base, el)),
            _ => return true,
        };
        let Some(url) = url else {
            return true;
        };
        if allowed.is_some_and(|set| !set.contains(url.as_str())) {
            return true;
        }
        let key = (kind, url.as_str().to_owned());
        if let Some(&i) = seen.get(&key) {
            out[i].occurrences += 1;
            return true;
        }
        let slot = match kind {
            MediaScoreKind::Image => 0,
            MediaScoreKind::Audio => 1,
            MediaScoreKind::Video => 2,
        };
        if per_kind[slot] >= MAX_SCORED_MEDIA {
            *truncated = true;
            return true;
        }
        per_kind[slot] += 1;
        let description = match kind {
            MediaScoreKind::Image => match v.attr("alt").map(str::trim) {
                Some(a) if !a.is_empty() => 1_000,
                Some(_) => 300,
                None if v.attr("role") == Some("presentation") => 300,
                None => 0,
            },
            _ => {
                if ["title", "aria-label"]
                    .iter()
                    .any(|n| v.attr(n).is_some_and(|t| !t.trim().is_empty()))
                {
                    1_000
                } else {
                    0
                }
            }
        };
        let dimensions = if kind == MediaScoreKind::Audio {
            500
        } else {
            dimension_score(v)
        };
        let format = match kind {
            MediaScoreKind::Image => image_format_score(&url),
            _ => {
                if kind_from_extension(&url).is_some_and(|k| {
                    matches!(
                        (k, kind),
                        (MediaKind::Audio, MediaScoreKind::Audio) | (MediaKind::Video, MediaScoreKind::Video)
                    )
                }) {
                    1_000
                } else if v.attr("type").is_some() {
                    900
                } else {
                    500
                }
            }
        };
        let intrinsic = IntrinsicMediaScore {
            description,
            dimensions,
            format,
            total: weighted(&[(400, description), (350, dimensions), (250, format)]),
        };
        seen.insert(key, out.len());
        out.push(RawMedia {
            url,
            kind,
            occurrences: 1,
            intrinsic,
            region: region_score(el),
            figure: figure_score(el),
        });
        true
    });
    out
}

fn finish_media(raw: Vec<RawMedia>, kind_filter: impl Fn(MediaScoreKind) -> bool) -> Vec<ScoredMedia> {
    let picked: Vec<RawMedia> = raw.into_iter().filter(|m| kind_filter(m.kind)).collect();
    let count = picked.len();
    picked
        .into_iter()
        .enumerate()
        .map(|(i, m)| {
            let pos = position(i, count);
            let total = weighted(&[(400, m.region), (350, m.figure), (250, pos)]);
            ScoredMedia {
                url: m.url,
                kind: m.kind,
                occurrences: m.occurrences,
                contextual: ContextualMediaScore {
                    region: m.region,
                    figure: m.figure,
                    position: pos,
                    total,
                },
                combined: mean(m.intrinsic.total, total),
                intrinsic: m.intrinsic,
            }
        })
        .collect()
}

/// Score the links and media of `doc`.
///
/// `links` is the document's link list (its indices are reported); only links found in it are
/// scored, so a narrowed list narrows the report. `allowed_media` limits scored media to those
/// URLs; `None` scores the whole page. `base` is the effective base of the document.
#[must_use]
pub fn score(
    doc: &Html,
    page: &Url,
    base: &Url,
    links: &[ExtractedLink],
    allowed_media: Option<&BTreeSet<String>>,
    options: &LinkMediaOptions,
) -> LinkMediaReport {
    let mut truncated = false;
    let raw_links = collect_links(doc, base, links, &mut truncated);
    let count = raw_links.len();
    let scored_links: Vec<ScoredLink> = raw_links
        .into_iter()
        .enumerate()
        .map(|(i, l)| {
            let pos = position(i, count);
            let total = weighted(&[(400, l.region), (300, l.density), (150, pos), (150, l.heading)]);
            ScoredLink {
                link_index: l.link_index,
                class: classify(page, &l.url),
                url: l.url,
                occurrences: l.occurrences,
                contextual: ContextualLinkScore {
                    region: l.region,
                    container_density: l.density,
                    position: pos,
                    heading: l.heading,
                    total,
                },
                combined: mean(l.intrinsic.total, total),
                intrinsic: l.intrinsic,
            }
        })
        .collect();
    let raw_media = collect_media(doc, base, allowed_media, &mut truncated);
    let images = finish_media(raw_media.clone(), |k| k == MediaScoreKind::Image);
    let media = finish_media(raw_media, |k| k != MediaScoreKind::Image);

    let mut previews = Vec::new();
    let mut refused_previews = Vec::new();
    let wanted = options.max_previews.min(MAX_PREVIEWS);
    if wanted > 0 {
        let mut order: Vec<&ScoredLink> = scored_links
            .iter()
            .filter(|l| l.combined >= options.min_preview_score && l.url != *page)
            .collect();
        order.sort_by(|a, b| b.combined.cmp(&a.combined).then(a.link_index.cmp(&b.link_index)));
        for link in order {
            if previews.len() >= wanted {
                break;
            }
            match PreviewIntentV1::new(link.url.clone(), PreviewPurposeV1::HeadMetadata) {
                Ok(intent) => previews.push(intent),
                Err(reason) if refused_previews.len() < MAX_REFUSED => {
                    refused_previews.push(RefusedPreview {
                        url: link.url.clone(),
                        reason,
                    })
                }
                Err(_) => {}
            }
        }
    }
    LinkMediaReport {
        schema: LINK_MEDIA_SCHEMA.to_owned(),
        links: scored_links,
        images,
        media,
        previews,
        refused_previews,
        truncated,
    }
}

/// Head metadata of a previewed page, projected from the bytes a worker fetched for an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HeadProjection {
    /// The previewed target (the intent's URL).
    pub url: Url,
    /// Title: `og:title`, then `<title>`.
    pub title: Option<String>,
    /// Meta description.
    pub description: Option<String>,
    /// Document language.
    pub language: Option<String>,
    /// Canonical URL.
    pub canonical_url: Option<Url>,
    /// `og:image` or `twitter:image`, resolved against the target.
    pub image_url: Option<Url>,
    /// `og:site_name`.
    pub site_name: Option<String>,
    /// Robots `noindex`.
    pub noindex: bool,
    /// Robots `nofollow`.
    pub nofollow: bool,
    /// The head bytes were cut at the intent's budget.
    pub truncated: bool,
    /// Further `og:*` properties, sorted by name.
    pub open_graph: BTreeMap<String, String>,
}

/// Project head metadata from `head_bytes`, the bytes a worker obtained for `intent`.
///
/// At most `intent.max_head_bytes` are read (invalid UTF-8 is replaced lossy) and the input is
/// cut after `</head>` when present, so a body never leaks into the projection.
///
/// # Errors
/// [`ExtractError::ParseMemory`] when the process-wide parse-memory budget is exhausted.
pub fn project_head(intent: &PreviewIntentV1, head_bytes: &[u8]) -> Result<HeadProjection, ExtractError> {
    let limit = usize::try_from(intent.max_head_bytes).unwrap_or(usize::MAX);
    let truncated = head_bytes.len() > limit;
    let slice = &head_bytes[..head_bytes.len().min(limit)];
    let text = String::from_utf8_lossy(slice);
    let lowered_end = text
        .to_ascii_lowercase()
        .find("</head>")
        .map(|i| i + "</head>".len());
    let head = lowered_end.map_or(&*text, |end| &text[..end]);
    let mut charge = crate::parse_budget::charge(head.len())?;
    let doc = crate::dom::parse_document(&mut charge, head)?;
    let base = effective_base(&doc, &intent.url);
    let info = crate::metadata::extract(&doc, &base);
    let md = &info.metadata;
    let image_url = ["og:image", "og:image:url", "og:image:secure_url"]
        .iter()
        .find_map(|k| md.open_graph.get(*k))
        .or_else(|| md.twitter.get("twitter:image"))
        .and_then(|raw| resolve(&base, raw))
        .filter(|u| matches!(u.scheme(), "http" | "https"));
    Ok(HeadProjection {
        url: intent.url.clone(),
        title: info.title,
        description: info.description,
        language: info.language,
        canonical_url: info.canonical_url,
        image_url,
        site_name: md.open_graph.get("og:site_name").cloned(),
        noindex: md.robots.noindex,
        nofollow: md.robots.nofollow,
        truncated,
        open_graph: md.open_graph.clone(),
    })
}
