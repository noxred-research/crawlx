//! The media files a page references, for the compatibility API `audio` and `video` formats.
//!
//! [`media_refs`] reads `<audio src>`, `<video src>`, the `<source>` elements inside them, the
//! Open Graph `og:audio` / `og:video` meta tags, `<link rel="alternate" type="audio/..|video/..">`
//! and `<a href>` links to files with a media extension. `<video poster>` is an image and is not
//! listed. URLs resolve against the document's effective base (`<base href>` aware), are limited
//! to `http`/`https`, lose their fragment and are de-duplicated in document order.
//! [`kind_from_content_type`] and [`kind_from_extension`] classify a downloaded file.

use std::collections::HashSet;

use scraper::Html;
use url::Url;

use crate::dom::{resolve, walk};
use crate::metadata::effective_base;
use crate::ExtractOptions;

/// Most media references returned for one page.
pub const MAX_MEDIA_REFS: usize = 200;

/// Audio file extensions (lower case, without the dot).
const AUDIO_EXTENSIONS: [&str; 8] = ["mp3", "m4a", "aac", "ogg", "oga", "opus", "wav", "flac"];
/// Video file extensions (lower case, without the dot).
const VIDEO_EXTENSIONS: [&str; 6] = ["mp4", "webm", "mov", "mkv", "m4v", "ogv"];
/// Open Graph meta properties that name an audio file.
const OG_AUDIO_KEYS: [&str; 3] = ["og:audio", "og:audio:url", "og:audio:secure_url"];
/// Open Graph meta properties that name a video file.
const OG_VIDEO_KEYS: [&str; 3] = ["og:video", "og:video:url", "og:video:secure_url"];

/// What a media file is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MediaKind {
    /// An audio file (`audio/*`, Ogg audio).
    Audio,
    /// A video file (`video/*`).
    Video,
}

/// One media file a page references.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MediaRef {
    /// Absolute `http(s)` URL without fragment.
    pub url: Url,
    /// Audio or video.
    pub kind: MediaKind,
    /// The media type the page declares for the file (`type` attribute, `og:*:type`), lower case
    /// and without parameters.
    pub declared_type: Option<String>,
    /// The page names the file in a media element (`<audio>`, `<video>`, `<source>`), a meta tag
    /// or a typed `<link>`; `false` for a plain `<a href>` recognised by its extension only.
    pub explicit: bool,
}

/// The media type of a `Content-Type` value: lower case, parameters dropped; `None` when empty.
#[must_use]
pub fn media_type(content_type: &str) -> Option<String> {
    let m = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    (!m.is_empty()).then_some(m)
}

/// The kind of a file by the extension of its URL path (see the module list of extensions).
#[must_use]
pub fn kind_from_extension(url: &Url) -> Option<MediaKind> {
    let name = url.path_segments()?.next_back()?;
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    if AUDIO_EXTENSIONS.contains(&ext.as_str()) {
        Some(MediaKind::Audio)
    } else if VIDEO_EXTENSIONS.contains(&ext.as_str()) {
        Some(MediaKind::Video)
    } else {
        None
    }
}

/// The kind of a response by its `Content-Type`: `audio/*` is audio, `video/*` video; the
/// generic `application/ogg` and `*/octet-stream` types fall back to the extension of `url`
/// (Ogg without a video extension is audio).
#[must_use]
pub fn kind_from_content_type(content_type: &str, url: &Url) -> Option<MediaKind> {
    let media = media_type(content_type)?;
    if media.starts_with("audio/") {
        Some(MediaKind::Audio)
    } else if media.starts_with("video/") {
        Some(MediaKind::Video)
    } else if media == "application/ogg" {
        Some(kind_from_extension(url).unwrap_or(MediaKind::Audio))
    } else if matches!(media.as_str(), "application/octet-stream" | "binary/octet-stream") {
        kind_from_extension(url)
    } else {
        None
    }
}

/// Kind of a reference: the declared type decides, then the element, then the extension.
fn kind_of(declared: Option<&str>, element: Option<MediaKind>, url: &Url) -> Option<MediaKind> {
    match declared {
        Some(t) => kind_from_content_type(t, url),
        None => element.or_else(|| kind_from_extension(url)),
    }
}

/// Is `t` (a `type` attribute value) an audio or video media type?
fn is_av_type(t: &str) -> bool {
    let t = t.trim().to_ascii_lowercase();
    t.starts_with("audio/") || t.starts_with("video/")
}

/// The references found so far.
struct Collector {
    base: Url,
    out: Vec<MediaRef>,
    seen: HashSet<(String, MediaKind)>,
    /// Indexes of references a later `og:*:type` tag proved to be player pages, not files.
    dropped: HashSet<usize>,
    /// Index of the latest `og:audio` / `og:video` reference, which a following `…:type` tag types.
    last_og: [Option<usize>; 2],
}

impl Collector {
    /// Add `raw` as a reference; returns its index when it was added.
    fn add(
        &mut self,
        raw: &str,
        declared: Option<&str>,
        element: Option<MediaKind>,
        explicit: bool,
    ) -> Option<usize> {
        if self.out.len() >= MAX_MEDIA_REFS {
            return None;
        }
        let mut url = resolve(&self.base, raw)?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        url.set_fragment(None);
        let declared = declared.and_then(media_type);
        let kind = kind_of(declared.as_deref(), element, &url)?;
        if !self.seen.insert((url.as_str().to_owned(), kind)) {
            return None;
        }
        self.out.push(MediaRef {
            url,
            kind,
            declared_type: declared,
            explicit,
        });
        Some(self.out.len() - 1)
    }

    /// `og:audio:type` / `og:video:type` (`video` selects which): the declared type of the latest
    /// reference of that kind. A type that is not audio, video or Ogg means the URL is a player
    /// page (`text/html`), so the reference is dropped.
    fn og_type(&mut self, video: bool, declared: &str) {
        let Some(i) = self.last_og[usize::from(video)] else {
            return;
        };
        let (Some(declared), Some(r)) = (media_type(declared), self.out.get_mut(i)) else {
            return;
        };
        match kind_from_content_type(&declared, &r.url) {
            Some(kind) => {
                r.kind = kind;
                r.declared_type = Some(declared);
            }
            None => {
                self.dropped.insert(i);
            }
        }
    }
}

/// Media references of `html` in document order, at most [`MAX_MEDIA_REFS`]. `base` is the page
/// URL; `<base href>` in the document refines it. Input beyond the default extraction limits
/// yields an empty list. The parse is not charged to [`crate::parse_budget`]: callers hold a
/// [`crate::parse_budget::charge`] around this call.
#[must_use]
pub fn media_refs(html: &str, base: &Url) -> Vec<MediaRef> {
    if crate::precheck(html, &ExtractOptions::default()).is_err() {
        return Vec::new();
    }
    let doc = Html::parse_document(html);
    let mut c = Collector {
        base: effective_base(&doc, base),
        out: Vec::new(),
        seen: HashSet::new(),
        dropped: HashSet::new(),
        last_og: [None, None],
    };
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "audio" | "video" => {
                let element = if v.name() == "audio" {
                    MediaKind::Audio
                } else {
                    MediaKind::Video
                };
                if let Some(src) = v.attr("src") {
                    c.add(src, None, Some(element), true);
                }
            }
            "source" => {
                let element = match el
                    .parent()
                    .and_then(scraper::ElementRef::wrap)
                    .map(|p| p.value().name())
                {
                    Some("audio") => Some(MediaKind::Audio),
                    Some("video") => Some(MediaKind::Video),
                    _ => None,
                };
                // A `<source>` of `<picture>` carries image types and falls out in `kind_of`.
                if let Some(src) = v.attr("src") {
                    if element.is_some() || v.attr("type").is_some() {
                        c.add(src, v.attr("type"), element, true);
                    }
                }
            }
            "meta" => {
                let key = v
                    .attr("property")
                    .or_else(|| v.attr("name"))
                    .map(|k| k.trim().to_ascii_lowercase());
                if let (Some(key), Some(content)) = (key.as_deref(), v.attr("content")) {
                    if OG_AUDIO_KEYS.contains(&key) {
                        c.last_og[0] = c.add(content, None, Some(MediaKind::Audio), true);
                    } else if OG_VIDEO_KEYS.contains(&key) {
                        c.last_og[1] = c.add(content, None, Some(MediaKind::Video), true);
                    } else if key == "og:audio:type" || key == "og:video:type" {
                        c.og_type(key == "og:video:type", content);
                    }
                }
                return false;
            }
            "link" => {
                let alternate = v
                    .attr("rel")
                    .is_some_and(|r| r.split_whitespace().any(|t| t.eq_ignore_ascii_case("alternate")));
                if let (true, Some(href), Some(t)) = (alternate, v.attr("href"), v.attr("type")) {
                    if is_av_type(t) {
                        c.add(href, Some(t), None, true);
                    }
                }
                return false;
            }
            "a" => {
                if let Some(href) = v.attr("href") {
                    // Without a media `type` the extension alone must recognise the file.
                    let declared = v.attr("type").filter(|t| is_av_type(t));
                    c.add(href, declared, None, declared.is_some());
                }
            }
            "script" | "style" | "template" => return false,
            _ => {}
        }
        true
    });
    let Collector { out, dropped, .. } = c;
    out.into_iter()
        .enumerate()
        .filter(|(i, _)| !dropped.contains(i))
        .map(|(_, r)| r)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/shows/ep1").unwrap()
    }

    fn urls(refs: &[MediaRef], kind: MediaKind) -> Vec<&str> {
        refs.iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.url.as_str())
            .collect()
    }

    const PAGE: &str = r#"<!doctype html><html><head>
        <meta property="og:audio" content="/og/ep1.mp3">
        <meta property="og:audio:type" content="audio/mpeg">
        <meta property="og:video:url" content="https://www.youtube.example/embed/abc">
        <meta property="og:video:type" content="text/html">
        <meta property="og:video:secure_url" content="https://cdn.example.org/ep1.mp4">
        <link rel="alternate" type="audio/ogg" href="feed/ep1.ogg">
        <link rel="alternate" type="application/rss+xml" href="/feed.xml">
        <script>var s = '<audio src="/in-script.mp3">';</script>
      </head><body>
        <audio src="a/direct.m4a" controls></audio>
        <audio controls><source src="/a/ep1.opus" type="audio/ogg; codecs=opus"><source src="/a/ep1.mp3" type="audio/mpeg"></audio>
        <video src="/v/clip.webm" poster="/v/poster.jpg"></video>
        <video><source src="/v/ep1.mp4" type="video/mp4"><source src="/v/ep1.mp4#t=5" type="video/mp4"></video>
        <picture><source srcset="/img/a.webp" type="image/webp"><source src="/img/b.png" type="image/png"><img src="/img/c.jpg"></picture>
        <a href="/files/episode.FLAC">flac</a>
        <a href="/files/talk.mov">mov</a>
        <a href="/files/notes.pdf">notes</a>
        <a href="https://dl.example.net/get?id=3" type="audio/mpeg">typed</a>
        <a href="javascript:play()">x</a>
        <audio src="blob:https://example.com/9b1"></audio>
      </body></html>"#;

    #[test]
    fn collects_media_elements_meta_links_and_extension_anchors_in_document_order() {
        let refs = media_refs(PAGE, &base());
        assert_eq!(
            urls(&refs, MediaKind::Audio),
            [
                "https://example.com/og/ep1.mp3",
                "https://example.com/shows/feed/ep1.ogg",
                "https://example.com/shows/a/direct.m4a",
                "https://example.com/a/ep1.opus",
                "https://example.com/a/ep1.mp3",
                "https://example.com/files/episode.FLAC",
                "https://dl.example.net/get?id=3",
            ]
        );
        assert_eq!(
            urls(&refs, MediaKind::Video),
            [
                "https://cdn.example.org/ep1.mp4",
                "https://example.com/v/clip.webm",
                "https://example.com/v/ep1.mp4",
                "https://example.com/files/talk.mov",
            ],
            "the html og:video player page, posters, images, blob: and pdf links are not media"
        );
        let og = &refs[0];
        assert_eq!(
            og.declared_type.as_deref(),
            Some("audio/mpeg"),
            "og:audio:type types the og:audio"
        );
        assert!(og.explicit);
        let anchor = refs
            .iter()
            .find(|r| r.url.path().ends_with("episode.FLAC"))
            .unwrap();
        assert!(!anchor.explicit, "an extension-only anchor is not explicit");
        let typed = refs
            .iter()
            .find(|r| r.url.host_str() == Some("dl.example.net"))
            .unwrap();
        assert!(typed.explicit && typed.declared_type.as_deref() == Some("audio/mpeg"));
        let opus = refs.iter().find(|r| r.url.path().ends_with("ep1.opus")).unwrap();
        assert_eq!(
            opus.declared_type.as_deref(),
            Some("audio/ogg"),
            "parameters are dropped"
        );
    }

    #[test]
    fn base_href_refines_resolution_and_non_http_urls_are_dropped() {
        let html = r#"<head><base href="https://media.example.net/root/"></head>
            <audio src="a.mp3"></audio><audio src="data:audio/mpeg;base64,AAAA"></audio>"#;
        let refs = media_refs(html, &base());
        assert_eq!(
            urls(&refs, MediaKind::Audio),
            ["https://media.example.net/root/a.mp3"]
        );
    }

    #[test]
    fn classification_by_content_type_and_extension() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert_eq!(
            kind_from_content_type("audio/mpeg", &u("https://x/a")),
            Some(MediaKind::Audio)
        );
        assert_eq!(
            kind_from_content_type("Video/MP4; x=1", &u("https://x/a")),
            Some(MediaKind::Video)
        );
        assert_eq!(
            kind_from_content_type("application/ogg", &u("https://x/a.ogg")),
            Some(MediaKind::Audio)
        );
        assert_eq!(
            kind_from_content_type("application/ogg", &u("https://x/a.ogv")),
            Some(MediaKind::Video)
        );
        assert_eq!(
            kind_from_content_type("application/octet-stream", &u("https://x/a.mp3?token=1")),
            Some(MediaKind::Audio)
        );
        assert_eq!(
            kind_from_content_type("application/octet-stream", &u("https://x/a.zip")),
            None
        );
        assert_eq!(kind_from_content_type("text/html", &u("https://x/a.mp3")), None);
        assert_eq!(kind_from_content_type("", &u("https://x/a.mp3")), None);
        assert_eq!(kind_from_extension(&u("https://x/dir.mp4/file")), None);
        assert_eq!(media_type(" Audio/MPEG ; q=1 ").as_deref(), Some("audio/mpeg"));
    }

    #[test]
    fn oversize_input_and_reference_floods_are_bounded() {
        let many: String = (0..MAX_MEDIA_REFS + 50)
            .map(|i| format!("<audio src=\"/a/{i}.mp3\"></audio>"))
            .collect();
        assert_eq!(media_refs(&many, &base()).len(), MAX_MEDIA_REFS);
        assert!(media_refs("", &base()).is_empty());
    }
}
