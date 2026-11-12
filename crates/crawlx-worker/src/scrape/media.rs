//! The `audio` and `video` formats: the media a page is or references, stored as artifacts.
//!
//! A hosted engine of the compatibility API serves an MP3 and the best video of a supported video page.
//! crawlx has no transcoder, so it returns the media file the page offers, as it is:
//!
//! 1. A body that is itself media (`audio/*`, `video/*`, `application/ogg`, or an
//!    `application/octet-stream` whose URL has a media extension) is the file. Such a body is a
//!    valid page when `audio` or `video` is requested (empty markdown); without those formats it
//!    stays an `unsupported_content` failure.
//! 2. An HTML page is searched for media ([`crawlx_extract::media::media_refs`]: `<audio>`,
//!    `<video>`, their `<source>`s, `og:audio` / `og:video`, typed `<link rel=alternate>`, links to
//!    files with a media extension). Per requested format the first match is downloaded through
//!    the run's fetcher, so the egress policy, the request controls and the politeness rules
//!    apply. An MP3 wins over other audio; a reference the page names in markup wins over a bare
//!    link. At most [`MAX_ATTEMPTS`] candidates are tried per format.
//! 3. `audio` without any audio file falls back to the video file (its container carries the
//!    audio track) with an `audio_not_extracted:` warning; audio that is not MP3 is returned as is
//!    with an `audio_not_mp3:` warning naming the content type.
//! 4. Transcript: when the LLM endpoint transcribes ([`LlmExtractor::can_transcribe`]) the stored
//!    audio (else the video) is sent to it; the text is [`ScrapeDocument::transcript`] and its
//!    tokens add to `llmTokens`. Without such an endpoint the page gets a
//!    `transcription_unavailable:` warning, after a failed call `transcription_failed:`.
//!
//! Nothing here fails the page. A format without a usable file leaves its field empty and adds a
//! warning: `audio_not_found:` / `video_not_found:` (nothing on the page, not downloadable, not
//! media, egress refused, out of time) or `media_too_large:` (a file beyond
//! [`DEFAULT_MEDIA_MAX_BYTES`], or the worker's `media_max_bytes`).
//! The download and the transcription share the page's `timeout`, less a reserve that keeps room
//! to store the page.

use crate::error::WorkerError;
use crate::runtime::CpuPool;
use crate::scrape::compose::BodyKind;
use crate::scrape::{guard, llm, Acquired, FetchObserver, ScrapeEngine};
use bytes::Bytes;
use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
use crawlx_extract::media::{kind_from_content_type, media_refs, media_type, MediaKind, MediaRef};
use crawlx_fetch::FetchOptions;
use crawlx_model::llm::chat_completions::MAX_TRANSCRIBE_BYTES;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};
use url::Url;

/// Default largest media file downloaded for one format (256 MiB; `WorkerConfig::media_max_bytes`).
/// The file is held in memory while it is downloaded, transcribed and stored, so the limit bounds
/// the memory of a scrape; a larger file is not stored and the page gets a `media_too_large:`
/// warning.
pub const DEFAULT_MEDIA_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Candidates tried per format before giving up.
pub(crate) const MAX_ATTEMPTS: usize = 3;

/// Smallest part of the page `timeout` kept back for storing the page.
const MIN_RESERVE: Duration = Duration::from_millis(250);
/// Largest part of the page `timeout` kept back for storing the page.
const MAX_RESERVE: Duration = Duration::from_secs(5);

/// One media file of a page.
#[derive(Clone)]
pub(crate) struct MediaFile {
    /// Where the file came from (after redirects).
    pub url: Url,
    /// Media type of the response, without parameters.
    pub content_type: String,
    /// The file.
    pub bytes: Bytes,
}

/// The files [`ScrapeEngine::media`] found; the page row stores them.
#[derive(Default)]
pub(crate) struct Media {
    /// File for the `audio` format.
    pub audio: Option<MediaFile>,
    /// File for the `video` format.
    pub video: Option<MediaFile>,
}

/// Why a candidate yielded no file.
enum Refusal {
    /// The file is larger than the worker's media limit.
    TooLarge,
    /// Anything else, as a short reason.
    Other(String),
}

/// What the body of `acq` is when it is a media file the run asked for.
fn own_kind(opts: &ScrapeOptions, acq: &Acquired, kind: BodyKind) -> Option<MediaKind> {
    if kind != BodyKind::Binary || acq.render.is_some() || !(200..300).contains(&acq.status) {
        return None;
    }
    if !(opts.wants("audio") || opts.wants("video")) {
        return None;
    }
    acq.content_type
        .as_deref()
        .and_then(|ct| kind_from_content_type(ct, &acq.final_url))
}

/// Is the body of `acq` a media file the `audio` / `video` formats serve (and so a valid page)?
pub(crate) fn is_media_body(opts: &ScrapeOptions, acq: &Acquired, kind: BodyKind) -> bool {
    own_kind(opts, acq, kind).is_some()
}

/// `url` without query and fragment, for messages.
fn short(url: &Url) -> String {
    let mut u = url.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

/// Candidates of `kind` in the order they are tried: an MP3 first (for audio), then references
/// the markup names, then bare links; at most [`MAX_ATTEMPTS`].
fn ranked(refs: &[MediaRef], kind: MediaKind) -> Vec<&MediaRef> {
    let is_mp3 = |r: &MediaRef| {
        kind == MediaKind::Audio
            && (matches!(r.declared_type.as_deref(), Some("audio/mpeg" | "audio/mp3"))
                || r.url.path().to_ascii_lowercase().ends_with(".mp3"))
    };
    let mut found: Vec<&MediaRef> = refs.iter().filter(|r| r.kind == kind).collect();
    found.sort_by_key(|r| {
        if is_mp3(r) {
            0u8
        } else if r.explicit {
            1
        } else {
            2
        }
    });
    found.truncate(MAX_ATTEMPTS);
    found
}

/// File extension for a media type (what a speech endpoint sniffs the format from).
fn extension(media: &str) -> &'static str {
    match media {
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/mp4" | "audio/x-m4a" | "audio/m4a" | "audio/aac" => "m4a",
        "audio/ogg" | "application/ogg" => "ogg",
        "audio/opus" => "opus",
        "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => "wav",
        "audio/flac" | "audio/x-flac" => "flac",
        "audio/webm" | "video/webm" => "webm",
        "video/mp4" => "mp4",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "video/ogg" => "ogv",
        _ => "bin",
    }
}

/// A file name for `file`: the last URL path segment when it has an extension, else `media.<ext>`.
fn file_name(file: &MediaFile) -> String {
    let segment = file
        .url
        .path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| s.contains('.'))
        .map(|s| {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                        c
                    } else {
                        '_'
                    }
                })
                .take(100)
                .collect::<String>()
        });
    segment.unwrap_or_else(|| format!("media.{}", extension(&file.content_type)))
}

/// End of the media phase: the page deadline less a reserve for storing the page.
fn phase_deadline(deadline: Instant, timeout_ms: u32) -> Instant {
    let reserve = Duration::from_millis(u64::from(timeout_ms) / 10).clamp(MIN_RESERVE, MAX_RESERVE);
    deadline.checked_sub(reserve).unwrap_or(deadline)
}

impl ScrapeEngine {
    /// Find, download and transcribe the media of `acq` for the `audio` / `video` formats and
    /// record the outcome in `doc` (`transcript`, `llmTokens`, `warning`). The returned files are
    /// stored with the page row.
    ///
    /// # Errors
    /// [`WorkerError`] when the CPU pool fails; every media problem is a warning.
    pub(super) async fn media(
        &self,
        acq: &mut Acquired,
        kind: BodyKind,
        cpu: &CpuPool,
        deadline: Instant,
        observe: &FetchObserver<'_>,
        doc: &mut ScrapeDocument,
    ) -> Result<Media, WorkerError> {
        let opts = &*self.options;
        let (want_audio, want_video) = (opts.wants("audio"), opts.wants("video"));
        let mut media = Media::default();
        if !(want_audio || want_video) {
            return Ok(media);
        }
        let deadline = phase_deadline(deadline, opts.timeout_ms);
        let own = own_kind(opts, acq, kind);
        let refs = if kind == BodyKind::Html && own.is_none() {
            let html = String::from_utf8_lossy(&acq.body).into_owned();
            let base = acq.final_url.clone();
            cpu.run(move || {
                // the charge is held until the parsed DOM inside `media_refs` is dropped
                let mut charge = crawlx_extract::parse_budget::charge(html.len())
                    .map_err(|e| WorkerError::Extraction(e.into()))?;
                media_refs(&mut charge, &html, &base).map_err(|e| WorkerError::Extraction(e.into()))
            })
            .await
            .map_err(|e| WorkerError::Other(format!("media discovery task failed: {e}")))??
        } else {
            Vec::new()
        };

        let mut warnings: Vec<String> = Vec::new();
        for (wanted, target) in [(want_audio, MediaKind::Audio), (want_video, MediaKind::Video)] {
            if !wanted {
                continue;
            }
            // `audio` already took the video file as its container: `video` is that file
            let container = media
                .audio
                .as_ref()
                .filter(|_| target == MediaKind::Video)
                .filter(|a| kind_from_content_type(&a.content_type, &a.url) == Some(MediaKind::Video));
            if let Some(file) = container {
                media.video = Some(file.clone());
                continue;
            }
            match self.obtain(target, own, acq, &refs, deadline, observe).await {
                Ok((file, note)) => {
                    warnings.extend(note);
                    if target == MediaKind::Audio {
                        media.audio = Some(file);
                    } else {
                        media.video = Some(file);
                    }
                }
                Err(w) => warnings.push(w),
            }
        }

        if let Some(file) = media.audio.as_ref().or(media.video.as_ref()) {
            warnings.extend(self.transcribe(file, deadline, doc).await);
        }
        for w in warnings {
            guard::push_warning(&mut doc.warning, self.redact(&w));
        }
        Ok(media)
    }

    /// The file for `target`, with an optional note for the page warning, or the warning that
    /// says why there is none.
    async fn obtain(
        &self,
        target: MediaKind,
        own: Option<MediaKind>,
        acq: &mut Acquired,
        refs: &[MediaRef],
        deadline: Instant,
        observe: &FetchObserver<'_>,
    ) -> Result<(MediaFile, Option<String>), String> {
        let label = if target == MediaKind::Audio {
            "audio"
        } else {
            "video"
        };
        let mut last: Option<Refusal> = None;
        let mut last_url: Option<Url> = None;

        // the page itself is the file
        if let Some(k) = own {
            if k == target || (target == MediaKind::Audio && k == MediaKind::Video) {
                match self.own_file(acq, deadline, observe).await {
                    Ok(file) => return Ok(finish(target, k, file)),
                    Err(r) => {
                        last = Some(r);
                        last_url = Some(acq.final_url.clone());
                    }
                }
            }
        }
        // audio: audio references first; a page without any audio file offers its video file as
        // the container of the audio track
        let mut kinds = vec![target];
        if target == MediaKind::Audio && ranked(refs, MediaKind::Audio).is_empty() {
            kinds.push(MediaKind::Video);
        }
        if own.is_none() {
            for k in kinds {
                for candidate in ranked(refs, k) {
                    match self.download(&candidate.url, deadline, observe, acq).await {
                        Ok((got, file)) if got == k => return Ok(finish(target, got, file)),
                        Ok((got, _)) => {
                            last = Some(Refusal::Other(format!(
                                "it is {} media, not {}",
                                name(got),
                                name(k)
                            )));
                            last_url = Some(candidate.url.clone());
                        }
                        Err(r) => {
                            last = Some(r);
                            last_url = Some(candidate.url.clone());
                        }
                    }
                }
            }
        }
        Err(match (last, last_url) {
            (Some(Refusal::TooLarge), Some(u)) => format!(
                "media_too_large: the {label} file {} is larger than the {} byte limit",
                short(&u),
                self.media_max_bytes
            ),
            (Some(Refusal::Other(why)), Some(u)) => {
                format!("{label}_not_found: {} cannot be used ({why})", short(&u))
            }
            _ => match own {
                Some(k) => format!("{label}_not_found: the URL is {} media, not {label}", name(k)),
                None => format!("{label}_not_found: the page references no {label} file"),
            },
        })
    }

    /// The body of the page as a media file. A body cut at the fetcher's response cap is fetched
    /// again under the media limit.
    async fn own_file(
        &self,
        acq: &mut Acquired,
        deadline: Instant,
        observe: &FetchObserver<'_>,
    ) -> Result<MediaFile, Refusal> {
        if acq.body.len() > self.media_max_bytes {
            return Err(Refusal::TooLarge);
        }
        if acq.body.len() >= self.fetcher.config().max_body_bytes {
            let url = acq.final_url.clone();
            return self.download(&url, deadline, observe, acq).await.map(|(_, f)| f);
        }
        let content_type = acq
            .content_type
            .as_deref()
            .and_then(media_type)
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        Ok(MediaFile {
            url: acq.final_url.clone(),
            content_type,
            bytes: acq.body.clone(),
        })
    }

    /// Download `url` through the run's fetcher and check it is a media file within the cap.
    async fn download(
        &self,
        url: &Url,
        deadline: Instant,
        observe: &FetchObserver<'_>,
        acq: &mut Acquired,
    ) -> Result<(MediaKind, MediaFile), Refusal> {
        let options = FetchOptions {
            max_body_bytes: Some(self.media_max_bytes),
            ..self.http_options()
        };
        let fetched = timeout_at(
            deadline,
            self.fetch_auxiliary_checked(
                url,
                &options,
                acq,
                observe,
                crawlx_policy::robots::HopKind::Media,
                false,
            ),
        )
        .await
        .map_err(|_| Refusal::Other("not downloaded within the page timeout".to_owned()))?;
        let resp = fetched.map_err(|e| Refusal::Other(format!("download failed: {e}")))?;
        if !resp.status.is_success() {
            return Err(Refusal::Other(format!("HTTP {}", resp.status.as_u16())));
        }
        if resp.truncated {
            return Err(Refusal::TooLarge);
        }
        let content_type = resp.content_type.as_deref().unwrap_or_default();
        let Some(kind) = kind_from_content_type(content_type, &resp.final_url) else {
            return Err(Refusal::Other(format!(
                "not a media file, content type {}",
                media_type(content_type).as_deref().unwrap_or("missing")
            )));
        };
        let content_type = media_type(content_type).unwrap_or_else(|| "application/octet-stream".to_owned());
        Ok((
            kind,
            MediaFile {
                url: resp.final_url,
                content_type,
                bytes: resp.body,
            },
        ))
    }

    /// Transcribe `file` when the LLM endpoint can, setting `doc.transcript` and charging the
    /// tokens. Returns the warnings of what did not work.
    async fn transcribe(&self, file: &MediaFile, deadline: Instant, doc: &mut ScrapeDocument) -> Vec<String> {
        let Some(llm) = self.llm.as_deref().filter(|l| l.can_transcribe()) else {
            return vec![
                "transcription_unavailable: the LLM endpoint does not transcribe audio; configure \
                 llm.transcribeEndpoint"
                    .to_owned(),
            ];
        };
        if file.bytes.len() > MAX_TRANSCRIBE_BYTES {
            return vec![format!(
                "transcription_failed: the file is larger than the {MAX_TRANSCRIBE_BYTES} byte transcription limit"
            )];
        }
        let name = self.redact(&file_name(file));
        let bytes = self.redact_bytes(&file.bytes);
        let call = llm.transcribe(&bytes, &name, &file.content_type);
        let done = match timeout_at(deadline, call).await {
            Ok(Ok(done)) => done,
            Ok(Err(e)) => return vec![format!("transcription_failed: {e}")],
            Err(_) => return vec!["transcription_failed: not finished within the page timeout".to_owned()],
        };
        llm::charge(doc, done.usage);
        let mut text = done.value;
        if let Some(spec) = &self.options.redact_pii {
            text = crawlx_extract::parse::redact::redact(&text, &guard::redact_options(spec)).text;
        }
        if text.trim().is_empty() {
            return vec!["transcription_failed: the speech endpoint returned no text".to_owned()];
        }
        doc.transcript = Some(text);
        Vec::new()
    }
}

/// Human name of a kind.
const fn name(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => "audio",
        MediaKind::Video => "video",
    }
}

/// `file` as the answer for `target`, with the warning its format earns: audio that is not an MP3
/// is returned as is, and a video file answering `audio` is the container of the audio track.
fn finish(target: MediaKind, found: MediaKind, file: MediaFile) -> (MediaFile, Option<String>) {
    let note = match (target, found) {
        (MediaKind::Audio, MediaKind::Video) => Some(format!(
            "audio_not_extracted: no audio file found; the video file ({}) is returned as the audio, \
             crawlx does not transcode",
            file.content_type
        )),
        (MediaKind::Audio, MediaKind::Audio)
            if !matches!(file.content_type.as_str(), "audio/mpeg" | "audio/mp3") =>
        {
            Some(format!(
                "audio_not_mp3: the audio is {} as the page offers it, crawlx does not transcode",
                file.content_type
            ))
        }
        _ => None,
    };
    (file, note)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn ranking_prefers_mp3_then_markup_and_caps_attempts() {
        let page = r#"<a href="/a.ogg">a</a><audio src="/b.opus"></audio><a href="/c.mp3">c</a>
               <audio src="/d.m4a"></audio><audio src="/e.wav"></audio><a href="/f.mp4">f</a>"#;
        let mut charge = crawlx_extract::parse_budget::charge(page.len()).unwrap();
        let refs = media_refs(&mut charge, page, &Url::parse("https://x.test/").unwrap()).unwrap();
        let got: Vec<&str> = ranked(&refs, MediaKind::Audio)
            .iter()
            .map(|r| r.url.path())
            .collect();
        assert_eq!(
            got,
            ["/c.mp3", "/b.opus", "/d.m4a"],
            "mp3, then markup, capped at {MAX_ATTEMPTS}"
        );
        let video: Vec<&str> = ranked(&refs, MediaKind::Video)
            .iter()
            .map(|r| r.url.path())
            .collect();
        assert_eq!(video, ["/f.mp4"]);
    }

    #[test]
    fn file_names_keep_safe_extensions_and_default_by_content_type() {
        let file = |u: &str, ct: &str| MediaFile {
            url: Url::parse(u).unwrap(),
            content_type: ct.to_owned(),
            bytes: Bytes::new(),
        };
        assert_eq!(
            file_name(&file("https://x.test/a/talk%20one.mp3?x=1", "audio/mpeg")),
            "talk_20one.mp3"
        );
        assert_eq!(
            file_name(&file("https://x.test/stream/7", "audio/ogg")),
            "media.ogg"
        );
        assert_eq!(file_name(&file("https://x.test/", "video/mp4")), "media.mp4");
    }

    #[test]
    fn the_media_phase_ends_before_the_page_deadline() {
        let now = Instant::now();
        let end = now + Duration::from_secs(30);
        assert_eq!(end - phase_deadline(end, 30_000), Duration::from_secs(3));
        assert_eq!(end - phase_deadline(end, 600_000), MAX_RESERVE);
        assert_eq!(end - phase_deadline(end, 100), MIN_RESERVE);
    }

    #[test]
    fn mismatched_format_notes() {
        let file = MediaFile {
            url: Url::parse("https://x.test/a.m4a").unwrap(),
            content_type: "audio/mp4".to_owned(),
            bytes: Bytes::new(),
        };
        let (_, note) = finish(MediaKind::Audio, MediaKind::Audio, file.clone());
        assert!(note.unwrap().starts_with("audio_not_mp3: "));
        let (_, note) = finish(MediaKind::Audio, MediaKind::Video, file.clone());
        assert!(note.unwrap().starts_with("audio_not_extracted: "));
        let mp3 = MediaFile {
            content_type: "audio/mpeg".to_owned(),
            ..file
        };
        assert!(finish(MediaKind::Audio, MediaKind::Audio, mp3).1.is_none());
    }
}
