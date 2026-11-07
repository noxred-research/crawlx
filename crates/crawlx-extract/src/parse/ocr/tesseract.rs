//! The `tesseract` backend: the Tesseract command line, fed a PNG on standard input, answering
//! TSV (word boxes and confidences) on standard output.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use super::{process, OcrConfig, OcrError, OcrPage, OcrParagraph};

/// A checked Tesseract installation.
#[derive(Debug, Clone)]
pub(super) struct Tesseract {
    program: PathBuf,
    languages: String,
    tessdata: Option<PathBuf>,
    timeout: Duration,
    min_confidence: u8,
}

impl Tesseract {
    /// Find the binary, run `--version` and check that every language of the config has data.
    pub(super) fn probe(config: &OcrConfig) -> Result<Self, OcrError> {
        let wanted = config
            .tesseract_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("tesseract"));
        let program = process::resolve(&wanted).ok_or_else(|| OcrError::Unavailable {
            backend: "tesseract",
            reason: format!(
                "the `{}` binary was not found; install Tesseract or set CRAWLX_OCR_TESSERACT",
                process::program_name(&wanted)
            ),
        })?;
        let this = Self {
            program,
            languages: config.languages.clone(),
            tessdata: config.tessdata_dir.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            min_confidence: config.min_confidence,
        };
        let version = this.run(&["--version"], &[])?;
        if !version.status.success() {
            return Err(OcrError::Unavailable {
                backend: "tesseract",
                reason: format!("`--version` failed: {}", version.stderr),
            });
        }
        let langs = this.run(&["--list-langs"], &[])?;
        // older releases print the list on stderr
        let listed = String::from_utf8_lossy(&langs.stdout).into_owned() + "\n" + &langs.stderr;
        for lang in this.languages.split('+') {
            if !listed.lines().any(|l| l.trim() == lang) {
                return Err(OcrError::Unavailable {
                    backend: "tesseract",
                    reason: format!(
                        "no trained data for language `{lang}`; install it or point CRAWLX_OCR_TESSDATA/TESSDATA_PREFIX at a directory that has `{lang}.traineddata`"
                    ),
                });
            }
        }
        Ok(this)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(args);
        if let Some(dir) = &self.tessdata {
            cmd.env("TESSDATA_PREFIX", dir);
        }
        // one thread per process: the worker's CPU pool is the unit of parallelism
        cmd.env("OMP_THREAD_LIMIT", "1");
        cmd
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Result<process::Output, OcrError> {
        process::run(self.command(args), &self.program, stdin, self.timeout)
    }

    /// Recognise one PNG. `dpi` is the scan resolution when the caller knows it.
    pub(super) fn recognize(&self, png: &[u8], dpi: Option<u32>) -> Result<OcrPage, OcrError> {
        let dpi_arg = dpi.map(|d| d.to_string());
        let mut args = vec!["stdin", "stdout", "-l", self.languages.as_str()];
        if let Some(d) = &dpi_arg {
            args.extend(["--dpi", d.as_str()]);
        }
        args.push("tsv");
        let out = self.run(&args, png)?;
        if !out.status.success() {
            return Err(OcrError::Failed {
                program: process::program_name(&self.program),
                status: out.status.to_string(),
                stderr: out.stderr,
            });
        }
        let tsv = String::from_utf8_lossy(&out.stdout);
        Ok(parse_tsv(&tsv, f64::from(self.min_confidence)))
    }
}

/// One recognised word.
struct Word {
    block: u32,
    par: u32,
    line: u32,
    left: u32,
    top: u32,
    right: u32,
    bottom: u32,
    conf: f64,
    text: String,
}

fn parse_word(line: &str) -> Option<Word> {
    let mut f = line.split('\t');
    let level: u32 = f.next()?.parse().ok()?;
    if level != 5 {
        return None;
    }
    let _page = f.next()?;
    let block = f.next()?.parse().ok()?;
    let par = f.next()?.parse().ok()?;
    let line_no = f.next()?.parse().ok()?;
    let _word = f.next()?;
    let left: u32 = f.next()?.parse().ok()?;
    let top: u32 = f.next()?.parse().ok()?;
    let width: u32 = f.next()?.parse().ok()?;
    let height: u32 = f.next()?.parse().ok()?;
    let conf: f64 = f.next()?.parse().ok()?;
    let text = f.next()?.trim().to_owned();
    if text.is_empty() || conf < 0.0 {
        return None;
    }
    Some(Word {
        block,
        par,
        line: line_no,
        left,
        top,
        right: left.saturating_add(width),
        bottom: top.saturating_add(height),
        conf,
        text,
    })
}

/// Paragraphs of Tesseract TSV output: words are grouped by `(block, paragraph)`, lines by
/// `line`; words under `min_confidence` (0-100) are dropped.
pub(super) fn parse_tsv(tsv: &str, min_confidence: f64) -> OcrPage {
    let (mut width, mut height) = (0u32, 0u32);
    let mut words: Vec<Word> = Vec::new();
    for row in tsv.lines().skip(1) {
        let mut f = row.split('\t');
        if f.next() == Some("1") {
            // level 1 is the page: its box is the image
            let cols: Vec<&str> = row.split('\t').collect();
            width = cols.get(8).and_then(|v| v.parse().ok()).unwrap_or(width);
            height = cols.get(9).and_then(|v| v.parse().ok()).unwrap_or(height);
            continue;
        }
        if let Some(w) = parse_word(row) {
            if w.conf >= min_confidence {
                words.push(w);
            }
        }
    }
    let mut paragraphs: Vec<OcrParagraph> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let (block, par) = (words[i].block, words[i].par);
        let mut j = i;
        while j < words.len() && words[j].block == block && words[j].par == par {
            j += 1;
        }
        let group = &words[i..j];
        let mut text = String::new();
        let mut last_line = None;
        for w in group {
            match last_line {
                None => {}
                Some(l) if l == w.line => text.push(' '),
                Some(_) => join_line(&mut text),
            }
            text.push_str(&w.text);
            last_line = Some(w.line);
        }
        let bbox = group.iter().fold([u32::MAX, u32::MAX, 0, 0], |b, w| {
            [
                b[0].min(w.left),
                b[1].min(w.top),
                b[2].max(w.right),
                b[3].max(w.bottom),
            ]
        });
        // word counts are far below 2^52, so the sum and the count are exact in f64
        let confidence = group.iter().map(|w| w.conf).sum::<f64>()
            / f64::from(u32::try_from(group.len()).unwrap_or(u32::MAX));
        paragraphs.push(OcrParagraph {
            text,
            bbox,
            confidence: Some((confidence / 100.0).clamp(0.0, 1.0)),
        });
        i = j;
    }
    OcrPage {
        width,
        height,
        paragraphs,
    }
}

/// Join the next line of a paragraph: a hyphen at the end of the line is removed.
fn join_line(text: &mut String) {
    if text.ends_with('-') && text.chars().rev().nth(1).is_some_and(char::is_alphabetic) {
        text.pop();
    } else {
        text.push(' ');
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const TSV: &str =
        "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n\
1\t1\t0\t0\t0\t0\t0\t0\t800\t600\t-1\t\n\
2\t1\t1\t0\t0\t0\t10\t10\t300\t40\t-1\t\n\
3\t1\t1\t1\t0\t0\t10\t10\t300\t40\t-1\t\n\
4\t1\t1\t1\t1\t0\t10\t10\t300\t20\t-1\t\n\
5\t1\t1\t1\t1\t1\t10\t10\t100\t20\t96.5\tHello\n\
5\t1\t1\t1\t1\t2\t120\t10\t90\t20\t90.5\tworld\n\
5\t1\t1\t1\t2\t1\t10\t30\t120\t20\t80\tcom-\n\
5\t1\t1\t1\t3\t1\t10\t50\t120\t20\t80\tputer\n\
5\t1\t2\t1\t1\t1\t10\t200\t50\t20\t5\tnoise\n\
5\t1\t2\t1\t1\t2\t70\t200\t50\t20\t-1\t \n";

    #[test]
    fn words_group_into_paragraphs_with_boxes_and_confidence() {
        let page = parse_tsv(TSV, 0.0);
        assert_eq!((page.width, page.height), (800, 600));
        assert_eq!(page.paragraphs.len(), 2);
        let first = &page.paragraphs[0];
        assert_eq!(first.text, "Hello world computer");
        assert_eq!(first.bbox, [10, 10, 210, 70]);
        let c = first.confidence.unwrap();
        assert!((c - (96.5 + 90.5 + 80.0 + 80.0) / 400.0).abs() < 1e-9, "{c}");
        assert_eq!(page.paragraphs[1].text, "noise");
    }

    #[test]
    fn the_confidence_floor_drops_noise() {
        let page = parse_tsv(TSV, 50.0);
        assert_eq!(page.paragraphs.len(), 1);
        assert_eq!(page.text(), "Hello world computer");
    }

    #[test]
    fn empty_output_is_an_empty_page() {
        assert!(parse_tsv("", 0.0).paragraphs.is_empty());
        assert!(parse_tsv("level\tpage_num\n", 0.0).paragraphs.is_empty());
    }
}
