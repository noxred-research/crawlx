#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! OCR: the Tesseract and `ocrs` backends on generated scans (`support/scan.rs`), image uploads,
//! scanned PDF pages (embedded scans, rotated scans, JPEG scans, rendered pages), configuration
//! and failure paths. Tests that need a binary or models skip (and say so) without them.

#[path = "support/scan.rs"]
mod scan;

use crawlx_extract::parse::ocr::{Ocr, OcrBackend, OcrConfig, OcrError, PdfOcr, Rasterizer};
use crawlx_extract::parse::pdf::{extract_pdf, PdfOptions, PdfText};
use crawlx_extract::parse::{parse_document_with, ParseError, ParseFormat, ParseOptions};
use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageEncoder};
use scan::{Gray, PageKind};
use std::sync::Arc;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn config(rasterizer: Rasterizer) -> OcrConfig {
    OcrConfig {
        backend: OcrBackend::Tesseract,
        rasterizer,
        ..OcrConfig::default()
            .apply_env(&|k| (k == "TESSDATA_PREFIX").then(|| env(k)).flatten())
            .unwrap()
    }
}

/// A Tesseract engine, or `None` (with a printed reason) when the host lacks it.
fn engine(config: &OcrConfig) -> Option<Arc<Ocr>> {
    match Ocr::shared(config) {
        Ok(engine) => engine,
        Err(e @ OcrError::Unavailable { .. }) => {
            eprintln!("skipping: {e}");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

fn tesseract(rasterizer: Rasterizer) -> Option<Arc<Ocr>> {
    engine(&config(rasterizer))
}

fn pdf_options(ocr: &Arc<Ocr>, mode: PdfOcr) -> PdfOptions {
    PdfOptions {
        ocr: Some(Arc::clone(ocr)),
        ocr_mode: mode,
        layout: true,
        ..PdfOptions::default()
    }
}

fn parse_options(ocr: Option<&Arc<Ocr>>) -> ParseOptions {
    ParseOptions {
        ocr: ocr.cloned(),
        ..ParseOptions::default()
    }
}

const SCALE: usize = 8;

/// A page image (2x the PDF page: 1224x1584 pixels) with two lines in the upper left.
fn page_scan() -> Gray {
    let (text, _) = scan::render_lines(&["HELLO WORLD", "SCANNED INVOICE"], SCALE);
    scan::on_page(&text, 1224, 1584, 100, 150)
}

fn jpeg(img: &Gray) -> Vec<u8> {
    let mut out = Vec::new();
    JpegEncoder::new_with_quality(&mut out, 92)
        .write_image(
            &img.pixels,
            u32::try_from(img.width).unwrap(),
            u32::try_from(img.height).unwrap(),
            ExtendedColorType::L8,
        )
        .unwrap();
    out
}

fn pdf_words(t: &PdfText) -> String {
    scan::words(&t.text)
}

// ---------------------------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------------------------

#[test]
fn tesseract_reads_a_generated_png() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let (img, boxes) = scan::render_lines(&["HELLO WORLD", "SCANNED INVOICE"], SCALE);
    let page = ocr.recognize_bytes(&scan::png(&img)).unwrap();
    assert_eq!(
        scan::words(&page.text()),
        "HELLO WORLD SCANNED INVOICE",
        "{page:?}"
    );
    assert_eq!(
        (page.width, page.height),
        (
            u32::try_from(img.width).unwrap(),
            u32::try_from(img.height).unwrap()
        )
    );
    // the paragraph boxes are in pixels of the image and cover the drawn lines
    let first = &page.paragraphs[0];
    let line = boxes[0];
    assert!(
        usize::try_from(first.bbox[0]).unwrap() <= line[0] + SCALE
            && usize::try_from(first.bbox[1]).unwrap() <= line[1] + SCALE
            && usize::try_from(first.bbox[2]).unwrap() + SCALE >= line[2],
        "{:?} vs {line:?}",
        first.bbox
    );
    let c = first.confidence.unwrap();
    assert!((0.5..=1.0).contains(&c), "{c}");
}

#[test]
fn image_uploads_need_an_engine_and_parse_to_markdown_with_one() {
    let png = scan::png(&scan::render_lines(&["HELLO WORLD"], SCALE).0);
    // no engine: refused, as before OCR existed
    let err = parse_document_with(&png, Some("scan.png"), None, &parse_options(None)).unwrap_err();
    assert!(matches!(err, ParseError::UnsupportedFormat { .. }), "{err}");
    assert!(err.to_string().contains("OCR"), "{err}");
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let doc = parse_document_with(&png, Some("scan.png"), None, &parse_options(Some(&ocr))).unwrap();
    assert_eq!(doc.format, ParseFormat::Png);
    assert_eq!(doc.content_type, "image/png");
    assert_eq!(scan::words(&doc.markdown), "HELLO WORLD");
    assert_eq!(scan::words(&doc.text), "HELLO WORLD");
    assert_eq!(doc.metadata["ocrBackend"], "tesseract");
    assert!(doc.metadata["ocrConfidence"].as_f64().unwrap() > 0.5);
    assert!(doc.metadata["width"].as_u64().unwrap() > 100);
    assert!(doc.warnings.is_empty(), "{:?}", doc.warnings);
}

#[test]
fn a_jpeg_upload_is_sniffed_from_its_bytes_and_read() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let bytes = jpeg(&scan::render_lines(&["HELLO WORLD"], SCALE).0);
    // the file name lies; the bytes win
    let doc = parse_document_with(
        &bytes,
        Some("scan.txt"),
        Some("text/plain"),
        &parse_options(Some(&ocr)),
    )
    .unwrap();
    assert_eq!(doc.format, ParseFormat::Jpeg);
    assert_eq!(scan::words(&doc.markdown), "HELLO WORLD");
}

#[test]
fn a_blank_image_parses_to_no_text_with_a_warning() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let blank = Gray {
        width: 300,
        height: 200,
        pixels: vec![255; 300 * 200],
    };
    let doc = parse_document_with(&scan::png(&blank), None, None, &parse_options(Some(&ocr))).unwrap();
    assert!(doc.markdown.trim().is_empty());
    assert!(
        doc.warnings.iter().any(|w| w.contains("no text")),
        "{:?}",
        doc.warnings
    );
}

#[test]
fn hostile_images_are_errors_never_panics() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let png = scan::png(&scan::render_lines(&["HELLO WORLD"], SCALE).0);
    // a truncated PNG is a corrupt image, not an OCR failure
    let err = parse_document_with(
        &png[..png.len() / 2],
        Some("a.png"),
        None,
        &parse_options(Some(&ocr)),
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Corrupt { .. }), "{err:?}");
    // a PNG header claiming a huge picture is refused from the header, before any allocation
    let mut huge = png[..33].to_vec();
    huge[16..20].copy_from_slice(&60_000u32.to_be_bytes());
    huge[20..24].copy_from_slice(&60_000u32.to_be_bytes());
    let err = ocr.recognize_bytes(&huge).unwrap_err();
    assert!(matches!(err, OcrError::Image(_)), "{err:?}");
    for junk in [
        &b""[..],
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff\xe0 not a jpeg",
        b"GIF89a",
    ] {
        assert!(ocr.recognize_bytes(junk).is_err());
    }
}

#[test]
fn the_pixel_limit_refuses_large_images() {
    let cfg = OcrConfig {
        max_image_pixels: 10_000,
        ..config(Rasterizer::Embedded)
    };
    let Some(ocr) = engine(&cfg) else {
        return;
    };
    let err = ocr
        .recognize_bytes(&scan::png(&scan::render_lines(&["HELLO WORLD"], SCALE).0))
        .unwrap_err();
    assert!(err.to_string().contains("limit is 10000"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------------------------

#[test]
fn scanned_pdf_pages_are_read_when_ocr_is_on_and_reported_when_it_is_not() {
    let scan = page_scan();
    let pdf = scan::pdf(&[PageKind::Scan {
        img: &scan,
        rotate: 0,
    }]);
    // no engine: the text layer is empty and the document says why
    let plain = extract_pdf(&pdf, &PdfOptions::default()).unwrap();
    assert!(plain.text.trim().is_empty());
    assert!(
        plain.warnings.iter().any(|w| w.contains("not OCR'd")),
        "{:?}",
        plain.warnings
    );
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    // mode off (parsers[].mode: fast) never runs the engine
    let off = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Off)).unwrap();
    assert!(off.text.trim().is_empty(), "{:?}", off.text);
    // auto: the page has no text layer, so it is read
    let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
    assert_eq!(pdf_words(&t), "HELLO WORLD SCANNED INVOICE", "{t:?}");
    assert!(t.markdown.contains("HELLO"), "{}", t.markdown);
    assert!(
        !t.warnings.iter().any(|w| w.contains("no extractable text")),
        "{:?}",
        t.warnings
    );
    // layout blocks say where the text is and that OCR read it
    let page = &t.layout[0];
    assert_eq!(page.status, "ok");
    let block = &page.items[0];
    assert_eq!(block.source, "ocr");
    assert!(block.confidence.ocr.unwrap() > 0.5);
    let [x0, y0, x1, y1] = block.bbox.unwrap();
    // drawn at 100..~600 px of 1224 across and 150..~370 px of 1584 down
    assert!((0.05..0.15).contains(&x0), "{x0}");
    assert!((0.08..0.14).contains(&y0), "{y0}");
    assert!(
        (0.6..0.8).contains(&x1) && (0.18..0.28).contains(&y1),
        "{:?}",
        block.bbox
    );
    assert_eq!(page.items.len(), t.pages[0].markdown.split("\n\n").count());
}

#[test]
fn require_text_fails_in_fast_mode_even_with_an_engine() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let scan = page_scan();
    let pdf = scan::pdf(&[PageKind::Scan {
        img: &scan,
        rotate: 0,
    }]);
    let fast = PdfOptions {
        require_text: true,
        ..pdf_options(&ocr, PdfOcr::Off)
    };
    assert!(matches!(extract_pdf(&pdf, &fast), Err(ParseError::NoText { .. })));
    // in auto mode the text the engine found satisfies the requirement
    let auto = PdfOptions {
        require_text: true,
        ..pdf_options(&ocr, PdfOcr::Auto)
    };
    assert!(extract_pdf(&pdf, &auto).is_ok());
}

#[test]
fn a_sideways_scan_with_a_page_rotation_is_read_upright() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    // the upright page is landscape; the scanner stored it turned, /Rotate turns it back
    let (text, _) = scan::render_lines(&["HELLO WORLD", "SCANNED INVOICE"], SCALE);
    let upright = scan::on_page(&text, 1584, 1224, 100, 150);
    for (stored, rotate) in [
        (scan::rotate_ccw(&upright), 90),
        (scan::rotate_cw(&upright), 270),
        (scan::rotate_cw(&scan::rotate_cw(&upright)), 180),
    ] {
        let pdf = scan::pdf(&[PageKind::Scan { img: &stored, rotate }]);
        let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
        assert_eq!(
            pdf_words(&t),
            "HELLO WORLD SCANNED INVOICE",
            "rotate {rotate}: {t:?}"
        );
        for b in &t.layout[0].items {
            let bb = b.bbox.unwrap();
            assert!(bb.iter().all(|v| (0.0..=1.0).contains(v)), "{bb:?}");
        }
    }
}

#[test]
fn a_jpeg_scan_inside_a_pdf_is_decoded() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let scan = page_scan();
    let bytes = jpeg(&scan);
    let pdf = scan::pdf(&[PageKind::Dct {
        jpeg: &bytes,
        width: scan.width,
        height: scan.height,
    }]);
    let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
    assert_eq!(pdf_words(&t), "HELLO WORLD SCANNED INVOICE", "{t:?}");
}

#[test]
fn pages_with_a_text_layer_are_not_touched_in_auto_mode() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let scan = page_scan();
    let pdf = scan::pdf(&[
        PageKind::Text { text: "NATIVE TEXT" },
        PageKind::Scan {
            img: &scan,
            rotate: 0,
        },
    ]);
    let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
    assert_eq!(t.pages[0].text.trim(), "NATIVE TEXT");
    assert_eq!(scan::words(&t.pages[1].text), "HELLO WORLD SCANNED INVOICE");
    assert_eq!(t.layout[0].items[0].source, "native_text");
    assert_eq!(t.layout[1].items[0].source, "ocr");
}

#[test]
fn always_mode_adds_the_text_of_embedded_images_to_a_text_layer_without_a_renderer() {
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let (img, _) = scan::render_lines(&["SCANNED PART"], SCALE);
    let pdf = scan::pdf(&[PageKind::TextAndScan {
        text: "VECTOR TEXT",
        img: &img,
    }]);
    let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Always)).unwrap();
    assert_eq!(pdf_words(&t), "VECTOR TEXT SCANNED PART", "{t:?}");
    let sources: Vec<&str> = t.layout[0].items.iter().map(|b| b.source).collect();
    assert_eq!(sources, ["native_text", "ocr"]);
}

#[test]
fn only_the_configured_number_of_pages_is_read() {
    let cfg = OcrConfig {
        max_pdf_pages: 1,
        ..config(Rasterizer::Embedded)
    };
    let Some(ocr) = engine(&cfg) else {
        return;
    };
    let scan = page_scan();
    let pdf = scan::pdf(&[
        PageKind::Scan {
            img: &scan,
            rotate: 0,
        },
        PageKind::Scan {
            img: &scan,
            rotate: 0,
        },
        PageKind::Scan {
            img: &scan,
            rotate: 0,
        },
    ]);
    let t = extract_pdf(&pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
    assert!(!t.pages[0].text.trim().is_empty());
    assert!(t.pages[1].text.trim().is_empty() && t.pages[2].text.trim().is_empty());
    assert_eq!(
        t.warnings.iter().filter(|w| w.contains("maxPdfPages")).count(),
        1,
        "{:?}",
        t.warnings
    );
}

#[test]
fn a_vector_only_page_is_unreadable_without_a_renderer_and_readable_with_pdftoppm() {
    let pdf = scan::pdf(&[PageKind::Vector { text: "HELLO VECTOR" }]);
    let Some(embedded) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let t = extract_pdf(&pdf, &pdf_options(&embedded, PdfOcr::Auto)).unwrap();
    assert!(t.text.trim().is_empty());
    assert!(
        t.warnings.iter().any(|w| w.contains("no rasteriser")),
        "{:?}",
        t.warnings
    );
    let Some(rendered) = engine(&config(Rasterizer::Pdftoppm)) else {
        return;
    };
    assert!(rendered.can_rasterize());
    let t = extract_pdf(&pdf, &pdf_options(&rendered, PdfOcr::Auto)).unwrap();
    assert_eq!(pdf_words(&t), "HELLO VECTOR", "{t:?}");
    // the box of the rendered page maps back to the rectangles' place: x 72..~510 of 612 pt,
    // y 600..642 of 792 pt (so 0.19..0.24 from the top)
    let [x0, y0, x1, y1] = t.layout[0].items[0].bbox.unwrap();
    assert!(
        (0.09..0.14).contains(&x0) && (0.8..0.87).contains(&x1),
        "{x0} {x1}"
    );
    assert!(
        (0.17..0.21).contains(&y0) && (0.23..0.27).contains(&y1),
        "{y0} {y1}"
    );
}

#[test]
fn always_mode_renders_the_whole_page_when_pdftoppm_exists() {
    let Some(rendered) = engine(&config(Rasterizer::Pdftoppm)) else {
        return;
    };
    let (img, _) = scan::render_lines(&["SCANNED PART"], SCALE);
    let pdf = scan::pdf(&[PageKind::TextAndScan {
        text: "VECTOR TEXT",
        img: &img,
    }]);
    let t = extract_pdf(&pdf, &pdf_options(&rendered, PdfOcr::Always)).unwrap();
    // one pass over the rendered page: both the text layer and the scan, all of it from OCR
    assert_eq!(pdf_words(&t), "VECTOR TEXT SCANNED PART", "{t:?}");
    assert!(t.layout[0].items.iter().all(|b| b.source == "ocr"));
}

#[test]
fn a_ccitt_g4_scan_is_decoded() {
    // `ccitt_g4.pdf`: the page_scan picture as a 1-bit CCITT Group 4 image, made with
    // `gs -sDEVICE=pdfwrite -dMonoImageFilter=/CCITTFaxEncode` from a PNG of `page_scan()`
    let Some(ocr) = tesseract(Rasterizer::Embedded) else {
        return;
    };
    let pdf = include_bytes!("fixtures/ocr/ccitt_g4.pdf");
    let t = extract_pdf(pdf, &pdf_options(&ocr, PdfOcr::Auto)).unwrap();
    assert_eq!(pdf_words(&t), "HELLO WORLD SCANNED INVOICE", "{t:?}");
}

// ---------------------------------------------------------------------------------------------
// Configuration and failures
// ---------------------------------------------------------------------------------------------

#[test]
fn a_missing_binary_is_reported_at_start_up_with_the_remedy() {
    let cfg = OcrConfig {
        backend: OcrBackend::Tesseract,
        tesseract_path: Some("/nonexistent/dir/tesseract".into()),
        ..OcrConfig::default()
    };
    let err = Ocr::from_config(&cfg).unwrap_err();
    assert!(
        matches!(
            err,
            OcrError::Unavailable {
                backend: "tesseract",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("CRAWLX_OCR_TESSERACT"), "{err}");
    // the off backend needs nothing
    assert!(Ocr::from_config(&OcrConfig::default()).unwrap().is_none());
}

#[test]
fn a_missing_language_is_reported_at_start_up() {
    let cfg = OcrConfig {
        languages: "eng+zzz".to_owned(),
        ..config(Rasterizer::Embedded)
    };
    match Ocr::from_config(&cfg) {
        Err(e @ OcrError::Unavailable { .. }) if e.to_string().contains("`zzz`") => {}
        Err(OcrError::Unavailable { reason, .. }) if reason.contains("binary") => {
            eprintln!("skipping: {reason}");
        }
        other => panic!("{other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_hung_engine_is_killed_at_the_deadline() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("tesseract");
    std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = OcrConfig {
        backend: OcrBackend::Tesseract,
        tesseract_path: Some(script),
        timeout_ms: 300,
        ..OcrConfig::default()
    };
    let started = std::time::Instant::now();
    let err = Ocr::from_config(&cfg).unwrap_err();
    assert!(matches!(err, OcrError::Timeout { millis: 300, .. }), "{err:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn the_environment_selects_and_tunes_the_engine() {
    let env = |pairs: &'static [(&str, &str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
    };
    let c = OcrConfig::from_env(&env(&[])).unwrap();
    assert_eq!(c, OcrConfig::default());
    assert_eq!(c.backend, OcrBackend::Off, "OCR is opt-in");
    let c = OcrConfig::from_env(&env(&[
        ("CRAWLX_OCR_BACKEND", "Tesseract"),
        ("CRAWLX_OCR_LANGUAGES", "eng+tur"),
        ("TESSDATA_PREFIX", "/usr/share/tessdata"),
        ("CRAWLX_OCR_DPI", "200"),
        ("CRAWLX_OCR_RASTERIZER", "embedded"),
        ("CRAWLX_OCR_MAX_PDF_PAGES", "7"),
        ("CRAWLX_OCR_MIN_CONFIDENCE", "30"),
    ]))
    .unwrap();
    assert_eq!(c.backend, OcrBackend::Tesseract);
    assert_eq!(c.languages, "eng+tur");
    assert_eq!(
        c.tessdata_dir.as_deref(),
        Some(std::path::Path::new("/usr/share/tessdata"))
    );
    assert_eq!((c.dpi, c.max_pdf_pages, c.min_confidence), (200, 7, 30));
    assert_eq!(c.rasterizer, Rasterizer::Embedded);
    // CRAWLX_OCR_TESSDATA wins over TESSDATA_PREFIX
    let c = OcrConfig::from_env(&env(&[("CRAWLX_OCR_TESSDATA", "/a"), ("TESSDATA_PREFIX", "/b")])).unwrap();
    assert_eq!(c.tessdata_dir.as_deref(), Some(std::path::Path::new("/a")));
    // The drop-in IMAGE_OCR_ENABLED picks Tesseract only when no backend is named
    let c = OcrConfig::from_env(&env(&[("IMAGE_OCR_ENABLED", "true")])).unwrap();
    assert_eq!(c.backend, OcrBackend::Tesseract);
    let c = OcrConfig::from_env(&env(&[
        ("IMAGE_OCR_ENABLED", "true"),
        ("CRAWLX_OCR_BACKEND", "ocrs"),
    ]))
    .unwrap();
    assert_eq!(c.backend, OcrBackend::Ocrs);
    let c = OcrConfig::from_env(&env(&[("IMAGE_OCR_ENABLED", "false")])).unwrap();
    assert_eq!(c.backend, OcrBackend::Off);
    for bad in [
        &[("CRAWLX_OCR_BACKEND", "cloud")][..],
        &[("CRAWLX_OCR_DPI", "10")],
        &[("CRAWLX_OCR_DPI", "abc")],
        &[("CRAWLX_OCR_LANGUAGES", "eng;rm")],
        &[("CRAWLX_OCR_TIMEOUT_MS", "0")],
        &[("CRAWLX_OCR_MIN_CONFIDENCE", "101")],
        &[("CRAWLX_OCR_RASTERIZER", "gs")],
    ] {
        let bad: &'static [(&str, &str)] = Box::leak(bad.to_vec().into_boxed_slice());
        assert!(
            matches!(OcrConfig::from_env(&env(bad)), Err(OcrError::Config(_))),
            "{bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// ocrs
// ---------------------------------------------------------------------------------------------

#[test]
fn ocrs_without_models_names_the_remedy() {
    let cfg = OcrConfig {
        backend: OcrBackend::Ocrs,
        models_dir: Some("/nonexistent/models".into()),
        ..OcrConfig::default()
    };
    let err = Ocr::from_config(&cfg).unwrap_err();
    assert!(err.to_string().contains("text-detection"), "{err}");
    assert!(err.to_string().contains("ocrs-models"), "{err}");
    let cfg = OcrConfig {
        models_dir: None,
        ..cfg
    };
    assert!(Ocr::from_config(&cfg)
        .unwrap_err()
        .to_string()
        .contains("CRAWLX_OCR_MODELS"));
}

#[test]
fn ocrs_reads_text_with_the_downloaded_models() {
    let Some(models) = env("CRAWLX_OCR_MODELS") else {
        eprintln!("skipping: CRAWLX_OCR_MODELS names no directory with the ocrs models");
        return;
    };
    let cfg = OcrConfig {
        backend: OcrBackend::Ocrs,
        models_dir: Some(models.into()),
        ..OcrConfig::default()
    };
    let ocr = Ocr::from_config(&cfg).unwrap().unwrap();
    assert_eq!(ocr.backend(), OcrBackend::Ocrs);
    let (img, _) = scan::render_lines(&["HELLO WORLD", "SCANNED INVOICE"], SCALE);
    let page = ocr.recognize_bytes(&scan::png(&img)).unwrap();
    // the models read natural type; this blocky bitmap font costs a letter now and then
    let words = scan::words(&page.text());
    assert!(
        words.starts_with("HELLO WORL") && words.ends_with("SCANNED INVOICE"),
        "{page:?}"
    );
    assert!(page.confidence().is_none(), "ocrs reports no confidence");
    // a scanned PDF page through the same engine
    let scan = page_scan();
    let pdf = scan::pdf(&[PageKind::Scan {
        img: &scan,
        rotate: 0,
    }]);
    let t = extract_pdf(&pdf, &pdf_options(&Arc::new(ocr), PdfOcr::Auto)).unwrap();
    let words = pdf_words(&t);
    assert!(
        words.starts_with("HELLO WORL") && words.ends_with("SCANNED INVOICE"),
        "{t:?}"
    );
    assert_eq!(t.layout[0].items[0].source, "ocr");
    assert!(t.layout[0].items[0].confidence.ocr.is_none());
}
