//! `--ocr-*` flags of `crawlx serve` and `crawlx worker`: precedence over `CRAWLX_OCR_*` and the
//! `[ocr]` table of `crawlx.toml`, start-up failure for a missing engine, and the effective
//! configuration printed by `crawlx config check`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::{CommandFactory as _, Parser as _};
use crawlx_cli::{Cli, Command, OcrArgs};
use crawlx_extract::parse::ocr::{OcrBackend, Rasterizer};
use std::collections::BTreeMap;

fn serve_args(extra: &[&str]) -> OcrArgs {
    let mut argv = vec!["crawlx", "serve"];
    argv.extend_from_slice(extra);
    match Cli::try_parse_from(argv).unwrap().command {
        Command::Serve(a) => a.ocr,
        other => panic!("{other:?}"),
    }
}

fn worker_args(extra: &[&str]) -> OcrArgs {
    let mut argv = vec!["crawlx", "worker"];
    argv.extend_from_slice(extra);
    match Cli::try_parse_from(argv).unwrap().command {
        Command::Worker(a) => a.ocr,
        other => panic!("{other:?}"),
    }
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |k| map.get(k).cloned()
}

#[test]
fn both_commands_document_the_flags() {
    for sub in ["serve", "worker"] {
        let help = Cli::command()
            .find_subcommand(sub)
            .unwrap()
            .clone()
            .render_long_help()
            .to_string();
        for flag in [
            "--ocr-backend",
            "--ocr-languages",
            "--ocr-tesseract",
            "--ocr-tessdata",
            "--ocr-models",
            "--ocr-rasterizer",
            "--ocr-max-pdf-pages",
        ] {
            assert!(help.contains(flag), "{sub} --help lacks {flag}");
        }
    }
}

#[test]
fn ocr_is_off_unless_asked_for() {
    let c = serve_args(&[]).config(&env(&[])).unwrap();
    assert_eq!(c.backend, OcrBackend::Off);
}

#[test]
fn flags_beat_the_environment_which_beats_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("crawlx.toml");
    std::fs::write(
        &file,
        "[ocr]\nbackend = \"ocrs\"\nlanguages = \"eng+tur\"\ndpi = 150\nmax_pdf_pages = 5\n",
    )
    .unwrap();
    let file_env = [("CRAWLX_CONFIG", file.to_str().unwrap())];
    // file only
    let c = worker_args(&[]).config(&env(&file_env)).unwrap();
    assert_eq!(
        (c.backend, c.languages.as_str(), c.dpi, c.max_pdf_pages),
        (OcrBackend::Ocrs, "eng+tur", 150, 5)
    );
    // the environment overrides the file
    let c = worker_args(&[])
        .config(&env(&[
            ("CRAWLX_CONFIG", file.to_str().unwrap()),
            ("CRAWLX_OCR_BACKEND", "tesseract"),
            ("CRAWLX_OCR_DPI", "200"),
        ]))
        .unwrap();
    assert_eq!(
        (c.backend, c.dpi, c.languages.as_str()),
        (OcrBackend::Tesseract, 200, "eng+tur")
    );
    // a flag overrides both
    let c = worker_args(&[
        "--ocr-backend",
        "off",
        "--ocr-rasterizer",
        "embedded",
        "--ocr-max-pdf-pages",
        "9",
    ])
    .config(&env(&[
        ("CRAWLX_CONFIG", file.to_str().unwrap()),
        ("CRAWLX_OCR_BACKEND", "tesseract"),
    ]))
    .unwrap();
    assert_eq!(
        (c.backend, c.rasterizer, c.max_pdf_pages),
        (OcrBackend::Off, Rasterizer::Embedded, 9)
    );
}

#[test]
fn a_bad_value_names_what_is_wrong() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("crawlx.toml");
    std::fs::write(&file, "[ocr]\nbackend = \"cloud\"\n").unwrap();
    let e = serve_args(&[])
        .config(&env(&[("CRAWLX_CONFIG", file.to_str().unwrap())]))
        .unwrap_err();
    assert!(format!("{e:#}").contains("[ocr] is invalid"), "{e:#}");
    let e = serve_args(&[])
        .config(&env(&[("CRAWLX_OCR_DPI", "5")]))
        .unwrap_err();
    assert!(format!("{e:#}").contains("dpi"), "{e:#}");
    assert!(Cli::try_parse_from(["crawlx", "serve", "--ocr-backend", "cloud"]).is_err());
}

#[tokio::test]
async fn a_missing_engine_stops_start_up_with_the_remedy() {
    let e = worker_args(&[
        "--ocr-backend",
        "tesseract",
        "--ocr-tesseract",
        "/nonexistent/tesseract",
    ])
    .engine(&env(&[]))
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("CRAWLX_OCR_TESSERACT"), "{e:#}");
    let e = worker_args(&["--ocr-backend", "ocrs", "--ocr-models", "/nonexistent"])
        .engine(&env(&[]))
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("text-detection"), "{e:#}");
    assert!(worker_args(&[]).engine(&env(&[])).await.unwrap().is_none());
}

#[tokio::test]
async fn a_working_tesseract_builds_an_engine() {
    let args = worker_args(&["--ocr-backend", "tesseract", "--ocr-rasterizer", "embedded"]);
    match args.engine(&env(&[])).await {
        Ok(Some(engine)) => assert_eq!(engine.backend(), OcrBackend::Tesseract),
        Ok(None) => panic!("tesseract was asked for"),
        Err(e) if format!("{e:#}").contains("binary was not found") => eprintln!("skipping: {e:#}"),
        Err(e) => panic!("{e:#}"),
    }
}
