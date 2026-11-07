//! The request error log (katana `-elog/-error-log`).
//!
//! Katana appends one JSON object per failed request to the file
//! (`pkg/output/error.go`: `timestamp`, `endpoint`, `source`, `error`). crawlx writes the
//! failed frontier rows of a finished run: `timestamp` (when the log was written),
//! `endpoint`, `error` (the failure reason), `depth` and, when a response was seen,
//! `status_code`. The file is created even when nothing failed, as katana creates it at
//! start-up.

use super::text_file::TextFile;
use super::OutputError;
use crate::run::UrlFailure;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One line of the error log.
#[derive(Serialize)]
struct Line<'a> {
    timestamp: crawlx_core::Timestamp,
    endpoint: &'a str,
    error: &'a str,
    depth: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
}

/// Write `failures` to `path` as JSON lines (`-elog`). With `no_clobber` an existing
/// non-empty file is left alone and the next numbered name is used
/// ([`unclobbered`](super::text_file::unclobbered)). Returns the file written.
///
/// # Errors
/// [`OutputError::Io`] when the file cannot be created or written,
/// [`OutputError::Json`] when a line cannot be serialized.
pub fn write_error_log(
    path: impl AsRef<Path>,
    failures: &[UrlFailure],
    no_clobber: bool,
) -> Result<PathBuf, OutputError> {
    let mut file = TextFile::create(path, no_clobber)?;
    let timestamp = chrono::Utc::now();
    for failure in failures {
        let line = Line {
            timestamp,
            endpoint: &failure.url,
            error: &failure.reason,
            depth: failure.depth,
            status_code: failure.status,
        };
        serde_json::to_writer(&mut file, &line)?;
        file.write_all(b"\n")?;
    }
    Ok(file.finish()?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::Value;

    fn failures() -> Vec<UrlFailure> {
        vec![
            UrlFailure::new("https://e.com/a".to_owned(), 1, "connection refused".to_owned()),
            UrlFailure::new("https://e.com/b".to_owned(), 2, "http_503".to_owned()),
        ]
    }

    fn read(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn one_json_line_per_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_error_log(dir.path().join("err.log"), &failures(), false).unwrap();
        let lines = read(&path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["endpoint"], "https://e.com/a");
        assert_eq!(lines[0]["error"], "connection refused");
        assert_eq!(lines[0]["depth"], 1);
        assert!(lines[0].get("status_code").is_none());
        assert!(lines[0]["timestamp"].is_string());
        assert_eq!(lines[1]["status_code"], 503);
    }

    #[test]
    fn the_file_exists_when_nothing_failed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_error_log(dir.path().join("err.log"), &[], false).unwrap();
        assert!(path.is_file());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "");
    }

    #[test]
    fn no_clobber_keeps_the_earlier_log() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("err.log");
        write_error_log(&target, &failures(), true).unwrap();
        let second = write_error_log(&target, &failures()[..1], true).unwrap();
        assert_eq!(second, dir.path().join("err1.log"));
        assert_eq!(read(&target).len(), 2, "first log untouched");
        assert_eq!(read(&second).len(), 1);
        write_error_log(&target, &[], false).unwrap();
        assert_eq!(read(&target).len(), 0, "without -ncb the file is replaced");
    }
}
