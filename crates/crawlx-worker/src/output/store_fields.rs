//! Per-host field wordlists (katana `-store-fields DIR`).
//!
//! Katana (`pkg/output/fields.go` `storeFields`/`appendToFileField`, commit
//! `9662cd7b60ba1bc3a88232433ddefc4f48a65bfe`, MIT) appends every value of a field to
//! `{dir}/{scheme}_{hostname}_{field}.txt`. Here a port in the host becomes `_` in the file
//! name and values already present in the file are not appended again (stable first-seen
//! order).

use super::fields::Field;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Default wordlist directory beneath the crawl or export output directory.
pub const DEFAULT_DIR: &str = "katana_field";

/// Directory of per-host wordlists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFields {
    dir: PathBuf,
}

/// Host part of the file name: `host[_port]`, never `:`.
fn host_label(url: &url::Url) -> String {
    let mut label = url.host_str().unwrap_or("unknown").replace(':', "_");
    if let Some(port) = url.port() {
        label.push('_');
        label.push_str(&port.to_string());
    }
    label
}

impl StoreFields {
    /// Wordlists under `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The wordlist directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file `values` of `field` for `url` go to.
    #[must_use]
    pub fn file_for(&self, url: &url::Url, field: &Field) -> PathBuf {
        self.dir.join(format!(
            "{}_{}_{}.txt",
            url.scheme(),
            host_label(url),
            field.as_str()
        ))
    }

    /// Append `values` (one per line, skipping lines already in the file and duplicates
    /// within `values`) to the wordlist of `field` for `url`'s scheme and host.
    ///
    /// # Errors
    /// Any I/O error creating the directory or reading/appending the file.
    pub fn write(&self, url: &url::Url, field: &Field, values: &[String]) -> std::io::Result<PathBuf> {
        let path = self.file_for(url, field);
        std::fs::create_dir_all(&self.dir)?;
        let mut seen: BTreeSet<String> = match File::open(&path) {
            Ok(f) => BufReader::new(f).lines().collect::<Result<_, _>>()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut w = BufWriter::new(file);
        for v in values {
            if seen.insert(v.clone()) {
                w.write_all(v.as_bytes())?;
                w.write_all(b"\n")?;
            }
        }
        w.flush()?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn writes_one_file_per_scheme_host_field_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let sf = StoreFields::new(dir.path().join("wl"));
        let u = url::Url::parse("https://a.example.com/x?k=1").unwrap();
        let p = sf.write(&u, &Field::Key, &s(&["k", "j", "k"])).unwrap();
        assert_eq!(p, dir.path().join("wl").join("https_a.example.com_key.txt"));
        let p2 = sf.write(&u, &Field::Key, &s(&["j", "z"])).unwrap();
        assert_eq!(p, p2);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "k\nj\nz\n");
        let other = url::Url::parse("http://a.example.com:8080/").unwrap();
        let p3 = sf
            .write(&other, &Field::Custom("email".to_owned()), &s(&["x@e.com"]))
            .unwrap();
        assert_eq!(
            p3.file_name().unwrap().to_str().unwrap(),
            "http_a.example.com_8080_email.txt"
        );
        assert_eq!(std::fs::read_to_string(&p3).unwrap(), "x@e.com\n");
        let v6 = url::Url::parse("http://[::1]:81/").unwrap();
        assert!(sf
            .file_for(&v6, &Field::Url)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("_url.txt"));
        assert!(!sf.file_for(&v6, &Field::Url).to_str().unwrap().contains(':'));
    }
}
