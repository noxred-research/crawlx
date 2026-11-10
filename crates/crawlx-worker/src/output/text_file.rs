//! The `-o FILE` output file and the reference `-ncb/-no-clobber` naming.
//!
//! The reference tool only applies `-no-clobber` to the `-store-response` directory
//! (`pkg/output/output.go` `createDirNameNoClobber`): when the target exists and is not
//! empty, the highest `<name><N>` sibling is found and `<name><N+1>` is used. The flag's help
//! text says "do not overwrite output file", so crawlx applies the same rule to `-o FILE`,
//! [`StoredResponses`](super::StoredResponses) and the error log: an existing non-empty
//! target is never touched, the next free numbered name is used instead. For a file the
//! number goes before the extension (`out.txt` -> `out1.txt`, `out2.txt`, ...). An empty or
//! missing target is used as is.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// The path to use for `path` under `-ncb`: `path` itself when it is missing or empty,
/// otherwise the first unused `<stem><N><ext>` after the highest existing `N`.
///
/// # Errors
/// I/O errors from inspecting `path` or listing its directory.
pub fn unclobbered(path: &Path) -> io::Result<PathBuf> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(path.to_owned()),
        Err(e) => return Err(e),
    };
    let empty = if meta.is_dir() {
        fs::read_dir(path)?.next().is_none()
    } else {
        meta.len() == 0
    };
    if empty {
        return Ok(path.to_owned());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && !meta.is_dir() => name.split_at(i),
        _ => (name.as_str(), ""),
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut highest = 0u64;
    for entry in fs::read_dir(parent)? {
        let entry_name = entry?.file_name().to_string_lossy().into_owned();
        let number = entry_name
            .strip_prefix(stem)
            .and_then(|rest| rest.strip_suffix(ext))
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(n) = number {
            highest = highest.max(n);
        }
    }
    Ok(path.with_file_name(format!("{stem}{}{ext}", highest.saturating_add(1))))
}

/// A buffered output file (`-o FILE`). Implements [`Write`]; the data is flushed on
/// [`TextFile::finish`] or drop.
#[derive(Debug)]
pub struct TextFile {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl TextFile {
    /// Create (truncate) `path`; with `no_clobber`, an existing non-empty file is left alone
    /// and the next numbered name is created instead ([`unclobbered`]).
    ///
    /// # Errors
    /// I/O errors from creating the file.
    pub fn create(path: impl AsRef<Path>, no_clobber: bool) -> io::Result<Self> {
        let path = if no_clobber {
            unclobbered(path.as_ref())?
        } else {
            path.as_ref().to_owned()
        };
        let file = File::create(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::new(file),
        })
    }

    /// The file being written (differs from the requested path under `no_clobber`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush, sync and close the file; returns its path.
    ///
    /// # Errors
    /// I/O errors from flushing or syncing.
    pub fn finish(mut self) -> io::Result<PathBuf> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(self.path)
    }
}

impl Write for TextFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn plain_create_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        fs::write(&path, "old").unwrap();
        let mut f = TextFile::create(&path, false).unwrap();
        assert_eq!(f.path(), path);
        f.write_all(b"new\n").unwrap();
        f.finish().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[test]
    fn no_clobber_picks_the_next_numbered_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        // missing: used as is
        let mut f = TextFile::create(&path, true).unwrap();
        assert_eq!(f.path(), path);
        f.write_all(b"one\n").unwrap();
        f.finish().unwrap();
        // existing and not empty: out1.txt, then out2.txt
        let mut f = TextFile::create(&path, true).unwrap();
        assert_eq!(f.path(), dir.path().join("out1.txt"));
        f.write_all(b"two\n").unwrap();
        f.finish().unwrap();
        let mut f = TextFile::create(&path, true).unwrap();
        assert_eq!(f.path(), dir.path().join("out2.txt"));
        f.write_all(b"three\n").unwrap();
        f.finish().unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "one\n",
            "the original is untouched"
        );
        assert_eq!(fs::read_to_string(dir.path().join("out1.txt")).unwrap(), "two\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("out2.txt")).unwrap(),
            "three\n"
        );
        // a gap does not matter: the highest number wins
        fs::write(dir.path().join("out7.txt"), "x").unwrap();
        assert_eq!(unclobbered(&path).unwrap(), dir.path().join("out8.txt"));
    }

    #[test]
    fn an_empty_target_is_reused_and_unrelated_names_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        fs::write(&path, "").unwrap();
        fs::write(dir.path().join("out-final.txt"), "x").unwrap();
        fs::write(dir.path().join("outx.txt"), "x").unwrap();
        assert_eq!(unclobbered(&path).unwrap(), path);
        fs::write(&path, "data").unwrap();
        assert_eq!(unclobbered(&path).unwrap(), dir.path().join("out1.txt"));
    }

    #[test]
    fn directories_get_a_numeric_suffix_without_an_extension() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("resp.d");
        assert_eq!(unclobbered(&target).unwrap(), target);
        fs::create_dir(&target).unwrap();
        assert_eq!(unclobbered(&target).unwrap(), target, "empty directory is reused");
        fs::write(target.join("f"), "x").unwrap();
        assert_eq!(unclobbered(&target).unwrap(), dir.path().join("resp.d1"));
    }
}
