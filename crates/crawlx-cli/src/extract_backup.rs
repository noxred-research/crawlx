//! `crawlx extract --backup-dir`: an operator-selected, exclusive copy of every admitted input.
//!
//! The directory must not exist; it is created owner-only and every copy is created exclusively
//! (`create_new`, mode 0600) under the input's relative path, so a backup can neither overwrite
//! anything nor merge two inputs that share a file name in different directories. It must lie
//! outside the input source tree. A zero-retention run never reaches this module: the flag
//! combination is refused when the arguments are parsed.

use anyhow::{bail, Context as _};
use std::path::{Component, Path, PathBuf};

/// A freshly created backup directory.
pub(super) struct Backup {
    root: PathBuf,
}

impl Backup {
    /// Create `dir` (which must not exist yet), outside `input_root` when that is a source tree.
    ///
    /// # Errors
    /// The directory exists, its parent cannot be resolved, it lies inside the source tree, or
    /// it cannot be created.
    pub(super) fn create(dir: &Path, input_root: Option<&Path>) -> anyhow::Result<Self> {
        let parent = dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = dir
            .file_name()
            .context("--backup-dir must name a new directory")?;
        let parent = std::fs::canonicalize(parent).context("resolving the parent of --backup-dir")?;
        let root = parent.join(name);
        if input_root.is_some_and(|source| root.starts_with(source)) {
            bail!("--backup-dir must be outside the input source tree");
        }
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&root)
            .context("creating --backup-dir (it must not exist yet; backups never overwrite)")?;
        Ok(Self { root })
    }

    /// Copy `bytes` to `relative` below the backup root.
    ///
    /// # Errors
    /// `relative` is absolute or climbs out of the root, or the exclusive create fails (an
    /// existing path is never replaced).
    pub(super) fn save(&self, relative: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            bail!("refusing to back up a path outside the backup root");
        }
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent).context("creating a backup subdirectory")?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&target)
            .context("creating a backup copy without clobbering")?;
        std::io::Write::write_all(&mut file, bytes).context("writing a backup copy")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn copies_keep_their_directories_and_never_overwrite() {
        let work = tempfile::tempdir().unwrap();
        let backup = Backup::create(&work.path().join("bak"), None).unwrap();
        backup.save("a/index.html", b"one").unwrap();
        backup.save("b/index.html", b"two").unwrap();
        assert_eq!(
            std::fs::read(work.path().join("bak/a/index.html")).unwrap(),
            b"one"
        );
        assert_eq!(
            std::fs::read(work.path().join("bak/b/index.html")).unwrap(),
            b"two"
        );
        assert!(backup.save("a/index.html", b"three").is_err());
        assert_eq!(
            std::fs::read(work.path().join("bak/a/index.html")).unwrap(),
            b"one"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| {
                std::fs::metadata(work.path().join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode("bak"), 0o700);
            assert_eq!(mode("bak/a/index.html"), 0o600);
        }
    }

    #[test]
    fn an_existing_directory_or_one_inside_the_source_tree_is_refused() {
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("exists")).unwrap();
        assert!(Backup::create(&work.path().join("exists"), None).is_err());
        let root = std::fs::canonicalize(work.path()).unwrap();
        let error = Backup::create(&work.path().join("inside"), Some(&root))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("outside the input source tree"), "{error}");
        assert!(!work.path().join("inside").exists());
    }

    #[test]
    fn paths_that_leave_the_root_are_refused() {
        let work = tempfile::tempdir().unwrap();
        let backup = Backup::create(&work.path().join("bak"), None).unwrap();
        for bad in ["", "/etc/passwd", "../escape.html", "a/../../escape.html", "./x"] {
            assert!(backup.save(bad, b"x").is_err(), "{bad:?}");
        }
        assert!(!work.path().join("escape.html").exists());
    }
}
