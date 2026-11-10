//! Named persistent browser profiles (`dynamic.browserProfile`, the compatibility API's
//! `profile{name,saveChanges}`).
//!
//! A profile is a Chromium user-data directory below the launcher's profiles directory
//! (`LaunchConfig::profiles_dir`, `--profiles-dir`), addressed by the relative
//! [`ProfileSpec::dir`] the worker builds as `<tenant>/<name>`. Every component is validated
//! here again, so a name can never leave the profiles directory.
//!
//! * `save_changes = true`: the directory itself is Chromium's `--user-data-dir`; what earlier
//!   runs left (persistent cookies, local storage) is there, and what this run writes stays.
//!   One browser process owns a directory at a time (Chromium's own singleton lock).
//! * `save_changes = false`: the run starts from a **copy** of the directory in a temp
//!   directory that is deleted with the browser; the profile on disk never changes. A profile
//!   that does not exist yet starts empty.
//!
//! Chromium writes cookies and local storage to disk asynchronously and on a clean exit, so a
//! run that keeps its changes must end its browser through `BrowserBackend::shutdown`
//! (`Browser.close`), never by killing it. Session cookies (no expiry) never reach the disk;
//! that is Chromium's rule, not a crawlx limit.

use crawlx_core::browser::{BrowserError, ProfileSpec};
use std::path::{Component, Path, PathBuf};

/// Longest single path component of a profile directory.
const MAX_COMPONENT_LEN: usize = 128;
/// Files that tie a user-data directory to a running browser; never copied.
const PROCESS_FILES: [&str; 3] = ["SingletonLock", "SingletonSocket", "SingletonCookie"];

/// The user-data directory a launch uses and the temp copy that owns it, if any.
#[derive(Debug)]
pub struct PreparedProfile {
    /// Passed to Chromium as `--user-data-dir`.
    pub dir: PathBuf,
    /// The discarded copy (`save_changes = false`); deleted when dropped.
    pub temp: Option<tempfile::TempDir>,
}

fn component_is_valid(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= MAX_COMPONENT_LEN
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `profiles_dir` joined with `spec.dir`, after checking that every component is `A-Z a-z 0-9
/// _ -`.
///
/// # Errors
/// [`BrowserError::Launch`] for an empty, absolute, dotted or otherwise unsafe directory.
pub fn profile_path(profiles_dir: &Path, spec: &ProfileSpec) -> Result<PathBuf, BrowserError> {
    let bad = |why: &str| BrowserError::Launch(format!("browser profile {:?}: {why}", spec.dir));
    if spec.dir.is_empty() {
        return Err(bad("empty name"));
    }
    let mut path = profiles_dir.to_path_buf();
    for component in Path::new(&spec.dir).components() {
        match component {
            Component::Normal(c) if c.to_str().is_some_and(component_is_valid) => path.push(c),
            _ => return Err(bad("each path component must be 1 to 128 of A-Z a-z 0-9 _ -")),
        }
    }
    Ok(path)
}

/// Make the user-data directory of `spec` ready for a launch (see the module docs).
///
/// # Errors
/// [`BrowserError::Launch`] for an unsafe name, [`BrowserError::Io`] when the directory cannot
/// be created or copied.
pub fn prepare(profiles_dir: &Path, spec: &ProfileSpec) -> Result<PreparedProfile, BrowserError> {
    let io = |e: std::io::Error| BrowserError::Io(e.to_string());
    let path = profile_path(profiles_dir, spec)?;
    if spec.save_changes {
        std::fs::create_dir_all(&path).map_err(io)?;
        return Ok(PreparedProfile {
            dir: path,
            temp: None,
        });
    }
    let temp = tempfile::Builder::new()
        .prefix("crawlx-chromium-profile-")
        .tempdir()
        .map_err(io)?;
    if path.is_dir() {
        copy_tree(&path, temp.path()).map_err(io)?;
    }
    Ok(PreparedProfile {
        dir: temp.path().to_path_buf(),
        temp: Some(temp),
    })
}

/// Recursive copy of `from` into the existing directory `to`, without the files that bind a
/// directory to a browser process and without symbolic links.
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|n| PROCESS_FILES.contains(&n)) {
            continue;
        }
        let kind = entry.file_type()?;
        let target = to.join(&name);
        if kind.is_dir() {
            std::fs::create_dir(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn spec(dir: &str, save: bool) -> ProfileSpec {
        ProfileSpec {
            dir: dir.to_owned(),
            save_changes: save,
        }
    }

    #[test]
    fn names_that_could_leave_the_profiles_directory_are_refused() {
        let root = Path::new("/profiles");
        for bad in ["", "..", "a/../b", "/abs", "a//b/..", "a b", "a.b", "é", "./a"] {
            assert!(profile_path(root, &spec(bad, true)).is_err(), "{bad:?}");
        }
        assert!(profile_path(root, &spec(&"x".repeat(129), true)).is_err());
        assert_eq!(
            profile_path(root, &spec("tenant-1/main_2", true)).unwrap(),
            Path::new("/profiles/tenant-1/main_2")
        );
    }

    #[test]
    fn a_kept_profile_is_the_directory_itself() {
        let root = tempfile::tempdir().unwrap();
        let p = prepare(root.path(), &spec("t/p", true)).unwrap();
        assert_eq!(p.dir, root.path().join("t/p"));
        assert!(p.dir.is_dir() && p.temp.is_none());
    }

    #[test]
    fn a_discarded_profile_is_a_copy_without_process_files_and_never_changes_the_original() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("t/p");
        std::fs::create_dir_all(original.join("Default")).unwrap();
        std::fs::write(original.join("Default/Cookies"), "c1").unwrap();
        std::fs::write(original.join("SingletonLock"), "host-1").unwrap();
        let p = prepare(root.path(), &spec("t/p", false)).unwrap();
        assert_ne!(p.dir, original);
        assert_eq!(
            std::fs::read_to_string(p.dir.join("Default/Cookies")).unwrap(),
            "c1"
        );
        assert!(!p.dir.join("SingletonLock").exists());
        std::fs::write(p.dir.join("Default/Cookies"), "changed").unwrap();
        assert_eq!(
            std::fs::read_to_string(original.join("Default/Cookies")).unwrap(),
            "c1"
        );
        let copy = p.dir.clone();
        drop(p);
        assert!(!copy.exists(), "the copy is deleted with the browser");
        // a profile that does not exist yet starts empty and is not created
        let fresh = prepare(root.path(), &spec("t/new", false)).unwrap();
        assert_eq!(std::fs::read_dir(&fresh.dir).unwrap().count(), 0);
        assert!(!root.path().join("t/new").exists());
    }
}
