//! Embeds `CRAWLX_GATE_SCOPE_DIGEST` over workspace sources and evaluator dependencies.
//!
//! Gate validation must expire when the evaluator, report schema, evidence producer or any
//! workspace dependency changes, not only when strategy/safety sources change. Collection
//! errors fail the build rather than producing a digest of incomplete or empty inputs.

use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|extension| {
            matches!(
                extension.to_str(),
                Some(
                    "rs" | "toml"
                        | "json"
                        | "sql"
                        | "html"
                        | "js"
                        | "css"
                        | "wasm"
                        | "svg"
                        | "png"
                        | "jpg"
                        | "jpeg"
                        | "gif"
                        | "webp"
                        | "txt"
                        | "onnx"
                )
            )
        }) {
            out.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest dir")?);
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("missing workspace root")?;
    let crates = root.join("crates");
    println!("cargo:rerun-if-changed={}", crates.display());
    let mut files = Vec::new();
    collect(&crates, &mut files)?;
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "chromium-pin.toml",
        "ci/layering.toml",
    ] {
        let file = root.join(name);
        println!("cargo:rerun-if-changed={}", file.display());
        if file.try_exists()? {
            files.push(file);
        } else if matches!(name, "Cargo.toml" | "Cargo.lock" | "chromium-pin.toml") {
            return Err(format!("missing required gate scope input {name}").into());
        }
    }
    // Paths are workspace-relative, independent of the checkout directory.
    let mut labelled = files
        .into_iter()
        .map(|file| {
            let label = file.strip_prefix(root)?.to_string_lossy().into_owned();
            Ok((label, file))
        })
        .collect::<Result<Vec<_>, std::path::StripPrefixError>>()?;
    labelled.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crawlx/gate-scope/v2\0");
    for (label, file) in labelled {
        let bytes = std::fs::read(file)?;
        hasher.update(&u64::try_from(label.len())?.to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&u64::try_from(bytes.len())?.to_le_bytes());
        hasher.update(&bytes);
    }
    println!(
        "cargo:rustc-env=CRAWLX_GATE_SCOPE_DIGEST={}",
        hasher.finalize().to_hex()
    );
    Ok(())
}
