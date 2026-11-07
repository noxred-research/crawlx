//! Embeds every `fixtures/<id>/` directory into the binary.
//!
//! The generated file declares one `FixtureDef` per fixture directory that has a
//! `manifest.json`; every other file in the directory (html, js, css, json) becomes a
//! servable file. Directories starting with `_` (shared assets) are skipped.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn content_type(name: &str) -> Option<&'static str> {
    let ext = Path::new(name).extension()?.to_str()?;
    Some(match ext {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let fixtures = manifest_dir.join("fixtures");
    println!("cargo:rerun-if-changed=fixtures");
    println!("cargo:rerun-if-changed=build.rs");

    let mut ids: Vec<String> = fs::read_dir(&fixtures)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !n.starts_with('_') && fixtures.join(n).join("manifest.json").is_file())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();

    let mut out = String::from(
        "/// Every fixture embedded at build time, sorted by id; one entry per `fixtures/<id>/` directory containing a `manifest.json`.\n\
         pub static GENERATED: &[FixtureDef] = &[\n",
    );
    for id in &ids {
        let dir = fixtures.join(id);
        println!("cargo:rerun-if-changed=fixtures/{id}");
        let mut files: Vec<String> = fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.path().is_file())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n != "manifest.json" && content_type(n).is_some())
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        let root = fixtures.display();
        let _ = writeln!(out, "    FixtureDef {{");
        let _ = writeln!(out, "        id: {id:?},");
        let _ = writeln!(
            out,
            "        manifest_json: include_str!(\"{root}/{id}/manifest.json\"),"
        );
        let _ = writeln!(out, "        files: &[");
        for f in &files {
            let ct = content_type(f).unwrap_or("application/octet-stream");
            let _ = writeln!(
                out,
                "            FileDef {{ name: {f:?}, content_type: {ct:?}, body: include_str!(\"{root}/{id}/{f}\") }},"
            );
        }
        let _ = writeln!(out, "        ],");
        let _ = writeln!(out, "    }},");
    }
    out.push_str("];\n");
    let common = fixtures.join("_common").join("gym.js");
    println!("cargo:rerun-if-changed=fixtures/_common");
    let _ = writeln!(
        out,
        "/// Seeded client library (`fixtures/_common/gym.js`) inlined into every fixture page; `{{{{SEED}}}}`/`{{{{FIXTURE}}}}` placeholders are filled per request.\npub static GYM_JS: &str = include_str!(\"{}\");",
        common.display()
    );

    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("fixtures_gen.rs");
    if let Err(e) = fs::write(&dest, out) {
        println!("cargo:warning=failed to write {}: {e}", dest.display());
        std::process::exit(1);
    }
}
