//! Explicit full RELAX NG validation against an embedded, pinned TEI P5 schema.
//!
//! No DTD, XInclude processing, catalog lookup, external schema reference, or
//! network resolution is enabled. The system validator is an operator dependency.

use anyhow::{bail, Context};
use quick_xml::{events::Event, Reader};
use sha2::{Digest as _, Sha256};
use std::{io::Write, process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

pub(super) const SOURCE: &str = "https://tei-c.org/Vault/P5/4.10.2/xml/tei/custom/schema/relaxng/tei_all.rng";
pub(super) const SHA256: &str = "95fa3f6e47cd196c353124e007bd5c4994989dba8a64496458442136293dafd0";
const SCHEMA: &[u8] = include_bytes!("../schemas/tei-p5-4.10.2.rng");
const MAX_XML_BYTES: usize = 33_554_432;

fn preflight(bytes: &[u8], schema: bool) -> anyhow::Result<()> {
    if bytes.len() > MAX_XML_BYTES {
        bail!("TEI XML byte limit exceeded");
    }
    // Only UTF-8 is accepted, preventing alternate-encoding declaration tricks.
    std::str::from_utf8(bytes).context("TEI XML must be UTF-8")?;
    let mut reader = Reader::from_reader(bytes);
    let mut depth = 0_u16;
    let mut nodes = 0_u32;
    loop {
        nodes = nodes.checked_add(1).context("TEI XML node limit exceeded")?;
        if nodes > 1_000_000 {
            bail!("TEI XML node limit exceeded");
        }
        let event = reader.read_event().context("malformed TEI XML")?;
        if let Event::Start(element) | Event::Empty(element) = &event {
            for attribute in element.attributes() {
                let attribute = attribute.context("malformed TEI XML attribute")?;
                quick_xml::escape::unescape_with(&attribute.value, quick_xml::escape::resolve_xml_entity)
                    .context("invalid TEI XML attribute reference")?;
            }
        }
        if schema {
            if let Event::Start(element) | Event::Empty(element) = &event {
                if matches!(element.local_name().as_ref(), "include" | "externalRef") {
                    bail!("pinned TEI schema must have an empty external dependency closure");
                }
            }
        }
        match event {
            Event::DocType(_) => bail!("TEI DTD and entity declarations are forbidden"),
            Event::Decl(decl) => {
                if let Some(encoding) = decl.encoding() {
                    if !encoding?.eq_ignore_ascii_case("UTF-8") {
                        bail!("TEI XML must declare UTF-8");
                    }
                }
            }
            Event::Start(_) => {
                depth = depth.checked_add(1).context("TEI XML depth limit")?;
                if depth > 128 {
                    bail!("TEI XML depth limit exceeded");
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).context("malformed TEI XML nesting")?;
            }
            Event::GeneralRef(reference) => {
                if reference
                    .resolve_char_ref()
                    .context("invalid TEI character reference")?
                    .is_none()
                {
                    let name: &str = &reference;
                    if quick_xml::escape::resolve_xml_entity(name).is_none() {
                        bail!("TEI custom entities are forbidden");
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        bail!("malformed TEI XML nesting");
    }
    Ok(())
}

/// Prepared pinned schema. Only public schema bytes touch disk.
pub(super) struct Validator {
    schema: tempfile::NamedTempFile,
}

impl Validator {
    pub(super) fn prepare() -> anyhow::Result<Self> {
        let executable = std::fs::metadata("/usr/bin/xmllint")
            .context("TEI validation capability unavailable: install operator-approved /usr/bin/xmllint (libxml2, MIT)")?;
        if !executable.is_file() {
            bail!("TEI validation capability unavailable: xmllint is not a regular executable");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if executable.permissions().mode() & 0o111 == 0 {
                bail!("TEI validation capability unavailable: xmllint has no execute permission");
            }
        }
        let digest = hex::encode(Sha256::digest(SCHEMA));
        if digest != SHA256 {
            bail!("pinned TEI schema digest mismatch");
        }
        preflight(SCHEMA, true)?;
        let mut schema = tempfile::NamedTempFile::new().context("creating local TEI schema handle")?;
        schema.write_all(SCHEMA)?;
        schema.flush()?;
        Ok(Self { schema })
    }

    /// Validate a complete document or corpus, not an ad-hoc element whitelist.
    pub(super) async fn validate(&self, bytes: &[u8], cancel: &CancellationToken) -> anyhow::Result<()> {
        preflight(bytes, false)?;
        let mut child = tokio::process::Command::new("/usr/bin/xmllint")
        .env_clear().env("XML_CATALOG_FILES", "").env("SGML_CATALOG_FILES", "")
        .args(["--nonet", "--nocatalogs", "--maxmem", "134217728", "--noout", "--relaxng"])
        .arg(self.schema.path()).arg("-")
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .kill_on_drop(true).spawn().context("TEI validation capability unavailable: install operator-approved /usr/bin/xmllint (libxml2, MIT)")?;
        let mut stdin = child.stdin.take().context("opening TEI validator input")?;
        let validation = async {
            stdin
                .write_all(bytes)
                .await
                .context("writing TEI validator input")?;
            stdin.shutdown().await?;
            drop(stdin);
            let status = child.wait().await?;
            if !status.success() {
                bail!("TEI RELAX NG schema validation failed");
            }
            Ok(())
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(anyhow::anyhow!("TEI validation cancelled")),
            result = tokio::time::timeout(Duration::from_secs(10), validation) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!("TEI validation deadline exceeded")),
                }
            },
        };
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}

pub(super) fn provenance() -> serde_json::Value {
    serde_json::json!({"schema":"TEI P5 tei_all", "version":"4.10.2", "source":SOURCE,
        "sha256":SHA256, "license":"BSD-2-Clause", "externalDependencies":[],
        "validator":"/usr/bin/xmllint", "grammar":"RELAX NG", "schematron":false,
        "notice":include_str!("../schemas/NOTICE")})
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn pinned_schema_has_no_transitive_external_resolution_and_keeps_its_digest() {
        assert_eq!(hex::encode(Sha256::digest(SCHEMA)), SHA256);
        preflight(SCHEMA, true).unwrap();
        for schema in [
            b"<grammar><include href='nested.rng'/></grammar>".as_slice(),
            b"<grammar><div><externalRef href='https://fixture.invalid/schema'/></div></grammar>".as_slice(),
            b"<!DOCTYPE grammar SYSTEM 'file:///tmp/untrusted'><grammar/>".as_slice(),
        ] {
            assert!(preflight(schema, true).is_err());
        }
    }

    #[test]
    fn document_dtd_encoding_and_depth_are_refused_before_validator_execution() {
        assert!(preflight(b"<!DOCTYPE TEI [<!ENTITY x 'expansion'>]><TEI>&x;</TEI>", false).is_err());
        assert!(preflight(b"<?xml version='1.0' encoding='ISO-8859-1'?><TEI/>", false).is_err());
        let deep = format!("{}{}", "<div>".repeat(129), "</div>".repeat(129));
        assert!(preflight(deep.as_bytes(), false).is_err());
        assert!(preflight(b"<TEI>&unbound;</TEI>", false).is_err());
        assert!(preflight(b"<TEI>&#x110000;</TEI>", false).is_err());
        assert!(preflight(b"<TEI key='one' key='two'/>", false).is_err());
        assert!(preflight(b"<TEI key='&unbound;'/>", false).is_err());
        preflight(b"<TEI>A &amp; B &#x1F642; &#50;</TEI>", false).unwrap();
    }
}
