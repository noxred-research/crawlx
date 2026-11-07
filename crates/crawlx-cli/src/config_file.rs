//! `crawlx crawl --config FILE`.
//!
//! Three shapes, chosen by extension (otherwise by content):
//!
//! * `.yaml`/`.yml`: katana's configuration file. Every key is the long name of a `crawl`
//!   flag (`field-scope: rdn`, `rate-limit: 50`, `crawl-scope: [a, b]`). The file is read
//!   through the same parser as the command line, so values are validated exactly like
//!   flags, and the result is a flag layer that command-line flags override.
//! * `.json`: a `CreateCrawl` body (camelCase, the `POST /v1/crawls` shape) whose absent keys
//!   keep their defaults.
//! * `.toml`: the same body in a `[crawl]` table.
//!
//! Unknown keys are an error naming the key, in all three shapes.

use crate::crawl::CrawlArgs;
use anyhow::{anyhow, bail, Context as _};
use clap::{Args as _, FromArgMatches as _};
use crawlx_core::CreateCrawl;
use serde_json::{json, Value};
use std::path::Path;

/// A parsed configuration file.
#[derive(Debug)]
pub(crate) enum ConfigLayer {
    /// A flag layer (katana-style YAML).
    Flags(Box<CrawlArgs>),
    /// A `CreateCrawl` body, validated: every key is known.
    Crawl(Value),
}

/// Read and validate `path`.
///
/// # Errors
/// An unreadable or malformed file, an unknown key, or a value its flag or field rejects.
pub(crate) fn load(path: &Path) -> anyhow::Result<ConfigLayer> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading config file {}", path.display()))?;
    let at = |what: &str| format!("config file {}: {what}", path.display());
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("toml") => {
            let table: toml::Table = toml::from_str(&text).map_err(|e| anyhow!(at(&e.to_string())))?;
            if let Some(key) = table.keys().find(|k| k.as_str() != "crawl") {
                bail!(at(&format!(
                    "unknown key `{key}` (the TOML form has one table, `[crawl]`, holding a CreateCrawl body)"
                )));
            }
            let body = match table.get("crawl") {
                Some(v) => serde_json::to_value(v).map_err(|e| anyhow!(at(&e.to_string())))?,
                None => json!({}),
            };
            Ok(ConfigLayer::Crawl(checked_body(body, path)?))
        }
        Some("json") => {
            let body: Value = serde_json::from_str(&text).map_err(|e| anyhow!(at(&e.to_string())))?;
            Ok(ConfigLayer::Crawl(checked_body(body, path)?))
        }
        Some("yaml" | "yml") => flags_from_yaml(&text, path),
        _ if text.trim_start().starts_with('{') => {
            let body: Value = serde_json::from_str(&text).map_err(|e| anyhow!(at(&e.to_string())))?;
            Ok(ConfigLayer::Crawl(checked_body(body, path)?))
        }
        _ => flags_from_yaml(&text, path),
    }
}

fn flags_from_yaml(text: &str, path: &Path) -> anyhow::Result<ConfigLayer> {
    let at = |what: &str| format!("config file {}: {what}", path.display());
    let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(|e| anyhow!(at(&e.to_string())))?;
    let map = match doc {
        serde_yaml_ng::Value::Null => serde_yaml_ng::Mapping::new(),
        serde_yaml_ng::Value::Mapping(m) => m,
        _ => bail!(at("expected a mapping of flag names to values")),
    };
    let command = CrawlArgs::augment_args(clap::Command::new("crawl"));
    let mut argv = vec!["crawl".to_owned()];
    for (key, value) in &map {
        let key = key
            .as_str()
            .ok_or_else(|| anyhow!(at("keys must be flag names")))?;
        if key == "config" {
            bail!(at("`config` cannot name another configuration file"));
        }
        let arg = command
            .get_arguments()
            .find(|a| {
                a.get_long() == Some(key) || a.get_all_aliases().is_some_and(|aliases| aliases.contains(&key))
            })
            .ok_or_else(|| anyhow!(at(&format!("unknown key `{key}`"))))?;
        let long = arg
            .get_long()
            .ok_or_else(|| anyhow!(at(&format!("key `{key}` has no long flag"))))?;
        let explicit_bool = matches!(arg.get_action(), clap::ArgAction::Set)
            && arg.get_value_parser().type_id() == std::any::TypeId::of::<bool>();
        scalar_tokens(long, key, value, explicit_bool, &mut argv).map_err(|e| anyhow!(at(&e)))?;
    }
    let matches = command
        .try_get_matches_from(&argv)
        .map_err(|e| anyhow!(at(&clap_message(&e))))?;
    let args = CrawlArgs::from_arg_matches(&matches).map_err(|e| anyhow!(at(&clap_message(&e))))?;
    Ok(ConfigLayer::Flags(Box::new(args)))
}

/// Tokens for one YAML entry; value-taking booleans preserve explicit false.
fn scalar_tokens(
    long: &str,
    key: &str,
    value: &serde_yaml_ng::Value,
    explicit_bool: bool,
    argv: &mut Vec<String>,
) -> Result<(), String> {
    use serde_yaml_ng::Value as Y;
    let one = |v: &Y| -> Result<Option<String>, String> {
        match v {
            Y::Bool(value) if explicit_bool => Ok(Some(format!("--{long}={value}"))),
            Y::Null | Y::Bool(false) => Ok(None),
            Y::Bool(true) => Ok(Some(format!("--{long}"))),
            Y::String(s) => Ok(Some(format!("--{long}={s}"))),
            Y::Number(n) => Ok(Some(format!("--{long}={n}"))),
            Y::Sequence(_) | Y::Mapping(_) | Y::Tagged(_) => {
                Err(format!("key `{key}` takes a scalar or a list of scalars"))
            }
        }
    };
    match value {
        Y::Sequence(items) => {
            for item in items {
                argv.extend(one(item)?);
            }
        }
        other => argv.extend(one(other)?),
    }
    Ok(())
}

/// First line of a clap error without the `error: ` prefix.
fn clap_message(e: &clap::Error) -> String {
    let text = e.to_string();
    let first = text.lines().next().unwrap_or_default();
    first.strip_prefix("error: ").unwrap_or(first).to_owned()
}

/// Validate a `CreateCrawl` body: it must be an object, deserialize, and use known keys only.
fn checked_body(body: Value, path: &Path) -> anyhow::Result<Value> {
    let at = |what: &str| format!("config file {}: {what}", path.display());
    if !body.is_object() {
        bail!(at("expected an object (a CreateCrawl body)"));
    }
    let base = serde_json::to_value(CreateCrawl::new(
        url::Url::parse("https://config.invalid/").map_err(|e| anyhow!(e))?,
    ))?;
    let mut merged = base;
    deep_merge(&mut merged, &body);
    serde_json::from_value::<CreateCrawl>(merged.clone()).map_err(|e| anyhow!(at(&e.to_string())))?;
    let mut unknown = Vec::new();
    find_unknown(&merged, &body, &mut Vec::new(), &mut unknown);
    if let Some(key) = unknown.first() {
        bail!(at(&format!("unknown key `{key}`")));
    }
    Ok(body)
}

/// Overlay `layer` on `base`: objects merge key by key, everything else is replaced.
pub(crate) fn deep_merge(base: &mut Value, layer: &Value) {
    match (base, layer) {
        (Value::Object(b), Value::Object(l)) => {
            for (k, v) in l {
                match b.get_mut(k) {
                    Some(slot) => deep_merge(slot, v),
                    None => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (slot, v) => *slot = v.clone(),
    }
}

#[derive(Clone, Debug)]
enum Seg {
    Key(String),
    Index(usize),
}

fn dotted(path: &[Seg]) -> String {
    path.iter()
        .map(|s| match s {
            Seg::Key(k) => k.clone(),
            Seg::Index(i) => format!("[{i}]"),
        })
        .collect::<Vec<_>>()
        .join(".")
        .replace(".[", "[")
}

fn value_at<'a>(root: &'a Value, path: &[Seg]) -> Option<&'a Value> {
    path.iter().try_fold(root, |v, seg| match seg {
        Seg::Key(k) => v.get(k),
        Seg::Index(i) => v.get(*i),
    })
}

fn set_at(root: &mut Value, path: &[Seg], value: Value) {
    match path.split_first() {
        None => *root = value,
        Some((Seg::Key(key), rest)) => {
            if let Some(object) = root.as_object_mut() {
                set_at(object.entry(key.clone()).or_insert(Value::Null), rest, value);
            }
        }
        Some((Seg::Index(index), rest)) => {
            if let Some(child) = root.get_mut(*index) {
                set_at(child, rest, value);
            }
        }
    }
}

/// Walk `layer` against what `CreateCrawl` serialises back. A key that is missing from the
/// round trip is either unknown or equal to its default and therefore skipped when
/// serialising; the two are told apart by probing: a known key reacts to some value (it
/// shows up in the round trip or makes deserialisation fail), an unknown key never does.
fn find_unknown(merged: &Value, layer: &Value, path: &mut Vec<Seg>, out: &mut Vec<String>) {
    let round_trip = serde_json::from_value::<CreateCrawl>(merged.clone())
        .ok()
        .and_then(|c| serde_json::to_value(c).ok())
        .unwrap_or(Value::Null);
    walk(merged, &round_trip, layer, path, out);
}

fn walk(merged: &Value, round_trip: &Value, layer: &Value, path: &mut Vec<Seg>, out: &mut Vec<String>) {
    match layer {
        Value::Object(map) => {
            for (key, child) in map {
                path.push(Seg::Key(key.clone()));
                let known = value_at(round_trip, path).is_some() || recognised(merged, path);
                if !known {
                    out.push(dotted(path));
                } else if child.is_object() || child.is_array() {
                    walk(merged, round_trip, child, path, out);
                }
                path.pop();
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                path.push(Seg::Index(i));
                if child.is_object() {
                    walk(merged, round_trip, child, path, out);
                }
                path.pop();
            }
        }
        _ => {}
    }
}

/// Does some value at `path` change how `CreateCrawl` reads the document?
fn recognised(merged: &Value, path: &[Seg]) -> bool {
    [json!(true), json!(1), json!("x"), json!(["x"]), json!({"x": "y"})]
        .into_iter()
        .any(|probe| {
            let mut candidate = merged.clone();
            set_at(&mut candidate, path, probe);
            match serde_json::from_value::<CreateCrawl>(candidate) {
                Err(_) => true,
                Ok(parsed) => serde_json::to_value(parsed)
                    .ok()
                    .is_some_and(|v| value_at(&v, path).is_some()),
            }
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn body(json: &str) -> anyhow::Result<Value> {
        checked_body(serde_json::from_str(json).unwrap(), Path::new("c.json"))
    }

    #[test]
    fn known_keys_pass_including_defaults_that_serialisation_skips() {
        body(
            r#"{"scope":{"strategy":"depth_first","pathClimb":false,"hostScopePattern":null},
                 "dynamic":{"maxScrollSteps":0,"interactionSelector":[]},
                 "fetch":{"timeoutMs":5000,"skipTlsVerification":false,"cookies":[],"extraHeaders":{}},
                 "extract":{"xhr":false,"formFill":{"enabled":false,"email":null}},
                 "roles":[{"name":"a","credentialRef":null,"loginPlan":null}]}"#,
        )
        .unwrap();
    }

    #[test]
    fn an_unknown_key_is_named_at_any_depth() {
        let err = body(r#"{"scope":{"strategyy":"depth_first"}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown key `scope.strategyy`"), "{err}");
        let err = body(r#"{"typo":false}"#).unwrap_err().to_string();
        assert!(err.contains("unknown key `typo`"), "{err}");
        let err = body(r#"{"fetch":{"cookies":[{"name":"a","value":"b","dom":"x"}]}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fetch.cookies[0].dom"), "{err}");
        let err = body(r#"{"scope":{"strategy":"sideways"}}"#)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("sideways") || err.contains("unknown variant"),
            "{err}"
        );
        assert!(body("[1]").is_err());
    }

    #[test]
    fn deep_merge_replaces_scalars_and_arrays_and_merges_objects() {
        let mut base = json!({"a": {"x": 1, "y": [1, 2]}, "b": 1});
        deep_merge(&mut base, &json!({"a": {"y": [3]}, "c": 2}));
        assert_eq!(base, json!({"a": {"x": 1, "y": [3]}, "b": 1, "c": 2}));
    }

    #[test]
    fn yaml_keys_are_flag_names_and_unknown_keys_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.yaml");
        std::fs::write(
            &p,
            "rate-limit: 50\ncrawl-scope:\n  - a\n  - b\nno-redirects: true\nretries: null\n",
        )
        .unwrap();
        let ConfigLayer::Flags(args) = load(&p).unwrap() else {
            panic!("flags")
        };
        assert_eq!(args.rate_limit, Some(50));
        assert_eq!(args.crawl_scope, ["a", "b"]);
        assert!(args.no_redirects);
        assert_eq!(args.retries, None);
        std::fs::write(&p, "rate-limitt: 50\n").unwrap();
        let err = load(&p).unwrap_err().to_string();
        assert!(err.contains("unknown key `rate-limitt`"), "{err}");
        std::fs::write(&p, "rate-limit: fast\n").unwrap();
        let err = load(&p).unwrap_err().to_string();
        assert!(err.contains("rate-limit"), "{err}");
        std::fs::write(&p, "config: other.yaml\n").unwrap();
        assert!(load(&p).is_err());
    }

    #[test]
    fn toml_form_is_one_crawl_table() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.toml");
        std::fs::write(
            &p,
            "[crawl.scope]\nstrategy = \"depth_first\"\n[crawl.limits]\nurls = 7\n",
        )
        .unwrap();
        let ConfigLayer::Crawl(v) = load(&p).unwrap() else {
            panic!("crawl")
        };
        assert_eq!(v["limits"]["urls"], 7);
        std::fs::write(&p, "[server]\nport = 1\n").unwrap();
        assert!(load(&p).unwrap_err().to_string().contains("unknown key `server`"));
    }

    #[test]
    fn captcha_body_uses_typed_reference_only_configuration() {
        let value = body(
            r#"{"crawl":{"captcha":{"provider":"capsolver","key_ref":"env://CAPTCHA_KEY",
                 "endpoint":"http://127.0.0.1:12345/","timeout_seconds":30,"poll_interval_ms":50}}}"#,
        )
        .unwrap();
        assert_eq!(value["crawl"]["captcha"]["provider"], "capsolver");
        assert!(body(r#"{"crawl":{"captcha":{"provider":"unknown","key_ref":"env://KEY"}}}"#).is_err());
        assert!(body(
            r#"{"crawl":{"captcha":{"provider":"capsolver","key_ref":"env://KEY","key":"literal"}}}"#
        )
        .is_err());
    }

    #[test]
    fn captcha_toml_settings_map_to_the_request_crawl_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("captcha.toml");
        std::fs::write(
            &path,
            "[crawl.crawl.captcha]\nprovider = \"capsolver\"\nkey_ref = \"env://CAPTCHA_KEY\"\ntimeout_seconds = 30\npoll_interval_ms = 50\n",
        )
        .unwrap();
        let ConfigLayer::Crawl(value) = load(&path).unwrap() else {
            panic!("crawl body");
        };
        assert_eq!(value["crawl"]["captcha"]["key_ref"], "env://CAPTCHA_KEY");
        assert_eq!(value["crawl"]["captcha"]["timeout_seconds"], 30);
    }
}
