//! Cookie and web-storage checkpointing. The blob is secret-bearing: the
//! caller encrypts it under the run's data key.
//!
//! Format (JSON): `{"version":1,"cookies":[<CDP Cookie>...],"origins":[{"origin","local":[[k,v]],"session":[[k,v]]}]}`.
//! Cookies cover the whole browser context (`Storage.getCookies`); web storage can only
//! be read for origins with an open document, so it covers the origins of the open tabs.
//! On import, storage for an origin is written when a document of that origin loads (and
//! immediately if one is open), without overwriting keys the page already set.

use super::{js, CdpContext};
use crawlx_core::browser::BrowserError;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const FORMAT_VERSION: u64 = 1;
const MAX_PROFILE_STORAGE_BYTES: usize = 1024 * 1024;
const MAX_PROFILE_COOKIES: usize = 4096;
const MAX_PROFILE_TABS: usize = 64;
const MAX_PROFILE_ENTRIES: usize = 4096;

fn profile_storage_error() -> BrowserError {
    BrowserError::Script("profile storage snapshot unavailable or exceeds bounds".to_owned())
}

fn write_profile_storage(value: &Value, mut output: &mut [u8]) -> Result<usize, BrowserError> {
    let capacity = output.len();
    serde_json::to_writer(&mut output, value).map_err(|_| profile_storage_error())?;
    Ok(capacity - output.len())
}

fn valid_profile_cookie(cookie: &Value) -> bool {
    ["name", "value", "domain", "path"]
        .iter()
        .all(|field| cookie.get(field).is_some_and(Value::is_string))
        && cookie["domain"].as_str().is_some_and(|domain| !domain.is_empty())
        && cookie["path"].as_str().is_some_and(|path| path.starts_with('/'))
        && ["secure", "httpOnly", "session"]
            .iter()
            .all(|field| cookie.get(field).is_some_and(Value::is_boolean))
        && cookie
            .get("expires")
            .and_then(Value::as_f64)
            .is_some_and(f64::is_finite)
        && cookie.get("size").and_then(Value::as_u64).is_some()
        && cookie
            .get("sameSite")
            .is_none_or(|value| matches!(value.as_str(), Some("Strict" | "Lax" | "None")))
        && cookie
            .get("priority")
            .is_none_or(|value| matches!(value.as_str(), Some("Low" | "Medium" | "High")))
        && cookie
            .get("sourceScheme")
            .is_none_or(|value| matches!(value.as_str(), Some("Unset" | "NonSecure" | "Secure")))
        && cookie
            .get("sourcePort")
            .is_none_or(|value| value.as_i64().is_some_and(|port| (-1..=65535).contains(&port)))
        && cookie.get("partitionKey").is_none_or(|value| {
            value
                .get("topLevelSite")
                .and_then(Value::as_str)
                .is_some_and(|site| crate::egress::origin_of_str(site).as_deref() == Some(site))
                && value.get("hasCrossSiteAncestor").is_some_and(Value::is_boolean)
        })
        && cookie.get("partitionKeyOpaque").is_none_or(Value::is_boolean)
}

fn profile_origin(value: &Value) -> Result<Option<&str>, BrowserError> {
    let object = value.as_object().ok_or_else(profile_storage_error)?;
    let origin = value
        .get("origin")
        .and_then(Value::as_str)
        .ok_or_else(profile_storage_error)?;
    if (origin.is_empty() || origin == "null")
        && object.len() == 2
        && value.get("blank") == Some(&Value::Bool(true))
    {
        return Ok(None);
    }
    if object.len() != 3 || crate::egress::origin_of_str(origin).as_deref() != Some(origin) {
        return Err(profile_storage_error());
    }
    let mut entries = 0_usize;
    let mut bytes = origin.len();
    for field in ["local", "session"] {
        let pairs = value
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(profile_storage_error)?;
        entries = entries
            .checked_add(pairs.len())
            .ok_or_else(profile_storage_error)?;
        if entries > MAX_PROFILE_ENTRIES {
            return Err(profile_storage_error());
        }
        let mut keys = BTreeSet::new();
        for pair in pairs {
            let pair = pair
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(profile_storage_error)?;
            let key = pair[0].as_str().ok_or_else(profile_storage_error)?;
            let value = pair[1].as_str().ok_or_else(profile_storage_error)?;
            if !keys.insert(key) {
                return Err(profile_storage_error());
            }
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or_else(profile_storage_error)?;
            if bytes > MAX_PROFILE_STORAGE_BYTES {
                return Err(profile_storage_error());
            }
        }
    }
    Ok(Some(origin))
}

/// Fields of a CDP `Cookie` that `Storage.setCookies` accepts back as a `CookieParam`.
fn cookie_param(cookie: &Value) -> Option<Value> {
    let name = cookie.get("name")?.as_str()?;
    let value = cookie.get("value")?.as_str()?;
    let mut p = Map::new();
    p.insert("name".to_owned(), json!(name));
    p.insert("value".to_owned(), json!(value));
    for key in [
        "domain",
        "path",
        "secure",
        "httpOnly",
        "sameSite",
        "priority",
        "sourceScheme",
        "sourcePort",
        "partitionKey",
    ] {
        if let Some(v) = cookie.get(key) {
            p.insert(key.to_owned(), v.clone());
        }
    }
    let session = cookie.get("session").and_then(Value::as_bool).unwrap_or(false);
    if !session {
        if let Some(exp) = cookie
            .get("expires")
            .filter(|e| e.as_f64().is_some_and(|f| f > 0.0))
        {
            p.insert("expires".to_owned(), exp.clone());
        }
    }
    Some(Value::Object(p))
}

impl CdpContext {
    #[doc = "Exports unredacted v1 cookies and open-tab local/session storage for encrypted custody only."]
    #[doc = ""]
    #[doc = "Returns at most 1 MiB, with at most 4096 cookies, 64 tabs, and 4096 storage entries per tab."]
    #[doc = "Known opaque about:blank documents are skipped. Conflicting same-origin tab snapshots fail."]
    #[doc = "Checkpoint export retains its separate redaction behavior."]
    #[doc = ""]
    #[doc = "# Errors"]
    #[doc = "Returns a sanitized BrowserError::Script on failed reads, denied storage, malformed state,"]
    #[doc = "changed tab membership, conflicting origin state, or exceeded bounds. No partial state returns."]
    pub async fn export_profile_storage(&self) -> Result<Vec<u8>, BrowserError> {
        let tab_ids = self.state.lock().graph.ids();
        if tab_ids.len() > MAX_PROFILE_TABS {
            return Err(profile_storage_error());
        }
        let (_, sess) = self.session_for(None).map_err(|_| profile_storage_error())?;
        let mut response = sess
            .client
            .call(
                "Storage.getCookies",
                None,
                json!({ "browserContextId": self.ctl.browser_context_id }),
            )
            .await
            .map_err(|_| profile_storage_error())?;
        let cookies = response
            .get_mut("cookies")
            .map(Value::take)
            .ok_or_else(profile_storage_error)?;
        let items = cookies.as_array().ok_or_else(profile_storage_error)?;
        if items.len() > MAX_PROFILE_COOKIES || !items.iter().all(valid_profile_cookie) {
            return Err(profile_storage_error());
        }
        let mut bytes = vec![0; MAX_PROFILE_STORAGE_BYTES];
        let mut remaining = bytes.as_mut_slice();
        serde_json::to_writer(&mut remaining, &cookies).map_err(|_| profile_storage_error())?;
        let mut origins = std::collections::BTreeMap::new();
        for tab in &tab_ids {
            let value = self
                .world_eval(Some(tab), js::READ_PROFILE_STORAGE, false)
                .await
                .map_err(|_| profile_storage_error())?;
            let Some(origin) = profile_origin(&value)? else {
                continue;
            };
            if let Some(previous) = origins.get(origin) {
                if previous != &value {
                    return Err(profile_storage_error());
                }
                continue;
            }
            serde_json::to_writer(&mut remaining, &value).map_err(|_| profile_storage_error())?;
            origins.insert(origin.to_owned(), value);
        }
        if self.state.lock().graph.ids() != tab_ids {
            return Err(profile_storage_error());
        }
        let storage = Value::Object(Map::from_iter([
            ("version".to_owned(), Value::from(FORMAT_VERSION)),
            ("cookies".to_owned(), cookies),
            (
                "origins".to_owned(),
                Value::Array(origins.into_values().collect()),
            ),
        ]));
        let length = write_profile_storage(&storage, &mut bytes)?;
        bytes.truncate(length);
        Ok(bytes)
    }

    pub(crate) async fn export_storage_impl(&mut self) -> Result<Vec<u8>, BrowserError> {
        let (_, sess) = self.session_for(None)?;
        let cookies = sess
            .client
            .call(
                "Storage.getCookies",
                None,
                json!({ "browserContextId": self.ctl.browser_context_id }),
            )
            .await?;
        let cookies = cookies.get("cookies").cloned().unwrap_or_else(|| json!([]));

        let tab_ids = self.state.lock().graph.ids();
        let mut origins: Vec<Value> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for tab in tab_ids {
            let Ok(v) = self.world_eval(Some(&tab), js::READ_STORAGE, false).await else {
                continue;
            };
            let origin = v
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if origin.is_empty() || origin == "null" || !seen.insert(origin.clone()) {
                continue;
            }
            origins.push(json!({
                "origin": origin,
                "local": v.get("local").cloned().unwrap_or_else(|| json!([])),
                "session": v.get("session").cloned().unwrap_or_else(|| json!([])),
            }));
        }
        origins.sort_by(|a, b| {
            a.get("origin")
                .and_then(Value::as_str)
                .cmp(&b.get("origin").and_then(Value::as_str))
        });
        let mut storage = json!({ "version": FORMAT_VERSION, "cookies": cookies, "origins": origins });
        self.ctl.config.captcha_secrets.redact_json(&mut storage)?;
        serde_json::to_vec(&storage).map_err(|e| BrowserError::Script(e.to_string()))
    }

    pub(crate) async fn import_storage_impl(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        let doc: Value = serde_json::from_slice(blob)
            .map_err(|e| BrowserError::Script(format!("invalid storage blob: {e}")))?;
        if doc.get("version").and_then(Value::as_u64) != Some(FORMAT_VERSION) {
            return Err(BrowserError::Script(
                "unsupported storage blob version".to_owned(),
            ));
        }
        let cookies: Vec<Value> = doc
            .get("cookies")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(cookie_param).collect())
            .unwrap_or_default();
        if !cookies.is_empty() {
            self.ctl
                .client
                .call(
                    "Storage.setCookies",
                    None,
                    json!({ "cookies": cookies, "browserContextId": self.ctl.browser_context_id }),
                )
                .await?;
        }
        let tab_ids = self.state.lock().graph.ids();
        for o in doc
            .get("origins")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let origin = o.get("origin").and_then(Value::as_str).unwrap_or_default();
            if origin.is_empty() {
                continue;
            }
            let local = o.get("local").cloned().unwrap_or_else(|| json!([]));
            let session = o.get("session").cloned().unwrap_or_else(|| json!([]));
            let script = js::write_storage_script(origin, &local, &session);
            for tab in &tab_ids {
                let Ok((_, sess)) = self.session_for(Some(tab)) else {
                    continue;
                };
                sess.send(
                    "Page.addScriptToEvaluateOnNewDocument",
                    json!({ "source": script, "worldName": js::WORLD_NAME }),
                )
                .await?;
                // also apply to the current document when it already has that origin
                let _ = self.world_eval(Some(tab), &script, false).await;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn cookie_params_keep_persistent_expiry_only() {
        let c = json!({"name": "sid", "value": "1", "domain": "a.test", "path": "/", "secure": true,
                       "httpOnly": true, "session": false, "expires": 1_900_000_000.5, "size": 4});
        let p = cookie_param(&c).unwrap();
        assert_eq!(p["name"], "sid");
        assert_eq!(p["expires"], json!(1_900_000_000.5));
        assert!(p.get("size").is_none());
        let s = json!({"name": "t", "value": "2", "domain": "a.test", "session": true, "expires": -1});
        assert!(cookie_param(&s).unwrap().get("expires").is_none());
        assert!(cookie_param(&json!({"value": "x"})).is_none());
    }

    #[test]
    fn profile_snapshot_preserves_secret_bytes_and_v1_schema() {
        let storage = json!({
            "version": FORMAT_VERSION,
            "cookies": [{
                "name": "sid", "value": "secret-cookie", "domain": "a.test", "path": "/",
                "secure": true, "httpOnly": true, "session": true, "expires": -1, "size": 16
            }],
            "origins": [{
                "origin": "https://a.test",
                "local": [["token", "secret-local"]],
                "session": [["token", "secret-session"]]
            }]
        });
        assert!(valid_profile_cookie(&storage["cookies"][0]));
        assert_eq!(
            profile_origin(&storage["origins"][0]).unwrap(),
            Some("https://a.test")
        );
        let mut bytes = vec![0; MAX_PROFILE_STORAGE_BYTES];
        let length = write_profile_storage(&storage, &mut bytes).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes[..length]).unwrap(),
            storage
        );
    }

    #[test]
    fn profile_snapshot_serialization_enforces_exact_byte_bound() {
        let mut bytes = vec![0; MAX_PROFILE_STORAGE_BYTES];
        let exact = Value::String("x".repeat(MAX_PROFILE_STORAGE_BYTES - 2));
        assert_eq!(
            write_profile_storage(&exact, &mut bytes).unwrap(),
            MAX_PROFILE_STORAGE_BYTES
        );
        let too_large = Value::String("x".repeat(MAX_PROFILE_STORAGE_BYTES - 1));
        assert!(write_profile_storage(&too_large, &mut bytes).is_err());
        let escaped = Value::String("\0".repeat(MAX_PROFILE_STORAGE_BYTES / 2));
        assert!(write_profile_storage(&escaped, &mut bytes).is_err());
    }

    #[test]
    fn profile_snapshot_rejects_malformed_or_denied_storage() {
        for value in [
            json!({"denied": true}),
            json!({"origin": "null", "local": [], "session": []}),
            json!({"origin": "", "local": [], "session": []}),
            json!({"origin": "https://a.test/path", "local": [], "session": []}),
            json!({"origin": "https://a.test", "local": [["k", null]], "session": []}),
            json!({"origin": "https://a.test", "local": [["k", "v", "x"]], "session": []}),
            json!({"origin": "https://a.test", "local": [["k", "v"], ["k", "w"]], "session": []}),
            json!({"origin": "https://a.test", "local": [], "session": [], "denied": true}),
        ] {
            assert!(profile_origin(&value).is_err());
        }
        assert_eq!(
            profile_origin(&json!({"origin": "null", "blank": true})).unwrap(),
            None
        );
    }

    #[test]
    fn profile_snapshot_rejects_storage_count_and_content_overflow() {
        let entries: Vec<Value> = (0..=MAX_PROFILE_ENTRIES)
            .map(|index| json!([index.to_string(), "v"]))
            .collect();
        assert!(profile_origin(&json!({
            "origin": "https://a.test", "local": entries, "session": []
        }))
        .is_err());
        assert!(profile_origin(&json!({
            "origin": "https://a.test",
            "local": [["k", "x".repeat(MAX_PROFILE_STORAGE_BYTES)]],
            "session": []
        }))
        .is_err());
    }

    #[test]
    fn profile_snapshot_rejects_malformed_cookie_fields() {
        let cookie = json!({
            "name": "sid", "value": "secret", "domain": "a.test", "path": "/",
            "secure": true, "httpOnly": true, "session": true, "expires": -1, "size": 9
        });
        for field in [
            "name", "value", "domain", "path", "secure", "httpOnly", "session", "expires", "size",
        ] {
            let mut malformed = cookie.clone();
            malformed[field] = Value::Null;
            assert!(!valid_profile_cookie(&malformed));
        }
        for (field, value) in [
            ("sameSite", json!("invalid")),
            ("sourcePort", json!(65536)),
            (
                "partitionKey",
                json!({"topLevelSite": "invalid", "hasCrossSiteAncestor": false}),
            ),
        ] {
            let mut malformed = cookie.clone();
            malformed[field] = value;
            assert!(!valid_profile_cookie(&malformed));
        }
    }
}
