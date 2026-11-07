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
}
