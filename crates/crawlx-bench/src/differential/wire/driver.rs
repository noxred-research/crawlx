//! Executes the scenarios of a [`WireFamily`] against one [`Target`] over HTTP and records the
//! raw exchanges. The driver judges nothing: [`super::compare`] derives
//! observations from what it recorded.

use super::sink::Sink;
use super::{
    substitute, AfterStep, Exchange, Hooks, Scenario, ScenarioCapture, Settle, WireCapture, WireFamily,
    WireProvenance,
};
use crate::differential::access::AccessLog;
use crate::error::BenchError;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Poll interval of status requests.
const POLL: Duration = Duration::from_millis(400);

/// Time a cancelled crawl gets to stop before the quiet window of a scenario opens.
const QUIET_GRACE: Duration = Duration::from_millis(1500);

/// A system under test reachable over the upstream v2 HTTP surface.
#[derive(Clone)]
#[non_exhaustive]
pub struct Target {
    /// System name (`upstream`, `crawlx`).
    pub system: String,
    /// `black_box_run` (the real upstream) or `crawlx_facade`.
    pub provenance: String,
    /// Pinned upstream commit, for the real upstream.
    pub commit: Option<String>,
    /// API root; request paths (`/v2/crawl`) are appended (`http://127.0.0.1:3102`, or
    /// `http://127.0.0.1:PORT/compat` for the facade).
    pub api_root: String,
    /// Bearer token the requests carry.
    pub bearer: String,
    /// Origin the system reaches the gym on (`http://gym.test:4101`).
    pub origin: String,
    /// The gym's `/__gym/ledger` as the runner reaches it, for the quiet check and the access log.
    pub gym_ledger_url: Option<String>,
    /// The webhook sink of the runner.
    pub sink: Option<Arc<Sink>>,
    /// Origin the system reaches the sink on (`http://gym.test:PORT`).
    pub sink_origin: Option<String>,
    /// Restart action for scenarios with a hook.
    pub hooks: Option<Arc<dyn Hooks>>,
}

impl Target {
    /// A target without gym ledger, sink or hooks.
    #[must_use]
    pub fn new(system: &str, provenance: &str, api_root: &str, bearer: &str, origin: &str) -> Self {
        Self {
            system: system.to_owned(),
            provenance: provenance.to_owned(),
            commit: None,
            api_root: api_root.trim_end_matches('/').to_owned(),
            bearer: bearer.to_owned(),
            origin: origin.trim_end_matches('/').to_owned(),
            gym_ledger_url: None,
            sink: None,
            sink_origin: None,
            hooks: None,
        }
    }

    /// Record the pinned upstream commit.
    #[must_use]
    pub fn with_commit(mut self, commit: Option<String>) -> Self {
        self.commit = commit;
        self
    }

    /// The gym's `/__gym/ledger` as the runner reaches it.
    #[must_use]
    pub fn with_gym_ledger(mut self, url: &str) -> Self {
        self.gym_ledger_url = Some(url.to_owned());
        self
    }

    /// The webhook sink and the origin the system reaches it on.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<Sink>, origin: &str) -> Self {
        self.sink = Some(sink);
        self.sink_origin = Some(origin.to_owned());
        self
    }

    /// The restart action of scenarios with a hook.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<dyn Hooks>) -> Self {
        self.hooks = Some(hooks);
        self
    }
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("system", &self.system)
            .field("api_root", &self.api_root)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// Reduce documents of a status body to `sourceURL` and `statusCode` (page bodies are not
/// committed); everything else is kept.
fn trim(mut v: Value) -> Value {
    if let Some(Value::Array(docs)) = v.get_mut("data") {
        for d in docs.iter_mut() {
            let meta = d.get("metadata");
            let reduced = json!({
                "sourceURL": meta.and_then(|m| m.get("sourceURL")).cloned().unwrap_or(Value::Null),
                "statusCode": meta.and_then(|m| m.get("statusCode")).cloned().unwrap_or(Value::Null),
            });
            *d = reduced;
        }
    }
    v
}

fn terminal(v: &Value) -> bool {
    matches!(
        v.get("status").and_then(Value::as_str),
        Some("completed" | "failed" | "cancelled")
    )
}

fn completed(v: &Value) -> u64 {
    v.get("completed").and_then(Value::as_u64).unwrap_or(0)
}

struct Driver<'a> {
    target: &'a Target,
    http: reqwest::Client,
}

impl Driver<'_> {
    async fn exchange(
        &self,
        step: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        raw: Option<&str>,
    ) -> Exchange {
        let url = format!("{}{path}", self.target.api_root);
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = self.http.request(m, &url).bearer_auth(&self.target.bearer);
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(r) = raw {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(r.to_owned());
        }
        let started = Instant::now();
        let (status, response) = match req.send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                match r.bytes().await {
                    Ok(bytes) => (
                        status,
                        serde_json::from_slice::<Value>(&bytes)
                            .map_or_else(|_| json!({ "_text": String::from_utf8_lossy(&bytes) }), trim),
                    ),
                    Err(e) => (status, json!({ "_error": e.to_string() })),
                }
            }
            Err(e) => (0, json!({ "_error": e.to_string() })),
        };
        Exchange {
            step: step.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            request: body.cloned(),
            status,
            response,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Poll `GET /v2/crawl/{id}` until `done` holds or the deadline passes; the last exchange.
    async fn poll(&self, step: &str, id: &str, timeout_s: u64, done: impl Fn(&Value) -> bool) -> Exchange {
        let deadline = Instant::now() + Duration::from_secs(timeout_s);
        loop {
            let ex = self
                .exchange(step, "GET", &format!("/v2/crawl/{id}"), None, None)
                .await;
            if (ex.status == 200 && done(&ex.response)) || Instant::now() >= deadline {
                return ex;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn ledger_count(&self) -> Option<u64> {
        let url = self.target.gym_ledger_url.as_deref()?;
        let body: Value = self.http.get(url).send().await.ok()?.json().await.ok()?;
        body.get("count").and_then(Value::as_u64)
    }

    async fn after(&self, step: &AfterStep, id: Option<&str>) -> Exchange {
        let path = step.path.replace("{id}", id.unwrap_or("unknown"));
        self.exchange(
            &format!("after:{}", step.label),
            &step.method,
            &path,
            step.body.as_ref(),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn scenario(&self, family: &WireFamily, spec: &Scenario) -> ScenarioCapture {
        let t = self.target;
        let mut out = ScenarioCapture {
            id: spec.id.clone(),
            ..ScenarioCapture::default()
        };
        let seed_path = spec.seed_path.as_deref().unwrap_or(&family.seed_path);
        let mut vars: BTreeMap<&str, String> = BTreeMap::new();
        vars.insert("origin", t.origin.clone());
        vars.insert("seed", format!("{}{seed_path}", t.origin.trim_end_matches('/')));
        let mut body = spec.body.as_ref().map(|b| {
            if let (Some(w), Some(origin)) = (&spec.webhook, &t.sink_origin) {
                vars.insert(
                    "sink",
                    format!("{}/hook/{}", origin.trim_end_matches('/'), w.label),
                );
            }
            substitute(b, &vars)
        });
        if let (Some(w), Some(sink), Some(origin)) = (&spec.webhook, &t.sink, &t.sink_origin) {
            sink.script(&w.label, w.fail_first, w.fail_status);
            let mut hook = json!({ "url": format!("{}/hook/{}", origin.trim_end_matches('/'), w.label) });
            if !w.headers.is_empty() {
                hook["headers"] = json!(w.headers);
            }
            if let Some(m) = &w.metadata {
                hook["metadata"] = m.clone();
            }
            if let Some(e) = &w.events {
                hook["events"] = json!(e);
            }
            if let Some(Value::Object(map)) = body.as_mut() {
                map.insert("webhook".to_owned(), hook);
            }
        }

        let request = self
            .exchange(
                "request",
                &spec.method,
                &spec.path,
                body.as_ref(),
                spec.raw_body.as_deref(),
            )
            .await;
        let id = (200..300)
            .contains(&request.status)
            .then(|| {
                request
                    .response
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        out.exchanges.push(request);

        if let Some(id) = id.as_deref() {
            if let Some(h) = &spec.hook {
                let trigger = self
                    .poll("trigger", id, h.timeout_s, |v| {
                        completed(v) >= h.after_completed || terminal(v)
                    })
                    .await;
                out.exchanges.push(trigger);
                let restarted = match &t.hooks {
                    Some(hooks) => hooks.restart().await,
                    None => Err("no restart hook configured".to_owned()),
                };
                out.notes.insert(
                    "hook".to_owned(),
                    json!({ "ok": restarted.is_ok(), "error": restarted.as_ref().err() }),
                );
                let started = Instant::now();
                let fin = self.poll("final", id, h.then_timeout_s, terminal).await;
                out.notes.insert(
                    "hook_to_final_ms".to_owned(),
                    json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
                );
                out.exchanges.push(fin);
            } else {
                match &spec.settle {
                    Settle::None => {}
                    Settle::Cancel => {
                        out.exchanges.push(
                            self.exchange("settle", "DELETE", &format!("/v2/crawl/{id}"), None, None)
                                .await,
                        );
                    }
                    Settle::Terminal { timeout_s } => {
                        out.exchanges
                            .push(self.poll("final", id, *timeout_s, terminal).await);
                    }
                    Settle::CancelAfter {
                        completed: n,
                        timeout_s,
                    } => {
                        let trigger = self
                            .poll("trigger", id, *timeout_s, |v| completed(v) >= *n || terminal(v))
                            .await;
                        out.exchanges.push(trigger);
                        out.exchanges.push(
                            self.exchange("settle", "DELETE", &format!("/v2/crawl/{id}"), None, None)
                                .await,
                        );
                        out.exchanges.push(self.poll("final", id, 60, terminal).await);
                    }
                }
            }
        }
        for step in &spec.after {
            let ex = self.after(step, id.as_deref()).await;
            out.exchanges.push(ex);
        }
        if spec.quiet_ms > 0 {
            tokio::time::sleep(QUIET_GRACE).await;
            let before = self.ledger_count().await;
            tokio::time::sleep(Duration::from_millis(spec.quiet_ms)).await;
            let after = self.ledger_count().await;
            if let (Some(b), Some(a)) = (before, after) {
                out.notes
                    .insert("quiet_requests".to_owned(), json!(a.saturating_sub(b)));
            }
        }
        if let (Some(w), Some(sink)) = (&spec.webhook, &t.sink) {
            tokio::time::sleep(Duration::from_millis(spec.sink_grace_ms)).await;
            let events = sink.take(&w.label);
            out.notes.insert(
                "sink_events".to_owned(),
                serde_json::to_value(events).unwrap_or(Value::Null),
            );
        }
        out
    }
}

/// Run every scenario of `family` against `target`, in order.
///
/// # Errors
/// [`BenchError::Network`] when the HTTP client cannot be built.
pub async fn run_family(target: &Target, family: &WireFamily) -> Result<WireCapture, BenchError> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| BenchError::Request(format!("http client: {e}")))?;
    let driver = Driver { target, http };
    let mut scenarios = Vec::with_capacity(family.scenarios.len());
    for spec in &family.scenarios {
        scenarios.push(driver.scenario(family, spec).await);
    }
    let access_log = match &target.gym_ledger_url {
        Some(url) => match driver.http.get(url).send().await {
            Ok(r) => r.json::<Value>().await.ok().map(|b| AccessLog::from_gym_json(&b)),
            Err(_) => None,
        },
        None => None,
    };
    Ok(WireCapture {
        wire_sample: WireProvenance {
            provenance: target.provenance.clone(),
            system: target.system.clone(),
            upstream_commit: target.commit.clone(),
            api_root: target.api_root.clone(),
            origin: target.origin.clone(),
        },
        family: family.id.clone(),
        scenarios,
        access_log,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn documents_are_reduced_to_url_and_status() {
        let v = trim(json!({"status": "completed", "data": [
            {"markdown": "# big", "metadata": {"sourceURL": "http://a/x", "statusCode": 200, "title": "t"}},
            {"metadata": {}}
        ]}));
        assert_eq!(
            v["data"][0],
            json!({"sourceURL": "http://a/x", "statusCode": 200})
        );
        assert_eq!(v["data"][1], json!({"sourceURL": null, "statusCode": null}));
        assert!(terminal(&v));
        assert_eq!(completed(&json!({"completed": 4})), 4);
    }
}
