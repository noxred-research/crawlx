//! Server-side ground-truth ledger.
//!
//! Every fact here was observed by the gym *server*: an HTTP request that
//! reached a backend route, a beacon the page posted when a handler ran, a
//! form body that arrived. Scoring asserts on this ledger, never on what the
//! crawler claims to have done.

use crawlx_core::time::{Clock, SystemClock, Timestamp};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A ground-truth fact the gym server observed; serialized with a `kind` tag in snake_case.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LedgerEvent {
    /// A page handler ran for a ground-truth control.
    Click {
        /// Id of the ground-truth control (the `id` in the manifest's `controls`) whose handler ran.
        control: String,
        /// `event.isTrusted` as reported by the page (client-side oracle).
        trusted: bool,
    },
    /// A request reached a backend route.
    Op {
        /// Upper-case HTTP method of the request (`GET`, `POST`).
        method: String,
        /// Request path without query string, including the fixture prefix (e.g. `/g01/api/op`).
        path: String,
        /// Raw query string without the leading `?`; `None` when the URL had none.
        query: Option<String>,
        /// `Host` header of the request as sent (including any `:port`); `None` when the request had none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// A form body arrived.
    FormSubmit {
        /// Id of the submitted form (the form's `id` in the fixture manifest).
        form: String,
        /// Decoded body fields as `name -> value`; JSON bodies are flattened to strings.
        fields: BTreeMap<String, String>,
    },
    /// A named client-side probe result (`webdriver=true`, `blocked`, ...).
    Probe {
        /// Probe name, e.g. `webdriver`.
        name: String,
        /// Probe value as reported by the page, e.g. `true`.
        value: String,
    },
    /// A backend behavior the fixture server executed (or refused) for a principal.
    Effect {
        /// Principal the request authenticated as (`anonymous` when none).
        principal: String,
        /// Behavior label, e.g. `delete:owner:active` or `view:denied`.
        effect: String,
        /// Resource the behavior applied to, e.g. `invoice-3`.
        resource: String,
        /// Relation of principal to resource (`own`, `other_user_same_role`, `admin`, `shared`, `none`).
        resource_context: String,
    },
}

/// One ledger row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct LedgerEntry {
    /// 1-based order of arrival.
    pub seq: u64,
    /// Server clock time at which the row was appended.
    pub at: Timestamp,
    /// Fixture the request belonged to.
    pub fixture: String,
    /// What the server observed; flattened so `kind` and the event fields sit beside `seq`/`at`/`fixture`.
    #[serde(flatten)]
    pub event: LedgerEvent,
}

/// Append-only event log of one gym server.
pub struct Ledger {
    clock: Arc<dyn Clock>,
    entries: Mutex<Vec<LedgerEntry>>,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl Ledger {
    /// Empty ledger stamping rows with `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            entries: Mutex::new(Vec::new()),
        }
    }

    fn push(&self, fixture: &str, event: LedgerEvent) {
        let at = self.clock.now();
        let mut g = self.entries.lock();
        let seq = g.len() as u64 + 1;
        g.push(LedgerEntry {
            seq,
            at,
            fixture: fixture.to_owned(),
            event,
        });
    }

    /// Record `click(control_id)`.
    pub fn click(&self, fixture: &str, control: &str, trusted: bool) {
        self.push(
            fixture,
            LedgerEvent::Click {
                control: control.to_owned(),
                trusted,
            },
        );
    }

    /// Record `op(method, path)` for a request without a `Host` header.
    pub fn op(&self, fixture: &str, method: &str, path: &str, query: Option<&str>) {
        self.op_at_host(fixture, method, path, query, None);
    }

    /// Record `op(method, path)` with the request's `Host` header (`app.gym.test:4101`).
    pub fn op_at_host(
        &self,
        fixture: &str,
        method: &str,
        path: &str,
        query: Option<&str>,
        host: Option<&str>,
    ) {
        self.push(
            fixture,
            LedgerEvent::Op {
                method: method.to_ascii_uppercase(),
                path: path.to_owned(),
                query: query.map(str::to_owned),
                host: host.map(str::to_owned),
            },
        );
    }

    /// Record `form_submit(form_id, fields)`.
    pub fn form_submit(&self, fixture: &str, form: &str, fields: BTreeMap<String, String>) {
        self.push(
            fixture,
            LedgerEvent::FormSubmit {
                form: form.to_owned(),
                fields,
            },
        );
    }

    /// Record a client-side probe.
    pub fn probe(&self, fixture: &str, name: &str, value: &str) {
        self.push(
            fixture,
            LedgerEvent::Probe {
                name: name.to_owned(),
                value: value.to_owned(),
            },
        );
    }

    /// Record a backend behavior the fixture server performed for `principal` on `resource`.
    pub fn effect(
        &self,
        fixture: &str,
        principal: &str,
        effect: &str,
        resource: &str,
        resource_context: &str,
    ) {
        self.push(
            fixture,
            LedgerEvent::Effect {
                principal: principal.to_owned(),
                effect: effect.to_owned(),
                resource: resource.to_owned(),
                resource_context: resource_context.to_owned(),
            },
        );
    }

    /// Forget everything (`/reset`).
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    /// Copy of all rows in arrival order.
    #[must_use]
    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.entries.lock().clone()
    }

    /// Rows of one fixture.
    #[must_use]
    pub fn entries_for(&self, fixture: &str) -> Vec<LedgerEntry> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .cloned()
            .collect()
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// No rows yet?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Distinct control ids with at least one click row, sorted.
    #[must_use]
    pub fn clicked(&self, fixture: &str) -> BTreeSet<String> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .filter_map(|e| match &e.event {
                LedgerEvent::Click { control, .. } => Some(control.clone()),
                _ => None,
            })
            .collect()
    }

    /// Click rows `(control, trusted)` in arrival order.
    #[must_use]
    pub fn clicks(&self, fixture: &str) -> Vec<(String, bool)> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .filter_map(|e| match &e.event {
                LedgerEvent::Click { control, trusted } => Some((control.clone(), *trusted)),
                _ => None,
            })
            .collect()
    }

    /// `(method, path)` of every op row of `fixture`, in order.
    #[must_use]
    pub fn ops(&self, fixture: &str) -> Vec<(String, String)> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .filter_map(|e| match &e.event {
                LedgerEvent::Op { method, path, .. } => Some((method.clone(), path.clone())),
                _ => None,
            })
            .collect()
    }

    /// How many op rows match `method` (case-insensitive) and start with `path_prefix`?
    #[must_use]
    pub fn count_ops(&self, method: &str, path_prefix: &str) -> usize {
        self.entries
            .lock()
            .iter()
            .filter(|e| match &e.event {
                LedgerEvent::Op { method: m, path, .. } => {
                    m.eq_ignore_ascii_case(method) && path.starts_with(path_prefix)
                }
                _ => false,
            })
            .count()
    }

    /// Form submissions `(form, fields)` of `fixture`.
    #[must_use]
    pub fn forms(&self, fixture: &str) -> Vec<(String, BTreeMap<String, String>)> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .filter_map(|e| match &e.event {
                LedgerEvent::FormSubmit { form, fields } => Some((form.clone(), fields.clone())),
                _ => None,
            })
            .collect()
    }

    /// Probe values by name for `fixture` (last write wins).
    #[must_use]
    pub fn probes(&self, fixture: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for e in self.entries.lock().iter().filter(|e| e.fixture == fixture) {
            if let LedgerEvent::Probe { name, value } = &e.event {
                out.insert(name.clone(), value.clone());
            }
        }
        out
    }

    /// Effect rows `(principal, effect, resource, resource_context)` of `fixture`, in order.
    #[must_use]
    pub fn effects(&self, fixture: &str) -> Vec<(String, String, String, String)> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.fixture == fixture)
            .filter_map(|e| match &e.event {
                LedgerEvent::Effect {
                    principal,
                    effect,
                    resource,
                    resource_context,
                } => Some((
                    principal.clone(),
                    effect.clone(),
                    resource.clone(),
                    resource_context.clone(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The JSON document served at `/__gym/ledger`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let entries = self.entries();
        serde_json::json!({ "count": entries.len(), "entries": entries })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::time::ManualClock;

    fn ledger() -> Ledger {
        Ledger::new(Arc::new(ManualClock::new(Timestamp::default())))
    }

    #[test]
    fn records_in_order_with_sequence_numbers() {
        let l = ledger();
        l.click("g01", "c1", true);
        l.op("g25", "delete", "/g25/api/projects/1", None);
        l.form_submit(
            "g25",
            "invite",
            BTreeMap::from([("email".to_owned(), "a@b.test".to_owned())]),
        );
        l.probe("g31", "webdriver", "true");
        let rows = l.entries();
        assert_eq!(rows.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!(l.clicked("g01").into_iter().collect::<Vec<_>>(), ["c1"]);
        assert_eq!(l.clicks("g01"), [("c1".to_owned(), true)]);
        assert_eq!(l.count_ops("DELETE", "/g25/api/projects"), 1);
        assert_eq!(
            l.ops("g25"),
            [("DELETE".to_owned(), "/g25/api/projects/1".to_owned())]
        );
        assert_eq!(l.forms("g25")[0].1["email"], "a@b.test");
        assert_eq!(l.probes("g31")["webdriver"], "true");
        assert_eq!(l.entries_for("g25").len(), 2);
    }

    #[test]
    fn json_round_trips_and_clear_empties() {
        let l = ledger();
        l.click("g01", "c1", false);
        let json = l.to_json();
        assert_eq!(json["count"], 1);
        assert_eq!(json["entries"][0]["kind"], "click");
        let back: Vec<LedgerEntry> = serde_json::from_value(json["entries"].clone()).unwrap();
        assert_eq!(back, l.entries());
        l.clear();
        assert!(l.is_empty());
    }

    #[test]
    fn op_records_the_request_host_and_omits_it_when_absent() {
        let l = ledger();
        l.op_at_host("d2", "get", "/d2/", None, Some("app.gym.test:1"));
        l.op("d2", "GET", "/d2/", None);
        let json = l.to_json();
        assert_eq!(json["entries"][0]["host"], "app.gym.test:1");
        assert!(json["entries"][1].get("host").is_none());
        let back: Vec<LedgerEntry> = serde_json::from_value(json["entries"].clone()).unwrap();
        assert_eq!(back, l.entries());
    }
}
