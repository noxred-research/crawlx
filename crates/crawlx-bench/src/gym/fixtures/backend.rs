//! Stateful fixture backends (each backend behavior exercised is
//! recorded with principal, resource, ...).
//!
//! Most fixtures only need the generic `/<id>/api/...` echo of the gym server. The fixtures
//! here have behavior that depends on server state: sessions that expire (G18), resources
//! owned by principals (G20, G22), an OAuth code exchange (G17), server-side form validation
//! (G24), multipart uploads (G16), delayed replies (`async-late`), WebSocket pushes (G09,
//! `async-late`) and the non-idempotent `counter`. Every behavior is appended to the
//! [`Ledger`] as an `Effect` row so scoring never trusts the page.
//!
//! State is deterministic: ids are counters, nothing reads wall time; `/__gym/reset` restores
//! the seeded baseline through [`Backend::reset`].

use crate::gym::ledger::Ledger;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Credentials every login form of the gym accepts (fixture secrets; never real).
pub const PASSWORD: &str = "gym-pass";

/// How many authenticated `me` calls a G18 session survives before it expires.
pub const G18_SESSION_USES: u32 = 3;

/// Largest upload G16 accepts, in bytes.
pub const G16_MAX_UPLOAD_BYTES: usize = 4096;

/// A parsed backend request.
#[derive(Clone, Debug)]
pub struct Request<'a> {
    /// Fixture id (`g18`).
    pub fixture: &'a str,
    /// Upper-case HTTP method.
    pub method: &'a str,
    /// Path after `/<fixture>/api/`, no leading slash (`invoices/3/comments`).
    pub route: &'a str,
    /// Decoded query parameters.
    pub query: &'a BTreeMap<String, String>,
    /// Decoded form or JSON body fields.
    pub fields: &'a BTreeMap<String, String>,
    /// Request cookies.
    pub cookies: &'a BTreeMap<String, String>,
    /// Raw body (multipart uploads).
    pub body: &'a [u8],
    /// `Content-Type` header, if any.
    pub content_type: Option<&'a str>,
}

/// What a backend answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// JSON body.
    pub body: Value,
    /// `Set-Cookie` header values.
    pub set_cookies: Vec<String>,
    /// Delay before the reply is sent (late-traffic fixtures).
    pub delay_ms: u64,
}

impl Reply {
    fn ok(body: Value) -> Self {
        Self {
            status: 200,
            body,
            set_cookies: Vec::new(),
            delay_ms: 0,
        }
    }

    fn status(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            set_cookies: Vec::new(),
            delay_ms: 0,
        }
    }

    fn with_cookie(mut self, cookie: String) -> Self {
        self.set_cookies.push(cookie);
        self
    }
}

/// One scheduled unsolicited WebSocket push: `(delay since connect in ms, message name)`.
pub type Push = (u64, &'static str);

/// Unsolicited pushes a fixture's `/ws` endpoint sends after connect.
#[must_use]
pub fn ws_pushes(fixture: &str) -> &'static [Push] {
    match fixture {
        // six decoys: each arrives shortly after a crawler is likely to have clicked something
        "g09" => &[
            (1500, "p1"),
            (3500, "p2"),
            (5500, "p3"),
            (7500, "p4"),
            (9500, "p5"),
            (11500, "p6"),
        ],
        "async-late" => &[(1000, "w1"), (2500, "w2"), (4000, "w3")],
        _ => &[],
    }
}

/// Reply to a client WebSocket request `{"req": name}`; `None` closes nothing and answers nothing.
#[must_use]
pub fn ws_reply(fixture: &str, req: &str) -> Option<Value> {
    match (fixture, req) {
        ("g09", "open-a") => Some(json!({ "reply": "a-reply" })),
        ("g09", "open-b") => Some(json!({ "reply": "b-reply" })),
        ("async-late", "ping") => Some(json!({ "reply": "pong" })),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct Session {
    user: String,
    uses_left: u32,
}

#[derive(Clone, Debug)]
struct Invoice {
    owner: String,
    title: String,
    shared: bool,
    status: String,
    comments: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct Item {
    owner: String,
    archived: bool,
}

#[derive(Clone, Debug)]
struct Inner {
    next_id: u64,
    sessions: BTreeMap<String, Session>,
    refresh_tokens: BTreeMap<String, String>,
    invoices: BTreeMap<u64, Invoice>,
    items: BTreeMap<u64, Item>,
    oauth_codes: BTreeSet<String>,
    /// `POST /counter/api/increment` count (`repeated_non_idempotent_actions`).
    counter: u64,
    /// Applied G25 star effects, keyed by logical project rather than DOM position.
    project_stars: BTreeMap<u64, u64>,
    removed_projects: BTreeSet<u64>,
}

impl Inner {
    fn baseline() -> Self {
        let inv = |owner: &str, title: &str, shared: bool| Invoice {
            owner: owner.to_owned(),
            title: title.to_owned(),
            shared,
            status: "open".to_owned(),
            comments: Vec::new(),
        };
        Self {
            next_id: 1,
            sessions: BTreeMap::new(),
            refresh_tokens: BTreeMap::new(),
            invoices: BTreeMap::from([
                (1, inv("alice", "Alice private invoice", false)),
                (2, inv("alice", "Alice shared invoice", true)),
                (3, inv("bob", "Bob private invoice", false)),
                (4, inv("bob", "Bob shared invoice", true)),
            ]),
            items: BTreeMap::from([
                (
                    1,
                    Item {
                        owner: "alice".to_owned(),
                        archived: false,
                    },
                ),
                (
                    2,
                    Item {
                        owner: "bob".to_owned(),
                        archived: false,
                    },
                ),
            ]),
            oauth_codes: BTreeSet::new(),
            counter: 0,
            project_stars: BTreeMap::new(),
            removed_projects: BTreeSet::new(),
        }
    }

    fn next(&mut self) -> u64 {
        let n = self.next_id;
        self.next_id += 1;
        n
    }
}

/// Opaque fixture state; evidence remains in the separate, append-only ledger.
#[derive(Debug)]
pub(crate) struct BackendSnapshot(Inner);

/// Server state of the stateful fixtures.
#[derive(Debug)]
pub struct Backend {
    inner: Mutex<Inner>,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::baseline()),
        }
    }
}

const fn role_of(user: &str) -> &'static str {
    match user.as_bytes() {
        b"admin" => "admin",
        b"alice" | b"bob" => "member",
        _ => "anonymous",
    }
}

fn principal<'a>(req: &Request<'a>) -> &'a str {
    let key = format!("{}_user", req.fixture);
    req.cookies.get(&key).map_or("anonymous", String::as_str)
}

fn cookie(fixture: &str, name: &str, value: &str) -> String {
    format!("{fixture}_{name}={value}; Path=/{fixture}; SameSite=Lax")
}

fn clear_cookie(fixture: &str, name: &str) -> String {
    format!("{fixture}_{name}=; Path=/{fixture}; Max-Age=0; SameSite=Lax")
}

fn id_of(segment: &str) -> Option<u64> {
    segment.parse().ok()
}

impl Backend {
    /// Restore the seeded baseline (`/__gym/reset`).
    pub fn reset(&self) {
        *self.inner.lock() = Inner::baseline();
    }

    /// Capture all mutable fixture state without copying the evidence ledger.
    pub(crate) fn snapshot(&self) -> BackendSnapshot {
        BackendSnapshot(self.inner.lock().clone())
    }

    /// Restore a captured fixture state without erasing evidence.
    pub(crate) fn restore(&self, snapshot: &BackendSnapshot) {
        self.inner.lock().clone_from(&snapshot.0);
    }

    /// Answer `req` when its fixture has a stateful backend; `None` falls through to the generic echo.
    #[must_use]
    pub fn handle(&self, ledger: &Ledger, req: &Request<'_>) -> Option<Reply> {
        match req.fixture {
            "g16" => Some(self.g16(ledger, req)),
            "g17" => Some(self.g17(ledger, req)),
            "g18" => Some(self.g18(ledger, req)),
            "g20" => Some(self.g20(ledger, req)),
            "g22" => Some(self.g22(ledger, req)),
            "g24" => Some(Self::g24(ledger, req)),
            "async-late" => Some(Self::async_late(ledger, req)),
            "counter" => Some(self.counter_api(ledger, req)),
            "stale-rerender" => Some(self.stale_rerender(ledger, req)),
            _ => None,
        }
    }

    /// Server-side count of the `counter` fixture: how many `POST /counter/api/increment`
    /// requests were applied since the last reset. The ground truth for
    /// `repeated_non_idempotent_actions`.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.inner.lock().counter
    }

    fn stale_rerender(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        if req.method == "GET" && req.route == "stars" {
            let state = self.inner.lock();
            return Reply::ok(json!({ "stars": state.project_stars, "removed": state.removed_projects }));
        }
        if req.method == "DELETE" {
            if let Some(id) = req
                .route
                .strip_prefix("projects/")
                .and_then(id_of)
                .filter(|id| (1..=8).contains(id))
            {
                let mut state = self.inner.lock();
                state.removed_projects.insert(id);
                state.project_stars.remove(&id);
                ledger.effect(
                    req.fixture,
                    "anonymous",
                    "remove:applied",
                    &id.to_string(),
                    "shared",
                );
                return Reply::ok(json!({ "ok": true, "project": id }));
            }
        }
        if req.method == "POST" {
            if let Some(id) = req
                .route
                .strip_prefix("projects/")
                .and_then(|route| route.strip_suffix("/star"))
                .and_then(id_of)
                .filter(|id| (1..=8).contains(id))
            {
                let mut state = self.inner.lock();
                if state.removed_projects.contains(&id) {
                    return Reply::status(404, json!({ "ok": false, "error": "project removed" }));
                }
                let count = state.project_stars.entry(id).or_default();
                *count = count.saturating_add(1);
                ledger.effect(
                    req.fixture,
                    "anonymous",
                    "star:applied",
                    &id.to_string(),
                    "shared",
                );
                return Reply::ok(json!({ "ok": true, "project": id, "stars": count }));
            }
        }
        Reply::ok(json!({ "ok": true, "route": req.route }))
    }

    fn login(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        let user = req.fields.get("user").cloned().unwrap_or_default();
        let password = req.fields.get("password").map_or(PASSWORD, String::as_str);
        if role_of(&user) == "anonymous" || password != PASSWORD {
            ledger.effect(req.fixture, "anonymous", "login:denied", "session", "none");
            return Reply::status(401, json!({ "ok": false, "error": "bad credentials" }));
        }
        let _ = self.inner.lock().next();
        ledger.effect(req.fixture, &user, "login:ok", "session", "own");
        Reply::ok(json!({ "ok": true, "user": user, "role": role_of(&user) })).with_cookie(cookie(
            req.fixture,
            "user",
            &user,
        ))
    }

    fn logout(ledger: &Ledger, req: &Request<'_>) -> Reply {
        ledger.effect(req.fixture, principal(req), "logout", "session", "own");
        Reply::ok(json!({ "ok": true })).with_cookie(clear_cookie(req.fixture, "user"))
    }

    // ---- G16 file-upload ------------------------------------------------------------------

    fn g16(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        let _ = self;
        let Some(ctx) = req.route.strip_prefix("upload/") else {
            return Reply::status(404, json!({ "ok": false }));
        };
        if req.method != "POST" {
            return Reply::status(405, json!({ "ok": false }));
        }
        let parts = multipart_files(req.content_type, req.body);
        if parts.is_empty() {
            ledger.effect("g16", "anonymous", &format!("upload:{ctx}:empty"), "-", "none");
            return Reply::status(400, json!({ "ok": false, "error": "no file" }));
        }
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for (name, size) in parts {
            let too_big = size > G16_MAX_UPLOAD_BYTES;
            let wrong_type = match ctx {
                "image" => !name.ends_with(".png"),
                "pdf" => !name.ends_with(".pdf"),
                _ => false,
            };
            let verdict = if too_big {
                "rejected_oversize"
            } else if wrong_type {
                "rejected_type"
            } else {
                "accepted"
            };
            ledger.effect(
                "g16",
                "anonymous",
                &format!("upload:{ctx}:{verdict}"),
                &name,
                "none",
            );
            if verdict == "accepted" {
                accepted.push(json!({ "name": name, "size": size }));
            } else {
                rejected.push(json!({ "name": name, "size": size, "reason": verdict }));
            }
        }
        let ok = rejected.is_empty();
        Reply::status(
            if ok { 200 } else { 413 },
            json!({ "ok": ok, "accepted": accepted, "rejected": rejected }),
        )
    }

    // ---- G17 multi-tab OAuth --------------------------------------------------------------

    fn g17(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        match (req.method, req.route) {
            ("POST", "oauth/authorize") => {
                let user = req.fields.get("user").map_or("alice", String::as_str);
                let allow = req.fields.get("decision").is_some_and(|d| d == "allow");
                if !allow {
                    ledger.effect("g17", user, "oauth:denied", "idp", "none");
                    return Reply::ok(json!({ "ok": false, "error": "access_denied" }));
                }
                let code = {
                    let mut g = self.inner.lock();
                    let code = format!("code-{}", g.next());
                    g.oauth_codes.insert(code.clone());
                    code
                };
                ledger.effect("g17", user, "oauth:authorize", "idp", "none");
                Reply::ok(json!({ "ok": true, "code": code, "user": user }))
            }
            ("POST", "oauth/token") => {
                let code = req.fields.get("code").cloned().unwrap_or_default();
                let valid = self.inner.lock().oauth_codes.remove(&code);
                if !valid {
                    ledger.effect("g17", "anonymous", "oauth:token_rejected", &code, "none");
                    return Reply::status(400, json!({ "ok": false, "error": "invalid_grant" }));
                }
                ledger.effect("g17", "alice", "oauth:token", &code, "own");
                Reply::ok(json!({ "ok": true, "access_token": format!("tok-{code}"), "user": "alice" }))
                    .with_cookie(cookie("g17", "user", "alice"))
            }
            ("GET", "profile") => {
                let p = principal(req);
                if p == "anonymous" {
                    return Reply::status(401, json!({ "ok": false }));
                }
                ledger.effect("g17", p, "profile:view", "profile", "own");
                Reply::ok(json!({ "ok": true, "user": p }))
            }
            _ => Reply::ok(json!({ "ok": true, "route": req.route })),
        }
    }

    // ---- G18 auth-expiry ------------------------------------------------------------------

    fn g18_session<'a>(&self, req: &Request<'a>) -> Option<(String, Session)> {
        let token = req.cookies.get("g18_session")?;
        let s = self.inner.lock().sessions.get(token)?.clone();
        Some((token.clone(), s))
    }

    fn g18_new_session(&self, user: &str) -> String {
        let mut g = self.inner.lock();
        let token = format!("s{}", g.next());
        g.sessions.insert(
            token.clone(),
            Session {
                user: user.to_owned(),
                uses_left: G18_SESSION_USES,
            },
        );
        token
    }

    fn g18(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        match (req.method, req.route) {
            ("POST", "login") => {
                let user = req.fields.get("user").cloned().unwrap_or_default();
                let password = req.fields.get("password").cloned().unwrap_or_default();
                let mode = req.fields.get("mode").map_or("hard", String::as_str);
                if user != "member" || password != PASSWORD {
                    ledger.effect("g18", "anonymous", "login:denied", "session", "none");
                    return Reply::status(401, json!({ "ok": false, "error": "bad credentials" }));
                }
                let token = self.g18_new_session(&user);
                let mut reply = Reply::ok(json!({ "ok": true, "user": user, "mode": mode }))
                    .with_cookie(cookie("g18", "session", &token));
                if mode == "silent" {
                    let refresh = {
                        let mut g = self.inner.lock();
                        let r = format!("r{}", g.next());
                        g.refresh_tokens.insert(r.clone(), user.clone());
                        r
                    };
                    reply = reply.with_cookie(cookie("g18", "refresh", &refresh));
                }
                ledger.effect("g18", &user, &format!("login:{mode}"), "session", "own");
                reply
            }
            ("GET", "me") | ("POST", "secret") => {
                let Some((token, session)) = self.g18_session(req) else {
                    ledger.effect("g18", "anonymous", "session:missing", "session", "none");
                    return Reply::status(401, json!({ "ok": false, "error": "expired" }));
                };
                if session.uses_left == 0 {
                    self.inner.lock().sessions.remove(&token);
                    ledger.effect("g18", &session.user, "session:expired", "session", "own");
                    return Reply::status(401, json!({ "ok": false, "error": "expired" }))
                        .with_cookie(clear_cookie("g18", "session"));
                }
                if let Some(s) = self.inner.lock().sessions.get_mut(&token) {
                    s.uses_left -= 1;
                }
                let effect = if req.route == "me" { "me:ok" } else { "secret:used" };
                ledger.effect("g18", &session.user, effect, "session", "own");
                Reply::ok(json!({ "ok": true, "user": session.user, "uses_left": session.uses_left - 1 }))
            }
            ("POST", "refresh") => {
                let user = req
                    .cookies
                    .get("g18_refresh")
                    .and_then(|r| self.inner.lock().refresh_tokens.get(r).cloned());
                let Some(user) = user else {
                    ledger.effect("g18", "anonymous", "refresh:denied", "session", "none");
                    return Reply::status(401, json!({ "ok": false, "error": "no refresh token" }));
                };
                let token = self.g18_new_session(&user);
                ledger.effect("g18", &user, "session:silent_refresh", "session", "own");
                Reply::ok(json!({ "ok": true, "user": user })).with_cookie(cookie("g18", "session", &token))
            }
            ("POST", "logout") => {
                if let Some(t) = req.cookies.get("g18_session") {
                    self.inner.lock().sessions.remove(t);
                }
                if let Some(r) = req.cookies.get("g18_refresh") {
                    self.inner.lock().refresh_tokens.remove(r);
                }
                ledger.effect("g18", "member", "session:hard_logout", "session", "own");
                Reply::ok(json!({ "ok": true }))
                    .with_cookie(clear_cookie("g18", "session"))
                    .with_cookie(clear_cookie("g18", "refresh"))
            }
            _ => Reply::ok(json!({ "ok": true, "route": req.route })),
        }
    }

    // ---- G20 cross-user workflows (`shared-workspace`) ---------------------------

    fn g20(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        let p = principal(req);
        let role = role_of(p);
        match (req.method, req.route) {
            ("POST", "login") => return self.login(ledger, req),
            ("POST", "logout") => return Self::logout(ledger, req),
            ("GET", "whoami") => return Reply::ok(json!({ "ok": true, "user": p, "role": role })),
            ("GET", "invoices") => {
                let g = self.inner.lock();
                let rows: Vec<Value> = g
                    .invoices
                    .iter()
                    .filter(|(_, inv)| role == "admin" || inv.shared || inv.owner == p)
                    .map(|(id, inv)| invoice_json(*id, inv))
                    .collect();
                return Reply::ok(json!({ "ok": true, "user": p, "invoices": rows }));
            }
            ("POST", "invoices") => {
                if role == "anonymous" {
                    ledger.effect("g20", p, "create:denied", "invoice", "none");
                    return Reply::status(401, json!({ "ok": false }));
                }
                let title = req
                    .fields
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| "Untitled".to_owned());
                let shared = req.fields.get("visibility").is_some_and(|v| v == "shared");
                let id = {
                    let mut g = self.inner.lock();
                    let id = g.next() + 100;
                    g.invoices.insert(
                        id,
                        Invoice {
                            owner: p.to_owned(),
                            title,
                            shared,
                            status: "open".to_owned(),
                            comments: Vec::new(),
                        },
                    );
                    id
                };
                ledger.effect("g20", p, "create:ok", &format!("invoice-{id}"), "own");
                return Reply::ok(json!({ "ok": true, "id": id }));
            }
            _ => {}
        }
        let Some(rest) = req.route.strip_prefix("invoices/") else {
            return Reply::ok(json!({ "ok": true, "route": req.route }));
        };
        let (id_s, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(id) = id_of(id_s) else {
            return Reply::status(404, json!({ "ok": false }));
        };
        let resource = format!("invoice-{id}");
        let Some(inv) = self.inner.lock().invoices.get(&id).cloned() else {
            return Reply::status(404, json!({ "ok": false, "error": "no such invoice" }));
        };
        let context = if role == "anonymous" {
            "none"
        } else if inv.owner == p {
            "own"
        } else if role == "admin" {
            "admin"
        } else if inv.shared {
            "shared"
        } else {
            "other_user_same_role"
        };
        let action = match (req.method, tail) {
            ("GET", "") => "view",
            ("PUT", "") | ("POST", "update") => "modify",
            ("POST", "comments") => "comment",
            ("DELETE", "") | ("POST", "delete") => "delete",
            _ => return Reply::status(404, json!({ "ok": false })),
        };
        let allowed = match context {
            "own" | "admin" => true,
            "shared" => action != "delete",
            _ => false,
        };
        if !allowed {
            ledger.effect("g20", p, &format!("{action}:denied"), &resource, context);
            let status = if role == "anonymous" { 401 } else { 403 };
            return Reply::status(
                status,
                json!({ "ok": false, "error": "forbidden", "context": context }),
            );
        }
        let mut g = self.inner.lock();
        let Some(inv) = g.invoices.get_mut(&id) else {
            return Reply::status(404, json!({ "ok": false }));
        };
        match action {
            "modify" => {
                if let Some(t) = req.fields.get("title") {
                    inv.title.clone_from(t);
                }
                if let Some(s) = req.fields.get("status") {
                    inv.status.clone_from(s);
                }
            }
            "comment" => {
                let text = req.fields.get("text").cloned().unwrap_or_default();
                inv.comments.push((p.to_owned(), text));
            }
            "delete" => {
                inv.status = "deleted".to_owned();
            }
            _ => {}
        }
        let body = invoice_json(id, inv);
        drop(g);
        ledger.effect("g20", p, &format!("{action}:ok"), &resource, context);
        Reply::ok(json!({ "ok": true, "context": context, "invoice": body }))
    }

    // ---- G22 one control, many behaviors (`one-button-n-behaviors`) --------------

    fn g22(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        let p = principal(req);
        let role = role_of(p);
        match (req.method, req.route) {
            ("POST", "login") => return self.login(ledger, req),
            ("POST", "logout") => return Self::logout(ledger, req),
            ("GET", "items") => {
                let g = self.inner.lock();
                let rows: Vec<Value> = g
                    .items
                    .iter()
                    .map(|(id, it)| json!({ "id": id, "owner": it.owner, "archived": it.archived }))
                    .collect();
                return Reply::ok(json!({ "ok": true, "user": p, "role": role, "items": rows }));
            }
            _ => {}
        }
        let Some(rest) = req.route.strip_prefix("items/") else {
            return Reply::ok(json!({ "ok": true, "route": req.route }));
        };
        let (id_s, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(id) = id_of(id_s) else {
            return Reply::status(404, json!({ "ok": false }));
        };
        let resource = format!("item-{id}");
        let Some(item) = self.inner.lock().items.get(&id).cloned() else {
            return Reply::status(404, json!({ "ok": false }));
        };
        let relation = if role == "anonymous" {
            "none"
        } else if item.owner == p {
            "own"
        } else if role == "admin" {
            "admin"
        } else {
            "other_user_same_role"
        };
        let state = if item.archived { "archived" } else { "active" };
        match (req.method, tail) {
            ("POST", "archive") => {
                if relation == "own" || relation == "admin" {
                    let archived = {
                        let mut g = self.inner.lock();
                        let it = g.items.get_mut(&id);
                        it.map(|it| {
                            it.archived = !it.archived;
                            it.archived
                        })
                    };
                    ledger.effect("g22", p, "archive:toggled", &resource, relation);
                    Reply::ok(json!({ "ok": true, "archived": archived }))
                } else {
                    ledger.effect("g22", p, "archive:denied", &resource, relation);
                    Reply::status(403, json!({ "ok": false }))
                }
            }
            ("DELETE", "") | ("POST", "delete") => {
                // The button is the same; the backend behavior is a function of
                // (principal role, owner relation, prior state): 12 distinct action contexts.
                let behavior = match (relation, state) {
                    ("own", "active") => "soft_delete",
                    ("own", "archived") => "purge",
                    ("admin", "active") => "admin_soft_delete",
                    ("admin", "archived") => "admin_purge",
                    _ => "denied",
                };
                ledger.effect(
                    "g22",
                    p,
                    &format!("delete:{behavior}:{state}"),
                    &resource,
                    relation,
                );
                if behavior == "denied" {
                    Reply::status(403, json!({ "ok": false, "behavior": behavior, "state": state }))
                } else {
                    Reply::ok(
                        json!({ "ok": true, "behavior": behavior, "state": state, "relation": relation }),
                    )
                }
            }
            _ => Reply::status(404, json!({ "ok": false })),
        }
    }

    // ---- G24 forms with server-side validation --------------------------------------------

    fn g24(ledger: &Ledger, req: &Request<'_>) -> Reply {
        let Some(form) = req.route.strip_prefix("form/") else {
            return Reply::ok(json!({ "ok": true, "route": req.route }));
        };
        if req.method != "POST" {
            return Reply::status(405, json!({ "ok": false }));
        }
        let form = form.trim_end_matches('/');
        ledger.form_submit("g24", form, req.fields.clone());
        let errors = validate_g24(form, req.fields);
        let verdict = if errors.is_empty() { "accepted" } else { "rejected" };
        ledger.effect(
            "g24",
            "anonymous",
            &format!("form:{form}:{verdict}"),
            form,
            "none",
        );
        if errors.is_empty() {
            Reply::ok(json!({ "ok": true, "form": form }))
        } else {
            Reply::status(422, json!({ "ok": false, "form": form, "errors": errors }))
        }
    }

    // ---- async-late (late-request attribution) --------------------------------------

    fn async_late(ledger: &Ledger, req: &Request<'_>) -> Reply {
        let delay_ms = match req.route {
            "slow" => 1500,
            "timer" => 0,
            _ => 0,
        };
        ledger.effect(
            "async-late",
            "anonymous",
            &format!("api:{}", req.route),
            req.route,
            "none",
        );
        Reply {
            status: 200,
            body: json!({ "ok": true, "route": req.route, "delay_ms": delay_ms }),
            set_cookies: Vec::new(),
            delay_ms,
        }
    }

    // ---- counter (`POST /counter`) -------------------------------------------------

    /// `POST increment` applies one non-idempotent write and records `increment:ok`;
    /// `GET count` reads without an effect row.
    fn counter_api(&self, ledger: &Ledger, req: &Request<'_>) -> Reply {
        match (req.method, req.route) {
            ("POST", "increment") => {
                let count = {
                    let mut g = self.inner.lock();
                    g.counter += 1;
                    g.counter
                };
                ledger.effect("counter", principal(req), "increment:ok", "counter", "none");
                Reply::ok(json!({ "ok": true, "count": count }))
            }
            ("GET", "count") => Reply::ok(json!({ "ok": true, "count": self.inner.lock().counter })),
            ("POST" | "GET", "count" | "increment") => Reply::status(405, json!({ "ok": false })),
            _ => Reply::status(404, json!({ "ok": false })),
        }
    }
}

fn invoice_json(id: u64, inv: &Invoice) -> Value {
    json!({
        "id": id,
        "owner": inv.owner,
        "title": inv.title,
        "visibility": if inv.shared { "shared" } else { "private" },
        "status": inv.status,
        "comments": inv.comments.iter().map(|(who, text)| json!({ "by": who, "text": text })).collect::<Vec<_>>(),
    })
}

/// Server-side validation of the G24 forms; returns `field -> reason` for every rejected field.
#[must_use]
pub fn validate_g24(form: &str, fields: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut errors = BTreeMap::new();
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("").trim();
    let mut require = |k: &str| {
        if get(k).is_empty() {
            errors.insert(k.to_owned(), "required".to_owned());
        }
    };
    let rules: &[(&str, &str)] = match form {
        "signup" => &[("email", "email"), ("name", "text"), ("password", "password")],
        "contact" => &[("email", "email"), ("phone", "phone"), ("message", "text")],
        "booking" => &[("date", "date"), ("guests", "number")],
        "profile" => &[("display", "text"), ("plan", "resource")],
        "invoice" => &[("amount", "number"), ("customer", "resource")],
        "search" => &[("q", "text")],
        "attach" => &[("note", "text")],
        "notify" => &[("to", "email"), ("body", "text")],
        _ => &[],
    };
    for (field, _) in rules {
        require(field);
    }
    for (field, class) in rules {
        let v = get(field);
        if v.is_empty() {
            continue;
        }
        let ok = match *class {
            "email" => {
                let (local, domain) = v.split_once('@').unwrap_or(("", ""));
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
            }
            "phone" => {
                let digits = v.chars().filter(char::is_ascii_digit).count();
                (7..=15).contains(&digits) && v.chars().all(|c| c.is_ascii_digit() || "+-() ".contains(c))
            }
            "date" => {
                let parts: Vec<&str> = v.split('-').collect();
                parts.len() == 3
                    && parts[0].len() == 4
                    && parts[1].len() == 2
                    && parts[2].len() == 2
                    && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
                    && (1..=12).contains(&parts[1].parse::<u32>().unwrap_or(0))
                    && (1..=31).contains(&parts[2].parse::<u32>().unwrap_or(0))
            }
            "number" => v
                .parse::<f64>()
                .is_ok_and(|n| n.is_finite() && (0.0..=1_000_000.0).contains(&n)),
            "resource" => matches!(v, "free" | "team" | "enterprise" | "acme" | "globex" | "initech"),
            "password" => v.len() >= 8,
            _ => v.len() <= 2000,
        };
        if !ok {
            errors.insert((*field).to_owned(), format!("invalid_{class}"));
        }
    }
    errors
}

/// `(filename, size)` of every file part of a multipart body; empty when the body is not multipart.
#[must_use]
pub fn multipart_files(content_type: Option<&str>, body: &[u8]) -> Vec<(String, usize)> {
    let Some(ct) = content_type else {
        return Vec::new();
    };
    let Some(boundary) = ct
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))
    else {
        return Vec::new();
    };
    let boundary = boundary.trim_matches('"');
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = find(rest, delim.as_bytes()) {
        rest = &rest[pos + delim.len()..];
        if rest.starts_with(b"--") {
            break;
        }
        let Some(hdr_end) = find(rest, b"\r\n\r\n") else {
            break;
        };
        let headers = String::from_utf8_lossy(&rest[..hdr_end]);
        let part_body = &rest[hdr_end + 4..];
        let end = find(part_body, delim.as_bytes()).unwrap_or(part_body.len());
        let content = &part_body[..end];
        let content_len = content.strip_suffix(b"\r\n").map_or(content.len(), <[u8]>::len);
        if let Some(name) = headers
            .split(';')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("filename="))
        {
            let name = name
                .split("\r\n")
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_owned();
            out.push((name, content_len));
        }
        rest = part_body;
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse a `Cookie` header value into `name -> value`.
#[must_use]
pub fn parse_cookies(header: Option<&str>) -> BTreeMap<String, String> {
    header
        .unwrap_or("")
        .split(';')
        .filter_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::time::SystemClock;
    use std::sync::Arc;

    fn ledger() -> Ledger {
        Ledger::new(Arc::new(SystemClock))
    }

    fn req<'a>(
        fixture: &'a str,
        method: &'a str,
        route: &'a str,
        fields: &'a BTreeMap<String, String>,
        cookies: &'a BTreeMap<String, String>,
        query: &'a BTreeMap<String, String>,
    ) -> Request<'a> {
        Request {
            fixture,
            method,
            route,
            query,
            fields,
            cookies,
            body: &[],
            content_type: None,
        }
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn cookies_of(reply: &Reply) -> BTreeMap<String, String> {
        reply
            .set_cookies
            .iter()
            .filter_map(|c| {
                let (kv, _) = c.split_once(';')?;
                let (k, v) = kv.split_once('=')?;
                Some((k.to_owned(), v.to_owned()))
            })
            .filter(|(_, v)| !v.is_empty())
            .collect()
    }

    #[test]
    fn g18_session_expires_after_three_uses_and_silently_refreshes() {
        let b = Backend::default();
        let l = ledger();
        let empty = BTreeMap::new();
        let login = fields(&[("user", "member"), ("password", PASSWORD), ("mode", "silent")]);
        let r = b
            .handle(&l, &req("g18", "POST", "login", &login, &empty, &empty))
            .unwrap();
        assert_eq!(r.status, 200);
        let cookies = cookies_of(&r);
        assert!(cookies.contains_key("g18_session") && cookies.contains_key("g18_refresh"));
        for _ in 0..G18_SESSION_USES {
            let r = b
                .handle(&l, &req("g18", "GET", "me", &empty, &cookies, &empty))
                .unwrap();
            assert_eq!(r.status, 200);
        }
        let r = b
            .handle(&l, &req("g18", "GET", "me", &empty, &cookies, &empty))
            .unwrap();
        assert_eq!(r.status, 401, "expired after {G18_SESSION_USES} uses");
        let r = b
            .handle(&l, &req("g18", "POST", "refresh", &empty, &cookies, &empty))
            .unwrap();
        assert_eq!(r.status, 200);
        let fresh = cookies_of(&r);
        let r = b
            .handle(&l, &req("g18", "GET", "me", &empty, &fresh, &empty))
            .unwrap();
        assert_eq!(r.status, 200);
        let effects: Vec<String> = l.effects("g18").into_iter().map(|e| e.1).collect();
        assert!(effects.contains(&"session:expired".to_owned()), "{effects:?}");
        assert!(
            effects.contains(&"session:silent_refresh".to_owned()),
            "{effects:?}"
        );
        // hard logout wipes both cookies
        let r = b
            .handle(&l, &req("g18", "POST", "logout", &empty, &fresh, &empty))
            .unwrap();
        assert_eq!(r.set_cookies.len(), 2);
        assert!(r.set_cookies.iter().all(|c| c.contains("Max-Age=0")));
        // the password never reaches the ledger
        assert!(l.entries().iter().all(|e| !format!("{e:?}").contains(PASSWORD)));
    }

    #[test]
    fn g20_matrix_follows_owner_shared_and_admin_rules() {
        let b = Backend::default();
        let l = ledger();
        let empty = BTreeMap::new();
        let as_user = |u: &str| fields(&[("g20_user", u)]);
        let (alice, bob, admin) = (as_user("alice"), as_user("bob"), as_user("admin"));
        // alice's private invoice 1: bob denied everywhere, admin allowed, alice allowed
        let r = b
            .handle(&l, &req("g20", "GET", "invoices/1", &empty, &bob, &empty))
            .unwrap();
        assert_eq!(r.status, 403);
        let r = b
            .handle(&l, &req("g20", "GET", "invoices/1", &empty, &admin, &empty))
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body["context"], "admin");
        // alice's shared invoice 2: bob may view, modify and comment, never delete
        let r = b
            .handle(&l, &req("g20", "GET", "invoices/2", &empty, &bob, &empty))
            .unwrap();
        assert_eq!((r.status, r.body["context"].as_str()), (200, Some("shared")));
        let text = fields(&[("text", "looks fine")]);
        let r = b
            .handle(
                &l,
                &req("g20", "POST", "invoices/2/comments", &text, &bob, &empty),
            )
            .unwrap();
        assert_eq!(r.status, 200);
        let r = b
            .handle(&l, &req("g20", "DELETE", "invoices/2", &empty, &bob, &empty))
            .unwrap();
        assert_eq!(r.status, 403);
        // alice sees bob's comment on her own invoice (round 2 of the shared-workspace protocol)
        let r = b
            .handle(&l, &req("g20", "GET", "invoices/2", &empty, &alice, &empty))
            .unwrap();
        assert_eq!(r.body["invoice"]["comments"][0]["by"], "bob");
        assert_eq!(r.body["context"], "own");
        // anonymous is 401 and listing hides private invoices of others
        let r = b
            .handle(&l, &req("g20", "GET", "invoices/1", &empty, &empty, &empty))
            .unwrap();
        assert_eq!(r.status, 401);
        let r = b
            .handle(&l, &req("g20", "GET", "invoices", &empty, &bob, &empty))
            .unwrap();
        let ids: Vec<u64> = r.body["invoices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, [2, 3, 4]);
        let contexts: BTreeSet<String> = l.effects("g20").into_iter().map(|e| e.3).collect();
        assert!(contexts.contains("other_user_same_role") && contexts.contains("shared"));
    }

    #[test]
    fn g22_same_button_has_twelve_context_dependent_behaviors() {
        let b = Backend::default();
        let l = ledger();
        let empty = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for user in ["alice", "bob", "admin"] {
            let c = fields(&[("g22_user", user)]);
            for item in ["1", "2"] {
                for archived in [false, true] {
                    b.reset();
                    if archived {
                        let owner = fields(&[("g22_user", if item == "1" { "alice" } else { "bob" })]);
                        let route = format!("items/{item}/archive");
                        let r = b
                            .handle(&l, &req("g22", "POST", &route, &empty, &owner, &empty))
                            .unwrap();
                        assert_eq!(r.status, 200);
                    }
                    let route = format!("items/{item}");
                    let _ = b
                        .handle(&l, &req("g22", "DELETE", &route, &empty, &c, &empty))
                        .unwrap();
                    let last = l.effects("g22").pop().unwrap();
                    assert!(last.1.starts_with("delete:"), "{last:?}");
                    seen.insert((last.0, last.2, last.1));
                }
            }
        }
        assert_eq!(seen.len(), 12, "{seen:?}");
        let behaviors: BTreeSet<&str> = seen.iter().map(|(_, _, e)| e.as_str()).collect();
        assert!(behaviors.contains("delete:soft_delete:active"));
        assert!(behaviors.contains("delete:purge:archived"));
        assert!(behaviors.contains("delete:admin_purge:archived"));
        assert!(behaviors.contains("delete:denied:active"));
    }

    #[test]
    fn g17_code_is_single_use() {
        let b = Backend::default();
        let l = ledger();
        let empty = BTreeMap::new();
        let allow = fields(&[("decision", "allow"), ("user", "alice")]);
        let r = b
            .handle(&l, &req("g17", "POST", "oauth/authorize", &allow, &empty, &empty))
            .unwrap();
        let code = r.body["code"].as_str().unwrap().to_owned();
        let ex = fields(&[("code", &code)]);
        let r = b
            .handle(&l, &req("g17", "POST", "oauth/token", &ex, &empty, &empty))
            .unwrap();
        assert_eq!(r.status, 200);
        let r = b
            .handle(&l, &req("g17", "POST", "oauth/token", &ex, &empty, &empty))
            .unwrap();
        assert_eq!(r.status, 400);
        let deny = fields(&[("decision", "deny")]);
        let r = b
            .handle(&l, &req("g17", "POST", "oauth/authorize", &deny, &empty, &empty))
            .unwrap();
        assert_eq!(r.body["error"], "access_denied");
    }

    #[test]
    fn g24_validation_rejects_bad_classes_and_accepts_good_ones() {
        let good = fields(&[
            ("email", "a@b.test"),
            ("phone", "+1 555 0100 200"),
            ("message", "hi"),
        ]);
        assert!(validate_g24("contact", &good).is_empty());
        let bad = fields(&[("email", "nope"), ("phone", "12"), ("message", "")]);
        let errs = validate_g24("contact", &bad);
        assert_eq!(errs["email"], "invalid_email");
        assert_eq!(errs["phone"], "invalid_phone");
        assert_eq!(errs["message"], "required");
        let booking = fields(&[("date", "2026-13-01"), ("guests", "-1")]);
        let errs = validate_g24("booking", &booking);
        assert_eq!(errs["date"], "invalid_date");
        assert_eq!(errs["guests"], "invalid_number");
        let profile = fields(&[("display", "Ann"), ("plan", "gold")]);
        assert_eq!(validate_g24("profile", &profile)["plan"], "invalid_resource");
    }

    #[test]
    fn multipart_parser_reports_file_names_and_sizes() {
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"small.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n1234\r\n--XX--\r\n";
        let parts = multipart_files(Some("multipart/form-data; boundary=XX"), body);
        assert_eq!(parts, vec![("small.png".to_owned(), 12)]);
        assert!(multipart_files(Some("application/json"), body).is_empty());
        let b = Backend::default();
        let l = ledger();
        let empty = BTreeMap::new();
        let r = b
            .handle(
                &l,
                &Request {
                    fixture: "g16",
                    method: "POST",
                    route: "upload/image",
                    query: &empty,
                    fields: &empty,
                    cookies: &empty,
                    body,
                    content_type: Some("multipart/form-data; boundary=XX"),
                },
            )
            .unwrap();
        assert_eq!(r.status, 200, "{:?}", r.body);
        let big = format!(
            "--XX\r\nContent-Disposition: form-data; name=\"file\"; filename=\"huge.png\"\r\n\r\n{}\r\n--XX--\r\n",
            "x".repeat(G16_MAX_UPLOAD_BYTES + 1)
        );
        let r = b
            .handle(
                &l,
                &Request {
                    fixture: "g16",
                    method: "POST",
                    route: "upload/oversize",
                    query: &empty,
                    fields: &empty,
                    cookies: &empty,
                    body: big.as_bytes(),
                    content_type: Some("multipart/form-data; boundary=XX"),
                },
            )
            .unwrap();
        assert_eq!(r.status, 413);
        assert_eq!(r.body["rejected"][0]["reason"], "rejected_oversize");
    }

    #[test]
    fn cookies_parse_and_pushes_are_per_fixture() {
        let c = parse_cookies(Some("a=1; g18_session=s7 ;x"));
        assert_eq!(c.get("g18_session").map(String::as_str), Some("s7"));
        assert_eq!(c.len(), 2);
        assert_eq!(ws_pushes("g09").len(), 6);
        assert_eq!(ws_pushes("g01").len(), 0);
        assert_eq!(ws_reply("g09", "open-a").unwrap()["reply"], "a-reply");
        assert!(ws_reply("g09", "nope").is_none());
    }
}
