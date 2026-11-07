//! Query-parameter classification.
//!
//! Precedence, first match wins: per-crawl override (`name` or
//! `route_template:name`, case-insensitive name), built-in lists
//! (`query_classifier_v1`), the observed-value entropy heuristic fed by
//! [`ParamClassifier::observe`], and finally the default `Filter` (kept).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::url::{ParamClass, RouteTemplate};
use parking_lot::RwLock;

/// Minimum value length for the session-token entropy heuristic.
pub const SESSION_MIN_LEN: usize = 16;
/// Minimum Shannon entropy (bits per character) for the session-token heuristic.
pub const SESSION_MIN_ENTROPY: f64 = 3.5;
/// Sessions required before a high-entropy parameter is classified `Session`.
pub const SESSION_MIN_SESSIONS: usize = 2;

const MAX_TRACKED_NAMES: usize = 4096;
const MAX_SESSIONS_PER_NAME: usize = 16;
const MAX_VALUES_PER_SESSION: usize = 16;
const MAX_ENUM_LITERAL: usize = 16;

/// One parameter occurrence to classify.
#[derive(Clone, Copy, Debug)]
pub struct ParamObservation<'a> {
    /// Route template of the URL carrying the parameter.
    pub route: &'a RouteTemplate,
    /// Decoded parameter name (any case).
    pub name: &'a str,
    /// Decoded parameter value.
    pub value: &'a str,
}

#[derive(Default, Debug)]
struct NameStats {
    /// High-entropy values per session id.
    sessions: BTreeMap<u64, BTreeSet<String>>,
    /// Any value that was not token-like was seen (disqualifies `Session`).
    saw_low_entropy: bool,
}

impl NameStats {
    fn looks_like_session_token(&self) -> bool {
        if self.saw_low_entropy || self.sessions.len() < SESSION_MIN_SESSIONS {
            return false;
        }
        // The same link must have yielded different values: no value may be
        // common to every session. UUIDs that are stable stay resource ids.
        let mut sets = self.sessions.values();
        let Some(first) = sets.next() else { return false };
        let mut common: BTreeSet<&String> = first.iter().collect();
        for s in sets {
            common.retain(|v| s.contains(*v));
        }
        common.is_empty()
    }
}

/// Classifies query parameters; shareable across threads (`observe` uses
/// interior mutability).
#[derive(Debug, Default)]
pub struct ParamClassifier {
    by_name: BTreeMap<String, ParamClass>,
    by_route: BTreeMap<(String, String), ParamClass>,
    stats: RwLock<BTreeMap<String, NameStats>>,
}

impl ParamClassifier {
    /// Build a classifier with per-crawl overrides. Keys are either a
    /// parameter name or `"/route/:id:name"` (route-scoped); names are
    /// compared case-insensitively.
    #[must_use]
    pub fn new(overrides: &BTreeMap<String, ParamClass>) -> Self {
        let mut by_name = BTreeMap::new();
        let mut by_route = BTreeMap::new();
        for (k, class) in overrides {
            match k.strip_prefix('/').and_then(|_| k.rsplit_once(':')) {
                Some((route, name)) if !name.is_empty() => {
                    by_route.insert((route.to_owned(), name.to_ascii_lowercase()), *class);
                }
                _ => {
                    by_name.insert(k.to_ascii_lowercase(), *class);
                }
            }
        }
        Self {
            by_name,
            by_route,
            stats: RwLock::new(BTreeMap::new()),
        }
    }

    /// Record a value seen for `name` in crawl session `session`. High-entropy
    /// values that differ across at least two sessions turn the parameter
    /// into `Session` (single-session evidence never drops a
    /// parameter).
    pub fn observe(&self, name: &str, value: &str, session: u64) {
        let key = name.to_ascii_lowercase();
        let token_like = is_token_like(value);
        let mut stats = self.stats.write();
        if !stats.contains_key(&key) && stats.len() >= MAX_TRACKED_NAMES {
            return;
        }
        let entry = stats.entry(key).or_default();
        if !token_like {
            entry.saw_low_entropy = true;
            return;
        }
        if !entry.sessions.contains_key(&session) && entry.sessions.len() >= MAX_SESSIONS_PER_NAME {
            return;
        }
        let values = entry.sessions.entry(session).or_default();
        if values.len() < MAX_VALUES_PER_SESSION {
            values.insert(value.to_owned());
        }
    }

    /// Classify one parameter.
    #[must_use]
    pub fn classify(&self, obs: &ParamObservation<'_>) -> ParamClass {
        let lower = lowercase(obs.name);
        if let Some(c) = self.override_for(obs.route, &lower) {
            return c;
        }
        if let Some(c) = builtin_class(&lower, obs.name, obs.value) {
            return c;
        }
        if self.learned_session(&lower) {
            return ParamClass::Session;
        }
        ParamClass::Filter
    }

    /// Per-crawl override for `lower_name` on `route`, if any.
    #[must_use]
    pub fn override_for(&self, route: &RouteTemplate, lower_name: &str) -> Option<ParamClass> {
        if !self.by_route.is_empty() {
            if let Some(c) = self.by_route.get(&(route.0.clone(), lower_name.to_owned())) {
                return Some(*c);
            }
        }
        self.by_name.get(lower_name).copied()
    }

    fn learned_session(&self, lower_name: &str) -> bool {
        let stats = self.stats.read();
        stats
            .get(lower_name)
            .is_some_and(NameStats::looks_like_session_token)
    }

    /// Does this classifier carry any state that can change classification
    /// beyond the built-in lists?
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.by_name.is_empty() && self.by_route.is_empty() && self.stats.read().is_empty()
    }
}

fn lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

/// Built-in lists (`query_classifier_v1`). `lower` is the lowercased name,
/// `original` keeps case for the camel-case `*Id` rule.
#[must_use]
pub fn builtin_class(lower: &str, original: &str, value: &str) -> Option<ParamClass> {
    if is_tracking(lower) {
        return Some(ParamClass::Tracking);
    }
    if is_session(lower) {
        return Some(ParamClass::Session);
    }
    if is_action(lower) {
        return Some(ParamClass::ActionBearing);
    }
    if is_navigation(lower) {
        return Some(ParamClass::Navigation);
    }
    if is_filter(lower) {
        return Some(ParamClass::Filter);
    }
    if is_resource_id(lower, original, value) {
        return Some(ParamClass::ResourceId);
    }
    None
}

fn is_tracking(n: &str) -> bool {
    n.starts_with("utm_")
        || n.starts_with("hsa_")
        || matches!(
            n,
            "gclid"
                | "gbraid"
                | "wbraid"
                | "fbclid"
                | "msclkid"
                | "dclid"
                | "yclid"
                | "mc_cid"
                | "mc_eid"
                | "_ga"
                | "_gl"
                | "igshid"
                | "_hsenc"
                | "_hsmi"
                | "cmpid"
                | "ref_src"
        )
}

fn is_session(n: &str) -> bool {
    n.starts_with("csrf")
        || n.starts_with("xsrf")
        || n.starts_with("x-amz-")
        || matches!(
            n,
            "sessionid"
                | "session_id"
                | "sid"
                | "phpsessid"
                | "jsessionid"
                | "sessid"
                | "token"
                | "access_token"
                | "id_token"
                | "refresh_token"
                | "api_key"
                | "apikey"
                | "auth"
                | "nonce"
                | "sig"
                | "signature"
                | "_csrf"
                | "authenticity_token"
                | "expires"
        )
}

fn is_action(n: &str) -> bool {
    matches!(
        n,
        "action"
            | "do"
            | "cmd"
            | "command"
            | "op"
            | "operation"
            | "method"
            | "_method"
            | "delete"
            | "remove"
            | "logout"
            | "signout"
            | "confirm"
            | "submit"
    )
}

fn is_navigation(n: &str) -> bool {
    matches!(
        n,
        "page"
            | "p"
            | "pg"
            | "offset"
            | "limit"
            | "per_page"
            | "page_size"
            | "cursor"
            | "after"
            | "before"
            | "start"
            | "tab"
            | "step"
    )
}

fn is_filter(n: &str) -> bool {
    n.starts_with("filter")
        || matches!(
            n,
            "q" | "query"
                | "search"
                | "s"
                | "sort"
                | "order"
                | "orderby"
                | "dir"
                | "category"
                | "cat"
                | "tag"
                | "lang"
                | "year"
                | "month"
                | "from"
                | "to"
                | "status"
        )
}

fn is_resource_id(lower: &str, original: &str, value: &str) -> bool {
    if matches!(lower, "id" | "uid" | "uuid" | "guid" | "pk" | "slug" | "sku") {
        return true;
    }
    if lower.len() > 3 && lower.ends_with("_id") {
        return true;
    }
    if original.len() > 2 && original.ends_with("Id") {
        return true;
    }
    lower == "key" && looks_like_id(value)
}

/// Does `v` look like an object identifier (integer, UUID, ULID, long hex)?
#[must_use]
pub fn looks_like_id(v: &str) -> bool {
    let n = v.len();
    if n == 0 || n > 64 {
        return false;
    }
    let b = v.as_bytes();
    if b.iter().all(u8::is_ascii_digit) {
        return true;
    }
    if is_uuid(b) {
        return true;
    }
    if n == 26
        && b.iter().all(|c| {
            c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'L' | b'O' | b'U'))
        })
    {
        return true;
    }
    n >= 8 && b.iter().all(u8::is_ascii_hexdigit) && b.iter().any(u8::is_ascii_digit)
}

/// `8-4-4-4-12` hex UUID shape.
#[must_use]
pub fn is_uuid(b: &[u8]) -> bool {
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Shannon entropy of `s` in bits per character.
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts: BTreeMap<char, u32> = BTreeMap::new();
    let mut total = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let t = f64::from(total);
    counts
        .values()
        .map(|&n| {
            let p = f64::from(n) / t;
            -p * p.log2()
        })
        .sum()
}

fn is_token_like(v: &str) -> bool {
    v.chars().count() >= SESSION_MIN_LEN && shannon_entropy(v) >= SESSION_MIN_ENTROPY
}

/// Deterministic bucket for a `Filter` value: `empty`, `num`, `bool`, a short
/// lowercase enum-like literal, or `str`. Stable across processes.
#[must_use]
pub fn bucket_value(v: &str) -> String {
    if v.is_empty() {
        return "empty".to_owned();
    }
    if v.bytes().all(|b| b.is_ascii_digit()) {
        return "num".to_owned();
    }
    let lower = v.to_ascii_lowercase();
    if matches!(lower.as_str(), "true" | "false" | "yes" | "no" | "on" | "off") {
        return "bool".to_owned();
    }
    if v.len() <= MAX_ENUM_LITERAL
        && v.bytes()
            .all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_')
    {
        return lower;
    }
    "str".to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn route() -> RouteTemplate {
        RouteTemplate("/x".into())
    }

    fn class(c: &ParamClassifier, name: &str, value: &str) -> ParamClass {
        c.classify(&ParamObservation {
            route: &route(),
            name,
            value,
        })
    }

    #[test]
    fn builtin_table() {
        let c = ParamClassifier::default();
        let table: &[(&str, &str, ParamClass)] = &[
            ("utm_source", "email", ParamClass::Tracking),
            ("UTM_Campaign", "x", ParamClass::Tracking),
            ("gclid", "abc", ParamClass::Tracking),
            ("fbclid", "abc", ParamClass::Tracking),
            ("msclkid", "abc", ParamClass::Tracking),
            ("mc_cid", "abc", ParamClass::Tracking),
            ("ref_src", "twsrc", ParamClass::Tracking),
            ("igshid", "q", ParamClass::Tracking),
            ("_ga", "1.2.3", ParamClass::Tracking),
            ("sessionid", "abc", ParamClass::Session),
            ("PHPSESSID", "abc", ParamClass::Session),
            ("jsessionid", "abc", ParamClass::Session),
            ("sid", "1", ParamClass::Session),
            ("token", "t", ParamClass::Session),
            ("auth", "a", ParamClass::Session),
            ("csrf_token", "a", ParamClass::Session),
            ("session_id", "5", ParamClass::Session),
            ("page", "2", ParamClass::Navigation),
            ("offset", "20", ParamClass::Navigation),
            ("cursor", "abc", ParamClass::Navigation),
            ("p", "3", ParamClass::Navigation),
            ("start", "10", ParamClass::Navigation),
            ("action", "delete", ParamClass::ActionBearing),
            ("do", "x", ParamClass::ActionBearing),
            ("cmd", "x", ParamClass::ActionBearing),
            ("op", "x", ParamClass::ActionBearing),
            ("method", "x", ParamClass::ActionBearing),
            ("id", "8472", ParamClass::ResourceId),
            ("user_id", "7", ParamClass::ResourceId),
            ("userId", "7", ParamClass::ResourceId),
            ("uid", "7", ParamClass::ResourceId),
            ("pk", "7", ParamClass::ResourceId),
            ("key", "8472", ParamClass::ResourceId),
            ("key", "my-api-docs", ParamClass::Filter),
            ("sort", "price", ParamClass::Filter),
            ("q", "shoes", ParamClass::Filter),
            ("ref", "home", ParamClass::Filter),
            ("state", "ca", ParamClass::Filter),
            ("whatever", "zzz", ParamClass::Filter),
        ];
        for (n, v, want) in table {
            assert_eq!(class(&c, n, v), *want, "{n}={v}");
        }
    }

    #[test]
    fn overrides_win_and_are_case_insensitive() {
        let mut o = BTreeMap::new();
        o.insert("ID".to_owned(), ParamClass::Filter);
        o.insert("ref".to_owned(), ParamClass::Tracking);
        o.insert("/invoice/:id:page".to_owned(), ParamClass::Filter);
        let c = ParamClassifier::new(&o);
        assert_eq!(class(&c, "id", "5"), ParamClass::Filter);
        assert_eq!(class(&c, "Ref", "5"), ParamClass::Tracking);
        // override applies to the named parameter only
        assert_eq!(class(&c, "user_id", "5"), ParamClass::ResourceId);
        let inv = RouteTemplate("/invoice/:id".into());
        let on = |r: &RouteTemplate| {
            c.classify(&ParamObservation {
                route: r,
                name: "page",
                value: "2",
            })
        };
        assert_eq!(on(&inv), ParamClass::Filter);
        assert_eq!(on(&route()), ParamClass::Navigation);
    }

    #[test]
    fn session_heuristic_needs_two_sessions_and_variation() {
        let c = ParamClassifier::default();
        let t1 = "Zk3pQ9xV7mR2tB8wL4nH";
        let t2 = "aF6yJ1cE5uD0sG9oX3iM";
        c.observe("blob", t1, 1);
        assert_eq!(
            class(&c, "blob", t1),
            ParamClass::Filter,
            "single session never drops"
        );
        c.observe("blob", t1, 2);
        assert_eq!(
            class(&c, "blob", t1),
            ParamClass::Filter,
            "stable across sessions is not a session token"
        );
        c.observe("blob", t2, 2);
        c.observe("other", t1, 1);
        c.observe("other", t2, 2);
        assert_eq!(class(&c, "other", t1), ParamClass::Session);
        // a short value ever seen disqualifies
        c.observe("other", "x", 3);
        assert_eq!(class(&c, "other", t1), ParamClass::Filter);
    }

    #[test]
    fn builtin_beats_heuristic() {
        let c = ParamClassifier::default();
        let (t1, t2) = ("Zk3pQ9xV7mR2tB8wL4nH", "aF6yJ1cE5uD0sG9oX3iM");
        c.observe("page", t1, 1);
        c.observe("page", t2, 2);
        assert_eq!(class(&c, "page", "1"), ParamClass::Navigation);
    }

    #[test]
    fn buckets() {
        assert_eq!(bucket_value(""), "empty");
        assert_eq!(bucket_value("123"), "num");
        assert_eq!(bucket_value("TRUE"), "bool");
        assert_eq!(bucket_value("Price"), "price");
        assert_eq!(bucket_value("hello world 2"), "str");
        assert_eq!(bucket_value("abc123"), "str");
    }

    #[test]
    fn entropy() {
        assert!(shannon_entropy("aaaa") < 0.01);
        assert!(shannon_entropy("Zk3pQ9xV7mR2tB8wL4nH") > 3.5);
    }
}
