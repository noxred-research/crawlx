//! Source gate of the request surface: engines without row-level security stay isolated only
//! because every statement of these modules runs under the tenant scope, so the modules may
//! name no raw `sqlx` query function and every function that builds a statement must resolve
//! the scope (`scope()`), demand operator authority (`require_operator()`) or be one of the
//! reviewed helpers that always run inside a caller that did.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// The request-surface modules.
const FILES: &[&str] = &[
    "src/repos/api.rs",
    "src/repos/authorization.rs",
    "src/repos/intel.rs",
    "src/repos/inspect.rs",
    "src/trusted.rs",
    "src/trail.rs",
    "src/approvals.rs",
];

/// Helpers that build a statement but are only called from inside a function that resolved the
/// scope (or that act for an operator by design).
const REVIEWED: &[&str] = &[
    // runs inside a transaction of a caller that resolved the scope
    "approval_in_transaction",
    "ensure_tenant_on",
    // the pre-authentication lookup is the one statement that carries no tenant
    "key_by_prefix",
    // approvals act for the tenant their lease names; `approval_scope` checks it first
    "lock_authority",
    "lock_request",
    "check_action",
    // a clock read
    "scalar_i64",
    // intel: `require_owned` is called with the caller's scope
    "require_owned",
    // webhook rows are read back by id inside a scoped call
    "delivery_from_row",
];

const FORBIDDEN: &[&str] = &["sqlx::query", "sqlx::raw_sql", "query_as(", "query_scalar("];

fn source(path: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

/// `(name, body)` of every function in `text`.
fn functions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(found) = text[at..].find("fn ") {
        let start = at + found;
        at = start + 3;
        let before = text[..start].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let name: String = text[start + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(open) = text[start..].find('{').map(|i| start + i) else {
            continue;
        };
        // a signature ends at its first `{` or `;`
        if text[start..open].contains(';') {
            continue;
        }
        let mut depth = 0_usize;
        let mut end = open;
        for (offset, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((name, text[open..=end].to_owned()));
        at = end;
    }
    out
}

#[test]
fn request_surface_modules_use_no_raw_sqlx_queries() {
    for file in FILES {
        let text = source(file);
        let code: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for token in FORBIDDEN {
            assert!(
                !code.contains(token),
                "{file} names `{token}`: request-surface statements go through the scoped statement layer"
            );
        }
    }
}

#[test]
fn every_request_surface_statement_resolves_the_tenant_scope() {
    for file in FILES {
        let text = source(file);
        let tests_at = text.find("#[cfg(test)]").unwrap_or(text.len());
        for (name, body) in functions(&text[..tests_at]) {
            let builds = body.contains("Stmt::<B>::dynamic(") || body.contains("stmt!(");
            if !builds || REVIEWED.contains(&name.as_str()) {
                continue;
            }
            assert!(
                body.contains("scope()")
                    || body.contains("require_operator()")
                    || body.contains("approval_scope(")
                    || body.contains("self.store.scope")
                    || body.contains("owned_privacy_scope"),
                "{file}: `{name}` builds a statement without resolving the tenant scope"
            );
        }
    }
}

#[test]
fn the_guard_is_present() {
    let tenant = source("src/tenant.rs");
    assert!(
        tenant.contains("fn scope(&self)"),
        "the request scope resolver is gone"
    );
    assert!(
        tenant.contains("tenant scope required"),
        "the fail-closed message is gone"
    );
}

/// Functions that may build a [`ScopedQuery`] without a resolved `Scope` of their own: they
/// run inside a caller that resolved it (`within_scope`) or are the pre-authentication lookup.
const WITHIN_SCOPE: &[&str] = &[
    "approval_in_transaction",
    "ensure_tenant_on",
    "lock_authority",
    "lock_request",
    "check_action",
];
const PRE_AUTHENTICATION: &[&str] = &["key_by_prefix"];

#[test]
fn the_reviewed_entry_points_stay_in_the_reviewed_functions() {
    for file in FILES {
        let text = source(file);
        let tests_at = text.find("#[cfg(test)]").unwrap_or(text.len());
        for (name, body) in functions(&text[..tests_at]) {
            if body.contains("ScopedQuery::within_scope(") {
                assert!(
                    WITHIN_SCOPE.contains(&name.as_str()),
                    "{file}: `{name}` uses `within_scope` but is not a reviewed in-transaction helper"
                );
            }
            if body.contains("ScopedQuery::pre_authentication(") {
                assert!(
                    PRE_AUTHENTICATION.contains(&name.as_str()),
                    "{file}: `{name}` uses `pre_authentication` but is not the key lookup"
                );
            }
        }
    }
}

#[test]
fn every_request_surface_module_denies_the_raw_statement_entry_points() {
    for file in FILES {
        assert!(
            source(file).contains("#![deny(clippy::disallowed_methods)]"),
            "{file} must deny clippy::disallowed_methods so only ScopedQuery runs statements"
        );
    }
    let config = source("clippy.toml");
    for path in [
        "crawlx_storage::sql::Stmt::execute",
        "crawlx_storage::sql::Stmt::execute_write",
        "crawlx_storage::sql::Stmt::fetch_all",
        "crawlx_storage::sql::Stmt::fetch_all_pool",
        "crawlx_storage::sql::Stmt::fetch_one",
        "crawlx_storage::sql::Stmt::fetch_one_pool",
        "crawlx_storage::sql::Stmt::fetch_optional",
        "crawlx_storage::sql::Stmt::fetch_optional_pool",
        "crawlx_storage::sql::Stmt::fetch_optional_write",
        "crawlx_storage::sql::Stmt::matched",
        "crawlx_storage::sql::Stmt::matched_write",
    ] {
        assert!(
            config.contains(&format!("path = \"{path}\"")),
            "clippy.toml no longer disallows `{path}`"
        );
    }
}

#[test]
fn the_mutation_feature_cannot_reach_a_release_build() {
    let lib = source("src/lib.rs");
    assert!(
        lib.contains("#[cfg(all(feature = \"unscoped-for-test\", not(debug_assertions)))]")
            && lib.contains("compile_error!("),
        "`unscoped-for-test` must be a compile error without debug assertions"
    );
}
