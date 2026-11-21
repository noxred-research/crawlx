//! Names of the properties a page's scripts added to `window` ([`ObservationBundle::js_globals`]).
//!
//! The page's main world and a freshly created isolated world of the same frame both start from
//! the browser's own global object (every built-in, DOM interface and API), but only the main
//! world sees what the page's scripts defined. The difference of their own property names is
//! therefore "own, non-native `window` properties" without wrapping, hooking or mutating anything
//! in the page: the expression reads names with `Object.getOwnPropertyNames`, which runs no getter
//! and returns no value. A name must look like an identifier and be at most
//! [`MAX_JS_GLOBAL_NAME_BYTES`] bytes (a longer or odd name is dropped, never truncated); the
//! script returns at most [`RAW_NAME_CAP`] of them and the result keeps at most [`MAX_JS_GLOBALS`].
//! The crawler's own hook functions (`__crawlx…`) are not page properties and are removed.
//!
//! [`ObservationBundle::js_globals`]: crawlx_core::observation::ObservationBundle::js_globals

use crawlx_core::observation::{MAX_JS_GLOBALS, MAX_JS_GLOBAL_NAME_BYTES};
use serde_json::Value;
use std::collections::BTreeSet;

/// Upper bound on the names either world returns.
pub const RAW_NAME_CAP: usize = 8192;

/// Prefix of the crawler's own main-world functions.
const OWN_PREFIX: &str = "__crawlx";

/// Evaluated in the main world and in the isolated world: identifier-shaped own property names
/// of `window`, bounded in count and length. Reads no value.
pub const NAMES_EXPRESSION: &str = r"(function crawlxGlobalNames() {
  try {
    var names = Object.getOwnPropertyNames(window);
    var out = [];
    for (var i = 0; i < names.length && out.length < 8192; i++) {
      var n = names[i];
      if (typeof n === 'string' && n.length <= 64 && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(n)) { out.push(n); }
    }
    return out;
  } catch (_) { return []; }
})()";

/// The string items of a `Runtime.evaluate` array result; anything else yields nothing.
#[must_use]
pub fn names_of(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(RAW_NAME_CAP)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Is `name` a plausible page global: identifier-shaped, within the length cap?
fn plausible(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_JS_GLOBAL_NAME_BYTES
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

/// The names of `main` that `pristine` lacks, sorted and deduplicated, at most
/// [`MAX_JS_GLOBALS`]. The result never holds a name the page did not define itself.
#[must_use]
pub fn page_defined(main: &[String], pristine: &[String]) -> Vec<String> {
    let native: BTreeSet<&str> = pristine.iter().map(String::as_str).collect();
    let mut out: BTreeSet<&str> = main
        .iter()
        .map(String::as_str)
        .filter(|name| plausible(name) && !name.starts_with(OWN_PREFIX) && !native.contains(name))
        .collect();
    while out.len() > MAX_JS_GLOBALS {
        out.pop_last();
    }
    out.into_iter().map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn only_names_the_pristine_global_lacks_are_reported_sorted_and_deduplicated() {
        let pristine = strings(&["document", "fetch", "location", "Array"]);
        let main = strings(&[
            "document",
            "jQuery",
            "fetch",
            "__NEXT_DATA__",
            "location",
            "jQuery",
            "__crawlxDrainDiscovery",
            "Array",
            "dataLayer",
        ]);
        assert_eq!(
            page_defined(&main, &pristine),
            ["__NEXT_DATA__", "dataLayer", "jQuery"]
        );
    }

    #[test]
    fn odd_or_long_names_are_dropped_never_truncated() {
        let long = "a".repeat(MAX_JS_GLOBAL_NAME_BYTES + 1);
        let fits = "b".repeat(MAX_JS_GLOBAL_NAME_BYTES);
        let main = vec![
            long,
            fits.clone(),
            "0".to_owned(),
            "a-b".to_owned(),
            "a b".to_owned(),
            String::new(),
            "ok$_1".to_owned(),
        ];
        assert_eq!(page_defined(&main, &[]), [fits, "ok$_1".to_owned()]);
    }

    #[test]
    fn the_count_is_capped() {
        let main: Vec<String> = (0..MAX_JS_GLOBALS + 50).map(|i| format!("g{i:05}")).collect();
        let got = page_defined(&main, &[]);
        assert_eq!(got.len(), MAX_JS_GLOBALS);
        assert_eq!(got[0], "g00000");
    }

    #[test]
    fn a_result_that_is_not_an_array_of_strings_yields_nothing() {
        assert!(names_of(&Value::Null).is_empty());
        assert!(names_of(&serde_json::json!({"a": 1})).is_empty());
        assert_eq!(names_of(&serde_json::json!(["a", 1, null, "b"])), ["a", "b"]);
    }
}
