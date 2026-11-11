//! The condition language's function set against the pinned reference DSL.
//!
//! `VECTORS` holds expressions with the value the reference function library (release v0.8.21,
//! the one the pinned reference tool selects) returned for them when this table was produced; each
//! row is evaluated here through the public [`Dsl`] API. `Absent` rows are the ones where the
//! reference returned an error or panicked: the condition must then be false, whatever it compares
//! the call with. `REFERENCE_FUNCTIONS` is the function set of that release (without its one
//! technology-detector function, which names a third-party product and stays an unknown name here),
//! and every name in it must be either supported or listed as unsupported with a reason.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_worker::output::dsl::{
    supported_functions, Dsl, DslError, MAX_LIST_LEN, MAX_VALUE_LEN, UNSUPPORTED_FUNCTIONS,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// What the reference returned.
enum Want {
    Str(&'static str),
    Num(f64),
    Bool(bool),
    List(&'static [&'static str]),
    /// An error or a panic: no value.
    Absent,
}
use Want::{Absent, Bool, List, Num, Str};

/// The variables the vectors read, as in the reference run.
fn record() -> Value {
    json!({
        "body": "Hello, World! héllo",
        "code": 200,
        "words": "alpha beta gamma",
        "multi": "a\nb\nc",
    })
}

/// A DSL string literal holding `text`.
fn literal(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn holds(source: &str) -> bool {
    Dsl::parse(source)
        .unwrap_or_else(|e| panic!("{source}: {e}"))
        .eval_value(&record())
}

/// Rows where the reference rejects the call at run time and this language already at parse time:
/// a wrong argument count, or a literal regex pattern that does not compile.
const REFUSED_AT_PARSE: [&str; 4] = [
    r##"equals_any("a")"##,
    "starts_with(words)",
    r##"replace_regex("abc", "(", "x")"##,
    r##"regex_any("(", "ab")"##,
];

const VECTORS: &[(&str, Want)] = &[
    (r##"index("hello", 1)"##, Str("e")),
    (r##"index("hello", 0)"##, Str("h")),
    (r##"index("hello", 5)"##, Absent),
    (r##"index("hello", -1)"##, Absent),
    (r##"index("héllo", 1)"##, Str("Ã")),
    (r##"reverse("hello")"##, Str("olleh")),
    (r##"reverse("héllo")"##, Str("olléh")),
    (r##"reverse("")"##, Str("")),
    (r##"repeat("ab", 3)"##, Str("ababab")),
    (r##"repeat("ab", 0)"##, Str("")),
    (r##"repeat("ab", -1)"##, Absent),
    (r##"repeat("", 5)"##, Str("")),
    (r##"replace("a-b-c", "-", "+")"##, Str("a+b+c")),
    (r##"replace("aaa", "a", "bb")"##, Str("bbbbbb")),
    (r##"replace("abc", "", "-")"##, Str("-a-b-c-")),
    (r##"replace("héllo", "", "-")"##, Str("-h-é-l-l-o-")),
    (r##"replace("abc", "x", "y")"##, Str("abc")),
    (r##"replace_regex("abc123def45", "[0-9]+", "#")"##, Str("abc#def#")),
    (r##"replace_regex("abc123", "([a-z]+)([0-9]+)", "$2$1")"##, Str("123abc")),
    (r##"replace_regex("abc", "x*", "-")"##, Str("-a-b-c-")),
    (r##"replace_regex("a.b", "\\.", "$$")"##, Str("a$b")),
    (r##"replace_regex("abc", "(", "x")"##, Absent),
    (r##"concat("a", 1, true, "b")"##, Str("a1trueb")),
    (r##"concat()"##, Str("")),
    (r##"concat("x")"##, Str("x")),
    (r##"join(",", "a", "b", "c")"##, Str("a,b,c")),
    (r##"join("-", split("a,b,c", ","))"##, Str("a-b-c")),
    (r##"join(",", split("a,b,c", ","), "d")"##, Absent),
    (r##"join(",", "a")"##, Absent),
    (r##"split("a,b,c", ",")"##, List(&["a", "b", "c"])),
    (r##"split("a,b,c", ",", 2)"##, List(&["a", "b,c"])),
    (r##"split("abcdef", 4)"##, List(&["abcd", "ef"])),
    (r##"split("abcdef", 2)"##, List(&["ab", "cd", "ef"])),
    (r##"split("héllo", 2)"##, List(&["hé", "ll", "o"])),
    (r##"split("abc", "")"##, List(&["a", "b", "c"])),
    (r##"split("a,b", ",", 0)"##, List(&[])),
    (r##"split("a,b,c", ",", -1)"##, List(&["a", "b", "c"])),
    (r##"substr("hello", 1)"##, Str("ello")),
    (r##"substr("hello", 1, 3)"##, Str("el")),
    (r##"substr("hello", 5)"##, Str("")),
    (r##"substr("hello", 6)"##, Absent),
    (r##"substr("hello", 3, 2)"##, Absent),
    (r##"substr("hello", 0, 9)"##, Absent),
    (r##"substr("", 0)"##, Absent),
    (r##"substr("hello", -1)"##, Absent),
    (r##"substr("héllo", 1, 2)"##, Str("\u{fffd}")),
    (r##"count("banana", "a")"##, Num(3.0)),
    (r##"count("banana", "")"##, Num(7.0)),
    (r##"count("banana", "na")"##, Num(2.0)),
    (r##"count("", "x")"##, Num(0.0)),
    (r##"regex_all("[0-9]+", "12", "34")"##, Bool(true)),
    (r##"regex_all("[0-9]+", "12", "ab")"##, Bool(false)),
    (r##"regex_any("[0-9]+", "ab", "34")"##, Bool(true)),
    (r##"regex_any("[0-9]+", "ab")"##, Bool(false)),
    (r##"regex_any("(", "ab")"##, Absent),
    (r##"equals_any("a", "b", "a")"##, Bool(true)),
    (r##"equals_any("a", "b")"##, Bool(false)),
    (r##"equals_any(1, "1")"##, Bool(true)),
    (r##"remove_bad_chars("he-l_lo", "-_")"##, Str("hello")),
    (r##"remove_bad_chars("hello", "")"##, Str("hello")),
    (r##"remove_bad_chars("héllo", "é")"##, Str("hllo")),
    (r##"to_string(1)"##, Str("1")),
    (r##"to_string(1.5)"##, Str("1.5")),
    (r##"to_string(true)"##, Str("true")),
    (r##"to_string("x")"##, Str("x")),
    (r##"to_string(100000000000000000000)"##, Str("100000000000000000000")),
    (r##"to_number("12")"##, Num(12.0)),
    (r##"to_number("-12")"##, Num(-12.0)),
    (r##"to_number("1.5")"##, Num(1.5)),
    (r##"to_number("abc")"##, Absent),
    (r##"to_number("012")"##, Num(12.0)),
    (r##"to_number("1e3")"##, Num(1000.0)),
    (r##"to_number("")"##, Absent),
    (r##"to_number(" 1")"##, Absent),
    (r##"base64("hello")"##, Str("aGVsbG8=")),
    (r##"base64("")"##, Str("")),
    (r##"base64("héllo")"##, Str("aMOpbGxv")),
    (r##"base64_decode("aGVsbG8=")"##, Str("hello")),
    (r##"base64_decode("aGVsbG8")"##, Absent),
    (r##"base64_decode("!!!")"##, Absent),
    (r##"hex_encode("hello")"##, Str("68656c6c6f")),
    (r##"hex_encode("hello", "x")"##, Str("\\x68\\x65\\x6c\\x6c\\x6f")),
    (r##"hex_encode("hello", "y")"##, Str("68656c6c6f")),
    (r##"hex_encode(1)"##, Str("")),
    (r##"hex_encode("")"##, Str("")),
    (r##"hex_decode("68656c6c6f")"##, Str("hello")),
    (r##"hex_decode("6")"##, Absent),
    (r##"hex_decode("zz")"##, Absent),
    (r##"hex_decode("68656C6C6F")"##, Str("hello")),
    (r##"url_encode("a b&c=d/é")"##, Str("a%20b%26c%3Dd%2F%C3%A9")),
    (r##"url_encode("a b-_.!~*'()")"##, Str("a%20b-_.!~*'()")),
    (r##"url_encode("a b", true)"##, Str("a%20b")),
    (r##"url_decode("a%20b%zz%4")"##, Str("a b%zz%4")),
    (r##"url_decode("a%20b%41")"##, Str("a bA")),
    (r##"url_decode("%41")"##, Str("A")),
    (r##"url_decode("%4")"##, Str("%4")),
    (r##"sha1("hello")"##, Str("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")),
    (r##"sha256("hello")"##, Str("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")),
    (r##"sha512("hello")"##, Str("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043")),
    (r##"sha256("")"##, Str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
    (r##"sort("hello")"##, Str("ehllo")),
    (r##"sort("b", "c", "a")"##, List(&["a", "b", "c"])),
    (r##"sort(3, 1, 2)"##, List(&["1", "2", "3"])),
    (r##"uniq("hello")"##, Str("helo")),
    (r##"uniq("a", "b", "a")"##, List(&["a", "b"])),
    (r##"len(split("a,b,c", ","))"##, Num(3.0)),
    (r##"len("héllo")"##, Num(6.0)),
    (r##"len(1234)"##, Num(4.0)),
    (r##"to_upper("héllo")"##, Str("HÉLLO")),
    (r##"to_lower("HÉLLO")"##, Str("héllo")),
    (r##"to_upper("ß")"##, Str("ß")),
    (r##"trim("xxhixx", "x")"##, Str("hi")),
    (r##"contains(to_lower(body), "hello")"##, Bool(true)),
    (r##"regex("^[a-z]+$", words)"##, Bool(false)),
    (r##"code == 200"##, Bool(true)),
    (r##"starts_with(body, "Hello", "x")"##, Bool(true)),
    (r##"ends_with(body, "x", "llo")"##, Bool(true)),
    (r##"contains_all(body, "Hello", "World")"##, Bool(true)),
    (r##"contains_any(body, "x", "World")"##, Bool(true)),
    (r##"line_starts_with(multi, "b")"##, Bool(true)),
    (r##"line_starts_with(multi, "x", "c")"##, Bool(true)),
    (r##"line_starts_with(multi, "x")"##, Bool(false)),
    (r##"line_ends_with(multi, "b")"##, Bool(true)),
    (r##"line_ends_with(multi, "z")"##, Bool(false)),
    (r##"len(multi)"##, Num(5.0)),
    (r##"to_lower("ΑΣ")"##, Str("ασ")),
    (r##"to_lower("İ")"##, Str("i")),
    (r##"to_upper("ǆ")"##, Str("Ǆ")),
    (r##"to_upper("ŉ")"##, Str("ŉ")),
    (r##"to_upper("ı")"##, Str("I")),
    (r##"to_lower("ǅ")"##, Str("ǆ")),
    (r##"replace_regex("baaac", "a*", "-")"##, Str("-b-c-")),
    (r##"replace_regex("abc", "(b)", "$1x")"##, Str("ac")),
    (r##"replace_regex("abc", "(?P<x>b)", "[${x}]")"##, Str("a[b]c")),
    (r##"replace_regex("abc", "b", "")"##, Str("ac")),
    (r##"split("1,2", "1")"##, List(&["1", ",", "2"])),
    (r##"split("a,b", ",", 1)"##, List(&["a,b"])),
    (r##"split("héllo", "", 3)"##, List(&["h", "é", "llo"])),
    (r##"split("", ",")"##, List(&[""])),
    (r##"split("abc", 0)"##, List(&["abc"])),
    (r##"count("héllo", "")"##, Num(6.0)),
    (r##"to_number("+1")"##, Num(1.0)),
    (r##"to_number("1.")"##, Num(1.0)),
    (r##"to_number(".5")"##, Num(0.5)),
    (r##"to_number(".")"##, Absent),
    (r##"to_number("e3")"##, Absent),
    (r##"to_number("99999999999999999999")"##, Absent),
    (r##"to_number("-0")"##, Num(0.0)),
    (r##"to_number("1e")"##, Absent),
    (r##"to_number("0x10")"##, Absent),
    (r##"substr("hello", 5, 5)"##, Str("")),
    (r##"url_encode("é", true)"##, Str("%C3%A9")),
    (r##"url_encode("", false)"##, Str("")),
    (r##"index(split("a,b,c", ","), 1)"##, Str("b")),
    (r##"index(split("a,b,c", ","), 3)"##, Absent),
    (r##"index("hello", "x")"##, Absent),
    (r##"base64_decode("aGVsbG9=")"##, Str("hello")),
    (r##"base64("a")"##, Str("YQ==")),
    (r##"sort("")"##, Str("")),
    (r##"uniq("")"##, Str("")),
    (r##"join("", "a", "b")"##, Str("ab")),
    (r##"join(",", split("", ","))"##, Str("")),
    (r##"equals_any("a")"##, Absent),
    (r##"repeat("ab", "2")"##, Str("abab")),
    (r##"repeat("ab", "x")"##, Absent),
    (r##"repeat("é", 2)"##, Str("éé")),
    (r##"hex_encode("é")"##, Str("c3a9")),
    (r##"hex_encode("hello", "X")"##, Str("\\x68\\x65\\x6c\\x6c\\x6f")),
    (r##"hex_decode("")"##, Str("")),
    (r##"hex_decode("0g")"##, Absent),
    (r##"url_decode("%e9")"##, Str("\u{fffd}")),
    (r##"url_decode("%C3%A9")"##, Str("é")),
    (r##"url_decode("100%")"##, Str("100%")),
    (r##"url_decode("%%41")"##, Str("%A")),
    (r##"remove_bad_chars(1234, "2")"##, Str("134")),
    (r##"reverse(123)"##, Str("321")),
    (r##"concat(1, 2.5)"##, Str("12.5")),
    (r##"len(words)"##, Num(16.0)),
    (r##"count(words, "a")"##, Num(5.0)),
    (r##"starts_with(words)"##, Absent),
    (r##"trimspace("  x ")"##, Str("x")),
    (r##"toupper("x")"##, Str("X")),
    (r##"containsany("abc", "b")"##, Bool(true)),
    (r##"trim_left("xxhixx", "x")"##, Str("hixx")),
    (r##"trim_right("xxhixx", "x")"##, Str("xxhi")),
    (r##"trim_space("  x y  ")"##, Str("x y")),
    (r##"trim_prefix("ababc", "ab")"##, Str("abc")),
    (r##"trim_suffix("cabab", "ab")"##, Str("cab")),
    (r##"trim_prefix("abc", "")"##, Str("abc")),
    (r##"trim("é🙂Hello🙂é", "🙂é")"##, Str("Hello")),
    (r##"trim_space(" x　")"##, Str("x")),
];

const REFERENCE_FUNCTIONS: [&str; 93] = [
    "aes_cbc",
    "aes_gcm",
    "base64",
    "base64_decode",
    "base64_py",
    "bin_to_dec",
    "compare_versions",
    "concat",
    "contains",
    "contains_all",
    "contains_any",
    "cookie_unsign",
    "count",
    "date_time",
    "dec_to_hex",
    "deflate",
    "ends_with",
    "equals_any",
    "generate_dotnet_gadget",
    "generate_java_gadget",
    "generate_jwt",
    "gzip",
    "gzip_decode",
    "gzip_mtime",
    "hex_decode",
    "hex_encode",
    "hex_to_dec",
    "hmac",
    "html_escape",
    "html_unescape",
    "index",
    "inflate",
    "ip_format",
    "jarm",
    "join",
    "json_minify",
    "json_prettify",
    "len",
    "line_ends_with",
    "line_starts_with",
    "llm_prompt",
    "md5",
    "mmh3",
    "oct_to_dec",
    "padding",
    "print_debug",
    "public_ip",
    "rand_base",
    "rand_char",
    "rand_int",
    "rand_ip",
    "rand_text_alpha",
    "rand_text_alphanumeric",
    "rand_text_numeric",
    "regex",
    "regex_all",
    "regex_any",
    "remove_bad_chars",
    "repeat",
    "replace",
    "replace_regex",
    "reverse",
    "rsa_encrypt",
    "sha1",
    "sha256",
    "sha512",
    "sort",
    "split",
    "starts_with",
    "substr",
    "to_bool",
    "to_lower",
    "to_number",
    "to_string",
    "to_title",
    "to_unix_time",
    "to_upper",
    "trim",
    "trim_left",
    "trim_prefix",
    "trim_right",
    "trim_space",
    "trim_suffix",
    "uniq",
    "unix_time",
    "unpack",
    "url_decode",
    "url_encode",
    "wait_for",
    "xor",
    "zip",
    "zlib",
    "zlib_decode",
];

#[test]
fn every_supported_function_matches_its_pinned_reference_vector() {
    let mut failures = Vec::new();
    for (expr, want) in VECTORS {
        let ok = match want {
            Str(text) => holds(&format!("({expr}) == {}", literal(text))),
            Num(n) => holds(&format!("({expr}) == {n}")),
            Bool(b) => holds(&format!("({expr}) == {b}")),
            List(items) => {
                holds(&format!("len({expr}) == {}", items.len()))
                    && holds(&format!(
                        "join(\"\u{1f}\", {expr}) == {}",
                        literal(&items.join("\u{1f}"))
                    ))
            }
            Absent => match Dsl::parse(&format!("({expr}) == \"\"")) {
                Ok(c) => {
                    !c.eval_value(&record())
                        && !Dsl::parse(&format!("({expr}) != \"\""))
                            .unwrap()
                            .eval_value(&record())
                        && !Dsl::parse(&format!("({expr}) == 0"))
                            .unwrap()
                            .eval_value(&record())
                }
                Err(e) => {
                    REFUSED_AT_PARSE.contains(expr)
                        && matches!(e, DslError::Arity { .. } | DslError::Regex { .. })
                }
            },
        };
        if !ok {
            failures.push(*expr);
        }
    }
    assert!(
        failures.is_empty(),
        "{} vector(s) differ from the reference:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn a_wrong_vector_is_detected() {
    // the harness itself: a changed expectation must fail, so the table above cannot pass vacuously
    assert!(holds(&format!(
        "(sha1(\"hello\")) == {}",
        literal("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    )));
    assert!(!holds(&format!(
        "(sha1(\"hello\")) == {}",
        literal("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434e")
    )));
    assert!(!holds("(to_upper(\"ß\")) == \"SS\""));
}

#[test]
fn every_supported_function_has_a_vector_and_the_tables_partition_the_reference_set() {
    let supported: Vec<&str> = supported_functions().map(|f| f.name).collect();
    let unsupported: Vec<&str> = UNSUPPORTED_FUNCTIONS.iter().map(|(name, _)| *name).collect();
    let supported_set: BTreeSet<&str> = supported.iter().copied().collect();
    let unsupported_set: BTreeSet<&str> = unsupported.iter().copied().collect();
    assert_eq!(supported.len(), supported_set.len(), "a function is listed twice");
    assert_eq!(
        unsupported.len(),
        unsupported_set.len(),
        "an unsupported function is listed twice"
    );
    assert!(
        supported_set.is_disjoint(&unsupported_set),
        "listed as both: {:?}",
        supported_set.intersection(&unsupported_set)
    );
    let reference: BTreeSet<&str> = REFERENCE_FUNCTIONS.into_iter().collect();
    assert_eq!(reference.len(), REFERENCE_FUNCTIONS.len());
    let covered: BTreeSet<&str> = supported_set.union(&unsupported_set).copied().collect();
    assert_eq!(
        covered.difference(&reference).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "named in a table but not a reference function"
    );
    assert_eq!(
        reference.difference(&covered).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "reference function in neither table"
    );
    assert!(UNSUPPORTED_FUNCTIONS.iter().all(|(_, why)| !why.is_empty()));
    // a function without a vector is a function nobody checked against the reference
    for name in &supported {
        let call = format!("{name}(");
        assert!(
            VECTORS.iter().any(|(expr, _)| expr.contains(&call)),
            "no reference vector exercises {name}"
        );
    }
    // the arities the table declares are the ones the parser enforces
    for function in supported_functions() {
        let too_few = function.min_args.checked_sub(1);
        if let Some(n) = too_few {
            let args = vec!["1"; n].join(", ");
            let error = Dsl::parse(&format!("{}({args})", function.name)).unwrap_err();
            assert!(
                matches!(error, DslError::Arity { got, .. } if got == n),
                "{}: {error}",
                function.name
            );
        }
        if let Some(max) = function.max_args {
            let args = vec!["1"; max + 1].join(", ");
            let error = Dsl::parse(&format!("{}({args})", function.name)).unwrap_err();
            assert!(
                matches!(error, DslError::Arity { .. }),
                "{}: {error}",
                function.name
            );
        }
    }
}

#[test]
fn unsupported_and_unlisted_functions_fail_with_their_byte_position() {
    let prefix = "status_code == 200 && ";
    for (name, reason) in UNSUPPORTED_FUNCTIONS {
        let error = Dsl::parse(&format!("{prefix}{name}(1)")).unwrap_err();
        assert!(
            matches!(&error, DslError::UnsupportedFunction { position, name: n, reason: r }
                if *position == prefix.len() && n == name && *r == reason),
            "{name}: {error}"
        );
        assert_eq!(error.position(), Some(prefix.len()));
        assert!(
            error.to_string().contains(&format!("at byte {}", prefix.len())),
            "{error}"
        );
        assert!(error.to_string().contains(reason), "{error}");
    }
    // names that are not in the reference set at all, including the ones that would evaluate text
    for name in [
        "eval", "exec", "system", "os", "import", "nosuch", "Contains", "len2",
    ] {
        let error = Dsl::parse(&format!("{prefix}{name}(1)")).unwrap_err();
        assert!(
            matches!(&error, DslError::UnknownFunction { position, name: n } if *position == prefix.len() && n == name),
            "{name}: {error}"
        );
        assert!(!error.to_string().contains("not supported"), "{error}");
    }
    // the position is a byte offset, not a character count
    let error = Dsl::parse("body == \"é\" && rand_int(1)").unwrap_err();
    assert_eq!(error.position(), Some("body == \"é\" && ".len()));
    assert_eq!(error.position(), Some(16));
    let error = Dsl::parse("contains(body, \"é\") || eval(body)").unwrap_err();
    assert_eq!(error.position(), Some(24));
    // an unknown name hides nowhere: in a dead branch, nested, or as an argument
    for source in [
        "false && eval(body)",
        "contains(to_lower(exec(body)), \"x\")",
        "len(sha256(body)) == 64 || system(1)",
    ] {
        assert!(Dsl::parse(source).is_err(), "{source}");
    }
}

#[test]
fn the_reference_spelling_without_underscores_works_for_every_supported_function() {
    for function in supported_functions() {
        let alias: String = function.name.chars().filter(|c| *c != '_').collect();
        let args = vec!["\"x\""; function.min_args.max(1)].join(", ");
        let canonical = Dsl::parse(&format!("{}({args}) == 1", function.name));
        let aliased = Dsl::parse(&format!("{alias}({args}) == 1"));
        assert_eq!(canonical.is_ok(), aliased.is_ok(), "{} / {alias}", function.name);
    }
    assert!(holds(
        "toupper(\"x\") == \"X\" && trimspace(\"  y \") == \"y\" && containsany(body, \"World\")"
    ));
    // an alias of an unsupported function is explained like the function itself
    let error = Dsl::parse("randint(1)").unwrap_err();
    assert!(
        matches!(error, DslError::UnsupportedFunction { position: 0, .. }),
        "{error}"
    );
}

#[test]
fn operands_results_and_lists_are_bounded_and_an_overrun_is_false_not_a_hang() {
    let big = "x".repeat(MAX_VALUE_LEN);
    let record = json!({ "big": big, "over": format!("{big}x"), "small": "ab" });
    let eval = |source: &str| Dsl::parse(source).unwrap().eval_value(&record);
    // exactly at the limit is fine, one byte over is not
    assert!(eval("len(reverse(big)) == 1048576"));
    assert!(!eval("len(reverse(over)) == 1048577"));
    assert!(eval("len(concat(big)) == 1048576"));
    assert!(!eval("len(concat(big, \"y\")) == 1048577"));
    assert!(eval("len(repeat(\"ab\", 524288)) == 1048576"));
    assert!(!eval("len(repeat(\"ab\", 524289)) == 1048578"));
    assert!(!eval("len(repeat(small, 9223372036854775807)) > 0"));
    assert!(!eval("len(repeat(\"\", -1)) == 0"));
    // growth by replacement is cut off while the result is built, not after
    assert!(!eval("len(replace(big, \"x\", \"xx\")) > 0"));
    assert!(!eval("len(replace(big, \"\", \"-\")) > 0"));
    assert!(!eval("len(replace_regex(big, \"x\", \"yy\")) > 0"));
    assert!(!eval("len(replace_regex(big, \"\", \"-\")) > 0"));
    assert!(eval("len(replace_regex(big, \"x\", \"y\")) == 1048576"));
    assert!(!eval("len(replace(over, \"x\", \"y\")) > 0"));
    // lists
    assert!(!eval("len(split(big, 1)) > 0"), "{MAX_LIST_LEN} elements at most");
    assert!(eval("len(split(big, 16)) == 65536"));
    assert!(!eval("len(split(big, \"\")) > 0"));
    // encoders and digests refuse oversized operands
    for call in [
        "base64(over)",
        "base64(big)",
        "sha1(over)",
        "sha256(over)",
        "sha512(over)",
        "hex_encode(over)",
        "hex_encode(big)",
        "url_encode(over)",
        "url_encode(replace(big, \"x\", \" \"))",
    ] {
        assert!(!eval(&format!("len({call}) > 0")), "{call}");
    }
    assert!(eval("len(sha256(big)) == 64"));
    // a list result is not a way around the limit
    assert!(!eval("len(join(\"\", split(over, 16))) > 0"));
}
