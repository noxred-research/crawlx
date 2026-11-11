//! The function table of the condition language.
//!
//! One table names every function of the language (its arity and its reference spelling) and one
//! table names the functions of the pinned reference DSL that this language does **not** have,
//! each with the reason. A name in neither table is [`DslError::UnknownFunction`](super::DslError);
//! a name in the second is [`DslError::UnsupportedFunction`](super::DslError) with the reason.
//!
//! Every function here is pure and bounded: it reads only its arguments, never the clock, the
//! environment, the network or a random source, and it never evaluates its text as code. Operands
//! and results over [`MAX_VALUE_LEN`] bytes, lists over [`MAX_LIST_LEN`] elements and regular
//! expressions the linear-time engine rejects evaluate to "no value", which makes the whole
//! condition `false` like any other evaluation failure.
//!
//! The semantics follow v0.8.21 of the reference DSL's function library, the release the pinned
//! reference tool's `go.mod` selects; `tests` carries one executable vector per function,
//! produced by running that release. Where the reference panics or returns a non-UTF-8 string the
//! result here is "no value" or the lossy UTF-8 text.

use super::{build_regex, stringify, EvalError, Val};
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine as _};
use regex::Regex;
use sha2::Digest as _;
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Longest operand or result of a function, in bytes.
pub const MAX_VALUE_LEN: usize = 1 << 20;
/// Longest list a function returns, in elements.
pub const MAX_LIST_LEN: usize = 1 << 16;

/// The functions of the language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Func {
    Contains,
    ContainsAny,
    ContainsAll,
    StartsWith,
    EndsWith,
    LineStartsWith,
    LineEndsWith,
    EqualsAny,
    Regex,
    RegexAll,
    RegexAny,
    Len,
    Count,
    Index,
    Substr,
    ToLower,
    ToUpper,
    Trim,
    TrimLeft,
    TrimRight,
    TrimSpace,
    TrimPrefix,
    TrimSuffix,
    RemoveBadChars,
    Reverse,
    Repeat,
    Replace,
    ReplaceRegex,
    Concat,
    Join,
    Split,
    Sort,
    Uniq,
    ToString,
    ToNumber,
    Base64,
    Base64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    Sha1,
    Sha256,
    Sha512,
}

/// One entry of the function table.
struct Spec {
    name: &'static str,
    func: Func,
    min: usize,
    /// `usize::MAX` for variadic.
    max: usize,
}

const fn spec(name: &'static str, func: Func, min: usize, max: usize) -> Spec {
    Spec { name, func, min, max }
}

const VARIADIC: usize = usize::MAX;

/// Every function of the language, in documentation order.
const TABLE: [Spec; 44] = [
    spec("contains", Func::Contains, 2, 2),
    spec("contains_any", Func::ContainsAny, 2, VARIADIC),
    spec("contains_all", Func::ContainsAll, 2, VARIADIC),
    spec("starts_with", Func::StartsWith, 2, VARIADIC),
    spec("ends_with", Func::EndsWith, 2, VARIADIC),
    spec("line_starts_with", Func::LineStartsWith, 2, VARIADIC),
    spec("line_ends_with", Func::LineEndsWith, 2, VARIADIC),
    spec("equals_any", Func::EqualsAny, 2, VARIADIC),
    spec("regex", Func::Regex, 2, 2),
    spec("regex_all", Func::RegexAll, 2, VARIADIC),
    spec("regex_any", Func::RegexAny, 2, VARIADIC),
    spec("len", Func::Len, 1, 1),
    spec("count", Func::Count, 2, 2),
    spec("index", Func::Index, 2, 2),
    spec("substr", Func::Substr, 2, 3),
    spec("to_lower", Func::ToLower, 1, 1),
    spec("to_upper", Func::ToUpper, 1, 1),
    spec("trim", Func::Trim, 2, 2),
    spec("trim_left", Func::TrimLeft, 2, 2),
    spec("trim_right", Func::TrimRight, 2, 2),
    spec("trim_space", Func::TrimSpace, 1, 1),
    spec("trim_prefix", Func::TrimPrefix, 2, 2),
    spec("trim_suffix", Func::TrimSuffix, 2, 2),
    spec("remove_bad_chars", Func::RemoveBadChars, 2, 2),
    spec("reverse", Func::Reverse, 1, 1),
    spec("repeat", Func::Repeat, 2, 2),
    spec("replace", Func::Replace, 3, 3),
    spec("replace_regex", Func::ReplaceRegex, 3, 3),
    spec("concat", Func::Concat, 0, VARIADIC),
    spec("join", Func::Join, 2, VARIADIC),
    spec("split", Func::Split, 2, 3),
    spec("sort", Func::Sort, 1, VARIADIC),
    spec("uniq", Func::Uniq, 1, VARIADIC),
    spec("to_string", Func::ToString, 1, 1),
    spec("to_number", Func::ToNumber, 1, 1),
    spec("base64", Func::Base64, 1, 1),
    spec("base64_decode", Func::Base64Decode, 1, 1),
    spec("hex_encode", Func::HexEncode, 1, 2),
    spec("hex_decode", Func::HexDecode, 1, 1),
    spec("url_encode", Func::UrlEncode, 1, 2),
    spec("url_decode", Func::UrlDecode, 1, 1),
    spec("sha1", Func::Sha1, 1, 1),
    spec("sha256", Func::Sha256, 1, 1),
    spec("sha512", Func::Sha512, 1, 1),
];

/// A function of the language, as listed by [`supported_functions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FunctionInfo {
    /// The reference spelling (`contains_any`); the spelling without underscores
    /// (`containsany`) is accepted too, as in the reference.
    pub name: &'static str,
    /// Fewest arguments.
    pub min_args: usize,
    /// Most arguments; `None` when the function takes any number.
    pub max_args: Option<usize>,
}

/// Every function the language has, in documentation order.
#[must_use = "the iterator does nothing unless consumed"]
pub fn supported_functions() -> impl ExactSizeIterator<Item = FunctionInfo> {
    TABLE.iter().map(|s| FunctionInfo {
        name: s.name,
        min_args: s.min,
        max_args: (s.max != VARIADIC).then_some(s.max),
    })
}

/// Functions of the pinned reference DSL that the language does not have, with the reason. Naming
/// one in a condition is a parse error that quotes the reason; the table and
/// [`supported_functions`] together cover the reference's whole function set.
pub const UNSUPPORTED_FUNCTIONS: [(&str, &str); 49] = [
    ("aes_cbc", "encryption with a caller-supplied key"),
    ("aes_gcm", "encryption with a caller-supplied key"),
    ("base64_py", "the line-wrapped variant is not implemented"),
    ("bin_to_dec", "base conversion is not implemented"),
    ("compare_versions", "version-range syntax is not implemented"),
    (
        "cookie_unsign",
        "signature verification with a caller-supplied secret",
    ),
    ("date_time", "reads the clock"),
    ("deflate", "compression output is not bounded by the operand"),
    ("dec_to_hex", "base conversion is not implemented"),
    ("generate_dotnet_gadget", "payload generation"),
    ("generate_java_gadget", "payload generation"),
    ("generate_jwt", "signing with a caller-supplied key"),
    ("gzip", "compression output is not bounded by the operand"),
    ("gzip_decode", "decompression is not bounded by the operand"),
    ("gzip_mtime", "decompression is not bounded by the operand"),
    ("hex_to_dec", "base conversion is not implemented"),
    ("hmac", "keyed digest with a caller-supplied secret"),
    ("html_escape", "the reference's entity table is not implemented"),
    ("html_unescape", "the full HTML entity table is not implemented"),
    ("inflate", "decompression is not bounded by the operand"),
    ("ip_format", "address formats are not implemented"),
    ("jarm", "opens network connections"),
    ("json_minify", "JSON re-encoding is not implemented"),
    ("json_prettify", "JSON re-encoding is not implemented"),
    ("llm_prompt", "calls a model service"),
    ("md5", "no MD5 implementation is linked"),
    ("mmh3", "no murmur hash implementation is linked"),
    ("oct_to_dec", "base conversion is not implemented"),
    ("padding", "block padding is not implemented"),
    ("print_debug", "writes to the log"),
    ("public_ip", "opens network connections"),
    ("rand_base", "reads a random source"),
    ("rand_char", "reads a random source"),
    ("rand_int", "reads a random source"),
    ("rand_ip", "reads a random source"),
    ("rand_text_alpha", "reads a random source"),
    ("rand_text_alphanumeric", "reads a random source"),
    ("rand_text_numeric", "reads a random source"),
    ("rsa_encrypt", "encryption with a caller-supplied key"),
    ("to_bool", "boolean coercion is not implemented"),
    ("to_title", "language-tagged title casing is not implemented"),
    ("to_unix_time", "time layouts are not implemented"),
    ("unix_time", "reads the clock"),
    ("unpack", "binary unpacking is not implemented"),
    ("wait_for", "sleeps"),
    ("xor", "binary output is not implemented"),
    ("zip", "archive output is not implemented"),
    ("zlib", "compression output is not bounded by the operand"),
    ("zlib_decode", "decompression is not bounded by the operand"),
];

/// `name` without underscores: the alias the reference registers next to every name.
fn alias_matches(canonical: &str, name: &str) -> bool {
    !name.contains('_') && canonical.contains('_') && canonical.chars().filter(|c| *c != '_').eq(name.chars())
}

impl Func {
    /// The function spelled `name` (or its underscore-free alias).
    pub(super) fn lookup(name: &str) -> Option<Self> {
        TABLE
            .iter()
            .find(|s| s.name == name || alias_matches(s.name, name))
            .map(|s| s.func)
    }

    fn spec(self) -> &'static Spec {
        // Every `Func` has a table entry (the `table_names_every_function_once` test).
        TABLE.iter().find(|s| s.func == self).unwrap_or(&TABLE[0])
    }

    pub(super) fn name(self) -> &'static str {
        self.spec().name
    }

    /// `(minimum, maximum)` argument count.
    pub(super) fn arity(self) -> (usize, usize) {
        let s = self.spec();
        (s.min, s.max)
    }

    /// `2`, `2 to 3` or `at least 2`.
    pub(super) fn arity_text(self) -> &'static str {
        match self.arity() {
            (0, VARIADIC) => "any number of",
            (1, VARIADIC) => "at least 1",
            (2, VARIADIC) => "at least 2",
            (1, 1) => "1",
            (2, 2) => "2",
            (3, 3) => "3",
            (1, 2) => "1 to 2",
            (2, 3) => "2 to 3",
            _ => "a different number of",
        }
    }

    /// Argument that holds the regex pattern, for functions that take one.
    pub(super) const fn pattern_argument(self) -> Option<usize> {
        match self {
            Self::Regex | Self::RegexAll | Self::RegexAny => Some(0),
            Self::ReplaceRegex => Some(1),
            _ => None,
        }
    }
}

/// The reason `name` is a reference function this language lacks.
pub(super) fn unsupported_reason(name: &str) -> Option<&'static str> {
    UNSUPPORTED_FUNCTIONS
        .iter()
        .find(|(n, _)| *n == name || alias_matches(n, name))
        .map(|(_, reason)| *reason)
}

// ---------------------------------------------------------------------------------------
// Evaluation

fn limit(len: usize) -> Result<(), EvalError> {
    if len > MAX_VALUE_LEN {
        Err(EvalError::Limit)
    } else {
        Ok(())
    }
}

fn limit_list(len: usize) -> Result<(), EvalError> {
    if len > MAX_LIST_LEN {
        Err(EvalError::Limit)
    } else {
        Ok(())
    }
}

/// Go's `strconv.Atoi`: an optional sign and decimal digits that fit an `i64`.
fn go_atoi(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.strip_prefix('+').unwrap_or(text).parse().ok()
}

fn lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

/// Go's `unicode.ToLower` per character: the single-character simple mapping, else the character.
fn go_lower(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch == '\u{130}' {
                return 'i';
            }
            let mut mapped = ch.to_lowercase();
            match (mapped.next(), mapped.next()) {
                (Some(one), None) => one,
                _ => ch,
            }
        })
        .collect()
}

/// Go's `unicode.ToUpper` per character: the single-character simple mapping, else the character.
fn go_upper(text: &str) -> String {
    text.chars()
        .map(|ch| {
            let mut mapped = ch.to_uppercase();
            match (mapped.next(), mapped.next()) {
                (Some(one), None) => one,
                _ => ch,
            }
        })
        .collect()
}

fn trim(func: Func, mut input: String, cutset: &str) -> Result<Val, EvalError> {
    if input.len() > MAX_VALUE_LEN || cutset.len() > super::MAX_TRIM_CUTSET_LEN {
        return Err(EvalError::Limit);
    }
    let left = match func {
        Func::Trim | Func::TrimLeft => input.trim_start_matches(|ch| cutset.contains(ch)),
        Func::TrimSpace => input.trim_start(),
        Func::TrimPrefix => input.strip_prefix(cutset).unwrap_or(&input),
        _ => &input,
    };
    let start = input.len() - left.len();
    let len = match func {
        Func::Trim | Func::TrimRight => left.trim_end_matches(|ch| cutset.contains(ch)).len(),
        Func::TrimSpace => left.trim_end().len(),
        Func::TrimSuffix => left.strip_suffix(cutset).unwrap_or(left).len(),
        _ => left.len(),
    };
    // Reuse the owned buffer; both offsets come from UTF-8 subslices of the input.
    drop(input.drain(..start));
    input.truncate(len);
    Ok(Val::Str(input))
}

/// Go's `strings.ReplaceAll`, stopping once the result would exceed [`MAX_VALUE_LEN`].
fn replace_all(input: &str, from: &str, to: &str) -> Result<String, EvalError> {
    let mut out = String::with_capacity(input.len().min(MAX_VALUE_LEN));
    if from.is_empty() {
        // between every character, before the first and after the last
        for ch in input.chars() {
            out.push_str(to);
            out.push(ch);
            limit(out.len())?;
        }
        out.push_str(to);
        limit(out.len())?;
        return Ok(out);
    }
    let mut last = 0;
    for (at, found) in input.match_indices(from) {
        out.push_str(&input[last..at]);
        out.push_str(to);
        last = at + found.len();
        limit(out.len())?;
    }
    out.push_str(&input[last..]);
    limit(out.len())?;
    Ok(out)
}

fn replace_regex(input: &str, re: &Regex, template: &str) -> Result<String, EvalError> {
    let mut out = String::with_capacity(input.len().min(MAX_VALUE_LEN));
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let Some(whole) = caps.get(0) else { continue };
        out.push_str(&input[last..whole.start()]);
        caps.expand(template, &mut out);
        last = whole.end();
        limit(out.len())?;
    }
    out.push_str(&input[last..]);
    limit(out.len())?;
    Ok(out)
}

/// Go's `strings.SplitN`; `n < 0` is all pieces, `n == 0` none.
fn split_n(input: &str, sep: &str, n: i64) -> Result<Vec<String>, EvalError> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let wanted = usize::try_from(n).unwrap_or(usize::MAX);
    if sep.is_empty() {
        // one piece per character; the last piece keeps the rest
        let mut pieces = Vec::new();
        let mut rest = input;
        while let Some(ch) = rest.chars().next() {
            if pieces.len() + 1 == wanted {
                break;
            }
            limit_list(pieces.len())?;
            let (head, tail) = rest.split_at(ch.len_utf8());
            pieces.push(head.to_owned());
            rest = tail;
        }
        if !rest.is_empty() {
            pieces.push(rest.to_owned());
        }
        limit_list(pieces.len())?;
        return Ok(pieces);
    }
    let mut pieces = Vec::new();
    for piece in input.splitn(wanted, sep) {
        limit_list(pieces.len())?;
        pieces.push(piece.to_owned());
    }
    Ok(pieces)
}

/// The reference's `toChunks`: pieces of `size` characters.
fn chunks(input: &str, size: i64) -> Result<Vec<String>, EvalError> {
    let size = usize::try_from(size).unwrap_or(0);
    if size == 0 || size >= input.len() {
        return Ok(vec![input.to_owned()]);
    }
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut count = 0;
    for (at, _) in input.char_indices() {
        if count == size {
            limit_list(pieces.len())?;
            pieces.push(input[start..at].to_owned());
            count = 0;
            start = at;
        }
        count += 1;
    }
    pieces.push(input[start..].to_owned());
    limit_list(pieces.len())?;
    Ok(pieces)
}

fn list_of(pieces: Vec<String>) -> Result<Val, EvalError> {
    limit_list(pieces.len())?;
    Ok(Val::List(pieces.into_iter().map(Val::Str).collect()))
}

/// Go's `strconv.Atoi` shape: `[-+]?(0|[1-9][0-9]*)`.
fn is_plain_int(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    digits == "0"
        || (digits.starts_with(|c: char| ('1'..='9').contains(&c))
            && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// The reference's float shape: `([-+]?[0-9]+)?(\.[0-9]*)?([eE][-+]?[0-9]+)?`.
fn is_plain_float(text: &str) -> bool {
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    if let Some(exponent) = exponent {
        let body = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if body.is_empty() || !digits(body) {
            return false;
        }
    }
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (mantissa, None),
    };
    let whole = whole.strip_prefix(['+', '-']).unwrap_or(whole);
    digits(whole) && fraction.is_none_or(digits)
}

fn to_number(text: &str) -> Result<Val, EvalError> {
    if text.is_empty() {
        return Err(EvalError::Argument);
    }
    if is_plain_int(text) {
        // as `Atoi`: a value outside the 64-bit range is an error
        go_atoi(text).ok_or(EvalError::Argument)?;
    } else if !is_plain_float(text) {
        return Err(EvalError::Argument);
    }
    text.parse::<f64>()
        .ok()
        .filter(|n| n.is_finite())
        .map(Val::Num)
        .ok_or(EvalError::Argument)
}

/// The base64 decoder of Go's `StdEncoding`: padding required, trailing bits ignored, line breaks skipped.
fn go_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    )
}

fn url_encode(input: &str, only_alphanumerics: bool) -> Result<String, EvalError> {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let keep = ch.is_ascii_alphanumeric()
            || (!only_alphanumerics && matches!(ch, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')'));
        if keep {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for byte in ch.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        }
        limit(out.len())?;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // the reference needs two more bytes strictly inside the input: `i + 2 < len`
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push(high << 4 | low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    lossy(out)
}

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn text_arg(values: &[Val], at: usize) -> String {
    values.get(at).map(stringify).unwrap_or_default()
}

fn regex_for<'a>(
    func: Func,
    values: &[Val],
    compiled: Option<&'a Regex>,
    storage: &'a mut Option<Regex>,
) -> Result<&'a Regex, EvalError> {
    if let Some(re) = compiled {
        return Ok(re);
    }
    let at = func.pattern_argument().unwrap_or(0);
    let pattern = text_arg(values, at);
    *storage = Some(build_regex(&pattern).map_err(|_| EvalError::Regex)?);
    storage.as_ref().ok_or(EvalError::Regex)
}

fn usize_to_f64(n: usize) -> f64 {
    u32::try_from(n).map_or(f64::from(u32::MAX), f64::from)
}

/// Apply `func` to evaluated arguments. `compiled` is the pattern a literal regex argument was
/// compiled to at parse time.
pub(super) fn apply(func: Func, values: Vec<Val>, compiled: Option<&Regex>) -> Result<Val, EvalError> {
    let result = compute(func, values, compiled)?;
    if let Val::Str(text) = &result {
        limit(text.len())?;
    }
    Ok(result)
}

fn compute(func: Func, mut values: Vec<Val>, compiled: Option<&Regex>) -> Result<Val, EvalError> {
    let first = values
        .first_mut()
        .map(|value| match value {
            Val::Str(text) => std::mem::take(text),
            _ => stringify(value),
        })
        .unwrap_or_default();
    let rest = |from: usize| values.iter().skip(from).map(stringify);
    let second = || text_arg(&values, 1);
    Ok(match func {
        Func::Contains => Val::Bool(first.contains(&second())),
        Func::ContainsAny => Val::Bool(rest(1).any(|s| first.contains(&s))),
        Func::ContainsAll => Val::Bool(rest(1).all(|s| first.contains(&s))),
        Func::StartsWith => Val::Bool(rest(1).any(|s| first.starts_with(&s))),
        Func::EndsWith => Val::Bool(rest(1).any(|s| first.ends_with(&s))),
        Func::LineStartsWith => {
            let prefixes: Vec<String> = rest(1).collect();
            Val::Bool(
                first
                    .split('\n')
                    .any(|line| prefixes.iter().any(|p| line.starts_with(p.as_str()))),
            )
        }
        Func::LineEndsWith => {
            let suffixes: Vec<String> = rest(1).collect();
            Val::Bool(
                first
                    .split('\n')
                    .any(|line| suffixes.iter().any(|p| line.ends_with(p.as_str()))),
            )
        }
        Func::EqualsAny => Val::Bool(rest(1).any(|s| s == first)),
        Func::Regex => {
            let input = text_arg(&values, 1);
            let mut owned = None;
            Val::Bool(regex_for(func, &[Val::Str(first)], compiled, &mut owned)?.is_match(&input))
        }
        Func::RegexAll | Func::RegexAny => {
            let inputs: Vec<String> = rest(1).collect();
            let mut owned = None;
            let re = regex_for(func, &[Val::Str(first)], compiled, &mut owned)?;
            Val::Bool(if func == Func::RegexAll {
                inputs.iter().all(|s| re.is_match(s))
            } else {
                inputs.iter().any(|s| re.is_match(s))
            })
        }
        Func::Len => match values.first() {
            Some(Val::List(items)) => Val::Num(usize_to_f64(items.len())),
            _ => Val::Num(usize_to_f64(first.len())),
        },
        Func::Count => Val::Num(usize_to_f64(first.matches(second().as_str()).count())),
        Func::Index => {
            let at = go_atoi(&second()).ok_or(EvalError::Argument)?;
            let at = usize::try_from(at).map_err(|_| EvalError::Argument)?;
            match values.first() {
                Some(Val::List(items)) => Val::Str(stringify(items.get(at).ok_or(EvalError::Argument)?)),
                _ => {
                    // the reference converts the selected byte to a character
                    let byte = *first.as_bytes().get(at).ok_or(EvalError::Argument)?;
                    Val::Str(char::from(byte).to_string())
                }
            }
        }
        Func::Substr => {
            if first.is_empty() {
                return Err(EvalError::Argument);
            }
            let start = go_atoi(&second()).ok_or(EvalError::Argument)?;
            let start = usize::try_from(start).map_err(|_| EvalError::Argument)?;
            if start > first.len() {
                return Err(EvalError::Argument);
            }
            let end = match values.get(2) {
                None => first.len(),
                Some(end) => {
                    let end = go_atoi(&stringify(end)).ok_or(EvalError::Argument)?;
                    let end = usize::try_from(end).map_err(|_| EvalError::Argument)?;
                    if end < start || end > first.len() {
                        return Err(EvalError::Argument);
                    }
                    end
                }
            };
            Val::Str(lossy(first.as_bytes()[start..end].to_vec()))
        }
        Func::ToLower => Val::Str(go_lower(&first)),
        Func::ToUpper => Val::Str(go_upper(&first)),
        Func::Trim
        | Func::TrimLeft
        | Func::TrimRight
        | Func::TrimSpace
        | Func::TrimPrefix
        | Func::TrimSuffix => trim(func, first, &second())?,
        Func::RemoveBadChars => {
            limit(first.len())?;
            let bad = second();
            Val::Str(first.chars().filter(|ch| !bad.contains(*ch)).collect())
        }
        Func::Reverse => {
            limit(first.len())?;
            Val::Str(first.chars().rev().collect())
        }
        Func::Repeat => {
            let count = go_atoi(&second()).ok_or(EvalError::Argument)?;
            let count = usize::try_from(count).map_err(|_| EvalError::Argument)?;
            limit(first.len().saturating_mul(count))?;
            Val::Str(first.repeat(count))
        }
        Func::Replace => {
            limit(first.len())?;
            Val::Str(replace_all(&first, &second(), &text_arg(&values, 2))?)
        }
        Func::ReplaceRegex => {
            limit(first.len())?;
            let mut owned = None;
            let re = regex_for(func, &values, compiled, &mut owned)?;
            Val::Str(replace_regex(&first, re, &text_arg(&values, 2))?)
        }
        Func::Concat => {
            let mut out = first;
            for part in rest(1) {
                out.push_str(&part);
                limit(out.len())?;
            }
            Val::Str(out)
        }
        Func::Join => {
            let sep = first;
            let mut parts: Vec<String> = Vec::new();
            if values.len() == 2 {
                match &values[1] {
                    Val::List(items) => parts.extend(items.iter().map(stringify)),
                    _ => return Err(EvalError::Argument),
                }
            } else {
                for value in values.iter().skip(1) {
                    if matches!(value, Val::List(_)) {
                        return Err(EvalError::Argument);
                    }
                    parts.push(stringify(value));
                }
            }
            let total: usize =
                parts.iter().map(String::len).sum::<usize>() + sep.len().saturating_mul(parts.len());
            limit(total)?;
            Val::Str(parts.join(&sep))
        }
        Func::Split => {
            limit(first.len())?;
            let second = second();
            match values.len() {
                2 => match go_atoi(&second) {
                    Some(size) => list_of(chunks(&first, size)?)?,
                    None => list_of(split_n(&first, &second, -1)?)?,
                },
                _ => {
                    let n = go_atoi(&text_arg(&values, 2)).ok_or(EvalError::Argument)?;
                    list_of(split_n(&first, &second, n)?)?
                }
            }
        }
        Func::Sort | Func::Uniq => {
            if values.len() == 1 {
                limit(first.len())?;
                let mut chars: Vec<char> = first.chars().collect();
                if func == Func::Sort {
                    chars.sort_unstable();
                } else {
                    let mut seen = BTreeSet::new();
                    chars.retain(|ch| seen.insert(*ch));
                }
                Val::Str(chars.into_iter().collect())
            } else {
                let mut tokens: Vec<String> = std::iter::once(first).chain(rest(1)).collect();
                if func == Func::Sort {
                    tokens.sort_unstable();
                } else {
                    let mut seen = BTreeSet::new();
                    tokens.retain(|token| seen.insert(token.clone()));
                }
                list_of(tokens)?
            }
        }
        Func::ToString => Val::Str(first),
        Func::ToNumber => to_number(&first)?,
        Func::Base64 => {
            limit(first.len())?;
            Val::Str(STANDARD.encode(first.as_bytes()))
        }
        Func::Base64Decode => {
            limit(first.len())?;
            let cleaned: String = first.chars().filter(|ch| !matches!(ch, '\r' | '\n')).collect();
            let bytes = go_base64().decode(cleaned).map_err(|_| EvalError::Argument)?;
            Val::Str(lossy(bytes))
        }
        Func::HexEncode => {
            // the reference encodes strings only: any other value is the empty string
            let text = match values.first() {
                Some(Val::Str(_)) | None => &first,
                Some(_) => "",
            };
            limit(text.len())?;
            let plain = hex_of(text.as_bytes());
            let escaped = values
                .get(1)
                .is_some_and(|f| stringify(f).eq_ignore_ascii_case("x"));
            if escaped {
                Val::Str(
                    plain
                        .as_bytes()
                        .chunks(2)
                        .filter_map(|pair| std::str::from_utf8(pair).ok())
                        .fold(String::new(), |mut out, pair| {
                            out.push_str("\\x");
                            out.push_str(pair);
                            out
                        }),
                )
            } else {
                Val::Str(plain)
            }
        }
        Func::HexDecode => {
            limit(first.len())?;
            Val::Str(lossy(
                hex::decode(first.as_bytes()).map_err(|_| EvalError::Argument)?,
            ))
        }
        Func::UrlEncode => {
            limit(first.len())?;
            let all = matches!(values.get(1), Some(Val::Bool(true)));
            Val::Str(url_encode(&first, all)?)
        }
        Func::UrlDecode => {
            limit(first.len())?;
            Val::Str(url_decode(&first))
        }
        Func::Sha1 => {
            limit(first.len())?;
            Val::Str(hex_of(&sha1::Sha1::digest(first.as_bytes())))
        }
        Func::Sha256 => {
            limit(first.len())?;
            Val::Str(hex_of(&sha2::Sha256::digest(first.as_bytes())))
        }
        Func::Sha512 => {
            limit(first.len())?;
            Val::Str(hex_of(&sha2::Sha512::digest(first.as_bytes())))
        }
    })
}
