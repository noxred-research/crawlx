//! Bounded secret inspection across arbitrary input chunk boundaries.
//!
//! This scanner validates one immutable secret snapshot, not publication authority.
//! Callers must consume the complete source, call `finish`, and atomically recheck
//! the snapshot epoch before publication. No chunk, partial result, or dropped
//! scanner approves output. Owned literal and decoded-key buffers are zeroized.
//! JSON object names are compared after decoding, without retaining value bodies.
//! Limits refuse ambiguous/unbounded input; they never downgrade JSON to binary.
//!
//! This is only the scoped literal check. It does not replace the global
//! redactor's credential syntax, sensitive-name, query or canonical-schema
//! policies, does not inspect compressed archive members, and never constructs
//! `Redacted` or implements `SecretFree`. Those boundaries remain mandatory.

use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Interpretation of the source representation, independent of transport chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretScanMode {
    /// Preserve byte inspection policy: inspect valid JSON and otherwise raw bytes.
    Auto,
    /// Require a complete JSON document with unique decoded object names.
    Json,
}

/// Fixed memory and source ceilings for incremental secret inspection.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SecretScanLimits {
    /// Maximum total source bytes; checked before processing each input chunk.
    pub max_bytes: u64,
    /// Maximum JSON container nesting.
    pub max_depth: usize,
    /// Maximum simultaneously retained decoded object names.
    pub max_keys: usize,
    /// Maximum simultaneously retained decoded object-name bytes.
    pub max_key_bytes: usize,
}

impl SecretScanLimits {
    /// Set source size and bounded JSON bookkeeping (128 levels, 4096 names, 1 MiB).
    #[must_use]
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            max_depth: 128,
            max_keys: 4096,
            max_key_bytes: 1024 * 1024,
        }
    }
}

/// Secret inspection failure; messages never include source bytes or secret values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretScanError {
    /// Raw bytes or a decoded JSON string contain a scoped literal.
    #[error("scoped secret detected")]
    Secret,
    /// Two names in the same object decode to identical bytes.
    #[error("duplicate JSON object name")]
    DuplicateName,
    /// Required JSON is malformed, truncated or has trailing data.
    #[error("invalid JSON secret inspection source")]
    InvalidJson,
    /// Source, snapshot or parser bookkeeping exceeded its fixed ceiling.
    #[error("secret inspection limit exceeded")]
    Limit,
    /// A failed scanner cannot later approve another prefix or suffix.
    #[error("secret inspection already failed")]
    Aborted,
}

struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    prefix: Vec<usize>,
    raw: usize,
    decoded: usize,
}

impl Pattern {
    fn new(bytes: &[u8]) -> Self {
        let mut prefix = vec![0; bytes.len()];
        let mut matched = 0;
        for index in 1..bytes.len() {
            while matched != 0 && bytes[index] != bytes[matched] {
                matched = prefix[matched - 1];
            }
            if bytes[index] == bytes[matched] {
                matched += 1;
            }
            prefix[index] = matched;
        }
        Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            prefix,
            raw: 0,
            decoded: 0,
        }
    }

    fn advance(&mut self, byte: u8, decoded: bool) -> bool {
        let state = if decoded { &mut self.decoded } else { &mut self.raw };
        while *state != 0 && self.bytes[*state] != byte {
            *state = self.prefix[*state - 1];
        }
        if self.bytes[*state] == byte {
            *state += 1;
        }
        if *state == self.bytes.len() {
            *state = self.prefix[*state - 1];
            true
        } else {
            false
        }
    }
}

/// Single-use, bounded scanner of raw bytes and decoded JSON string values/names.
/// No method releases source bytes or a reusable approval token.
///
/// This scanner is not an artifact approval wrapper:
///
/// ```compile_fail
/// use crawlx_core::secret::{SecretByteScanner, SecretFree};
/// fn approved<T: SecretFree>(_: T) {}
/// fn cannot_publish(scanner: SecretByteScanner) {
///     approved(scanner);
/// }
/// ```
#[must_use]
#[non_exhaustive]
pub struct SecretByteScanner {
    patterns: Vec<Pattern>,
    json: Option<JsonScanner>,
    mode: SecretScanMode,
    limits: SecretScanLimits,
    bytes: u64,
    failed: bool,
    decoded_secret: bool,
}

impl SecretByteScanner {
    pub(crate) fn from_literals<'a>(
        literals: impl IntoIterator<Item = &'a [u8]>,
        mode: SecretScanMode,
        limits: SecretScanLimits,
    ) -> Result<Self, SecretScanError> {
        let mut patterns = Vec::new();
        let mut total = 0usize;
        for literal in literals {
            if literal.is_empty() {
                continue;
            }
            total = total.checked_add(literal.len()).ok_or(SecretScanError::Limit)?;
            // The authority admits 256 raw values plus their URL encodings.
            if literal.len() > 64 * 1024 || total > 4 * 1024 * 1024 || patterns.len() >= 512 {
                return Err(SecretScanError::Limit);
            }
            patterns.push(Pattern::new(literal));
        }
        Ok(Self {
            patterns,
            json: Some(JsonScanner::new()),
            mode,
            limits,
            bytes: 0,
            failed: false,
            decoded_secret: false,
        })
    }

    /// Inspect the next source chunk without retaining its body.
    ///
    /// # Errors
    /// Refuses raw scoped literals, duplicate JSON names, required malformed JSON,
    /// source/bookkeeping limits, and any use after an earlier error.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), SecretScanError> {
        if self.failed {
            return Err(SecretScanError::Aborted);
        }
        self.failed = true;
        let size = u64::try_from(bytes.len()).map_err(|_| SecretScanError::Limit)?;
        self.bytes = self.bytes.checked_add(size).ok_or(SecretScanError::Limit)?;
        if self.bytes > self.limits.max_bytes {
            return Err(SecretScanError::Limit);
        }
        for &byte in bytes {
            if self
                .patterns
                .iter_mut()
                .any(|pattern| pattern.advance(byte, false))
            {
                return Err(SecretScanError::Secret);
            }
            if let Some(json) = &mut self.json {
                let result = json.push(byte, &mut self.patterns, &mut self.decoded_secret, self.limits);
                match result {
                    Err(SecretScanError::InvalidJson) if self.mode == SecretScanMode::Auto => {
                        self.json = None;
                        self.decoded_secret = false;
                    }
                    other => other?,
                }
            }
        }
        self.failed = false;
        Ok(())
    }

    /// Finish exactly at physical EOF. Success concerns only this secret snapshot.
    ///
    /// # Errors
    /// Refuses a failed scanner, malformed/truncated required JSON, or a scoped
    /// literal decoded inside a complete JSON document. Callers must not approve
    /// an interrupted or partially consumed source by omitting this call.
    pub fn finish(mut self) -> Result<(), SecretScanError> {
        if self.failed {
            return Err(SecretScanError::Aborted);
        }
        if let Some(json) = &mut self.json {
            match json.finish() {
                Ok(()) if self.decoded_secret => return Err(SecretScanError::Secret),
                Err(SecretScanError::InvalidJson) if self.mode == SecretScanMode::Auto => {}
                other => other?,
            }
        }
        Ok(())
    }
}

// Prefix-table lengths encode literal structure. Erase them as well as raw bytes.
impl Drop for Pattern {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.prefix.zeroize();
        self.raw.zeroize();
        self.decoded.zeroize();
    }
}

#[derive(Clone, Copy)]
enum Position {
    Value,
    Done,
    ArrayFirst,
    ArrayNext,
    ArrayComma,
    ObjectFirst,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectComma,
}

struct Names {
    values: BTreeSet<SecretName>,
    bytes: usize,
}

struct SecretName(Zeroizing<Vec<u8>>);
impl PartialEq for SecretName {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}
impl Eq for SecretName {}
impl PartialOrd for SecretName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SecretName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_slice().cmp(other.0.as_slice())
    }
}

struct Container {
    position: Position,
    names: Option<Names>,
}

#[derive(Clone, Copy)]
enum Escape {
    None,
    Slash,
    Unicode { value: u16, digits: u8 },
    LowSlash(u16),
    LowU(u16),
    LowDigits { high: u16, value: u16, digits: u8 },
}

struct JsonString {
    key: Option<Zeroizing<Vec<u8>>>,
    escape: Escape,
    utf8_remaining: u8,
    next_min: u8,
    next_max: u8,
}

#[derive(Clone, Copy)]
enum NumberState {
    Minus,
    Zero,
    Integer,
    Dot,
    Fraction,
    Exponent,
    Sign,
    ExponentDigits,
}

impl NumberState {
    fn complete(self) -> bool {
        matches!(
            self,
            Self::Zero | Self::Integer | Self::Fraction | Self::ExponentDigits
        )
    }

    fn advance(self, byte: u8) -> Option<Self> {
        match (self, byte) {
            (Self::Minus, b'0') => Some(Self::Zero),
            (Self::Minus, b'1'..=b'9') => Some(Self::Integer),
            (Self::Integer, b'0'..=b'9') => Some(Self::Integer),
            (Self::Zero | Self::Integer, b'.') => Some(Self::Dot),
            (Self::Dot | Self::Fraction, b'0'..=b'9') => Some(Self::Fraction),
            (Self::Zero | Self::Integer | Self::Fraction, b'e' | b'E') => Some(Self::Exponent),
            (Self::Exponent, b'+' | b'-') => Some(Self::Sign),
            (Self::Exponent | Self::Sign | Self::ExponentDigits, b'0'..=b'9') => Some(Self::ExponentDigits),
            _ => None,
        }
    }
}

enum Token {
    None,
    String(JsonString),
    Literal { expected: &'static [u8], index: usize },
    Number(NumberState),
}

struct JsonScanner {
    root: Position,
    stack: Vec<Container>,
    token: Token,
    keys: usize,
    key_bytes: usize,
}

impl JsonScanner {
    fn new() -> Self {
        Self {
            root: Position::Value,
            stack: Vec::new(),
            token: Token::None,
            keys: 0,
            key_bytes: 0,
        }
    }

    fn position(&self) -> Position {
        self.stack
            .last()
            .map_or(self.root, |container| container.position)
    }

    fn set_position(&mut self, position: Position) {
        if let Some(container) = self.stack.last_mut() {
            container.position = position;
        } else {
            self.root = position;
        }
    }

    fn value_done(&mut self) -> Result<(), SecretScanError> {
        let next = match self.position() {
            Position::Value => Position::Done,
            Position::ArrayFirst | Position::ArrayNext => Position::ArrayComma,
            Position::ObjectValue => Position::ObjectComma,
            _ => return Err(SecretScanError::InvalidJson),
        };
        self.set_position(next);
        Ok(())
    }

    fn close(&mut self) -> Result<(), SecretScanError> {
        let container = self.stack.pop().ok_or(SecretScanError::InvalidJson)?;
        if let Some(names) = container.names {
            self.keys -= names.values.len();
            self.key_bytes -= names.bytes;
        }
        self.value_done()
    }

    fn push(
        &mut self,
        byte: u8,
        patterns: &mut [Pattern],
        decoded_secret: &mut bool,
        limits: SecretScanLimits,
    ) -> Result<(), SecretScanError> {
        match &mut self.token {
            Token::String(string) => {
                if string.push(byte, patterns, decoded_secret, self.key_bytes, limits)? {
                    let Token::String(string) = std::mem::replace(&mut self.token, Token::None) else {
                        return Err(SecretScanError::InvalidJson);
                    };
                    if let Some(key) = string.key {
                        let names = self
                            .stack
                            .last_mut()
                            .and_then(|container| container.names.as_mut())
                            .ok_or(SecretScanError::InvalidJson)?;
                        let key = SecretName(key);
                        let key_len = key.0.len();
                        self.keys = self.keys.checked_add(1).ok_or(SecretScanError::Limit)?;
                        self.key_bytes = self
                            .key_bytes
                            .checked_add(key_len)
                            .ok_or(SecretScanError::Limit)?;
                        if self.keys > limits.max_keys || self.key_bytes > limits.max_key_bytes {
                            return Err(SecretScanError::Limit);
                        }
                        if !names.values.insert(key) {
                            return Err(SecretScanError::DuplicateName);
                        }
                        names.bytes += key_len;
                        self.set_position(Position::ObjectColon);
                    } else {
                        self.value_done()?;
                    }
                }
                return Ok(());
            }
            Token::Literal { expected, index } => {
                if expected.get(*index) != Some(&byte) {
                    return Err(SecretScanError::InvalidJson);
                }
                *index += 1;
                if *index == expected.len() {
                    self.token = Token::None;
                    self.value_done()?;
                }
                return Ok(());
            }
            Token::Number(state) => {
                if let Some(next) = state.advance(byte) {
                    *state = next;
                    return Ok(());
                }
                if !state.complete() {
                    return Err(SecretScanError::InvalidJson);
                }
                self.token = Token::None;
                self.value_done()?;
                // A number's delimiter still belongs to the surrounding grammar.
            }
            Token::None => {}
        }
        if matches!(byte, b' ' | b'\r' | b'\n' | b'\t') {
            return Ok(());
        }
        match (self.position(), byte) {
            (Position::ArrayFirst | Position::ArrayComma, b']') => return self.close(),
            (Position::ObjectFirst | Position::ObjectComma, b'}') => return self.close(),
            (Position::ArrayComma, b',') => {
                self.set_position(Position::ArrayNext);
                return Ok(());
            }
            (Position::ObjectComma, b',') => {
                self.set_position(Position::ObjectKey);
                return Ok(());
            }
            (Position::ObjectColon, b':') => {
                self.set_position(Position::ObjectValue);
                return Ok(());
            }
            (Position::ObjectFirst | Position::ObjectKey, b'"') => {
                self.start_string(true, patterns);
                return Ok(());
            }
            (Position::Value | Position::ArrayFirst | Position::ArrayNext | Position::ObjectValue, _) => {}
            _ => return Err(SecretScanError::InvalidJson),
        }
        match byte {
            b'{' | b'[' => {
                if self.stack.len() >= limits.max_depth {
                    return Err(SecretScanError::Limit);
                }
                let object = byte == b'{';
                self.stack.push(Container {
                    position: if object {
                        Position::ObjectFirst
                    } else {
                        Position::ArrayFirst
                    },
                    names: object.then(|| Names {
                        values: BTreeSet::new(),
                        bytes: 0,
                    }),
                });
            }
            b'"' => self.start_string(false, patterns),
            b't' => {
                self.token = Token::Literal {
                    expected: b"true",
                    index: 1,
                }
            }
            b'f' => {
                self.token = Token::Literal {
                    expected: b"false",
                    index: 1,
                }
            }
            b'n' => {
                self.token = Token::Literal {
                    expected: b"null",
                    index: 1,
                }
            }
            b'-' => self.token = Token::Number(NumberState::Minus),
            b'0' => self.token = Token::Number(NumberState::Zero),
            b'1'..=b'9' => self.token = Token::Number(NumberState::Integer),
            _ => return Err(SecretScanError::InvalidJson),
        }
        Ok(())
    }

    fn start_string(&mut self, key: bool, patterns: &mut [Pattern]) {
        for pattern in patterns {
            pattern.decoded = 0;
        }
        self.token = Token::String(JsonString {
            key: key.then(|| Zeroizing::new(Vec::new())),
            escape: Escape::None,
            utf8_remaining: 0,
            next_min: 0x80,
            next_max: 0xbf,
        });
    }

    fn finish(&mut self) -> Result<(), SecretScanError> {
        if let Token::Number(state) = self.token {
            if !state.complete() {
                return Err(SecretScanError::InvalidJson);
            }
            self.token = Token::None;
            self.value_done()?;
        }
        if self.stack.is_empty() && matches!(self.token, Token::None) && matches!(self.root, Position::Done) {
            Ok(())
        } else {
            Err(SecretScanError::InvalidJson)
        }
    }
}

impl JsonString {
    fn emit(
        &mut self,
        byte: u8,
        patterns: &mut [Pattern],
        found: &mut bool,
        key_bytes: usize,
        limits: SecretScanLimits,
    ) -> Result<(), SecretScanError> {
        for pattern in patterns {
            *found |= pattern.advance(byte, true);
        }
        if let Some(key) = &mut self.key {
            push_secret_byte(key, byte, limits.max_key_bytes.saturating_sub(key_bytes))?;
        }
        Ok(())
    }

    fn push(
        &mut self,
        byte: u8,
        patterns: &mut [Pattern],
        found: &mut bool,
        key_bytes: usize,
        limits: SecretScanLimits,
    ) -> Result<bool, SecretScanError> {
        let scalar = match self.escape {
            Escape::None => {
                if self.utf8_remaining != 0 {
                    if byte < self.next_min || byte > self.next_max {
                        return Err(SecretScanError::InvalidJson);
                    }
                    self.utf8_remaining -= 1;
                    self.next_min = 0x80;
                    self.next_max = 0xbf;
                } else {
                    match byte {
                        b'"' => return Ok(true),
                        b'\\' => {
                            self.escape = Escape::Slash;
                            return Ok(false);
                        }
                        0..=0x1f => return Err(SecretScanError::InvalidJson),
                        0x20..=0x7f => {}
                        0xc2..=0xdf => self.utf8_remaining = 1,
                        0xe0..=0xef => {
                            self.utf8_remaining = 2;
                            self.next_min = if byte == 0xe0 { 0xa0 } else { 0x80 };
                            self.next_max = if byte == 0xed { 0x9f } else { 0xbf };
                        }
                        0xf0..=0xf4 => {
                            self.utf8_remaining = 3;
                            self.next_min = if byte == 0xf0 { 0x90 } else { 0x80 };
                            self.next_max = if byte == 0xf4 { 0x8f } else { 0xbf };
                        }
                        _ => return Err(SecretScanError::InvalidJson),
                    }
                }
                self.emit(byte, patterns, found, key_bytes, limits)?;
                return Ok(false);
            }
            Escape::Slash => {
                self.escape = Escape::None;
                match byte {
                    b'"' | b'\\' | b'/' => char::from(byte),
                    b'b' => '\u{0008}',
                    b'f' => '\u{000c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        self.escape = Escape::Unicode { value: 0, digits: 0 };
                        return Ok(false);
                    }
                    _ => return Err(SecretScanError::InvalidJson),
                }
            }
            Escape::Unicode { value, digits } => {
                let value = (value << 4) | hex(byte)?;
                if digits != 3 {
                    self.escape = Escape::Unicode {
                        value,
                        digits: digits + 1,
                    };
                    return Ok(false);
                }
                if (0xd800..=0xdbff).contains(&value) {
                    self.escape = Escape::LowSlash(value);
                    return Ok(false);
                }
                self.escape = Escape::None;
                char::from_u32(u32::from(value)).ok_or(SecretScanError::InvalidJson)?
            }
            Escape::LowSlash(high) => {
                if byte != b'\\' {
                    return Err(SecretScanError::InvalidJson);
                }
                self.escape = Escape::LowU(high);
                return Ok(false);
            }
            Escape::LowU(high) => {
                if byte != b'u' {
                    return Err(SecretScanError::InvalidJson);
                }
                self.escape = Escape::LowDigits {
                    high,
                    value: 0,
                    digits: 0,
                };
                return Ok(false);
            }
            Escape::LowDigits { high, value, digits } => {
                let value = (value << 4) | hex(byte)?;
                if digits != 3 {
                    self.escape = Escape::LowDigits {
                        high,
                        value,
                        digits: digits + 1,
                    };
                    return Ok(false);
                }
                if !(0xdc00..=0xdfff).contains(&value) {
                    return Err(SecretScanError::InvalidJson);
                }
                self.escape = Escape::None;
                let scalar = 0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(value) - 0xdc00);
                char::from_u32(scalar).ok_or(SecretScanError::InvalidJson)?
            }
        };
        let mut encoded = [0; 4];
        for &byte in scalar.encode_utf8(&mut encoded).as_bytes() {
            self.emit(byte, patterns, found, key_bytes, limits)?;
        }
        Ok(false)
    }
}
// Never let Vec reallocate a live decoded key: realloc may free unwiped prefixes.
// Geometric replacement avoids reserving the full run key budget for every name.
fn push_secret_byte(key: &mut Zeroizing<Vec<u8>>, byte: u8, maximum: usize) -> Result<(), SecretScanError> {
    use zeroize::Zeroize as _;
    if key.len() >= maximum {
        return Err(SecretScanError::Limit);
    }
    if key.len() == key.capacity() {
        let capacity = key.capacity().saturating_mul(2).max(32).min(maximum);
        let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
        replacement.extend_from_slice(key);
        key.zeroize();
        *key = replacement;
    }
    key.push(byte);
    Ok(())
}

fn hex(byte: u8) -> Result<u16, SecretScanError> {
    match byte {
        b'0'..=b'9' => Ok(u16::from(byte - b'0')),
        b'a'..=b'f' => Ok(u16::from(byte - b'a') + 10),
        b'A'..=b'F' => Ok(u16::from(byte - b'A') + 10),
        _ => Err(SecretScanError::InvalidJson),
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
