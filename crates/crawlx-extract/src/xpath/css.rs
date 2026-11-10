//! CSS selector lists with the `::text` and `::attr(name)` projections.
//!
//! Each top-level comma-separated selector may end in one projection. Elements are matched by the
//! standard CSS engine on the existing tree; the projection then selects the element's direct
//! text nodes or one attribute node. Any other pseudo-element is a typed unsupported-selector
//! error, never a silent empty match or a string rewrite of the expression.
use super::SelectorError;
use scraper::Selector;

/// Most comma-separated selectors in one CSS expression.
const MAX_PARTS: usize = 64;
/// Longest attribute name accepted by `::attr(name)`.
const MAX_ATTRIBUTE_NAME: usize = 128;

/// What a matched element contributes to the selected node set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Projection {
    /// The element itself.
    Elements,
    /// Direct child text nodes, in document order.
    Text,
    /// The named attribute node (ASCII case-insensitive local name).
    Attr(String),
}

/// One compiled selector of a CSS list.
#[derive(Debug, Clone)]
pub(super) struct Part {
    pub(super) selector: Selector,
    pub(super) projection: Projection,
}

/// Byte ranges of the top-level parts of `source` and the first top-level `::` in each.
fn scan(source: &str) -> Vec<(usize, usize, Option<usize>)> {
    let bytes = source.as_bytes();
    let mut parts = Vec::new();
    let (mut start, mut pseudo) = (0usize, None);
    let (mut quote, mut brackets, mut parens, mut escaped) = (None::<u8>, 0usize, 0usize, false);
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        if escaped {
            escaped = false;
        } else if let Some(open) = quote {
            if byte == b'\\' {
                escaped = true;
            } else if byte == open {
                quote = None;
            }
        } else {
            match byte {
                b'\\' => escaped = true,
                b'"' | b'\'' => quote = Some(byte),
                b'[' => brackets += 1,
                b']' => brackets = brackets.saturating_sub(1),
                b'(' => parens += 1,
                b')' => parens = parens.saturating_sub(1),
                b',' if brackets == 0 && parens == 0 => {
                    parts.push((start, i, pseudo.take()));
                    start = i + 1;
                }
                b':' if brackets == 0
                    && parens == 0
                    && pseudo.is_none()
                    && bytes.get(i + 1) == Some(&b':') =>
                {
                    pseudo = Some(i);
                    i += 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    parts.push((start, bytes.len(), pseudo));
    parts
}

/// Whether any top-level selector of `source` carries a pseudo-element.
pub(super) fn has_pseudo_element(source: &str) -> bool {
    scan(source).iter().any(|(_, _, pseudo)| pseudo.is_some())
}

fn projection(suffix: &str) -> Result<Projection, SelectorError> {
    let suffix = suffix.trim();
    if suffix.eq_ignore_ascii_case("::text") {
        return Ok(Projection::Text);
    }
    let unsupported = SelectorError::Unsupported("pseudo-element other than ::text and ::attr(name)");
    let Some(rest) = suffix
        .get(..7)
        .filter(|head| head.eq_ignore_ascii_case("::attr("))
    else {
        return Err(unsupported);
    };
    let Some(inner) = suffix[rest.len()..].strip_suffix(')') else {
        return Err(unsupported);
    };
    let inner = inner.trim();
    let name = match inner.as_bytes() {
        [quote @ (b'"' | b'\''), .., last] if last == quote && inner.len() >= 2 => &inner[1..inner.len() - 1],
        _ => inner,
    };
    if name.is_empty()
        || name.len() > MAX_ATTRIBUTE_NAME
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
    {
        return Err(SelectorError::Syntax);
    }
    Ok(Projection::Attr(name.to_owned()))
}

/// Compile a CSS selector list, splitting trailing `::text`/`::attr(name)` projections.
///
/// # Errors
/// `Unsupported` for any other pseudo-element, `Syntax` for invalid CSS or attribute names,
/// `Budget` for more than 64 selectors.
pub(super) fn compile(source: &str) -> Result<Vec<Part>, SelectorError> {
    let ranges = scan(source);
    if ranges.len() > MAX_PARTS {
        return Err(SelectorError::Budget("css selector list"));
    }
    let mut parts = Vec::with_capacity(ranges.len());
    for (start, end, pseudo) in ranges {
        let (base, projection) = match pseudo {
            Some(at) => (&source[start..at], projection(&source[at..end])?),
            None => (&source[start..end], Projection::Elements),
        };
        let base = base.trim();
        let base = if base.is_empty() && projection != Projection::Elements {
            "*"
        } else {
            base
        };
        let selector = Selector::parse(base).map_err(|_| SelectorError::Syntax)?;
        parts.push(Part { selector, projection });
    }
    Ok(parts)
}
