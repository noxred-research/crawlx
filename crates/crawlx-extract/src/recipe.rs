//! Declarative storefront recipe: collection/product JSON bodies in, one item per variant out.
//!
//! The recipe is plain data ([`StorefrontRecipeV1`], serializable, digest-pinned). Evaluation is
//! a pure function of locally supplied JSON bodies: there is no expression language, no fetch,
//! no write path and no code execution. Field locations are bounded dotted paths
//! (`a.b[0].c`); nothing else can be selected.
//!
//! Prices are decimal *strings*. A decimal field accepts a JSON string of digits (`19.99`) or a
//! JSON integer; a JSON floating point number is refused as a typed fault so that no float ever
//! decides a price. Integer minor units (`1999` at exponent 2) are converted with integer
//! arithmetic only. Identifiers are emitted as strings whether the source used numbers or strings.
//!
//! Pagination is an explicit output: after each page the evaluator may emit one
//! [`DiscoveryIntentV1`] ([`DiscoveryPurposeV1::ReadMoreReference`]) naming the next page, which
//! must stay on the origin of the page it came from. A worker decides whether to fetch it; the
//! caller then supplies the next body to [`CompiledStorefront::extract_pages`].

use crawlx_core::extraction::{DiscoveryIntentV1, DiscoveryPurposeV1};
use crawlx_core::hash::Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use url::Url;

/// Domain tag of [`CompiledStorefront::digest`].
pub const RECIPE_DIGEST_DOMAIN: &str = "crawlx.recipe.storefront.v1";
const MAX_PATH_SEGMENTS: usize = 8;
const MAX_KEY_BYTES: usize = 64;
const MAX_FIELDS: usize = 64;
const MAX_PRODUCTS_PER_PAGE: usize = 10_000;
const MAX_ITEMS: usize = 100_000;
const MAX_PAGES: usize = 1_000;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_DECIMAL_BYTES: usize = 40;
const MAX_MINOR_EXPONENT: u8 = 18;
const MAX_PAGE_NUMBER: u32 = 100_000;

/// How one source value becomes an output field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FieldKindV1 {
    /// Identifier: non-empty string or integer, emitted as a string.
    Id,
    /// UTF-8 text.
    Text,
    /// Boolean.
    Bool,
    /// Decimal string (`-?digits[.digits]`) or JSON integer; floats are refused.
    Decimal,
    /// JSON integer in minor units, emitted as a decimal string with `exponent` fraction digits.
    MinorUnits {
        /// Number of fraction digits, at most 18.
        exponent: u8,
    },
}

/// One output field and where to read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecipeFieldV1 {
    /// Output field name; unique across product and variant fields.
    pub name: String,
    /// Bounded dotted path relative to the product (or variant) object.
    pub path: String,
    /// Value interpretation.
    pub kind: FieldKindV1,
    /// A missing or null value rejects the variant; otherwise it is emitted as `null`.
    #[serde(default)]
    pub required: bool,
}

impl RecipeFieldV1 {
    /// Optional field.
    #[must_use]
    pub fn new(name: &str, path: &str, kind: FieldKindV1) -> Self {
        Self {
            name: name.to_owned(),
            path: path.to_owned(),
            kind,
            required: false,
        }
    }

    /// Mark the field required.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// How the next page is announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum NextPageV1 {
    /// The body holds the next page reference (absolute or relative) at `path`.
    Field {
        /// Path of the string holding the reference.
        path: String,
    },
    /// Page-number query parameter: when a page holds at least `per_page` products the next page
    /// is the same URL with `param` incremented (an absent parameter counts as page 1).
    Param {
        /// Query parameter name.
        param: String,
        /// Full-page product count, at least 1.
        per_page: u32,
    },
}

/// Declarative recipe, version one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StorefrontRecipeV1 {
    /// Exactly one.
    pub version: u16,
    /// Path of the product array in a page body (empty: the body itself).
    pub products: String,
    /// Path of the variant array inside a product.
    pub variants: String,
    /// Fields read from each product.
    pub product_fields: Vec<RecipeFieldV1>,
    /// Fields read from each variant.
    pub variant_fields: Vec<RecipeFieldV1>,
    /// Pagination, if the source paginates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page: Option<NextPageV1>,
}

impl StorefrontRecipeV1 {
    /// The common collection layout: `products[]` each with `variants[]`, ids, titles and
    /// decimal-string prices, paginated by a `page` query parameter of 250 products.
    #[must_use]
    pub fn collection_products() -> Self {
        use FieldKindV1::{Bool, Decimal, Id, Text};
        // wire-compat: field names of the common storefront collection JSON layout
        Self {
            version: 1,
            products: "products".to_owned(),
            variants: "variants".to_owned(),
            product_fields: vec![
                RecipeFieldV1::new("product_id", "id", Id).required(),
                RecipeFieldV1::new("handle", "handle", Text),
                RecipeFieldV1::new("title", "title", Text),
                RecipeFieldV1::new("vendor", "vendor", Text),
                RecipeFieldV1::new("product_type", "product_type", Text),
            ],
            variant_fields: vec![
                RecipeFieldV1::new("variant_id", "id", Id).required(),
                RecipeFieldV1::new("sku", "sku", Text),
                RecipeFieldV1::new("variant_title", "title", Text),
                RecipeFieldV1::new("price", "price", Decimal).required(),
                RecipeFieldV1::new("compare_at_price", "compare_at_price", Decimal),
                RecipeFieldV1::new("available", "available", Bool),
            ],
            next_page: Some(NextPageV1::Param {
                param: "page".to_owned(),
                per_page: 250,
            }),
        }
    }

    /// Validate and compile the recipe.
    ///
    /// # Errors
    /// Returns [`RecipeError::Invalid`] for an unsupported version, bad paths, duplicate or empty
    /// field names or out-of-range options.
    pub fn compile(&self) -> Result<CompiledStorefront, RecipeError> {
        let invalid = |reason: &'static str| RecipeError::Invalid(reason);
        if self.version != 1 {
            return Err(invalid("unsupported recipe version"));
        }
        if self.product_fields.len() + self.variant_fields.len() > MAX_FIELDS {
            return Err(invalid("too many fields"));
        }
        let mut names = BTreeSet::new();
        let compile_fields = |fields: &[RecipeFieldV1], names: &mut BTreeSet<String>| {
            fields
                .iter()
                .map(|field| {
                    if field.name.is_empty() || field.name.len() > MAX_KEY_BYTES {
                        return Err(invalid("field name is empty or too long"));
                    }
                    if !names.insert(field.name.clone()) {
                        return Err(invalid("duplicate field name"));
                    }
                    if let FieldKindV1::MinorUnits { exponent } = field.kind {
                        if exponent > MAX_MINOR_EXPONENT {
                            return Err(invalid("minor unit exponent too large"));
                        }
                    }
                    Ok(CompiledField {
                        name: field.name.clone(),
                        path: parse_path(&field.path)?,
                        kind: field.kind.clone(),
                        required: field.required,
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let product_fields = compile_fields(&self.product_fields, &mut names)?;
        let variant_fields = compile_fields(&self.variant_fields, &mut names)?;
        let next = match &self.next_page {
            None => None,
            Some(NextPageV1::Field { path }) => Some(CompiledNext::Field(parse_path(path)?)),
            Some(NextPageV1::Param { param, per_page }) => {
                if param.is_empty() || param.len() > MAX_KEY_BYTES || *per_page == 0 {
                    return Err(invalid("invalid page parameter"));
                }
                Some(CompiledNext::Param {
                    param: param.clone(),
                    per_page: usize::try_from(*per_page).unwrap_or(usize::MAX),
                })
            }
        };
        let digest = Digest::of_value(RECIPE_DIGEST_DOMAIN, self)
            .map_err(|_| invalid("recipe is not serializable"))?;
        Ok(CompiledStorefront {
            digest,
            products: parse_path(&self.products)?,
            variants: parse_path(&self.variants)?,
            product_fields,
            variant_fields,
            next,
        })
    }

    /// Compile and require the recipe to match a pinned digest.
    ///
    /// # Errors
    /// [`RecipeError::DigestMismatch`] when the compiled digest differs, plus [`Self::compile`]'s.
    pub fn compile_pinned(&self, expected: &Digest) -> Result<CompiledStorefront, RecipeError> {
        let compiled = self.compile()?;
        if compiled.digest != *expected {
            return Err(RecipeError::DigestMismatch);
        }
        Ok(compiled)
    }
}

/// Recipe compilation or evaluation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecipeError {
    /// The recipe is not acceptable.
    #[error("invalid storefront recipe: {0}")]
    Invalid(&'static str),
    /// The recipe does not match the pinned digest.
    #[error("storefront recipe digest does not match the pin")]
    DigestMismatch,
    /// The product path does not lead to an array in this body.
    #[error("page body has no product array at the recipe path")]
    ProductsNotArray,
    /// A bound on products, items or pages was exceeded.
    #[error("storefront recipe limit exceeded: {0}")]
    Limit(&'static str),
}

/// Why one variant (or product) produced no item.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecipeFault {
    /// The product is not a JSON object.
    #[error("product is not an object")]
    ProductNotObject,
    /// The product has no variant array.
    #[error("product has no variant array")]
    VariantsMissing,
    /// The variant is not a JSON object.
    #[error("variant is not an object")]
    VariantNotObject,
    /// A required field is missing or null.
    #[error("required field `{0}` is missing")]
    MissingField(String),
    /// A value has the wrong JSON type or is out of bounds.
    #[error("field `{0}` has an invalid value")]
    InvalidValue(String),
    /// A decimal field holds a floating point number.
    #[error("field `{0}` is a floating point number; decimal strings are required")]
    FloatNumber(String),
    /// A decimal string is malformed.
    #[error("field `{0}` is not a decimal string")]
    InvalidDecimal(String),
}

/// A product or variant that produced no item.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecipeRejection {
    /// Zero-based product position within its page.
    pub product: usize,
    /// Zero-based variant position, absent for product-level faults.
    pub variant: Option<usize>,
    /// Reason.
    pub fault: RecipeFault,
}

/// Result of one page.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct StorefrontPage {
    /// One JSON object per variant, in source order.
    pub items: Vec<Value>,
    /// Products/variants that were skipped, with the reason.
    pub rejected: Vec<RecipeRejection>,
    /// Next page reference, never fetched by the extractor.
    pub next: Option<DiscoveryIntentV1>,
}

/// Result of several pages.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct StorefrontOutput {
    /// Items of every page in order, without repeats.
    pub items: Vec<Value>,
    /// Rejections with page-relative positions, tagged by page index.
    pub rejected: Vec<(usize, RecipeRejection)>,
    /// Items dropped because an earlier page already produced the same id tuple.
    pub duplicates: usize,
    /// Next-page reference announced by the last page.
    pub next: Option<DiscoveryIntentV1>,
    /// Pages evaluated.
    pub pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(usize),
}

fn parse_path(source: &str) -> Result<Vec<Segment>, RecipeError> {
    let bad = || RecipeError::Invalid("invalid field path");
    let mut segments = Vec::new();
    let bytes = source.as_bytes();
    let mut position = 0;
    let mut expect_key = true;
    while position < bytes.len() {
        if bytes[position] == b'.' {
            if expect_key {
                return Err(bad());
            }
            position += 1;
            expect_key = true;
            if position == bytes.len() {
                return Err(bad());
            }
            continue;
        }
        if bytes[position] == b'[' {
            let close = source[position..].find(']').ok_or_else(bad)? + position;
            let index = source[position + 1..close].parse::<usize>().map_err(|_| bad())?;
            segments.push(Segment::Index(index));
            position = close + 1;
            expect_key = false;
        } else if expect_key {
            let end = source[position..]
                .find(['.', '['])
                .map_or(source.len(), |offset| position + offset);
            let key = &source[position..end];
            if key.is_empty()
                || key.len() > MAX_KEY_BYTES
                || key.contains(']')
                || key.chars().any(char::is_control)
            {
                return Err(bad());
            }
            segments.push(Segment::Key(key.to_owned()));
            position = end;
            expect_key = false;
        } else {
            return Err(bad());
        }
        if segments.len() > MAX_PATH_SEGMENTS {
            return Err(bad());
        }
    }
    Ok(segments)
}

fn lookup<'a>(root: &'a Value, path: &[Segment]) -> Option<&'a Value> {
    path.iter().try_fold(root, |value, segment| match segment {
        Segment::Key(key) => value.as_object()?.get(key),
        Segment::Index(index) => value.as_array()?.get(*index),
    })
}

#[derive(Debug, Clone)]
struct CompiledField {
    name: String,
    path: Vec<Segment>,
    kind: FieldKindV1,
    required: bool,
}

#[derive(Debug, Clone)]
enum CompiledNext {
    Field(Vec<Segment>),
    Param { param: String, per_page: usize },
}

/// Validated recipe ready to evaluate bodies.
#[derive(Debug, Clone)]
pub struct CompiledStorefront {
    digest: Digest,
    products: Vec<Segment>,
    variants: Vec<Segment>,
    product_fields: Vec<CompiledField>,
    variant_fields: Vec<CompiledField>,
    next: Option<CompiledNext>,
}

fn is_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let (whole, fraction) = digits
        .split_once('.')
        .map_or((digits, None), |(w, f)| (w, Some(f)));
    text.len() <= MAX_DECIMAL_BYTES
        && !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

fn minor_units(value: i64, exponent: u8) -> String {
    let negative = value < 0;
    let mut digits = value.unsigned_abs().to_string();
    let exponent = usize::from(exponent);
    if exponent > 0 {
        if digits.len() <= exponent {
            digits = format!("{}{digits}", "0".repeat(exponent + 1 - digits.len()));
        }
        digits.insert(digits.len() - exponent, '.');
    }
    if negative {
        digits.insert(0, '-');
    }
    digits
}

fn convert(field: &CompiledField, value: Option<&Value>) -> Result<Value, RecipeFault> {
    let name = || field.name.clone();
    let value = match value {
        None | Some(Value::Null) => {
            return if field.required {
                Err(RecipeFault::MissingField(name()))
            } else {
                Ok(Value::Null)
            };
        }
        Some(value) => value,
    };
    match (&field.kind, value) {
        (FieldKindV1::Id, Value::String(id)) if !id.is_empty() && id.len() <= MAX_ID_BYTES => {
            Ok(Value::String(id.clone()))
        }
        (FieldKindV1::Id, Value::Number(number)) if number.is_i64() || number.is_u64() => {
            Ok(Value::String(number.to_string()))
        }
        (FieldKindV1::Text, Value::String(text)) if text.len() <= MAX_TEXT_BYTES => {
            Ok(Value::String(text.clone()))
        }
        (FieldKindV1::Bool, Value::Bool(flag)) => Ok(Value::Bool(*flag)),
        (FieldKindV1::Decimal, Value::String(text)) => {
            if is_decimal(text) {
                Ok(Value::String(text.clone()))
            } else {
                Err(RecipeFault::InvalidDecimal(name()))
            }
        }
        (FieldKindV1::Decimal, Value::Number(number)) => {
            if number.is_i64() || number.is_u64() {
                Ok(Value::String(number.to_string()))
            } else {
                Err(RecipeFault::FloatNumber(name()))
            }
        }
        (FieldKindV1::MinorUnits { exponent }, Value::Number(number)) => match number.as_i64() {
            Some(units) => Ok(Value::String(minor_units(units, *exponent))),
            None if number.is_f64() => Err(RecipeFault::FloatNumber(name())),
            None => Err(RecipeFault::InvalidValue(name())),
        },
        _ => Err(RecipeFault::InvalidValue(name())),
    }
}

fn read_fields(
    fields: &[CompiledField],
    source: &Value,
    out: &mut Map<String, Value>,
) -> Result<(), RecipeFault> {
    for field in fields {
        out.insert(field.name.clone(), convert(field, lookup(source, &field.path))?);
    }
    Ok(())
}

fn origin(url: &Url) -> (&str, Option<&str>, Option<u16>) {
    (url.scheme(), url.host_str(), url.port_or_known_default())
}

impl CompiledStorefront {
    /// Digest of the recipe this evaluator was compiled from.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest
    }

    fn next_intent(&self, page: &Url, body: &Value, products: usize) -> Option<DiscoveryIntentV1> {
        let next = match self.next.as_ref()? {
            CompiledNext::Field(path) => {
                let reference = lookup(body, path)?.as_str()?.trim();
                if reference.is_empty() {
                    return None;
                }
                page.join(reference).ok()?
            }
            CompiledNext::Param { param, per_page } => {
                if products < *per_page {
                    return None;
                }
                let current = page
                    .query_pairs()
                    .find(|(key, _)| key == param.as_str())
                    .map_or(Some(1), |(_, value)| value.parse::<u32>().ok())?;
                let upcoming = current
                    .checked_add(1)
                    .filter(|number| *number <= MAX_PAGE_NUMBER)?;
                let mut next = page.clone();
                let kept: Vec<(String, String)> = page
                    .query_pairs()
                    .filter(|(key, _)| key != param.as_str())
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect();
                {
                    let mut pairs = next.query_pairs_mut();
                    pairs.clear();
                    pairs.extend_pairs(kept.iter().map(|(key, value)| (key.as_str(), value.as_str())));
                    pairs.append_pair(param, &upcoming.to_string());
                }
                next
            }
        };
        let mut next = next;
        next.set_fragment(None);
        if !matches!(next.scheme(), "http" | "https")
            || !next.username().is_empty()
            || next.password().is_some()
            || origin(&next) != origin(page)
            || next == *page
        {
            return None;
        }
        Some(DiscoveryIntentV1::new(
            next,
            DiscoveryPurposeV1::ReadMoreReference,
        ))
    }

    /// Evaluate one page body fetched from `page`.
    ///
    /// # Errors
    /// [`RecipeError::ProductsNotArray`] when the body has no product array at the recipe path,
    /// [`RecipeError::Limit`] past the product or item bounds.
    pub fn extract_page(&self, page: &Url, body: &Value) -> Result<StorefrontPage, RecipeError> {
        let products = lookup(body, &self.products)
            .and_then(Value::as_array)
            .ok_or(RecipeError::ProductsNotArray)?;
        if products.len() > MAX_PRODUCTS_PER_PAGE {
            return Err(RecipeError::Limit("products per page"));
        }
        let mut items = Vec::new();
        let mut rejected = Vec::new();
        for (product_index, product) in products.iter().enumerate() {
            let reject = |variant, fault| RecipeRejection {
                product: product_index,
                variant,
                fault,
            };
            if !product.is_object() {
                rejected.push(reject(None, RecipeFault::ProductNotObject));
                continue;
            }
            let mut shared = Map::new();
            if let Err(fault) = read_fields(&self.product_fields, product, &mut shared) {
                rejected.push(reject(None, fault));
                continue;
            }
            let Some(variants) = lookup(product, &self.variants).and_then(Value::as_array) else {
                rejected.push(reject(None, RecipeFault::VariantsMissing));
                continue;
            };
            for (variant_index, variant) in variants.iter().enumerate() {
                if !variant.is_object() {
                    rejected.push(reject(Some(variant_index), RecipeFault::VariantNotObject));
                    continue;
                }
                let mut item = shared.clone();
                match read_fields(&self.variant_fields, variant, &mut item) {
                    Ok(()) => {
                        if items.len() >= MAX_ITEMS {
                            return Err(RecipeError::Limit("items"));
                        }
                        items.push(Value::Object(item));
                    }
                    Err(fault) => rejected.push(reject(Some(variant_index), fault)),
                }
            }
        }
        Ok(StorefrontPage {
            next: self.next_intent(page, body, products.len()),
            items,
            rejected,
        })
    }

    /// Evaluate pages in order and merge them; an item whose id fields repeat an earlier item
    /// (overlapping pages) is dropped and counted.
    ///
    /// # Errors
    /// Same as [`Self::extract_page`] for any page, plus a bound on the page count.
    pub fn extract_pages(&self, pages: &[(Url, Value)]) -> Result<StorefrontOutput, RecipeError> {
        if pages.len() > MAX_PAGES {
            return Err(RecipeError::Limit("pages"));
        }
        let id_fields: Vec<&str> = self
            .product_fields
            .iter()
            .chain(&self.variant_fields)
            .filter(|field| field.kind == FieldKindV1::Id)
            .map(|field| field.name.as_str())
            .collect();
        let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
        let mut output = StorefrontOutput {
            items: Vec::new(),
            rejected: Vec::new(),
            duplicates: 0,
            next: None,
            pages: 0,
        };
        for (page_index, (url, body)) in pages.iter().enumerate() {
            let page = self.extract_page(url, body)?;
            output.pages += 1;
            output
                .rejected
                .extend(page.rejected.into_iter().map(|rejection| (page_index, rejection)));
            for item in page.items {
                let key: Vec<String> = id_fields
                    .iter()
                    .map(|name| item.get(*name).and_then(Value::as_str).unwrap_or("").to_owned())
                    .collect();
                if !id_fields.is_empty() && !seen.insert(key) {
                    output.duplicates += 1;
                } else if output.items.len() >= MAX_ITEMS {
                    return Err(RecipeError::Limit("items"));
                } else {
                    output.items.push(item);
                }
            }
            output.next = page.next;
        }
        Ok(output)
    }
}
