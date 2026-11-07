//! Offline, budgeted JSON Schema assertions for item recipes.
//! Supported vocabulary is explicit; unsupported keywords reject compilation rather than passing validation.
use crate::xpath::{SelectorDocument, SelectorError};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
pub(super) trait WorkBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), SelectorError>;
}
impl WorkBudget for SelectorDocument<'_> {
    fn charge(&mut self, bytes: usize) -> Result<(), SelectorError> {
        SelectorDocument::charge(self, bytes)
    }
}
#[derive(Default)]
pub(super) struct ProjectionBudget {
    operations: usize,
}
impl WorkBudget for ProjectionBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), SelectorError> {
        self.operations = self.operations.saturating_add(bytes);
        if self.operations > crawlx_core::selectors::MAX_OPERATIONS {
            Err(SelectorError::Budget("item projection operations"))
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
pub(super) struct Schema {
    rules: Vec<Rule>,
}
#[derive(Debug)]
enum Rule {
    Bool(bool),
    Type(Vec<String>),
    Enum(Vec<Value>),
    Const(Value),
    Number(&'static str, serde_json::Number),
    Length(&'static str, usize),
    Pattern(Regex, usize),
    Required(Vec<String>),
    Properties(
        BTreeMap<String, Schema>,
        Vec<(Regex, usize, Schema)>,
        Option<Box<Schema>>,
    ),
    PropertyNames(Box<Schema>),
    Items(Vec<Schema>, Option<Box<Schema>>),
    Contains(Box<Schema>, usize, Option<usize>),
    Unique,
    Group(&'static str, Vec<Schema>),
    Not(Box<Schema>),
    Conditional(Box<Schema>, Option<Box<Schema>>, Option<Box<Schema>>),
    DependentRequired(BTreeMap<String, Vec<String>>),
    DependentSchemas(BTreeMap<String, Schema>),
}
fn bad(message: &'static str) -> SelectorError {
    SelectorError::Schema(message)
}
struct Compiler<'a> {
    registry: &'a BTreeMap<String, Value>,
    active: BTreeSet<String>,
    nodes: usize,
    literal_bytes: usize,
}
pub(super) fn compile_registry(
    key: &str,
    registry: &BTreeMap<String, Value>,
) -> Result<Schema, SelectorError> {
    let value = registry.get(key).ok_or_else(|| bad("missing root schema"))?;
    let mut compiler = Compiler {
        registry,
        active: BTreeSet::new(),
        nodes: 0,
        literal_bytes: 0,
    };
    compiler.compile(value, value, key, 0)
}
fn string_list(value: &Value) -> Result<Vec<String>, SelectorError> {
    value
        .as_array()
        .ok_or_else(|| bad("expected string array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad("expected string"))
        })
        .collect()
}
fn count(value: &Value) -> Result<usize, SelectorError> {
    usize::try_from(
        value
            .as_u64()
            .ok_or_else(|| bad("expected nonnegative integer"))?,
    )
    .map_err(|_| bad("integer overflow"))
}
fn regex(source: &str) -> Result<Regex, SelectorError> {
    if source.len() > 512 {
        return Err(bad("schema pattern too long"));
    }
    RegexBuilder::new(source)
        .size_limit(262_144)
        .dfa_size_limit(262_144)
        .build()
        .map_err(|_| bad("invalid bounded Rust regex pattern"))
}
impl Compiler<'_> {
    fn reserve_literal(&mut self, value: &impl serde::Serialize) -> Result<(), SelectorError> {
        let remaining = 262_144usize.saturating_sub(self.literal_bytes);
        let bytes = crawlx_core::selectors::bounded_json_len(value, remaining)
            .map_err(|_| SelectorError::Budget("expanded schema literal bytes"))?;
        self.literal_bytes = self.literal_bytes.saturating_add(bytes);
        Ok(())
    }
    fn compile(
        &mut self,
        value: &Value,
        root: &Value,
        key: &str,
        depth: usize,
    ) -> Result<Schema, SelectorError> {
        self.nodes += 1;
        if self.nodes > 512 || depth > 64 {
            return Err(SelectorError::Budget("schema AST"));
        }
        if let Some(b) = value.as_bool() {
            return Ok(Schema {
                rules: vec![Rule::Bool(b)],
            });
        }
        let object = value
            .as_object()
            .ok_or_else(|| bad("schema must be object or boolean"))?;
        let mut rules = Vec::new();
        // Only data copied into compiled rules is charged here. Definitions remain
        // borrowed; every expanded reference pays before cloning enum/const data.
        for keyword in [
            "type",
            "enum",
            "const",
            "required",
            "dependentRequired",
            "pattern",
        ] {
            if let Some(literal) = object.get(keyword) {
                self.reserve_literal(literal)?;
            }
        }
        for keyword in object.keys() {
            if !matches!(
                keyword.as_str(),
                "$ref"
                    | "$defs"
                    | "definitions"
                    | "$schema"
                    | "title"
                    | "description"
                    | "default"
                    | "examples"
                    | "deprecated"
                    | "readOnly"
                    | "writeOnly"
                    | "type"
                    | "enum"
                    | "const"
                    | "minimum"
                    | "maximum"
                    | "exclusiveMinimum"
                    | "exclusiveMaximum"
                    | "multipleOf"
                    | "minLength"
                    | "maxLength"
                    | "pattern"
                    | "minItems"
                    | "maxItems"
                    | "minProperties"
                    | "maxProperties"
                    | "required"
                    | "properties"
                    | "patternProperties"
                    | "additionalProperties"
                    | "propertyNames"
                    | "prefixItems"
                    | "items"
                    | "contains"
                    | "minContains"
                    | "maxContains"
                    | "uniqueItems"
                    | "allOf"
                    | "anyOf"
                    | "oneOf"
                    | "not"
                    | "if"
                    | "then"
                    | "else"
                    | "dependentRequired"
                    | "dependentSchemas"
            ) {
                return Err(bad("unsupported schema keyword"));
            }
        }
        if let Some(reference) = object.get("$ref") {
            let reference = reference.as_str().ok_or_else(|| bad("invalid reference"))?;
            let (target_key, fragment) = if let Some(pointer) = reference.strip_prefix('#') {
                (key, pointer)
            } else if let Some(rest) = reference.strip_prefix("registry:") {
                rest.split_once('#').unwrap_or((rest, ""))
            } else {
                return Err(bad("remote schema references forbidden"));
            };
            if !fragment.is_empty() && !fragment.starts_with('/') {
                return Err(bad("only JSON pointer fragments supported"));
            }
            let target_root = if target_key == key {
                root
            } else {
                self.registry
                    .get(target_key)
                    .ok_or_else(|| bad("missing pinned schema"))?
            };
            let target = if fragment.is_empty() {
                target_root
            } else {
                target_root
                    .pointer(fragment)
                    .ok_or_else(|| bad("missing schema pointer"))?
            };
            let identity = format!("{target_key}#{fragment}");
            if !self.active.insert(identity.clone()) {
                return Err(bad("cyclic schema reference"));
            }
            rules.extend(self.compile(target, target_root, target_key, depth + 1)?.rules);
            self.active.remove(&identity);
        }
        if let Some(t) = object.get("type") {
            let types = if let Some(s) = t.as_str() {
                vec![s.to_owned()]
            } else {
                string_list(t)?
            };
            if types.is_empty()
                || types.iter().any(|s| {
                    !matches!(
                        s.as_str(),
                        "null" | "boolean" | "object" | "array" | "number" | "integer" | "string"
                    )
                })
            {
                return Err(bad("unknown schema type"));
            }
            rules.push(Rule::Type(types));
        }
        if let Some(v) = object.get("enum") {
            let variants = v.as_array().ok_or_else(|| bad("enum must be array"))?;
            if variants.is_empty() {
                return Err(bad("empty enum"));
            }
            rules.push(Rule::Enum(variants.clone()));
        }
        if let Some(v) = object.get("const") {
            rules.push(Rule::Const(v.clone()));
        }
        for (name, keyword) in [
            ("minimum", "minimum"),
            ("maximum", "maximum"),
            ("exclusiveMinimum", "exclusiveMinimum"),
            ("exclusiveMaximum", "exclusiveMaximum"),
            ("multipleOf", "multipleOf"),
        ] {
            if let Some(v) = object.get(name) {
                let Value::Number(n) = v else {
                    return Err(bad("numeric schema bound required"));
                };
                let (negative, digits, _) = decimal(n);
                if keyword == "multipleOf" && (negative || digits == "0") {
                    return Err(bad("nonpositive multipleOf"));
                }
                rules.push(Rule::Number(keyword, n.clone()));
            }
        }
        for (name, keyword) in [
            ("minLength", "minLength"),
            ("maxLength", "maxLength"),
            ("minItems", "minItems"),
            ("maxItems", "maxItems"),
            ("minProperties", "minProperties"),
            ("maxProperties", "maxProperties"),
        ] {
            if let Some(v) = object.get(name) {
                rules.push(Rule::Length(keyword, count(v)?));
            }
        }
        if let Some(v) = object.get("pattern") {
            let source = v.as_str().ok_or_else(|| bad("pattern must be string"))?;
            rules.push(Rule::Pattern(regex(source)?, source.len()));
        }
        if let Some(v) = object.get("required") {
            rules.push(Rule::Required(string_list(v)?));
        }
        if object.contains_key("properties")
            || object.contains_key("patternProperties")
            || object.contains_key("additionalProperties")
        {
            let properties = self.map(object.get("properties"), root, key, depth)?;
            let mut patterns = Vec::new();
            if let Some(v) = object.get("patternProperties") {
                for (pattern, schema) in v
                    .as_object()
                    .ok_or_else(|| bad("patternProperties must be object"))?
                {
                    patterns.push((
                        regex(pattern)?,
                        pattern.len(),
                        self.compile(schema, root, key, depth + 1)?,
                    ));
                }
            }
            let additional = object
                .get("additionalProperties")
                .map(|v| self.compile(v, root, key, depth + 1).map(Box::new))
                .transpose()?;
            rules.push(Rule::Properties(properties, patterns, additional));
        }
        if let Some(v) = object.get("propertyNames") {
            rules.push(Rule::PropertyNames(Box::new(self.compile(
                v,
                root,
                key,
                depth + 1,
            )?)));
        }
        if object.contains_key("items") || object.contains_key("prefixItems") {
            let mut prefix = Vec::new();
            if let Some(v) = object.get("prefixItems") {
                for v in v.as_array().ok_or_else(|| bad("prefixItems must be array"))? {
                    prefix.push(self.compile(v, root, key, depth + 1)?);
                }
            }
            let items = object
                .get("items")
                .map(|v| self.compile(v, root, key, depth + 1).map(Box::new))
                .transpose()?;
            rules.push(Rule::Items(prefix, items));
        }
        if let Some(v) = object.get("contains") {
            let min = object.get("minContains").map(count).transpose()?.unwrap_or(1);
            let max = object.get("maxContains").map(count).transpose()?;
            rules.push(Rule::Contains(
                Box::new(self.compile(v, root, key, depth + 1)?),
                min,
                max,
            ));
        }
        if let Some(v) = object.get("uniqueItems") {
            if v.as_bool().ok_or_else(|| bad("uniqueItems must be boolean"))? {
                rules.push(Rule::Unique);
            }
        }
        for (name, keyword) in [("allOf", "allOf"), ("anyOf", "anyOf"), ("oneOf", "oneOf")] {
            if let Some(v) = object.get(name) {
                let values = v
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| bad("schema group must be nonempty array"))?;
                let mut group = Vec::new();
                for v in values {
                    group.push(self.compile(v, root, key, depth + 1)?);
                }
                rules.push(Rule::Group(keyword, group));
            }
        }
        if let Some(v) = object.get("not") {
            rules.push(Rule::Not(Box::new(self.compile(v, root, key, depth + 1)?)));
        }
        if let Some(v) = object.get("if") {
            let condition = Box::new(self.compile(v, root, key, depth + 1)?);
            let then = object
                .get("then")
                .map(|v| self.compile(v, root, key, depth + 1).map(Box::new))
                .transpose()?;
            let otherwise = object
                .get("else")
                .map(|v| self.compile(v, root, key, depth + 1).map(Box::new))
                .transpose()?;
            rules.push(Rule::Conditional(condition, then, otherwise));
        }
        if let Some(v) = object.get("dependentRequired") {
            let mut dependencies = BTreeMap::new();
            for (k, v) in v
                .as_object()
                .ok_or_else(|| bad("dependentRequired must be object"))?
            {
                dependencies.insert(k.clone(), string_list(v)?);
            }
            rules.push(Rule::DependentRequired(dependencies));
        }
        if object.contains_key("dependentSchemas") {
            rules.push(Rule::DependentSchemas(self.map(
                object.get("dependentSchemas"),
                root,
                key,
                depth,
            )?));
        }
        Ok(Schema { rules })
    }
    fn map(
        &mut self,
        value: Option<&Value>,
        root: &Value,
        key: &str,
        depth: usize,
    ) -> Result<BTreeMap<String, Schema>, SelectorError> {
        let mut result = BTreeMap::new();
        if let Some(value) = value {
            for (k, v) in value
                .as_object()
                .ok_or_else(|| bad("schema map must be object"))?
            {
                self.reserve_literal(k)?;
                result.insert(k.clone(), self.compile(v, root, key, depth + 1)?);
            }
        }
        Ok(result)
    }
}
fn size(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Array(a) => a.iter().fold(1usize, |n, v| n.saturating_add(size(v))),
        Value::Object(o) => o.iter().fold(1usize, |n, (k, v)| {
            n.saturating_add(k.len()).saturating_add(size(v))
        }),
        _ => 1,
    }
}

// JSON Schema compares mathematical numeric values, not serde's integer/float storage variants.
fn equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => decimal(a) == decimal(b),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equivalent(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(k, a)| b.get(k).is_some_and(|b| equivalent(a, b)))
        }
        _ => a == b,
    }
}
fn decimal(number: &serde_json::Number) -> (bool, String, i32) {
    let source = number.to_string();
    let negative = source.starts_with('-');
    let unsigned = source.strip_prefix('-').unwrap_or(&source);
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0), |(m, e)| (m, e.parse::<i32>().unwrap_or(0)));
    let fraction = mantissa.split_once('.').map_or(0, |(_, f)| f.len());
    let mut digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    digits = digits.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return (false, "0".into(), 0);
    }
    let trailing = digits.len().saturating_sub(digits.trim_end_matches('0').len());
    digits.truncate(digits.len().saturating_sub(trailing));
    let power = exponent
        .saturating_sub(i32::try_from(fraction).unwrap_or(i32::MAX))
        .saturating_add(i32::try_from(trailing).unwrap_or(i32::MAX));
    (negative, digits, power)
}

fn decimal_order(a: &serde_json::Number, b: &serde_json::Number) -> std::cmp::Ordering {
    let (an, ad, ap) = decimal(a);
    let (bn, bd, bp) = decimal(b);
    if an != bn {
        return if an {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    let order = if ad == "0" && bd == "0" {
        std::cmp::Ordering::Equal
    } else if ad == "0" {
        std::cmp::Ordering::Less
    } else if bd == "0" {
        std::cmp::Ordering::Greater
    } else {
        let a_order = i64::try_from(ad.len())
            .unwrap_or(i64::MAX)
            .saturating_add(i64::from(ap));
        let b_order = i64::try_from(bd.len())
            .unwrap_or(i64::MAX)
            .saturating_add(i64::from(bp));
        a_order.cmp(&b_order).then_with(|| {
            let width = ad.len().max(bd.len());
            ad.bytes()
                .chain(std::iter::repeat(b'0'))
                .take(width)
                .cmp(bd.bytes().chain(std::iter::repeat(b'0')).take(width))
        })
    };
    if an {
        order.reverse()
    } else {
        order
    }
}

fn multiple_of(
    a: &serde_json::Number,
    b: &serde_json::Number,
    doc: &mut impl WorkBudget,
) -> Result<bool, SelectorError> {
    let (_, ad, ap) = decimal(a);
    let (_, bd, bp) = decimal(b);
    if ad == "0" {
        return Ok(true);
    }
    let mut numerator: Vec<u8> = ad.bytes().map(|b| b - b'0').collect();
    let mut denominator: Vec<u8> = bd.bytes().map(|b| b - b'0').collect();
    let shift = ap.saturating_sub(bp);
    let zeros =
        usize::try_from(shift.unsigned_abs()).map_err(|_| SelectorError::Budget("schema decimal digits"))?;
    if zeros > 1024 {
        return Err(SelectorError::Budget("schema decimal digits"));
    }
    if shift >= 0 {
        numerator.resize(numerator.len().saturating_add(zeros), 0);
    } else {
        denominator.resize(denominator.len().saturating_add(zeros), 0);
    }
    doc.charge(numerator.len().saturating_add(denominator.len()))?;
    let mut remainder = Vec::new();
    for digit in numerator {
        remainder.push(digit);
        let zeroes = remainder.iter().take_while(|v| **v == 0).count();
        if zeroes > 0 {
            drop(remainder.drain(..zeroes));
        }
        loop {
            doc.charge(remainder.len().saturating_add(denominator.len()))?;
            if remainder.len() < denominator.len()
                || (remainder.len() == denominator.len() && remainder < denominator)
            {
                break;
            }
            let mut borrow = 0u8;
            for offset in 0..remainder.len() {
                let i = remainder.len() - 1 - offset;
                let sub = denominator
                    .len()
                    .checked_sub(offset + 1)
                    .map_or(0, |j| denominator[j])
                    .saturating_add(borrow);
                if remainder[i] < sub {
                    remainder[i] = 10 + remainder[i] - sub;
                    borrow = 1;
                } else {
                    remainder[i] -= sub;
                    borrow = 0;
                }
            }
            let zeroes = remainder.iter().take_while(|v| **v == 0).count();
            if zeroes > 0 {
                drop(remainder.drain(..zeroes));
            }
        }
    }
    Ok(remainder.is_empty())
}
impl Schema {
    pub(super) fn validate(&self, value: &Value, doc: &mut impl WorkBudget) -> Result<bool, SelectorError> {
        doc.charge(1)?;
        for rule in &self.rules {
            doc.charge(1)?;
            let valid = match rule {
                Rule::Bool(v) => *v,
                Rule::Type(types) => types.iter().any(|t| match t.as_str() {
                    "null" => value.is_null(),
                    "boolean" => value.is_boolean(),
                    "object" => value.is_object(),
                    "array" => value.is_array(),
                    "number" => value.is_number(),
                    "integer" => matches!(value,Value::Number(n) if decimal(n).2>=0),
                    "string" => value.is_string(),
                    _ => false,
                }),
                Rule::Enum(values) => {
                    let mut found = false;
                    for v in values {
                        doc.charge(size(v).saturating_add(size(value)))?;
                        found |= equivalent(v, value);
                    }
                    found
                }
                Rule::Const(v) => {
                    doc.charge(size(v).saturating_add(size(value)))?;
                    equivalent(v, value)
                }
                Rule::Number(kind, bound) => {
                    if let Value::Number(number) = value {
                        doc.charge(number.to_string().len().saturating_add(bound.to_string().len()))?;
                        let order = decimal_order(number, bound);
                        match *kind {
                            "minimum" => !order.is_lt(),
                            "maximum" => !order.is_gt(),
                            "exclusiveMinimum" => order.is_gt(),
                            "exclusiveMaximum" => order.is_lt(),
                            "multipleOf" => multiple_of(number, bound, doc)?,
                            _ => false,
                        }
                    } else {
                        true
                    }
                }
                Rule::Length(kind, bound) => {
                    let length = match *kind {
                        "minLength" | "maxLength" => {
                            if let Some(s) = value.as_str() {
                                doc.charge(s.len())?;
                                Some(s.chars().count())
                            } else {
                                None
                            }
                        }
                        "minItems" | "maxItems" => value.as_array().map(Vec::len),
                        _ => value.as_object().map(serde_json::Map::len),
                    };
                    length.is_none_or(|n| {
                        if kind.starts_with("min") {
                            n >= *bound
                        } else {
                            n <= *bound
                        }
                    })
                }
                Rule::Pattern(pattern, len) => {
                    if let Some(s) = value.as_str() {
                        doc.charge(s.len().saturating_mul(*len))?;
                        pattern.is_match(s)
                    } else {
                        true
                    }
                }
                Rule::Required(names) => {
                    if let Some(o) = value.as_object() {
                        doc.charge(names.len())?;
                        names.iter().all(|n| o.contains_key(n))
                    } else {
                        true
                    }
                }
                Rule::Properties(properties, patterns, additional) => {
                    let mut valid = true;
                    if let Some(object) = value.as_object() {
                        for (key, value) in object {
                            doc.charge(1)?;
                            let mut matched = false;
                            if let Some(schema) = properties.get(key) {
                                matched = true;
                                valid &= schema.validate(value, doc)?;
                            }
                            for (pattern, len, schema) in patterns {
                                doc.charge(key.len().saturating_mul(*len))?;
                                if pattern.is_match(key) {
                                    matched = true;
                                    valid &= schema.validate(value, doc)?;
                                }
                            }
                            if !matched {
                                if let Some(schema) = additional {
                                    valid &= schema.validate(value, doc)?;
                                }
                            }
                        }
                    }
                    valid
                }
                Rule::PropertyNames(schema) => {
                    let mut valid = true;
                    if let Some(object) = value.as_object() {
                        for key in object.keys() {
                            doc.charge(key.len())?;
                            valid &= schema.validate(&Value::String(key.clone()), doc)?;
                        }
                    }
                    valid
                }
                Rule::Items(prefix, items) => {
                    let mut valid = true;
                    if let Some(array) = value.as_array() {
                        for (i, value) in array.iter().enumerate() {
                            doc.charge(1)?;
                            if let Some(schema) = prefix.get(i).or(items.as_deref()) {
                                valid &= schema.validate(value, doc)?;
                            }
                        }
                    }
                    valid
                }
                Rule::Contains(schema, min, max) => {
                    if let Some(array) = value.as_array() {
                        let mut count = 0usize;
                        for v in array {
                            if schema.validate(v, doc)? {
                                count += 1;
                            }
                        }
                        count >= *min && max.is_none_or(|max| count <= max)
                    } else {
                        true
                    }
                }
                Rule::Unique => {
                    let mut valid = true;
                    if let Some(array) = value.as_array() {
                        for (i, a) in array.iter().enumerate() {
                            for b in &array[..i] {
                                doc.charge(size(a).saturating_add(size(b)))?;
                                valid &= !equivalent(a, b);
                            }
                        }
                    }
                    valid
                }
                Rule::Group(kind, group) => {
                    let mut matched = 0usize;
                    for schema in group {
                        if schema.validate(value, doc)? {
                            matched += 1;
                        }
                    }
                    match *kind {
                        "allOf" => matched == group.len(),
                        "anyOf" => matched > 0,
                        _ => matched == 1,
                    }
                }
                Rule::Not(schema) => !schema.validate(value, doc)?,
                Rule::Conditional(condition, then, otherwise) => {
                    let schema = if condition.validate(value, doc)? {
                        then
                    } else {
                        otherwise
                    };
                    if let Some(schema) = schema {
                        schema.validate(value, doc)?
                    } else {
                        true
                    }
                }
                Rule::DependentRequired(dependencies) => {
                    let mut valid = true;
                    if let Some(object) = value.as_object() {
                        for (key, names) in dependencies {
                            doc.charge(names.len().saturating_add(1))?;
                            if object.contains_key(key) {
                                valid &= names.iter().all(|n| object.contains_key(n));
                            }
                        }
                    }
                    valid
                }
                Rule::DependentSchemas(dependencies) => {
                    let mut valid = true;
                    if let Some(object) = value.as_object() {
                        for (key, schema) in dependencies {
                            doc.charge(1)?;
                            if object.contains_key(key) {
                                valid &= schema.validate(value, doc)?;
                            }
                        }
                    }
                    valid
                }
            };
            if !valid {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn number(source: &str) -> serde_json::Number {
        serde_json::from_str(source).unwrap()
    }
    #[test]
    fn decimals_compare_without_binary_float_rounding_or_integer_loss() {
        assert!(decimal_order(&number("9007199254740993"), &number("9007199254740992")).is_gt());
        assert!(decimal_order(&number("-9007199254740993"), &number("-9007199254740992")).is_lt());
        assert!(equivalent(
            &Value::Number(number("2.0")),
            &Value::Number(number("2"))
        ));
        assert!(decimal_order(&number("1e-100"), &number("0")).is_gt());
    }
    #[test]
    fn decimal_multiple_is_exact_and_charges_long_division() {
        let html = scraper::Html::parse_document("<p>x</p>");
        let mut doc = SelectorDocument::new(&html).unwrap();
        assert!(multiple_of(&number("0.3"), &number("0.1"), &mut doc).unwrap());
        assert!(!multiple_of(&number("0.31"), &number("0.1"), &mut doc).unwrap());
        assert!(multiple_of(&number("-1.2"), &number("0.2"), &mut doc).unwrap());
        doc.restrict_operations(1);
        assert!(matches!(
            multiple_of(&number("99.9"), &number("0.1"), &mut doc),
            Err(SelectorError::Budget(_))
        ));
    }
}
