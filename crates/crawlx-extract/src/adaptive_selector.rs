//! Scoped, pure structural relocation for extraction only.
//! Descriptors omit text, attribute values, URLs and browser epochs. Persistence belongs
//! to the caller's retention-aware repository; recovery never grants target authority.
use crate::xpath::{SelectorDocument, SelectorError};
use crawlx_core::selectors::{AdaptiveSelectorSpecV1, SelectorScopeV1, StructuralDescriptorV1};
use scraper::ElementRef;
use std::collections::BTreeSet;
/// Explicit recovery decision. Ambiguity always abstains.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelocationOutcome {
    /// Unique structural candidate passed both score gates.
    Recovered {
        /// Static document node index, never an action locator.
        node: usize,
        /// Fixed-point score, 0..1000; not a probability.
        score: u16,
    },
    /// Best candidate failed separation from runner-up.
    Ambiguous {
        /// Best score.
        best: u16,
        /// Runner-up score.
        runner_up: u16,
    },
    /// No candidate passed minimum score.
    NotFound,
}
fn descriptor(doc: &mut SelectorDocument<'_>, node: usize) -> Result<StructuralDescriptorV1, SelectorError> {
    let el = doc.element(node).ok_or(SelectorError::NodeSetRequired)?;
    let parent = el.parent().and_then(ElementRef::wrap);
    let grandparent = parent.and_then(|p| p.parent()).and_then(ElementRef::wrap);
    let mut attributes = BTreeSet::new();
    for (name, _) in &el.value().attrs {
        doc.charge(name.local.len())?;
        attributes.insert(name.local.to_string());
    }
    let mut index = 0usize;
    for sibling in el.prev_siblings() {
        doc.charge(1)?;
        if sibling.value().is_element() {
            index += 1;
        }
    }
    Ok(StructuralDescriptorV1::new(
        el.value().name().into(),
        parent.map(|p| p.value().name().into()),
        grandparent.map(|p| p.value().name().into()),
        attributes.into_iter().collect(),
        index,
    ))
}
/// Capture sanitized structure from an already selected element and caller authority.
/// # Errors
/// Returns invalid scope, descriptor bound or shared operation-budget errors.
pub fn capture(
    doc: &mut SelectorDocument<'_>,
    node: usize,
    selector_id: String,
    scope: SelectorScopeV1,
) -> Result<AdaptiveSelectorSpecV1, SelectorError> {
    scope.validate()?;
    let spec = AdaptiveSelectorSpecV1::new(selector_id, scope, descriptor(doc, node)?);
    spec.validate()?;
    Ok(spec)
}

/// Capture one structural descriptor from bounded caller-owned HTML.
/// This ingestion convenience parses once; callers already holding an index use `capture`.
/// # Errors
/// Rejects input above 8 MiB, invalid scope, excessive DOM shape, shared work exhaustion or an
/// exhausted process-wide parse-memory budget (`SelectorError::Budget`).
pub fn capture_html(
    html: &str,
    node: usize,
    selector_id: String,
    scope: SelectorScopeV1,
) -> Result<AdaptiveSelectorSpecV1, SelectorError> {
    scope.validate()?;
    let (_charge, parsed) = parse_owned_html(html)?;
    let mut document = SelectorDocument::new(&parsed)?;
    capture(&mut document, node, selector_id, scope)
}

/// Relocate within bounded caller-owned HTML, without making a request or granting authority.
/// # Errors
/// Rejects scope mismatch, input above 8 MiB, excessive DOM shape, shared work exhaustion or an
/// exhausted process-wide parse-memory budget (`SelectorError::Budget`).
pub fn relocate_html(
    html: &str,
    spec: &AdaptiveSelectorSpecV1,
    scope: &SelectorScopeV1,
) -> Result<RelocationOutcome, SelectorError> {
    spec.validate()?;
    scope.validate()?;
    if &spec.scope != scope {
        return Err(SelectorError::ScopeMismatch);
    }
    let (_charge, parsed) = parse_owned_html(html)?;
    let mut document = SelectorDocument::new(&parsed)?;
    relocate(&mut document, spec, scope)
}

/// The charge must outlive the returned tree: bind it before the tree so it drops last.
fn parse_owned_html(html: &str) -> Result<(crate::parse_budget::ParseCharge, scraper::Html), SelectorError> {
    if html.len() > 8 * 1024 * 1024 {
        return Err(SelectorError::Budget("adaptive input bytes"));
    }
    let charge =
        crate::parse_budget::charge(html.len()).map_err(|_| SelectorError::Budget("parse memory"))?;
    let parsed = scraper::Html::parse_document(html);
    crate::dom::check_limits(&parsed, 100_000).map_err(|_| SelectorError::Budget("adaptive DOM shape"))?;
    Ok((charge, parsed))
}
/// Match structure inside exactly the authenticated caller namespace.
/// # Errors
/// Scope mismatch, malformed versions and candidate/work exhaustion fail explicitly.
pub fn relocate(
    doc: &mut SelectorDocument<'_>,
    spec: &AdaptiveSelectorSpecV1,
    caller_scope: &SelectorScopeV1,
) -> Result<RelocationOutcome, SelectorError> {
    spec.validate()?;
    caller_scope.validate()?;
    if &spec.scope != caller_scope {
        return Err(SelectorError::ScopeMismatch);
    }
    let mut best = None;
    let mut runner_up = 0u16;
    for node in doc.element_candidates(spec.max_candidates)? {
        doc.charge(1)?;
        let candidate = descriptor(doc, node)?;
        let score = score(&spec.descriptor, &candidate);
        if let Some((_, best_score)) = best {
            if score > best_score {
                runner_up = best_score;
                best = Some((node, score));
            } else {
                runner_up = runner_up.max(score);
            }
        } else {
            best = Some((node, score));
        }
    }
    let Some((node, score)) = best else {
        return Ok(RelocationOutcome::NotFound);
    };
    if score < spec.threshold {
        return Ok(RelocationOutcome::NotFound);
    }
    if score.saturating_sub(runner_up) < spec.runner_up_margin {
        return Ok(RelocationOutcome::Ambiguous {
            best: score,
            runner_up,
        });
    }
    Ok(RelocationOutcome::Recovered { node, score })
}
fn score(saved: &StructuralDescriptorV1, candidate: &StructuralDescriptorV1) -> u16 {
    // A different element kind is not the same extraction field.
    if saved.tag != candidate.tag {
        return 0;
    }
    let mut score = 400u16;
    if saved.parent_tag == candidate.parent_tag {
        score += 250;
    }
    if saved.grandparent_tag == candidate.grandparent_tag {
        score += 150;
    }
    if saved.attribute_names == candidate.attribute_names {
        score += 100;
    }
    if saved.sibling_index == candidate.sibling_index {
        score += 100;
    }
    score
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::xpath::{CompiledSelector, XPathValue};
    use std::collections::BTreeMap;
    fn scope() -> SelectorScopeV1 {
        SelectorScopeV1::new(
            "tenant".into(),
            "principal".into(),
            "https://example.test".into(),
            "news".into(),
            "article/v1".into(),
        )
    }
    fn saved() -> AdaptiveSelectorSpecV1 {
        let html = scraper::Html::parse_document("<article><p class='old'>saved</p></article>");
        let mut doc = SelectorDocument::new(&html).unwrap();
        let XPathValue::Nodes(nodes) = doc
            .evaluate(&CompiledSelector::xpath("//p").unwrap(), &BTreeMap::new())
            .unwrap()
        else {
            panic!()
        };
        capture(&mut doc, nodes[0], "body".into(), scope()).unwrap()
    }
    #[test]
    fn renamed_class_recovers_without_text() {
        let spec = saved();
        let html = scraper::Html::parse_document("<article><p class='renamed'>different</p></article>");
        let mut doc = SelectorDocument::new(&html).unwrap();
        assert!(matches!(
            relocate(&mut doc, &spec, &scope()).unwrap(),
            RelocationOutcome::Recovered { .. }
        ));
    }
    #[test]
    fn equal_decoys_abstain() {
        let spec = saved();
        let html = scraper::Html::parse_document(
            "<article><p class='a'>one</p></article><article><p class='b'>two</p></article>",
        );
        let mut doc = SelectorDocument::new(&html).unwrap();
        assert!(matches!(
            relocate(&mut doc, &spec, &scope()).unwrap(),
            RelocationOutcome::Ambiguous { .. }
        ));
    }
    #[test]
    fn foreign_tenant_never_matches() {
        let spec = saved();
        let html = scraper::Html::parse_document("<article><p class='old'>saved</p></article>");
        let mut doc = SelectorDocument::new(&html).unwrap();
        let mut other = scope();
        other.tenant = "other".into();
        assert!(matches!(
            relocate(&mut doc, &spec, &other),
            Err(SelectorError::ScopeMismatch)
        ));
    }
}
