//! Diagnostic-lane synthetic input.
//!
//! This is the only module in the repository allowed to contain `.click()` or
//! `dispatchEvent(` script strings (`ci/lint-static.sh`). Everything dispatched from here
//! produces untrusted events (`event.isTrusted === false`) and is recorded in the
//! `diagnostic` lane; it never backs a `trusted_ui` action.

/// `this` = element: dispatch an untrusted click (`SyntheticClick`, diagnostic lane only).
pub const SYNTHETIC_CLICK: &str = r#"function () { this.click(); return true; }"#;

/// Deliver an admitted captcha token through diagnostic-only synthetic input.
/// The widget controller retains ownership, freshness and callback handling.
pub(super) const CAPTCHA_DELIVERY: &str = r#"async function(id, token) {
    if (!window.__crawlxCaptcha) return false;
    const writeValue = (field, value) => {
        field.value = value;
        field.dispatchEvent(new Event('input', {bubbles: true}));
        field.dispatchEvent(new Event('change', {bubbles: true}));
    };
    return await window.__crawlxCaptcha.deliver(id, token, writeValue);
}"#;
