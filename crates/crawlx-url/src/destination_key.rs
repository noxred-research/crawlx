//! `destination_key` for link identities.
//!
//! `origin + route template + kept params`, where `ResourceId` values are
//! replaced by the `:id` slot, `Filter` values are bucketed (see
//! [`crate::params::bucket_value`]) and `Navigation`/`ActionBearing` values
//! stay raw. `Tracking` and `Session` parameters never appear. It is built
//! from the *classified* URL, never from a parameter-stripped one.

use crawlx_core::url::{CanonicalUrl, ParamClass};
use url::form_urlencoded::byte_serialize;

/// Identity string of a link destination, e.g.
/// `https://shop.example/invoice/:id?id=:id&page=2`.
#[must_use]
pub fn destination_key(canonical: &CanonicalUrl) -> String {
    let mut out = String::with_capacity(canonical.origin.len() + canonical.route_template.0.len() + 32);
    out.push_str(&canonical.origin);
    out.push_str(&canonical.route_template.0);
    let mut first = true;
    for p in canonical.params.iter().filter(|p| p.class.kept()) {
        out.push(if first { '?' } else { '&' });
        first = false;
        out.extend(byte_serialize(p.name.as_bytes()));
        out.push('=');
        if p.class == ParamClass::ResourceId {
            out.push_str(":id");
        } else {
            out.extend(byte_serialize(p.value.as_deref().unwrap_or("").as_bytes()));
        }
    }
    out
}
