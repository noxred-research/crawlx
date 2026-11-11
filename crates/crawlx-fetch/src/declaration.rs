//! Declaration-level response overrides: MIME type, text encoding and HTTP-error status sets.
//!
//! These map a crawl declaration (what the operator knows about a source) onto fetch
//! behaviour without a callback or arbitrary object:
//!
//! * a MIME override replaces the effective `Content-Type`; the sender's value is kept in the
//!   response evidence;
//! * an encoding override wins over every other charset source ([`crate::charset`]);
//! * a status set decides which HTTP error statuses are *allowed* (delivered as ordinary
//!   responses, not retried) or *denied* (refused with [`crate::FetchError::StatusDenied`]).
//!
//! A status set never suppresses origin feedback: a `429` or `503` the declaration allows
//! still reaches the governor, so its cooldown applies to every later start on that origin,
//! in this process and in every worker sharing the deployment admission store.

use crate::charset::is_supported_label;
use crate::error::FetchError;
use std::collections::BTreeSet;

/// How a declaration treats one HTTP status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusVerdict {
    /// Refuse the response.
    Deny,
    /// Deliver the response as is; do not retry it.
    Allow,
    /// No declaration: the plane's ordinary handling (retry `429`/`503`, deliver the rest).
    Default,
}

/// Allowed and denied HTTP statuses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpErrorStatuses {
    allow: BTreeSet<u16>,
    deny: BTreeSet<u16>,
}

impl HttpErrorStatuses {
    /// Add allowed statuses.
    #[must_use]
    pub fn allowing(mut self, statuses: impl IntoIterator<Item = u16>) -> Self {
        self.allow.extend(statuses);
        self
    }

    /// Add denied statuses.
    #[must_use]
    pub fn denying(mut self, statuses: impl IntoIterator<Item = u16>) -> Self {
        self.deny.extend(statuses);
        self
    }

    /// The declaration's verdict for `status`. Deny wins over allow.
    #[must_use]
    pub fn verdict(&self, status: u16) -> StatusVerdict {
        if self.deny.contains(&status) {
            StatusVerdict::Deny
        } else if self.allow.contains(&status) {
            StatusVerdict::Allow
        } else {
            StatusVerdict::Default
        }
    }

    /// No status is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    fn validate(&self) -> Result<(), FetchError> {
        let valid = |s: &u16| (100..=599).contains(s);
        if !self.allow.iter().all(valid) || !self.deny.iter().all(valid) {
            return Err(FetchError::InvalidDeclaration { field: "statuses" });
        }
        if self.allow.intersection(&self.deny).next().is_some() {
            return Err(FetchError::InvalidDeclaration {
                field: "statuses.conflict",
            });
        }
        Ok(())
    }
}

/// Declared overrides of one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResponseDeclaration {
    /// Effective MIME type (`type/subtype`, no parameters).
    pub content_type: Option<String>,
    /// Effective text encoding label.
    pub charset: Option<String>,
    /// HTTP error status sets.
    pub statuses: HttpErrorStatuses,
}

impl ResponseDeclaration {
    /// Override the effective MIME type.
    #[must_use]
    pub fn with_content_type(mut self, mime: impl Into<String>) -> Self {
        self.content_type = Some(mime.into());
        self
    }

    /// Override the text encoding.
    #[must_use]
    pub fn with_charset(mut self, label: impl Into<String>) -> Self {
        self.charset = Some(label.into());
        self
    }

    /// Replace the status sets.
    #[must_use]
    pub fn with_statuses(mut self, statuses: HttpErrorStatuses) -> Self {
        self.statuses = statuses;
        self
    }

    /// Nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_type.is_none() && self.charset.is_none() && self.statuses.is_empty()
    }

    /// Reject a malformed declaration before any request is sent.
    ///
    /// # Errors
    /// [`FetchError::InvalidDeclaration`] naming the field: a MIME type that is not
    /// `type/subtype`, an encoding label this plane does not honour, a status outside
    /// `100..=599`, or a status both allowed and denied.
    pub fn validate(&self) -> Result<(), FetchError> {
        if let Some(mime) = &self.content_type {
            let token = |part: &str| {
                !part.is_empty()
                    && part.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || matches!(b, b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+')
                    })
            };
            let valid = mime.len() <= 100
                && mime
                    .split_once('/')
                    .is_some_and(|(kind, subtype)| token(kind) && token(subtype));
            if !valid {
                return Err(FetchError::InvalidDeclaration { field: "contentType" });
            }
        }
        if self
            .charset
            .as_deref()
            .is_some_and(|label| !is_supported_label(label))
        {
            return Err(FetchError::InvalidDeclaration { field: "charset" });
        }
        self.statuses.validate()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn deny_wins_and_unlisted_statuses_keep_default_handling() {
        let statuses = HttpErrorStatuses::default().allowing([404, 429]).denying([403]);
        assert_eq!(statuses.verdict(403), StatusVerdict::Deny);
        assert_eq!(statuses.verdict(404), StatusVerdict::Allow);
        assert_eq!(statuses.verdict(429), StatusVerdict::Allow);
        assert_eq!(statuses.verdict(503), StatusVerdict::Default);
        assert!(!statuses.is_empty());
        assert!(ResponseDeclaration::default().is_empty());
    }

    #[test]
    fn invalid_declarations_name_their_field() {
        let field = |declaration: ResponseDeclaration| match declaration.validate() {
            Err(FetchError::InvalidDeclaration { field }) => field,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            field(ResponseDeclaration::default().with_content_type("text")),
            "contentType"
        );
        assert_eq!(
            field(ResponseDeclaration::default().with_content_type("text/html\r\nx: y")),
            "contentType"
        );
        assert_eq!(
            field(ResponseDeclaration::default().with_charset("klingon")),
            "charset"
        );
        assert_eq!(
            field(ResponseDeclaration::default().with_statuses(HttpErrorStatuses::default().allowing([99]))),
            "statuses"
        );
        assert_eq!(
            field(
                ResponseDeclaration::default()
                    .with_statuses(HttpErrorStatuses::default().allowing([404]).denying([404]))
            ),
            "statuses.conflict"
        );
        ResponseDeclaration::default()
            .with_content_type("application/vnd.api+json")
            .with_charset("Shift_JIS")
            .with_statuses(HttpErrorStatuses::default().allowing([429]))
            .validate()
            .unwrap();
    }
}
