//! Typed errors for the URL plane.

/// Errors returned by canonicalization, scope compilation and sitemap parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    /// Input was empty (or only whitespace).
    #[error("empty url")]
    Empty,
    /// Input exceeded the configured maximum length.
    #[error("url too long: {len} bytes (max {max})")]
    TooLong {
        /// Input length in bytes.
        len: usize,
        /// Configured maximum length in bytes.
        max: usize,
    },
    /// The URL did not parse (WHATWG URL parser message).
    #[error("invalid url: {0}")]
    Parse(String),
    /// Only `http` and `https` survive canonicalization.
    #[error("unsupported scheme `{0}`")]
    Scheme(String),
    /// The URL has no host.
    #[error("url has no host")]
    NoHost,
    /// A scope pattern was rejected (too long, too many, or not compilable within limits).
    #[error("invalid scope pattern `{pattern}`: {reason}")]
    Pattern {
        /// The offending pattern text.
        pattern: String,
        /// Why the pattern was rejected.
        reason: String,
    },
    /// A sitemap document was not usable.
    #[error("invalid sitemap: {0}")]
    Sitemap(String),
}
