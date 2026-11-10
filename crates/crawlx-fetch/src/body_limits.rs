//! Body-size defaults of the fetch plane.
//!
//! The streaming reader and the independent wire/decoded/expansion limits live in
//! [`crate::codec`]: the decoded cap applies to bytes after decoding, so a compression bomb
//! stops at the limit too, and a separate wire cap bounds the compressed size.

/// Default decoded-body cap: 8 MiB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
