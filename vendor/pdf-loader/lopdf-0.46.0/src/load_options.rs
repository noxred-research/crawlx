use crate::Object;

/// Type alias for the filter function used during PDF loading.
///
/// The function receives an object ID and a mutable reference to the object,
/// and returns `Some((id, object))` to keep it or `None` to discard it.
pub type FilterFunc = fn((u32, u16), &mut Object) -> Option<((u32, u16), Object)>;

/// Options for loading PDF documents.
///
/// Use this struct to configure password, object filtering, and strictness
/// when loading a PDF. The default is lenient parsing with no password or filter.
///
/// # Examples
///
/// ```no_run
/// use lopdf::{Document, LoadOptions};
///
/// // Load with a password
/// let doc = Document::load_with_options(
///     "encrypted.pdf",
///     LoadOptions::with_password("secret"),
/// );
///
/// // Load with strict parsing
/// let doc = Document::load_with_options(
///     "document.pdf",
///     LoadOptions { strict: true, ..Default::default() },
/// );
/// ```
#[derive(Clone, Default)]
pub struct LoadOptions {
    /// Password for encrypted PDFs.
    pub password: Option<String>,
    /// Object filter applied during loading.
    pub filter: Option<FilterFunc>,
    /// When `true`, reject non-conforming PDFs instead of silently accepting them.
    /// Defaults to `false` (lenient parsing), which also repairs damaged cross-reference
    /// data and reports it in [`Document::xref_recovery`](crate::Document::xref_recovery).
    pub strict: bool,
    /// Maximum number of bytes any single stream may decompress to during
    /// loading (object streams and cross-reference streams).
    ///
    /// Compression filters can inflate a tiny input into an enormous output (a
    /// "decompression bomb"). Because object and xref streams are decoded eagerly
    /// while the document is loaded, an unbounded stream can exhaust memory
    /// before any of your code runs. Set this to bound that per-stream cost when
    /// loading untrusted PDFs; a stream that would exceed it fails with
    /// [`crate::DecompressError::MemoryLimitExceeded`].
    ///
    /// `None` (the default) applies no limit.
    pub max_decompressed_size: Option<usize>,
    /// Maximum cumulative decoded bytes for eagerly loaded object and cross-reference
    /// streams, including unfiltered streams. Each cached object stream is charged once.
    ///
    /// The remaining budget bounds decoding before allocation. Intermediate filter
    /// outputs also obey that remaining limit. Ordinary page streams are not decoded
    /// by loading and are not covered. `None` (the default) applies no aggregate limit.
    /// Exceeding this budget returns [`crate::DecompressError::MemoryLimitExceeded`],
    /// even during lenient loading or cross-reference recovery.
    pub max_total_decompressed_size: Option<usize>,
    /// Maximum eager object and cross-reference counts.
    ///
    /// Three independent cumulative counters apply this limit: parsed syntax
    /// nodes (including nested arrays, dictionary keys and values), retained normal
    /// objects plus declared object-stream members, and cross-reference entries
    /// (including free entries and older sections). The syntax counter spans all
    /// direct-object parsing in a load, including trailers, recovery, encrypted
    /// objects and object-stream members; it is checked before collection growth.
    ///
    /// Counts are checked before retaining entries or allocating object-stream
    /// headers. Reusing cached members does not charge their syntax nodes again;
    /// reparsing raw objects does. Failed parse attempts and discarding objects
    /// through `filter` do not refund budgets. Bounded loading uses sequential parsing.
    ///
    /// `None` (the default) applies no object limit. Exceeding this budget returns
    /// [`crate::DecompressError::MemoryLimitExceeded`], also in lenient mode.
    pub max_objects: Option<usize>,
}

impl std::fmt::Debug for LoadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadOptions")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("filter", &self.filter.map(|_| "fn(..)"))
            .field("strict", &self.strict)
            .field("max_decompressed_size", &self.max_decompressed_size)
            .field("max_total_decompressed_size", &self.max_total_decompressed_size)
            .field("max_objects", &self.max_objects)
            .finish()
    }
}

impl LoadOptions {
    /// Create options with a password for encrypted PDFs.
    pub fn with_password(password: &str) -> Self {
        Self {
            password: Some(password.to_string()),
            ..Default::default()
        }
    }

    /// Create options with an object filter.
    pub fn with_filter(filter: FilterFunc) -> Self {
        Self {
            filter: Some(filter),
            ..Default::default()
        }
    }

    /// Create options that bound how large any single stream may decompress to
    /// during loading, to defend against decompression bombs in untrusted PDFs.
    /// See [`LoadOptions::max_decompressed_size`].
    pub fn with_max_decompressed_size(max_decompressed_size: usize) -> Self {
        Self {
            max_decompressed_size: Some(max_decompressed_size),
            ..Default::default()
        }
    }
}
