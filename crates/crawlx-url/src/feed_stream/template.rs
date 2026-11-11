//! Declarative row templates: which XML elements/attributes or CSV columns become row fields.

use super::FeedStreamError;
use std::collections::{BTreeMap, BTreeSet};

const ATOM_NS: &str = "http://www.w3.org/2005/Atom";

/// Element or attribute name matched by namespace URI and local name, never by prefix.
///
/// `namespace == None` matches only names in no namespace; an unprefixed attribute is always in
/// no namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct XmlName {
    /// Namespace URI, or `None` for no namespace.
    pub namespace: Option<String>,
    /// Local name without prefix.
    pub local: String,
}

impl XmlName {
    /// Name in no namespace.
    #[must_use]
    pub fn local(local: &str) -> Self {
        Self {
            namespace: None,
            local: local.to_owned(),
        }
    }

    /// Name in the namespace identified by `namespace`.
    #[must_use]
    pub fn namespaced(namespace: &str, local: &str) -> Self {
        Self {
            namespace: Some(namespace.to_owned()),
            local: local.to_owned(),
        }
    }
}

/// One output field of an XML row: the text of a descendant element (or of the item itself), or
/// one attribute of such an element.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct XmlField {
    /// Output field name.
    pub name: String,
    /// Element path below the item element; empty selects the item element itself.
    pub path: Vec<XmlName>,
    /// Attribute to read from the selected element; `None` reads the element's own text.
    pub attribute: Option<XmlName>,
    /// A missing or empty value makes the whole row malformed.
    pub required: bool,
}

impl XmlField {
    /// Field holding the trimmed text of the element at `path` below the item.
    #[must_use]
    pub fn element(name: &str, path: Vec<XmlName>) -> Self {
        Self {
            name: name.to_owned(),
            path,
            attribute: None,
            required: false,
        }
    }

    /// Field holding attribute `attribute` of the element at `path` below the item.
    #[must_use]
    pub fn attribute(name: &str, path: Vec<XmlName>, attribute: XmlName) -> Self {
        Self {
            name: name.to_owned(),
            path,
            attribute: Some(attribute),
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

/// XML item template. The first matching occurrence of a field inside an item wins.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct XmlTemplate {
    /// Element that delimits one row, matched at any depth outside another row.
    pub item: XmlName,
    /// Field mapping in output order (output maps are sorted by field name).
    pub fields: Vec<XmlField>,
}

impl XmlTemplate {
    /// Validate and build a template.
    ///
    /// # Errors
    /// Rejects an empty field list, empty or duplicate field names, empty local names and two
    /// fields reading the same element or attribute.
    pub fn new(item: XmlName, fields: Vec<XmlField>) -> Result<Self, FeedStreamError> {
        let template = Self { item, fields };
        template.validate()?;
        Ok(template)
    }

    /// Check the template; run again after editing public fields.
    ///
    /// # Errors
    /// Same conditions as [`Self::new`].
    pub fn validate(&self) -> Result<(), FeedStreamError> {
        let (item, fields) = (&self.item, &self.fields);
        if item.local.is_empty() {
            return Err(template("item element name is empty"));
        }
        if fields.is_empty() {
            return Err(template("xml template has no fields"));
        }
        let mut names = BTreeSet::new();
        let mut sources = BTreeSet::new();
        for field in fields {
            if field.name.is_empty() {
                return Err(template("field name is empty"));
            }
            if !names.insert(field.name.as_str()) {
                return Err(template("duplicate field name"));
            }
            if field.path.iter().any(|name| name.local.is_empty())
                || field.attribute.as_ref().is_some_and(|name| name.local.is_empty())
            {
                return Err(template("empty xml name in field path"));
            }
            if !sources.insert((&field.path, &field.attribute)) {
                return Err(template("two fields read the same xml source"));
            }
        }
        Ok(())
    }
}

/// How CSV columns get their field names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CsvHeader {
    /// First record is the header. With an empty `rename` every column keeps its header text as
    /// the field name; otherwise only the listed headers are kept, renamed to their value.
    FirstRow {
        /// Header text to field name.
        rename: BTreeMap<String, String>,
    },
    /// No header record; column `i` is named by entry `i`.
    Positional(Vec<String>),
}

/// CSV row template (RFC 4180 quoting with a configurable delimiter and quote byte).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CsvTemplate {
    /// Field delimiter byte.
    pub delimiter: u8,
    /// Quote byte; a doubled quote inside a quoted field is one literal quote.
    pub quote: u8,
    /// Column naming.
    pub header: CsvHeader,
    /// Output field names that must be non-empty.
    pub required: Vec<String>,
}

impl CsvTemplate {
    /// Comma-delimited, `"`-quoted template whose header row names the fields.
    #[must_use]
    pub fn with_header() -> Self {
        Self {
            delimiter: b',',
            quote: b'"',
            header: CsvHeader::FirstRow {
                rename: BTreeMap::new(),
            },
            required: Vec::new(),
        }
    }

    /// Comma-delimited, `"`-quoted template without a header row.
    ///
    /// # Errors
    /// Rejects an empty or duplicate column name list.
    pub fn positional(columns: &[&str]) -> Result<Self, FeedStreamError> {
        let template = Self {
            delimiter: b',',
            quote: b'"',
            header: CsvHeader::Positional(columns.iter().map(|name| (*name).to_owned()).collect()),
            required: Vec::new(),
        };
        template.validate()?;
        Ok(template)
    }

    /// Use another delimiter byte.
    #[must_use]
    pub fn delimiter(mut self, delimiter: u8) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Use another quote byte.
    #[must_use]
    pub fn quote(mut self, quote: u8) -> Self {
        self.quote = quote;
        self
    }

    /// Keep only mapped header columns: `header` becomes output field `field`.
    #[must_use]
    pub fn map_column(mut self, header: &str, field: &str) -> Self {
        if let CsvHeader::FirstRow { rename } = &mut self.header {
            rename.insert(header.to_owned(), field.to_owned());
        }
        self
    }

    /// Require output field `field` to be non-empty on every row.
    #[must_use]
    pub fn require(mut self, field: &str) -> Self {
        self.required.push(field.to_owned());
        self
    }

    /// Check delimiter/quote bytes and name lists.
    ///
    /// # Errors
    /// Rejects line-break or equal delimiter/quote bytes, empty or duplicate names and required
    /// fields that a positional header cannot produce.
    pub fn validate(&self) -> Result<(), FeedStreamError> {
        if matches!(self.delimiter, b'\r' | b'\n') || matches!(self.quote, b'\r' | b'\n') {
            return Err(template("csv delimiter and quote must not be line breaks"));
        }
        if self.delimiter == self.quote {
            return Err(template("csv delimiter and quote must differ"));
        }
        match &self.header {
            CsvHeader::FirstRow { rename } => {
                let mut seen = BTreeSet::new();
                for (header, field) in rename {
                    if header.is_empty() || field.is_empty() {
                        return Err(template("csv column mapping contains an empty name"));
                    }
                    if !seen.insert(field.as_str()) {
                        return Err(template("two csv columns map to one field"));
                    }
                }
                if !rename.is_empty() {
                    let fields: BTreeSet<&str> = rename.values().map(String::as_str).collect();
                    if self.required.iter().any(|name| !fields.contains(name.as_str())) {
                        return Err(template("required csv field is not mapped"));
                    }
                }
            }
            CsvHeader::Positional(columns) => {
                if columns.is_empty() {
                    return Err(template("csv template has no columns"));
                }
                let mut seen = BTreeSet::new();
                for name in columns {
                    if name.is_empty() {
                        return Err(template("csv column name is empty"));
                    }
                    if !seen.insert(name.as_str()) {
                        return Err(template("duplicate csv column name"));
                    }
                }
                if self.required.iter().any(|name| !seen.contains(name.as_str())) {
                    return Err(template("required csv field is not a column"));
                }
            }
        }
        Ok(())
    }
}

/// Row template for one streamed source format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeedTemplate {
    /// XML item rows.
    Xml(XmlTemplate),
    /// CSV records.
    Csv(CsvTemplate),
}

impl FeedTemplate {
    /// Unnamespaced `<item>` rows with `title`, `link`, `guid`, `pub_date` and `description`.
    #[must_use]
    pub fn rss_items() -> Self {
        let leaf = |field: &str, element: &str| XmlField::element(field, vec![XmlName::local(element)]);
        let fields = vec![
            leaf("title", "title"),
            leaf("link", "link"),
            leaf("guid", "guid"),
            leaf("pub_date", "pubDate"),
            leaf("description", "description"),
        ];
        Self::Xml(XmlTemplate {
            item: XmlName::local("item"),
            fields,
        })
    }

    /// Atom `<entry>` rows with `id`, `title`, `updated`, `summary` and the first `link@href`.
    ///
    /// The `link` field is the `href` of the first `link` element in the entry.
    #[must_use]
    pub fn atom_entries() -> Self {
        let atom = |local: &str| XmlName::namespaced(ATOM_NS, local);
        let leaf = |field: &str, element: &str| XmlField::element(field, vec![atom(element)]);
        let fields = vec![
            leaf("id", "id"),
            leaf("title", "title"),
            leaf("updated", "updated"),
            leaf("summary", "summary"),
            XmlField::attribute("link", vec![atom("link")], XmlName::local("href")),
        ];
        Self::Xml(XmlTemplate {
            item: atom("entry"),
            fields,
        })
    }
}

fn template(reason: &str) -> FeedStreamError {
    FeedStreamError::Template(reason.to_owned())
}
