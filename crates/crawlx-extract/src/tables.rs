//! HTML table model and GitHub-flavoured pipe-table rendering
//! (module `tables`).
//!
//! `colspan` is expanded into empty cells after the spanning cell and
//! `rowspan` into empty cells in the following rows, so every row has the same
//! number of columns. The header row is the first row when it lives in
//! `thead` or consists only of `th` cells; otherwise an empty header row is
//! emitted because GFM requires one.

use serde::{Deserialize, Serialize};

use crate::dom::{collapse_ws, Elem, Node};
use crate::text::to_text;

/// Largest honoured `colspan`/`rowspan`.
const MAX_SPAN: usize = 64;
/// Upper bound on columns per row.
const MAX_COLS: usize = 1024;
/// Budget of expanded cells per table; spans collapse to 1 once exhausted.
const CELL_BUDGET: usize = 500_000;

/// Column alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    /// No explicit alignment.
    #[default]
    None,
    /// Left aligned.
    Left,
    /// Centered.
    Center,
    /// Right aligned.
    Right,
}

/// One `td`/`th`.
#[derive(Debug)]
pub struct Cell<'a> {
    /// The cell element.
    pub elem: &'a Elem,
    /// `th` cell.
    pub header: bool,
    /// Columns spanned (>= 1).
    pub colspan: usize,
    /// Rows spanned (>= 1).
    pub rowspan: usize,
    /// Alignment from `align` or inline `text-align`.
    pub align: Align,
}

/// One `tr`.
#[derive(Debug)]
pub struct Row<'a> {
    /// Cells in order.
    pub cells: Vec<Cell<'a>>,
    /// Row is inside a `thead`.
    pub in_thead: bool,
}

/// Structural view of a `table` element.
#[derive(Debug, Default)]
pub struct Table<'a> {
    /// `caption` element.
    pub caption: Option<&'a Elem>,
    /// Rows in document order.
    pub rows: Vec<Row<'a>>,
}

fn parse_span(e: &Elem, name: &str) -> usize {
    e.attr(name)
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map_or(1, |n| n.clamp(1, MAX_SPAN))
}

fn align_of(e: &Elem) -> Align {
    let from = |v: &str| match v.trim().to_ascii_lowercase().as_str() {
        "left" | "start" => Some(Align::Left),
        "center" | "middle" => Some(Align::Center),
        "right" | "end" => Some(Align::Right),
        _ => None,
    };
    if let Some(a) = e.attr("align").and_then(from) {
        return a;
    }
    if let Some(style) = e.attr("style") {
        for decl in style.split(';') {
            if let Some((p, v)) = decl.split_once(':') {
                if p.trim().eq_ignore_ascii_case("text-align") {
                    if let Some(a) = from(v.trim().trim_end_matches("!important")) {
                        return a;
                    }
                }
            }
        }
    }
    Align::None
}

fn row_of(tr: &Elem, in_thead: bool) -> Row<'_> {
    let cells = tr
        .child_elems()
        .filter(|c| c.tag == "td" || c.tag == "th")
        .map(|c| Cell {
            elem: c,
            header: c.tag == "th",
            colspan: parse_span(c, "colspan"),
            rowspan: parse_span(c, "rowspan"),
            align: align_of(c),
        })
        .collect();
    Row { cells, in_thead }
}

fn collect_into<'a>(e: &'a Elem, in_thead: bool, t: &mut Table<'a>) {
    for c in e.child_elems() {
        match c.tag.as_str() {
            "caption" => {
                t.caption.get_or_insert(c);
            }
            "thead" => collect_into(c, true, t),
            "tbody" | "tfoot" => collect_into(c, in_thead, t),
            "tr" => t.rows.push(row_of(c, in_thead)),
            _ => {}
        }
    }
}

/// Build the structural model of `table`.
#[must_use]
pub fn collect(table: &Elem) -> Table<'_> {
    let mut t = Table::default();
    collect_into(table, false, &mut t);
    t
}

#[derive(Clone)]
struct GridCell {
    text: String,
    header: bool,
    align: Align,
}

impl Table<'_> {
    /// The only cell when the table is a single-cell layout wrapper.
    #[must_use]
    pub fn single_cell(&self) -> Option<&Elem> {
        match self.rows.as_slice() {
            [row] => match row.cells.as_slice() {
                [cell] => Some(cell.elem),
                _ => None,
            },
            _ => None,
        }
    }

    /// Expand spans into a rectangular grid. With `repeat`, every slot a span covers carries the
    /// spanning cell's text and header flag; otherwise covered slots are empty.
    fn grid(&self, cell_text: &mut dyn FnMut(&Elem) -> String, repeat: bool) -> Vec<(Vec<GridCell>, bool)> {
        let mut budget = CELL_BUDGET;
        let mut pending: Vec<usize> = Vec::new();
        let mut carried: Vec<GridCell> = Vec::new();
        let mut rows = Vec::with_capacity(self.rows.len());
        let empty = |header, align| GridCell {
            text: String::new(),
            header,
            align,
        };
        for row in &self.rows {
            let mut out: Vec<GridCell> = Vec::new();
            for cell in &row.cells {
                while pending.get(out.len()).copied().unwrap_or(0) > 0 {
                    let col = out.len();
                    pending[col] -= 1;
                    out.push(if repeat {
                        carried[col].clone()
                    } else {
                        empty(false, Align::None)
                    });
                }
                let (cs, rs) = if budget >= cell.colspan * cell.rowspan {
                    (cell.colspan, cell.rowspan)
                } else {
                    (1, 1)
                };
                budget = budget.saturating_sub(cs * rs);
                let text = cell_text(cell.elem);
                for k in 0..cs {
                    let col = out.len();
                    if col >= MAX_COLS {
                        break;
                    }
                    if pending.len() <= col {
                        pending.resize(col + 1, 0);
                        carried.resize(col + 1, empty(false, Align::None));
                    }
                    let slot = if k == 0 || repeat {
                        GridCell {
                            text: text.clone(),
                            header: cell.header,
                            align: cell.align,
                        }
                    } else {
                        empty(cell.header, cell.align)
                    };
                    if rs > 1 {
                        pending[col] = rs - 1;
                        carried[col] = slot.clone();
                    }
                    out.push(slot);
                }
            }
            while pending.get(out.len()).copied().unwrap_or(0) > 0 {
                let col = out.len();
                pending[col] -= 1;
                out.push(if repeat {
                    carried[col].clone()
                } else {
                    empty(false, Align::None)
                });
            }
            rows.push((out, row.in_thead));
        }
        rows
    }

    /// Render as a GFM pipe table, or `None` when the table has no content.
    pub fn render(&self, cell_text: &mut dyn FnMut(&Elem) -> String) -> Option<String> {
        let mut rows = self.grid(cell_text, false);
        rows.retain(|(cells, _)| cells.iter().any(|c| !c.text.is_empty()));
        if rows.is_empty() {
            return None;
        }
        let ncols = rows.iter().map(|(c, _)| c.len()).max().unwrap_or(0);
        if ncols == 0 {
            return None;
        }
        let first_is_header = {
            let (cells, in_thead) = &rows[0];
            *in_thead || (!cells.is_empty() && cells.iter().all(|c| c.header))
        };
        let header: Vec<GridCell> = if first_is_header {
            rows.remove(0).0
        } else {
            Vec::new()
        };
        let align_source: &[GridCell] = if first_is_header {
            &header
        } else {
            rows.first().map_or(&[][..], |(c, _)| c.as_slice())
        };
        let aligns: Vec<Align> = (0..ncols)
            .map(|i| align_source.get(i).map_or(Align::None, |c| c.align))
            .collect();

        let line = |cells: &[GridCell]| {
            let mut s = String::from("|");
            for i in 0..ncols {
                s.push(' ');
                if let Some(c) = cells.get(i) {
                    s.push_str(&c.text);
                }
                s.push_str(" |");
            }
            s
        };
        let mut lines = Vec::with_capacity(rows.len() + 2);
        lines.push(line(&header));
        let mut sep = String::from("|");
        for a in &aligns {
            sep.push_str(match a {
                Align::None => " --- |",
                Align::Left => " :--- |",
                Align::Center => " :---: |",
                Align::Right => " ---: |",
            });
        }
        lines.push(sep);
        for (cells, _) in &rows {
            lines.push(line(cells));
        }
        Some(lines.join("\n"))
    }
}

/// Version of the table scoring and row normalization rules. Any change to a weight, threshold
/// or normalization step must bump it.
pub const TABLE_RULES_VERSION: &str = "table_rules_v1";
/// Most tables reported for one document; the rest set [`TableExtraction::truncated`].
pub const MAX_TABLES: usize = 256;
/// Deepest table nesting examined.
const MAX_NESTING: usize = 32;
/// Total score from which a table is data.
const DATA_THRESHOLD: u32 = 600;
/// Total score up to which a table is layout.
const LAYOUT_THRESHOLD: u32 = 350;
/// Link density (permille of cell text inside anchors) from which a table is layout.
const LINK_LAYOUT_PERMILLE: u32 = 700;
/// Share of rows (permille) that must span the full column count for a data table.
const RAGGED_PERMILLE: u32 = 700;
/// Mean cell length (characters) up to which cells count as short.
const SHORT_CELL: u64 = 80;
/// Mean cell length (characters) from which cells count as prose.
const PROSE_CELL: u64 = 400;

const BLOCK_IN_CELL: &[&str] = &[
    "div",
    "p",
    "ul",
    "ol",
    "dl",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "form",
    "section",
    "article",
    "pre",
    "table",
];

/// What a table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TableKind {
    /// Tabular data: normalized rows are reported.
    Data,
    /// Used for page layout: no rows are reported, nested tables are examined on their own.
    Layout,
    /// The evidence does not settle it: no rows are reported.
    Ambiguous,
}

/// Score components of one table, each 0..=1000 permille except the counts. The components stay
/// separate so an ambiguous outcome can be explained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct TableScore {
    /// Rows after dropping fully empty ones.
    pub rows: usize,
    /// Columns after span expansion.
    pub columns: usize,
    /// Leading header rows (`thead` rows or all-`th` rows).
    pub header_rows: usize,
    /// Tables nested inside the cells of this one.
    pub nested_tables: usize,
    /// Permille of cell text that sits inside anchors.
    pub link_density: u32,
    /// More than one row and column.
    pub shape: u32,
    /// Rows that span exactly the full column count.
    pub consistency: u32,
    /// Header evidence: header rows, or `th` cells.
    pub header: u32,
    /// One minus link density.
    pub link: u32,
    /// No nested tables, few block-level cells.
    pub structure: u32,
    /// Share of non-empty cells.
    pub fill: u32,
    /// Short cells (data) against prose cells (layout).
    pub brevity: u32,
    /// Weighted total.
    pub total: u32,
}

/// Outcome of analysing one table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableAnalysis {
    /// Data, layout or ambiguous.
    pub kind: TableKind,
    /// Score components.
    pub score: TableScore,
    /// Collapsed caption text.
    pub caption: Option<String>,
    /// Normalized column names; empty unless data with header rows.
    pub header: Vec<String>,
    /// Normalized rows; empty unless data.
    pub rows: Vec<Vec<String>>,
}

#[derive(Default)]
struct Acc {
    cells: usize,
    nonempty: usize,
    text_chars: u64,
    link_chars: u64,
    block_cells: usize,
    nested: usize,
    any_th: bool,
}

fn text_len(e: &Elem, in_link: bool, chars: &mut u64, links: &mut u64) {
    let in_link = in_link || e.tag == "a";
    for c in &e.children {
        match c {
            Node::Text(t) => {
                let n = u64::try_from(t.chars().filter(|c| !c.is_whitespace()).count()).unwrap_or(u64::MAX);
                *chars = chars.saturating_add(n);
                if in_link {
                    *links = links.saturating_add(n);
                }
            }
            Node::Elem(child) => text_len(child, in_link, chars, links),
        }
    }
}

fn count_tables(e: &Elem) -> usize {
    e.child_elems()
        .map(|c| usize::from(c.tag == "table") + count_tables(c))
        .sum()
}

fn has_block(e: &Elem) -> bool {
    e.child_elems()
        .any(|c| BLOCK_IN_CELL.contains(&c.tag.as_str()) || has_block(c))
}

fn permille(part: usize, whole: usize) -> u32 {
    if whole == 0 {
        return 0;
    }
    let v = part.saturating_mul(1_000) / whole;
    u32::try_from(v.min(1_000)).unwrap_or(1_000)
}

impl Table<'_> {
    /// Score the table and, when it is a data table, normalize its rows.
    ///
    /// Normalization (`table_rules_v1`): spans repeat the spanning cell's whitespace-collapsed text
    /// into every slot they cover; fully empty rows are dropped; the leading `thead` or all-`th`
    /// rows are header rows, merged per column by joining their distinct consecutive non-empty
    /// parts with ` / `; data rows are padded to the column count.
    ///
    /// Decision: a single-cell, empty or nested-table-bearing table is layout; so is one whose
    /// cell text is mostly links (70% or more). Otherwise the weighted score decides: 600 or more
    /// is data, 350 or less layout, the band between ambiguous. A one-row or one-column table
    /// without header rows, a table without data rows, or one where fewer than 70% of the rows
    /// span the full column count is at best ambiguous.
    #[must_use]
    pub fn analyze(&self) -> TableAnalysis {
        let mut acc = Acc::default();
        let mut text = |cell: &Elem| -> String {
            let t = collapse_ws(&to_text(&cell.children));
            acc.cells += 1;
            if !t.is_empty() {
                acc.nonempty += 1;
            }
            let (mut chars, mut links) = (0, 0);
            text_len(cell, false, &mut chars, &mut links);
            acc.text_chars = acc.text_chars.saturating_add(chars);
            acc.link_chars = acc.link_chars.saturating_add(links);
            if has_block(cell) {
                acc.block_cells += 1;
            }
            acc.nested += count_tables(cell);
            if cell.tag == "th" {
                acc.any_th = true;
            }
            t
        };
        let mut grid = self.grid(&mut text, true);
        grid.retain(|(cells, _)| cells.iter().any(|c| !c.text.is_empty()));
        let caption = self
            .caption
            .map(|c| collapse_ws(&to_text(&c.children)))
            .filter(|c| !c.is_empty());
        let rows = grid.len();
        let columns = grid.iter().map(|(c, _)| c.len()).max().unwrap_or(0);
        let header_rows = grid
            .iter()
            .take_while(|(cells, in_thead)| {
                *in_thead || (!cells.is_empty() && cells.iter().all(|c| c.header))
            })
            .count();
        let consistent = grid.iter().filter(|(c, _)| c.len() == columns).count();

        let link_density = acc
            .link_chars
            .saturating_mul(1_000)
            .checked_div(acc.text_chars)
            .map_or(0, |d| u32::try_from(d.min(1_000)).unwrap_or(1_000));
        let shape = if rows == 0 || columns == 0 || (rows == 1 && columns == 1) {
            0
        } else if rows >= 2 && columns >= 2 {
            1_000
        } else {
            400
        };
        let consistency = permille(consistent, rows);
        let header = if header_rows > 0 {
            1_000
        } else if acc.any_th {
            500
        } else {
            0
        };
        let structure = if acc.nested > 0 {
            0
        } else {
            1_000 - permille(acc.block_cells, acc.cells.max(1))
        };
        let fill = permille(acc.nonempty, acc.cells.max(1));
        let mean_cell = acc
            .text_chars
            .checked_div(u64::try_from(acc.nonempty).unwrap_or(u64::MAX).max(1))
            .unwrap_or(0);
        let brevity = if mean_cell <= SHORT_CELL {
            1_000
        } else if mean_cell >= PROSE_CELL {
            0
        } else {
            u32::try_from((PROSE_CELL - mean_cell) * 1_000 / (PROSE_CELL - SHORT_CELL)).unwrap_or(0)
        };
        let link = 1_000 - link_density;
        let total = (100 * shape
            + 150 * consistency
            + 150 * header
            + 100 * link
            + 200 * structure
            + 100 * fill
            + 200 * brevity)
            / 1_000;

        let one_dimensional = rows < 2 || columns < 2;
        let data_rows = rows - header_rows;
        let kind = if rows == 0
            || columns == 0
            || (rows == 1 && columns == 1)
            || acc.nested > 0
            || link_density >= LINK_LAYOUT_PERMILLE
        {
            TableKind::Layout
        } else if total >= DATA_THRESHOLD {
            if (one_dimensional && header_rows == 0) || data_rows == 0 || consistency < RAGGED_PERMILLE {
                TableKind::Ambiguous
            } else {
                TableKind::Data
            }
        } else if total <= LAYOUT_THRESHOLD {
            TableKind::Layout
        } else {
            TableKind::Ambiguous
        };

        let (header_out, rows_out) = if kind == TableKind::Data {
            fn text_at(row: &[GridCell], col: usize) -> &str {
                row.get(col).map_or("", |c| c.text.as_str())
            }
            let header_out: Vec<String> = if header_rows == 0 {
                Vec::new()
            } else {
                (0..columns)
                    .map(|col| {
                        let mut parts: Vec<&str> = Vec::new();
                        for (cells, _) in &grid[..header_rows] {
                            let part = text_at(cells, col);
                            if !part.is_empty() && parts.last() != Some(&part) {
                                parts.push(part);
                            }
                        }
                        parts.join(" / ")
                    })
                    .collect()
            };
            let rows_out = grid[header_rows..]
                .iter()
                .map(|(cells, _)| (0..columns).map(|col| text_at(cells, col).to_owned()).collect())
                .collect();
            (header_out, rows_out)
        } else {
            (Vec::new(), Vec::new())
        };

        TableAnalysis {
            kind,
            score: TableScore {
                rows,
                columns,
                header_rows,
                nested_tables: acc.nested,
                link_density,
                shape,
                consistency,
                header,
                link,
                structure,
                fill,
                brevity,
                total,
            },
            caption,
            header: header_out,
            rows: rows_out,
        }
    }
}

/// One table of a document with its analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ExtractedTable {
    /// Position in document order among all reported tables.
    pub index: usize,
    /// Table nesting depth; 0 for an outermost table.
    pub depth: usize,
    /// Index of the table whose cell contains this one.
    pub parent: Option<usize>,
    /// Data, layout or ambiguous.
    pub kind: TableKind,
    /// Score components.
    pub score: TableScore,
    /// Caption text.
    pub caption: Option<String>,
    /// Merged header names of a data table with header rows.
    pub header: Vec<String>,
    /// Normalized rows of a data table.
    pub rows: Vec<Vec<String>>,
}

/// All tables of a content tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct TableExtraction {
    /// Version of the scoring and normalization rules ([`TABLE_RULES_VERSION`]).
    pub rules: String,
    /// Tables in document order.
    pub tables: Vec<ExtractedTable>,
    /// More than [`MAX_TABLES`] tables, or nesting deeper than 32, were left out.
    pub truncated: bool,
}

fn walk_tables(node: &Node, depth: usize, parent: Option<usize>, out: &mut TableExtraction) {
    let Node::Elem(e) = node else {
        return;
    };
    if e.tag != "table" {
        for c in &e.children {
            walk_tables(c, depth, parent, out);
        }
        return;
    }
    if out.tables.len() >= MAX_TABLES || depth > MAX_NESTING {
        out.truncated = true;
        return;
    }
    let index = out.tables.len();
    let model = collect(e);
    let analysis = model.analyze();
    out.tables.push(ExtractedTable {
        index,
        depth,
        parent,
        kind: analysis.kind,
        score: analysis.score,
        caption: analysis.caption,
        header: analysis.header,
        rows: analysis.rows,
    });
    for row in &model.rows {
        for cell in &row.cells {
            for c in &cell.elem.children {
                walk_tables(c, depth + 1, Some(index), out);
            }
        }
    }
}

/// Analyse every table of `nodes` in document order. Tables nested in cells are reported with
/// their own analysis and the index of the enclosing table.
#[must_use]
pub fn extract_tables(nodes: &[Node]) -> TableExtraction {
    let mut out = TableExtraction {
        rules: TABLE_RULES_VERSION.to_owned(),
        tables: Vec::new(),
        truncated: false,
    };
    for n in nodes {
        walk_tables(n, 0, None, &mut out);
    }
    out
}
