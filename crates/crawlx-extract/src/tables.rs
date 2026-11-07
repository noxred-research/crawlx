//! HTML table model and GitHub-flavoured pipe-table rendering
//! (module `tables`).
//!
//! `colspan` is expanded into empty cells after the spanning cell and
//! `rowspan` into empty cells in the following rows, so every row has the same
//! number of columns. The header row is the first row when it lives in
//! `thead` or consists only of `th` cells; otherwise an empty header row is
//! emitted because GFM requires one.

use crate::dom::Elem;

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

    fn grid(&self, cell_text: &mut dyn FnMut(&Elem) -> String) -> Vec<(Vec<GridCell>, bool)> {
        let mut budget = CELL_BUDGET;
        let mut pending: Vec<usize> = Vec::new();
        let mut rows = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut out: Vec<GridCell> = Vec::new();
            let empty = |header, align| GridCell {
                text: String::new(),
                header,
                align,
            };
            for cell in &row.cells {
                while pending.get(out.len()).copied().unwrap_or(0) > 0 {
                    let col = out.len();
                    pending[col] -= 1;
                    out.push(empty(false, Align::None));
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
                    }
                    if rs > 1 {
                        pending[col] = rs - 1;
                    }
                    out.push(if k == 0 {
                        GridCell {
                            text: text.clone(),
                            header: cell.header,
                            align: cell.align,
                        }
                    } else {
                        empty(cell.header, cell.align)
                    });
                }
            }
            while pending.get(out.len()).copied().unwrap_or(0) > 0 {
                let col = out.len();
                pending[col] -= 1;
                out.push(empty(false, Align::None));
            }
            rows.push((out, row.in_thead));
        }
        rows
    }

    /// Render as a GFM pipe table, or `None` when the table has no content.
    pub fn render(&self, cell_text: &mut dyn FnMut(&Elem) -> String) -> Option<String> {
        let mut rows = self.grid(cell_text);
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
