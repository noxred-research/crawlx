//! Line diff of two markdown documents for monitor checks: a unified diff (`diff.text`) and the
//! same hunks as a `parse-diff` style AST (`diff.json`, `{files:[{from,to,chunks,...}]}`).
//!
//! The edit script comes from Myers' O(ND) algorithm over lines. Common leading and trailing
//! lines are trimmed first, so a small edit in a large page costs little; when the edit distance
//! of the middle exceeds [`MAX_EDIT_DISTANCE`] the middle is reported as one replaced block (still
//! a correct diff, only not minimal). Output is capped at [`MAX_DIFF_LINES`] lines and marked
//! `truncated`.

use serde_json::{json, Value};

/// Unchanged lines shown around a change.
pub const CONTEXT_LINES: usize = 3;
/// Largest edit distance the Myers search explores before falling back to a replaced block.
pub const MAX_EDIT_DISTANCE: usize = 1_000;
/// Most lines (context included) the rendered diff carries.
pub const MAX_DIFF_LINES: usize = 5_000;

/// A rendered diff.
#[derive(Clone, PartialEq, Debug)]
pub struct Diff {
    /// Unified diff text (`--- previous` / `+++ current` / hunks).
    pub text: String,
    /// `parse-diff` AST (`{files: [...]}`).
    pub json: Value,
    /// Lines added.
    pub additions: usize,
    /// Lines removed.
    pub deletions: usize,
    /// The output hit [`MAX_DIFF_LINES`].
    pub truncated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    /// Line `a` of the old text equals line `b` of the new text.
    Equal(usize, usize),
    /// Line `a` of the old text is gone.
    Delete(usize),
    /// Line `b` of the new text is new.
    Insert(usize),
}

fn to_isize(n: usize) -> isize {
    isize::try_from(n).unwrap_or(isize::MAX)
}

fn to_usize(n: isize) -> usize {
    usize::try_from(n).unwrap_or(0)
}

/// Myers shortest edit script between `a` and `b`; `None` when it exceeds `limit` edits.
fn myers(a: &[&str], b: &[&str], limit: usize) -> Option<Vec<Op>> {
    let n = to_isize(a.len());
    let m = to_isize(b.len());
    if a.is_empty() && b.is_empty() {
        return Some(Vec::new());
    }
    let max = to_usize(n + m).min(limit);
    let offset = to_isize(max) + 1;
    let at = |k: isize| to_usize(k + offset);
    let mut v = vec![0_isize; 2 * max + 3];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    for d in 0..=to_isize(max) {
        trace.push(v[at(-d - 1)..=at(d + 1)].to_vec());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) {
                v[at(k + 1)]
            } else {
                v[at(k - 1)] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[to_usize(x)] == b[to_usize(y)] {
                x += 1;
                y += 1;
            }
            v[at(k)] = x;
            if x >= n && y >= m {
                return Some(backtrack(&trace, a.len(), b.len(), d));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(trace: &[Vec<isize>], n: usize, m: usize, last: isize) -> Vec<Op> {
    let mut x = to_isize(n);
    let mut y = to_isize(m);
    let mut ops: Vec<Op> = Vec::new();
    for d in (0..=last).rev() {
        // round `d` saved the diagonals -d-1 ..= d+1
        let round = &trace[to_usize(d)];
        let v = |k: isize| round[to_usize(k + d + 1)];
        let k = x - y;
        let prev_k = if k == -d || (k != d && v(k - 1) < v(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = v(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Equal(to_usize(x - 1), to_usize(y - 1)));
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(Op::Insert(to_usize(prev_y)));
            } else {
                ops.push(Op::Delete(to_usize(prev_x)));
            }
        }
        x = prev_x;
        y = prev_y;
    }
    ops.reverse();
    ops
}

/// The full edit script of `old` to `new`.
fn script(old: &[&str], new: &[&str]) -> Vec<Op> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let max_suffix = old.len().min(new.len()) - prefix;
    let suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(max_suffix)
        .take_while(|(a, b)| a == b)
        .count();
    let a = &old[prefix..old.len() - suffix];
    let b = &new[prefix..new.len() - suffix];
    let mut ops: Vec<Op> = (0..prefix).map(|i| Op::Equal(i, i)).collect();
    match myers(a, b, MAX_EDIT_DISTANCE) {
        Some(middle) => ops.extend(middle.into_iter().map(|op| match op {
            Op::Equal(x, y) => Op::Equal(x + prefix, y + prefix),
            Op::Delete(x) => Op::Delete(x + prefix),
            Op::Insert(y) => Op::Insert(y + prefix),
        })),
        None => {
            ops.extend((0..a.len()).map(|i| Op::Delete(i + prefix)));
            ops.extend((0..b.len()).map(|j| Op::Insert(j + prefix)));
        }
    }
    ops.extend((0..suffix).map(|i| Op::Equal(old.len() - suffix + i, new.len() - suffix + i)));
    ops
}

/// Diff `previous` against `current`; `None` when the line sequences are identical.
#[must_use]
pub fn diff(previous: &str, current: &str) -> Option<Diff> {
    let old: Vec<&str> = previous.lines().collect();
    let new: Vec<&str> = current.lines().collect();
    let ops = script(&old, &new);
    if ops.iter().all(|op| matches!(op, Op::Equal(..))) {
        return None;
    }
    // (old lines consumed, new lines consumed) before each op
    let mut before = Vec::with_capacity(ops.len());
    let (mut ai, mut bi) = (0_usize, 0_usize);
    for op in &ops {
        before.push((ai, bi));
        match op {
            Op::Equal(..) => {
                ai += 1;
                bi += 1;
            }
            Op::Delete(_) => ai += 1,
            Op::Insert(_) => bi += 1,
        }
    }
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Op::Equal(..)))
        .map(|(i, _)| i)
        .collect();
    // hunks: runs of changes closer than two contexts apart merge
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for &i in &changed {
        match spans.last_mut() {
            Some((_, end)) if i <= *end + 2 * CONTEXT_LINES + 1 => *end = i,
            _ => spans.push((i, i)),
        }
    }
    let mut text = String::from("--- previous\n+++ current\n");
    let mut chunks: Vec<Value> = Vec::new();
    let (mut additions, mut deletions) = (0_usize, 0_usize);
    let mut emitted = 0_usize;
    let mut truncated = false;
    'hunks: for (first, last) in spans {
        let start = first.saturating_sub(CONTEXT_LINES);
        let end = (last + CONTEXT_LINES).min(ops.len() - 1);
        let (old_from, new_from) = before[start];
        let mut old_lines = 0_usize;
        let mut new_lines = 0_usize;
        let mut body = String::new();
        let mut changes: Vec<Value> = Vec::new();
        for (idx, op) in ops.iter().enumerate().take(end + 1).skip(start) {
            if emitted >= MAX_DIFF_LINES {
                truncated = true;
                break;
            }
            emitted += 1;
            let (old_no, new_no) = (before[idx].0 + 1, before[idx].1 + 1);
            match *op {
                Op::Equal(a, _) => {
                    old_lines += 1;
                    new_lines += 1;
                    body.push(' ');
                    body.push_str(old[a]);
                    body.push('\n');
                    changes.push(json!({
                        "type": "normal", "normal": true, "ln1": old_no, "ln2": new_no,
                        "content": format!(" {}", old[a]),
                    }));
                }
                Op::Delete(a) => {
                    old_lines += 1;
                    deletions += 1;
                    body.push('-');
                    body.push_str(old[a]);
                    body.push('\n');
                    changes.push(json!({
                        "type": "del", "del": true, "ln": old_no, "content": format!("-{}", old[a]),
                    }));
                }
                Op::Insert(b) => {
                    new_lines += 1;
                    additions += 1;
                    body.push('+');
                    body.push_str(new[b]);
                    body.push('\n');
                    changes.push(json!({
                        "type": "add", "add": true, "ln": new_no, "content": format!("+{}", new[b]),
                    }));
                }
            }
        }
        // git convention: an empty side is addressed by the line before it
        let old_start = if old_lines == 0 { old_from } else { old_from + 1 };
        let new_start = if new_lines == 0 { new_from } else { new_from + 1 };
        let header = format!("@@ -{old_start},{old_lines} +{new_start},{new_lines} @@");
        text.push_str(&header);
        text.push('\n');
        text.push_str(&body);
        chunks.push(json!({
            "content": header,
            "changes": changes,
            "oldStart": old_start,
            "oldLines": old_lines,
            "newStart": new_start,
            "newLines": new_lines,
        }));
        if truncated {
            break 'hunks;
        }
    }
    if truncated {
        text.push_str("\\ diff truncated\n");
    }
    let json = json!({
        "files": [{
            "from": "previous",
            "to": "current",
            "chunks": chunks,
            "additions": additions,
            "deletions": deletions,
        }]
    });
    Some(Diff {
        text,
        json,
        additions,
        deletions,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn identical_texts_have_no_diff() {
        assert!(diff("a\nb\n", "a\nb\n").is_none());
        assert!(diff("", "").is_none());
        // a trailing newline alone is not a line change
        assert!(diff("a\nb", "a\nb\n").is_none());
    }

    #[test]
    fn replaced_line_renders_a_unified_hunk() {
        let d = diff(
            "# Pricing\nStarter — $19/mo\nPro\n",
            "# Pricing\nStarter — $24/mo\nPro\n",
        )
        .unwrap();
        assert_eq!(
            d.text,
            "--- previous\n+++ current\n@@ -1,3 +1,3 @@\n # Pricing\n-Starter — $19/mo\n+Starter — $24/mo\n Pro\n"
        );
        assert_eq!((d.additions, d.deletions), (1, 1));
        let chunk = &d.json["files"][0]["chunks"][0];
        assert_eq!(chunk["content"], "@@ -1,3 +1,3 @@");
        assert_eq!(chunk["changes"][1]["type"], "del");
        assert_eq!(chunk["changes"][2]["type"], "add");
        assert_eq!(chunk["changes"][2]["ln"], 2);
        assert!(!d.truncated);
    }

    #[test]
    fn insertion_and_deletion_at_the_edges() {
        let d = diff("b\nc\n", "a\nb\nc\n").unwrap();
        assert_eq!(d.text, "--- previous\n+++ current\n@@ -1,2 +1,3 @@\n+a\n b\n c\n");
        let d = diff("a\nb\nc\n", "a\nb\n").unwrap();
        assert_eq!(d.text, "--- previous\n+++ current\n@@ -1,3 +1,2 @@\n a\n b\n-c\n");
        let d = diff("", "x\ny\n").unwrap();
        assert_eq!(d.text, "--- previous\n+++ current\n@@ -0,0 +1,2 @@\n+x\n+y\n");
        let d = diff("x\ny\n", "").unwrap();
        assert_eq!(d.text, "--- previous\n+++ current\n@@ -1,2 +0,0 @@\n-x\n-y\n");
    }

    #[test]
    fn distant_changes_make_separate_hunks_and_near_ones_merge() {
        let old: Vec<String> = (1..=30).map(|i| format!("line {i}")).collect();
        let mut new = old.clone();
        new[1] = "changed 2".to_owned();
        new[27] = "changed 28".to_owned();
        let d = diff(&old.join("\n"), &new.join("\n")).unwrap();
        assert_eq!(d.json["files"][0]["chunks"].as_array().unwrap().len(), 2);
        let mut near = old.clone();
        near[1] = "changed 2".to_owned();
        near[6] = "changed 7".to_owned();
        let d = diff(&old.join("\n"), &near.join("\n")).unwrap();
        assert_eq!(d.json["files"][0]["chunks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn applying_the_script_reproduces_the_new_text() {
        let old = "a\nb\nc\nd\ne\nf\ng\n";
        let new = "a\nc\nd\nx\ne\ng\nh\n";
        let o: Vec<&str> = old.lines().collect();
        let n: Vec<&str> = new.lines().collect();
        let mut rebuilt: Vec<&str> = Vec::new();
        for op in script(&o, &n) {
            match op {
                Op::Equal(_, b) | Op::Insert(b) => rebuilt.push(n[b]),
                Op::Delete(_) => {}
            }
        }
        assert_eq!(rebuilt, n);
    }

    #[test]
    fn huge_edit_distance_falls_back_to_a_replaced_block() {
        let old: Vec<String> = (0..3_000).map(|i| format!("old {i}")).collect();
        let new: Vec<String> = (0..3_000).map(|i| format!("new {i}")).collect();
        let d = diff(&old.join("\n"), &new.join("\n")).unwrap();
        // 3000 deletions fill most of the 5000-line budget, 2000 insertions fit after them
        assert_eq!((d.additions, d.deletions), (MAX_DIFF_LINES - 3_000, 3_000));
        assert!(d.truncated, "6000 changed lines exceed the output cap");
        assert!(d.text.ends_with("\\ diff truncated\n"));
        assert_eq!(d.json["files"][0]["chunks"].as_array().unwrap().len(), 1);
    }
}
