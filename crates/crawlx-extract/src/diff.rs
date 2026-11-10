//! Change-tracking diffs (compatibility API `changeTracking`, `git-diff` and `json` modes).
//!
//! [`markdown_diff`] compares two Markdown documents line by line and renders the result the
//! way `git diff` does: hunks with three lines of context, a `@@ -a,b +c,d @@` header per hunk,
//! ` `/`-`/`+` line prefixes and, inside a hunk, the deleted lines of a changed block before its
//! added lines. The same hunks are returned structured as
//! `{"files":[{"from":null,"to":null,"chunks":[{"content":"@@ -1,3 +1,3 @@","changes":[...]}]}]}`;
//! a change is `{"type":"normal","ln1":n,"ln2":m,"content":..}` for context,
//! `{"type":"del","ln":old,"content":..}` or `{"type":"add","ln":new,"content":..}`, with the
//! line prefix removed from `content`. Line numbers are 1-based.
//!
//! Lines compare without trailing whitespace and with `\r\n` read as `\n`.
//!
//! [`json_diff`] is the field-level comparison of the `json` mode: every top-level key of either
//! document maps to `{"previous":..,"current":..}`, unchanged keys included, a missing side
//! being `null`.
//!
//! The line diff is Myers' algorithm (the `similar` crate). Inputs whose changed middle exceeds
//! [`MAX_DIFF_LINES`] lines are reported as one replaced block (still a valid, if coarser,
//! diff) so the work is bounded.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use similar::{capture_diff, group_diff_ops, Algorithm, DiffOp};

/// Lines of context around a change (git's default).
const CONTEXT_LINES: usize = 3;

/// Largest combined line count of the changed middle (what remains after the common prefix and
/// suffix) that is diffed minimally; larger middles become one replaced block.
pub const MAX_DIFF_LINES: usize = 20_000;

/// Result of [`markdown_diff`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct MarkdownDiff {
    /// Git-style hunk list; empty when the inputs are equal. Lines are joined by `\n` with no
    /// trailing newline.
    pub text: String,
    /// The same hunks as the compatibility API's structured `diff.json`.
    pub json: Value,
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().map(str::trim_end).collect()
}

/// Edit script from `old` to `new`, without the unchanged outer context.
fn script(old: &[&str], new: &[&str]) -> Vec<DiffOp> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let max_suffix = old.len().min(new.len()) - prefix;
    let suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(max_suffix)
        .take_while(|(a, b)| a == b)
        .count();
    let (old_end, new_end) = (old.len() - suffix, new.len() - suffix);
    let (old_mid, new_mid) = (old_end - prefix, new_end - prefix);

    let mut ops = Vec::new();
    if prefix > 0 {
        ops.push(DiffOp::Equal {
            old_index: 0,
            new_index: 0,
            len: prefix,
        });
    }
    if old_mid > 0 && new_mid > 0 {
        if old_mid + new_mid <= MAX_DIFF_LINES {
            ops.extend(capture_diff(
                Algorithm::Myers,
                old,
                prefix..old_end,
                new,
                prefix..new_end,
            ));
        } else {
            ops.push(DiffOp::Replace {
                old_index: prefix,
                old_len: old_mid,
                new_index: prefix,
                new_len: new_mid,
            });
        }
    } else if old_mid > 0 {
        ops.push(DiffOp::Delete {
            old_index: prefix,
            old_len: old_mid,
            new_index: prefix,
        });
    } else if new_mid > 0 {
        ops.push(DiffOp::Insert {
            old_index: prefix,
            new_index: prefix,
            new_len: new_mid,
        });
    }
    if suffix > 0 {
        ops.push(DiffOp::Equal {
            old_index: old_end,
            new_index: new_end,
            len: suffix,
        });
    }
    contiguous(ops)
}

/// Rebuild `ops` with indices derived from their lengths and order: the `old_index` the algorithm
/// reports for an insertion (and the `new_index` of a deletion) is not reliable, and hunk headers
/// are computed from these indices.
fn contiguous(ops: Vec<DiffOp>) -> Vec<DiffOp> {
    let (mut i, mut j) = (0usize, 0usize);
    ops.into_iter()
        .map(|op| {
            let rebuilt = match op {
                DiffOp::Equal { len, .. } => DiffOp::Equal {
                    old_index: i,
                    new_index: j,
                    len,
                },
                DiffOp::Delete { old_len, .. } => DiffOp::Delete {
                    old_index: i,
                    old_len,
                    new_index: j,
                },
                DiffOp::Insert { new_len, .. } => DiffOp::Insert {
                    old_index: i,
                    new_index: j,
                    new_len,
                },
                DiffOp::Replace { old_len, new_len, .. } => DiffOp::Replace {
                    old_index: i,
                    old_len,
                    new_index: j,
                    new_len,
                },
            };
            let (_, old, new) = rebuilt.as_tag_tuple();
            (i, j) = (old.end, new.end);
            rebuilt
        })
        .collect()
}

/// 1-based start and length of a hunk side, git style (an empty side starts at the line before).
fn side(start: usize, len: usize) -> (usize, usize) {
    if len == 0 {
        (start, 0)
    } else {
        (start + 1, len)
    }
}

/// Git-style line diff of two Markdown documents. Equal inputs give an empty `text` and
/// `{"files":[]}`.
#[must_use]
pub fn markdown_diff(previous: &str, current: &str) -> MarkdownDiff {
    let (old, new) = (lines(previous), lines(current));
    let ops = script(&old, &new);
    let changed = ops.iter().any(|op| !matches!(op, DiffOp::Equal { .. }));
    if !changed {
        return MarkdownDiff {
            text: String::new(),
            json: json!({ "files": [] }),
        };
    }

    let mut text_lines: Vec<String> = Vec::new();
    let mut chunks: Vec<Value> = Vec::new();
    for group in group_diff_ops(ops, CONTEXT_LINES) {
        let (Some(first), Some(last)) = (group.first(), group.last()) else {
            continue;
        };
        let old_range = first.old_range().start..last.old_range().end;
        let new_range = first.new_range().start..last.new_range().end;
        let (os, ol) = side(old_range.start, old_range.len());
        let (ns, nl) = side(new_range.start, new_range.len());
        let header = format!("@@ -{os},{ol} +{ns},{nl} @@");
        text_lines.push(header.clone());

        let mut changes: Vec<Value> = Vec::new();
        for op in &group {
            let (_, o, n) = op.as_tag_tuple();
            match op {
                DiffOp::Equal { .. } => {
                    for (i, j) in o.zip(n) {
                        text_lines.push(format!(" {}", old[i]));
                        changes.push(json!({
                            "type": "normal", "ln1": i + 1, "ln2": j + 1, "content": old[i],
                        }));
                    }
                }
                DiffOp::Delete { .. } | DiffOp::Insert { .. } | DiffOp::Replace { .. } => {
                    for i in o {
                        text_lines.push(format!("-{}", old[i]));
                        changes.push(json!({ "type": "del", "ln": i + 1, "content": old[i] }));
                    }
                    for j in n {
                        text_lines.push(format!("+{}", new[j]));
                        changes.push(json!({ "type": "add", "ln": j + 1, "content": new[j] }));
                    }
                }
            }
        }
        chunks.push(json!({ "content": header, "changes": changes }));
    }

    MarkdownDiff {
        text: text_lines.join("\n"),
        json: json!({ "files": [{ "from": null, "to": null, "chunks": chunks }] }),
    }
}

/// Field-level comparison of two JSON extractions: `{key: {"previous": .., "current": ..}}` over
/// the union of the top-level keys of both documents (unchanged keys included, a missing side is
/// `null`). A side that is not a JSON object has no keys.
#[must_use]
pub fn json_diff(previous: &Value, current: &Value) -> Value {
    let empty = Map::new();
    let prev = previous.as_object().unwrap_or(&empty);
    let cur = current.as_object().unwrap_or(&empty);
    let keys: BTreeSet<&String> = prev.keys().chain(cur.keys()).collect();
    let out: Map<String, Value> = keys
        .into_iter()
        .map(|k| {
            (
                k.clone(),
                json!({
                    "previous": prev.get(k).cloned().unwrap_or(Value::Null),
                    "current": cur.get(k).cloned().unwrap_or(Value::Null),
                }),
            )
        })
        .collect();
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn changed_lines_render_exactly_like_the_reference_example() {
        let prev = "# Pricing\nStarter: $9/mo\nPro: $29/mo\n";
        let cur = "# Pricing\nStarter: $12/mo\nPro: $39/mo\n";
        let d = markdown_diff(prev, cur);
        assert_eq!(
            d.text,
            "@@ -1,3 +1,3 @@\n # Pricing\n-Starter: $9/mo\n-Pro: $29/mo\n+Starter: $12/mo\n+Pro: $39/mo"
        );
        assert_eq!(
            d.json,
            json!({"files": [{"from": null, "to": null, "chunks": [{
                "content": "@@ -1,3 +1,3 @@",
                "changes": [
                    {"type": "normal", "ln1": 1, "ln2": 1, "content": "# Pricing"},
                    {"type": "del", "ln": 2, "content": "Starter: $9/mo"},
                    {"type": "del", "ln": 3, "content": "Pro: $29/mo"},
                    {"type": "add", "ln": 2, "content": "Starter: $12/mo"},
                    {"type": "add", "ln": 3, "content": "Pro: $39/mo"}
                ]
            }]}]})
        );
    }

    #[test]
    fn equal_documents_have_no_hunks() {
        let d = markdown_diff("a\nb\n", "a\nb\n");
        assert_eq!(d.text, "");
        assert_eq!(d.json, json!({"files": []}));
    }

    #[test]
    fn line_endings_and_trailing_whitespace_do_not_count_as_changes() {
        let d = markdown_diff("a  \r\nb\r\n", "a\nb");
        assert_eq!(d.text, "");
    }

    #[test]
    fn added_lines_at_the_end_keep_three_context_lines() {
        let prev = "1\n2\n3\n4\n5\n";
        let cur = "1\n2\n3\n4\n5\n6\n7\n";
        let d = markdown_diff(prev, cur);
        assert_eq!(d.text, "@@ -3,3 +3,5 @@\n 3\n 4\n 5\n+6\n+7");
    }

    #[test]
    fn removed_lines_are_marked_with_old_line_numbers() {
        let d = markdown_diff("keep\ngone\nkeep too\n", "keep\nkeep too\n");
        assert_eq!(d.text, "@@ -1,3 +1,2 @@\n keep\n-gone\n keep too");
        let changes = &d.json["files"][0]["chunks"][0]["changes"];
        assert_eq!(changes[1], json!({"type": "del", "ln": 2, "content": "gone"}));
    }

    #[test]
    fn first_version_is_one_added_hunk_from_line_zero() {
        let d = markdown_diff("", "# New\ntext\n");
        assert_eq!(d.text, "@@ -0,0 +1,2 @@\n+# New\n+text");
    }

    #[test]
    fn page_removed_is_one_deleted_hunk() {
        let d = markdown_diff("# Old\ntext\n", "");
        assert_eq!(d.text, "@@ -1,2 +0,0 @@\n-# Old\n-text");
    }

    #[test]
    fn distant_changes_make_separate_hunks_and_close_changes_merge() {
        let prev: String = (1..=20).map(|i| format!("line {i}\n")).collect();
        let far = prev
            .replace("line 2\n", "LINE 2\n")
            .replace("line 19\n", "LINE 19\n");
        let d = markdown_diff(&prev, &far);
        assert_eq!(d.json["files"][0]["chunks"].as_array().unwrap().len(), 2);
        assert!(d.text.contains("@@ -1,5 +1,5 @@"));
        assert!(d.text.contains("@@ -16,5 +16,5 @@"));

        let near = prev
            .replace("line 2\n", "LINE 2\n")
            .replace("line 6\n", "LINE 6\n");
        let d = markdown_diff(&prev, &near);
        assert_eq!(d.json["files"][0]["chunks"].as_array().unwrap().len(), 1);
        assert!(d.text.starts_with("@@ -1,9 +1,9 @@"));
    }

    #[test]
    fn insert_in_the_middle_keeps_following_lines_numbered_in_the_new_file() {
        let d = markdown_diff("a\nb\nc\n", "a\nNEW\nb\nc\n");
        assert_eq!(d.text, "@@ -1,3 +1,4 @@\n a\n+NEW\n b\n c");
        let changes = d.json["files"][0]["chunks"][0]["changes"].as_array().unwrap();
        assert_eq!(
            changes[2],
            json!({"type": "normal", "ln1": 2, "ln2": 3, "content": "b"})
        );
    }

    #[test]
    fn huge_changed_middle_degrades_to_one_replaced_block() {
        let prev: String = (0..MAX_DIFF_LINES).map(|i| format!("old {i}\n")).collect();
        let cur: String = (0..MAX_DIFF_LINES).map(|i| format!("new {i}\n")).collect();
        let d = markdown_diff(&format!("head\n{prev}tail\n"), &format!("head\n{cur}tail\n"));
        let chunks = d.json["files"][0]["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 1);
        let total = MAX_DIFF_LINES + 2;
        assert!(d
            .text
            .starts_with(&format!("@@ -1,{total} +1,{total} @@\n head\n-old 0")));
    }

    #[test]
    fn deletion_then_kept_line_then_insertion_is_positioned_by_op_lengths() {
        // Found by the property test: the algorithm reports a bogus `old_index` for the trailing
        // insertion, which used to cut the hunk short.
        let prev = "a\nb\nc\nd\ne\nf\ng\nz\n";
        let d = markdown_diff(prev, "z\nq\nr\n");
        assert_eq!(d.text, "@@ -1,8 +1,3 @@\n-a\n-b\n-c\n-d\n-e\n-f\n-g\n z\n+q\n+r");
        let blanks = format!("{}a\n\n\naa\n{}b\n", "\n".repeat(7), "\n".repeat(7));
        let d = markdown_diff(&blanks, "b\nb\nc\n");
        assert!(d.text.starts_with("@@ -1,19 +1,3 @@\n-\n"), "{}", d.text);
        assert!(d.text.ends_with("\n b\n+b\n+c"), "{}", d.text);
    }

    #[test]
    fn json_diff_covers_the_union_of_top_level_keys_including_unchanged() {
        let prev = json!({"price": "$19.99", "availability": "In Stock", "sku": "A1"});
        let cur = json!({"price": "$24.99", "availability": "In Stock", "color": "red"});
        let d = json_diff(&prev, &cur);
        assert_eq!(
            d,
            json!({
                "availability": {"previous": "In Stock", "current": "In Stock"},
                "color": {"previous": null, "current": "red"},
                "price": {"previous": "$19.99", "current": "$24.99"},
                "sku": {"previous": "A1", "current": null},
            })
        );
    }

    #[test]
    fn json_diff_keeps_nested_values_whole() {
        let prev = json!({"plans": [{"n": "a"}]});
        let cur = json!({"plans": [{"n": "a"}, {"n": "b"}]});
        let d = json_diff(&prev, &cur);
        assert_eq!(d["plans"]["previous"], json!([{"n": "a"}]));
        assert_eq!(d["plans"]["current"], json!([{"n": "a"}, {"n": "b"}]));
    }

    #[test]
    fn json_diff_of_non_objects_has_no_keys() {
        assert_eq!(json_diff(&json!([1]), &json!("x")), json!({}));
    }
}
