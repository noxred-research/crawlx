#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Focused Markdown conversion cases.

use crawlx_extract::{ExtractOptions, Extractor};
use url::Url;

fn md(html: &str) -> String {
    let base = Url::parse("https://example.com/dir/page").unwrap();
    let o = ExtractOptions {
        only_main_content: false,
        ..ExtractOptions::default()
    };
    Extractor::extract(html, &base, &o).unwrap().markdown
}

#[test]
fn headings_and_paragraphs() {
    assert_eq!(
        md("<h1>One</h1><h3>Three <a href=/x>link</a></h3><p>Para</p>"),
        "# One\n\n### Three [link](https://example.com/x)\n\nPara"
    );
}

#[test]
fn whitespace_is_collapsed() {
    assert_eq!(
        md("<p>  a \n\t b   <span> c </span>  d </p>\n\n\n<p>e</p>"),
        "a b c d\n\ne"
    );
    assert_eq!(md("<p>a<b> bold </b>b</p>"), "a **bold** b");
    assert_eq!(md("<p>x<em> </em>y</p>"), "x y");
}

#[test]
fn emphasis_hugs_content() {
    assert_eq!(
        md("<p><strong> lead</strong> and <em>trail </em>end</p>"),
        "**lead** and *trail* end"
    );
}

#[test]
fn special_characters_are_escaped() {
    assert_eq!(
        md("<p>*star* _under_ `tick` [brk] a_b #1 &lt;tag> &amp;copy; 5 &lt; 6 ~~x~~</p>"),
        "\\*star\\* \\_under\\_ \\`tick\\` \\[brk\\] a_b #1 \\<tag> \\&copy; 5 < 6 \\~~x\\~~"
    );
}

#[test]
fn line_start_markers_are_escaped() {
    assert_eq!(md("<p># not heading</p><p>- not list</p><p>1. not ordered</p><p>&gt; not quote</p><p>+ plus</p><p>---</p>"),
        "\\# not heading\n\n\\- not list\n\n1\\. not ordered\n\n\\> not quote\n\n\\+ plus\n\n\\---");
}

#[test]
fn inline_code_handles_backticks() {
    assert_eq!(
        md("<p><code>a`b</code> and <code>``x</code> and <code> sp  ace </code></p>"),
        "``a`b`` and ``` ``x ``` and `sp ace`"
    );
}

#[test]
fn fenced_code_uses_longer_fence_when_needed() {
    let out = md("<pre>line1\n```\nline3</pre>");
    assert_eq!(out, "````\nline1\n```\nline3\n````");
}

#[test]
fn code_language_from_wrapper_and_attributes() {
    assert_eq!(
        md("<div class=\"highlight highlight-source-python\"><pre>x = 1</pre></div>"),
        "```python\nx = 1\n```"
    );
    assert_eq!(md("<pre class=\"brush lang-js\">a()</pre>"), "```js\na()\n```");
    assert_eq!(
        md("<pre><code data-lang=\"Go\">b()</code></pre>"),
        "```go\nb()\n```"
    );
}

#[test]
fn pre_preserves_whitespace_and_br() {
    assert_eq!(md("<pre>  a\n    b<br>c</pre>"), "```\n  a\n    b\nc\n```");
}

#[test]
fn blockquote_nested() {
    assert_eq!(
        md("<blockquote><p>a</p><blockquote><p>b</p></blockquote></blockquote>"),
        "> a\n>\n> > b"
    );
}

#[test]
fn lists_nested_and_ordered_numbering() {
    assert_eq!(
        md("<ul><li>a<ul><li>b<ol><li>c</li><li>d</li></ol></li></ul></li><li>e</li></ul>"),
        "- a\n  - b\n    1. c\n    2. d\n- e"
    );
    assert_eq!(
        md("<ol start=9><li>x</li><li>y</li><li>z</li></ol>"),
        "9. x\n10. y\n11. z"
    );
}

#[test]
fn loose_list_items_are_separated_by_blank_lines() {
    assert_eq!(
        md("<ul><li><p>a</p><p>b</p></li><li><p>c</p></li></ul>"),
        "- a\n\n  b\n\n- c"
    );
}

#[test]
fn list_item_with_code_block() {
    assert_eq!(
        md("<ul><li>run<pre>make\nmake test</pre></li></ul>"),
        "- run\n\n  ```\n  make\n  make test\n  ```"
    );
}

#[test]
fn links_resolve_and_javascript_is_skipped() {
    assert_eq!(
        md("<p><a href='../up'>up</a> <a href='javascript:x()'>js</a> <a href='https://e.com/a_(b)'>paren</a> <a href=''>empty</a> <a href='/i'><img src='p.png' alt='pic'></a> <a href='/nothing'></a></p>"),
        "[up](https://example.com/up) js [paren](https://e.com/a_%28b%29) empty [![pic](https://example.com/dir/p.png)](https://example.com/i)"
    );
}

#[test]
fn images_use_alt_and_lazy_sources() {
    assert_eq!(
        md("<p><img src='data:image/png;base64,AAAA' srcset='a.png 1x, b.png 2x' alt='[x] y'></p><p><img alt='nosrc'></p>"),
        "![\\[x\\] y](https://example.com/dir/a.png)"
    );
}

#[test]
fn br_and_hr() {
    assert_eq!(md("<p>a<br>b<br/> c</p><hr><p>d</p>"), "a  \nb  \nc\n\n---\n\nd");
}

#[test]
fn table_colspan_rowspan_and_header_detection() {
    assert_eq!(
        md("<table><tr><th>A</th><th>B</th><th>C</th></tr><tr><td rowspan=2>x</td><td colspan=2>y</td></tr><tr><td>p</td><td>q</td></tr></table>"),
        "| A | B | C |\n| --- | --- | --- |\n| x | y |  |\n|  | p | q |"
    );
    // No th and no thead: an empty header row keeps the GFM table valid.
    assert_eq!(
        md("<table><tr><td>1</td><td>2</td></tr><tr><td>3</td><td>4</td></tr></table>"),
        "|  |  |\n| --- | --- |\n| 1 | 2 |\n| 3 | 4 |"
    );
}

#[test]
fn table_alignment_and_cell_content() {
    assert_eq!(
        md("<table><thead><tr><th style='text-align:center'>H</th><th align=left>I</th></tr></thead><tbody><tr><td><b>a</b><br>b|c</td><td><ul><li>x</li><li>y</li></ul></td></tr></tbody></table>"),
        "| H | I |\n| :---: | :--- |\n| **a**<br>b\\|c | x y |"
    );
}

#[test]
fn definition_lists() {
    assert_eq!(
        md("<dl><dt>T1</dt><dd>d1</dd><dd>d2</dd><dt>T2</dt><dd>d3</dd></dl>"),
        "**T1**\n: d1\n: d2\n\n**T2**\n: d3"
    );
}

#[test]
fn hidden_and_non_content_elements_are_removed() {
    let html = "<p>a</p><div hidden>h1</div><div aria-hidden='true'>h2</div><span style='color:red; DISPLAY : none !important'>h3</span>\
<script>s()</script><style>p{}</style><noscript>ns</noscript><template><p>t</p></template><svg><text>svgtext</text></svg><p>b</p>";
    assert_eq!(md(html), "a\n\nb");
}

#[test]
fn unknown_wrappers_and_inline_blocks_degrade_gracefully() {
    assert_eq!(
        md("<custom-card><div>a</div><div>b</div></custom-card><span><p>c</p></span>"),
        "a\n\nb\n\nc"
    );
    assert_eq!(
        md("<a href='/x'><div>card <b>title</b></div><p>sub</p></a>"),
        "[card **title** sub](https://example.com/x)"
    );
}

#[test]
fn layout_table_with_single_cell_is_unwrapped() {
    assert_eq!(
        md("<table><tr><td><h2>T</h2><p>body</p></td></tr></table>"),
        "## T\n\nbody"
    );
}

#[test]
fn never_more_than_one_blank_line_between_blocks() {
    let out = md(
        "<div><div><p>a</p></div></div><div></div><p>&nbsp;</p><p>b</p>\n\n\n\n<div><br><br></div><p>c</p>",
    );
    assert!(!out.contains("\n\n\n"), "{out:?}");
    assert_eq!(out, "a\n\nb\n\nc");
}

#[test]
fn text_and_html_outputs() {
    let base = Url::parse("https://example.com/").unwrap();
    let o = ExtractOptions {
        only_main_content: false,
        ..ExtractOptions::default()
    };
    let d = Extractor::extract(
        "<h1>T</h1><p onclick='x()' style='c'>a <a href='/l' target=_blank>l</a> <img src=/i.png alt=a></p><ul><li>one</li><li>two</li></ul>",
        &base,
        &o,
    )
    .unwrap();
    assert_eq!(d.text, "T\n\na l\n\none\ntwo");
    assert_eq!(
        d.html,
        "<body><h1>T</h1><p>a <a href=\"https://example.com/l\">l</a> <img src=\"https://example.com/i.png\" alt=\"a\"></p><ul><li>one</li><li>two</li></ul></body>"
    );
    assert_eq!(d.word_count, 5);
}
