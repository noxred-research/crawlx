//! Authored static XPath conformance and adversarial corpus. No network fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
const SOURCE:&str="<html lang='en-GB'><body><main id='story'><p id='a'>first <b>bold</b></p><!--note--><p id='b'>second</p><aside>side</aside></main><footer>end</footer><svg xmlns='http://www.w3.org/2000/svg'><text>vector</text></svg></body></html>";
fn value(expression: &str) -> XPathValue {
    let html = Html::parse_document(SOURCE);
    let mut doc = SelectorDocument::new(&html).unwrap();
    doc.evaluate(&CompiledSelector::xpath(expression).unwrap(), &BTreeMap::new())
        .unwrap()
}
fn strings(expression: &str) -> Vec<String> {
    let html = Html::parse_document(SOURCE);
    let mut doc = SelectorDocument::new(&html).unwrap();
    let XPathValue::Nodes(nodes) = doc
        .evaluate(&CompiledSelector::xpath(expression).unwrap(), &BTreeMap::new())
        .unwrap()
    else {
        panic!("not a node set")
    };
    nodes.into_iter().map(|n| doc.string_value(n).unwrap()).collect()
}
fn boolean_value(expression: &str) -> bool {
    let XPathValue::Boolean(b) = value(expression) else {
        panic!("not boolean")
    };
    b
}
#[test]
fn axes_and_node_tests_preserve_document_order() {
    for (expression, expected) in [
        ("//main/child::p/@id", vec!["a", "b"]),
        ("//b/parent::p/@id", vec!["a"]),
        ("//b/ancestor::main/@id", vec!["story"]),
        ("//main/descendant::b/text()", vec!["bold"]),
        ("//p[@id='a']/following-sibling::p/@id", vec!["b"]),
        ("//p[@id='b']/preceding-sibling::*[1]/@id", vec!["a"]),
        ("//b/following::p[1]/@id", vec!["b"]),
        ("//p[@id='b']/preceding::b/text()", vec!["bold"]),
        ("//p[@id='b']/self::p/@id", vec!["b"]),
        ("//p[@id='b']/ancestor-or-self::p/@id", vec!["b"]),
        ("//p[@id='a']/descendant-or-self::b/text()", vec!["bold"]),
        ("//main/comment()", vec!["note"]),
        ("//p[@id='a']/attribute::id", vec!["a"]),
        ("//p[@id='a']/namespace::xml", vec![XML_NS]),
        ("//p[@id='a']/../@id", vec!["story"]),
        ("//p[@id='b']/./@id", vec!["b"]),
        (
            "//p[@id='b'] | //p[@id='a'] | //p[@id='a']",
            vec!["first bold", "second"],
        ),
    ] {
        assert_eq!(strings(expression), expected, "{expression}");
    }
    assert!(strings("//processing-instruction()").is_empty());
    assert!(boolean_value("count(/child::html/body/main/node())=4"));
}
#[test]
fn predicates_and_xpath_conversion_rules() {
    for expression in [
        "count(//p)=2",
        "//p[1]/@id='a'",
        "(//p)[last()]/@id='b'",
        "//p[position()=last()]/@id='b'",
        "//p/@id != //p/@id",
        "//p/@id = //p/@id",
        "//missing = false()",
        "not(//missing)",
        "boolean(//p)",
        "number('-2.5')=-2.5",
        "string(1 div 0)='Infinity'",
        "string(0 div 0)='NaN'",
        "number('1e2') != number('1e2')",
        "1+2*3=7",
        "-5 mod 2=-1",
        "2<3 and 4>=4 or false()",
        "sum(//missing)=0",
    ] {
        assert!(boolean_value(expression), "{expression}");
    }
    assert_eq!(strings("//p[false()]"), Vec::<String>::new());
}
#[test]
fn every_core_function_family() {
    for expression in [
        "count(id('story a'))=2",
        "count(//p[lang('en')])=2",
        "local-name(//main)='main'",
        "name(//main)='main'",
        "namespace-uri(//main)='http://www.w3.org/1999/xhtml'",
        "string(//b)='bold'",
        "string-length('雪a')=2",
        "concat('a','b','c')='abc'",
        "starts-with('abc','a')",
        "contains('abc','b')",
        "substring-before('abc','b')='a'",
        "substring-after('abc','b')='c'",
        "substring('12345',1.5,2.6)='234'",
        "substring('12345',0,3)='12'",
        "translate('bar','abc','ABC')='BAr'",
        "normalize-space(' a \t b ')= 'a b'",
        "floor(-1.5)=-2",
        "ceiling(-1.5)=-1",
        "round(-1.5)=-1",
        "true() and not(false())",
        "string(true())='true'",
        "number(true())=1",
    ] {
        assert!(boolean_value(expression), "{expression}");
    }
}
#[test]
fn namespace_bindings_select_foreign_dom_nodes() {
    let html = Html::parse_document(SOURCE);
    let mut doc = SelectorDocument::new(&html).unwrap();
    let ns = BTreeMap::from([("s".into(), "http://www.w3.org/2000/svg".into())]);
    let XPathValue::Nodes(nodes) = doc
        .evaluate(&CompiledSelector::xpath("//s:svg/s:text").unwrap(), &ns)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(nodes.len(), 1);
    assert_eq!(doc.string_value(nodes[0]).unwrap(), "vector");
    assert!(matches!(
        doc.evaluate(&CompiledSelector::xpath("//unknown:p").unwrap(), &BTreeMap::new()),
        Err(SelectorError::Namespace)
    ));
}
#[test]
fn malicious_syntax_and_external_functions_reject() {
    for source in [
        "document('http://127.0.0.1/')",
        "unparsed-entity-uri('x')",
        "system-property('x')",
        "foo()",
        "//p[",
        "$secret",
        "//p/unknown::node()",
        "//p[1] trailing",
        "count()",
    ] {
        assert!(CompiledSelector::xpath(source).is_err(), "{source}");
    }
    assert!(matches!(
        CompiledSelector::xpath(&"x".repeat(4097)),
        Err(SelectorError::Budget("expression bytes"))
    ));
    let deep = format!("{}1{}", "(".repeat(513), ")".repeat(513));
    assert!(matches!(
        CompiledSelector::xpath(&deep),
        Err(SelectorError::Budget(_))
    ));
    let ast = std::iter::repeat_n("1", 257).collect::<Vec<_>>().join("+");
    assert!(matches!(
        CompiledSelector::xpath(&ast),
        Err(SelectorError::Budget(_))
    ));
}

#[test]
fn nested_prefixes_and_predicates_stop_before_exhausting_the_stack() {
    for source in [
        format!("{}1{}", "(".repeat(65), ")".repeat(65)),
        format!("{}true(){}", "not(".repeat(65), ")".repeat(65)),
        format!("{}true(){}", "//p[".repeat(65), "]".repeat(65)),
        format!("{}1", "-".repeat(65)),
    ] {
        assert!(matches!(
            CompiledSelector::xpath(&source),
            Err(SelectorError::Budget("parser depth"))
        ));
    }
    assert!(boolean_value(&format!("{}1{}=1", "(".repeat(16), ")".repeat(16))));
}

#[test]
fn shallow_parser_cannot_emit_an_unbounded_evaluation_stack() {
    let expression = std::iter::repeat_n("1", 256).collect::<Vec<_>>().join("+");
    assert!(matches!(
        CompiledSelector::xpath(&expression),
        Err(SelectorError::Budget("AST depth"))
    ));
    let expression = std::iter::repeat_n("1", 32).collect::<Vec<_>>().join("+");
    assert!(boolean_value(&format!("({expression})=32")));
}

#[test]
fn rounding_does_not_change_integers_or_double_round_half_boundaries() {
    for expression in [
        "round(0.49999999999999994)=0",
        "round(4503599627370497)=4503599627370497",
        "substring('ab',0.49999999999999994,1)=''",
        "1 div round(-0.5) = -1 div 0",
    ] {
        assert!(boolean_value(expression), "{expression}");
    }
}

#[test]
fn xml_ncname_continuation_characters_are_valid_attribute_names() {
    let html = Html::parse_document("<p data·key='value'>content</p>");
    let mut document = SelectorDocument::new(&html).unwrap();
    let selector = CompiledSelector::xpath("string(//p/@data·key)").unwrap();
    let XPathValue::String(actual) = document.evaluate(&selector, &BTreeMap::new()).unwrap() else {
        panic!("attribute string projection must produce a string");
    };
    assert_eq!(actual, "value");
}

#[test]
fn attribute_abbreviation_cannot_be_combined_with_an_explicit_axis() {
    assert!(matches!(
        CompiledSelector::xpath("//@child::p"),
        Err(SelectorError::Syntax)
    ));
}

#[test]
fn only_xml_space_is_accepted_between_xpath_tokens() {
    for source in ["1\u{000B}+2", "1\u{000C}+2"] {
        assert!(matches!(
            CompiledSelector::xpath(source),
            Err(SelectorError::Syntax)
        ));
    }
    assert!(boolean_value("1 \t\r\n + 2 = 3"));
}
#[test]
fn work_and_selected_limits_are_errors_not_empty_sets() {
    let html = Html::parse_document(SOURCE);
    let mut doc = SelectorDocument::new(&html).unwrap();
    doc.restrict_operations(1);
    assert!(matches!(
        doc.evaluate(&CompiledSelector::xpath("//p").unwrap(), &BTreeMap::new()),
        Err(SelectorError::Budget("operations"))
    ));
    let html = Html::parse_document(&format!("<main>{}</main>", "<p>x</p>".repeat(MAX_SELECTED + 1)));
    let mut doc = SelectorDocument::new(&html).unwrap();
    assert!(matches!(
        doc.evaluate(&CompiledSelector::xpath("//p").unwrap(), &BTreeMap::new()),
        Err(SelectorError::Budget("selected nodes"))
    ));
}
