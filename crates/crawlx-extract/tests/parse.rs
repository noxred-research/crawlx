#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `crawlx_extract::parse`: every supported format round-trips fixture text into Markdown, limits
//! hold, and hostile input yields typed errors, never a panic.
//!
//! All fixtures are generated here: zip containers with the `zip` writer, OLE2 files with `cfb`,
//! PDFs with `lopdf`, BIFF records by hand.

use std::io::{Cursor, Write};

use crawlx_extract::parse::pdf::{extract_pdf, PdfOptions};
use crawlx_extract::parse::{
    detect_format, parse_document, parse_document_with, supported_formats, ParseError, ParseFormat,
    ParseLimits, ParseOptions, ParsedDocument,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------------------------
// fixture builders
// ---------------------------------------------------------------------------------------------

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

const W_NS: &str = r#"xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships""#;

fn docx() -> Vec<u8> {
    let document = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document {W_NS}><w:body>
<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Quarterly Report</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Revenue grew </w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>twelve percent</w:t></w:r><w:r><w:t xml:space="preserve"> see </w:t></w:r><w:hyperlink r:id="rId1"><w:r><w:t>the site</w:t></w:r></w:hyperlink><w:r><w:t>.</w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr><w:r><w:t>first bullet</w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="2"/></w:numPr></w:pPr><w:r><w:t>step one</w:t></w:r></w:p>
<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>Details</w:t></w:r></w:p>
<w:tbl>
<w:tr><w:tc><w:p><w:r><w:t>Name</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Qty</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p><w:r><w:t>Widget</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>4</w:t></w:r></w:p></w:tc></w:tr>
</w:tbl>
<w:p><w:r><w:t xml:space="preserve">Field </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> HYPERLINK "https://example.com/field" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>field link</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
</w:body></w:document>"#
    );
    let styles = format!(
        r#"<w:styles {W_NS}>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/></w:style>
</w:styles>"#
    );
    let numbering = format!(
        r#"<w:numbering {W_NS}>
<w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:numFmt w:val="bullet"/></w:lvl></w:abstractNum>
<w:abstractNum w:abstractNumId="1"><w:lvl w:ilvl="0"><w:numFmt w:val="decimal"/></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num><w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>
</w:numbering>"#
    );
    let rels = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/site" TargetMode="External"/></Relationships>"#;
    let core = r#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:title>Q3 Report</dc:title><dc:creator>Ada Lovelace</dc:creator><dcterms:created>2024-05-01T10:00:00Z</dcterms:created></cp:coreProperties>"#;
    zip_of(&[
        (
            "[Content_Types].xml",
            br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("word/document.xml", document.as_bytes()),
        ("word/styles.xml", styles.as_bytes()),
        ("word/numbering.xml", numbering.as_bytes()),
        ("word/_rels/document.xml.rels", rels.as_bytes()),
        ("docProps/core.xml", core.as_bytes()),
    ])
}

const SS_NS: &str = r#"xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships""#;

fn xlsx_with(sheet1_rows: &str) -> Vec<u8> {
    let workbook = format!(
        r#"<workbook {SS_NS}><sheets><sheet name="Sales" sheetId="1" r:id="rId1"/><sheet name="Notes" sheetId="2" r:id="rId2"/></sheets></workbook>"#
    );
    let sheet1 = format!(r#"<worksheet {SS_NS}><sheetData>{sheet1_rows}</sheetData></worksheet>"#);
    let sheet2 = format!(
        r#"<worksheet {SS_NS}><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>remember the milk</t></is></c></row></sheetData></worksheet>"#
    );
    let rels = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/></Relationships>"#;
    let root_rels = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;
    zip_of(&[
        (
            "[Content_Types].xml",
            br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/workbook.xml", workbook.as_bytes()),
        ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/worksheets/sheet2.xml", sheet2.as_bytes()),
    ])
}

fn xlsx() -> Vec<u8> {
    xlsx_with(
        r#"<row r="1"><c r="A1" t="inlineStr"><is><t>Item</t></is></c><c r="B1" t="inlineStr"><is><t>Price</t></is></c></row>
<row r="2"><c r="A2" t="inlineStr"><is><t>Widget</t></is></c><c r="B2"><v>9.5</v></c></row>
<row r="3"><c r="A3" t="inlineStr"><is><t>Gadget</t></is></c><c r="B3"><v>12</v></c></row>"#,
    )
}

const P_NS: &str = r#"xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main""#;

fn shape(ph: &str, paras: &str) -> String {
    format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="s"/><p:cNvSpPr/><p:nvPr>{ph}</p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/>{paras}</p:txBody></p:sp>"#
    )
}

fn pptx_with_slides(n: usize) -> Vec<u8> {
    // presentation order is slide{n}..slide1 reversed against the file names
    let mut ids = String::new();
    let mut prel = String::new();
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for k in 0..n {
        let file = n - k; // first in order -> highest number
        ids.push_str(&format!(r#"<p:sldId id="{}" r:id="rId{}"/>"#, 256 + k, k + 2));
        prel.push_str(&format!(
            r#"<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{file}.xml"/>"#,
            k + 2
        ));
        let title = shape(
            r#"<p:ph type="title"/>"#,
            &format!(r#"<a:p><a:r><a:t>Slide title {}</a:t></a:r></a:p>"#, k + 1),
        );
        let body = if k == 0 {
            shape(
                r#"<p:ph idx="1"/>"#,
                r#"<a:p><a:r><a:t>Ship parse</a:t></a:r></a:p><a:p><a:r><a:rPr><a:hlinkClick r:id="rId1"/></a:rPr><a:t>the docs</a:t></a:r></a:p>"#,
            )
        } else {
            let tbl = r#"<p:graphicFrame><a:graphic><a:graphicData><a:tbl><a:tr><a:tc><a:txBody><a:p><a:r><a:t>Item</a:t></a:r></a:p></a:txBody></a:tc><a:tc><a:txBody><a:p><a:r><a:t>Cost</a:t></a:r></a:p></a:txBody></a:tc></a:tr><a:tr><a:tc><a:txBody><a:p><a:r><a:t>Rent</a:t></a:r></a:p></a:txBody></a:tc><a:tc><a:txBody><a:p><a:r><a:t>1200</a:t></a:r></a:p></a:txBody></a:tc></a:tr></a:tbl></a:graphicData></a:graphic></p:graphicFrame>"#;
            tbl.to_owned()
        };
        let slide = format!(r#"<p:sld {P_NS}><p:cSld><p:spTree>{title}{body}</p:spTree></p:cSld></p:sld>"#);
        entries.push((format!("ppt/slides/slide{file}.xml"), slide.into_bytes()));
        if k == 0 {
            entries.push((
                format!("ppt/slides/_rels/slide{file}.xml.rels"),
                br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/docs" TargetMode="External"/></Relationships>"#.to_vec(),
            ));
        }
    }
    let presentation = format!(r#"<p:presentation {P_NS}><p:sldIdLst>{ids}</p:sldIdLst></p:presentation>"#);
    let prels = format!(
        r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{prel}</Relationships>"#
    );
    let mut all: Vec<(&str, &[u8])> = vec![
        (
            "[Content_Types].xml",
            br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("ppt/presentation.xml", presentation.as_bytes()),
        ("ppt/_rels/presentation.xml.rels", prels.as_bytes()),
    ];
    for (n, d) in &entries {
        all.push((n.as_str(), d.as_slice()));
    }
    zip_of(&all)
}

const O_NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0""#;

fn odf(mime: &str, body: &str) -> Vec<u8> {
    let content = format!(
        r#"<office:document-content {O_NS}><office:automatic-styles><style:style style:name="T1" style:family="text"><style:text-properties fo:font-weight="bold"/></style:style><text:list-style style:name="L2"><text:list-level-style-number text:level="1"/></text:list-style></office:automatic-styles><office:body>{body}</office:body></office:document-content>"#
    );
    let meta = r#"<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"><office:meta><dc:title>Handbook</dc:title><dc:creator>Grace Hopper</dc:creator><meta:keyword>alpha</meta:keyword><meta:keyword>beta</meta:keyword></office:meta></office:document-meta>"#;
    zip_of(&[
        ("mimetype", mime.as_bytes()),
        ("content.xml", content.as_bytes()),
        ("meta.xml", meta.as_bytes()),
    ])
}

fn odt() -> Vec<u8> {
    odf(
        "application/vnd.oasis.opendocument.text",
        r#"<office:text><text:h text:outline-level="1">Handbook</text:h><text:p>Plain <text:span text:style-name="T1">bold</text:span> and <text:a xlink:href="https://example.com/odt">a link</text:a>.</text:p><text:list><text:list-item><text:p>alpha</text:p></text:list-item></text:list><text:list text:style-name="L2"><text:list-item><text:p>one</text:p></text:list-item></text:list><table:table><table:table-row><table:table-cell><text:p>H1</text:p></table:table-cell><table:table-cell><text:p>H2</text:p></table:table-cell></table:table-row><table:table-row><table:table-cell><text:p>v1</text:p></table:table-cell><table:table-cell><text:p>v2</text:p></table:table-cell></table:table-row></table:table><text:p>Note<text:note><text:note-body><text:p>footnote body</text:p></text:note-body></text:note>.</text:p></office:text>"#,
    )
}

fn ods_body(extra: &str) -> String {
    format!(
        r#"<office:spreadsheet><table:table table:name="Budget"><table:table-row><table:table-cell office:value-type="string"><text:p>Item</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>Cost</text:p></table:table-cell></table:table-row><table:table-row><table:table-cell office:value-type="string"><text:p>Rent</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="1200"><text:p>1,200.00</text:p></table:table-cell></table:table-row>{extra}</table:table></office:spreadsheet>"#
    )
}

fn ods() -> Vec<u8> {
    odf(
        "application/vnd.oasis.opendocument.spreadsheet",
        &ods_body(
            r#"<table:table-row table:number-rows-repeated="1048576"><table:table-cell table:number-columns-repeated="16384"/></table:table-row>"#,
        ),
    )
}

fn odp() -> Vec<u8> {
    odf(
        "application/vnd.oasis.opendocument.presentation",
        r#"<office:presentation><draw:page draw:name="page1"><draw:frame presentation:class="title"><draw:text-box><text:p>Launch plan</text:p></draw:text-box></draw:frame><draw:frame presentation:class="outline"><draw:text-box><text:list><text:list-item><text:p>Step A</text:p></text:list-item><text:list-item><text:p>Step B</text:p></text:list-item></text:list></draw:text-box></draw:frame></draw:page><draw:page draw:name="page2"><draw:frame presentation:class="title"><draw:text-box><text:p>Wrap up</text:p></draw:text-box></draw:frame></draw:page></office:presentation>"#,
    )
}

fn epub() -> Vec<u8> {
    let container = r#"<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>"#;
    let opf = r#"<package xmlns="http://www.idpf.org/2007/opf" version="3.0"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>The Book</dc:title><dc:creator>Grace</dc:creator><dc:language>en</dc:language></metadata><manifest><item id="c2" href="text/ch%202.xhtml" media-type="application/xhtml+xml"/><item id="c1" href="text/ch1.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="c1"/><itemref idref="c2"/></spine></package>"#;
    let ch1 = r#"<html xmlns="http://www.w3.org/1999/xhtml"><body><h1>Chapter One</h1><p>It began with <a href="https://example.com/epub">a link</a>.</p></body></html>"#;
    let ch2 = r#"<html xmlns="http://www.w3.org/1999/xhtml"><body><h1>Chapter Two</h1><p>It continued.</p></body></html>"#;
    zip_of(&[
        ("mimetype", b"application/epub+zip"),
        ("META-INF/container.xml", container.as_bytes()),
        ("OEBPS/content.opf", opf.as_bytes()),
        ("OEBPS/text/ch1.xhtml", ch1.as_bytes()),
        ("OEBPS/text/ch 2.xhtml", ch2.as_bytes()),
    ])
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn ole(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (name, data) in streams {
        let mut s = cf.create_stream(format!("/{name}")).unwrap();
        s.write_all(data).unwrap();
    }
    cf.into_inner().into_inner()
}

/// A Word 97 file whose main text is `text` (ASCII) in one compressed piece.
fn doc_with(text: &str, flags: u16) -> Vec<u8> {
    let mut wd = vec![0u8; 0x400];
    put16(&mut wd, 0, 0xA5EC);
    put16(&mut wd, 0x0A, flags);
    put16(&mut wd, 32, 14);
    put16(&mut wd, 62, 22);
    put32(&mut wd, 76, u32::try_from(text.len()).unwrap());
    put16(&mut wd, 152, 93);
    put32(&mut wd, 418, 0);
    put32(&mut wd, 422, 21);
    wd.extend_from_slice(text.as_bytes());
    let mut table = vec![0x02u8];
    table.extend_from_slice(&16u32.to_le_bytes());
    table.extend_from_slice(&0u32.to_le_bytes());
    table.extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
    table.extend_from_slice(&0u16.to_le_bytes());
    table.extend_from_slice(&((0x400u32 * 2) | 0x4000_0000).to_le_bytes());
    table.extend_from_slice(&0u16.to_le_bytes());
    let table_name = if flags & 0x0200 != 0 { "1Table" } else { "0Table" };
    ole(&[("WordDocument", wd), (table_name, table)])
}

fn doc() -> Vec<u8> {
    doc_with(
        "Legacy heading\rSecond paragraph with \x13 HYPERLINK \"https://example.com/doc\" \x14click here\x15 inside.\rA1\x07B1\x07\x07A2\x07B2\x07\x07After table\r",
        0x0200,
    )
}

fn rec(ver: u16, inst: u16, ty: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((inst << 4) | ver).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn ppt() -> Vec<u8> {
    let persist = || rec(0, 0, 0x03F3, &[0u8; 20]);
    let header = |t: u32| rec(0, 0, 0x0F9F, &t.to_le_bytes());
    let mut slwt = Vec::new();
    slwt.extend(persist());
    slwt.extend(header(0));
    slwt.extend(rec(0, 0, 0x0FA0, &utf16("Deck Title")));
    slwt.extend(header(1));
    slwt.extend(rec(0, 0, 0x0FA8, b"point one\rpoint two"));
    slwt.extend(persist());
    slwt.extend(header(0));
    slwt.extend(rec(0, 0, 0x0FA0, &utf16("Second Slide")));
    let document = rec(0xF, 0, 0x03E8, &rec(0xF, 0, 0x0FF0, &slwt));
    let mut notes = header(2);
    notes.extend(rec(0, 0, 0x0FA0, &utf16("secret speaker notes")));
    let mut stream = document;
    stream.extend(rec(0xF, 0, 0x03F0, &notes));
    ole(&[("PowerPoint Document", stream)])
}

fn biff(id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn xls() -> Vec<u8> {
    let bof = |dt: u16| {
        let mut d = Vec::new();
        d.extend_from_slice(&0x0600u16.to_le_bytes());
        d.extend_from_slice(&dt.to_le_bytes());
        d.extend_from_slice(&0x0DBBu16.to_le_bytes());
        d.extend_from_slice(&0x07CCu16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&6u32.to_le_bytes());
        biff(0x0809, &d)
    };
    let strings = ["Part", "Count", "Bolt", "Nut"];
    let mut sst = Vec::new();
    sst.extend_from_slice(&4u32.to_le_bytes());
    sst.extend_from_slice(&4u32.to_le_bytes());
    for s in strings {
        sst.extend_from_slice(&u16::try_from(s.len()).unwrap().to_le_bytes());
        sst.push(0);
        sst.extend_from_slice(s.as_bytes());
    }
    let sst_rec = biff(0x00FC, &sst);
    let name = b"Stock";
    let boundsheet_len = 4 + 4 + 2 + 1 + 1 + name.len();
    let globals_len = bof(5).len()
        + biff(0x0042, &1200u16.to_le_bytes()).len()
        + boundsheet_len
        + sst_rec.len()
        + biff(0x000A, &[]).len();
    let mut bs = Vec::new();
    bs.extend_from_slice(&u32::try_from(globals_len).unwrap().to_le_bytes());
    bs.extend_from_slice(&0u16.to_le_bytes());
    bs.push(u8::try_from(name.len()).unwrap());
    bs.push(0);
    bs.extend_from_slice(name);
    let mut wb = Vec::new();
    wb.extend(bof(5));
    wb.extend(biff(0x0042, &1200u16.to_le_bytes()));
    wb.extend(biff(0x0085, &bs));
    wb.extend(sst_rec);
    wb.extend(biff(0x000A, &[]));
    wb.extend(bof(0x10));
    let mut dim = Vec::new();
    dim.extend_from_slice(&0u32.to_le_bytes());
    dim.extend_from_slice(&3u32.to_le_bytes());
    dim.extend_from_slice(&0u16.to_le_bytes());
    dim.extend_from_slice(&2u16.to_le_bytes());
    dim.extend_from_slice(&0u16.to_le_bytes());
    wb.extend(biff(0x0200, &dim));
    let label = |r: u16, c: u16, isst: u32| {
        let mut d = Vec::new();
        d.extend_from_slice(&r.to_le_bytes());
        d.extend_from_slice(&c.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&isst.to_le_bytes());
        biff(0x00FD, &d)
    };
    let number = |r: u16, c: u16, v: f64| {
        let mut d = Vec::new();
        d.extend_from_slice(&r.to_le_bytes());
        d.extend_from_slice(&c.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&v.to_le_bytes());
        biff(0x0203, &d)
    };
    wb.extend(label(0, 0, 0));
    wb.extend(label(0, 1, 1));
    wb.extend(label(1, 0, 2));
    wb.extend(number(1, 1, 40.0));
    wb.extend(label(2, 0, 3));
    wb.extend(number(2, 1, 17.5));
    wb.extend(biff(0x000A, &[]));
    ole(&[("Workbook", wb)])
}

fn varint_id(id: u16) -> Vec<u8> {
    if id < 0x80 {
        vec![u8::try_from(id).unwrap()]
    } else {
        vec![
            u8::try_from((id & 0x7F) | 0x80).unwrap(),
            u8::try_from(id >> 7).unwrap(),
        ]
    }
}

fn brec(id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = varint_id(id);
    let mut len = data.len();
    loop {
        let mut b = u8::try_from(len & 0x7F).unwrap();
        len >>= 7;
        if len > 0 {
            b |= 0x80;
        }
        out.push(b);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(data);
    out
}

fn wide(s: &str) -> Vec<u8> {
    let mut out = u32::try_from(s.encode_utf16().count())
        .unwrap()
        .to_le_bytes()
        .to_vec();
    out.extend(utf16(s));
    out
}

fn xlsb() -> Vec<u8> {
    let mut wbin = Vec::new();
    wbin.extend(brec(0x83, &[]));
    wbin.extend(brec(0x8F, &[]));
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&0u32.to_le_bytes());
    bundle.extend_from_slice(&1u32.to_le_bytes());
    bundle.extend(wide("rId1"));
    bundle.extend(wide("Ledger"));
    wbin.extend(brec(0x9C, &bundle));
    wbin.extend(brec(0x90, &[]));
    wbin.extend(brec(0x84, &[]));
    let mut sheet = Vec::new();
    sheet.extend(brec(0x81, &[]));
    let mut dim = Vec::new();
    for v in [0u32, 1, 0, 1] {
        dim.extend_from_slice(&v.to_le_bytes());
    }
    sheet.extend(brec(0x94, &dim));
    sheet.extend(brec(0x91, &[]));
    for (r, (a, b)) in [("Account", 0.0f64), ("Cash", 250.0)].into_iter().enumerate() {
        let mut row = Vec::new();
        row.extend_from_slice(&u32::try_from(r).unwrap().to_le_bytes());
        row.extend_from_slice(&0u32.to_le_bytes());
        row.extend_from_slice(&0u16.to_le_bytes());
        row.extend_from_slice(&[0u8; 1]);
        row.extend_from_slice(&[0u8; 1]);
        row.extend_from_slice(&[0u8; 4]);
        sheet.extend(brec(0x00, &row));
        let mut c0 = Vec::new();
        c0.extend_from_slice(&0u32.to_le_bytes());
        c0.extend_from_slice(&0u32.to_le_bytes());
        c0.extend(wide(a));
        sheet.extend(brec(0x06, &c0));
        let mut c1 = Vec::new();
        c1.extend_from_slice(&1u32.to_le_bytes());
        c1.extend_from_slice(&0u32.to_le_bytes());
        if r == 0 {
            c1.extend(wide("Balance"));
            sheet.extend(brec(0x06, &c1));
        } else {
            c1.extend_from_slice(&b.to_le_bytes());
            sheet.extend(brec(0x05, &c1));
        }
    }
    sheet.extend(brec(0x92, &[]));
    sheet.extend(brec(0x82, &[]));
    let rels = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.bin"/></Relationships>"#;
    let root = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.bin"/></Relationships>"#;
    zip_of(&[
        (
            "[Content_Types].xml",
            br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
        ),
        ("_rels/.rels", root.as_bytes()),
        ("xl/workbook.bin", &wbin),
        ("xl/_rels/workbook.bin.rels", rels.as_bytes()),
        ("xl/worksheets/sheet1.bin", &sheet),
    ])
}

const RTF: &str = r#"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Arial;}}{\colortbl;\red0\green0\blue0;}{\info{\title RTF Title}{\author Rita}}\pard\outlinelevel0\b Report Heading\b0\par
\pard Body with \i italic\i0  and caf\'e9 and \u8364? euro and {\field{\*\fldinst{HYPERLINK "https://example.com/rtf"}}{\fldrslt{link text}}}.\par
{\*\listtext\pard \bullet\tab}\pard\ls1 list item one\par
\trowd\cellx3000\cellx6000\pard\intbl Cell A\cell Cell B\cell\row
\trowd\cellx3000\cellx6000\pard\intbl 1\cell 2\cell\row
\pard After table\par}"#;

/// A PDF with two pages: a 24 pt title, wrapped body text, a list, content emitted bottom-up.
fn pdf_pages(page_texts: &[Vec<(&str, f32, f32, f32)>], title: Option<&str>) -> Vec<u8> {
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Document, Object, Stream};
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica", "Encoding" => "WinAnsiEncoding",
    });
    let resources_id = doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
    let mut kids: Vec<Object> = Vec::new();
    for lines in page_texts {
        let mut ops = Vec::new();
        for (text, size, x, y) in lines {
            ops.push(Operation::new("BT", vec![]));
            ops.push(Operation::new("Tf", vec!["F1".into(), (*size).into()]));
            ops.push(Operation::new("Td", vec![(*x).into(), (*y).into()]));
            ops.push(Operation::new("Tj", vec![Object::string_literal(*text)]));
            ops.push(Operation::new("ET", vec![]));
        }
        let content = Content { operations: ops };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        kids.push(page_id.into());
    }
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Count" => i64::try_from(kids.len()).unwrap(), "Kids" => kids,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    if let Some(t) = title {
        let info = doc.add_object(dictionary! {
            "Title" => Object::string_literal(t), "Author" => Object::string_literal("Ada"),
        });
        doc.trailer.set("Info", info);
    }
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

fn pdf() -> Vec<u8> {
    pdf_pages(
        &[
            // emitted bottom-up on purpose: output must follow the geometry
            vec![
                ("1. step one", 12.0, 72.0, 560.0),
                ("- first point", 12.0, 72.0, 600.0),
                ("Second paragraph here.", 12.0, 72.0, 640.0),
                ("two lines of body text.", 12.0, 72.0, 676.0),
                ("This paragraph wraps across", 12.0, 72.0, 690.0),
                ("Annual Report", 24.0, 72.0, 730.0),
            ],
            vec![("Second page text", 12.0, 72.0, 700.0)],
        ],
        Some("Annual Report 2024"),
    )
}

fn parse(bytes: &[u8], name: &str) -> ParsedDocument {
    parse_document(bytes, Some(name), None, &ParseLimits::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn err(bytes: &[u8], name: &str, limits: &ParseLimits) -> ParseError {
    parse_document(bytes, Some(name), None, limits).expect_err(name)
}

// ---------------------------------------------------------------------------------------------
// round trips
// ---------------------------------------------------------------------------------------------

#[test]
fn docx_round_trip() {
    let d = parse(&docx(), "report.docx");
    assert_eq!(d.format, ParseFormat::Docx);
    let md = &d.markdown;
    assert!(md.starts_with("# Quarterly Report\n"), "{md}");
    assert!(
        md.contains("Revenue grew **twelve percent** see [the site](https://example.com/site)."),
        "{md}"
    );
    assert!(md.contains("\n- first bullet"), "{md}");
    assert!(md.contains("\n1. step one"), "{md}");
    assert!(md.contains("\n## Details\n"), "{md}");
    assert!(
        md.contains("| Name | Qty |\n| --- | --- |\n| Widget | 4 |"),
        "{md}"
    );
    assert!(
        md.contains("Field [field link](https://example.com/field)"),
        "{md}"
    );
    assert_eq!(
        d.links,
        vec!["https://example.com/site", "https://example.com/field"]
    );
    assert_eq!(d.title.as_deref(), Some("Q3 Report"));
    assert_eq!(d.metadata["author"], "Ada Lovelace");
    assert!(
        d.html.contains("<h1>Quarterly Report</h1>") && d.html.contains("<table>"),
        "{}",
        d.html
    );
    assert!(d.text.contains("Widget\t4"), "{}", d.text);
    assert_eq!(
        d.content_type,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    assert_eq!(d.credits(), 1);
}

#[test]
fn office_references_preserve_text_links_metadata_and_sheet_cells() {
    let document = format!(
        r#"<w:document {W_NS}><w:body><w:p><w:r><w:t>A &amp; B &lt;ok&gt; &#x1F642; &#50;</w:t></w:r></w:p><w:p><w:hyperlink r:id="rId1"><w:r><w:t>link</w:t></w:r></w:hyperlink></w:p></w:body></w:document>"#
    );
    let docx = zip_of(&[
        ("[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#),
        ("word/document.xml", document.as_bytes()),
        ("word/_rels/document.xml.rels", br#"<Relationships><Relationship Id="rId1" Target="https://example.test/?a=1&amp;b=&#50;" TargetMode="External"/></Relationships>"#),
        ("docProps/core.xml", br#"<coreProperties><title>A &amp; B &#50;</title><creator>Ada &#76;ovelace</creator></coreProperties>"#),
    ]);
    let parsed = parse(&docx, "references.docx");
    assert!(parsed.text.starts_with("A & B <ok> 🙂 2"), "{}", parsed.text);
    assert_eq!(parsed.title.as_deref(), Some("A & B 2"));
    assert_eq!(parsed.metadata["author"], "Ada Lovelace");
    assert_eq!(parsed.links, vec!["https://example.test/?a=1&b=2"]);

    let odt = odf(
        "application/vnd.oasis.opendocument.text",
        r#"<office:text><text:p>A &amp; B &lt;ok&gt; &#x1F642; &#50;</text:p><text:p><text:a xlink:href="https://example.test/?a=1&amp;b=&#50;">link</text:a></text:p></office:text>"#,
    );
    let parsed = parse(&odt, "references.odt");
    assert!(parsed.text.starts_with("A & B <ok> 🙂 2"), "{}", parsed.text);
    assert_eq!(parsed.links, vec!["https://example.test/?a=1&b=2"]);

    let xlsx = xlsx_with(
        r#"<row r="1"><c r="A1" t="inlineStr"><is><t>A &amp; B &#x1F642; &#50;</t></is></c></row>"#,
    );
    let parsed = parse(&xlsx, "references.xlsx");
    assert!(parsed.text.contains("A & B 🙂 2"), "{}", parsed.text);
}

#[test]
fn office_reference_heavy_hyperlinks_preserve_text_and_links() {
    // Keep the fixture bounded while exposing per-reference copies of a long hyperlink target.
    const REFERENCES: usize = 16 * 1024;
    let href = format!("https://example.test/{}", "a".repeat(4096));
    let references = "&amp;&#38;&#x26;".repeat(REFERENCES / 3);
    let expected = format!("start{}end", "&".repeat(REFERENCES / 3 * 3));
    let label = format!("start{references}end");
    let document = format!(
        r#"<w:document {W_NS}><w:body><w:p><w:hyperlink r:id="rId1"><w:r><w:t>{label}</w:t></w:r></w:hyperlink></w:p></w:body></w:document>"#
    );
    let relationships = format!(
        r#"<Relationships><Relationship Id="rId1" Target="{href}" TargetMode="External"/></Relationships>"#
    );
    let docx = zip_of(&[
        ("[Content_Types].xml", br#"<Types/>"#),
        ("word/document.xml", document.as_bytes()),
        ("word/_rels/document.xml.rels", relationships.as_bytes()),
    ]);
    let slide = format!(
        r#"<p:sld {P_NS}><p:cSld><p:spTree>{}</p:spTree></p:cSld></p:sld>"#,
        shape(
            "",
            &format!(r#"<a:p><a:r><a:rPr><a:hlinkClick r:id="rId1"/></a:rPr><a:t>{label}</a:t></a:r></a:p>"#),
        )
    );
    let pptx = zip_of(&[
        ("[Content_Types].xml", br#"<Types/>"#),
        (
            "ppt/presentation.xml",
            br#"<presentation><sldIdLst><sldId r:id="rId1"/></sldIdLst></presentation>"#,
        ),
        (
            "ppt/_rels/presentation.xml.rels",
            br#"<Relationships><Relationship Id="rId1" Target="slides/slide1.xml"/></Relationships>"#,
        ),
        ("ppt/slides/slide1.xml", slide.as_bytes()),
        ("ppt/slides/_rels/slide1.xml.rels", relationships.as_bytes()),
    ]);
    let odt = odf(
        "application/vnd.oasis.opendocument.text",
        &format!(
            r#"<office:text><text:p><text:a xlink:href="{href}">{label}</text:a></text:p></office:text>"#
        ),
    );
    for (bytes, name) in [
        (docx, "references.docx"),
        (pptx, "references.pptx"),
        (odt, "references.odt"),
    ] {
        let parsed = parse(&bytes, name);
        assert_eq!(parsed.text, expected, "{name}");
        assert_eq!(parsed.links, vec![href.clone()], "{name}");
        assert!(
            parsed.markdown.contains(&format!("[{expected}]({href})")),
            "{name}"
        );
        assert_eq!(parsed.html.matches("href=").count(), 1, "{name}");
    }
}

#[test]
fn docm_extension_uses_the_docx_reader() {
    assert_eq!(parse(&docx(), "macro.docm").format, ParseFormat::Docx);
}

#[test]
fn xlsx_round_trip() {
    let d = parse(&xlsx(), "sales.xlsx");
    assert_eq!(d.format, ParseFormat::Xlsx);
    let md = &d.markdown;
    assert!(
        md.contains("## Sales\n\n| Item | Price |\n| --- | --- |\n| Widget | 9.5 |\n| Gadget | 12 |"),
        "{md}"
    );
    assert!(md.contains("## Notes\n\n| remember the milk |"), "{md}");
    assert_eq!(parse(&xlsx(), "sales.xlsm").format, ParseFormat::Xlsx);
}

#[test]
fn xlsx_sparse_far_cell_does_not_allocate_its_bounding_box() {
    let bytes = xlsx_with(
        r#"<row r="1"><c r="A1" t="inlineStr"><is><t>near</t></is></c></row><row r="1048576"><c r="XFD1048576" t="inlineStr"><is><t>far</t></is></c></row>"#,
    );
    let d = parse(&bytes, "bomb.xlsx");
    assert!(d.markdown.contains("near"), "{}", d.markdown);
    assert!(
        d.warnings.iter().any(|w| w.contains("columns beyond")),
        "{:?}",
        d.warnings
    );
}

#[test]
fn xlsb_round_trip() {
    let d = parse(&xlsb(), "ledger.xlsb");
    assert_eq!(d.format, ParseFormat::Xlsb);
    assert!(
        d.markdown
            .contains("## Ledger\n\n| Account | Balance |\n| --- | --- |\n| Cash | 250 |"),
        "{}",
        d.markdown
    );
}

#[test]
fn xls_round_trip() {
    let d = parse(&xls(), "stock.xls");
    assert_eq!(d.format, ParseFormat::Xls);
    assert!(
        d.markdown
            .contains("## Stock\n\n| Part | Count |\n| --- | --- |\n| Bolt | 40 |\n| Nut | 17.5 |"),
        "{:?}",
        d.markdown
    );
}

#[test]
fn pptx_round_trip_follows_presentation_order() {
    let d = parse(&pptx_with_slides(2), "deck.pptx");
    assert_eq!(d.format, ParseFormat::Pptx);
    let md = &d.markdown;
    let first = md.find("# Slide title 1").expect(md);
    let second = md.find("# Slide title 2").expect(md);
    assert!(first < second, "{md}");
    assert!(
        md.contains("- Ship parse\n- [the docs](https://example.com/docs)"),
        "{md}"
    );
    assert!(md.contains("\n\n---\n\n# Slide title 2"), "{md}");
    assert!(
        md.contains("| Item | Cost |\n| --- | --- |\n| Rent | 1200 |"),
        "{md}"
    );
    assert_eq!(d.links, vec!["https://example.com/docs"]);
    assert_eq!(parse(&pptx_with_slides(1), "deck.pptm").format, ParseFormat::Pptx);
}

#[test]
fn ppt_round_trip_skips_notes() {
    let d = parse(&ppt(), "deck.ppt");
    assert_eq!(d.format, ParseFormat::Ppt);
    assert_eq!(
        d.markdown,
        "# Deck Title\n\n- point one\n- point two\n\n---\n\n# Second Slide"
    );
    assert!(!d.markdown.contains("secret"), "{}", d.markdown);
}

#[test]
fn odt_round_trip() {
    let d = parse(&odt(), "handbook.odt");
    assert_eq!(d.format, ParseFormat::Odt);
    let md = &d.markdown;
    assert!(md.starts_with("# Handbook\n"), "{md}");
    assert!(
        md.contains("Plain **bold** and [a link](https://example.com/odt)."),
        "{md}"
    );
    assert!(md.contains("- alpha"), "{md}");
    assert!(md.contains("1. one"), "{md}");
    assert!(md.contains("| H1 | H2 |\n| --- | --- |\n| v1 | v2 |"), "{md}");
    assert!(md.contains("\nNote."), "{md}");
    assert!(!md.contains("footnote body"), "{md}");
    assert_eq!(d.title.as_deref(), Some("Handbook"));
    assert_eq!(d.metadata["author"], "Grace Hopper");
    assert_eq!(d.metadata["keywords"], "alpha, beta");
}

#[test]
fn ods_round_trip_and_repeat_bomb() {
    let d = parse(&ods(), "budget.ods");
    assert_eq!(d.format, ParseFormat::Ods);
    assert!(
        d.markdown
            .contains("## Budget\n\n| Item | Cost |\n| --- | --- |\n| Rent | 1,200.00 |"),
        "{}",
        d.markdown
    );
}

#[test]
fn odp_round_trip() {
    let d = parse(&odp(), "deck.odp");
    assert_eq!(d.format, ParseFormat::Odp);
    assert_eq!(
        d.markdown,
        "# Launch plan\n\n- Step A\n- Step B\n\n---\n\n# Wrap up"
    );
}

#[test]
fn doc_round_trip() {
    let d = parse(&doc(), "legacy.doc");
    assert_eq!(d.format, ParseFormat::Doc);
    let md = &d.markdown;
    assert!(md.contains("Legacy heading"), "{md}");
    assert!(
        md.contains("Second paragraph with [click here](https://example.com/doc) inside."),
        "{md}"
    );
    assert!(md.contains("| A1 | B1 |\n| --- | --- |\n| A2 | B2 |"), "{md}");
    assert!(md.trim_end().ends_with("After table"), "{md}");
}

#[test]
fn rtf_round_trip() {
    let d = parse(RTF.as_bytes(), "report.rtf");
    assert_eq!(d.format, ParseFormat::Rtf);
    let md = &d.markdown;
    assert!(
        md.starts_with("# **Report Heading**\n") || md.starts_with("# Report Heading\n"),
        "{md}"
    );
    assert!(
        md.contains("Body with *italic* and café and € euro and [link text](https://example.com/rtf)."),
        "{md}"
    );
    assert!(md.contains("\n- list item one"), "{md}");
    assert!(
        md.contains("| Cell A | Cell B |\n| --- | --- |\n| 1 | 2 |"),
        "{md}"
    );
    assert!(md.trim_end().ends_with("After table"), "{md}");
    assert_eq!(d.title.as_deref(), Some("RTF Title"));
    assert_eq!(d.metadata["author"], "Rita");
}

#[test]
fn epub_round_trip_follows_the_spine() {
    let d = parse(&epub(), "book.epub");
    assert_eq!(d.format, ParseFormat::Epub);
    assert_eq!(d.title.as_deref(), Some("The Book"));
    assert_eq!(d.metadata["author"], "Grace");
    let one = d.markdown.find("# Chapter One").expect(&d.markdown);
    let two = d.markdown.find("# Chapter Two").expect(&d.markdown);
    assert!(one < two, "{}", d.markdown);
    assert!(
        d.markdown.contains("[a link](https://example.com/epub)"),
        "{}",
        d.markdown
    );
    assert_eq!(d.links, vec!["https://example.com/epub"]);
}

#[test]
fn csv_round_trip_with_quotes_and_delimiters() {
    let d = parse(
        b"name,note\n\"Smith, Jo\",\"says \"\"hi\"\"\"\nLee,a|b\n",
        "people.csv",
    );
    assert_eq!(d.format, ParseFormat::Csv);
    assert_eq!(
        d.markdown,
        "| name | note |\n| --- | --- |\n| Smith, Jo | says \"hi\" |\n| Lee | a\\|b |"
    );
    let semi = parse("a;b\n1;2\n".as_bytes(), "semi.csv");
    assert_eq!(semi.markdown, "| a | b |\n| --- | --- |\n| 1 | 2 |");
    let tab = parse(b"a\tb\n1\t2", "tab.csv");
    assert_eq!(tab.markdown, "| a | b |\n| --- | --- |\n| 1 | 2 |");
}

#[test]
fn txt_and_md_round_trip() {
    let t = parse(
        b"first line\nsecond line\n\nsee https://example.com/t.\n",
        "notes.txt",
    );
    assert_eq!(t.format, ParseFormat::Txt);
    assert_eq!(
        t.markdown,
        "first line\nsecond line\n\nsee https://example.com/t."
    );
    assert_eq!(t.links, vec!["https://example.com/t"]);
    assert!(t.html.contains("<p>first line<br>second line</p>"), "{}", t.html);

    let src = "# Title\n\nSome **bold** and [a link](https://example.com/m).\n\n- one\n- two\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n```\ncode\n```\n";
    let m = parse(src.as_bytes(), "readme.md");
    assert_eq!(m.format, ParseFormat::Md);
    assert_eq!(m.markdown, src.trim());
    assert_eq!(m.title.as_deref(), Some("Title"));
    assert_eq!(m.links, vec!["https://example.com/m"]);
    assert!(m.html.contains("<h1>Title</h1>"), "{}", m.html);
    assert!(
        m.html.contains("<strong>bold</strong>")
            && m.html.contains("<a href=\"https://example.com/m\">a link</a>"),
        "{}",
        m.html
    );
    assert!(m.html.contains("<ul><li>one</li><li>two</li></ul>"), "{}", m.html);
    assert!(
        m.html.contains("<table>") && m.html.contains("<pre><code>code</code></pre>"),
        "{}",
        m.html
    );
}

const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Uploaded Page</title><meta name="description" content="from a file"></head><body><nav><a href="/menu">Menu</a></nav><main><h1>Hello</h1><p>Body text with <a href="https://example.com/abs">an absolute link</a> and <a href="rel/page.html">a relative one</a>.</p><img src="pic.png" alt="pic"><img src="data:image/png;base64,AAAA" alt="inline"></main></body></html>"#;

#[test]
fn html_round_trip_keeps_relative_references_relative() {
    for name in ["page.html", "page.htm", "page.xhtml"] {
        let d = parse(PAGE.as_bytes(), name);
        assert_eq!(d.format, ParseFormat::Html, "{name}");
        assert!(d.markdown.contains("# Hello"), "{}", d.markdown);
        assert!(
            d.markdown.contains("[a relative one](rel/page.html)"),
            "{}",
            d.markdown
        );
        assert!(!d.markdown.contains("upload.invalid"), "{}", d.markdown);
        assert_eq!(d.links, vec!["https://example.com/abs"]);
        assert_eq!(d.title.as_deref(), Some("Uploaded Page"));
        assert_eq!(d.metadata["description"], "from a file");
        assert_eq!(d.raw_html, PAGE);
        assert!(d.images.contains(&"pic.png".to_owned()), "{:?}", d.images);
    }
}

#[test]
fn html_options_only_main_content_and_selectors() {
    let full = parse_document_with(
        PAGE.as_bytes(),
        Some("p.html"),
        None,
        &ParseOptions {
            only_main_content: false,
            ..ParseOptions::default()
        },
    )
    .unwrap();
    assert!(full.markdown.contains("Menu"), "{}", full.markdown);
    let main = parse_document_with(PAGE.as_bytes(), Some("p.html"), None, &ParseOptions::default()).unwrap();
    assert!(!main.markdown.contains("Menu"), "{}", main.markdown);
    let only_h1 = parse_document_with(
        PAGE.as_bytes(),
        Some("p.html"),
        None,
        &ParseOptions {
            include_tags: vec!["h1".into()],
            ..ParseOptions::default()
        },
    )
    .unwrap();
    assert_eq!(only_h1.markdown.trim(), "# Hello");
    let excluded = parse_document_with(
        PAGE.as_bytes(),
        Some("p.html"),
        None,
        &ParseOptions {
            only_main_content: false,
            exclude_tags: vec!["nav".into(), "img".into()],
            ..ParseOptions::default()
        },
    )
    .unwrap();
    assert!(!excluded.markdown.contains("Menu"), "{}", excluded.markdown);
    let bad = parse_document_with(
        PAGE.as_bytes(),
        Some("p.html"),
        None,
        &ParseOptions {
            include_tags: vec!["h1[".into()],
            ..ParseOptions::default()
        },
    );
    assert!(matches!(bad, Err(ParseError::InvalidSelector { .. })), "{bad:?}");
}

#[test]
fn html_non_utf8_charset_is_decoded() {
    let mut page = b"<html><head><meta charset=\"iso-8859-1\"></head><body><p>caf".to_vec();
    page.push(0xE9);
    page.extend_from_slice(b"</p></body></html>");
    let d = parse(&page, "latin.html");
    assert!(d.markdown.contains("café"), "{}", d.markdown);
}

// ---------------------------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------------------------

#[test]
fn pdf_text_layer_reading_order_headings_lists_and_metadata() {
    let d = parse(&pdf(), "report.pdf");
    assert_eq!(d.format, ParseFormat::Pdf);
    let page1 = "# Annual Report\n\nThis paragraph wraps across two lines of body text.\n\nSecond paragraph here.\n\n- first point\n1. step one";
    assert!(d.markdown.starts_with(page1), "{}", d.markdown);
    assert!(d.markdown.ends_with("\n\nSecond page text"), "{}", d.markdown);
    assert_eq!(d.num_pages, Some(2));
    assert_eq!(d.total_pages, Some(2));
    assert_eq!(d.credits(), 2);
    assert_eq!(d.title.as_deref(), Some("Annual Report 2024"));
    assert_eq!(d.metadata["author"], "Ada");
    assert_eq!(d.pages.len(), 2);
    assert_eq!(d.pages[1].page_number, 2);
    assert_eq!(d.pages[1].markdown, "Second page text");
    assert_eq!(d.content_type, "application/pdf");
}

#[test]
fn extract_pdf_options_page_markers_selection_and_cap() {
    let bytes = pdf();
    let plain = extract_pdf(&bytes, &PdfOptions::default()).unwrap();
    assert_eq!((plain.num_pages, plain.total_pages), (2, 2));
    let marked = extract_pdf(
        &bytes,
        &PdfOptions {
            page_markers: true,
            ..PdfOptions::default()
        },
    )
    .unwrap();
    assert!(
        marked
            .markdown
            .contains("\n\n---\n\n<!-- page 2 -->\n\nSecond page text"),
        "{}",
        marked.markdown
    );
    assert!(
        !marked.markdown.contains("<!-- page 1 -->"),
        "{}",
        marked.markdown
    );
    let capped = extract_pdf(
        &bytes,
        &PdfOptions {
            max_pages: Some(1),
            ..PdfOptions::default()
        },
    )
    .unwrap();
    assert_eq!((capped.num_pages, capped.total_pages), (1, 2));
    assert!(!capped.markdown.contains("Second page"), "{}", capped.markdown);
    let picked = extract_pdf(
        &bytes,
        &PdfOptions {
            pages: vec![2, 9],
            ..PdfOptions::default()
        },
    )
    .unwrap();
    assert_eq!(picked.markdown, "Second page text");
    assert_eq!((picked.num_pages, picked.total_pages), (1, 2));
    assert!(
        picked.warnings.iter().any(|w| w.contains("not in the document")),
        "{:?}",
        picked.warnings
    );
}

#[test]
fn pdf_layout_blocks_have_boxes_and_spans_into_the_markdown() {
    let d = parse_document_with(
        &pdf(),
        Some("r.pdf"),
        None,
        &ParseOptions {
            pdf_layout: true,
            ..ParseOptions::default()
        },
    )
    .unwrap();
    assert_eq!(d.layout.len(), 2);
    let p1 = &d.layout[0];
    assert_eq!(p1.page_number, 1);
    assert_eq!(p1.items[0].kind, "title");
    assert_eq!(p1.items[0].id, "p1.b0");
    assert_eq!(p1.items[1].kind, "text");
    let chars: Vec<char> = d.markdown.chars().collect();
    for page in &d.layout {
        for item in &page.items {
            let [x0, y0, x1, y1] = item.bbox.expect("page has a media box");
            assert!((0.0..=1.0).contains(&x0) && x0 < x1 && x1 <= 1.0, "{item:?}");
            assert!((0.0..=1.0).contains(&y0) && y0 < y1 && y1 <= 1.0, "{item:?}");
            let [s, e] = item.markdown_span.expect("span");
            assert_eq!(chars[s..e].iter().collect::<String>(), item.content);
        }
    }
    assert!(
        p1.items[0].bbox.unwrap()[1] < p1.items[1].bbox.unwrap()[1],
        "title is above the body"
    );
    let json = serde_json::to_value(&d.layout[0]).unwrap();
    assert_eq!(json["pageNumber"], 1);
    assert_eq!(json["items"][0]["type"], "title");
    assert!(json["items"][0]["markdownSpan"].is_array());
}

#[test]
fn pdf_without_text_warns_or_fails_in_fast_mode() {
    let empty = pdf_pages(&[vec![]], None);
    let d = parse(&empty, "scan.pdf");
    assert_eq!(d.markdown, "");
    assert!(
        d.warnings.iter().any(|w| w.contains("no extractable text")),
        "{:?}",
        d.warnings
    );
    let e = parse_document_with(
        &empty,
        Some("scan.pdf"),
        None,
        &ParseOptions {
            pdf_require_text: true,
            ..ParseOptions::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, ParseError::NoText { format: "pdf" }), "{e:?}");
}

#[test]
fn encrypted_and_corrupt_pdfs_are_typed_errors() {
    let encrypted = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n5 0 obj\n<< /Filter /Standard /V 1 /R 2 /O (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) /U (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) /P -4 >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 5 0 R /ID [(abcdefghijklmnop) (abcdefghijklmnop)] /Size 6 >>\n%%EOF\n";
    let e = err(encrypted, "locked.pdf", &ParseLimits::default());
    assert!(matches!(e, ParseError::Encrypted { format: "pdf" }), "{e:?}");
    for junk in [&b"%PDF-1.4\ngarbage"[..], b"%PDF-", b"not a pdf at all"] {
        let e = err(junk, "x.pdf", &ParseLimits::default());
        assert!(matches!(e, ParseError::Corrupt { format: "pdf", .. }), "{e:?}");
    }
    let mut truncated = pdf();
    truncated.truncate(truncated.len() / 2);
    let r = parse_document(&truncated, Some("t.pdf"), None, &ParseLimits::default());
    assert!(!matches!(r, Err(ParseError::Internal { .. })), "{r:?}");
}

// ---------------------------------------------------------------------------------------------
// detection and formats
// ---------------------------------------------------------------------------------------------

#[test]
fn formats_list_every_documented_extension() {
    let want = [
        ".html", ".htm", ".xhtml", ".pdf", ".docx", ".doc", ".docm", ".odt", ".ods", ".odp", ".rtf", ".xlsx",
        ".xls", ".xlsm", ".xlsb", ".pptx", ".ppt", ".pptm", ".epub", ".csv", ".txt", ".md",
    ];
    let listed: Vec<&str> = supported_formats()
        .iter()
        .filter(|f| f.available)
        .flat_map(|f| f.extensions.iter().copied())
        .collect();
    for ext in want {
        assert!(listed.contains(&ext), "{ext} missing from {listed:?}");
        assert!(ParseFormat::from_extension(ext).is_some(), "{ext}");
    }
    let docx = supported_formats().iter().find(|f| f.format == "docx").unwrap();
    assert_eq!(docx.extensions[0], ".docx");
    assert!(docx
        .mime_types
        .contains(&"application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
    let png = supported_formats().iter().find(|f| f.format == "png").unwrap();
    assert!(!png.available);
    assert_eq!(
        serde_json::to_value(docx).unwrap()["mimeTypes"][0],
        docx.mime_types[0]
    );
}

#[test]
fn bytes_win_over_a_wrong_extension_and_mime_fills_in() {
    let limits = ParseLimits::default();
    assert_eq!(
        detect_format(&docx(), Some("report.txt"), None, &limits).unwrap(),
        ParseFormat::Docx
    );
    assert_eq!(
        detect_format(&xlsx(), Some("a.xls"), None, &limits).unwrap(),
        ParseFormat::Xlsx
    );
    assert_eq!(
        detect_format(&pdf(), None, None, &limits).unwrap(),
        ParseFormat::Pdf
    );
    assert_eq!(
        detect_format(&epub(), Some("b.zip"), None, &limits).unwrap(),
        ParseFormat::Epub
    );
    assert_eq!(
        detect_format(b"a,b\n1,2", None, Some("text/csv; charset=utf-8"), &limits).unwrap(),
        ParseFormat::Csv
    );
    assert_eq!(
        detect_format(b"<!DOCTYPE html><p>x</p>", Some("noext"), None, &limits).unwrap(),
        ParseFormat::Html
    );
    assert_eq!(
        detect_format(RTF.as_bytes(), Some("x.dat"), None, &limits).unwrap(),
        ParseFormat::Rtf
    );
}

#[test]
fn unsupported_types_are_typed() {
    let limits = ParseLimits::default();
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    for (bytes, name) in [
        (&png[..], "pic.png"),
        (b"\xff\xd8\xff\xe0jpeg", "pic.jpg"),
        (b"MZ\x90\0binary", "tool.exe"),
        (b"plain", "data.bin"),
        (&zip_of(&[("a.txt", b"hi")])[..], "a.zip"),
        (&[0x1f, 0x8b, 8, 0][..], "a.gz"),
    ] {
        let e = err(bytes, name, &limits);
        assert!(matches!(e, ParseError::UnsupportedFormat { .. }), "{name}: {e:?}");
    }
    let e = detect_format(b"hello", None, None, &limits).unwrap_err();
    assert!(matches!(e, ParseError::UnsupportedFormat { .. }), "{e:?}");
    let e = err(png, "pic.png", &limits);
    assert!(e.to_string().contains("OCR"), "{e}");
}

// ---------------------------------------------------------------------------------------------
// limits
// ---------------------------------------------------------------------------------------------

#[test]
fn input_limit_is_enforced_before_parsing() {
    let limits = ParseLimits {
        max_input_bytes: 100,
        ..ParseLimits::default()
    };
    let e = err(&[b'a'; 101], "big.txt", &limits);
    assert!(
        matches!(
            e,
            ParseError::TooLarge {
                what: "input bytes",
                limit: 100,
                actual: 101
            }
        ),
        "{e:?}"
    );
    assert!(parse_document(&[b'a'; 100], Some("ok.txt"), None, &limits).is_ok());
}

#[test]
fn zip_bomb_stops_at_the_uncompressed_budget() {
    // 8 MiB of zeros deflates to a few KiB.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let bomb = zip_of(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", &zeros),
    ]);
    assert!(bomb.len() < 64 * 1024, "fixture is not a bomb: {}", bomb.len());
    let limits = ParseLimits {
        max_uncompressed_bytes: 1024 * 1024,
        ..ParseLimits::default()
    };
    for name in ["b.docx", "b.xlsx", "b.pptx", "b.epub", "b.odt", "b.xlsb"] {
        let e = err(&bomb, name, &limits);
        assert!(matches!(e, ParseError::TooLarge { .. }), "{name}: {e:?}");
    }
}

#[test]
fn zip_entry_count_limit() {
    let names: Vec<String> = (0..20).map(|i| format!("f{i}.txt")).collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
    let many = zip_of(&entries);
    let limits = ParseLimits {
        max_entries: 10,
        ..ParseLimits::default()
    };
    let e = err(&many, "m.docx", &limits);
    assert!(
        matches!(
            e,
            ParseError::TooLarge {
                what: "archive entries",
                limit: 10,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn soft_limits_truncate_with_warnings() {
    let limits = ParseLimits {
        max_rows: 3,
        ..ParseLimits::default()
    };
    let csv: String = (0..10).map(|i| format!("{i},x\n")).collect();
    let d = parse_document(csv.as_bytes(), Some("r.csv"), None, &limits).unwrap();
    assert_eq!(d.markdown.matches('\n').count(), 3, "{}", d.markdown); // 3 rows + separator
    assert!(
        d.warnings.iter().any(|w| w.contains("row limit")),
        "{:?}",
        d.warnings
    );

    let d = parse_document(
        &pptx_with_slides(3),
        Some("s.pptx"),
        None,
        &ParseLimits {
            max_pages: 2,
            ..ParseLimits::default()
        },
    )
    .unwrap();
    assert!(
        d.markdown.contains("Slide title 2") && !d.markdown.contains("Slide title 3"),
        "{}",
        d.markdown
    );
    assert!(
        d.warnings.iter().any(|w| w.contains("only the first 2")),
        "{:?}",
        d.warnings
    );

    let d = parse_document(
        &xlsx(),
        Some("s.xlsx"),
        None,
        &ParseLimits {
            max_sheets: 1,
            ..ParseLimits::default()
        },
    )
    .unwrap();
    assert!(
        d.markdown.contains("## Sales") && !d.markdown.contains("## Notes"),
        "{}",
        d.markdown
    );
    assert!(
        d.warnings.iter().any(|w| w.contains("only the first 1")),
        "{:?}",
        d.warnings
    );

    let d = parse_document(
        &ods(),
        Some("o.ods"),
        None,
        &ParseLimits {
            max_rows: 1,
            ..ParseLimits::default()
        },
    )
    .unwrap();
    assert!(
        d.markdown.contains("Item") && !d.markdown.contains("Rent"),
        "{}",
        d.markdown
    );
    assert!(
        d.warnings.iter().any(|w| w.contains("row limit")),
        "{:?}",
        d.warnings
    );

    let p = extract_pdf(
        &pdf(),
        &PdfOptions {
            limits: ParseLimits {
                max_pages: 1,
                ..ParseLimits::default()
            },
            ..PdfOptions::default()
        },
    )
    .unwrap();
    assert_eq!((p.num_pages, p.total_pages), (1, 2));
}

#[test]
fn rtf_group_depth_bomb_is_bounded() {
    let mut bomb = String::from("{\\rtf1 ");
    bomb.push_str(&"{".repeat(100_000));
    let e = err(bomb.as_bytes(), "b.rtf", &ParseLimits::default());
    assert!(
        matches!(
            e,
            ParseError::TooLarge {
                what: "group depth",
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn encrypted_office_files_are_typed() {
    let ole_enc = ole(&[
        ("EncryptedPackage", vec![1, 2, 3]),
        ("EncryptionInfo", vec![4, 5]),
    ]);
    let e = err(&ole_enc, "secret.docx", &ParseLimits::default());
    assert!(matches!(e, ParseError::Encrypted { format: "docx" }), "{e:?}");
    let e = err(
        &doc_with("x\r", 0x0200 | 0x0100),
        "enc.doc",
        &ParseLimits::default(),
    );
    assert!(matches!(e, ParseError::Encrypted { format: "doc" }), "{e:?}");
    let mut stream = rec(0xF, 0, 0x2F14, &[0u8; 4]);
    stream.extend(rec(0, 0, 0x0FA0, &utf16("x")));
    let e = err(
        &ole(&[("PowerPoint Document", stream)]),
        "enc.ppt",
        &ParseLimits::default(),
    );
    assert!(matches!(e, ParseError::Encrypted { format: "ppt" }), "{e:?}");
}

// ---------------------------------------------------------------------------------------------
// hostile input
// ---------------------------------------------------------------------------------------------

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("a.docx", docx()),
        ("a.xlsx", xlsx()),
        ("a.xlsb", xlsb()),
        ("a.xls", xls()),
        ("a.pptx", pptx_with_slides(2)),
        ("a.ppt", ppt()),
        ("a.doc", doc()),
        ("a.odt", odt()),
        ("a.ods", ods()),
        ("a.odp", odp()),
        ("a.epub", epub()),
        ("a.rtf", RTF.as_bytes().to_vec()),
        ("a.pdf", pdf()),
        ("a.csv", b"a,b\n1,2\n".to_vec()),
        ("a.html", PAGE.as_bytes().to_vec()),
        ("a.md", b"# t\n\n- x\n".to_vec()),
        ("a.txt", b"hello".to_vec()),
    ]
}

fn is_internal(r: &Result<ParsedDocument, ParseError>) -> bool {
    matches!(r, Err(ParseError::Internal { .. }))
}

/// Formats parsed by a third-party crate (`calamine`, `lopdf`). A panic inside them on hostile
/// bytes (calamine indexes the shared-string table of an `.xlsb` unchecked) is contained by the
/// parse guard and reported as `Internal`; every other parser is ours and must never panic.
fn third_party(name: &str) -> bool {
    matches!(name.rsplit('.').next(), Some("pdf" | "xls" | "xlsx" | "xlsb"))
}

fn never_internal(r: &Result<ParsedDocument, ParseError>, name: &str, what: &str) {
    assert!(!is_internal(r) || third_party(name), "{what}: parser panicked");
}

#[test]
fn malformed_table_never_panics() {
    let exts = [
        "x.html", "x.pdf", "x.docx", "x.doc", "x.odt", "x.ods", "x.odp", "x.rtf", "x.xlsx", "x.xls",
        "x.xlsb", "x.pptx", "x.ppt", "x.epub", "x.csv", "x.txt", "x.md",
    ];
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        b"PK\x03\x04".to_vec(),
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
        b"%PDF-1.7\n".to_vec(),
        b"{\\rtf1".to_vec(),
        b"{\\rtf1\\u-1\\'".to_vec(),
        vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        vec![0xFF; 600],
        vec![0u8; 5000],
        "ünïcödé \u{feff}".as_bytes().to_vec(),
        b"<html><".to_vec(),
        b"<<<<<>>>>>&&&&;;;;".to_vec(),
        b"\"unterminated,csv\n\"".to_vec(),
    ];
    for bytes in &cases {
        for name in exts {
            let r = parse_document(bytes, Some(name), None, &ParseLimits::default());
            never_internal(
                &r,
                name,
                &format!("{name} on {:?}", &bytes[..bytes.len().min(16)]),
            );
        }
    }
}

#[test]
fn truncated_and_corrupted_fixtures_never_panic() {
    for (name, bytes) in fixtures() {
        for cut in [
            0,
            1,
            7,
            bytes.len() / 3,
            bytes.len() / 2,
            bytes.len().saturating_sub(1),
        ] {
            let r = parse_document(
                &bytes[..cut.min(bytes.len())],
                Some(name),
                None,
                &ParseLimits::default(),
            );
            never_internal(&r, name, &format!("{name} truncated at {cut}"));
        }
        for at in (0..bytes.len()).step_by((bytes.len() / 40).max(1)) {
            let mut b = bytes.clone();
            b[at] ^= 0xA5;
            let r = parse_document(&b, Some(name), None, &ParseLimits::default());
            never_internal(&r, name, &format!("{name} flipped at {at}"));
        }
    }
}

#[test]
fn every_fixture_parses_to_non_empty_markdown() {
    for (name, bytes) in fixtures() {
        let d = parse(&bytes, name);
        assert!(!d.markdown.trim().is_empty(), "{name}");
        assert!(d.warnings.is_empty(), "{name}: {:?}", d.warnings);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..1536),
        ext in prop_oneof![
            Just("html"), Just("pdf"), Just("docx"), Just("doc"), Just("odt"), Just("ods"), Just("odp"),
            Just("rtf"), Just("xlsx"), Just("xls"), Just("xlsb"), Just("pptx"), Just("ppt"), Just("epub"),
            Just("csv"), Just("txt"), Just("md"),
        ],
    ) {
        let r = parse_document(&bytes, Some(&format!("f.{ext}")), None, &ParseLimits::default());
        prop_assert!(!is_internal(&r) || third_party(ext));
    }

    #[test]
    fn magic_prefixed_noise_never_panics(
        tail in proptest::collection::vec(any::<u8>(), 0..1024),
        head in prop_oneof![
            Just(b"PK\x03\x04".to_vec()),
            Just(b"%PDF-1.4\n".to_vec()),
            Just(vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
            Just(b"{\\rtf1 ".to_vec()),
        ],
    ) {
        let mut bytes = head;
        bytes.extend(tail);
        let r = parse_document(&bytes, None, None, &ParseLimits::default());
        // lopdf (PDF magic) and calamine (PK noise is never a valid workbook) are third-party
        prop_assert!(!is_internal(&r) || bytes.starts_with(b"%PDF"));
    }
}
