#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Scans for the OCR tests, built without any image or PDF library: a 5x7 bitmap font drawn to
//! grey pixels, a PNG writer (stored deflate blocks) and PDFs that carry the pixels as a raw
//! `DeviceGray` image (a scan), as vector rectangles (no text layer, no image) or as a real text
//! layer next to a scan.
//!
//! Include it with `#[path = "support/scan.rs"] mod scan;`. Dependency-free on purpose, so the
//! API and worker tests can include the same file.

/// Grey pixels, row-major, 0 black .. 255 white.
#[derive(Clone)]
pub struct Gray {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

const GLYPHS: &[(char, [&str; 7])] = &[
    (
        'A',
        ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    ),
    (
        'B',
        ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    ),
    (
        'C',
        ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    ),
    (
        'D',
        ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    ),
    (
        'E',
        ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    ),
    (
        'F',
        ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    ),
    (
        'G',
        ["01110", "10001", "10000", "10111", "10001", "10001", "01111"],
    ),
    (
        'H',
        ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    ),
    (
        'I',
        ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    ),
    (
        'J',
        ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
    ),
    (
        'K',
        ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    ),
    (
        'L',
        ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    ),
    (
        'M',
        ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    ),
    (
        'N',
        ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    ),
    (
        'O',
        ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    ),
    (
        'P',
        ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    ),
    (
        'Q',
        ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    ),
    (
        'R',
        ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    ),
    (
        'S',
        ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    ),
    (
        'T',
        ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    ),
    (
        'U',
        ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    ),
    (
        'V',
        ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    ),
    (
        'W',
        ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    ),
    (
        'X',
        ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    ),
    (
        'Y',
        ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    ),
    (
        'Z',
        ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    ),
    (
        '0',
        ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    ),
    (
        '1',
        ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    ),
    (
        '2',
        ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    ),
    (
        '3',
        ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    ),
    (
        '4',
        ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    ),
    (
        '5',
        ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    ),
    (
        '6',
        ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
    ),
    (
        '7',
        ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    ),
    (
        '8',
        ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    ),
    (
        '9',
        ["01110", "10001", "10001", "01111", "00001", "00010", "01100"],
    ),
];

fn glyph(c: char) -> Option<&'static [&'static str; 7]> {
    let c = c.to_ascii_uppercase();
    GLYPHS.iter().find(|(g, _)| *g == c).map(|(_, rows)| rows)
}

/// Draw `lines` (upper-case letters, digits and spaces; other characters are blank) with each
/// font cell `scale` pixels wide, on white, with a margin of four cells. Returns the picture and
/// the pixel boxes `[left, top, right, bottom]` of every line.
pub fn render_lines(lines: &[&str], scale: usize) -> (Gray, Vec<[usize; 4]>) {
    let margin = 4 * scale;
    let cell = scale;
    let line_h = 7 * cell;
    let gap = 6 * cell;
    let width = lines
        .iter()
        .map(|l| l.chars().map(|c| if c == ' ' { 8 } else { 6 }).sum::<usize>() * cell)
        .max()
        .unwrap_or(0)
        + 2 * margin;
    let height = lines.len() * line_h + lines.len().saturating_sub(1) * gap + 2 * margin;
    let mut pixels = vec![255u8; width * height];
    let mut boxes = Vec::new();
    for (row, line) in lines.iter().enumerate() {
        let top = margin + row * (line_h + gap);
        let mut x = margin;
        for c in line.chars() {
            if c == ' ' {
                x += 8 * cell;
                continue;
            }
            if let Some(g) = glyph(c) {
                for (gy, bits) in g.iter().enumerate() {
                    for (gx, b) in bits.bytes().enumerate() {
                        if b == b'1' {
                            for dy in 0..cell {
                                for dx in 0..cell {
                                    pixels[(top + gy * cell + dy) * width + x + gx * cell + dx] = 0;
                                }
                            }
                        }
                    }
                }
            }
            x += 6 * cell;
        }
        boxes.push([margin, top, x.saturating_sub(cell), top + line_h]);
    }
    (
        blur(
            &Gray {
                width,
                height,
                pixels,
            },
            scale / 3,
        ),
        boxes,
    )
}

/// Box blur of radius `r` (soft edges: Tesseract reads blocky bitmap glyphs poorly).
fn blur(img: &Gray, r: usize) -> Gray {
    if r == 0 {
        return img.clone();
    }
    let mut out = img.clone();
    for y in 0..img.height {
        for x in 0..img.width {
            let (mut sum, mut n) = (0u32, 0u32);
            for yy in y.saturating_sub(r)..=(y + r).min(img.height - 1) {
                for xx in x.saturating_sub(r)..=(x + r).min(img.width - 1) {
                    sum += u32::from(img.pixels[yy * img.width + xx]);
                    n += 1;
                }
            }
            out.pixels[y * img.width + x] = u8::try_from(sum / n).unwrap();
        }
    }
    out
}

/// One line of text.
pub fn render(text: &str, scale: usize) -> Gray {
    render_lines(&[text], scale).0
}

/// `img` on a white page of `width` x `height` with the picture's top-left corner at `(x, y)`.
pub fn on_page(img: &Gray, width: usize, height: usize, x: usize, y: usize) -> Gray {
    let mut pixels = vec![255u8; width * height];
    for row in 0..img.height.min(height.saturating_sub(y)) {
        for col in 0..img.width.min(width.saturating_sub(x)) {
            pixels[(y + row) * width + x + col] = img.pixels[row * img.width + col];
        }
    }
    Gray {
        width,
        height,
        pixels,
    }
}

/// The picture turned a quarter turn clockwise.
pub fn rotate_cw(img: &Gray) -> Gray {
    let (w, h) = (img.width, img.height);
    let mut pixels = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            // (x, y) lands at (h - 1 - y, x) in an image h wide and w high
            pixels[x * h + (h - 1 - y)] = img.pixels[y * w + x];
        }
    }
    Gray {
        width: h,
        height: w,
        pixels,
    }
}

/// The picture turned a quarter turn counter-clockwise.
pub fn rotate_ccw(img: &Gray) -> Gray {
    rotate_cw(&rotate_cw(&rotate_cw(img)))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
}

/// A grey PNG (zlib stored blocks: valid, uncompressed).
pub fn png(img: &Gray) -> Vec<u8> {
    let mut raw = Vec::with_capacity((img.width + 1) * img.height);
    for row in img.pixels.chunks(img.width) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65_535).collect();
    for (i, b) in blocks.iter().enumerate() {
        z.push(u8::from(i + 1 == blocks.len()));
        let len = u16::try_from(b.len()).unwrap();
        z.extend_from_slice(&len.to_le_bytes());
        z.extend_from_slice(&(!len).to_le_bytes());
        z.extend_from_slice(b);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&u32::try_from(img.width).unwrap().to_be_bytes());
    ihdr.extend_from_slice(&u32::try_from(img.height).unwrap().to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// A page of a generated PDF.
pub enum PageKind<'a> {
    /// A raw `DeviceGray` image scaled to the page, page rotation `rotate` degrees.
    Scan { img: &'a Gray, rotate: u32 },
    /// A JPEG (`DCTDecode`) scan scaled to the page.
    Dct {
        jpeg: &'a [u8],
        width: usize,
        height: usize,
    },
    /// Black rectangles for every lit font cell: no text layer, no image.
    Vector { text: &'a str },
    /// A Helvetica text layer.
    Text { text: &'a str },
    /// A Helvetica text layer in the upper half and a scan in the lower half.
    TextAndScan { text: &'a str, img: &'a Gray },
}

enum Image<'a> {
    Raw(&'a Gray),
    Jpeg {
        bytes: &'a [u8],
        width: usize,
        height: usize,
    },
}

/// A PDF with one US-letter page per entry (a real xref table).
pub fn pdf(pages: &[PageKind<'_>]) -> Vec<u8> {
    let n = pages.len();
    // objects 1 catalog, 2 pages, 3 font; page i uses 4 + 3i (page), 5 + 3i (contents), 6 + 3i (image)
    let mut objects: Vec<Vec<u8>> = vec![b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()];
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 4 + 3 * i)).collect();
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    for (i, page) in pages.iter().enumerate() {
        let (contents, image, rotate): (String, Option<Image<'_>>, u32) = match page {
            PageKind::Scan { img, rotate } => (
                "q 612 0 0 792 0 0 cm /Im0 Do Q".to_owned(),
                Some(Image::Raw(img)),
                *rotate,
            ),
            PageKind::Dct { jpeg, width, height } => (
                "q 612 0 0 792 0 0 cm /Im0 Do Q".to_owned(),
                Some(Image::Jpeg {
                    bytes: jpeg,
                    width: *width,
                    height: *height,
                }),
                0,
            ),
            PageKind::Vector { text } => (vector_ops(text), None, 0),
            PageKind::Text { text } => (format!("BT /F1 24 Tf 72 700 Td ({text}) Tj ET"), None, 0),
            PageKind::TextAndScan { text, img } => (
                format!(
                    "BT /F1 24 Tf 72 740 Td ({text}) Tj ET q 468 0 0 {} 72 100 cm /Im0 Do Q",
                    468 * img.height / img.width
                ),
                Some(Image::Raw(img)),
                0,
            ),
        };
        let xobject = if image.is_some() {
            format!(" /XObject << /Im0 {} 0 R >>", 6 + 3 * i)
        } else {
            String::new()
        };
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Rotate {rotate} /Contents {} 0 R /Resources << /Font << /F1 3 0 R >>{xobject} >> >>",
                5 + 3 * i
            )
            .into_bytes(),
        );
        objects.push(format!("<< /Length {} >>\nstream\n{contents}\nendstream", contents.len()).into_bytes());
        match image {
            Some(img) => {
                let (w, h, filter, data): (usize, usize, &str, &[u8]) = match &img {
                    Image::Raw(g) => (g.width, g.height, "", &g.pixels),
                    Image::Jpeg { bytes, width, height } => (*width, *height, "/Filter /DCTDecode ", bytes),
                };
                let mut obj = format!(
                    "<< /Type /XObject /Subtype /Image /Width {w} /Height {h} /ColorSpace /DeviceGray /BitsPerComponent 8 {filter}/Length {} >>\nstream\n",
                    data.len()
                )
                .into_bytes();
                obj.extend_from_slice(data);
                obj.extend_from_slice(b"\nendstream");
                objects.push(obj);
            }
            None => objects.push(b"<< >>".to_vec()),
        }
    }
    assemble(&objects)
}

/// Rectangles for the lit cells of `text` (cell 6 pt), starting at (72, 600). Three passes of
/// growing darkness (halo, edge, core) soften the stair-steps, which hard squares would leave
/// for the recogniser to trip on.
fn vector_ops(text: &str) -> String {
    let mut cells: Vec<(f32, f32)> = Vec::new();
    let mut x = 72.0f32;
    for c in text.chars() {
        if c == ' ' {
            x += 8.0 * 6.0;
            continue;
        }
        if let Some(g) = glyph(c) {
            for (gy, bits) in g.iter().enumerate() {
                for (gx, b) in bits.bytes().enumerate() {
                    if b == b'1' {
                        // rows go down from the top of the line at 642 pt
                        cells.push((x + gx as f32 * 6.0, 636.0 - gy as f32 * 6.0));
                    }
                }
            }
        }
        x += 6.0 * 6.0;
    }
    let mut ops = String::new();
    for (grow, gray) in [(1.4f32, "0.85"), (0.7, "0.5"), (0.0, "0")] {
        ops.push_str(&format!("{gray} g\n"));
        for (cx, cy) in &cells {
            let (rx, ry, side) = (cx - grow, cy - grow, 6.0 + 2.0 * grow);
            ops.push_str(&format!("{rx} {ry} {side} {side} re f\n"));
        }
    }
    ops
}

fn assemble(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Lower-case, letters and digits only, words joined by one space: the form tests compare.
pub fn words(text: &str) -> String {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>()
        .join(" ")
}
