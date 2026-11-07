//! Decoding, orienting and encoding the images the OCR backends read.

use std::io::Cursor;

use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{DynamicImage, ExtendedColorType, GrayImage, ImageDecoder, ImageEncoder, ImageReader};

use super::OcrError;

/// Decode an image of any enabled format (PNG, JPEG, GIF, BMP, TIFF, WebP): the first frame.
///
/// The dimensions are read from the header and checked against `max_pixels` before any pixel
/// memory is allocated.
pub(super) fn decode(bytes: &[u8], max_pixels: u64) -> Result<DynamicImage, OcrError> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| OcrError::Image(format!("the format cannot be read: {e}")))?;
    let decoder = reader
        .into_decoder()
        .map_err(|e| OcrError::Image(e.to_string()))?;
    let (w, h) = decoder.dimensions();
    check_size(w, h, max_pixels)?;
    DynamicImage::from_decoder(decoder).map_err(|e| OcrError::Image(e.to_string()))
}

/// Refuse an empty image or one over `max_pixels`.
pub(super) fn check_size(width: u32, height: u32, max_pixels: u64) -> Result<(), OcrError> {
    let pixels = u64::from(width) * u64::from(height);
    if pixels == 0 {
        return Err(OcrError::Image("the image has no pixels".to_owned()));
    }
    if pixels > max_pixels {
        return Err(OcrError::Image(format!(
            "the image has {pixels} pixels ({width}x{height}); the limit is {max_pixels}"
        )));
    }
    Ok(())
}

/// Grey pixels of `img`; transparent areas are composited onto white (a transparent pixel has
/// no colour of its own, and black would hide dark text).
fn to_gray(img: &DynamicImage) -> GrayImage {
    if !img.color().has_alpha() {
        return img.to_luma8();
    }
    let la = img.to_luma_alpha8();
    let (w, h) = la.dimensions();
    let mut out = GrayImage::new(w, h);
    for (x, y, p) in la.enumerate_pixels() {
        let [l, a] = p.0;
        let (l, a) = (u16::from(l), u16::from(a));
        // alpha-over-white; the result is at most 255
        let v = (l * a + 255 * (255 - a) + 127) / 255;
        out.put_pixel(x, y, image::Luma([u8::try_from(v).unwrap_or(255)]));
    }
    out
}

/// The grey PNG Tesseract reads.
pub(super) fn to_png(img: &DynamicImage) -> Result<Vec<u8>, OcrError> {
    let gray = to_gray(img);
    let mut out = Vec::new();
    PngEncoder::new_with_quality(&mut out, CompressionType::Fast, FilterType::Sub)
        .write_image(gray.as_raw(), gray.width(), gray.height(), ExtendedColorType::L8)
        .map_err(|e| OcrError::Image(format!("PNG encoding failed: {e}")))?;
    Ok(out)
}

/// Rotate `img` clockwise by `quarters` quarter turns.
pub(super) fn rotate_cw(img: DynamicImage, quarters: u8) -> DynamicImage {
    match quarters % 4 {
        1 => img.rotate90(),
        2 => img.rotate180(),
        3 => img.rotate270(),
        _ => img,
    }
}

/// RGB pixels for the `ocrs` engine (grey, composited like [`to_png`]).
#[cfg(feature = "ocrs")]
pub(super) fn to_rgb(img: &DynamicImage) -> image::RgbImage {
    if img.color().has_alpha() {
        DynamicImage::ImageLuma8(to_gray(img)).to_rgb8()
    } else {
        img.to_rgb8()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use image::{Luma, LumaA};

    #[test]
    fn png_round_trips_and_the_size_limit_is_checked_from_the_header() {
        let mut g = GrayImage::new(40, 30);
        g.put_pixel(3, 4, Luma([200]));
        let png = to_png(&DynamicImage::ImageLuma8(g)).unwrap();
        let back = decode(&png, 10_000).unwrap().to_luma8();
        assert_eq!(back.dimensions(), (40, 30));
        assert_eq!(back.get_pixel(3, 4).0, [200]);
        let err = decode(&png, 1_000).unwrap_err();
        assert!(err.to_string().contains("1200 pixels"), "{err}");
        assert!(decode(b"not an image", 1_000).is_err());
    }

    #[test]
    fn transparent_pixels_become_white() {
        let mut img = image::GrayAlphaImage::new(2, 1);
        img.put_pixel(0, 0, LumaA([0, 0]));
        img.put_pixel(1, 0, LumaA([0, 255]));
        let g = to_gray(&DynamicImage::ImageLumaA8(img));
        assert_eq!(g.get_pixel(0, 0).0, [255]);
        assert_eq!(g.get_pixel(1, 0).0, [0]);
    }

    #[test]
    fn quarter_turns_are_clockwise() {
        let mut g = GrayImage::new(2, 1);
        g.put_pixel(0, 0, Luma([1]));
        g.put_pixel(1, 0, Luma([2]));
        let r = rotate_cw(DynamicImage::ImageLuma8(g.clone()), 1).to_luma8();
        assert_eq!(r.dimensions(), (1, 2));
        assert_eq!((r.get_pixel(0, 0).0, r.get_pixel(0, 1).0), ([1], [2]));
        let r = rotate_cw(DynamicImage::ImageLuma8(g), 3).to_luma8();
        assert_eq!((r.get_pixel(0, 0).0, r.get_pixel(0, 1).0), ([2], [1]));
    }
}
