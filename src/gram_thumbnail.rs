//! Small JPEG previews of Gram image attachments (`gram.get_file` with
//! `thumbnail: {max_px}`), so a phone on a slow link shows an image card from
//! a few kilobytes instead of the whole file.
//!
//! JPEG and PNG sources are decoded (by content, not by the advisory MIME
//! type), scaled down by area averaging so the longer edge is at most
//! `max_px`, turned upright from their EXIF orientation (a JPEG's APP1, a
//! PNG's `eXIf`), and encoded as a baseline JPEG. Transparency is composited
//! over white. Anything else (HEIC, GIF, WebP, a damaged file, an image over
//! [`MAX_SOURCE_PIXELS`]) has no thumbnail; the caller says so and the client
//! falls back to the full file. A render holds the whole source file and
//! image in memory, so at most [`RENDER_PERMITS`] run at once, at most
//! [`MAX_WAITING`] requests wait, and a request for a preview already being
//! rendered waits for that render instead of reading the file again.

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};

use base64::Engine as _;
use zune_jpeg::zune_core::bytestream::ZCursor;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;
use zune_jpeg::JpegDecoder;

use crate::api::schema::{ErrorBody, ResponseResult};
use crate::persist::gram::GramFile;

/// Smallest and largest `max_px` a client may ask for.
pub const MIN_MAX_PX: u32 = 16;
pub const MAX_MAX_PX: u32 = 1024;

/// Largest source image decoded, in pixels: 50 MP is about 150 MB of RGB
/// while it is scaled down.
pub const MAX_SOURCE_PIXELS: u64 = 50_000_000;

/// JPEG quality of the preview. 80 keeps text in a screenshot legible at
/// preview size; a 512 px preview is typically 20-60 KB.
const QUALITY: u8 = 80;

const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// A rendered preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumbnail {
    pub width: u32,
    pub height: u32,
    pub jpeg: Vec<u8>,
}

/// Renders that may hold a source file at once. Each holds the whole
/// attachment (up to 100 MiB) and, while decoding, up to 200 MB of pixels.
pub const RENDER_PERMITS: usize = 1;

/// Requests that may wait for a render, their own or one of the same preview
/// already under way. One more answers `busy`.
pub const MAX_WAITING: usize = 16;

static RENDERER: Renderer = Renderer::new(RENDER_PERMITS);

/// Renders `source` (a whole image file) as a JPEG whose longer edge is at
/// most `max_px`. A smaller image keeps its size. `Err` says why there is no
/// thumbnail.
pub fn render(source: &[u8], max_px: u32) -> Result<Thumbnail, String> {
    let (image, orientation) = if source.starts_with(JPEG_MAGIC) {
        decode_jpeg(source, max_px)?
    } else if source.starts_with(PNG_MAGIC) {
        (decode_png(source, max_px)?, png_orientation(source))
    } else {
        return Err("only JPEG and PNG images have thumbnails".into());
    };
    let image = orient(image, orientation);
    let jpeg = encode_jpeg(&image)?;
    Ok(Thumbnail {
        width: image.width,
        height: image.height,
        jpeg,
    })
}

/// The `gram.get_file {thumbnail}` result for the attachment `file`: its
/// cached preview at `max_px` (clamped to [`MIN_MAX_PX`]..=[`MAX_MAX_PX`]),
/// or one rendered from the bytes `load` returns, read only once the render
/// is admitted. `cache` keeps a rendered preview for next time. Errors are
/// `thumbnail_unavailable` (the attachment has no preview; fetch the file),
/// `busy` (too many renders wait; retry) or `gram_file_error`.
pub(crate) fn file_thumbnail<S: AsRef<[u8]>>(
    file: &GramFile,
    max_px: u32,
    load: impl FnOnce() -> io::Result<S>,
    cache: bool,
) -> Result<ResponseResult, ErrorBody> {
    file_thumbnail_with(&RENDERER, file, max_px, load, cache)
}

fn file_thumbnail_with<S: AsRef<[u8]>>(
    renderer: &Renderer,
    file: &GramFile,
    max_px: u32,
    load: impl FnOnce() -> io::Result<S>,
    cache: bool,
) -> Result<ResponseResult, ErrorBody> {
    let max_px = max_px.clamp(MIN_MAX_PX, MAX_MAX_PX);
    let cached = cache
        .then(|| crate::persist::gram_thumbs::get(&file.sha256, max_px))
        .flatten()
        .and_then(|jpeg| {
            let (width, height) = jpeg_size(&jpeg)?;
            Some(Thumbnail {
                width,
                height,
                jpeg,
            })
        });
    let thumbnail = match cached {
        Some(thumbnail) => thumbnail,
        None => renderer.run((file.sha256.clone(), max_px), || {
            // Taken before the read: once the attachment is deleted, what
            // this render read can no longer be cached.
            let lease = cache.then(|| crate::persist::gram_thumbs::lease(&file.sha256));
            let source = load().map_err(|err| {
                Failure::Unread(ErrorBody {
                    code: "gram_file_error".into(),
                    message: format!("failed to read file: {err}"),
                })
            })?;
            let rendered = render(source.as_ref(), max_px);
            // Freed before the permit, so the next render's read never
            // overlaps it.
            drop(source);
            let thumbnail = rendered.map_err(|message| {
                Failure::Refused(ErrorBody {
                    code: "thumbnail_unavailable".into(),
                    message,
                })
            })?;
            if let Some(lease) = lease {
                lease.put(max_px, &thumbnail.jpeg);
            }
            Ok(thumbnail)
        })?,
    };
    Ok(ResponseResult::GramFileThumbnail {
        name: file.name.clone(),
        mime: file.mime.clone(),
        size: file.size,
        sha256: file.sha256.clone(),
        width: thumbnail.width,
        height: thumbnail.height,
        thumbnail_size: thumbnail.jpeg.len() as u64,
        data_base64: base64::engine::general_purpose::STANDARD.encode(&thumbnail.jpeg),
    })
}

fn busy() -> ErrorBody {
    ErrorBody {
        code: "busy".into(),
        message: "too many thumbnails are waiting to render; retry shortly".into(),
    }
}

/// Why a render has no thumbnail.
#[derive(Debug, Clone)]
enum Failure {
    /// The requester's own copy of the source could not be read (its
    /// message was deleted, say). Requests sharing the render read their own.
    Unread(ErrorBody),
    /// The bytes have no thumbnail: true for every request of this content.
    Refused(ErrorBody),
}

impl Failure {
    fn into_body(self) -> ErrorBody {
        match self {
            Self::Unread(body) | Self::Refused(body) => body,
        }
    }
}

type Rendered = Result<Thumbnail, Failure>;

/// Admission to rendering: `permits` renders at once, [`MAX_WAITING`]
/// requests waiting, and one render per preview.
struct Renderer {
    permits: usize,
    admission: Mutex<Admission>,
    /// Signalled when a render finishes.
    finished: Condvar,
}

struct Admission {
    running: usize,
    waiting: usize,
    /// Renders running or waiting for a permit, by `(sha256, max_px)`, each
    /// with its result once it has one.
    renders: BTreeMap<(String, u32), Arc<OnceLock<Rendered>>>,
}

impl Renderer {
    const fn new(permits: usize) -> Self {
        Self {
            permits,
            admission: Mutex::new(Admission {
                running: 0,
                waiting: 0,
                renders: BTreeMap::new(),
            }),
            finished: Condvar::new(),
        }
    }

    fn admission(&self) -> MutexGuard<'_, Admission> {
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The preview `key` names: the result of its render already under way,
    /// or of `render` once a permit is free. `busy`, without waiting, when
    /// [`MAX_WAITING`] requests already wait. A shared render that could not
    /// read its requester's source is not taken as this request's answer:
    /// it renders once more from its own source, without joining again.
    fn run(
        &self,
        key: (String, u32),
        render: impl FnOnce() -> Rendered,
    ) -> Result<Thumbnail, ErrorBody> {
        let mut admission = self.admission();
        if let Some(result) = admission.renders.get(&key).cloned() {
            if admission.waiting >= MAX_WAITING {
                return Err(busy());
            }
            admission.waiting += 1;
            let rendered = loop {
                if let Some(rendered) = result.get() {
                    break rendered.clone();
                }
                admission = self
                    .finished
                    .wait(admission)
                    .unwrap_or_else(PoisonError::into_inner);
            };
            admission.waiting -= 1;
            match rendered {
                Err(Failure::Unread(_)) => {}
                rendered => return rendered.map_err(Failure::into_body),
            }
        }
        if admission.running >= self.permits && admission.waiting >= MAX_WAITING {
            return Err(busy());
        }
        // Registered for others to join unless a render of `key` already
        // is: only after one that could not read its source.
        let result = Arc::<OnceLock<Rendered>>::default();
        admission
            .renders
            .entry(key.clone())
            .or_insert_with(|| Arc::clone(&result));
        if admission.running >= self.permits {
            admission.waiting += 1;
            admission = self
                .finished
                .wait_while(admission, |admission| admission.running >= self.permits)
                .unwrap_or_else(PoisonError::into_inner);
            admission.waiting -= 1;
        }
        admission.running += 1;
        drop(admission);
        let running = Running {
            renderer: self,
            key,
            result,
        };
        let rendered = render();
        let _ = running.result.set(rendered.clone());
        rendered.map_err(Failure::into_body)
    }
}

/// A render holding a permit, which it gives back when dropped, also when
/// the render panicked.
struct Running<'a> {
    renderer: &'a Renderer,
    key: (String, u32),
    result: Arc<OnceLock<Rendered>>,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut admission = self.renderer.admission();
        admission.running -= 1;
        if admission
            .renders
            .get(&self.key)
            .is_some_and(|registered| Arc::ptr_eq(registered, &self.result))
        {
            admission.renders.remove(&self.key);
        }
        // Only lands when the render panicked: its waiters get an answer.
        let _ = self.result.set(Err(Failure::Refused(ErrorBody {
            code: "thumbnail_unavailable".into(),
            message: "the thumbnail render failed".into(),
        })));
        self.renderer.finished.notify_all();
    }
}

/// The pixel size of a JPEG this module wrote, read from its header.
pub fn jpeg_size(jpeg: &[u8]) -> Option<(u32, u32)> {
    let mut decoder = JpegDecoder::new(ZCursor::new(jpeg));
    decoder.decode_headers().ok()?;
    let (width, height) = decoder.dimensions()?;
    Some((u32::try_from(width).ok()?, u32::try_from(height).ok()?))
}

/// Tightly packed 8-bit RGB.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rgb {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

fn check_size(width: u64, height: u64) -> Result<(), String> {
    if width == 0 || height == 0 {
        return Err("the image is empty".into());
    }
    if width * height > MAX_SOURCE_PIXELS {
        return Err(format!(
            "the image is {width}x{height}, over the {MAX_SOURCE_PIXELS}-pixel thumbnail limit"
        ));
    }
    Ok(())
}

fn decode_jpeg(source: &[u8], max_px: u32) -> Result<(Rgb, u8), String> {
    // Only the pixel count is limited (`check_size`), not either edge: the
    // decoder's default 16384 would refuse a 20000x2000 panorama.
    let options = DecoderOptions::default()
        .jpeg_set_out_colorspace(ColorSpace::RGB)
        .set_max_width(usize::from(u16::MAX))
        .set_max_height(usize::from(u16::MAX));
    let mut decoder = JpegDecoder::new_with_options(ZCursor::new(source), options);
    decoder
        .decode_headers()
        .map_err(|err| format!("unreadable JPEG: {err:?}"))?;
    let (width, height) = decoder
        .dimensions()
        .ok_or_else(|| "unreadable JPEG: no frame header".to_string())?;
    check_size(width as u64, height as u64)?;
    let orientation = decoder.exif().map_or(1, |exif| exif_orientation(exif));
    let pixels = decoder
        .decode()
        .map_err(|err| format!("unreadable JPEG: {err:?}"))?;
    let image = downscale(width, height, 3, &pixels, max_px, |px| {
        [px[0], px[1], px[2]]
    });
    Ok((image, orientation))
}

fn decode_png(source: &[u8], max_px: u32) -> Result<Rgb, String> {
    let mut decoder = png::Decoder::new_with_limits(
        Cursor::new(source),
        png::Limits {
            // Four 8-bit channels at the pixel limit.
            bytes: (MAX_SOURCE_PIXELS * 4) as usize,
        },
    );
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|err| format!("unreadable PNG: {err}"))?;
    let (width, height) = {
        let info = reader.info();
        (info.width, info.height)
    };
    check_size(u64::from(width), u64::from(height))?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let frame = reader
        .next_frame(&mut buffer)
        .map_err(|err| format!("unreadable PNG: {err}"))?;
    buffer.truncate(frame.buffer_size());
    let (width, height) = (frame.width as usize, frame.height as usize);
    // After EXPAND and STRIP_16 every sample is 8 bits; transparency is
    // composited over white.
    let over_white = |value: u8, alpha: u8| -> u8 {
        let (value, alpha) = (u32::from(value), u32::from(alpha));
        ((value * alpha + 255 * (255 - alpha) + 127) / 255) as u8
    };
    let image = match frame.color_type {
        png::ColorType::Rgb => downscale(width, height, 3, &buffer, max_px, |px| {
            [px[0], px[1], px[2]]
        }),
        png::ColorType::Rgba => downscale(width, height, 4, &buffer, max_px, |px| {
            [
                over_white(px[0], px[3]),
                over_white(px[1], px[3]),
                over_white(px[2], px[3]),
            ]
        }),
        png::ColorType::Grayscale => downscale(width, height, 1, &buffer, max_px, |px| [px[0]; 3]),
        png::ColorType::GrayscaleAlpha => downscale(width, height, 2, &buffer, max_px, |px| {
            [over_white(px[0], px[1]); 3]
        }),
        png::ColorType::Indexed => return Err("unreadable PNG: palette not expanded".into()),
    };
    Ok(image)
}

/// The output size for a `width`x`height` source: the longer edge becomes
/// `max_px` (never larger than the source), the other keeps the aspect ratio.
fn target_size(width: usize, height: usize, max_px: u32) -> (usize, usize) {
    let max_px = max_px as usize;
    let longer = width.max(height);
    if longer <= max_px {
        return (width, height);
    }
    let scale = |edge: usize| ((edge * max_px + longer / 2) / longer).max(1);
    (scale(width), scale(height))
}

/// Area-average downscale of `channels`-byte pixels to RGB: each output pixel
/// is the mean of the source pixels its cell covers, after `to_rgb`.
fn downscale(
    width: usize,
    height: usize,
    channels: usize,
    pixels: &[u8],
    max_px: u32,
    to_rgb: impl Fn(&[u8]) -> [u8; 3],
) -> Rgb {
    let (out_width, out_height) = target_size(width, height, max_px);
    // The source columns each output column covers: [starts[x], starts[x + 1]).
    let starts: Vec<usize> = (0..=out_width).map(|x| x * width / out_width).collect();
    let stride = width * channels;
    let mut out = Vec::with_capacity(out_width * out_height * 3);
    let mut sums = vec![0u64; out_width * 3];
    for out_y in 0..out_height {
        let (top, bottom) = (
            out_y * height / out_height,
            (out_y + 1) * height / out_height,
        );
        sums.fill(0);
        for row in pixels[top * stride..bottom * stride].chunks_exact(stride) {
            for out_x in 0..out_width {
                let cell = &mut sums[out_x * 3..out_x * 3 + 3];
                let span = &row[starts[out_x] * channels..starts[out_x + 1] * channels];
                for px in span.chunks_exact(channels) {
                    let [r, g, b] = to_rgb(px);
                    cell[0] += u64::from(r);
                    cell[1] += u64::from(g);
                    cell[2] += u64::from(b);
                }
            }
        }
        let rows = (bottom - top) as u64;
        for out_x in 0..out_width {
            let count = rows * (starts[out_x + 1] - starts[out_x]) as u64;
            for sum in &sums[out_x * 3..out_x * 3 + 3] {
                out.push(((sum + count / 2) / count) as u8);
            }
        }
    }
    Rgb {
        width: out_width as u32,
        height: out_height as u32,
        pixels: out,
    }
}

/// The EXIF orientation in a PNG's `eXIf` chunk, 1 without one. Every chunk
/// up to `IEND` is looked at, since writers put `eXIf` before or after the
/// image data.
fn png_orientation(png: &[u8]) -> u8 {
    let mut at = PNG_MAGIC.len();
    while let Some(header) = png.get(at..at + 8) {
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(data) = png.get(at + 8..).and_then(|rest| rest.get(..len)) else {
            break;
        };
        match &header[4..] {
            b"eXIf" => return exif_orientation(data),
            b"IEND" => break,
            // Length, type, data, CRC.
            _ => at += 8 + len + 4,
        }
    }
    1
}

/// EXIF orientation (tag 0x0112 in IFD0), 1 when absent or unreadable.
/// `exif` starts at the TIFF header (optionally behind `Exif\0\0`).
fn exif_orientation(exif: &[u8]) -> u8 {
    let tiff = exif.strip_prefix(b"Exif\0\0").unwrap_or(exif);
    let little = match tiff.get(..2) {
        Some(b"II") => true,
        Some(b"MM") => false,
        _ => return 1,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let bytes: [u8; 2] = tiff.get(at..at + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let bytes: [u8; 4] = tiff.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    };
    let find = || -> Option<u8> {
        if u16_at(2)? != 42 {
            return None;
        }
        let ifd = u32_at(4)? as usize;
        let entries = u16_at(ifd)? as usize;
        (0..entries).find_map(|index| {
            let entry = ifd + 2 + index * 12;
            // SHORT (type 3), one value, stored in the first two value bytes.
            (u16_at(entry)? == 0x0112 && u16_at(entry + 2)? == 3)
                .then(|| u16_at(entry + 8))
                .flatten()
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| (1..=8).contains(value))
        })
    };
    find().unwrap_or(1)
}

/// Turns `image` upright for EXIF `orientation` (1-8).
fn orient(image: Rgb, orientation: u8) -> Rgb {
    if !(2..=8).contains(&orientation) {
        return image;
    }
    let (w, h) = (image.width as usize, image.height as usize);
    let swaps = orientation >= 5;
    let (out_w, out_h) = if swaps { (h, w) } else { (w, h) };
    let mut pixels = Vec::with_capacity(image.pixels.len());
    for dy in 0..out_h {
        for dx in 0..out_w {
            let (sx, sy) = match orientation {
                2 => (w - 1 - dx, dy),
                3 => (w - 1 - dx, h - 1 - dy),
                4 => (dx, h - 1 - dy),
                5 => (dy, dx),
                6 => (dy, h - 1 - dx),
                7 => (w - 1 - dy, h - 1 - dx),
                _ => (w - 1 - dy, dx),
            };
            let at = (sy * w + sx) * 3;
            pixels.extend_from_slice(&image.pixels[at..at + 3]);
        }
    }
    Rgb {
        width: out_w as u32,
        height: out_h as u32,
        pixels,
    }
}

fn encode_jpeg(image: &Rgb) -> Result<Vec<u8>, String> {
    let mut jpeg = Vec::new();
    let encoder = jpeg_encoder::Encoder::new(&mut jpeg, QUALITY);
    // `max_px` caps both edges well inside a JPEG's 65535.
    encoder
        .encode(
            &image.pixels,
            image.width as u16,
            image.height as u16,
            jpeg_encoder::ColorType::Rgb,
        )
        .map_err(|err| format!("could not encode the thumbnail: {err}"))?;
    Ok(jpeg)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A `width`x`height` RGB image: the left half red, the right half blue.
    pub(crate) fn split_rgb(width: u32, height: u32) -> Vec<u8> {
        (0..height)
            .flat_map(|_| {
                (0..width).flat_map(move |x| {
                    if x < width / 2 {
                        [255, 0, 0]
                    } else {
                        [0, 0, 255]
                    }
                })
            })
            .collect()
    }

    pub(crate) fn jpeg_of(width: u32, height: u32) -> Vec<u8> {
        encode_jpeg(&Rgb {
            width,
            height,
            pixels: split_rgb(width, height),
        })
        .unwrap()
    }

    fn png_of(width: u32, height: u32, color: png::ColorType, pixels: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(color);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(pixels).unwrap();
        writer.finish().unwrap();
        bytes
    }

    fn decode(jpeg: &[u8]) -> (usize, usize, Vec<u8>) {
        let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);
        let mut decoder = JpegDecoder::new_with_options(ZCursor::new(jpeg), options);
        let pixels = decoder.decode().unwrap();
        let (width, height) = decoder.dimensions().unwrap();
        (width, height, pixels)
    }

    fn pixel(image: &(usize, usize, Vec<u8>), x: usize, y: usize) -> [u8; 3] {
        let at = (y * image.0 + x) * 3;
        [image.2[at], image.2[at + 1], image.2[at + 2]]
    }

    fn near(actual: [u8; 3], expected: [u8; 3]) -> bool {
        actual
            .iter()
            .zip(expected)
            .all(|(&a, e)| (i16::from(a) - i16::from(e)).abs() <= 24)
    }

    #[test]
    fn a_large_jpeg_shrinks_to_max_px_keeping_its_aspect_and_colors() {
        let source = jpeg_of(1600, 1200);
        let thumbnail = render(&source, 320).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (320, 240));
        assert!(thumbnail.jpeg.len() < source.len() / 4);
        assert_eq!(jpeg_size(&thumbnail.jpeg), Some((320, 240)));
        let image = decode(&thumbnail.jpeg);
        assert!(
            near(pixel(&image, 40, 120), [255, 0, 0]),
            "{:?}",
            pixel(&image, 40, 120)
        );
        assert!(
            near(pixel(&image, 280, 120), [0, 0, 255]),
            "{:?}",
            pixel(&image, 280, 120)
        );
    }

    #[test]
    fn a_small_image_keeps_its_size() {
        let thumbnail = render(&jpeg_of(100, 60), 320).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (100, 60));
    }

    #[test]
    fn a_png_with_transparency_lands_on_white() {
        // Left half opaque green, right half fully transparent.
        let (width, height) = (400u32, 100u32);
        let pixels: Vec<u8> = (0..height)
            .flat_map(|_| {
                (0..width).flat_map(move |x| {
                    if x < width / 2 {
                        [0, 255, 0, 255]
                    } else {
                        [0, 0, 0, 0]
                    }
                })
            })
            .collect();
        let source = png_of(width, height, png::ColorType::Rgba, &pixels);
        let thumbnail = render(&source, 100).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (100, 25));
        let image = decode(&thumbnail.jpeg);
        assert!(
            near(pixel(&image, 10, 12), [0, 255, 0]),
            "{:?}",
            pixel(&image, 10, 12)
        );
        assert!(
            near(pixel(&image, 90, 12), [255, 255, 255]),
            "{:?}",
            pixel(&image, 90, 12)
        );
    }

    #[test]
    fn a_grayscale_png_renders() {
        let source = png_of(64, 64, png::ColorType::Grayscale, &[128; 64 * 64]);
        let image = decode(&render(&source, 32).unwrap().jpeg);
        assert_eq!((image.0, image.1), (32, 32));
        assert!(near(pixel(&image, 16, 16), [128, 128, 128]));
    }

    #[test]
    fn other_formats_and_damaged_files_have_no_thumbnail() {
        assert!(render(b"GIF89a....", 64).is_err());
        assert!(render(b"\0\0\0\x18ftypheic", 64).is_err());
        let mut truncated = jpeg_of(64, 64);
        truncated.truncate(40);
        assert!(render(&truncated, 64).is_err());
    }

    /// A TIFF header with one IFD0 entry: orientation `value`.
    fn exif(little: bool, value: u16) -> Vec<u8> {
        let u16b = |v: u16| {
            if little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        let u32b = |v: u32| {
            if little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        };
        let mut tiff = Vec::new();
        tiff.extend_from_slice(if little { b"II" } else { b"MM" });
        tiff.extend_from_slice(&u16b(42));
        tiff.extend_from_slice(&u32b(8));
        tiff.extend_from_slice(&u16b(1));
        tiff.extend_from_slice(&u16b(0x0112));
        tiff.extend_from_slice(&u16b(3));
        tiff.extend_from_slice(&u32b(1));
        tiff.extend_from_slice(&u16b(value));
        tiff.extend_from_slice(&[0, 0]);
        tiff.extend_from_slice(&u32b(0));
        tiff
    }

    #[test]
    fn exif_orientation_reads_either_byte_order() {
        assert_eq!(exif_orientation(&exif(true, 6)), 6);
        assert_eq!(exif_orientation(&exif(false, 8)), 8);
        let mut prefixed = b"Exif\0\0".to_vec();
        prefixed.extend(exif(true, 3));
        assert_eq!(exif_orientation(&prefixed), 3);
        assert_eq!(exif_orientation(&exif(true, 0)), 1);
        assert_eq!(exif_orientation(b"junk"), 1);
    }

    /// A JPEG with an APP1 EXIF segment saying `orientation`.
    fn jpeg_with_orientation(width: u32, height: u32, orientation: u16) -> Vec<u8> {
        let plain = jpeg_of(width, height);
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend(exif(false, orientation));
        let mut jpeg = plain[..2].to_vec();
        jpeg.extend_from_slice(&[0xFF, 0xE1]);
        jpeg.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        jpeg.extend(payload);
        jpeg.extend_from_slice(&plain[2..]);
        jpeg
    }

    #[test]
    fn a_rotated_photo_comes_out_upright() {
        // Stored 200x100 (red left, blue right); orientation 6 = rotate 90
        // degrees clockwise to display, so red ends up on top.
        let thumbnail = render(&jpeg_with_orientation(200, 100, 6), 100).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (50, 100));
        let image = decode(&thumbnail.jpeg);
        assert!(
            near(pixel(&image, 25, 10), [255, 0, 0]),
            "{:?}",
            pixel(&image, 25, 10)
        );
        assert!(
            near(pixel(&image, 25, 90), [0, 0, 255]),
            "{:?}",
            pixel(&image, 25, 90)
        );
        // Orientation 8 (90 degrees counter-clockwise): red at the bottom.
        let image = decode(
            &render(&jpeg_with_orientation(200, 100, 8), 100)
                .unwrap()
                .jpeg,
        );
        assert!(
            near(pixel(&image, 25, 90), [255, 0, 0]),
            "{:?}",
            pixel(&image, 25, 90)
        );
    }

    #[test]
    fn orient_maps_every_orientation() {
        // 2x1: pixel A then pixel B.
        let image = Rgb {
            width: 2,
            height: 1,
            pixels: vec![1, 1, 1, 2, 2, 2],
        };
        let cases = [
            (1, 2, 1, vec![1, 2]),
            (2, 2, 1, vec![2, 1]),
            (3, 2, 1, vec![2, 1]),
            (4, 2, 1, vec![1, 2]),
            (5, 1, 2, vec![1, 2]),
            (6, 1, 2, vec![1, 2]),
            (7, 1, 2, vec![2, 1]),
            (8, 1, 2, vec![2, 1]),
        ];
        for (orientation, width, height, order) in cases {
            let out = orient(image.clone(), orientation);
            assert_eq!(
                (out.width, out.height),
                (width, height),
                "orientation {orientation}"
            );
            let firsts: Vec<u8> = out.pixels.chunks(3).map(|px| px[0]).collect();
            assert_eq!(firsts, order, "orientation {orientation}");
        }
    }

    #[test]
    fn target_size_caps_the_longer_edge() {
        assert_eq!(target_size(4000, 3000, 512), (512, 384));
        assert_eq!(target_size(1170, 2532, 512), (237, 512));
        assert_eq!(target_size(10000, 3, 100), (100, 1));
        assert_eq!(target_size(300, 200, 512), (300, 200));
    }

    /// A baseline grayscale JPEG of `width`x`height`, mid-gray: every 8x8
    /// block is DC-only, two zero bits under one-code Huffman tables. Cheap
    /// at any size, where encoding a real image of 40 MP takes seconds.
    fn gray_jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut jpeg = vec![0xFF, 0xD8];
        // DQT: table 0, all ones.
        jpeg.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
        jpeg.extend_from_slice(&[1; 64]);
        // SOF0: 8-bit, one component (id 1, 1x1 sampling, table 0).
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
        jpeg.extend_from_slice(&height.to_be_bytes());
        jpeg.extend_from_slice(&width.to_be_bytes());
        jpeg.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
        // DHT: DC table 0, then AC table 0, each one 1-bit code for symbol 0
        // (DC difference 0; end of block).
        for class in [0x00, 0x10] {
            jpeg.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x14, class, 1]);
            jpeg.extend_from_slice(&[0; 16]);
        }
        // SOS: the one component, tables 0 and 0, coefficients 0..=63.
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        let blocks = usize::from(width).div_ceil(8) * usize::from(height).div_ceil(8);
        jpeg.resize(jpeg.len() + (blocks * 2).div_ceil(8), 0);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        jpeg
    }

    #[test]
    fn a_panorama_wider_than_16384_px_renders_under_the_pixel_limit() {
        let thumbnail = render(&gray_jpeg(20_000, 2_000), 256).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (256, 26));
        let image = decode(&thumbnail.jpeg);
        assert!(near(pixel(&image, 128, 13), [128, 128, 128]));
        // 52 MP: refused from the header, before decoding.
        let err = render(&gray_jpeg(20_000, 2_600), 256).unwrap_err();
        assert!(err.contains("50000000-pixel thumbnail limit"), "{err}");
    }

    #[test]
    fn a_png_turned_by_its_exif_comes_out_upright() {
        // Stored 200x100 (red left, blue right), its eXIf chunk saying
        // orientation 6: rotate 90 degrees clockwise, so red ends up on top.
        let (width, height) = (200, 100);
        let mut source = Vec::new();
        let mut encoder = png::Encoder::new(&mut source, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer
            .write_chunk(png::chunk::eXIf, &exif(true, 6))
            .unwrap();
        writer.write_image_data(&split_rgb(width, height)).unwrap();
        writer.finish().unwrap();
        assert_eq!(png_orientation(&source), 6);
        let thumbnail = render(&source, 100).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (50, 100));
        let image = decode(&thumbnail.jpeg);
        assert!(
            near(pixel(&image, 25, 10), [255, 0, 0]),
            "{:?}",
            pixel(&image, 25, 10)
        );
        assert!(
            near(pixel(&image, 25, 90), [0, 0, 255]),
            "{:?}",
            pixel(&image, 25, 90)
        );
        // No eXIf, or a damaged chunk list: as stored.
        assert_eq!(
            png_orientation(&png_of(2, 2, png::ColorType::Grayscale, &[0; 4])),
            1
        );
        assert_eq!(png_orientation(&source[..40]), 1);
    }

    fn image_file(sha256: &str, mime: &str) -> GramFile {
        GramFile {
            name: "image".into(),
            size: 0,
            mime: mime.into(),
            sha256: sha256.into(),
        }
    }

    #[test]
    fn an_image_is_known_by_its_content_not_its_mime() {
        let renderer = Renderer::new(1);
        let png = png_of(64, 32, png::ColorType::Rgb, &split_rgb(64, 32));
        for (kind, source) in [("JPEG", jpeg_of(64, 32)), ("PNG", png)] {
            for mime in ["", "application/octet-stream"] {
                let file = image_file(&"a".repeat(64), mime);
                let reply = file_thumbnail_with(&renderer, &file, 32, || Ok(source.clone()), false);
                assert!(
                    matches!(
                        reply,
                        Ok(ResponseResult::GramFileThumbnail {
                            width: 32,
                            height: 16,
                            ..
                        })
                    ),
                    "{kind} as {mime:?}: {reply:?}"
                );
            }
        }
    }

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Source bytes that count how many are alive.
    struct Counted {
        bytes: Vec<u8>,
        alive: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for Counted {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.alive.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn cold_requests_hold_no_more_sources_than_permits() {
        let renderer = Renderer::new(2);
        let source = jpeg_of(64, 64);
        let alive = Arc::new(AtomicUsize::new(0));
        let most = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for n in 0..8 {
                let (renderer, source, alive, most) = (&renderer, &source, &alive, &most);
                scope.spawn(move || {
                    let load = || {
                        let now = alive.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        // Long enough for every other request to come in.
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        Ok(Counted {
                            bytes: source.clone(),
                            alive: Arc::clone(alive),
                        })
                    };
                    let file = image_file(&format!("{n:064}"), "image/jpeg");
                    let reply = file_thumbnail_with(renderer, &file, 32, load, false);
                    assert!(reply.is_ok(), "{reply:?}");
                });
            }
        });
        assert_eq!(alive.load(Ordering::SeqCst), 0);
        let most = most.load(Ordering::SeqCst);
        assert!(most <= 2, "{most} sources held at once");
    }

    #[test]
    fn requests_for_one_preview_share_one_render() {
        let renderer = Renderer::new(1);
        let source = jpeg_of(64, 64);
        let loads = AtomicUsize::new(0);
        let others = 5;
        let replies: Vec<_> = std::thread::scope(|scope| {
            let (renderer, source, loads) = (&renderer, &source, &loads);
            let requests: Vec<_> = (0..=others)
                .map(|_| {
                    scope.spawn(move || {
                        let load = || {
                            if loads.fetch_add(1, Ordering::SeqCst) == 0 {
                                wait_until("the other requests wait", || {
                                    renderer.admission().waiting == others
                                });
                            }
                            Ok(source.clone())
                        };
                        let file = image_file(&"b".repeat(64), "image/jpeg");
                        file_thumbnail_with(renderer, &file, 32, load, false)
                    })
                })
                .collect();
            requests
                .into_iter()
                .map(|request| request.join().unwrap())
                .collect()
        });
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert!(replies[0].is_ok(), "{:?}", replies[0]);
        assert!(replies.iter().all(|reply| *reply == replies[0]));
    }

    #[test]
    fn requests_past_the_waiting_limit_are_busy() {
        let renderer = Renderer::new(1);
        let source = jpeg_of(64, 64);
        let (release, released) = std::sync::mpsc::channel::<()>();
        let released = Mutex::new(released);
        let request = |key: String| {
            let load = || {
                // Until the sender is dropped.
                let _ = released.lock().unwrap().recv();
                Ok(source.clone())
            };
            file_thumbnail_with(&renderer, &image_file(&key, "image/jpeg"), 32, load, false)
        };
        let refused = |key: String| {
            let load = || -> io::Result<Vec<u8>> { panic!("a refused request reads nothing") };
            file_thumbnail_with(&renderer, &image_file(&key, "image/jpeg"), 32, load, false)
        };
        std::thread::scope(|scope| {
            // Owned here, so a failed assertion releases the renders too and
            // the scope can join them.
            let release = release;
            let running = scope.spawn(|| request("running".into()));
            wait_until("one render runs", || renderer.admission().running == 1);
            let waiting: Vec<_> = (0..MAX_WAITING)
                .map(|n| scope.spawn(move || request(format!("waiting-{n}"))))
                .collect();
            wait_until("the queue fills", || {
                renderer.admission().waiting == MAX_WAITING
            });
            for key in ["one more", "running"] {
                let reply = refused(key.into());
                assert_eq!(reply.unwrap_err().code, "busy", "{key}");
            }
            drop(release);
            assert!(running.join().unwrap().is_ok());
            for request in waiting {
                assert!(request.join().unwrap().is_ok());
            }
        });
    }

    #[test]
    fn a_request_sharing_a_render_reads_its_own_source_when_that_render_could_not() {
        let renderer = Renderer::new(1);
        let source = jpeg_of(64, 64);
        let file = image_file(&"c".repeat(64), "image/jpeg");
        let (deleted, kept) = std::thread::scope(|scope| {
            let (renderer, source, file) = (&renderer, &source, &file);
            let deleted = scope.spawn(move || {
                let load = || -> io::Result<Vec<u8>> {
                    wait_until("the kept message's request joins", || {
                        renderer.admission().waiting == 1
                    });
                    Err(io::Error::new(io::ErrorKind::NotFound, "message deleted"))
                };
                file_thumbnail_with(renderer, file, 32, load, false)
            });
            wait_until("the deleted message's render runs", || {
                renderer.admission().running == 1
            });
            let kept = scope.spawn(move || {
                file_thumbnail_with(renderer, file, 32, || Ok(source.clone()), false)
            });
            (deleted.join().unwrap(), kept.join().unwrap())
        });
        let error = deleted.expect_err("the deleted message has no source");
        assert_eq!(error.code, "gram_file_error", "{error:?}");
        assert!(kept.is_ok(), "{kept:?}");
        let admission = renderer.admission();
        assert_eq!((admission.running, admission.waiting), (0, 0));
        assert!(admission.renders.is_empty());
    }
}
