//! V4L2 camera capture. Produces an RGB8 frame suitable for the pipeline.

use crate::bio_err;
use aegyra_common::Result;
use image::{ImageBuffer, Rgb};
use v4l::buffer::Type;
use v4l::io::mmap::Stream;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture;
use v4l::{Device, FourCC};

pub type Frame = ImageBuffer<Rgb<u8>, Vec<u8>>;
pub type IrFrame = ImageBuffer<image::Luma<u8>, Vec<u8>>;

pub const DEFAULT_DEVICE: &str = "/dev/video0";
/// Companion IR sensor on Windows-Hello-style laptops. Typically 8-bit
/// greyscale (`GREY` FourCC) paired with an active NIR (~850 nm)
/// illuminator that fires whenever the device is opened. ASUS / Lenovo /
/// HP use /dev/video2 conventionally (video0/1 are the dual-node RGB cam).
pub const DEFAULT_IR_DEVICE: &str = "/dev/video2";
const CAPTURE_WIDTH: u32 = 640;
const CAPTURE_HEIGHT: u32 = 480;
const IR_CAPTURE_WIDTH: u32 = 640;
const IR_CAPTURE_HEIGHT: u32 = 400;

/// Frames to capture-and-discard before the real one. UVC sensors ramp
/// auto-exposure and auto-gain over the first ~8–15 frames after a
/// format change; grabbing frame 0 gives a shot mid-ramp, which for IR
/// makes intensity vary 3× at constant distance. 8 frames at 15 fps
/// (IR) ≈ 530 ms; at 30 fps (RGB) ≈ 270 ms. Tuned against Ben's ASUS
/// WBF rig, 2026-04-15: halved IR FRR.
const AE_WARMUP_FRAMES: usize = 5;

/// Capture a single frame from the default camera. Blocks until one frame
/// is delivered or the device errors out.
pub fn capture_frame() -> Result<Frame> {
    capture_from(DEFAULT_DEVICE)
}

/// Capture a single frame from the default IR companion sensor. Returns
/// `Ok(None)` (not an error) if the device is absent — laptops without a
/// Windows-Hello-class IR camera are supported, the IR signal just never
/// contributes.
pub fn capture_ir_frame() -> Result<Option<IrFrame>> {
    if !std::path::Path::new(DEFAULT_IR_DEVICE).exists() {
        return Ok(None);
    }
    capture_ir_from(DEFAULT_IR_DEVICE).map(Some)
}

pub fn capture_ir_from(path: &str) -> Result<IrFrame> {
    let dev = Device::with_path(path).map_err(|e| bio_err(format!("open {path}: {e}")))?;

    let mut fmt = dev.format().map_err(|e| bio_err(format!("get format: {e}")))?;
    fmt.width = IR_CAPTURE_WIDTH;
    fmt.height = IR_CAPTURE_HEIGHT;
    fmt.fourcc = FourCC::new(b"GREY");
    let fmt = dev
        .set_format(&fmt)
        .map_err(|e| bio_err(format!("set format: {e}")))?;

    let mut stream = Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| bio_err(format!("stream init: {e}")))?;
    // AE warmup — see notes on AE_WARMUP_FRAMES.
    for _ in 0..AE_WARMUP_FRAMES {
        stream
            .next()
            .map_err(|e| bio_err(format!("IR warmup: {e}")))?;
    }
    let (buf, _meta) = stream
        .next()
        .map_err(|e| bio_err(format!("stream next: {e}")))?;

    if &fmt.fourcc.repr != b"GREY" {
        return Err(bio_err(format!(
            "unexpected IR pixel format: {:?}",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("?")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    let expected = (w * h) as usize;
    if buf.len() < expected {
        return Err(bio_err(format!(
            "short IR buffer: got {}, expected {}",
            buf.len(),
            expected
        )));
    }
    let img = ImageBuffer::<image::Luma<u8>, Vec<u8>>::from_raw(w, h, buf[..expected].to_vec())
        .ok_or_else(|| bio_err("IR buffer dimensions mismatch"))?;
    Ok(img)
}

pub fn capture_from(path: &str) -> Result<Frame> {
    let dev = Device::with_path(path).map_err(|e| bio_err(format!("open {path}: {e}")))?;

    let mut fmt = dev.format().map_err(|e| bio_err(format!("get format: {e}")))?;
    fmt.width = CAPTURE_WIDTH;
    fmt.height = CAPTURE_HEIGHT;
    fmt.fourcc = FourCC::new(b"MJPG");
    let fmt = dev.set_format(&fmt).map_err(|e| bio_err(format!("set format: {e}")))?;

    let mut stream = Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| bio_err(format!("stream init: {e}")))?;

    // Warm up — discard the first N frames while AE/AGC converge. Without
    // this, captures grabbed mid-ramp produce wildly variable exposure.
    for _ in 0..AE_WARMUP_FRAMES {
        stream
            .next()
            .map_err(|e| bio_err(format!("warmup: {e}")))?;
    }

    let (buf, _meta) = stream.next().map_err(|e| bio_err(format!("stream next: {e}")))?;

    decode(&fmt.fourcc, buf, fmt.width, fmt.height)
}

fn decode(fourcc: &FourCC, buf: &[u8], w: u32, h: u32) -> Result<Frame> {
    match &fourcc.repr {
        b"MJPG" => {
            let img = image::load_from_memory_with_format(buf, image::ImageFormat::Jpeg)
                .map_err(|e| bio_err(format!("jpeg decode: {e}")))?;
            Ok(img.to_rgb8())
        }
        b"YUYV" => Ok(yuyv_to_rgb(buf, w, h)),
        other => Err(bio_err(format!(
            "unsupported camera pixel format: {:?}",
            std::str::from_utf8(other).unwrap_or("?")
        ))),
    }
}

fn yuyv_to_rgb(buf: &[u8], w: u32, h: u32) -> Frame {
    let mut out = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(w, h);
    let row = (w * 2) as usize;
    for y in 0..h as usize {
        let base = y * row;
        for x in (0..w as usize).step_by(2) {
            let i = base + x * 2;
            if i + 3 >= buf.len() {
                break;
            }
            let (y0, u, y1, v) = (buf[i] as i32, buf[i + 1] as i32, buf[i + 2] as i32, buf[i + 3] as i32);
            out.put_pixel(x as u32, y as u32, yuv_pixel(y0, u, v));
            out.put_pixel(x as u32 + 1, y as u32, yuv_pixel(y1, u, v));
        }
    }
    out
}

fn yuv_pixel(y: i32, u: i32, v: i32) -> Rgb<u8> {
    let c = y - 16;
    let d = u - 128;
    let e = v - 128;
    let r = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8;
    let g = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8;
    let b = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8;
    Rgb([r, g, b])
}
