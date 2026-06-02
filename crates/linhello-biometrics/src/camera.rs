//! V4L2 camera capture. Produces an RGB8 frame suitable for the pipeline.

use crate::bio_err;
use linhello_common::Result;
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

/// RGB warmup: 5 frames at 30fps = 167ms. RGB face detection is
/// lighting-invariant enough that AE doesn't need full convergence.
const AE_WARMUP_RGB: usize = 5;
/// IR warmup: 8 frames at 15fps = 533ms. The active NIR emitter needs
/// time to reach steady-state, and the face/bg ratio requires stable
/// absolute intensity within the frame. 5 frames caused 100% FRR.
const AE_WARMUP_IR: usize = 8;

/// Capture a single frame from the selected RGB camera. Blocks until one
/// frame is delivered or the device errors out.
pub fn capture_frame() -> Result<Frame> {
    capture_from(&rgb_device())
}

/// Capture a single frame from the selected IR companion sensor. Returns
/// `Ok(None)` (not an error) if no IR device is present — laptops/cameras
/// without a Windows-Hello-class IR sensor are supported, the IR signal just
/// never contributes.
pub fn capture_ir_frame() -> Result<Option<IrFrame>> {
    match ir_device() {
        Some(path) => capture_ir_from(&path).map(Some),
        None => Ok(None),
    }
}

// ── Camera discovery & selection ────────────────────────────────────────
//
// LinuxHello runs on internal laptop sensors *and* external UVC cameras, including
// Windows-Hello-class USB modules that expose a colour node plus a greyscale
// NIR node. We classify each /dev/video* node by the pixel formats it offers
// (colour ⇒ usable as RGB; greyscale-only ⇒ IR companion) and pick a device
// by precedence: explicit env var → /etc/linhello/cameras.conf → auto-detect →
// built-in default. The choice is cached for the process; re-plugging a camera
// needs a daemon restart.

use std::sync::OnceLock;

/// What a video node is good for in the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraKind {
    /// Colour-capable — used as the RGB face camera.
    Rgb,
    /// Greyscale-only — a NIR companion sensor (active-IR liveness).
    Ir,
    /// No usable capture formats (metadata node, or unreadable).
    Unknown,
}

/// A discovered video device.
#[derive(Debug, Clone)]
pub struct CameraInfo {
    pub path: String,
    pub name: Option<String>,
    pub kind: CameraKind,
    /// Pixel formats the node advertises (FourCC strings).
    pub fourccs: Vec<String>,
    /// `false` for virtual cameras (v4l2loopback/OBS) — never auto-selected.
    pub trusted: bool,
}

/// Enumerate all V4L capture nodes with their classification. Nodes that
/// can't be opened or offer no formats are reported as `Unknown` rather than
/// dropped, so `linhello doctor` can show them.
pub fn enumerate() -> Vec<CameraInfo> {
    v4l::context::enum_devices()
        .into_iter()
        .filter_map(|node| {
            let path = node.path().to_str()?.to_string();
            let (kind, fourccs) = classify_device(&path);
            let trusted = linhello_liveness::device::validate_camera_device(&path).score > 0.0;
            Some(CameraInfo {
                name: node.name(),
                path,
                kind,
                fourccs,
                trusted,
            })
        })
        .collect()
}

fn classify_device(path: &str) -> (CameraKind, Vec<String>) {
    use v4l::video::Capture;
    let dev = match Device::with_path(path) {
        Ok(d) => d,
        Err(_) => return (CameraKind::Unknown, Vec::new()),
    };
    let formats = match dev.enum_formats() {
        Ok(f) => f,
        Err(_) => return (CameraKind::Unknown, Vec::new()),
    };
    let fourccs: Vec<String> = formats.iter().map(|d| fourcc_str(&d.fourcc.repr)).collect();
    (classify_fourccs(&fourccs), fourccs)
}

fn fourcc_str(repr: &[u8; 4]) -> String {
    std::str::from_utf8(repr)
        .unwrap_or("?")
        .trim_end_matches(['\0', ' '])
        .to_string()
}

/// Decide a device kind from the FourCC formats it advertises. Colour formats
/// win (a Windows-Hello RGB node may also expose some greyscale modes); a node
/// offering *only* greyscale is the IR companion. Pure so it's unit-testable.
pub fn classify_fourccs(fourccs: &[String]) -> CameraKind {
    let is_color = |f: &str| {
        matches!(
            f,
            "MJPG" | "YUYV" | "YUY2" | "RGB3" | "BGR3" | "NV12" | "YU12" | "UYVY" | "H264"
        )
    };
    let is_grey = |f: &str| matches!(f, "GREY" | "Y8" | "Y16" | "Y10" | "Y12" | "GREZ");
    let has_color = fourccs.iter().any(|f| is_color(f));
    let has_grey = fourccs.iter().any(|f| is_grey(f));
    match (has_color, has_grey) {
        (true, _) => CameraKind::Rgb,
        (false, true) => CameraKind::Ir,
        (false, false) => CameraKind::Unknown,
    }
}

/// Resolved RGB device path (cached per process).
pub fn rgb_device() -> String {
    static RGB: OnceLock<String> = OnceLock::new();
    RGB.get_or_init(resolve_rgb).clone()
}

/// Resolved IR device path, or `None` if this machine has no IR sensor.
pub fn ir_device() -> Option<String> {
    static IR: OnceLock<Option<String>> = OnceLock::new();
    IR.get_or_init(resolve_ir).clone()
}

fn resolve_rgb() -> String {
    if let Some(p) = env_device("LINHELLO_RGB_DEVICE") {
        return p;
    }
    if let Some(p) = conf_device("rgb") {
        return p;
    }
    enumerate()
        .into_iter()
        .find(|c| c.kind == CameraKind::Rgb && c.trusted)
        .map(|c| c.path)
        .unwrap_or_else(|| DEFAULT_DEVICE.to_string())
}

fn resolve_ir() -> Option<String> {
    if let Some(p) = env_device("LINHELLO_IR_DEVICE") {
        return exists(p);
    }
    if let Some(p) = conf_device("ir") {
        return exists(p);
    }
    if let Some(c) = enumerate().into_iter().find(|c| c.kind == CameraKind::Ir) {
        return Some(c.path);
    }
    exists(DEFAULT_IR_DEVICE.to_string())
}

fn env_device(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|s| !s.is_empty())
}

fn exists(path: String) -> Option<String> {
    std::path::Path::new(&path).exists().then_some(path)
}

/// Read `rgb=`/`ir=` from `/etc/linhello/cameras.conf` (simple `key=value`,
/// `#` comments). Lets a user pin an external camera across reboots.
fn conf_device(key: &str) -> Option<String> {
    let path = std::path::Path::new(linhello_common::CONFIG_ROOT).join("cameras.conf");
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
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
    for _ in 0..AE_WARMUP_IR {
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

    for _ in 0..AE_WARMUP_RGB {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn color_node_is_rgb() {
        assert_eq!(classify_fourccs(&s(&["MJPG", "YUYV"])), CameraKind::Rgb);
        // Windows-Hello RGB nodes sometimes also list a greyscale mode.
        assert_eq!(classify_fourccs(&s(&["YUYV", "GREY"])), CameraKind::Rgb);
    }

    #[test]
    fn greyscale_only_node_is_ir() {
        assert_eq!(classify_fourccs(&s(&["GREY"])), CameraKind::Ir);
        assert_eq!(classify_fourccs(&s(&["Y8", "Y16"])), CameraKind::Ir);
    }

    #[test]
    fn no_capture_formats_is_unknown() {
        assert_eq!(classify_fourccs(&s(&[])), CameraKind::Unknown);
        assert_eq!(classify_fourccs(&s(&["META"])), CameraKind::Unknown);
    }

    #[test]
    fn fourcc_trims_padding() {
        assert_eq!(fourcc_str(b"GREY"), "GREY");
        assert_eq!(fourcc_str(b"Y8\0\0"), "Y8");
        assert_eq!(fourcc_str(b"Y16 "), "Y16");
    }
}
