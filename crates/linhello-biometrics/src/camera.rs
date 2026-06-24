//! V4L2 camera capture. Produces an RGB8 frame suitable for the pipeline.

use crate::bio_err;
use linhello_common::Result;
use image::{ImageBuffer, Rgb};
use std::sync::Mutex;
use std::time::{Duration, Instant};
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
/// IR warmup: default 8 frames at 15fps = 533ms. The active NIR emitter needs
/// time to reach steady-state, and the face/bg ratio requires stable
/// absolute intensity within the frame. 5 frames caused 100% FRR. Tunable via
/// `LINHELLO_IR_WARMUP` for diagnosing emitter/exposure behaviour on a given
/// camera.
fn ae_warmup_ir() -> usize {
    std::env::var("LINHELLO_IR_WARMUP")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(8)
}

/// Capture a single frame from the selected RGB camera. Blocks until one
/// frame is delivered or the device errors out.
pub fn capture_frame() -> Result<Frame> {
    capture_from(&rgb_device())
}

/// Frames grabbed per IR capture; the NIR emitter strobes (frames alternate
/// illuminated / ambient), so we keep the brightest = the emitter-on phase.
const IR_BURST: usize = 6;

/// Capture a frame from the IR companion sensor, or `Ok(None)` if there is no
/// IR device. A brief one-shot — open → warm → short burst → brightest → close.
/// Brief so it does NOT continuously contend with the RGB camera on shared-USB
/// Windows-Hello modules (a persistent IR stream starved RGB capture), and
/// burst-select so it lands on the emitter-on strobe phase rather than a dark
/// ambient frame. The IR signal is advisory — a miss is just "no IR this sample".
pub fn capture_ir_frame() -> Result<Option<IrFrame>> {
    match ir_device() {
        Some(path) => capture_ir_from(&path).map(Some),
        None => Ok(None),
    }
}

/// Cheap sampled mean luma of an IR frame — used to pick the bright strobe phase.
fn ir_mean_luma(img: &IrFrame) -> f32 {
    let data = img.as_raw();
    if data.is_empty() {
        return 0.0;
    }
    let step = (data.len() / 4096).max(1);
    let (mut sum, mut n) = (0u64, 0u64);
    let mut i = 0;
    while i < data.len() {
        sum += data[i] as u64;
        n += 1;
        i += step;
    }
    sum as f32 / n.max(1) as f32
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

/// Hard deadline for one full enumeration pass. Enumeration opens every
/// `/dev/video*` node and issues `ENUM_FMT`/`QUERYCAP` ioctls (`classify_device`)
/// — USB transfers that, on a UVC camera wedged across suspend/resume, can block
/// in *uninterruptible* kernel sleep with no timeout of their own. This path runs
/// *before* the timed capture (resolution + camera-binding snapshot), so without
/// a bound it hangs `do_verify`/`do_authenticate` indefinitely and the greeter
/// sits on "Looking for your face…" forever instead of falling back to the
/// password. Bounding it keeps the daemon's invariant: a frozen camera must never
/// hang the PAM stack. Normal enumeration is well under 100ms; 3s only ever trips
/// on a genuinely stuck device.
const ENUMERATE_TIMEOUT: Duration = Duration::from_secs(3);

/// Enumerate all V4L capture nodes with their classification. Nodes that
/// can't be opened or offer no formats are reported as `Unknown` rather than
/// dropped, so `linhello doctor` can show them. Bounded by [`ENUMERATE_TIMEOUT`]
/// so a wedged USB camera can't block the (untimed) device-resolution path that
/// precedes capture; on timeout we return an empty list — resolution then falls
/// back to the default device and the *capture* deadline takes over from there.
pub fn enumerate() -> Vec<CameraInfo> {
    match run_with_deadline(ENUMERATE_TIMEOUT, enumerate_blocking) {
        Some(v) => v,
        None => {
            tracing::warn!(
                "camera enumeration did not finish within {}s (a video node is wedged — likely a USB camera that did not resume from suspend); treating as no cameras so PAM falls back to the password",
                ENUMERATE_TIMEOUT.as_secs()
            );
            Vec::new()
        }
    }
}

fn enumerate_blocking() -> Vec<CameraInfo> {
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

/// How long a resolved camera path is reused before re-resolving. Short enough
/// that hot-plugging a camera is picked up within a couple seconds (by the auth
/// path, `doctor`, and the TUI) WITHOUT a daemon restart, but long enough that a
/// capture burst doesn't re-enumerate V4L on every frame. (Replaces a permanent
/// per-process cache, which pinned whatever was present at daemon startup — so a
/// camera plugged in later was ignored until restart, and one mis-resolved during
/// USB settle stayed wrong.)
const RESOLVE_TTL: Duration = Duration::from_secs(2);

/// Resolved RGB device path. Re-resolved at most once per [`RESOLVE_TTL`].
pub fn rgb_device() -> String {
    static CACHE: Mutex<Option<(Instant, String)>> = Mutex::new(None);
    let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = g.as_ref() {
        if at.elapsed() < RESOLVE_TTL {
            return v.clone();
        }
    }
    let v = resolve_rgb();
    *g = Some((Instant::now(), v.clone()));
    v
}

/// Resolved IR device path, or `None` if this machine has no IR sensor. Also
/// re-resolved at most once per [`RESOLVE_TTL`] so a reconnected IR camera is
/// picked up live.
pub fn ir_device() -> Option<String> {
    static CACHE: Mutex<Option<(Instant, Option<String>)>> = Mutex::new(None);
    let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, v)) = g.as_ref() {
        if at.elapsed() < RESOLVE_TTL {
            return v.clone();
        }
    }
    let v = resolve_ir();
    *g = Some((Instant::now(), v.clone()));
    v
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
    linhello_common::config::read_kv("cameras.conf", key)
}

/// Persist the operator's camera choice to `/etc/linhello/cameras.conf` so the
/// daemon resolves these devices on its next start. `ir = None` clears the IR
/// pin (auto-detect resumes). Requires write access to `CONFIG_ROOT` (root);
/// the `linhello setup` wizard calls this. The daemon caches device paths per
/// process, so a `systemctl restart linhellod` is needed to pick up changes.
pub fn write_cameras_conf(rgb: &str, ir: Option<&str>) -> Result<()> {
    linhello_common::config::write_kv("cameras.conf", "rgb", rgb)
        .map_err(|e| bio_err(format!("writing cameras.conf: {e}")))?;
    if let Some(ir) = ir {
        linhello_common::config::write_kv("cameras.conf", "ir", ir)
            .map_err(|e| bio_err(format!("writing cameras.conf: {e}")))?;
    }
    Ok(())
}

/// Hard deadline for one capture attempt. A frozen USB camera or hung V4L
/// driver must never hang the PAM stack (login/sudo) — past the deadline we
/// return an error (PAM falls through to password) and the stuck worker thread
/// is abandoned (it holds one fd; the kernel reclaims it if the device resets).
const CAPTURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const IR_CAPTURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// Run `f` on a detached worker thread, returning `None` if it does not finish
/// within `timeout`. On timeout the worker is abandoned — it may be parked in an
/// uninterruptible V4L ioctl on a wedged device, holding one fd, which the kernel
/// reclaims when the device resets — but the *caller* is freed regardless. That
/// is the whole point: neither a stalled capture nor a stalled enumeration may
/// ever hang the PAM stack (login / lock screen / sudo). Shared by the capture
/// deadline and the enumeration deadline so both honour the same invariant.
fn run_with_deadline<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).ok()
}

/// Run a capture closure on a worker thread with a deadline.
fn capture_with_timeout<T: Send + 'static>(
    what: &str,
    path: String,
    timeout: std::time::Duration,
    f: fn(&str) -> Result<T>,
) -> Result<T> {
    let label = path.clone();
    match run_with_deadline(timeout, move || f(&path)) {
        Some(r) => r,
        None => Err(bio_err(format!(
            "{what} camera {label} produced no frame within {}s (device hung or held by another app)",
            timeout.as_secs()
        ))),
    }
}

/// Serialises all camera I/O across the process. KDE's lock screen runs TWO PAM
/// stacks at once (`kde` + `kde-fingerprint`), so two Verify operations would
/// otherwise open and STREAMON the same V4L node simultaneously — the loser gets
/// EBUSY ("Device or resource busy") and the unlock fails (seen post-resume,
/// where slower warm-up makes the captures overlap). Serialising also stops a
/// Windows-Hello module's shared-USB IR and RGB nodes from contending (a
/// persistent IR stream has been observed to starve RGB capture). The lock is
/// held only for one *bounded* capture, so the longest a waiter blocks is a
/// single capture deadline; an abandoned (timed-out) worker holds the device,
/// not this lock, so it can never deadlock the PAM stack.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

pub fn capture_ir_from(path: &str) -> Result<IrFrame> {
    let _serial = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    capture_with_timeout("IR", path.to_string(), IR_CAPTURE_TIMEOUT, capture_ir_from_blocking)
}

fn capture_ir_from_blocking(path: &str) -> Result<IrFrame> {
    let dev = Device::with_path(path).map_err(|e| bio_err(format!("open {path}: {e}")))?;

    let mut fmt = dev.format().map_err(|e| bio_err(format!("get format: {e}")))?;
    fmt.width = IR_CAPTURE_WIDTH;
    fmt.height = IR_CAPTURE_HEIGHT;
    fmt.fourcc = FourCC::new(b"GREY");
    let fmt = dev
        .set_format(&fmt)
        .map_err(|e| bio_err(format!("set format: {e}")))?;
    if &fmt.fourcc.repr != b"GREY" {
        return Err(bio_err(format!(
            "unexpected IR pixel format: {:?}",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("?")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    // Widen before multiplying: driver-reported dimensions are u32, and `w * h`
    // in u32 could overflow (wrapping in release) and yield a too-small buffer.
    let expected = (w as usize) * (h as usize);

    let mut stream = Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| bio_err(format!("stream init: {e}")))?;
    // Light the active-IR emitter before warming up: on many Windows-Hello USB
    // modules the NIR illuminator is gated behind a vendor UVC extension-unit
    // control that `uvcvideo` never drives, so without this the warmup/burst
    // frames come back black. Best-effort and device-wide on the open fd.
    {
        let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
        crate::ir_emitter::enable(dev.handle().fd(), &card);
    }
    for _ in 0..ae_warmup_ir() {
        stream
            .next()
            .map_err(|e| bio_err(format!("IR warmup: {e}")))?;
    }
    // Grab a short burst and keep the brightest (emitter-on strobe phase).
    let mut best: Option<(f32, IrFrame)> = None;
    for _ in 0..IR_BURST {
        let (buf, _meta) = stream
            .next()
            .map_err(|e| bio_err(format!("stream next: {e}")))?;
        if buf.len() < expected {
            continue;
        }
        if let Some(img) =
            ImageBuffer::<image::Luma<u8>, Vec<u8>>::from_raw(w, h, buf[..expected].to_vec())
        {
            let m = ir_mean_luma(&img);
            if best.as_ref().map(|(bm, _)| m > *bm).unwrap_or(true) {
                best = Some((m, img));
            }
        }
    }
    best.map(|(_, img)| img)
        .ok_or_else(|| bio_err("no IR frame captured"))
}

/// Pixel formats we can decode, in preference order. V4L2's S_FMT adjusts
/// rather than failing on most drivers — we always decode by the fourcc the
/// driver actually *returned* — but some drivers reject the request outright
/// or settle on a format we can't decode (NV12-only pipelines, H264-only
/// nodes). Trying each preference covers MJPEG-only and YUYV-only cameras.
const RGB_FOURCC_PREFS: [&[u8; 4]; 2] = [b"MJPG", b"YUYV"];

fn decodable(fourcc: &FourCC) -> bool {
    matches!(&fourcc.repr, b"MJPG" | b"YUYV")
}

pub fn capture_from(path: &str) -> Result<Frame> {
    let _serial = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    capture_with_timeout("RGB", path.to_string(), CAPTURE_TIMEOUT, capture_from_blocking)
}

fn capture_from_blocking(path: &str) -> Result<Frame> {
    let dev = Device::with_path(path).map_err(|e| bio_err(format!("open {path}: {e}")))?;

    let mut last_err: Option<crate::LinuxHelloError> = None;
    for pref in RGB_FOURCC_PREFS {
        let mut fmt = match dev.format() {
            Ok(f) => f,
            Err(e) => return Err(bio_err(format!("get format: {e}"))),
        };
        fmt.width = CAPTURE_WIDTH;
        fmt.height = CAPTURE_HEIGHT;
        fmt.fourcc = FourCC::new(pref);
        // The driver may adjust width/height/fourcc — that's fine, we use what
        // it returns. Only an outright rejection or an undecodable result moves
        // us to the next preference.
        let fmt = match dev.set_format(&fmt) {
            Ok(f) => f,
            Err(e) => {
                last_err = Some(bio_err(format!("set format {:?}: {e}", fourcc_str(pref))));
                continue;
            }
        };
        if !decodable(&fmt.fourcc) {
            last_err = Some(bio_err(format!(
                "driver chose unsupported pixel format {:?} (wanted {:?})",
                fourcc_str(&fmt.fourcc.repr),
                fourcc_str(pref),
            )));
            continue;
        }

        let mut stream = Stream::with_buffers(&dev, Type::VideoCapture, 4)
            .map_err(|e| bio_err(format!("stream init: {e}")))?;
        for _ in 0..AE_WARMUP_RGB {
            stream
                .next()
                .map_err(|e| bio_err(format!("warmup: {e}")))?;
        }
        // Some UVC modules (e.g. the NexiGo N930W) intermittently deliver torn /
        // incomplete MJPG frames — a single grab then fails the whole capture
        // ("illegal start bytes", truncated DHT). Grab a few and return the first
        // that decodes; skip obviously-incomplete JPEGs cheaply before decoding.
        let mut decode_err: Option<crate::LinuxHelloError> = None;
        for _ in 0..RGB_DECODE_ATTEMPTS {
            let (buf, _meta) = stream
                .next()
                .map_err(|e| bio_err(format!("stream next: {e}")))?;
            if &fmt.fourcc.repr == b"MJPG" && !is_complete_jpeg(buf) {
                decode_err = Some(bio_err("incomplete MJPG frame"));
                continue;
            }
            match decode(&fmt.fourcc, buf, fmt.width, fmt.height) {
                Ok(frame) => return Ok(frame),
                Err(e) => decode_err = Some(e),
            }
        }
        // Every attempt at this pixel format failed to decode — fall through to
        // the next preference (MJPG → YUYV, which is uncompressed and can't tear).
        last_err = decode_err;
    }
    Err(last_err
        .unwrap_or_else(|| bio_err("no usable pixel format (camera offers neither MJPG nor YUYV)")))
}

/// Frames to try per pixel format before giving up / falling back. At 30fps the
/// worst case adds ~130ms, well within the capture deadline, and a couple of
/// retries reliably clears the N930W's occasional torn-MJPG frames.
const RGB_DECODE_ATTEMPTS: usize = 4;

/// Cheap structural check that a buffer is a *complete* JPEG: starts with the
/// SOI marker (`FF D8`) and ends with EOI (`FF D9`). Catches the torn/desynced
/// MJPG frames some UVC cameras emit without paying for a full decode attempt.
fn is_complete_jpeg(buf: &[u8]) -> bool {
    buf.len() > 4
        && buf[0] == 0xFF
        && buf[1] == 0xD8
        && buf[buf.len() - 2] == 0xFF
        && buf[buf.len() - 1] == 0xD9
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
    fn complete_jpeg_detection() {
        // SOI ... EOI
        assert!(is_complete_jpeg(&[0xFF, 0xD8, 0x00, 0x11, 0xFF, 0xD9]));
        // missing SOI (torn/desynced frame — the N930W failure mode)
        assert!(!is_complete_jpeg(&[0x58, 0xCB, 0x00, 0x11, 0xFF, 0xD9]));
        // truncated (no EOI)
        assert!(!is_complete_jpeg(&[0xFF, 0xD8, 0x00, 0x11, 0x00, 0x00]));
        // too short
        assert!(!is_complete_jpeg(&[0xFF, 0xD8]));
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
    fn deadline_returns_value_when_fast() {
        let got = run_with_deadline(Duration::from_secs(5), || 42);
        assert_eq!(got, Some(42));
    }

    #[test]
    fn deadline_trips_on_a_stuck_worker() {
        // A worker that outlives the deadline (stands in for a wedged V4L ioctl)
        // must not block the caller: the wrapper returns None promptly so the
        // auth path can fall back to the password instead of hanging PAM.
        let start = Instant::now();
        let got = run_with_deadline(Duration::from_millis(150), || {
            std::thread::sleep(Duration::from_secs(30));
            42
        });
        assert_eq!(got, None);
        assert!(start.elapsed() < Duration::from_secs(5), "deadline did not free the caller");
    }

    #[test]
    fn fourcc_trims_padding() {
        assert_eq!(fourcc_str(b"GREY"), "GREY");
        assert_eq!(fourcc_str(b"Y8\0\0"), "Y8");
        assert_eq!(fourcc_str(b"Y16 "), "Y16");
    }
}
