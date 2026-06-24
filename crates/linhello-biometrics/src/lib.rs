//! Face-recognition pipeline: capture → detect → align → embed → match.

use linhello_common::{LinuxHelloError, Result};
use serde::{Deserialize, Serialize};

pub mod align;
pub mod camera;
pub mod detect;
pub mod ir_emitter;
pub mod embed;
pub mod enroll;
pub mod matcher;
mod ort_init;

/// Default cosine-similarity threshold for a successful match (ArcFace, 512-D,
/// L2). Override at runtime via the `LINHELLO_MATCH_THRESHOLD` env var or
/// `match_threshold=` in `/etc/linhello/settings.conf` — the `linhello setup`
/// wizard writes the latter after calibrating against your live scores.
pub const DEFAULT_MATCH_THRESHOLD: f32 = 0.60;

/// Resolved match threshold (cached per process): env → `settings.conf` →
/// default. Clamped to `[0.30, 0.95]` so a malformed/hostile config can neither
/// disable auth (too low) nor make it impossible (too high).
pub fn match_threshold() -> f32 {
    static T: std::sync::OnceLock<f32> = std::sync::OnceLock::new();
    *T.get_or_init(|| {
        std::env::var("LINHELLO_MATCH_THRESHOLD")
            .ok()
            .and_then(|s| s.trim().parse::<f32>().ok())
            .or_else(|| {
                linhello_common::config::read_kv("settings.conf", "match_threshold")
                    .and_then(|s| s.parse::<f32>().ok())
            })
            .filter(|v| v.is_finite())
            .map(|v| v.clamp(0.30, 0.95))
            .unwrap_or(DEFAULT_MATCH_THRESHOLD)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub matched: bool,
    pub score: f32,
}

/// Capture a short RGB burst (one open, several frames — see `camera::capture_burst`),
/// detect a face in each, and return the largest-face frame for recognition plus
/// the temporal eye-motion score across the sequence (`None` if <2 frames had a
/// face). Shared by the auth path and the `linhello test` liveness diagnostic.
///
/// RGB+detect runs FIRST, then IR (never concurrently): on shared-USB Windows-Hello
/// modules a simultaneous IR grab starves the RGB stream (observed ~17s latency on
/// the N930W). The lost overlap is a fair price for reliable capture there.
/// Frames the ML anti-spoof scores per auth; their MEDIAN is the gate value
/// (denoises MiniFASNet's jittery one-shot reading — a single blurred/mid-blink
/// frame can read ~1.0 and false-reject a live user). Override with
/// `LINHELLO_ANTISPOOF_FRAMES` (1 restores legacy single-frame behaviour).
const DEFAULT_ANTISPOOF_FRAMES: usize = 5;

fn antispoof_frames() -> usize {
    std::env::var("LINHELLO_ANTISPOOF_FRAMES")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| (1..=15).contains(&n))
        .unwrap_or(DEFAULT_ANTISPOOF_FRAMES)
}

/// `(camera path, best frame, best face, median spoof_prob, temporal motion score)`.
type BurstCapture = (String, camera::Frame, detect::Face, Option<f32>, Option<f32>);

fn capture_burst_detect() -> Result<BurstCapture> {
    let path = camera::rgb_device();
    // Multi-frame so the ML anti-spoof can be median-aggregated (denoised) across
    // the burst; widen to the temporal burst when that experimental gate is on.
    let n = antispoof_frames()
        .max(if linhello_liveness::temporal_gate_enabled() {
            camera::TEMPORAL_BURST
        } else {
            0
        })
        .max(1);
    let frames = camera::capture_burst(&path, n)?;
    let detector = detect::Detector::cached()?;
    let mut eye_seq: Vec<linhello_liveness::temporal::EyeFrame> = Vec::new();
    let mut detected: Vec<(usize, [f32; 4])> = Vec::new();
    let mut best: Option<(usize, detect::Face, f32)> = None;
    for (i, f) in frames.iter().enumerate() {
        if let Some(face) = detector.detect(f).ok().and_then(|v| v.into_iter().next()) {
            eye_seq.push(linhello_liveness::temporal::eye_frame(f, &face.landmarks));
            detected.push((i, face.bbox));
            let area =
                (face.bbox[2] - face.bbox[0]).max(0.0) * (face.bbox[3] - face.bbox[1]).max(0.0);
            if best.as_ref().map(|(_, _, a)| area > *a).unwrap_or(true) {
                best = Some((i, face, area));
            }
        }
    }
    let (bi, face, _) = best.ok_or_else(|| bio_err("no face detected"))?;
    let temporal_score = linhello_liveness::temporal::motion_score(&eye_seq);
    // Median anti-spoof across every detected frame — the denoised gate value.
    let ml_frames: Vec<(&camera::Frame, [f32; 4])> =
        detected.iter().map(|(i, b)| (&frames[*i], *b)).collect();
    let spoof_prob = linhello_liveness::LivenessEvaluator::cached()?.antispoof_median(&ml_frames)?;
    Ok((path, frames[bi].clone(), face, spoof_prob, temporal_score))
}

/// Capture, detect the primary face, and run the liveness gate. Returns the
/// frame, face, and signals on success; errors (with a human-readable reason)
/// when no face is visible or liveness rejects.
fn capture_detect_live() -> Result<(camera::Frame, detect::Face, linhello_liveness::LivenessSignals)> {
    let (path, frame, face, spoof_prob, temporal_score) = capture_burst_detect()?;

    let ir = camera::capture_ir_frame().ok().flatten();

    let evaluator = linhello_liveness::LivenessEvaluator::cached()?;
    let report = evaluator.evaluate(
        &frame, face.bbox, &face.landmarks, &path, ir.as_ref(), spoof_prob, temporal_score,
    )?;
    if matches!(report.decision, linhello_liveness::LivenessDecision::Spoof) {
        return Err(bio_err(format!(
            "liveness check failed: {}",
            report.reason.as_deref().unwrap_or("spoof detected")
        )));
    }
    if matches!(report.decision, linhello_liveness::LivenessDecision::Uncertain) {
        return Err(bio_err(format!(
            "liveness uncertain: {}",
            report.reason.as_deref().unwrap_or("try again")
        )));
    }
    Ok((frame, face, report.signals))
}

pub fn capture_and_embed() -> Result<Vec<f32>> {
    capture_and_embed_signals().map(|(v, _)| v)
}

/// Like [`capture_and_embed`] but also returns the liveness signals from the same
/// capture, so the caller can apply a per-user calibrated IR liveness gate (the
/// signals carry the active-IR cues) or record an enrollment observation.
pub fn capture_and_embed_signals(
) -> Result<(Vec<f32>, linhello_liveness::LivenessSignals)> {
    let (frame, face, signals) = capture_detect_live()?;
    let aligned = align::align(&frame, &face)?;
    let embedder = embed::Embedder::cached()?;
    let emb = embedder.embed(&aligned)?;
    Ok((emb, signals))
}

/// Capture one RGB frame and return live framing geometry for the enrollment
/// positioning guide (see `Request::PositionSample`).
///
/// Detection only — no alignment, embedding, IR capture, or anti-spoof ML — so
/// it is cheap enough to poll while the user frames their face, and it exposes
/// no biometric template or match score. The gates that set `well_framed`
/// reuse the auth path's thresholds (`MIN_FACE_FRAC`, `MAX_ANGLE_DEG`), so a
/// "well framed" reading implies a subsequent enroll/verify will accept the
/// framing.
pub fn capture_position_sample() -> Result<linhello_common::ipc::PositionReport> {
    use linhello_liveness::orientation::estimate_pose;

    // Capture RGB and detect FIRST, then IR — sequentially, never concurrently.
    // On shared-USB Windows-Hello modules a simultaneous IR grab starves the RGB
    // capture and wrecks RGB face detection, so the guide serialises them.
    let frame = camera::capture_frame()?;
    let (fw, fh) = (frame.width(), frame.height());
    let detector = detect::Detector::cached()?;
    let faces = detector.detect(&frame)?;
    let face_count = faces.len() as u32;
    let ir = camera::capture_ir_frame().ok().flatten();
    let ir_present = ir.is_some();

    // Prefer the RGB face (RGB is what enrollment/recognition embeds). IR layers
    // on as an illumination / liveness-readiness signal over the same region.
    if let Some(face) = faces.into_iter().next() {
        let (yaw, pitch) = estimate_pose(&face.landmarks);
        let (face_lum, frame_lum, sharp) = region_stats(&frame, face.bbox);
        let ir_sig = ir
            .as_ref()
            .map(|irf| linhello_liveness::ir::evaluate(irf, face.bbox, (fw, fh), &face.landmarks));
        return Ok(framing_guidance(FramingInput {
            face_count,
            frame_w: fw,
            frame_h: fh,
            primary: Some((face.bbox, yaw, pitch, face_lum, frame_lum, sharp)),
            ir_present,
            ir_sig,
            low_light: false,
        }));
    }

    // No RGB face. Only treat this as a low-light situation (IR fallback +
    // "add light") when the RGB frame is genuinely dark — a transient miss in
    // good light (fast head-turn, extreme angle) should read as "no face", not
    // a misleading "too dark".
    let rgb_dark = frame_mean_luma(&frame) < 60.0;
    if rgb_dark {
        if let Some(irf) = ir.as_ref() {
            let ir_rgb = ir_to_rgb(irf);
            if let Some(face) = detector.detect(&ir_rgb).ok().and_then(|v| v.into_iter().next()) {
                let (yaw, pitch) = estimate_pose(&face.landmarks);
                let (iw, ih) = (irf.width(), irf.height());
                let (face_lum, frame_lum, sharp) = region_stats(&ir_rgb, face.bbox);
                let ir_sig = Some(linhello_liveness::ir::evaluate(irf, face.bbox, (iw, ih), &face.landmarks));
                return Ok(framing_guidance(FramingInput {
                    face_count: 1,
                    frame_w: iw,
                    frame_h: ih,
                    primary: Some((face.bbox, yaw, pitch, face_lum, frame_lum, sharp)),
                    ir_present,
                    ir_sig,
                    low_light: true,
                }));
            }
        }
    }

    Ok(framing_guidance(FramingInput {
        face_count: 0,
        frame_w: fw,
        frame_h: fh,
        primary: None,
        ir_present,
        ir_sig: None,
        low_light: false,
    }))
}

/// Per-frame brightness/sharpness over the face region (and the whole frame, for
/// backlight detection). Returns `(face_mean_luma, frame_mean_luma, sharpness)`
/// where sharpness is the mean absolute luma gradient (camera-relative; higher =
/// crisper). Coarsely sampled so it stays cheap enough to poll.
fn region_stats(frame: &camera::Frame, bbox: [f32; 4]) -> (f32, f32, f32) {
    let (fw, fh) = (frame.width() as i32, frame.height() as i32);
    let luma = |x: i32, y: i32| -> f32 {
        let p = frame.get_pixel(x.clamp(0, fw - 1) as u32, y.clamp(0, fh - 1) as u32);
        0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32
    };
    let x1 = bbox[0].max(0.0) as i32;
    let y1 = bbox[1].max(0.0) as i32;
    let x2 = (bbox[2] as i32).min(fw - 1);
    let y2 = (bbox[3] as i32).min(fh - 1);
    let sx = ((x2 - x1).max(1) / 32).max(1);
    let sy = ((y2 - y1).max(1) / 32).max(1);
    let (mut sum, mut n, mut grad, mut gn) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
    let mut y = y1;
    while y <= y2 {
        let mut x = x1;
        while x <= x2 {
            let l = luma(x, y);
            sum += l;
            n += 1.0;
            grad += (luma(x + sx, y) - l).abs() + (luma(x, y + sy) - l).abs();
            gn += 1.0;
            x += sx;
        }
        y += sy;
    }
    let face_mean = if n > 0.0 { sum / n } else { 0.0 };
    let sharp = if gn > 0.0 { grad / gn } else { 0.0 };
    // Whole-frame mean on a coarse grid (for backlight: bright surround, dark face).
    let (mut fsum, mut fcount) = (0.0f32, 0.0f32);
    let mut y = 0;
    while y < fh {
        let mut x = 0;
        while x < fw {
            fsum += luma(x, y);
            fcount += 1.0;
            x += 40;
        }
        y += 40;
    }
    let frame_mean = if fcount > 0.0 { fsum / fcount } else { 0.0 };
    (face_mean, frame_mean, sharp)
}

/// Coarse whole-frame mean luma — distinguishes a genuinely dark RGB frame
/// (low light) from a transient detection miss in good light.
fn frame_mean_luma(frame: &camera::Frame) -> f32 {
    let (w, h) = (frame.width(), frame.height());
    let (mut sum, mut n) = (0.0f32, 0.0f32);
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            let p = frame.get_pixel(x, y);
            sum += 0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32;
            n += 1.0;
            x += 32;
        }
        y += 32;
    }
    if n > 0.0 {
        sum / n
    } else {
        0.0
    }
}

fn lerp01(v: f32, lo: f32, hi: f32) -> f32 {
    ((v - lo) / (hi - lo)).clamp(0.0, 1.0)
}

/// Widen an IR (greyscale) frame into the RGB `Frame` the detector expects, by
/// replicating the luma into all three channels.
fn ir_to_rgb(ir: &camera::IrFrame) -> camera::Frame {
    let (w, h) = (ir.width(), ir.height());
    image::ImageBuffer::from_fn(w, h, |x, y| {
        let l = ir.get_pixel(x, y)[0];
        image::Rgb([l, l, l])
    })
}

/// Inputs to the pure framing decision. Split from camera IO so it is
/// deterministically testable. `primary` is the detected face's `(bbox, yaw,
/// pitch, face_luma, frame_luma, sharpness)`; `ir_sig` is the IR companion's
/// signals over the same region when available.
struct FramingInput {
    face_count: u32,
    frame_w: u32,
    frame_h: u32,
    primary: Option<([f32; 4], f32, f32, f32, f32, f32)>,
    ir_present: bool,
    ir_sig: Option<linhello_liveness::ir::IrSignals>,
    /// RGB couldn't find the face but IR could — too dark to embed an RGB face.
    low_light: bool,
}

/// Pure framing-decision logic. Direction hints assume raw-frame (non-mirrored)
/// image coordinates — the camera is NOT mirrored, so a face on the image's
/// right means the user has moved to their own left, hence "Move right" to
/// re-centre (and the symmetric fix for head-turn). `well_framed` mirrors the
/// auth path's gates plus a lighting floor; IR contributes an
/// illumination/liveness-readiness signal and, in the dark, a clearer message.
fn framing_guidance(input: FramingInput) -> linhello_common::ipc::PositionReport {
    use linhello_common::ipc::PositionReport;
    use linhello_liveness::orientation::MAX_ANGLE_DEG;

    const MIN_FRAC: f32 = linhello_liveness::ir::MIN_FACE_FRAC; // 0.15
    const MAX_FRAC: f32 = 0.60; // beyond this the face fills the frame — too close
    const CENTER_TOL: f32 = 0.18; // allowed bbox-center offset, fraction of frame
    const DIM_GATE: f32 = 40.0; // below this the face is too dark to enroll well;
                                // matches the light-score floor (see `light_score`)
                                // so the gate is never stricter than the quality model.
    const BRIGHT_GATE: f32 = 230.0; // above this it's blown out
    const BACKLIT_DELTA: f32 = 55.0; // frame brighter than face by this → backlit…
    // …but only flag it when the FACE itself is under-lit. A bright background
    // (a window behind the user) is harmless if the face is adequately exposed —
    // it's only a problem when it leaves the face a dark silhouette. 65 ≈ the
    // light-score midpoint (the lerp 40→90), i.e. "at least half-decently lit".
    const BACKLIT_FACE_FLOOR: f32 = 65.0;

    let FramingInput {
        face_count,
        frame_w,
        frame_h,
        primary,
        ir_present,
        ir_sig,
        low_light,
    } = input;

    let (ir_brightness, ir_face_bg) = match &ir_sig {
        Some(s) => (Some(s.mean_face), Some(s.face_bg_ratio)),
        None => (None, None),
    };

    let Some(([x1, y1, x2, y2], yaw, pitch, face_lum, frame_lum, sharp)) = primary else {
        // No face from either camera, OR IR-only "too dark" path handled below.
        return PositionReport {
            face_count: 0,
            frame_w,
            frame_h,
            bbox: None,
            face_frac: None,
            yaw_deg: None,
            pitch_deg: None,
            brightness: None,
            sharpness: None,
            quality: 0,
            ir_present,
            ir_brightness,
            ir_face_bg,
            low_light: false,
            well_framed: false,
            guidance: "No face detected — center yourself in front of the camera".to_string(),
        };
    };

    let face_frac = (x2 - x1).max(0.0) / frame_w as f32;
    let off_x = (x1 + x2) / 2.0 - frame_w as f32 / 2.0;
    let off_y = (y1 + y2) / 2.0 - frame_h as f32 / 2.0;
    let centered =
        off_x.abs() <= CENTER_TOL * frame_w as f32 && off_y.abs() <= CENTER_TOL * frame_h as f32;
    // Backlit only counts against framing when the face is genuinely dim — a
    // bright surround over a well-exposed face is cosmetic, not a blocker.
    let backlit = (frame_lum - face_lum) >= BACKLIT_DELTA && face_lum < BACKLIT_FACE_FLOOR;
    let lit = (DIM_GATE..=BRIGHT_GATE).contains(&face_lum) && !backlit;

    // IR-only (low-light) path: the IR camera sees the face but RGB is too dark
    // to embed. Guide the user to add light rather than auto-capturing.
    if low_light {
        let q = ir_face_bg
            .map(|r| (lerp01(r, 1.0, 1.6) * 60.0) as u8)
            .unwrap_or(30);
        return PositionReport {
            face_count: 1,
            frame_w,
            frame_h,
            bbox: Some([x1, y1, x2, y2]),
            face_frac: Some(face_frac),
            yaw_deg: Some(yaw),
            pitch_deg: Some(pitch),
            brightness: Some(face_lum),
            sharpness: Some(sharp),
            quality: q,
            ir_present,
            ir_brightness,
            ir_face_bg,
            low_light: true,
            well_framed: false, // can't embed an RGB face in the dark
            guidance: "Too dark to enroll — add light (IR can see you)".to_string(),
        };
    }

    // Highest-priority correction first. Distance → vertical → horizontal →
    // head-turn → chin → lighting → ready.
    let guidance = if face_count > 1 {
        "Multiple faces — only you should be in frame"
    } else if face_frac < MIN_FRAC {
        "Move closer"
    } else if face_frac > MAX_FRAC {
        "Move back a little"
    } else if off_y < -CENTER_TOL * frame_h as f32 {
        "Move your head down" // face is high in frame → lower yourself
    } else if off_y > CENTER_TOL * frame_h as f32 {
        "Move your head up"
    } else if off_x > CENTER_TOL * frame_w as f32 {
        "Move right" // face on image-right → user is to their left → move right
    } else if off_x < -CENTER_TOL * frame_w as f32 {
        "Move left"
    } else if yaw > MAX_ANGLE_DEG {
        "Turn your head slightly left"
    } else if yaw < -MAX_ANGLE_DEG {
        "Turn your head slightly right"
    } else if pitch > MAX_ANGLE_DEG {
        // Positive pitch = chin tucked DOWN (looking down) → raise it to frontal.
        "Lift your chin a little"
    } else if pitch < -MAX_ANGLE_DEG {
        // Negative pitch = chin UP (looking up) → bring it down to frontal.
        "Lower your chin a little"
    } else if backlit {
        "Reduce backlighting — face a light source"
    } else if face_lum < DIM_GATE {
        "More light on your face"
    } else if face_lum > BRIGHT_GATE {
        "Too bright — reduce glare"
    } else {
        "Hold still — ready to capture"
    };

    let well_framed = face_count == 1
        && (MIN_FRAC..=MAX_FRAC).contains(&face_frac)
        && yaw.abs() <= MAX_ANGLE_DEG
        && pitch.abs() <= MAX_ANGLE_DEG
        && centered
        && lit;

    // Composite 0–100 quality from the sub-signals (also drives the quality bar
    // and the auto-capture threshold in the enrollment UI).
    let size_score = if (0.22..=0.45).contains(&face_frac) {
        1.0
    } else if face_frac < 0.22 {
        lerp01(face_frac, MIN_FRAC, 0.22)
    } else {
        1.0 - lerp01(face_frac, 0.45, 0.70)
    };
    let off = (off_x.abs() / (frame_w as f32 / 2.0)).max(off_y.abs() / (frame_h as f32 / 2.0));
    let center_score = (1.0 - off).clamp(0.0, 1.0);
    let pose_score = 1.0 - (yaw.abs().max(pitch.abs()) / 30.0).clamp(0.0, 1.0);
    let light_score = if (90.0..=190.0).contains(&face_lum) {
        1.0
    } else if face_lum < 90.0 {
        lerp01(face_lum, 40.0, 90.0)
    } else {
        1.0 - lerp01(face_lum, 190.0, 235.0)
    };
    let sharp_score = (sharp / 12.0).clamp(0.0, 1.0);
    // IR readiness: a real, emitter-lit face is brighter than its background.
    let ir_score = ir_face_bg.map(|r| lerp01(r, 1.0, 1.5));
    let quality = ((0.25 * size_score
        + 0.20 * center_score
        + 0.20 * pose_score
        + 0.15 * light_score
        + 0.10 * sharp_score
        + 0.10 * ir_score.unwrap_or(0.5))
        * 100.0)
        .round()
        .clamp(0.0, 100.0) as u8;

    PositionReport {
        face_count,
        frame_w,
        frame_h,
        bbox: Some([x1, y1, x2, y2]),
        face_frac: Some(face_frac),
        yaw_deg: Some(yaw),
        pitch_deg: Some(pitch),
        brightness: Some(face_lum),
        sharpness: Some(sharp),
        quality,
        ir_present,
        ir_brightness,
        ir_face_bg,
        low_light: false,
        well_framed,
        guidance: guidance.to_string(),
    }
}

#[cfg(test)]
mod position_tests {
    use super::{framing_guidance, FramingInput};

    // Frame is 640×480; a well-centered face spans ~30% width.
    const W: u32 = 640;
    const H: u32 = 480;

    // Build a centered bbox of the given width fraction (square-ish).
    fn centered_bbox(frac: f32) -> [f32; 4] {
        let bw = frac * W as f32;
        let cx = W as f32 / 2.0;
        let cy = H as f32 / 2.0;
        [cx - bw / 2.0, cy - bw / 2.0, cx + bw / 2.0, cy + bw / 2.0]
    }

    // Face primary with good lighting (140) and sharpness (20) defaults.
    fn good(bbox: [f32; 4], yaw: f32, pitch: f32) -> Option<([f32; 4], f32, f32, f32, f32, f32)> {
        Some((bbox, yaw, pitch, 140.0, 140.0, 20.0))
    }

    // FramingInput at the default frame size with no IR.
    fn fi(face_count: u32, primary: Option<([f32; 4], f32, f32, f32, f32, f32)>) -> FramingInput {
        FramingInput {
            face_count,
            frame_w: W,
            frame_h: H,
            primary,
            ir_present: false,
            ir_sig: None,
            low_light: false,
        }
    }

    #[test]
    fn no_face_asks_to_center() {
        let r = framing_guidance(fi(0, None));
        assert!(!r.well_framed);
        assert!(r.guidance.contains("No face"));
        assert!(r.face_frac.is_none());
        assert_eq!(r.quality, 0);
    }

    #[test]
    fn good_framing_is_well_framed_and_high_quality() {
        let r = framing_guidance(fi(1, good(centered_bbox(0.30), 2.0, -5.0)));
        assert!(r.well_framed, "guidance was: {}", r.guidance);
        assert!(r.guidance.contains("Hold still"));
        assert!(r.quality >= 80, "quality was {}", r.quality);
    }

    #[test]
    fn too_far_asks_to_move_closer() {
        let r = framing_guidance(fi(1, good(centered_bbox(0.10), 0.0, 0.0)));
        assert!(!r.well_framed);
        assert_eq!(r.guidance, "Move closer");
    }

    #[test]
    fn too_close_asks_to_move_back() {
        let r = framing_guidance(fi(1, good(centered_bbox(0.75), 0.0, 0.0)));
        assert!(!r.well_framed);
        assert_eq!(r.guidance, "Move back a little");
    }

    #[test]
    fn multiple_faces_flagged_first() {
        let r = framing_guidance(fi(2, good(centered_bbox(0.30), 0.0, 0.0)));
        assert!(!r.well_framed);
        assert!(r.guidance.contains("Multiple faces"));
    }

    #[test]
    fn yaw_turn_directions_are_corrective_not_descriptive() {
        // Fixed inversion: a face turned one way is told to turn back the other.
        let pos = framing_guidance(fi(1, good(centered_bbox(0.30), 30.0, 0.0)));
        assert_eq!(pos.guidance, "Turn your head slightly left");
        let neg = framing_guidance(fi(1, good(centered_bbox(0.30), -30.0, 0.0)));
        assert_eq!(neg.guidance, "Turn your head slightly right");
    }

    #[test]
    fn pitch_chin_directions() {
        // +pitch = chin DOWN (looking down) → corrective advice is to LIFT it.
        let down = framing_guidance(fi(1, good(centered_bbox(0.30), 0.0, 30.0)));
        assert_eq!(down.guidance, "Lift your chin a little");
        // -pitch = chin UP (looking up) → corrective advice is to LOWER it.
        let up = framing_guidance(fi(1, good(centered_bbox(0.30), 0.0, -30.0)));
        assert_eq!(up.guidance, "Lower your chin a little");
    }

    #[test]
    fn off_center_horizontal_is_corrective() {
        // Face pushed to the image-LEFT → user moved to their right → "Move left".
        let left_bbox = [10.0, 200.0, 200.0, 390.0]; // center x ≈ 105 ≪ 320
        let r = framing_guidance(fi(1, good(left_bbox, 0.0, 0.0)));
        assert_eq!(r.guidance, "Move left");
        // Face pushed to the image-RIGHT → "Move right".
        let right_bbox = [440.0, 200.0, 630.0, 390.0]; // center x ≈ 535 ≫ 320
        let r2 = framing_guidance(fi(1, good(right_bbox, 0.0, 0.0)));
        assert_eq!(r2.guidance, "Move right");
    }

    #[test]
    fn vertical_position_guidance() {
        // Face high in frame (small y) → lower yourself.
        let high = [270.0, 10.0, 370.0, 110.0];
        assert_eq!(framing_guidance(fi(1, good(high, 0.0, 0.0))).guidance, "Move your head down");
        // Face low in frame.
        let low = [270.0, 370.0, 370.0, 470.0];
        assert_eq!(framing_guidance(fi(1, good(low, 0.0, 0.0))).guidance, "Move your head up");
    }

    #[test]
    fn lighting_guidance_and_gate() {
        // Too dim: blocks well_framed even with perfect framing. (Use a luma
        // clearly below DIM_GATE so the test tracks the gate, not the boundary.)
        let dim = Some((centered_bbox(0.30), 0.0, 0.0, 30.0, 30.0, 20.0));
        let r = framing_guidance(fi(1, dim));
        assert_eq!(r.guidance, "More light on your face");
        assert!(!r.well_framed);
        // Backlit: bright surround over a genuinely DIM face (only then is it a
        // problem — a bright background over a well-exposed face is cosmetic).
        let backlit = Some((centered_bbox(0.30), 0.0, 0.0, 50.0, 130.0, 20.0));
        assert!(framing_guidance(fi(1, backlit)).guidance.contains("backlight"));
        // Bright surround but a well-exposed face must NOT be flagged backlit.
        let bright_bg_ok = Some((centered_bbox(0.30), 0.0, 0.0, 120.0, 200.0, 20.0));
        assert_eq!(
            framing_guidance(fi(1, bright_bg_ok)).guidance,
            "Hold still — ready to capture"
        );
        // Blown out.
        let bright = Some((centered_bbox(0.30), 0.0, 0.0, 240.0, 240.0, 20.0));
        assert!(framing_guidance(fi(1, bright)).guidance.contains("Too bright"));
    }

    #[test]
    fn low_light_ir_says_add_light_not_no_face() {
        let mut input = fi(1, good(centered_bbox(0.30), 0.0, 0.0));
        input.ir_present = true;
        input.low_light = true;
        let r = framing_guidance(input);
        assert!(!r.well_framed, "must not auto-capture in the dark");
        assert!(r.guidance.contains("add light"));
        assert!(r.low_light);
        assert!(r.ir_present);
    }
}

/// Standalone liveness probe for `linhello liveness-test`. Captures one frame,
/// runs detection + liveness, and returns the raw report. Never touches
/// enrollment data or embeddings.
pub fn run_liveness_test() -> Result<linhello_liveness::LivenessReport> {
    let (path, frame, face, spoof_prob, temporal_score) = capture_burst_detect()?;
    let ir = camera::capture_ir_frame().ok().flatten();
    let evaluator = linhello_liveness::LivenessEvaluator::cached()?;
    evaluator.evaluate(
        &frame, face.bbox, &face.landmarks, &path, ir.as_ref(), spoof_prob, temporal_score,
    )
}

// NOTE: the former `authenticate_user` helper (which matched against the
// plaintext `embedding.bin` directly) was removed — it bypassed the encrypted,
// TPM-keyed template store. The daemon authenticates via `load_user_samples`
// (encrypted, fail-closed) + `capture_and_embed` + `match_against`.

/// Match a live embedding against stored samples. Separated out so the
/// daemon can call this with pre-decrypted embeddings from the encrypted
/// store.
pub fn match_against(live: &[f32], samples: &[Vec<f32>]) -> AuthResult {
    let score = samples
        .iter()
        .map(|s| matcher::cosine(live, s))
        .fold(f32::NEG_INFINITY, f32::max);
    AuthResult {
        matched: score >= match_threshold(),
        score,
    }
}

/// Parse raw bytes (from decrypted storage) into embedding vectors.
pub fn parse_embeddings(raw: &[u8]) -> Result<Vec<Vec<f32>>> {
    enroll::parse_raw_embeddings(raw)
}

/// Append one face sample to the user's enrollment. File is created on
/// first call.
pub fn enroll_user(user: &str) -> Result<()> {
    let vec = capture_and_embed()?;
    enroll::append_embedding(user, &vec)
}

/// Wipe all existing samples and store a fresh single sample.
pub fn enroll_user_reset(user: &str) -> Result<()> {
    let vec = capture_and_embed()?;
    enroll::save_embedding(user, &vec)
}

pub(crate) fn bio_err(msg: impl Into<String>) -> LinuxHelloError {
    LinuxHelloError::Biometrics(msg.into())
}
