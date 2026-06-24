//! Active-IR liveness signal.
//!
//! Laptops with a Windows-Hello-class face sensor ship a dedicated IR
//! camera + a ~850 nm illuminator a few cm from the lens. When the IR
//! device is opened the illuminator fires, so anything at close range
//! (a real user's face ~40–60 cm away) gets strongly lit while anything
//! further away (a photo on the wall ~1.5–2 m away) falls off as 1/r².
//! That geometry is the single strongest defeater of the print-attack
//! class that RGB-only anti-spoof struggles with.
//!
//! On real hardware both IR cues — the face/background intensity ratio and the
//! near-saturated "glint" fraction — proved too rig/lighting/pose-dependent to
//! hard-gate on. A 2026-06-02 bring-up on Ben's ASUS rig saw a live user
//! rejected on glints ~75% of the time, and the face/bg ratio straddling 1.0
//! (face often *darker* than background) with a ~3× darker IR frame than the
//! original calibration — so the ratio gate vetoed the user, and worse, did so
//! *before* the trained ML anti-spoof ever ran.
//!
//! Therefore **IR is advisory**: its statistics fold into `ir_score` for
//! telemetry/confidence but do not reject on their own. The liveness gate is
//! the **mandatory ML anti-spoof model + virtual-camera (device-trust) +
//! head-orientation** checks. The only IR-derived hard outcome kept is the
//! framing hint `TooFar` (face too small to recognise reliably). All raw IR
//! stats remain in the `ir_*` signals for auditing and future re-tuning.
//!
//! Signals extracted:
//!   * `mean_face`        — mean intensity in the bbox region mapped
//!     proportionally from the RGB frame to the IR frame.
//!   * `std_face`         — standard deviation inside the same region
//!     (real faces have structure; flat photos at distance are uniform).
//!   * `highlight_frac`   — fraction of near-saturated pixels (>240)
//!     inside the face region. Real skin under active IR shows two
//!     bright eye-glints; a flat photo either has no glints or (for
//!     glossy paper) a single diffuse hotspot.
//!
//! Calibration (Ben's ASUS FHD + IR, 2026-04-15):
//!
//!   real face @ 50 cm : mean 185, std 70, hi-frac 0.416  ← PASS
//!   real face @ 70 cm : mean  68, std 23, hi-frac 0.000  ← reject as "move closer"
//!   wall photo (2 m)  : mean  84, std 36, hi-frac 0.000  ← reject
//!
//! These per-distance numbers are why IR is advisory (see above). The only
//! framing requirement we keep is that the face fill ≥`MIN_FACE_FRAC` (0.15) of
//! the RGB frame — below that it's too small to recognise reliably, so we
//! return "move closer" (the same UX constraint Windows Hello lives with).

use image::GrayImage;
use serde::{Deserialize, Serialize};

/// Minimum face width / frame width before we accept the frame for
/// recognition. Below this the face is too small to recognise reliably, so we
/// return `TooFar` ("move closer"). Set to 0.15 after on-hardware testing:
/// a normal laptop-on-desk sitting distance lands at ~0.19–0.25, and 0.20 was
/// occasionally tripping the prompt; 0.15 gives comfortable margin while still
/// rejecting genuinely-too-far framing.
pub const MIN_FACE_FRAC: f32 = 0.15;

/// Minimum face/background IR intensity ratio. A real face under the
/// emitter at normal laptop distance should have ratio ≥ 1.3 (face is
/// 30%+ brighter than surroundings because the emitter concentrates on
/// it). A flat photo of a face on a wall has ratio ~1.0 (same surface,
/// same ambient illumination). This signal is AE-gain-invariant.
const MIN_FACE_BG_RATIO: f32 = 1.2;

/// Soft-confidence threshold for the highlight fraction used in `ir_score`:
/// hi_frac ≥ 0.08 → full confidence; below it the score leans on
/// face_bg_ratio. Glints are *not* a hard gate — see the module docs for why.
const MIN_HIGHLIGHT_FRAC: f32 = 0.08;

#[derive(Debug, Clone)]
pub struct IrSignals {
    pub mean_face: f32,
    pub std_face: f32,
    pub highlight_frac: f32,
    /// Mean IR intensity of pixels OUTSIDE the face bbox.
    pub mean_bg: f32,
    /// `mean_face / mean_bg`. A real face under the active emitter is
    /// brighter than the background (emitter concentrates on what's in
    /// front). A flat photo at distance has ratio ~1.0 because the "face"
    /// area reflects the same ambient IR as the surrounding surface.
    /// AE-gain-invariant — the main advantage over absolute thresholds.
    pub face_bg_ratio: f32,
    /// Strength of the weaker eye's specular IR glint (brightest pixel minus
    /// local mean in a small window at each eye landmark, min of the two). The
    /// active emitter reflects off a real 3D cornea as a sharp highlight; a flat
    /// photo/screen produces little or diffuse reflection. A strong active-IR
    /// liveness cue — see Phase 2. Advisory until calibrated on hardware.
    pub eye_glint: f32,
    pub ir_score: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrVerdict {
    /// All thresholds met — pass the IR gate.
    Real,
    /// Face too small in frame to trust IR. Operator should move closer.
    TooFar,
    /// IR signals below threshold despite adequate framing — likely spoof.
    Reject(&'static str),
}

/// Given the computed signals and the RGB face coverage, produce a
/// verdict. Kept separate from `evaluate` so the gating policy is
/// auditable independently of the image processing.
pub fn classify(_s: &IrSignals, face_frac: f32) -> IrVerdict {
    if face_frac < MIN_FACE_FRAC {
        // The one hard IR-derived outcome we keep: a face too small in frame
        // can't be recognised reliably. This is a framing hint, not a spoof
        // verdict — the caller turns it into "move closer".
        return IrVerdict::TooFar;
    }
    // IR ratio and glints are advisory only (folded into `ir_score` by
    // `evaluate`): on real hardware the emitter's differential illumination is
    // too rig/lighting-dependent to hard-gate on without false-rejecting live
    // users. The liveness gate is the mandatory ML anti-spoof + virtual-camera
    // + orientation checks. See the module docs.
    IrVerdict::Real
}

/// Compute IR signals from `ir` using `rgb_bbox` (frame-space pixels of
/// the RGB detector) rescaled into IR frame coordinates. We assume the
/// two sensors are coaxial enough that a proportional mapping is good
/// to a few percent — close enough for a statistical signal. For a
/// hard-gate-grade signal we'd cross-calibrate with a checkerboard.
///
/// `rgb_size` is `(rgb_width, rgb_height)` in pixels. `landmarks` are the 5
/// SCRFD points (RGB pixels) — eyes [0],[1] are used for the glint probe.
pub fn evaluate(
    ir: &GrayImage,
    rgb_bbox: [f32; 4],
    rgb_size: (u32, u32),
    landmarks: &[[f32; 2]; 5],
) -> IrSignals {
    let (rw, rh) = (rgb_size.0 as f32, rgb_size.1 as f32);
    let (iw, ih) = (ir.width() as f32, ir.height() as f32);

    // Proportional bbox rescale.
    let sx = iw / rw.max(1.0);
    let sy = ih / rh.max(1.0);
    let x1 = (rgb_bbox[0] * sx).clamp(0.0, iw - 1.0) as u32;
    let y1 = (rgb_bbox[1] * sy).clamp(0.0, ih - 1.0) as u32;
    let x2 = (rgb_bbox[2] * sx).clamp(0.0, iw - 1.0) as u32;
    let y2 = (rgb_bbox[3] * sy).clamp(0.0, ih - 1.0) as u32;
    let (x1, x2) = (x1.min(x2), x1.max(x2).max(x1 + 1).min(ir.width() - 1));
    let (y1, y2) = (y1.min(y2), y1.max(y2).max(y1 + 1).min(ir.height() - 1));

    let mut n: u64 = 0;
    let mut sum: u64 = 0;
    let mut sum_sq: u64 = 0;
    let mut hi: u64 = 0;
    for y in y1..=y2 {
        for x in x1..=x2 {
            let v = ir.get_pixel(x, y).0[0] as u64;
            sum += v;
            sum_sq += v * v;
            if v > 240 {
                hi += 1;
            }
            n += 1;
        }
    }
    if n == 0 {
        return empty_signals();
    }

    let mean = sum as f32 / n as f32;
    let var = (sum_sq as f32 / n as f32 - mean * mean).max(0.0);
    let std = var.sqrt();
    let hi_frac = hi as f32 / n as f32;

    // Background: mean of all pixels OUTSIDE the face bbox.
    let total_px = ir.width() as u64 * ir.height() as u64;
    let bg_n = total_px.saturating_sub(n);
    let frame_sum: u64 = ir.pixels().map(|p| p.0[0] as u64).sum();
    let bg_sum = frame_sum.saturating_sub(sum);
    let mean_bg = if bg_n > 0 {
        bg_sum as f32 / bg_n as f32
    } else {
        1.0
    };
    let face_bg_ratio = if mean_bg > 1.0 {
        mean / mean_bg
    } else {
        mean
    };

    // Score: face/background ratio normalized against the minimum
    // expected for a real face under the emitter. Ratio ≥ MIN_FACE_BG_RATIO
    // means the emitter is differentially illuminating the face region —
    // signature of a 3D object close to the source, not a flat surface
    // at ambient-IR distance.
    let ratio_ok = (face_bg_ratio / MIN_FACE_BG_RATIO).min(1.0);
    let hi_ok = (hi_frac / MIN_HIGHLIGHT_FRAC).min(1.0);
    let ir_score = ratio_ok.min(hi_ok.max(0.5));

    // Eye glints: search a window at each eye landmark (rescaled to IR) for the
    // specular spike (brightest pixel − window mean), and require both eyes by
    // taking the weaker. The window is generous (~1/8 of face width) because the
    // RGB and IR sensors are parallax-offset, so the mapped eye point is only
    // approximate; a tight window would miss the cornea.
    let glint_r = (((x2 - x1) as i32) / 8).clamp(8, 28);
    let eye_px = |lm: [f32; 2]| ((lm[0] * sx) as i32, (lm[1] * sy) as i32);
    let (lx, ly) = eye_px(landmarks[0]);
    let (rx, ry) = eye_px(landmarks[1]);
    let eye_glint = eye_glint_at(ir, lx, ly, glint_r).min(eye_glint_at(ir, rx, ry, glint_r));

    IrSignals {
        mean_face: mean,
        std_face: std,
        highlight_frac: hi_frac,
        mean_bg,
        face_bg_ratio,
        eye_glint,
        ir_score,
    }
}

/// Specular-glint strength in a window centred at `(cx, cy)`: brightest pixel
/// minus the window mean. A sharp corneal reflection spikes well above the
/// local baseline; a flat surface barely does.
fn eye_glint_at(ir: &GrayImage, cx: i32, cy: i32, r: i32) -> f32 {
    let (w, h) = (ir.width() as i32, ir.height() as i32);
    let (mut sum, mut n, mut maxv) = (0u64, 0u64, 0u8);
    for y in (cy - r).max(0)..=(cy + r).min(h - 1) {
        for x in (cx - r).max(0)..=(cx + r).min(w - 1) {
            let v = ir.get_pixel(x as u32, y as u32).0[0];
            sum += v as u64;
            n += 1;
            maxv = maxv.max(v);
        }
    }
    if n == 0 {
        return 0.0;
    }
    (maxv as f32 - sum as f32 / n as f32).max(0.0)
}

// ── Enrollment-calibrated active-IR liveness gate ───────────────────────────
//
// The raw IR cues (face/background ratio, corneal glint) are too rig/lighting/
// pose-dependent to hard-gate on with ABSOLUTE thresholds — that false-rejected
// live users ~75% of the time, which is why IR was demoted to advisory. The fix
// is to calibrate PER USER at enrollment: record the live user's own IR cue
// distribution, then at auth require the live signature to stay within that
// envelope. A flat photo or a screen replay can't reproduce it (a screen emits
// almost no NIR → dark face region + no twin corneal glints; a far photo has no
// active-emitter face/bg lift), while the genuine user — measured against their
// OWN enrolled values, not a one-size threshold — passes. The gate is ADDITIVE
// to the ML anti-spoof (both must pass), so it only ever tightens security.

/// One IR observation captured from the live user (at enrollment) or the current
/// attempt (at auth). Only the AE-gain-invariant, per-user-stable cues are kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrObservation {
    pub face_bg_ratio: f32,
    pub eye_glint: f32,
    pub ir_score: f32,
    /// Face fill at capture time — recorded for context/auditing (the gate runs
    /// only past the `MIN_FACE_FRAC` framing check, so all observations are close).
    pub face_frac: f32,
}

impl IrObservation {
    /// Extract an observation from a finished [`crate::LivenessSignals`], or
    /// `None` if no IR frame contributed (so the caller can fail closed).
    pub fn from_signals(s: &crate::LivenessSignals) -> Option<Self> {
        Some(IrObservation {
            face_bg_ratio: s.ir_face_bg_ratio?,
            eye_glint: s.ir_eye_glint?,
            ir_score: s.ir_score?,
            face_frac: s.face_frac?,
        })
    }
}

/// Per-user IR liveness envelope, accumulated across enrollment captures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IrCalibration {
    pub observations: Vec<IrObservation>,
}

/// Outcome of gating a live observation against the enrolled envelope.
#[derive(Debug, Clone, PartialEq)]
pub enum IrGate {
    /// Live IR signature is consistent with the enrolled live user.
    Pass,
    /// Live IR cues fell below the enrolled envelope — likely a presentation
    /// attack (flat photo / screen replay).
    Reject(String),
    /// Too few enrolled IR observations to gate (legacy / non-IR enrollment).
    NotCalibrated,
}

/// Minimum IR observations before the gate engages. Below this we stay advisory
/// (legacy profiles, or hardware where IR rarely captured during enroll).
pub const MIN_CALIBRATION_OBSERVATIONS: usize = 3;

fn env_margin(var: &str, default: f32) -> f32 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1.0)
        .unwrap_or(default)
}

impl IrCalibration {
    pub fn is_ready(&self) -> bool {
        self.observations.len() >= MIN_CALIBRATION_OBSERVATIONS
    }

    pub fn push(&mut self, o: IrObservation) {
        self.observations.push(o);
    }

    /// Robust low-end of a cue: ~20th percentile (so one noisy enroll frame
    /// doesn't set the floor), but never below the smallest sample for tiny N.
    fn robust_low(mut vals: Vec<f32>) -> f32 {
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        if vals.is_empty() {
            return 0.0;
        }
        let idx = (((vals.len() as f32) * 0.2).floor() as usize).min(vals.len() - 1);
        vals[idx]
    }

    /// Gate a live observation. Rejects only when BOTH active-IR cues fall below
    /// the user's own enrolled envelope (margined) — lenient to the genuine user
    /// (who shows at least one cue), strict on flat media (which shows neither).
    /// Margins are tunable via `LINHELLO_IR_RATIO_MARGIN` / `LINHELLO_IR_GLINT_MARGIN`.
    pub fn gate(&self, live: &IrObservation) -> IrGate {
        if !self.is_ready() {
            return IrGate::NotCalibrated;
        }
        let ratio_ref = Self::robust_low(self.observations.iter().map(|o| o.face_bg_ratio).collect());
        let glint_ref = Self::robust_low(self.observations.iter().map(|o| o.eye_glint).collect());
        let ratio_thr = ratio_ref * env_margin("LINHELLO_IR_RATIO_MARGIN", 0.7);
        let glint_thr = glint_ref * env_margin("LINHELLO_IR_GLINT_MARGIN", 0.5);

        let ratio_absent = live.face_bg_ratio < ratio_thr;
        let glint_absent = live.eye_glint < glint_thr;
        if ratio_absent && glint_absent {
            IrGate::Reject(format!(
                "active-IR liveness below your enrolled profile (face/bg {:.2} < {:.2} AND eye-glint {:.0} < {:.0}) — looks like a photo or screen, not a live face",
                live.face_bg_ratio, ratio_thr, live.eye_glint, glint_thr
            ))
        } else {
            IrGate::Pass
        }
    }
}

fn empty_signals() -> IrSignals {
    IrSignals {
        mean_face: 0.0,
        std_face: 0.0,
        highlight_frac: 0.0,
        mean_bg: 0.0,
        face_bg_ratio: 0.0,
        eye_glint: 0.0,
        ir_score: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(face_bg_ratio: f32, highlight_frac: f32) -> IrSignals {
        IrSignals {
            mean_face: 180.0,
            std_face: 60.0,
            highlight_frac,
            mean_bg: 100.0,
            face_bg_ratio,
            eye_glint: 0.0,
            ir_score: 0.0,
        }
    }

    #[test]
    fn eye_glint_detects_specular_spike() {
        use image::{GrayImage, Luma};
        // Flat grey image → no glint.
        let flat = GrayImage::from_pixel(64, 64, Luma([90]));
        assert_eq!(super::eye_glint_at(&flat, 32, 32, 5), 0.0);
        // Add a bright specular spot at (32,32) → glint spikes.
        let mut spot = GrayImage::from_pixel(64, 64, Luma([90]));
        spot.put_pixel(32, 32, Luma([255]));
        assert!(super::eye_glint_at(&spot, 32, 32, 5) > 100.0);
    }

    #[test]
    fn live_face_passes() {
        // Ben's calibrated real-face values: ratio well above 1.2, glints 0.416.
        assert_eq!(classify(&sig(1.8, 0.416), 0.45), IrVerdict::Real);
    }

    #[test]
    fn too_far_when_face_small() {
        assert_eq!(classify(&sig(1.8, 0.416), 0.10), IrVerdict::TooFar);
    }

    #[test]
    fn low_ratio_no_longer_hard_rejects() {
        // IR ratio is advisory now: a low ratio (which on real hardware also
        // occurs for live users with a dark IR frame) must NOT reject. The
        // print/screen defense is the mandatory ML anti-spoof, not this.
        assert_eq!(classify(&sig(1.0, 0.4), 0.45), IrVerdict::Real);
        assert_eq!(classify(&sig(0.85, 0.006), 0.24), IrVerdict::Real); // Ben's live rig
    }

    #[test]
    fn glintless_face_passes_ir_gate() {
        // Glints are advisory too — a frame without glints still passes IR.
        assert_eq!(classify(&sig(1.5, 0.0), 0.45), IrVerdict::Real);
    }

    fn obs(face_bg_ratio: f32, eye_glint: f32) -> IrObservation {
        IrObservation { face_bg_ratio, eye_glint, ir_score: 0.8, face_frac: 0.3 }
    }

    fn live_cal() -> IrCalibration {
        // A genuine user's enrolled envelope: strong face/bg lift + corneal glints.
        IrCalibration {
            observations: vec![
                obs(1.6, 45.0), obs(1.5, 38.0), obs(1.7, 52.0), obs(1.55, 41.0),
            ],
        }
    }

    #[test]
    fn calibration_not_ready_below_min_observations() {
        let cal = IrCalibration { observations: vec![obs(1.6, 45.0), obs(1.5, 40.0)] };
        assert_eq!(cal.gate(&obs(1.0, 1.0)), IrGate::NotCalibrated);
    }

    #[test]
    fn live_user_passes_their_own_envelope() {
        assert_eq!(live_cal().gate(&obs(1.5, 40.0)), IrGate::Pass);
        // Even a somewhat-low frame passes while ONE cue stays healthy.
        assert_eq!(live_cal().gate(&obs(1.0, 40.0)), IrGate::Pass); // glint healthy
        assert_eq!(live_cal().gate(&obs(1.6, 5.0)), IrGate::Pass);  // ratio healthy
    }

    #[test]
    fn flat_photo_or_screen_rejected() {
        // Screen replay / matte photo: no face/bg lift AND no twin corneal glint.
        assert!(matches!(live_cal().gate(&obs(1.0, 2.0)), IrGate::Reject(_)));
        assert!(matches!(live_cal().gate(&obs(0.9, 0.0)), IrGate::Reject(_)));
    }

    #[test]
    fn from_signals_requires_ir_fields() {
        let mut s = crate::LivenessSignals::empty();
        assert!(IrObservation::from_signals(&s).is_none());
        s.ir_face_bg_ratio = Some(1.5);
        s.ir_eye_glint = Some(40.0);
        s.ir_score = Some(0.8);
        s.face_frac = Some(0.3);
        assert!(IrObservation::from_signals(&s).is_some());
    }
}
