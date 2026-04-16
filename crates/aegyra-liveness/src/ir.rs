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
//! Current implementation is a **raw heuristic** — we compute summary
//! statistics on the IR frame and surface them as `ir_score` without
//! gating. That lets the operator tune a threshold against their actual
//! rig before we promote the signal to a hard gate.
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
//! Pure mean is ambiguous (real-far and photo overlap). `hi-frac` is
//! decisive — eye glints + illumination hotspots only appear on a live
//! 3D face close enough to the emitter for specular returns. We require
//! the face to fill ≥25% of the RGB frame before trusting IR at all;
//! below that, reject with "move closer" rather than accepting a weak
//! signal (same UX constraint Windows Hello lives with).

use image::GrayImage;

/// Minimum face width / frame width before IR signals are trustworthy.
/// Below this, reject with "move closer" — IR returns fall off as 1/r²
/// so a real face at arm's length can score the same as a wall photo.
pub const MIN_FACE_FRAC: f32 = 0.25;

/// All three conditions must hold simultaneously for a PASS. Derived from
/// the one-shot calibration above; tighten later if we see false rejects.
const MIN_MEAN: f32 = 120.0;
const MIN_STD: f32 = 25.0;
const MIN_HIGHLIGHT_FRAC: f32 = 0.08;

#[derive(Debug, Clone)]
pub struct IrSignals {
    pub mean_face: f32,
    pub std_face: f32,
    pub highlight_frac: f32,
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
pub fn classify(s: &IrSignals, face_frac: f32) -> IrVerdict {
    if face_frac < MIN_FACE_FRAC {
        return IrVerdict::TooFar;
    }
    if s.mean_face < MIN_MEAN {
        return IrVerdict::Reject("IR illumination too low (face not close enough to emitter)");
    }
    if s.highlight_frac < MIN_HIGHLIGHT_FRAC {
        return IrVerdict::Reject("no eye-glint / hotspot pattern (characteristic of flat surface)");
    }
    if s.std_face < MIN_STD {
        return IrVerdict::Reject("IR intensity too uniform (characteristic of flat surface)");
    }
    IrVerdict::Real
}

/// Compute IR signals from `ir` using `rgb_bbox` (frame-space pixels of
/// the RGB detector) rescaled into IR frame coordinates. We assume the
/// two sensors are coaxial enough that a proportional mapping is good
/// to a few percent — close enough for a statistical signal. For a
/// hard-gate-grade signal we'd cross-calibrate with a checkerboard.
///
/// `rgb_size` is `(rgb_width, rgb_height)` in pixels.
pub fn evaluate(ir: &GrayImage, rgb_bbox: [f32; 4], rgb_size: (u32, u32)) -> IrSignals {
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
        return IrSignals {
            mean_face: 0.0,
            std_face: 0.0,
            highlight_frac: 0.0,
            ir_score: 0.0,
        };
    }

    let mean = sum as f32 / n as f32;
    // var = E[x²] - (E[x])² ; clamp against rounding noise
    let var = (sum_sq as f32 / n as f32 - mean * mean).max(0.0);
    let std = var.sqrt();
    let hi_frac = hi as f32 / n as f32;

    // Score is the *joint* satisfaction of all three thresholds: 1.0 if
    // every one clears, else the worst-performing fraction. Single-signal
    // scoring hides the fact that real-far and wall-photo can match on
    // mean alone; only requiring all three signals simultaneously gives
    // the ≫10× separation we saw in calibration.
    let mean_ok = (mean / MIN_MEAN).min(1.0);
    let std_ok = (std / MIN_STD).min(1.0);
    let hi_ok = (hi_frac / MIN_HIGHLIGHT_FRAC).min(1.0);
    let ir_score = mean_ok.min(std_ok).min(hi_ok);

    IrSignals {
        mean_face: mean,
        std_face: std,
        highlight_frac: hi_frac,
        ir_score,
    }
}
