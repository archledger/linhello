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
//! `ir_score` for now: the linearly-scaled mean_face, clamped to [0, 1]
//! against an expected bright-live-skin range. We will replace this with
//! a calibrated classifier once measurements accumulate.

use image::GrayImage;

#[derive(Debug, Clone)]
pub struct IrSignals {
    pub mean_face: f32,
    pub std_face: f32,
    pub highlight_frac: f32,
    pub ir_score: f32,
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

    // Provisional score: a real face well-illuminated by the active IR
    // emitter at ~40–60 cm sits in the mid-bright band (~120–200 on an
    // 8-bit scale). A wall photo drops well below 80 because of 1/r²
    // fall-off, and a screen replay sits below 40 because screens emit
    // almost no NIR. Linear-stretch that band to [0, 1]; the caller
    // picks a threshold after calibrating on real data.
    let ir_score = ((mean - 60.0) / (160.0 - 60.0)).clamp(0.0, 1.0);

    IrSignals {
        mean_face: mean,
        std_face: std,
        highlight_frac: hi_frac,
        ir_score,
    }
}
