//! Passive temporal liveness: eye micro-motion across a short frame burst.
//! **Experimental — OFF by default** (`LINHELLO_TEMPORAL_GATE=1` to opt in).
//!
//! Idea: a live person's eyes are never still (microsaccades, gaze shifts, blinks)
//! while a static photo/screen image is identical frame to frame; sampling each eye
//! patch RELATIVE to that frame's own eye landmark removes global motion so (in
//! theory) only genuine eye dynamics survive.
//!
//! Reality (on-hardware validation, 2026-06-23): eye-motion *magnitude* over a
//! ~0.4s burst does NOT separate a live face from a HAND-HELD photo. The photo's
//! hand jitter + motion blur produced scores of 11–21 vs a live face's 10–14 —
//! overlapping, photo sometimes higher. Landmark-alignment removes pure
//! translation but not blur or detector jitter. Only a *blink* (the eye-closure
//! pattern) is qualitatively distinct from jitter, which needs a longer window or
//! an active "blink" challenge. So this magnitude score is kept as TELEMETRY and a
//! foundation for a future blink-challenge; the gate is opt-in and must never be
//! the sole defense (the ML anti-spoof + calibrated IR remain primary). A *video*
//! replay would defeat motion entirely — that is what IR/depth are for.

use image::RgbImage;

/// Side length of the normalized grayscale eye patch.
const PATCH: usize = 16;
/// Eye-patch half-window in source pixels, as a fraction of the inter-ocular
/// distance — large enough to contain the eye + lid through a blink, small enough
/// to exclude the brow/cheek (which a head-tilt would move and confound).
const EYE_WIN_FRAC: f32 = 0.30;
/// Floor on the half-window so a small/distant face still yields a usable patch.
const MIN_WIN_PX: f32 = 6.0;

/// Per-frame landmark-aligned grayscale descriptors for both eyes.
#[derive(Clone)]
pub struct EyeFrame {
    left: [u8; PATCH * PATCH],
    right: [u8; PATCH * PATCH],
}

/// Extract both eye patches from `frame` using the 5 SCRFD landmarks
/// ([left_eye, right_eye, nose, ...]). Patches are sampled around the eye points,
/// so they track the eye through global motion.
pub fn eye_frame(frame: &RgbImage, landmarks: &[[f32; 2]; 5]) -> EyeFrame {
    // Window scales with inter-ocular distance so it's framing-invariant.
    let dx = landmarks[1][0] - landmarks[0][0];
    let dy = landmarks[1][1] - landmarks[0][1];
    let iod = (dx * dx + dy * dy).sqrt();
    let r = (iod * EYE_WIN_FRAC).max(MIN_WIN_PX);
    EyeFrame {
        left: extract_patch(frame, landmarks[0], r),
        right: extract_patch(frame, landmarks[1], r),
    }
}

/// Nearest-neighbour-downsample a `2r×2r` box centred on `c` to a `PATCH×PATCH`
/// grayscale patch. Out-of-frame samples read 0.
fn extract_patch(frame: &RgbImage, c: [f32; 2], r: f32) -> [u8; PATCH * PATCH] {
    let (w, h) = (frame.width() as i32, frame.height() as i32);
    let x0 = (c[0] - r).round() as i32;
    let y0 = (c[1] - r).round() as i32;
    let side = (2.0 * r).max(1.0);
    let mut out = [0u8; PATCH * PATCH];
    for py in 0..PATCH {
        for px in 0..PATCH {
            let sx = x0 + (px as f32 * side / PATCH as f32) as i32;
            let sy = y0 + (py as f32 * side / PATCH as f32) as i32;
            out[py * PATCH + px] = if sx >= 0 && sy >= 0 && sx < w && sy < h {
                let p = frame.get_pixel(sx as u32, sy as u32).0;
                ((p[0] as u32 * 30 + p[1] as u32 * 59 + p[2] as u32 * 11) / 100) as u8
            } else {
                0
            };
        }
    }
    out
}

/// Mean-subtracted L1 distance between two patches. Mean subtraction makes it
/// invariant to overall brightness change (auto-exposure flicker), so only
/// *structural* change in the eye region counts.
fn patch_diff(a: &[u8], b: &[u8]) -> f32 {
    let n = a.len() as f32;
    let ma = a.iter().map(|&v| v as f32).sum::<f32>() / n;
    let mb = b.iter().map(|&v| v as f32).sum::<f32>() / n;
    let mut s = 0.0;
    for i in 0..a.len() {
        s += (((a[i] as f32) - ma) - ((b[i] as f32) - mb)).abs();
    }
    s / n
}

/// Temporal eye-motion score across a burst: the mean consecutive-frame eye-patch
/// difference, taking the MAX of the two eyes (one moving eye is enough — the
/// other may be occluded by a glint or hair). `None` when fewer than 2 frames had
/// a detected face (can't measure motion → caller stays advisory).
pub fn motion_score(seq: &[EyeFrame]) -> Option<f32> {
    if seq.len() < 2 {
        return None;
    }
    let mut left = 0.0f32;
    let mut right = 0.0f32;
    for w in seq.windows(2) {
        left += patch_diff(&w[0].left, &w[1].left);
        right += patch_diff(&w[0].right, &w[1].right);
    }
    let n = (seq.len() - 1) as f32;
    Some((left / n).max(right / n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    fn lm(eye_l: [f32; 2], eye_r: [f32; 2]) -> [[f32; 2]; 5] {
        [eye_l, eye_r, [56.0, 70.0], [42.0, 92.0], [70.0, 92.0]]
    }

    #[test]
    fn static_image_scores_near_zero() {
        // Identical frames (a still photo) → no eye change.
        let mut img = RgbImage::from_pixel(112, 112, Rgb([120, 120, 120]));
        // some structure in the eye region so a patch isn't flat
        img.put_pixel(38, 51, Rgb([10, 10, 10]));
        img.put_pixel(74, 51, Rgb([10, 10, 10]));
        let l = lm([38.0, 51.0], [74.0, 51.0]);
        let seq: Vec<EyeFrame> = (0..6).map(|_| eye_frame(&img, &l)).collect();
        let s = motion_score(&seq).unwrap();
        assert!(s < 1.0, "static score {s} should be ~0");
    }

    #[test]
    fn changing_eye_region_scores_high() {
        // Eye pixel toggles dark/bright between frames (a blink/saccade) → high score.
        let l = lm([38.0, 51.0], [74.0, 51.0]);
        let seq: Vec<EyeFrame> = (0..6)
            .map(|i| {
                let v = if i % 2 == 0 { 10 } else { 230 };
                let mut img = RgbImage::from_pixel(112, 112, Rgb([120, 120, 120]));
                // fill the eye windows with the toggling value
                for yy in 40..62 {
                    for xx in 28..48 {
                        img.put_pixel(xx, yy, Rgb([v, v, v]));
                    }
                    for xx in 64..84 {
                        img.put_pixel(xx, yy, Rgb([v, v, v]));
                    }
                }
                eye_frame(&img, &l)
            })
            .collect();
        let s = motion_score(&seq).unwrap();
        assert!(s > 20.0, "moving score {s} should be high");
    }

    #[test]
    fn too_few_frames_is_none() {
        let img = RgbImage::from_pixel(112, 112, Rgb([120, 120, 120]));
        let l = lm([38.0, 51.0], [74.0, 51.0]);
        assert!(motion_score(&[eye_frame(&img, &l)]).is_none());
    }
}
