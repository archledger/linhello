//! 5-point similarity-transform face alignment to the ArcFace 112×112 template.
//!
//! We fit a similarity transform T(x) = s·R·x + t mapping detected landmarks
//! to the ArcFace reference points, then resample the source image via the
//! *inverse* transform with bilinear interpolation.

use crate::bio_err;
use crate::camera::Frame;
use crate::detect::Face;
use linhello_common::Result;
use image::{ImageBuffer, Rgb};

pub const OUT_SIZE: u32 = 112;

/// Canonical ArcFace landmark template for 112×112 crops (InsightFace).
const ARCFACE_TEMPLATE: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// 2×3 affine matrix stored row-major: [a, -b, tx, b, a, ty].
#[derive(Debug, Clone, Copy)]
pub struct Similarity {
    pub a: f32,
    pub b: f32,
    pub tx: f32,
    pub ty: f32,
}

impl Similarity {
    /// Forward map: src → dst.
    pub fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        (self.a * x - self.b * y + self.tx,
         self.b * x + self.a * y + self.ty)
    }

    /// Inverse map: dst → src.
    pub fn invert(&self) -> Self {
        let det = self.a * self.a + self.b * self.b;
        let ia = self.a / det;
        let ib = -self.b / det;
        let itx = -(ia * self.tx - ib * self.ty);
        let ity = -(ib * self.tx + ia * self.ty);
        Similarity { a: ia, b: ib, tx: itx, ty: ity }
    }
}

/// Fit `src → dst` via linear least squares on [a, b, tx, ty].
///
/// Each correspondence gives two equations:
///   [ x  -y  1  0 ] [a, b, tx, ty]ᵀ = x'
///   [ y   x  0  1 ]                  = y'
pub fn estimate_similarity(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> Similarity {
    // Normal equations: AᵀA · p = Aᵀb  (4×4 system).
    let mut ata = [[0.0f64; 4]; 4];
    let mut atb = [0.0f64; 4];
    for i in 0..5 {
        let (x, y) = (src[i][0] as f64, src[i][1] as f64);
        let (xp, yp) = (dst[i][0] as f64, dst[i][1] as f64);
        let rows = [[x, -y, 1.0, 0.0], [y, x, 0.0, 1.0]];
        let targets = [xp, yp];
        for (row, t) in rows.iter().zip(targets.iter()) {
            for r in 0..4 {
                for c in 0..4 {
                    ata[r][c] += row[r] * row[c];
                }
                atb[r] += row[r] * t;
            }
        }
    }
    let p = solve4(ata, atb).unwrap_or([1.0, 0.0, 0.0, 0.0]);
    Similarity { a: p[0] as f32, b: p[1] as f32, tx: p[2] as f32, ty: p[3] as f32 }
}

/// Align and crop the detected face into a 112×112 RGB image.
pub fn align(frame: &Frame, face: &Face) -> Result<Frame> {
    if frame.width() == 0 || frame.height() == 0 {
        return Err(bio_err("empty frame"));
    }
    let tform = estimate_similarity(&face.landmarks, &ARCFACE_TEMPLATE);
    let inv = tform.invert();
    Ok(warp(frame, &inv, OUT_SIZE, OUT_SIZE))
}

fn warp(src: &Frame, inv: &Similarity, w: u32, h: u32) -> Frame {
    let mut out = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(w, h);
    let (sw, sh) = (src.width() as i32, src.height() as i32);
    for y in 0..h {
        for x in 0..w {
            let (sx, sy) = inv.apply(x as f32, y as f32);
            let px = bilinear(src, sx, sy, sw, sh);
            out.put_pixel(x, y, px);
        }
    }
    out
}

fn bilinear(src: &Frame, x: f32, y: f32, sw: i32, sh: i32) -> Rgb<u8> {
    if x < 0.0 || y < 0.0 || x > (sw - 1) as f32 || y > (sh - 1) as f32 {
        return Rgb([0, 0, 0]);
    }
    let x0 = x.floor() as i32;
    let y0 = y.floor() as i32;
    let x1 = (x0 + 1).min(sw - 1);
    let y1 = (y0 + 1).min(sh - 1);
    let dx = x - x0 as f32;
    let dy = y - y0 as f32;

    let p00 = src.get_pixel(x0 as u32, y0 as u32).0;
    let p10 = src.get_pixel(x1 as u32, y0 as u32).0;
    let p01 = src.get_pixel(x0 as u32, y1 as u32).0;
    let p11 = src.get_pixel(x1 as u32, y1 as u32).0;

    let mut out = [0u8; 3];
    for c in 0..3 {
        let v = (p00[c] as f32) * (1.0 - dx) * (1.0 - dy)
            + (p10[c] as f32) * dx * (1.0 - dy)
            + (p01[c] as f32) * (1.0 - dx) * dy
            + (p11[c] as f32) * dx * dy;
        out[c] = v.clamp(0.0, 255.0) as u8;
    }
    Rgb(out)
}

/// Gaussian elimination with partial pivoting on a 4×4 system.
fn solve4(mut m: [[f64; 4]; 4], mut b: [f64; 4]) -> Option<[f64; 4]> {
    for i in 0..4 {
        let mut pivot = i;
        for r in (i + 1)..4 {
            if m[r][i].abs() > m[pivot][i].abs() {
                pivot = r;
            }
        }
        if m[pivot][i].abs() < 1e-12 {
            return None;
        }
        m.swap(i, pivot);
        b.swap(i, pivot);
        for r in (i + 1)..4 {
            let f = m[r][i] / m[i][i];
            for c in i..4 {
                m[r][c] -= f * m[i][c];
            }
            b[r] -= f * b[i];
        }
    }
    let mut x = [0.0; 4];
    for i in (0..4).rev() {
        let mut s = b[i];
        for c in (i + 1)..4 {
            s -= m[i][c] * x[c];
        }
        x[i] = s / m[i][i];
    }
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_similarity_round_trips() {
        let src = [[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366], [41.5493, 92.3655], [70.7299, 92.2041]];
        let tform = estimate_similarity(&src, &src);
        assert!((tform.a - 1.0).abs() < 1e-3);
        assert!(tform.b.abs() < 1e-3);
        assert!(tform.tx.abs() < 1e-2);
        assert!(tform.ty.abs() < 1e-2);
    }

    #[test]
    fn translation_only() {
        let src = ARCFACE_TEMPLATE;
        let dst: [[f32; 2]; 5] = std::array::from_fn(|i| [src[i][0] + 5.0, src[i][1] - 3.0]);
        let t = estimate_similarity(&src, &dst);
        assert!((t.a - 1.0).abs() < 1e-3);
        assert!(t.b.abs() < 1e-3);
        assert!((t.tx - 5.0).abs() < 1e-2);
        assert!((t.ty + 3.0).abs() < 1e-2);
    }

    #[test]
    fn invert_composes_to_identity() {
        let t = Similarity { a: 0.8, b: 0.3, tx: 12.0, ty: -4.0 };
        let inv = t.invert();
        let (x, y) = t.apply(17.0, 23.0);
        let (xb, yb) = inv.apply(x, y);
        assert!((xb - 17.0).abs() < 1e-3);
        assert!((yb - 23.0).abs() < 1e-3);
    }
}
