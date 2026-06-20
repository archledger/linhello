//! MiniFASNet anti-spoof inference.
//!
//! Reference: `minivision-ai/Silent-Face-Anti-Spoofing`. Upstream's own
//! `test.py` runs a *dual-model ensemble* — a 2.7×-crop `MiniFASNetV2` and a
//! 4.0×-crop `MiniFASNetV1SE` — and sums the softmax outputs before picking
//! a class. Single-model MiniFASNet is known-weak against printed-photo
//! attacks (empirically observed on Ben's setup: real face 0.001,
//! large printed photo 0.03–0.13; no safe threshold between them).
//!
//! We replicate the ensemble: each `(session, scale)` pair produces a
//! 3-way softmax; we average across models, then treat class 1 as "real"
//! so `spoof_prob = 1 - avg_p[1]`. If only one model is configured we
//! fall back to single-model behaviour (still useful, just weaker).
//!
//! Input shape per model: `[1, 3, 80, 80]` BGR float32, raw 0–255 (no
//! mean/std). Scaled-crop logic matches upstream's `CropImage`.

use linhello_common::{LinuxHelloError, Result};
use image::{imageops::FilterType, RgbImage};
use ndarray::Array4;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Value;
use std::path::Path;
use std::sync::{Mutex, Once};

const INPUT_SIZE: u32 = 80;

static ORT_INIT: Once = Once::new();

/// Idempotent ORT init. Mirrors `linhello-biometrics::ort_init` so we don't
/// pull that crate as a dep (it would create a circular graph with biometrics
/// consuming liveness). Both resolve the dylib via `linhello_common::platform`.
fn ensure_ort() -> Result<()> {
    ORT_INIT.call_once(|| {
        if std::env::var_os("ORT_DYLIB_PATH").is_none() {
            if let Some(path) = linhello_common::platform::onnxruntime_dylib() {
                std::env::set_var("ORT_DYLIB_PATH", path);
            }
        }
        // ort rc.12: commit() returns bool (false = an environment was already
        // committed elsewhere) and no longer loads the dylib here — ONNX Runtime
        // is loaded lazily on the first Session, where a missing/broken
        // libonnxruntime is reported (the path probe above keeps that actionable).
        let _ = ort::init().with_name("linhello-liveness").commit();
    });
    Ok(())
}

struct Member {
    session: Mutex<Session>,
    scale: f32,
    label: String,
}

pub struct AntiSpoofModel {
    members: Vec<Member>,
}

impl AntiSpoofModel {
    /// Load a single model at `path` using `scale` for the pre-crop. Kept
    /// as a thin wrapper over `load_ensemble` for existing single-model
    /// callers.
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_ensemble(&[(path, 2.7, "single")])
    }

    /// Load an ensemble. Each entry is `(path, pre-crop scale, label)`.
    /// Labels are only used in error messages.
    pub fn load_ensemble(items: &[(&Path, f32, &str)]) -> Result<Self> {
        if items.is_empty() {
            return Err(LinuxHelloError::Biometrics(
                "anti-spoof ensemble is empty".into(),
            ));
        }
        ensure_ort()?;
        let mut members = Vec::with_capacity(items.len());
        for (path, scale, label) in items {
            if !path.exists() {
                return Err(LinuxHelloError::Biometrics(format!(
                    "anti-spoof model ({label}) not found at {}",
                    path.display()
                )));
            }
            let session = Session::builder()
                .map_err(|e| LinuxHelloError::Biometrics(format!("ort builder: {e}")))?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(|e| LinuxHelloError::Biometrics(format!("opt level: {e}")))?
                .commit_from_file(path)
                .map_err(|e| {
                    LinuxHelloError::Biometrics(format!("load anti-spoof ({label}): {e}"))
                })?;
            members.push(Member {
                session: Mutex::new(session),
                scale: *scale,
                label: (*label).to_string(),
            });
        }
        Ok(Self { members })
    }

    /// Predict spoof probability (0.0 = real, 1.0 = spoof) for `frame` with
    /// face bbox `[x1, y1, x2, y2]`. For an ensemble we sum softmax outputs
    /// across members, average by count, and take class 1 as "real" — the
    /// approach upstream uses in `test.py`.
    pub fn predict(&self, frame: &RgbImage, bbox: [f32; 4]) -> Result<f32> {
        // Three-class convention [fake_print, real, fake_screen]; binary
        // models still work because we only look at index 1.
        let mut sum = [0.0f32; 3];
        for m in &self.members {
            let crop = crop_scaled(frame, bbox, m.scale, INPUT_SIZE);
            let arr = preprocess(&crop);
            let input = Value::from_array(arr).map_err(|e| {
                LinuxHelloError::Biometrics(format!("build input ({}): {e}", m.label))
            })?;
            let mut session = m.session.lock().unwrap();
            let outputs = session.run(ort::inputs![input]).map_err(|e| {
                LinuxHelloError::Biometrics(format!("antispoof inference ({}): {e}", m.label))
            })?;
            let (_shape, data) = outputs[0].try_extract_tensor::<f32>().map_err(|e| {
                LinuxHelloError::Biometrics(format!("extract ({}): {e}", m.label))
            })?;
            let logits = data.to_vec();
            if logits.len() < 2 {
                return Err(LinuxHelloError::Biometrics(format!(
                    "unexpected antispoof output shape from {} (len {})",
                    m.label,
                    logits.len()
                )));
            }
            let probs = softmax(&logits);
            for i in 0..sum.len().min(probs.len()) {
                sum[i] += probs[i];
            }
        }
        let real_p = sum[1] / self.members.len() as f32;
        Ok((1.0 - real_p).clamp(0.0, 1.0))
    }
}

/// Expand `bbox` around its center by `scale`, clip to frame bounds, and
/// resize the crop to `out×out`. Matches `CropImage._get_new_box` from
/// minivision-ai/Silent-Face-Anti-Spoofing.
fn crop_scaled(frame: &RgbImage, bbox: [f32; 4], scale: f32, out: u32) -> RgbImage {
    let (fw, fh) = (frame.width() as f32, frame.height() as f32);
    let [x1, y1, x2, y2] = bbox;
    let box_w = (x2 - x1).max(1.0);
    let box_h = (y2 - y1).max(1.0);
    let cx = x1 + box_w / 2.0;
    let cy = y1 + box_h / 2.0;

    // Repo clamps scale so the expanded box fits within frame; we do the same.
    let eff = scale.min(((fh - 1.0) / box_h).min((fw - 1.0) / box_w));
    let new_w = box_w * eff;
    let new_h = box_h * eff;

    let mut lx = cx - new_w / 2.0;
    let mut ly = cy - new_h / 2.0;
    let mut rx = cx + new_w / 2.0;
    let mut ry = cy + new_h / 2.0;
    // Shift the box inside the frame if a corner spilled out.
    if lx < 0.0 {
        rx -= lx;
        lx = 0.0;
    }
    if ly < 0.0 {
        ry -= ly;
        ly = 0.0;
    }
    if rx > fw {
        lx -= rx - fw;
        rx = fw;
    }
    if ry > fh {
        ly -= ry - fh;
        ry = fh;
    }
    let lx = lx.max(0.0) as u32;
    let ly = ly.max(0.0) as u32;
    let rx = (rx.min(fw) as u32).max(lx + 1);
    let ry = (ry.min(fh) as u32).max(ly + 1);

    let sub = image::imageops::crop_imm(frame, lx, ly, rx - lx, ry - ly).to_image();
    image::imageops::resize(&sub, out, out, FilterType::Triangle)
}

/// NCHW float32 in BGR channel order, raw 0–255 values (no mean/std).
fn preprocess(face: &RgbImage) -> Array4<f32> {
    let n = INPUT_SIZE as usize;
    let mut arr = Array4::<f32>::zeros((1, 3, n, n));
    for (x, y, px) in face.enumerate_pixels() {
        let [r, g, b] = px.0;
        // BGR order
        arr[[0, 0, y as usize, x as usize]] = b as f32;
        arr[[0, 1, y as usize, x as usize]] = g as f32;
        arr[[0, 2, y as usize, x as usize]] = r as f32;
    }
    arr
}

fn softmax(x: &[f32]) -> Vec<f32> {
    let m = x.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = x.iter().map(|v| (v - m).exp()).collect();
    let s: f32 = exps.iter().sum();
    if s > 0.0 {
        exps.into_iter().map(|v| v / s).collect()
    } else {
        vec![0.0; x.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_sums_to_one() {
        let p = softmax(&[1.0, 2.0, 3.0]);
        let s: f32 = p.iter().sum();
        assert!((s - 1.0).abs() < 1e-5);
    }

    #[test]
    fn crop_clamps_to_frame() {
        let img = RgbImage::new(100, 100);
        // Bbox at the edge should not panic and should produce an 80x80.
        let out = crop_scaled(&img, [90.0, 90.0, 99.0, 99.0], 2.7, 80);
        assert_eq!(out.width(), 80);
        assert_eq!(out.height(), 80);
    }
}
