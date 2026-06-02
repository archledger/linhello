//! SCRFD face detector (InsightFace buffalo_l `det_10g.onnx`), run on
//! ONNX Runtime via the `ort` crate.
//!
//! Anchors: 2 per location across strides 8/16/32, 640×640 input.
//! Outputs are 9 tensors in this order (per InsightFace export):
//!   score_8, score_16, score_32, bbox_8, bbox_16, bbox_32,
//!   kps_8,   kps_16,   kps_32

use crate::bio_err;
use crate::camera::Frame;
use crate::ort_init;
use linhello_common::Result;
use image::imageops::FilterType;
use ndarray::Array4;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Value;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const INPUT_SIZE: u32 = 640;
pub const STRIDES: [u32; 3] = [8, 16, 32];
pub const NUM_ANCHORS: usize = 2;
const DEFAULT_MODEL: &str = "/etc/linhello/det_10g.onnx";
const SCORE_THRESHOLD: f32 = 0.5;
const NMS_IOU: f32 = 0.4;

#[derive(Debug, Clone)]
pub struct Face {
    pub score: f32,
    pub bbox: [f32; 4],
    pub landmarks: [[f32; 2]; 5],
}

pub struct Detector {
    session: Mutex<Session>,
}

static CACHED: std::sync::OnceLock<std::result::Result<Detector, String>> =
    std::sync::OnceLock::new();

impl Detector {
    pub fn cached() -> Result<&'static Detector> {
        CACHED
            .get_or_init(|| Self::load_default().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| bio_err(e.clone()))
    }

    pub fn load_default() -> Result<Self> {
        let path = std::env::var_os("LINHELLO_DET_MODEL")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MODEL));
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(bio_err(format!("SCRFD model not found at {}", path.display())));
        }
        ort_init::ensure_initialized()?;
        let session = Session::builder()
            .map_err(|e| bio_err(format!("ort builder: {e}")))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| bio_err(format!("opt level: {e}")))?
            .commit_from_file(path)
            .map_err(|e| bio_err(format!("load scrfd: {e}")))?;
        Ok(Self { session: Mutex::new(session) })
    }

    pub fn detect(&self, frame: &Frame) -> Result<Vec<Face>> {
        let (ow, oh) = (frame.width(), frame.height());
        let (letterboxed, scale, pad_x, pad_y) = letterbox(frame, INPUT_SIZE);
        let arr = preprocess(&letterboxed);
        let input = Value::from_array(arr)
            .map_err(|e| bio_err(format!("build input: {e}")))?;

        let mut session = self.session.lock().unwrap();
        let outputs = session
            .run(ort::inputs![input])
            .map_err(|e| bio_err(format!("scrfd inference: {e}")))?;
        if outputs.len() < 9 {
            return Err(bio_err(format!(
                "scrfd returned {} outputs, expected 9",
                outputs.len()
            )));
        }

        let mut all: Vec<Vec<f32>> = Vec::with_capacity(9);
        for i in 0..9 {
            let (_shape, data) = outputs[i]
                .try_extract_tensor::<f32>()
                .map_err(|e| bio_err(format!("extract out {i}: {e}")))?;
            all.push(data.to_vec());
        }

        let mut faces: Vec<Face> = Vec::new();
        for (i, &stride) in STRIDES.iter().enumerate() {
            let grid_w = INPUT_SIZE / stride;
            let grid_h = INPUT_SIZE / stride;
            decode_stride(
                stride, grid_w, grid_h,
                &all[i],       // scores
                &all[i + 3],   // bboxes
                &all[i + 6],   // kps
                &mut faces,
            );
        }

        for f in &mut faces {
            f.bbox[0] = ((f.bbox[0] - pad_x) / scale).clamp(0.0, ow as f32 - 1.0);
            f.bbox[1] = ((f.bbox[1] - pad_y) / scale).clamp(0.0, oh as f32 - 1.0);
            f.bbox[2] = ((f.bbox[2] - pad_x) / scale).clamp(0.0, ow as f32 - 1.0);
            f.bbox[3] = ((f.bbox[3] - pad_y) / scale).clamp(0.0, oh as f32 - 1.0);
            for lm in &mut f.landmarks {
                lm[0] = ((lm[0] - pad_x) / scale).clamp(0.0, ow as f32 - 1.0);
                lm[1] = ((lm[1] - pad_y) / scale).clamp(0.0, oh as f32 - 1.0);
            }
        }

        Ok(nms(faces, NMS_IOU))
    }
}

fn decode_stride(
    stride: u32,
    grid_w: u32,
    grid_h: u32,
    scores: &[f32],
    bboxes: &[f32],
    kpses: &[f32],
    out: &mut Vec<Face>,
) {
    let total = (grid_w * grid_h) as usize * NUM_ANCHORS;
    for i in 0..total {
        let s = scores[i];
        if s < SCORE_THRESHOLD {
            continue;
        }
        let cell = i / NUM_ANCHORS;
        let gx = (cell as u32 % grid_w) as f32;
        let gy = (cell as u32 / grid_w) as f32;
        let cx = gx * stride as f32;
        let cy = gy * stride as f32;

        let b = &bboxes[i * 4..i * 4 + 4];
        let x1 = cx - b[0] * stride as f32;
        let y1 = cy - b[1] * stride as f32;
        let x2 = cx + b[2] * stride as f32;
        let y2 = cy + b[3] * stride as f32;

        let k = &kpses[i * 10..i * 10 + 10];
        let mut landmarks = [[0.0f32; 2]; 5];
        for (j, lm) in landmarks.iter_mut().enumerate() {
            lm[0] = cx + k[j * 2] * stride as f32;
            lm[1] = cy + k[j * 2 + 1] * stride as f32;
        }

        out.push(Face { score: s, bbox: [x1, y1, x2, y2], landmarks });
    }
}

fn letterbox(frame: &Frame, size: u32) -> (Frame, f32, f32, f32) {
    let (w, h) = (frame.width() as f32, frame.height() as f32);
    let scale = (size as f32 / w).min(size as f32 / h);
    let nw = (w * scale).round() as u32;
    let nh = (h * scale).round() as u32;
    let resized = image::imageops::resize(frame, nw, nh, FilterType::Triangle);
    let pad_x = ((size - nw) / 2) as f32;
    let pad_y = ((size - nh) / 2) as f32;

    let mut canvas = image::ImageBuffer::from_pixel(size, size, image::Rgb([0u8, 0, 0]));
    image::imageops::overlay(&mut canvas, &resized, pad_x as i64, pad_y as i64);
    (canvas, scale, pad_x, pad_y)
}

fn preprocess(frame: &Frame) -> Array4<f32> {
    let (w, h) = (frame.width() as usize, frame.height() as usize);
    let mut arr = Array4::<f32>::zeros((1, 3, h, w));
    for (x, y, px) in frame.enumerate_pixels() {
        let [r, g, b] = px.0;
        arr[[0, 0, y as usize, x as usize]] = (r as f32 - 127.5) / 128.0;
        arr[[0, 1, y as usize, x as usize]] = (g as f32 - 127.5) / 128.0;
        arr[[0, 2, y as usize, x as usize]] = (b as f32 - 127.5) / 128.0;
    }
    arr
}

fn iou(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let x1 = a[0].max(b[0]);
    let y1 = a[1].max(b[1]);
    let x2 = a[2].min(b[2]);
    let y2 = a[3].min(b[3]);
    let inter = (x2 - x1).max(0.0) * (y2 - y1).max(0.0);
    let area_a = (a[2] - a[0]).max(0.0) * (a[3] - a[1]).max(0.0);
    let area_b = (b[2] - b[0]).max(0.0) * (b[3] - b[1]).max(0.0);
    let union = area_a + area_b - inter;
    if union <= 0.0 { 0.0 } else { inter / union }
}

fn nms(mut faces: Vec<Face>, thresh: f32) -> Vec<Face> {
    faces.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    let mut kept: Vec<Face> = Vec::new();
    for f in faces {
        if kept.iter().all(|k| iou(&f.bbox, &k.bbox) < thresh) {
            kept.push(f);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iou_identical_is_one() {
        let a = [0.0, 0.0, 10.0, 10.0];
        assert!((iou(&a, &a) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn iou_disjoint_is_zero() {
        let a = [0.0, 0.0, 5.0, 5.0];
        let b = [10.0, 10.0, 20.0, 20.0];
        assert_eq!(iou(&a, &b), 0.0);
    }

    #[test]
    fn nms_suppresses_overlap() {
        let hi = Face { score: 0.9, bbox: [0.0, 0.0, 10.0, 10.0], landmarks: [[0.0; 2]; 5] };
        let lo = Face { score: 0.8, bbox: [1.0, 1.0, 11.0, 11.0], landmarks: [[0.0; 2]; 5] };
        let kept = nms(vec![hi.clone(), lo], 0.4);
        assert_eq!(kept.len(), 1);
        assert!((kept[0].score - 0.9).abs() < 1e-6);
    }
}
