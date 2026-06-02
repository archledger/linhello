//! ArcFace embedding via `ort` (ONNX Runtime).
//!
//! Expected model: InsightFace buffalo_l `w600k_r50.onnx`, renamed or symlinked
//! to `/etc/linhello/face.onnx`. Input `[1, 3, 112, 112]`, output `[1, 512]`.

use crate::align::OUT_SIZE as FACE_SIZE;
use crate::bio_err;
use crate::camera::Frame;
use crate::ort_init;
use linhello_common::Result;
use ndarray::Array4;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Value;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const EMBED_DIM: usize = 512;
const DEFAULT_MODEL: &str = "/etc/linhello/face.onnx";

pub struct Embedder {
    session: Mutex<Session>,
}

static CACHED: std::sync::OnceLock<std::result::Result<Embedder, String>> =
    std::sync::OnceLock::new();

impl Embedder {
    pub fn cached() -> Result<&'static Embedder> {
        CACHED
            .get_or_init(|| Self::load_default().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| bio_err(e.clone()))
    }

    pub fn load_default() -> Result<Self> {
        let path = std::env::var_os("LINHELLO_MODEL_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MODEL));
        Self::load(&path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(bio_err(format!("ONNX model not found at {}", path.display())));
        }
        ort_init::ensure_initialized()?;
        let session = Session::builder()
            .map_err(|e| bio_err(format!("ort builder: {e}")))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| bio_err(format!("opt level: {e}")))?
            .commit_from_file(path)
            .map_err(|e| bio_err(format!("load arcface: {e}")))?;
        Ok(Self { session: Mutex::new(session) })
    }

    /// Produce an L2-normalized 512-D embedding from a 112×112 face crop.
    pub fn embed(&self, face: &Frame) -> Result<Vec<f32>> {
        if face.width() != FACE_SIZE || face.height() != FACE_SIZE {
            return Err(bio_err("face crop must be 112x112"));
        }
        let arr = preprocess(face);
        let input = Value::from_array(arr)
            .map_err(|e| bio_err(format!("build input: {e}")))?;

        let mut session = self.session.lock().unwrap();
        let outputs = session
            .run(ort::inputs![input])
            .map_err(|e| bio_err(format!("inference: {e}")))?;
        let (_shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| bio_err(format!("extract: {e}")))?;
        let mut v: Vec<f32> = data.to_vec();
        if v.len() != EMBED_DIM {
            return Err(bio_err(format!(
                "unexpected embedding dim {} (want {EMBED_DIM})",
                v.len()
            )));
        }
        l2_normalize(&mut v);
        Ok(v)
    }
}

fn preprocess(face: &Frame) -> Array4<f32> {
    let mut arr = Array4::<f32>::zeros((1, 3, FACE_SIZE as usize, FACE_SIZE as usize));
    for (x, y, px) in face.enumerate_pixels() {
        let [r, g, b] = px.0;
        arr[[0, 0, y as usize, x as usize]] = (r as f32 - 127.5) / 128.0;
        arr[[0, 1, y as usize, x as usize]] = (g as f32 - 127.5) / 128.0;
        arr[[0, 2, y as usize, x as usize]] = (b as f32 - 127.5) / 128.0;
    }
    arr
}

fn l2_normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}
