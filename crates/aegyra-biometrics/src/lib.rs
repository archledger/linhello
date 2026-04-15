//! Face-recognition pipeline: capture → detect → align → embed → match.

use aegyra_common::{AegyraError, Result};
use serde::{Deserialize, Serialize};

pub mod align;
pub mod camera;
pub mod detect;
pub mod embed;
pub mod enroll;
pub mod matcher;
mod ort_init;

/// Cosine-similarity threshold for a successful match (ArcFace, 512-D, L2).
pub const MATCH_THRESHOLD: f32 = 0.60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub matched: bool,
    pub score: f32,
}

fn capture_and_embed() -> Result<Vec<f32>> {
    let frame = camera::capture_frame()?;
    let detector = detect::Detector::load_default()?;
    let faces = detector.detect(&frame)?;
    let face = faces
        .into_iter()
        .next()
        .ok_or_else(|| bio_err("no face detected"))?;
    let aligned = align::align(&frame, &face)?;
    let embedder = embed::Embedder::load_default()?;
    embedder.embed(&aligned)
}

pub fn authenticate_user(user: &str) -> Result<AuthResult> {
    let samples = enroll::load_embeddings(user)?;
    let live = capture_and_embed()?;
    let score = samples
        .iter()
        .map(|s| matcher::cosine(&live, s))
        .fold(f32::NEG_INFINITY, f32::max);
    Ok(AuthResult {
        matched: score >= MATCH_THRESHOLD,
        score,
    })
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

pub(crate) fn bio_err(msg: impl Into<String>) -> AegyraError {
    AegyraError::Biometrics(msg.into())
}
