//! Face-recognition pipeline: capture → detect → align → embed → match.

use linhello_common::{LinuxHelloError, Result};
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

/// Capture one frame, detect the primary face, and run the liveness gate.
/// Returns the frame + face on success; errors (with a human-readable reason)
/// when no face is visible or liveness rejects.
fn capture_detect_live() -> Result<(camera::Frame, detect::Face)> {
    // Parallel RGB + IR capture: IR warmup (~530ms) runs in a background
    // thread while RGB capture + face detection happen in the foreground.
    // Saves ~500ms vs. sequential.
    let ir_handle = std::thread::spawn(|| camera::capture_ir_frame().ok().flatten());

    let frame = camera::capture_frame()?;
    let detector = detect::Detector::cached()?;
    let faces = detector.detect(&frame)?;
    let face = faces
        .into_iter()
        .next()
        .ok_or_else(|| bio_err("no face detected"))?;

    let ir = ir_handle.join().unwrap_or(None);

    let evaluator = linhello_liveness::LivenessEvaluator::cached()?;
    let report = evaluator.evaluate(
        &frame, face.bbox, &face.landmarks, &camera::rgb_device(), ir.as_ref(),
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
    Ok((frame, face))
}

pub fn capture_and_embed() -> Result<Vec<f32>> {
    let (frame, face) = capture_detect_live()?;
    let aligned = align::align(&frame, &face)?;
    let embedder = embed::Embedder::cached()?;
    embedder.embed(&aligned)
}

/// Standalone liveness probe for `linhello liveness-test`. Captures one frame,
/// runs detection + liveness, and returns the raw report. Never touches
/// enrollment data or embeddings.
pub fn run_liveness_test() -> Result<linhello_liveness::LivenessReport> {
    let ir_handle = std::thread::spawn(|| camera::capture_ir_frame().ok().flatten());
    let frame = camera::capture_frame()?;
    let detector = detect::Detector::cached()?;
    let faces = detector.detect(&frame)?;
    let face = faces
        .into_iter()
        .next()
        .ok_or_else(|| bio_err("no face detected"))?;
    let ir = ir_handle.join().unwrap_or(None);
    let evaluator = linhello_liveness::LivenessEvaluator::cached()?;
    evaluator.evaluate(&frame, face.bbox, &face.landmarks, &camera::rgb_device(), ir.as_ref())
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
        matched: score >= MATCH_THRESHOLD,
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
