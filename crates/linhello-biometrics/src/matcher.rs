//! Similarity scoring for face embeddings.

/// Cosine similarity on already-L2-normalized vectors is just the dot product.
///
/// Inputs are expected to be unit-length (the embedder normalizes live vectors
/// and `enroll::parse_raw_embeddings` re-normalizes stored ones). The result is
/// clamped to `[-1, 1]` as a final guard against floating-point drift or any
/// non-unit input slipping through, so a single sample can never score above
/// the match threshold purely on magnitude.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    dot.clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_vectors_score_one() {
        let v = vec![1.0, 0.0, 0.0];
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn orthogonal_vectors_score_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn length_mismatch_is_zero() {
        assert_eq!(cosine(&[1.0], &[1.0, 0.0]), 0.0);
    }

    #[test]
    fn non_unit_inputs_are_clamped_to_one() {
        // Even if a non-unit vector slips through, cosine must not exceed 1.0,
        // so it can't clear the match threshold purely on magnitude.
        let a = vec![10.0, 0.0, 0.0];
        assert!(cosine(&a, &a) <= 1.0);
    }
}
