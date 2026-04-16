//! Persistent storage of face enrollments at /etc/aegyra/<user>/embedding.bin.
//!
//! Format: concatenated raw little-endian f32 values, one embedding after
//! the next with no separator. Sample count = file_size / (EMBEDDING_DIM * 4).
//! Multi-sample by design — enroll once per lighting/appearance variation
//! (glasses on/off, beard/no-beard) and auth takes the best match.

use crate::bio_err;
use aegyra_common::{Result, CONFIG_ROOT};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// ArcFace buffalo_l produces 512-D L2-normalized embeddings.
pub const EMBEDDING_DIM: usize = 512;
const STRIDE_BYTES: usize = EMBEDDING_DIM * 4;

fn user_dir(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(bio_err("invalid user name"));
    }
    Ok(PathBuf::from(CONFIG_ROOT).join(user))
}

fn embedding_path(user: &str) -> Result<PathBuf> {
    Ok(user_dir(user)?.join("embedding.bin"))
}

fn check_dim(vec: &[f32]) -> Result<()> {
    if vec.len() != EMBEDDING_DIM {
        return Err(bio_err(format!(
            "embedding dim {} != expected {}",
            vec.len(),
            EMBEDDING_DIM
        )));
    }
    Ok(())
}

fn embedding_bytes(vec: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vec.len() * 4);
    for f in vec {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    bytes
}

/// Overwrite any existing enrollment with a single fresh sample.
pub fn save_embedding(user: &str, vec: &[f32]) -> Result<()> {
    check_dim(vec)?;
    let dir = user_dir(user)?;
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("embedding.bin"), embedding_bytes(vec))?;
    Ok(())
}

/// Append a sample to the user's enrollment, creating the file if absent.
pub fn append_embedding(user: &str, vec: &[f32]) -> Result<()> {
    check_dim(vec)?;
    let dir = user_dir(user)?;
    fs::create_dir_all(&dir)?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("embedding.bin"))?;
    f.write_all(&embedding_bytes(vec))?;
    Ok(())
}

/// Parse raw embedding bytes into f32 vectors.
pub fn parse_raw_embeddings(bytes: &[u8]) -> Result<Vec<Vec<f32>>> {
    if bytes.is_empty() || bytes.len() % STRIDE_BYTES != 0 {
        return Err(bio_err(format!(
            "enrollment size {} not a multiple of {} (dim={})",
            bytes.len(),
            STRIDE_BYTES,
            EMBEDDING_DIM
        )));
    }
    let samples = bytes
        .chunks_exact(STRIDE_BYTES)
        .map(|chunk| {
            chunk
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect::<Vec<f32>>()
        })
        .collect();
    Ok(samples)
}

/// Load all enrolled samples for a user. Returns a non-empty vector on
/// success.
pub fn load_embeddings(user: &str) -> Result<Vec<Vec<f32>>> {
    let path = embedding_path(user)?;
    let bytes = fs::read(&path).map_err(|e| {
        bio_err(format!("read enrollment {}: {e}", path.display()))
    })?;
    parse_raw_embeddings(&bytes)
}

pub fn sample_count(user: &str) -> Result<usize> {
    let path = embedding_path(user)?;
    let len = fs::metadata(&path)
        .map_err(|e| bio_err(format!("stat {}: {e}", path.display())))?
        .len() as usize;
    Ok(len / STRIDE_BYTES)
}
