//! Persistent storage of face enrollments at /etc/aegyra/<user>/embedding.bin.
//!
//! Format: raw little-endian f32 values, no header — length is implied by
//! file size. The daemon is responsible for enforcing 0600 perms and root
//! ownership when writing from a privileged context.

use crate::bio_err;
use aegyra_common::{Result, CONFIG_ROOT};
use std::fs;
use std::path::PathBuf;

fn user_dir(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(bio_err("invalid user name"));
    }
    Ok(PathBuf::from(CONFIG_ROOT).join(user))
}

fn embedding_path(user: &str) -> Result<PathBuf> {
    Ok(user_dir(user)?.join("embedding.bin"))
}

pub fn save_embedding(user: &str, vec: &[f32]) -> Result<()> {
    let dir = user_dir(user)?;
    fs::create_dir_all(&dir)?;
    let mut bytes = Vec::with_capacity(vec.len() * 4);
    for f in vec {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    fs::write(dir.join("embedding.bin"), &bytes)?;
    Ok(())
}

pub fn load_embedding(user: &str) -> Result<Vec<f32>> {
    let path = embedding_path(user)?;
    let bytes = fs::read(&path).map_err(|e| {
        bio_err(format!("read enrollment {}: {e}", path.display()))
    })?;
    if bytes.len() % 4 != 0 {
        return Err(bio_err("enrollment file size not a multiple of 4"));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}
