//! Security engine: TPM sealing/unsealing, PCR policy, and memory protection.

use aegyra_common::{AegyraError, Result, SecurityLevel, CONFIG_ROOT};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub mod crypto;
pub mod envelope;
pub mod memlock;
pub mod policy;
pub mod tpm;

pub fn envelope_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("tpm_envelope.json")
}

pub fn password_envelope_path(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(AegyraError::Policy("invalid user name".into()));
    }
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("password_envelope.json"))
}

pub fn detect_security_level() -> SecurityLevel {
    policy::detect()
}

/// Seal a new random 32-byte secret against the current PCR policy, persist
/// the envelope, and return the plaintext (so an initial enrollment flow can
/// hand it to PAM immediately without waiting for the first unseal).
pub fn reseal_random_secret() -> Result<Zeroizing<Vec<u8>>> {
    use rand::RngCore;
    let mut buf = Zeroizing::new(vec![0u8; 32]);
    rand::thread_rng().fill_bytes(&mut buf);
    let level = detect_security_level();
    let env = tpm::seal(&buf, level)?;
    env.save(&envelope_path())?;
    Ok(buf)
}

/// Seal a caller-supplied secret (e.g. a login password) against PCRs.
pub fn reseal_secret(secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        return Err(AegyraError::Policy("empty secret".into()));
    }
    let level = detect_security_level();
    let env = tpm::seal(secret, level)?;
    env.save(&envelope_path())?;
    Ok(())
}

/// Unseal the stored secret. The returned buffer is `Zeroizing` and mlocked
/// so it cannot be paged out or leak into a core dump.
pub fn unseal_keyring_secret() -> Result<Zeroizing<Vec<u8>>> {
    let env = envelope::SealedEnvelope::load(&envelope_path())?;
    let plain = tpm::unseal(&env)?;
    memlock::lock_slice(&plain)?;
    Ok(plain)
}

/// Seal a user's login password under the current PCR policy, persist to
/// the per-user envelope. Caller owns zeroization of `password`.
pub fn seal_password(user: &str, password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(AegyraError::Policy("empty password".into()));
    }
    let path = password_envelope_path(user)?;
    let level = detect_security_level();
    let env = tpm::seal(password, level)?;
    env.save(&path)?;
    // Restrict to root — the envelope doesn't leak plaintext, but enforcing
    // 0600 matches the enrollment file's posture.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Unseal a user's login password. mlocked + Zeroizing on return.
pub fn unseal_password(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = password_envelope_path(user)?;
    let env = envelope::SealedEnvelope::load(&path)?;
    let plain = tpm::unseal(&env)?;
    memlock::lock_slice(&plain)?;
    Ok(plain)
}

// ── Template-key management ──────────────────────────────────────────

fn template_key_path(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(AegyraError::Policy("invalid user name".into()));
    }
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("template_key_envelope.json"))
}

fn encrypted_embedding_path(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(AegyraError::Policy("invalid user name".into()));
    }
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("embedding.enc"))
}

fn legacy_embedding_path(user: &str) -> Result<PathBuf> {
    if user.is_empty() || user.contains('/') || user.contains('\0') {
        return Err(AegyraError::Policy("invalid user name".into()));
    }
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("embedding.bin"))
}

/// Ensure a per-user template AES-256 key exists (sealed under TPM).
/// Returns the plaintext key (Zeroizing). If no envelope exists yet,
/// generates a fresh key and seals it.
pub fn ensure_template_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let kp = template_key_path(user)?;
    if kp.exists() {
        return unseal_template_key(user);
    }
    let key = crypto::generate_key();
    let level = detect_security_level();
    let env = tpm::seal(&key, level)?;
    env.save(&kp)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

/// Unseal an existing per-user template key.
pub fn unseal_template_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let kp = template_key_path(user)?;
    let env = envelope::SealedEnvelope::load(&kp)?;
    let key = tpm::unseal(&env)?;
    memlock::lock_slice(&key)?;
    Ok(key)
}

/// Encrypt raw embedding bytes and write to `embedding.enc`. Creates the
/// user directory if absent. Removes any legacy `embedding.bin`.
pub fn save_encrypted_embedding(user: &str, raw: &[u8], key: &[u8]) -> Result<()> {
    let enc_path = encrypted_embedding_path(user)?;
    if let Some(parent) = enc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let blob = crypto::encrypt(key, raw)?;
    std::fs::write(&enc_path, blob)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600))?;
    // Remove unencrypted legacy file if present.
    let _ = std::fs::remove_file(legacy_embedding_path(user)?);
    Ok(())
}

/// Load and decrypt the user's face embeddings. Returns the raw bytes
/// (caller parses into f32 vectors). Falls back to legacy `embedding.bin`
/// and auto-migrates: encrypts in place and deletes the plaintext file.
pub fn load_encrypted_embedding(user: &str, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let enc_path = encrypted_embedding_path(user)?;
    if enc_path.exists() {
        let blob = std::fs::read(&enc_path)?;
        return crypto::decrypt(key, &blob);
    }
    // Migration: read legacy, encrypt, save encrypted, delete legacy.
    let legacy = legacy_embedding_path(user)?;
    if legacy.exists() {
        tracing::info!("migrating {} to encrypted storage", legacy.display());
        let raw = std::fs::read(&legacy)?;
        save_encrypted_embedding(user, &raw, key)?;
        let _ = std::fs::remove_file(&legacy);
        return Ok(Zeroizing::new(raw));
    }
    Err(AegyraError::Biometrics(format!(
        "no enrollment found for user '{user}'"
    )))
}
