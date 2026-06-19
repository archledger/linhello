//! Security engine: TPM sealing/unsealing, PCR policy, and memory protection.

use linhello_common::{LinuxHelloError, Result, SecurityLevel, CONFIG_ROOT};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub mod crypto;
pub mod envelope;
pub mod memlock;
pub mod pcrsig;
pub mod policy;
pub mod recovery;
pub mod tpm;

pub fn envelope_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("tpm_envelope.json")
}

/// Validate that `user` is a safe single path component before it is ever
/// joined onto `CONFIG_ROOT`. Rejects empty names, path separators, NUL, and
/// the traversal names `.`/`..`. Because `/` is rejected, no multi-segment or
/// absolute path can form, so `CONFIG_ROOT.join(user)` always stays one level
/// under the config root. Does **not** verify the account exists.
pub fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user == "."
        || user == ".."
        || user.contains('/')
        || user.contains('\\')
        || user.contains('\0')
    {
        return Err(LinuxHelloError::Policy("invalid user name".into()));
    }
    Ok(())
}

pub fn password_envelope_path(user: &str) -> Result<PathBuf> {
    validate_user(user)?;
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
    let env = tpm::seal_secret(&buf)?;
    env.save(&envelope_path())?;
    Ok(buf)
}

/// Seal a caller-supplied secret (e.g. a login password) against PCRs.
pub fn reseal_secret(secret: &[u8]) -> Result<()> {
    if secret.is_empty() {
        return Err(LinuxHelloError::Policy("empty secret".into()));
    }
    let env = tpm::seal_secret(secret)?;
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
        return Err(LinuxHelloError::Policy("empty password".into()));
    }
    let path = password_envelope_path(user)?;
    let env = tpm::seal_secret(password)?;
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

pub fn template_key_path_pub(user: &str) -> Result<PathBuf> {
    template_key_path(user)
}

fn template_key_path(user: &str) -> Result<PathBuf> {
    validate_user(user)?;
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("template_key_envelope.json"))
}

fn encrypted_embedding_path(user: &str) -> Result<PathBuf> {
    validate_user(user)?;
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("embedding.enc"))
}

fn legacy_embedding_path(user: &str) -> Result<PathBuf> {
    validate_user(user)?;
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
    let env = tpm::seal_secret(&key)?;
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

/// Seal a *specific* template key under the current TPM policy and persist the
/// envelope (0600). Used to re-seal after a recovery, or to bind a freshly
/// generated key during enrollment.
pub fn seal_template_key(user: &str, key: &[u8]) -> Result<()> {
    if key.len() != crypto::KEY_LEN {
        return Err(LinuxHelloError::Policy(format!(
            "template key must be {} bytes, got {}",
            crypto::KEY_LEN,
            key.len()
        )));
    }
    let kp = template_key_path(user)?;
    let env = tpm::seal_secret(key)?;
    env.save(&kp)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// ── Recovery passphrase (dedicated, separate from the login password) ────

pub fn recovery_envelope_path(user: &str) -> Result<PathBuf> {
    validate_user(user)?;
    Ok(PathBuf::from(CONFIG_ROOT)
        .join(user)
        .join("recovery_envelope.json"))
}

/// True if a recovery passphrase has been set for `user`.
pub fn recovery_exists(user: &str) -> bool {
    recovery_envelope_path(user)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Wrap the user's *current* template key under a recovery passphrase and
/// persist the recovery envelope (0600). Requires the template key to be
/// unsealable now (i.e. run while the TPM path still works, e.g. at enroll).
pub fn save_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    let key = unseal_template_key(user)?;
    let env = recovery::wrap(passphrase, &key)?;
    let path = recovery_envelope_path(user)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&env)
        .map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
    std::fs::write(&path, json)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Restore the template key from the recovery passphrase and re-seal it under
/// the current TPM policy — the manual backstop when the automatic self-heal
/// can't run (Secure Boot off, TPM cleared, disk moved). Face unlock works again
/// afterwards with no re-enrollment.
pub fn restore_from_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    let path = recovery_envelope_path(user)?;
    let json = std::fs::read_to_string(&path).map_err(|_| {
        LinuxHelloError::Policy(format!("no recovery passphrase is set for '{user}'"))
    })?;
    let env: recovery::RecoveryEnvelope =
        serde_json::from_str(&json).map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
    let key = recovery::unwrap(passphrase, &env)?;
    seal_template_key(user, &key)?;
    Ok(())
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
/// (caller parses into f32 vectors).
///
/// Encrypted storage (`embedding.enc`) is authenticated (AES-256-GCM), so a
/// tampered template is rejected on decrypt. A legacy plaintext `embedding.bin`
/// is **not** trusted by default: a one-time migration is only performed when
/// `LINHELLO_ALLOW_LEGACY_MIGRATION` is set, because a plaintext template carries
/// no integrity guarantee (a root-written or tampered file would otherwise be
/// adopted as the enrolled face). Fresh installs never produce `embedding.bin`.
pub fn load_encrypted_embedding(user: &str, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let enc_path = encrypted_embedding_path(user)?;
    if enc_path.exists() {
        let blob = std::fs::read(&enc_path)?;
        return crypto::decrypt(key, &blob);
    }
    let legacy = legacy_embedding_path(user)?;
    if legacy.exists() {
        if !legacy_migration_allowed() {
            return Err(LinuxHelloError::Biometrics(format!(
                "found legacy plaintext template for '{user}' but migration is \
                 disabled (unauthenticated at rest). Re-enroll, or set \
                 LINHELLO_ALLOW_LEGACY_MIGRATION=1 for a one-time upgrade."
            )));
        }
        // One-time, opt-in migration: read legacy, encrypt, save, delete.
        tracing::info!("migrating {} to encrypted storage", legacy.display());
        let raw = std::fs::read(&legacy)?;
        save_encrypted_embedding(user, &raw, key)?;
        let _ = std::fs::remove_file(&legacy);
        return Ok(Zeroizing::new(raw));
    }
    Err(LinuxHelloError::Biometrics(format!(
        "no enrollment found for user '{user}'"
    )))
}

fn legacy_migration_allowed() -> bool {
    std::env::var("LINHELLO_ALLOW_LEGACY_MIGRATION")
        .ok()
        .as_deref()
        .map(|v| matches!(v, "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn validate_user_accepts_plain_names() {
        for ok in ["ben", "root", "user1", "a.b", "Jean-Luc"] {
            assert!(validate_user(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn validate_user_rejects_traversal_and_separators() {
        for bad in ["", ".", "..", "../etc", "a/b", "/etc", "a\\b", "a\0b", "..\0"] {
            assert!(validate_user(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn user_paths_stay_under_config_root() {
        // Any accepted user must produce a path exactly one level below
        // CONFIG_ROOT — no traversal can escape.
        let p = password_envelope_path("ben").unwrap();
        assert_eq!(p.parent().unwrap(), Path::new(CONFIG_ROOT).join("ben"));
        // A traversal attempt never yields a path at all.
        assert!(password_envelope_path("..").is_err());
        assert!(template_key_path("../../root").is_err());
        assert!(encrypted_embedding_path("a/b").is_err());
    }
}
