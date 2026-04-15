//! Security engine: TPM sealing/unsealing, PCR policy, and memory protection.

use aegyra_common::{AegyraError, Result, SecurityLevel, CONFIG_ROOT};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub mod envelope;
pub mod memlock;
pub mod policy;
pub mod tpm;

pub fn envelope_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("tpm_envelope.json")
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
