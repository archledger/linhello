//! Consume systemd's signed-PCR-policy artifacts.
//!
//! When a UKI is built with `ukify --pcr-private-key`/`--pcr-public-key` (or
//! `systemd-measure sign`), systemd-stub exposes, at boot:
//!   * `/run/systemd/tpm2-pcr-signature.json` — per-PCR-state signatures
//!   * `/run/systemd/tpm2-pcr-public-key.pem` — the authorizing public key
//!
//! Each kernel update reships a fresh signature inside the new UKI, so a
//! `PolicyAuthorize`-bound secret keeps unsealing across updates with no reseal
//! or re-enrollment. This module discovers and parses those files; the TPM
//! `PolicyAuthorize` machinery lives in [`crate::tpm`].
//!
//! Signature-file schema (one array per PCR bank):
//! ```json
//! { "sha256": [ { "pcrs": [11], "pkfp": "<hex>", "pol": "<hex>", "sig": "<b64>" } ] }
//! ```
//! `pol` is the authorized PCR-policy digest; `sig` is the signature over it.

use linhello_common::{LinuxHelloError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default PCR bank we operate in. systemd writes `sha256` on modern systems.
pub const DEFAULT_BANK: &str = "sha256";

/// Lowercase-hex SHA-256 of the DER `SubjectPublicKeyInfo` of the PCR-signing
/// public key this host trusts (the systemd UKI PCR signing key). The
/// authorized (`Full`) path refuses to seal under, or unseal with, any key
/// whose SPKI does not hash to this value, so a rogue key dropped into a
/// higher-priority search dir (`/etc/systemd`) cannot authorize an unseal.
///
/// NOTE: this is the SHA-256 of the X.509 SPKI (matches
/// `openssl pkey -pubin -outform DER | sha256sum`), which is **not** the same
/// as systemd's own `pkfp` field in `tpm2-pcr-signature.json` (a different
/// convention). We pin the key itself, then the TPM `verify_signature` step
/// enforces it cryptographically. Established 2026-06-15; rotate this constant
/// whenever the UKI PCR signing key is rotated.
pub const TRUSTED_PUBKEY_SPKI_SHA256: &str =
    "86812b40a327339e23d3c1a5621f31041e7581e1cc334746f3af62e861525ede";

/// Search order matching `systemd-cryptenroll`/`systemd-cryptsetup`.
const SEARCH_DIRS: [&str; 3] = ["/etc/systemd", "/run/systemd", "/usr/lib/systemd"];
const SIGNATURE_FILE: &str = "tpm2-pcr-signature.json";
const PUBKEY_FILE: &str = "tpm2-pcr-public-key.pem";

/// One authorized PCR policy + its signature, for a single PCR-state/phase.
#[derive(Debug, Clone)]
pub struct PcrSignature {
    /// PCR indices this signature covers (e.g. `[11]`).
    pub pcrs: Vec<u32>,
    /// Public-key fingerprint (hex), identifies the signing key.
    pub pkfp: String,
    /// The authorized PCR-policy digest (raw bytes).
    pub pol: Vec<u8>,
    /// Signature over the authorized policy (raw bytes).
    pub sig: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    pcrs: Vec<u32>,
    pkfp: String,
    pol: String,
    sig: String,
}

/// Locate the signature JSON, honouring `LINHELLO_PCR_SIGNATURE` for test/dev.
pub fn discover_signature_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LINHELLO_PCR_SIGNATURE") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    discover(SIGNATURE_FILE)
}

/// Locate the public-key PEM, honouring `LINHELLO_PCR_PUBKEY` for test/dev.
pub fn discover_pubkey_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LINHELLO_PCR_PUBKEY") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    discover(PUBKEY_FILE)
}

fn discover(file: &str) -> Option<PathBuf> {
    SEARCH_DIRS
        .iter()
        .map(|d| Path::new(d).join(file))
        .find(|p| p.exists())
}

/// True when both signed-policy artifacts are present — i.e. the signed-PCR
/// policy path is usable on this machine.
pub fn signed_policy_available() -> bool {
    discover_signature_path().is_some() && discover_pubkey_path().is_some()
}

/// Read the authorizing public key as PEM text, enforcing the pinned trust
/// anchor. Errors if the discovered key is not the trusted signing key, so the
/// policy layer falls back to the literal (PCR 7) tier rather than honour an
/// untrusted key.
pub fn load_pubkey_pem() -> Result<String> {
    let path = discover_pubkey_path()
        .ok_or_else(|| LinuxHelloError::Policy("no TPM2 PCR public key found".into()))?;
    let pem = std::fs::read_to_string(&path).map_err(LinuxHelloError::Io)?;
    ensure_trusted_pubkey(&pem)?;
    Ok(pem)
}

/// Lowercase-hex SHA-256 of `pubkey_pem`'s DER `SubjectPublicKeyInfo` — the
/// fingerprint pinned by [`TRUSTED_PUBKEY_SPKI_SHA256`].
pub fn pubkey_spki_fingerprint(pubkey_pem: &str) -> Result<String> {
    let key = rsa::RsaPublicKey::from_public_key_pem(pubkey_pem)
        .map_err(|e| LinuxHelloError::Policy(format!("parse PCR public key: {e}")))?;
    let der = key
        .to_public_key_der()
        .map_err(|e| LinuxHelloError::Policy(format!("encode PCR public key SPKI: {e}")))?;
    Ok(hex_lower(Sha256::digest(der.as_bytes()).as_slice()))
}

/// Error unless `pubkey_pem` is exactly the pinned trusted signing key. Used on
/// both the seal path (which key to bind) and the unseal path (whether the key
/// recorded in an envelope is still trusted).
pub fn ensure_trusted_pubkey(pubkey_pem: &str) -> Result<()> {
    let fp = pubkey_spki_fingerprint(pubkey_pem)?;
    if fp != TRUSTED_PUBKEY_SPKI_SHA256 {
        return Err(LinuxHelloError::Policy(format!(
            "PCR signing key fingerprint {fp} is not the pinned trusted key \
             {TRUSTED_PUBKEY_SPKI_SHA256}"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse all signatures for `bank` from the discovered signature file.
pub fn load_signatures(bank: &str) -> Result<Vec<PcrSignature>> {
    let path = discover_signature_path()
        .ok_or_else(|| LinuxHelloError::Policy("no TPM2 PCR signature file found".into()))?;
    let text = std::fs::read_to_string(&path).map_err(LinuxHelloError::Io)?;
    parse_signatures(&text, bank)
}

/// Parse signatures for `bank` from in-memory JSON (the testable core of
/// [`load_signatures`]).
pub fn parse_signatures(text: &str, bank: &str) -> Result<Vec<PcrSignature>> {
    let raw: HashMap<String, Vec<RawEntry>> =
        serde_json::from_str(text).map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
    let entries = match raw.get(bank) {
        Some(e) => e,
        None => return Ok(Vec::new()),
    };
    entries
        .iter()
        .map(|e| {
            Ok(PcrSignature {
                pcrs: e.pcrs.clone(),
                pkfp: e.pkfp.clone(),
                pol: from_hex(&e.pol)?,
                sig: STANDARD
                    .decode(&e.sig)
                    .map_err(|err| LinuxHelloError::Serde(format!("bad signature base64: {err}")))?,
            })
        })
        .collect()
}

/// Find a signature whose authorized policy digest equals `policy_digest`
/// (and that covers exactly `pcrs`). Returns the first match.
pub fn find_for_policy<'a>(
    sigs: &'a [PcrSignature],
    pcrs: &[u32],
    policy_digest: &[u8],
) -> Option<&'a PcrSignature> {
    sigs.iter()
        .find(|s| s.pol == policy_digest && s.pcrs == pcrs)
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(LinuxHelloError::Serde("odd-length hex string".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| LinuxHelloError::Serde(format!("bad hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic two-bank, two-phase signature file (truncated digests/sigs).
    const FIXTURE: &str = r#"{
      "sha1": [
        {"pcrs":[11],"pkfp":"aa","pol":"0102","sig":"AAEC"}
      ],
      "sha256": [
        {"pcrs":[11],"pkfp":"7682","pol":"265bfca5","sig":"anN2"},
        {"pcrs":[11],"pkfp":"7682","pol":"deadbeef","sig":"Y2Fm"}
      ]
    }"#;

    #[test]
    fn parses_requested_bank_only() {
        let sha256 = parse_signatures(FIXTURE, "sha256").unwrap();
        assert_eq!(sha256.len(), 2);
        assert_eq!(sha256[0].pcrs, vec![11]);
        assert_eq!(sha256[0].pol, vec![0x26, 0x5b, 0xfc, 0xa5]);
        assert_eq!(sha256[0].sig, b"jsv"); // base64 "anN2" -> "jsv"
    }

    #[test]
    fn missing_bank_is_empty_not_error() {
        assert!(parse_signatures(FIXTURE, "sha384").unwrap().is_empty());
    }

    #[test]
    fn find_matches_policy_and_pcrs() {
        let sigs = parse_signatures(FIXTURE, "sha256").unwrap();
        let hit = find_for_policy(&sigs, &[11], &[0xde, 0xad, 0xbe, 0xef]);
        assert!(hit.is_some());
        // Wrong PCR set -> no match even if digest matches.
        assert!(find_for_policy(&sigs, &[7, 11], &[0xde, 0xad, 0xbe, 0xef]).is_none());
        // Unknown digest -> no match.
        assert!(find_for_policy(&sigs, &[11], &[0x00]).is_none());
    }

    #[test]
    fn rejects_bad_hex() {
        let bad = r#"{"sha256":[{"pcrs":[11],"pkfp":"a","pol":"xyz","sig":"AA=="}]}"#;
        assert!(parse_signatures(bad, "sha256").is_err());
    }

    #[test]
    fn spki_fingerprint_is_deterministic_64_hex() {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};
        let mut rng = rand::thread_rng();
        let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let pem = rsa::RsaPublicKey::from(&sk)
            .to_public_key_pem(LineEnding::LF)
            .expect("pem");
        let fp = pubkey_spki_fingerprint(&pem).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(fp, pubkey_spki_fingerprint(&pem).unwrap(), "deterministic");
        // A freshly generated key is not the pinned production key.
        assert!(ensure_trusted_pubkey(&pem).is_err());
    }
}
