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

use linhello_common::{LinuxHelloError, Result, CONFIG_ROOT};
use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
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

// ── linhello's own PCR-policy signer (GRUB / non-UKI self-heal) ──────────
//
// On systems with no systemd-signed UKI (the common GRUB case), linhello acts
// as its *own* PolicyAuthorize signer over PCR 7. It generates a per-host RSA
// key, seals the template key under `PolicyAuthorize(host_key)`, and signs the
// current PCR-7 policy. When a firmware/dbx update shifts PCR 7, the next unseal
// finds no matching signature and — *only while Secure Boot is still enabled* —
// re-signs the new PCR-7 state with the same host key. The sealed object is
// untouched, so face unlock heals on the first attempt with no re-enrollment.
//
// Security posture (chosen by the operator): the gate weakens from "this exact
// db/dbx" to "any PCR-7 state while Secure Boot stays on" — the host key holder
// (root) can bless any SB-on state, exactly like BitLocker's default PCR-7
// behaviour. An offline attacker still cannot unseal (the secret is TPM-bound);
// an attacker who disables Secure Boot is refused a re-sign and falls back to
// the password.

/// Path of the per-host RSA private key that signs linhello's PCR-7 policies.
pub fn host_signing_key_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("pcr-signing-key.pem")
}

/// Path of the matching public key (the trust anchor for the host signer).
pub fn host_signing_pub_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("pcr-signing-pub.pem")
}

/// Host-wide signature file (same schema as systemd's `tpm2-pcr-signature.json`).
/// PCR 7 is host-global, so this lives once under the config root, not per-user.
pub fn host_signature_path() -> PathBuf {
    PathBuf::from(CONFIG_ROOT).join("pcr-signature.json")
}

/// Which key authorized an envelope's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    /// systemd's UKI PCR-11 signing key (pinned by [`TRUSTED_PUBKEY_SPKI_SHA256`]).
    Systemd,
    /// This host's own linhello PCR-7 signing key.
    LinhelloHost,
}

/// Classify the signing key recorded in an envelope, failing closed if it is
/// neither the pinned systemd key nor this host's own signing key. This is the
/// trust gate for the authorized unseal path: a rewritten envelope referencing
/// an attacker key matches neither anchor and is rejected.
pub fn classify_signer(pubkey_pem: &str) -> Result<SignerKind> {
    let fp = pubkey_spki_fingerprint(pubkey_pem)?;
    if fp == TRUSTED_PUBKEY_SPKI_SHA256 {
        return Ok(SignerKind::Systemd);
    }
    if let Ok(host_pem) = std::fs::read_to_string(host_signing_pub_path()) {
        if pubkey_spki_fingerprint(&host_pem)? == fp {
            return Ok(SignerKind::LinhelloHost);
        }
    }
    Err(LinuxHelloError::Policy(format!(
        "authorized envelope references signing key {fp}, which is neither the \
         pinned systemd key nor this host's linhello signing key; refusing to unseal"
    )))
}

/// Ensure the per-host signing key exists; generate + persist (root-only) on
/// first use. Returns the public-key PEM (the value an envelope binds to).
pub fn ensure_host_signing_key() -> Result<String> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use std::os::unix::fs::PermissionsExt;

    let pub_path = host_signing_pub_path();
    if pub_path.exists() {
        // Already provisioned. NEVER regenerate over an existing public key:
        // envelopes are sealed to it (via `classify_signer`), so a new key would
        // orphan them. Require the private half to be usable; if it isn't (e.g.
        // a non-root caller can't read the 0600 key), surface the error so the
        // policy layer falls back to the literal binding rather than spending a
        // keygen on every call.
        let pem = std::fs::read_to_string(&pub_path)?;
        host_private_key()?;
        return Ok(pem);
    }

    let mut rng = rand::thread_rng();
    let sk = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| LinuxHelloError::Policy(format!("generate host signing key: {e}")))?;
    let priv_pem = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| LinuxHelloError::Policy(format!("encode host signing key: {e}")))?;
    let pub_pem = rsa::RsaPublicKey::from(&sk)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| LinuxHelloError::Policy(format!("encode host signing pubkey: {e}")))?;

    if let Some(parent) = pub_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let key_path = host_signing_key_path();
    std::fs::write(&key_path, priv_pem.as_bytes())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&pub_path, pub_pem.as_bytes())?;
    std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
    Ok(pub_pem)
}

fn host_private_key() -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    let pem = std::fs::read_to_string(host_signing_key_path())?;
    rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
        .map_err(|e| LinuxHelloError::Policy(format!("parse host signing key: {e}")))
}

/// Sign an authorization hash (`aHash = H(approvedPolicy ‖ policyRef)`) with the
/// host signing key, producing an RSASSA-PKCS1v1.5-SHA256 signature — the form
/// `TPM2_VerifySignature` accepts for the PolicyAuthorize step.
pub fn sign_ahash(ahash: &[u8]) -> Result<Vec<u8>> {
    let sk = host_private_key()?;
    sk.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), ahash)
        .map_err(|e| LinuxHelloError::Policy(format!("sign PCR policy: {e}")))
}

/// Load this host's own signatures (from [`host_signature_path`]).
pub fn host_signatures(bank: &str) -> Result<Vec<PcrSignature>> {
    let path = host_signature_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(LinuxHelloError::Io)?;
    parse_signatures(&text, bank)
}

#[derive(Serialize)]
struct WriteEntry {
    pcrs: Vec<u32>,
    pkfp: String,
    pol: String,
    sig: String,
}

/// Persist (append, de-duplicated by policy digest) a host signature for
/// `pcrs`/`pol_digest`/`sig` in `bank`. Old entries are kept so a PCR rollback
/// (e.g. a dbx downgrade) still unseals.
pub fn persist_host_signature(
    bank: &str,
    pcrs: &[u32],
    pol_digest: &[u8],
    sig: &[u8],
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = host_signature_path();
    let mut banks: HashMap<String, Vec<WriteEntry>> = HashMap::new();

    // Preserve any existing entries across all banks.
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(existing) = serde_json::from_str::<HashMap<String, Vec<RawEntry>>>(&text) {
            for (b, entries) in existing {
                banks.insert(
                    b,
                    entries
                        .into_iter()
                        .map(|e| WriteEntry {
                            pcrs: e.pcrs,
                            pkfp: e.pkfp,
                            pol: e.pol,
                            sig: e.sig,
                        })
                        .collect(),
                );
            }
        }
    }

    let pol_hex = hex_lower(pol_digest);
    let entry = WriteEntry {
        pcrs: pcrs.to_vec(),
        pkfp: pubkey_spki_fingerprint(&std::fs::read_to_string(host_signing_pub_path())?)?,
        pol: pol_hex.clone(),
        sig: STANDARD.encode(sig),
    };
    let list = banks.entry(bank.to_string()).or_default();
    if !list.iter().any(|e| e.pol == pol_hex && e.pcrs == pcrs) {
        list.push(entry);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&banks)
        .map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
    // Write atomically: a torn write here (concurrent auths, power loss) would
    // otherwise corrupt the signature file and brick the self-heal path.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
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
