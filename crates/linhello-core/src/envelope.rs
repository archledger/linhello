//! On-disk TPM envelope format.
//!
//! ```json
//! {
//!   "version": 2,
//!   "mode": "Full",
//!   "pcrs": [11],
//!   "policy": { "type": "authorized", "pubkey_pem": "...", "policy_ref": "" },
//!   "public":  "<base64 TPM2B_PUBLIC>",
//!   "private": "<base64 TPM2B_PRIVATE>"
//! }
//! ```
//!
//! `policy` selects how the sealed object's `authPolicy` was built:
//!   * `pcr_literal` (v1 default) — a literal `PolicyPCR` digest over `pcrs`.
//!     The TPM rejects unseal the moment any of those PCRs drifts, so a kernel
//!     update that moves PCR 11 permanently breaks it.
//!   * `authorized` — a `PolicyAuthorize` over a signing public key. Any PCR
//!     state for which a valid signature exists unseals, so a kernel update
//!     that ships a fresh signature needs no reseal or re-enrollment.

use linhello_common::{LinuxHelloError, Result, SecurityLevel};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Current envelope schema version for newly written envelopes.
pub const CURRENT_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub pcr: u32,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

/// How the sealed object's `authPolicy` was constructed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyKind {
    /// Literal `PolicyPCR` digest over `SealedEnvelope::pcrs`. Fragile across
    /// updates that change any bound PCR. This is the implicit kind for v1
    /// envelopes that predate the `policy` field (hence the `Default`).
    #[default]
    PcrLiteral,
    /// `PolicyAuthorize` bound to a signing public key. At unseal we replay
    /// `PolicyPCR` over the current PCRs, then present a signature (over that
    /// policy) that verifies under `pubkey_pem` to satisfy the authorization.
    Authorized {
        /// PEM-encoded RSA public key whose signatures authorize PCR policies.
        pubkey_pem: String,
        /// Opaque policy reference folded into the authorized policy. Must match
        /// the signer's convention; empty matches systemd's `ukify`/`measure`.
        #[serde(with = "b64", default)]
        policy_ref: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub version: u32,
    pub mode: SecurityLevel,
    /// PCRs replayed via `PolicyPCR` at unseal time (for both policy kinds).
    pub pcrs: Vec<u32>,
    /// Policy construction. Absent in v1 envelopes ⇒ `PcrLiteral`.
    #[serde(default)]
    pub policy: PolicyKind,
    #[serde(with = "b64")]
    pub public: Vec<u8>,
    #[serde(with = "b64")]
    pub private: Vec<u8>,
    /// SHA-256 values for `pcrs`, in the same order, captured at seal time.
    /// Used only for diagnostics — the TPM itself enforces policy via the
    /// digest baked into `public`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pcr_values: Vec<PcrValue>,
}

impl SealedEnvelope {
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(|e| LinuxHelloError::Serde(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
        fs::write(path, s)?;
        Ok(())
    }
}

mod b64 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        use serde::Deserialize;
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_envelope_without_policy_defaults_to_literal() {
        // A pre-`policy` envelope must still load and be treated as literal.
        let json = r#"{
            "version": 1, "mode": "Medium", "pcrs": [7],
            "public": "AAEC", "private": "AwQF"
        }"#;
        let env: SealedEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.policy, PolicyKind::PcrLiteral);
        assert_eq!(env.pcrs, vec![7]);
        assert!(env.pcr_values.is_empty());
    }

    #[test]
    fn authorized_envelope_roundtrips() {
        let env = SealedEnvelope {
            version: CURRENT_VERSION,
            mode: SecurityLevel::Full,
            pcrs: vec![11],
            policy: PolicyKind::Authorized {
                pubkey_pem: "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"
                    .into(),
                policy_ref: Vec::new(),
            },
            public: vec![1, 2, 3],
            private: vec![4, 5, 6],
            pcr_values: vec![PcrValue { pcr: 11, value: vec![0xab; 32] }],
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: SealedEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.policy, env.policy);
        assert_eq!(back.pcrs, env.pcrs);
        assert_eq!(back.version, CURRENT_VERSION);
    }

    #[test]
    fn authorized_policy_tag_is_snake_case() {
        let json = r#"{
            "version": 2, "mode": "Full", "pcrs": [11],
            "policy": {"type": "authorized", "pubkey_pem": "x", "policy_ref": ""},
            "public": "AAEC", "private": "AwQF"
        }"#;
        let env: SealedEnvelope = serde_json::from_str(json).unwrap();
        match env.policy {
            PolicyKind::Authorized { pubkey_pem, policy_ref } => {
                assert_eq!(pubkey_pem, "x");
                assert!(policy_ref.is_empty());
            }
            other => panic!("expected authorized, got {other:?}"),
        }
    }
}

