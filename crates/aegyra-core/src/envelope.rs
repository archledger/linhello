//! On-disk TPM envelope format.
//!
//! ```json
//! {
//!   "version": 1,
//!   "mode": "Medium",
//!   "pcrs": [7],
//!   "public":  "<base64 TPM2B_PUBLIC>",
//!   "private": "<base64 TPM2B_PRIVATE>"
//! }
//! ```

use aegyra_common::{AegyraError, Result, SecurityLevel};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub pcr: u32,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub version: u32,
    pub mode: SecurityLevel,
    pub pcrs: Vec<u32>,
    #[serde(with = "b64")]
    pub public: Vec<u8>,
    #[serde(with = "b64")]
    pub private: Vec<u8>,
    /// SHA-256 values for `pcrs`, in the same order, captured at seal time.
    /// Used only for diagnostics — the TPM itself enforces policy via the
    /// PolicyPCR digest baked into `public`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pcr_values: Vec<PcrValue>,
}

impl SealedEnvelope {
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(|e| AegyraError::Serde(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| AegyraError::Serde(e.to_string()))?;
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

