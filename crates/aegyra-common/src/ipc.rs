//! Wire protocol for the `/run/aegyra.sock` daemon.
//!
//! Messages are newline-delimited JSON. One request, one response per
//! connection. Binary payloads (sealed secrets) travel as raw byte arrays —
//! JSON array-of-integers is acceptable at the sizes we care about (≤32 B).

use crate::{BootMode, SecurityLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Capture one frame and store the resulting embedding. Default appends
    /// to any existing samples (supports glasses-on / glasses-off / other
    /// appearance variations). `reset: true` wipes prior samples first.
    Enroll {
        user: String,
        #[serde(default)]
        reset: bool,
    },
    Verify { user: String },
    /// Verify the user's face and, on success, return the unsealed keyring
    /// secret. Only callers with uid 0 are permitted.
    Unseal { user: String },
    /// Seal a freshly generated random secret under the current PCR policy.
    Reseal,
    /// Seal a user-supplied secret (login password) against PCRs for the
    /// given user. Per-user envelope at /etc/aegyra/<user>/password_envelope.json.
    /// Root-only.
    SealPassword { user: String, password: Vec<u8> },
    /// Face-verify the user and, on success, return their TPM-sealed login
    /// password so pam_gnome_keyring can unlock the existing keyring with
    /// `use_authtok`. Root-only.
    UnsealPassword { user: String },
    /// Report envelope presence, PCR drift, and TPM reachability without
    /// attempting a full unseal.
    Diagnose,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Status {
        security_level: SecurityLevel,
        boot_mode: BootMode,
        secure_boot: bool,
        loader: Option<String>,
    },
    Enrolled {
        samples: usize,
    },
    Verified {
        matched: bool,
        score: f32,
    },
    Unsealed {
        secret: Vec<u8>,
    },
    Resealed {
        bytes: usize,
    },
    PasswordSealed,
    PasswordUnsealed {
        secret: Vec<u8>,
    },
    Diagnosed {
        envelope_present: bool,
        security_level: SecurityLevel,
        tracked_pcrs: Vec<u32>,
        /// `None` when no drift (or no PCR values stored). `Some(list)` names
        /// the PCRs whose SHA-256 differs from the seal-time snapshot.
        pcr_drift: Option<Vec<u32>>,
        tpm_error: Option<String>,
    },
    Error {
        message: String,
    },
}
