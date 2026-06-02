//! Wire protocol for the `/run/linhello.sock` daemon.
//!
//! Messages are newline-delimited JSON. One request, one response per
//! connection. Binary payloads (sealed secrets) travel as raw byte arrays —
//! JSON array-of-integers is acceptable at the sizes we care about (≤32 B).

use crate::{BootMode, SecurityLevel};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Fallback for `Verified.threshold` when decoding a response from an older
/// daemon that didn't send the field. Mirrors `DEFAULT_MATCH_THRESHOLD`.
fn default_threshold() -> f32 {
    0.60
}

/// A byte buffer carrying a secret (login password / unsealed keyring secret)
/// across the wire. Serializes identically to `Vec<u8>` (a JSON array of
/// integers), but the in-memory buffer is wiped on drop and its `Debug` is
/// redacted, so a secret never lingers on the heap of the daemon or PAM host
/// or leaks into a log line.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }
    /// Borrow the raw bytes. Callers must not copy them into a non-zeroizing
    /// buffer.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([{} bytes redacted])", self.0.len())
    }
}

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
    /// given user. Per-user envelope at /etc/linhello/<user>/password_envelope.json.
    /// Root-only.
    SealPassword { user: String, password: SecretBytes },
    /// Face-verify the user and, on success, return their TPM-sealed login
    /// password so pam_gnome_keyring can unlock the existing keyring with
    /// `use_authtok`. Root-only.
    UnsealPassword { user: String },
    /// Report envelope presence, PCR drift, and TPM reachability without
    /// attempting a full unseal.
    Diagnose,
    /// Capture one frame and run the liveness pipeline. Debug-only; returns
    /// raw signals so the operator can tune thresholds. Does not touch
    /// enrollment data.
    LivenessTest,
    /// Unseal + immediately reseal all per-user TPM envelopes (password +
    /// template key) under current PCR state. Used by the pacman hook
    /// after kernel/bootloader updates. Root-only.
    ResealUserEnvelopes { user: String },
    /// Probe the host for the hardware/software LinuxHello needs (TPM, Secure
    /// Boot, RGB/IR cameras, ONNX runtime, models). Unprivileged.
    Probe,
}

/// Result of a single capability check in [`CapabilityReport`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Present and usable.
    Ok,
    /// Usable but degraded (e.g. running without IR liveness / signed policy).
    Warn,
    /// Absent — blocks LinuxHello if the check is `required`.
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub name: String,
    pub status: CapabilityStatus,
    pub detail: String,
    /// If true, `Missing` means LinuxHello cannot function.
    pub required: bool,
}

/// Host readiness summary returned by [`Request::Probe`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub checks: Vec<CapabilityCheck>,
}

impl CapabilityReport {
    /// Can LinuxHello run at all? True unless a required capability is missing.
    pub fn can_run(&self) -> bool {
        self.checks
            .iter()
            .all(|c| !(c.required && c.status == CapabilityStatus::Missing))
    }

    /// Running, but with a reduced security/feature posture?
    pub fn degraded(&self) -> bool {
        self.can_run()
            && self.checks.iter().any(|c| {
                c.status == CapabilityStatus::Warn
                    || (!c.required && c.status == CapabilityStatus::Missing)
            })
    }
}

/// Wire-side liveness summary. Mirrors `linhello_liveness::LivenessReport` but
/// lives here so `linhello-common` stays a leaf crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessSummary {
    pub decision: String, // "real" | "spoof" | "uncertain"
    pub spoof_prob: Option<f32>,
    pub ml_score: Option<f32>,
    pub device_score: f32,
    pub device_name: Option<String>,
    pub device_driver: Option<String>,
    pub ir_score: Option<f32>,
    pub ir_mean: Option<f32>,
    pub ir_std: Option<f32>,
    pub ir_highlight_frac: Option<f32>,
    pub ir_face_bg_ratio: Option<f32>,
    pub face_frac: Option<f32>,
    pub yaw_deg: Option<f32>,
    pub pitch_deg: Option<f32>,
    pub reason: Option<String>,
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
        /// The cosine threshold the daemon compared against (so clients can
        /// show "score 0.71 ≥ 0.60" without guessing the daemon's config).
        #[serde(default = "default_threshold")]
        threshold: f32,
    },
    Unsealed {
        secret: SecretBytes,
    },
    Resealed {
        bytes: usize,
    },
    PasswordSealed,
    PasswordUnsealed {
        secret: SecretBytes,
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
    LivenessChecked {
        summary: LivenessSummary,
    },
    UserEnvelopesResealed {
        password: bool,
        template_key: bool,
    },
    Capabilities {
        report: CapabilityReport,
    },
    Error {
        message: String,
    },
}
