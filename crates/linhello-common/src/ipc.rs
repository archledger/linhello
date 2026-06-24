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

/// Default for `PolicyStatus.hardware_ready` when decoding from an older daemon
/// that didn't send it — assume ready (no spurious warning).
fn ready_default() -> bool {
    true
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
    /// Tiered-policy authentication (the PAM entry point). The daemon classifies
    /// `service` (with logind warm-session state), looks up the hardware tier,
    /// and either unseals (→ `PasswordUnsealed`), verifies without releasing the
    /// secret (→ `Verified{matched:true}`), or denies (→ `Error`). Replaces the
    /// euid heuristic in pam_linhello. Root-only for the unseal path.
    Authenticate { user: String, service: String },
    /// Pre-flight for [`Request::Authenticate`]: run the *same* classify → tier →
    /// warm → decide pipeline but DO NOT capture or touch the camera/TPM. Lets the
    /// PAM module learn whether this operation will actually engage the camera
    /// (→ `AuthPlan{engage:true}`) before it announces "Looking for your face…".
    /// On the convenience tier at the greeter (a `Deny`), `engage` is false so no
    /// prompt is shown and PAM falls straight through to the password — no camera
    /// is ever lit. Cheap and side-effect-free.
    AuthIntent { user: String, service: String },
    /// Report the effective biometric tier and the per-operation policy for
    /// `user` (what face auth will do for screen-unlock / login / sudo / etc.),
    /// without capturing or touching the camera/TPM. Pure status, so `doctor`
    /// and the TUI can surface exactly what the daemon will do — no drift from
    /// the real decision path. Gated like [`Request::AuthIntent`] (own uid/root).
    PolicyStatus { user: String },
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
    /// Capture one frame and return live framing geometry (face presence,
    /// size, orientation, centering) for the enrollment positioning guide.
    /// Detection-only: no embedding, match score, or image pixels leave the
    /// daemon. Unprivileged; intended to be polled at a few Hz while the user
    /// frames their face.
    PositionSample,
    /// List the enrolled profiles (identities with a stored face template)
    /// plus their friendly names and sample counts. Metadata only — no
    /// biometrics. Unprivileged.
    ListProfiles,
    /// Capture one frame and identify which enrolled profile it best matches
    /// (1:N). Returns the best profile and a ranked candidate list. Root-only:
    /// it is an identity oracle, so it stays an administrative/setup operation.
    Identify,
    /// Set (or clear, with an empty name) a profile's friendly display name.
    /// Root-only.
    SetProfileName { user: String, name: String },
    /// Wrap the user's current template key under a dedicated recovery
    /// passphrase (separate from the login password) and persist the recovery
    /// envelope. Requires the template key to be unsealable now. Root-only.
    SaveRecovery { user: String, passphrase: SecretBytes },
    /// Restore the template key from the recovery passphrase and re-seal it under
    /// the current TPM policy — the manual backstop when the automatic self-heal
    /// can't run (Secure Boot off, TPM cleared, disk moved). Root-only.
    RestoreFromRecovery { user: String, passphrase: SecretBytes },
}

/// One enrolled identity, as reported by [`Request::ListProfiles`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    /// Storage name (the directory under `CONFIG_ROOT`, and the PAM user when
    /// wired into login).
    pub user: String,
    /// Friendly display name, if the operator set one.
    pub name: Option<String>,
    /// Number of stored face samples.
    pub samples: usize,
    /// A sealed login-password envelope exists (so this profile can unlock a
    /// keyring on login).
    pub has_password: bool,
}

/// One operation class and the action the daemon would take for it under the
/// current tier + policy, as reported by [`Request::PolicyStatus`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationPolicy {
    /// Human label for the operation ("Screen unlock", "Login (greeter)", …).
    pub operation: String,
    /// The action: `"verify"` | `"unseal"` | `"deny"`.
    pub action: String,
    /// One-line plain-English meaning of that action for this operation.
    pub effect: String,
}

/// One scored candidate in an [`Request::Identify`] result, best first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifyCandidate {
    pub user: String,
    pub name: Option<String>,
    pub score: f32,
}

/// Live framing geometry for the enrollment positioning guide
/// ([`Request::PositionSample`]). Carries only detector geometry — never image
/// pixels — so it is safe to send over the socket and to poll repeatedly. The
/// gates that set `well_framed` mirror the auth path (`MIN_FACE_FRAC`,
/// `MAX_ANGLE_DEG`), so "well framed" here implies enrollment will accept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionReport {
    /// Number of faces detected in the frame.
    pub face_count: u32,
    pub frame_w: u32,
    pub frame_h: u32,
    /// Primary face bounding box `[x1, y1, x2, y2]` in frame pixels, if any.
    pub bbox: Option<[f32; 4]>,
    /// Face width / frame width (framing/distance signal).
    pub face_frac: Option<f32>,
    pub yaw_deg: Option<f32>,
    pub pitch_deg: Option<f32>,
    /// Mean luma (0–255) of the face region — lighting signal.
    pub brightness: Option<f32>,
    /// Relative sharpness of the face region (gradient energy); higher = crisper.
    /// Camera-relative, not an absolute scale — used for blur/motion hints.
    pub sharpness: Option<f32>,
    /// Composite framing quality, 0–100, from size/centering/pose/lighting (+IR).
    pub quality: u8,
    /// An IR companion sensor is present and produced a frame this sample.
    pub ir_present: bool,
    /// Mean IR intensity over the face region (emitter illumination signal).
    pub ir_brightness: Option<f32>,
    /// IR face/background ratio — a real, emitter-lit face is brighter than its
    /// surroundings (>1). The "IR can see your face" / liveness-ready signal.
    pub ir_face_bg: Option<f32>,
    /// True when RGB couldn't find the face but IR could — too dark for an RGB
    /// enrollment capture, even though the IR camera sees you.
    pub low_light: bool,
    /// All framing gates pass — safe to capture an enrollment sample.
    pub well_framed: bool,
    /// One-line human guidance ("Move closer", "Hold still — ready to capture").
    pub guidance: String,
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
    /// Specular IR eye-glint strength (Phase 2 active-IR liveness probe).
    pub ir_eye_glint: Option<f32>,
    /// Center÷edge IR brightness — the depth/curvature cue (>1.3 for a live 3-D
    /// face, ~1 for a flat photo/screen). `#[serde(default)]` for older daemons.
    #[serde(default)]
    pub ir_depth_ratio: Option<f32>,
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
    Position {
        report: PositionReport,
    },
    Profiles {
        profiles: Vec<ProfileInfo>,
    },
    /// Result of [`Request::Identify`]. `best` is `None` when no profile cleared
    /// the threshold; `candidates` is always the full ranked list (best first)
    /// so the caller can show near-misses.
    Identified {
        best: Option<IdentifyCandidate>,
        threshold: f32,
        candidates: Vec<IdentifyCandidate>,
    },
    ProfileNameSet,
    /// A recovery passphrase was set (the template key was wrapped under it).
    RecoverySaved,
    /// The template key was restored from the recovery passphrase and re-sealed.
    RecoveryRestored,
    /// Result of [`Request::AuthIntent`]: the decision the daemon *would* make for
    /// this (user, service, tier, warm) without capturing. `engage` is true when
    /// the action is Verify or Unseal (the camera will be lit), false for Deny.
    /// `action` carries the human label ("verify" | "unseal" | "deny") for logs.
    AuthPlan {
        engage: bool,
        action: String,
        /// When the camera *would* engage but is currently unusable, a short,
        /// user-facing reason the PAM module shows at the greeter/lock screen
        /// instead of "Looking for your face…" (e.g. the hardware privacy switch
        /// is on, or no camera is detected). `None` when the camera is ready or
        /// the operation doesn't engage it. `#[serde(default)]` for older daemons.
        #[serde(default)]
        camera_notice: Option<String>,
    },
    /// Result of [`Request::PolicyStatus`]: the effective tier and per-operation
    /// policy the daemon would apply right now.
    PolicyStatus {
        /// Effective tier label, e.g. `"secure (RGB + active IR)"` /
        /// `"convenience (RGB only)"`.
        tier: String,
        /// True when the effective tier is Secure (may unseal credentials).
        secure: bool,
        /// Hardware tier from the enrolled camera binding, before any
        /// `policy.conf` `tier=` override.
        hardware_tier: String,
        /// The effective tier was forced by `policy.conf` (differs from hardware).
        overridden: bool,
        /// Whether `user` has an enrolled camera binding at all.
        enrolled: bool,
        /// Live check: the currently-present cameras still satisfy the enrolled
        /// binding (for a Secure-tier user, the IR camera is present and matches).
        /// `false` means secure operations will fail closed to the password right
        /// now — the tier itself does NOT downgrade. Defaults true for older
        /// daemons that don't report it.
        #[serde(default = "ready_default")]
        hardware_ready: bool,
        /// Human explanation when `hardware_ready` is false (e.g. "IR camera not
        /// detected …"); empty when ready.
        #[serde(default)]
        hardware_note: String,
        /// Per-operation rows (screen unlock, login, elevation, remote, unknown).
        ops: Vec<OperationPolicy>,
    },
    Error {
        message: String,
    },
}
