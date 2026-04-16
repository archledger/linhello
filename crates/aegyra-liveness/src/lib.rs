//! Passive liveness + camera-trust checks.
//!
//! Two signals only (by design — see Aegyra design notes):
//!   * `ml_score`      — MiniFASNet anti-spoof (high value, catches photos/screens)
//!   * `device_score`  — v4l sysfs trust (rejects v4l2loopback / OBS virtual cam)
//!
//! Future signals (motion, blink, depth) have reserved `Option<f32>` slots in
//! [`LivenessSignals`] so they can land without an API break.
//!
//! Decision policy is a **hard gate**, not a weighted sum: any failing signal
//! rejects. Weighted fusion on a tiny set of heterogeneous signals lets a
//! strong ML score mask a failing device check — exactly the inversion we
//! don't want.

pub mod antispoof;
pub mod device;

use aegyra_common::{AegyraError, Result};
use image::RgbImage;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default location for the MiniFASNet ONNX model. See `models/README.md`.
pub const DEFAULT_ANTISPOOF_MODEL: &str = "/etc/aegyra/antispoof.onnx";

/// Reject if `spoof_prob >= this`. 0.5 is the MiniFASNet default.
pub const DEFAULT_SPOOF_THRESHOLD: f32 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessConfig {
    /// Path to the anti-spoof ONNX model. `None` ⇒ skip ML check entirely
    /// (device check still runs).
    pub antispoof_model: Option<PathBuf>,
    /// Reject threshold on the softmax spoof probability.
    pub spoof_threshold: f32,
    /// If true, absence of the anti-spoof model is a hard failure. If false,
    /// we warn once and proceed with device check only.
    pub require_antispoof: bool,
}

impl LivenessConfig {
    /// Build from environment: `AEGYRA_ANTISPOOF_MODEL`, `AEGYRA_SPOOF_THRESHOLD`,
    /// `AEGYRA_REQUIRE_ANTISPOOF`. Always resolves to a concrete path (env
    /// override or default); `LivenessEvaluator::new` then surfaces a
    /// path-specific error if the file is missing.
    pub fn from_env() -> Self {
        let antispoof_model = Some(
            std::env::var_os("AEGYRA_ANTISPOOF_MODEL")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ANTISPOOF_MODEL)),
        );

        let spoof_threshold = std::env::var("AEGYRA_SPOOF_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_SPOOF_THRESHOLD);

        let require_antispoof = std::env::var("AEGYRA_REQUIRE_ANTISPOOF")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "yes"))
            .unwrap_or(false);

        LivenessConfig {
            antispoof_model,
            spoof_threshold,
            require_antispoof,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LivenessDecision {
    Real,
    Spoof,
    Uncertain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessSignals {
    /// Softmax probability from the anti-spoof model that the frame is a
    /// spoof. `None` when the model is absent.
    pub spoof_prob: Option<f32>,
    /// `1.0 - spoof_prob` for convenient reporting. `None` when absent.
    pub ml_score: Option<f32>,
    /// Camera trust: 1.0 real hardware, 0.5 unknown driver, 0.0 virtual cam.
    pub device_score: f32,
    pub device_name: Option<String>,
    pub device_driver: Option<String>,

    // --- reserved for future signals (Phase 2/4 in design) ---
    pub motion_score: Option<f32>,
    pub blink_score: Option<f32>,
    pub consistency_score: Option<f32>,
    pub depth_score: Option<f32>,
    pub ir_score: Option<f32>,
}

impl LivenessSignals {
    fn empty() -> Self {
        LivenessSignals {
            spoof_prob: None,
            ml_score: None,
            device_score: 0.5,
            device_name: None,
            device_driver: None,
            motion_score: None,
            blink_score: None,
            consistency_score: None,
            depth_score: None,
            ir_score: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessReport {
    pub decision: LivenessDecision,
    pub signals: LivenessSignals,
    /// Human-readable explanation of the decision (reason for Spoof/Uncertain).
    pub reason: Option<String>,
}

pub struct LivenessEvaluator {
    config: LivenessConfig,
    antispoof: Option<antispoof::AntiSpoofModel>,
}

impl LivenessEvaluator {
    pub fn new(config: LivenessConfig) -> Result<Self> {
        let antispoof = match &config.antispoof_model {
            Some(path) if path.exists() => Some(antispoof::AntiSpoofModel::load(path)?),
            Some(path) => {
                if config.require_antispoof {
                    return Err(AegyraError::Biometrics(format!(
                        "anti-spoof model required but not found at {}",
                        path.display()
                    )));
                }
                tracing::warn!(
                    "anti-spoof model not found at {} — liveness ML check disabled",
                    path.display()
                );
                None
            }
            None => {
                if config.require_antispoof {
                    return Err(AegyraError::Biometrics(
                        "anti-spoof model required but AEGYRA_ANTISPOOF_MODEL not set".into(),
                    ));
                }
                tracing::warn!("liveness ML check disabled (no anti-spoof model configured)");
                None
            }
        };
        Ok(Self { config, antispoof })
    }

    pub fn from_env() -> Result<Self> {
        Self::new(LivenessConfig::from_env())
    }

    /// Evaluate liveness for `frame` with a detected face at `bbox`
    /// (x1, y1, x2, y2 in frame pixels). `camera_path` is the device that
    /// produced the frame (e.g. `/dev/video0`).
    pub fn evaluate(
        &self,
        frame: &RgbImage,
        bbox: [f32; 4],
        camera_path: &str,
    ) -> Result<LivenessReport> {
        let mut signals = LivenessSignals::empty();

        // Device check is cheap and always runs. A virtual cam is an instant
        // reject regardless of ML score.
        let dev = device::validate_camera_device(camera_path);
        signals.device_score = dev.score;
        signals.device_name = dev.name;
        signals.device_driver = dev.driver;

        if signals.device_score == 0.0 {
            return Ok(LivenessReport {
                decision: LivenessDecision::Spoof,
                reason: Some(format!(
                    "virtual camera detected (driver={:?})",
                    signals.device_driver
                )),
                signals,
            });
        }

        // ML check when available.
        if let Some(m) = &self.antispoof {
            let spoof_prob = m.predict(frame, bbox)?;
            signals.spoof_prob = Some(spoof_prob);
            signals.ml_score = Some(1.0 - spoof_prob);

            if spoof_prob >= self.config.spoof_threshold {
                return Ok(LivenessReport {
                    decision: LivenessDecision::Spoof,
                    reason: Some(format!(
                        "anti-spoof rejected (spoof_prob={spoof_prob:.3} ≥ {:.3})",
                        self.config.spoof_threshold
                    )),
                    signals,
                });
            }
        }

        // No ML model + unknown device ⇒ we can't vouch for liveness.
        let decision = if signals.ml_score.is_none() && signals.device_score < 1.0 {
            LivenessDecision::Uncertain
        } else {
            LivenessDecision::Real
        };
        Ok(LivenessReport {
            decision,
            signals,
            reason: None,
        })
    }
}
