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
pub mod ir;

use aegyra_common::{AegyraError, Result};
use image::RgbImage;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Primary MiniFASNet model (2.7× scale, MiniFASNetV2). Always required
/// when anti-spoof is enabled.
pub const DEFAULT_ANTISPOOF_MODEL: &str = "/etc/aegyra/antispoof.onnx";

/// Secondary MiniFASNet model (4.0× scale, MiniFASNetV1SE). Optional — if
/// present, we run both and average softmax outputs (dual-model fusion is
/// what upstream recommends). If absent we fall back to single-model mode.
pub const DEFAULT_ANTISPOOF_MODEL_4: &str = "/etc/aegyra/antispoof_4.onnx";

/// Reject if `spoof_prob >= this`. 0.5 is the MiniFASNet default.
pub const DEFAULT_SPOOF_THRESHOLD: f32 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessConfig {
    /// Primary anti-spoof model (2.7× scale). `None` ⇒ skip ML check
    /// entirely (device check still runs).
    pub antispoof_model: Option<PathBuf>,
    /// Secondary anti-spoof model (4.0× scale) for dual-model fusion.
    /// `None` ⇒ run single-model (weaker — see upstream).
    pub antispoof_model_4: Option<PathBuf>,
    /// Reject threshold on the softmax spoof probability.
    pub spoof_threshold: f32,
    /// If true, absence of the primary anti-spoof model is a hard failure.
    /// The secondary model is always optional — its absence only downgrades
    /// to single-model mode, it never fails.
    pub require_antispoof: bool,
}

impl LivenessConfig {
    /// Build from environment:
    ///   * `AEGYRA_ANTISPOOF_MODEL`   — primary (2.7×) model path, default
    ///     `/etc/aegyra/antispoof.onnx`. Always resolves to a concrete path;
    ///     existence is checked in `LivenessEvaluator::new`.
    ///   * `AEGYRA_ANTISPOOF_MODEL_4` — secondary (4.0×) model path,
    ///     default `/etc/aegyra/antispoof_4.onnx`. Optional at runtime: if
    ///     the file is missing, we downgrade to single-model mode with a
    ///     one-time warning.
    ///   * `AEGYRA_SPOOF_THRESHOLD`    — reject threshold (default 0.5).
    ///   * `AEGYRA_REQUIRE_ANTISPOOF`  — fail-closed on missing primary.
    pub fn from_env() -> Self {
        let antispoof_model = Some(
            std::env::var_os("AEGYRA_ANTISPOOF_MODEL")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ANTISPOOF_MODEL)),
        );
        let antispoof_model_4 = Some(
            std::env::var_os("AEGYRA_ANTISPOOF_MODEL_4")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ANTISPOOF_MODEL_4)),
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
            antispoof_model_4,
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

    // --- IR companion sensor (Phase A — active-IR liveness) ---
    /// Heuristic 0..1 score derived from IR intensity in the face region.
    /// Near-0 for a wall photo (1/r² fall-off under active NIR) or a
    /// screen replay (screens emit almost no NIR). Near-1 for a real
    /// face well-illuminated by the active IR emitter.
    pub ir_score: Option<f32>,
    /// Raw mean pixel intensity in the face bbox (0–255). Surfaced so the
    /// operator can calibrate a threshold on their own rig before we
    /// promote `ir_score` to a hard gate.
    pub ir_mean: Option<f32>,
    /// Std-dev of IR intensity in the face bbox. Real skin under active
    /// NIR has structure (nose shadow, eye sockets); flat photos at
    /// distance are nearly uniform.
    pub ir_std: Option<f32>,
    /// Fraction of near-saturated (>240) pixels in the face bbox. Real
    /// eye glints show as small bright clusters; glossy paper photos
    /// show a single diffuse hotspot; matte photos/screens show none.
    pub ir_highlight_frac: Option<f32>,
    /// face_mean / background_mean in the IR frame. AE-gain-invariant
    /// signal: a real face under the emitter is brighter than surroundings;
    /// a flat photo on a wall is not.
    pub ir_face_bg_ratio: Option<f32>,
    /// Face bbox width / frame width. Gates the IR signal: we only
    /// trust IR when face_frac ≥ `ir::MIN_FACE_FRAC` (25%), otherwise
    /// the user is too far for active-NIR to discriminate a live face
    /// from a wall photo.
    pub face_frac: Option<f32>,

    // --- reserved for future signals (not yet implemented) ---
    pub motion_score: Option<f32>,
    pub blink_score: Option<f32>,
    pub consistency_score: Option<f32>,
    pub depth_score: Option<f32>,
}

impl LivenessSignals {
    fn empty() -> Self {
        LivenessSignals {
            spoof_prob: None,
            ml_score: None,
            device_score: 0.5,
            device_name: None,
            device_driver: None,
            ir_score: None,
            ir_mean: None,
            ir_std: None,
            ir_highlight_frac: None,
            ir_face_bg_ratio: None,
            face_frac: None,
            motion_score: None,
            blink_score: None,
            consistency_score: None,
            depth_score: None,
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
        // Build the ensemble. Primary (2.7×) is mandatory when require_antispoof
        // is set; secondary (4.0×) is always optional and, if missing, we
        // downgrade to single-model mode with a warning.
        let mut items: Vec<(std::path::PathBuf, f32, &'static str)> = Vec::new();

        match &config.antispoof_model {
            Some(path) if path.exists() => items.push((path.clone(), 2.7, "2.7_V2")),
            Some(path) => {
                if config.require_antispoof {
                    return Err(AegyraError::Biometrics(format!(
                        "anti-spoof model required but not found at {}",
                        path.display()
                    )));
                }
                tracing::warn!(
                    "primary anti-spoof model not found at {} — liveness ML check disabled",
                    path.display()
                );
            }
            None => {
                if config.require_antispoof {
                    return Err(AegyraError::Biometrics(
                        "anti-spoof required but no primary model configured".into(),
                    ));
                }
                tracing::warn!("liveness ML check disabled (no anti-spoof model configured)");
            }
        }

        if let Some(p4) = &config.antispoof_model_4 {
            if p4.exists() {
                items.push((p4.clone(), 4.0, "4.0_V1SE"));
            } else {
                tracing::warn!(
                    "secondary anti-spoof model not found at {} — running single-model \
                     (weaker against printed-photo attacks; install the 4.0× model \
                     for dual-model fusion)",
                    p4.display()
                );
            }
        }

        let antispoof = if items.is_empty() {
            None
        } else {
            let refs: Vec<(&std::path::Path, f32, &str)> =
                items.iter().map(|(p, s, l)| (p.as_path(), *s, *l)).collect();
            Some(antispoof::AntiSpoofModel::load_ensemble(&refs)?)
        };
        Ok(Self { config, antispoof })
    }

    pub fn from_env() -> Result<Self> {
        Self::new(LivenessConfig::from_env())
    }

    /// Evaluate liveness for `frame` with a detected face at `bbox`
    /// (x1, y1, x2, y2 in frame pixels). `camera_path` is the device that
    /// produced the frame (e.g. `/dev/video0`). `ir` is an optional
    /// grayscale frame from the companion NIR sensor; when present we
    /// populate the `ir_*` fields of `LivenessSignals`.
    pub fn evaluate(
        &self,
        frame: &RgbImage,
        bbox: [f32; 4],
        camera_path: &str,
        ir: Option<&image::GrayImage>,
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

        // Face coverage: fraction of frame width the detected bbox spans.
        // Gates the IR signal below (IR is only trustworthy when the face
        // is close enough to the active emitter — roughly ≥25% of frame).
        let bbox_w = (bbox[2] - bbox[0]).max(0.0);
        let face_frac = bbox_w / frame.width().max(1) as f32;
        signals.face_frac = Some(face_frac);

        // IR gate when a companion sensor is present. Policy derived from
        // calibration on Ben's ASUS WBF rig — see aegyra-liveness/src/ir.rs
        // for thresholds and rationale.
        if let Some(ir_frame) = ir {
            let rgb_size = (frame.width(), frame.height());
            let s = ir::evaluate(ir_frame, bbox, rgb_size);
            signals.ir_score = Some(s.ir_score);
            signals.ir_mean = Some(s.mean_face);
            signals.ir_std = Some(s.std_face);
            signals.ir_highlight_frac = Some(s.highlight_frac);
            signals.ir_face_bg_ratio = Some(s.face_bg_ratio);

            match ir::classify(&s, face_frac) {
                ir::IrVerdict::Real => { /* IR passes; fall through to ML */ }
                ir::IrVerdict::TooFar => {
                    // Uncertain, not spoof: the user is legitimate but
                    // positioned where we can't verify. Surface as a
                    // human-actionable message; the caller (PAM stack,
                    // sudo, etc.) turns this into a retry loop.
                    return Ok(LivenessReport {
                        decision: LivenessDecision::Uncertain,
                        reason: Some(format!(
                            "move closer to the camera — face fills {:.0}% of frame, \
                             need ≥{:.0}% for IR liveness",
                            face_frac * 100.0,
                            ir::MIN_FACE_FRAC * 100.0,
                        )),
                        signals,
                    });
                }
                ir::IrVerdict::Reject(reason) => {
                    return Ok(LivenessReport {
                        decision: LivenessDecision::Spoof,
                        reason: Some(format!("IR liveness rejected: {reason}")),
                        signals,
                    });
                }
            }
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
