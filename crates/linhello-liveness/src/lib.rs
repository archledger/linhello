//! Passive liveness + camera-trust checks.
//!
//! Two signals only (by design — see LinuxHello design notes):
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
pub mod device_binding;
pub mod ir;
pub mod orientation;
pub mod temporal;

use linhello_common::{LinuxHelloError, Result};
use image::RgbImage;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Primary MiniFASNet model (2.7× scale, MiniFASNetV2). Always required
/// when anti-spoof is enabled.
pub const DEFAULT_ANTISPOOF_MODEL: &str = "/etc/linhello/antispoof.onnx";

/// Secondary MiniFASNet model (4.0× scale, MiniFASNetV1SE). Optional — if
/// present, we run both and average softmax outputs (dual-model fusion is
/// what upstream recommends). If absent we fall back to single-model mode.
pub const DEFAULT_ANTISPOOF_MODEL_4: &str = "/etc/linhello/antispoof_4.onnx";

/// Reject if `spoof_prob >= this`. 0.5 is the MiniFASNet default.
pub const DEFAULT_SPOOF_THRESHOLD: f32 = 0.5;

/// Default minimum temporal eye-motion score (mean-subtracted L1, 0–255 scale)
/// for a live face. Tunable via `LINHELLO_TEMPORAL_MIN`.
///
/// EXPERIMENTAL and OFF by default — see [`temporal_gate_enabled`]. On-hardware
/// validation (2026-06-23) showed passive eye-motion *magnitude* over a ~0.4s
/// burst does NOT separate a live face from a hand-held photo: a jittered photo's
/// motion blur scored 11–21 while a live face scored 10–14 (overlapping). Only a
/// *blink* (the eye-closure pattern) is qualitatively distinct from jitter, which
/// needs a longer window or an active "blink" challenge. The capture/scoring
/// infrastructure is kept for that follow-up; the magnitude gate stays opt-in so
/// it can never false-reject a live user or pass a jittered photo by default.
pub const DEFAULT_TEMPORAL_MIN: f32 = 8.0;

/// Whether the (experimental) temporal eye-motion gate is enabled. OFF by default
/// — opt in with `LINHELLO_TEMPORAL_GATE=1` (see [`DEFAULT_TEMPORAL_MIN`] for why).
pub fn temporal_gate_enabled() -> bool {
    std::env::var("LINHELLO_TEMPORAL_GATE")
        .ok()
        .as_deref()
        .map(|v| matches!(v, "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn temporal_min() -> f32 {
    std::env::var("LINHELLO_TEMPORAL_MIN")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(DEFAULT_TEMPORAL_MIN)
}

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
    /// If true, a missing IR frame is a hard decline (Uncertain) rather than a
    /// silent downgrade to the RGB-only path. Opt-in (default false) so boxes
    /// without an IR sensor keep working; enable it on IR-equipped hardware so
    /// jamming/unplugging the IR camera cannot weaken liveness.
    pub require_ir: bool,
}

impl LivenessConfig {
    /// Build from environment:
    ///   * `LINHELLO_ANTISPOOF_MODEL`   — primary (2.7×) model path, default
    ///     `/etc/linhello/antispoof.onnx`. Always resolves to a concrete path;
    ///     existence is checked in `LivenessEvaluator::new`.
    ///   * `LINHELLO_ANTISPOOF_MODEL_4` — secondary (4.0×) model path,
    ///     default `/etc/linhello/antispoof_4.onnx`. Optional at runtime: if
    ///     the file is missing, we downgrade to single-model mode with a
    ///     one-time warning.
    ///   * `LINHELLO_SPOOF_THRESHOLD`    — reject threshold (default 0.5).
    ///   * `LINHELLO_REQUIRE_ANTISPOOF`  — require the primary model.
    ///     **Defaults to true** (fail-closed): if the model is missing,
    ///     `LivenessEvaluator::new` errors and the auth path declines rather
    ///     than silently running without ML anti-spoof. Set to
    ///     `0`/`false`/`no`/`off` to explicitly opt out (e.g. for bring-up on a
    ///     box without the model).
    pub fn from_env() -> Self {
        let antispoof_model = Some(
            std::env::var_os("LINHELLO_ANTISPOOF_MODEL")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ANTISPOOF_MODEL)),
        );
        let antispoof_model_4 = Some(
            std::env::var_os("LINHELLO_ANTISPOOF_MODEL_4")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ANTISPOOF_MODEL_4)),
        );

        // Reject threshold on a 0..1 softmax probability. Validate and clamp:
        // a NaN/inf (or out-of-range) value would otherwise make the comparison
        // `spoof_prob >= threshold` never fire, silently disabling the ML gate.
        let spoof_threshold = std::env::var("LINHELLO_SPOOF_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<f32>().ok())
            .filter(|v| v.is_finite())
            .map(|v| v.clamp(0.0, 1.0))
            .unwrap_or(DEFAULT_SPOOF_THRESHOLD);

        // Fail-closed by default: only an explicit falsey value disables the
        // requirement. A missing/empty env var keeps anti-spoof mandatory.
        let require_antispoof = std::env::var("LINHELLO_REQUIRE_ANTISPOOF")
            .ok()
            .as_deref()
            .map(|v| !matches!(v, "0" | "false" | "no" | "off" | ""))
            .unwrap_or(true);

        // Opt-in (default false): require an IR frame to be present.
        let require_ir = std::env::var("LINHELLO_REQUIRE_IR")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        LivenessConfig {
            antispoof_model,
            antispoof_model_4,
            spoof_threshold,
            require_antispoof,
            require_ir,
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
    /// Weaker-eye specular IR glint strength (Phase 2). High for a real cornea
    /// reflecting the active emitter, low for a flat photo/screen.
    pub ir_eye_glint: Option<f32>,
    /// Face bbox width / frame width. Gates the IR signal: we only
    /// trust IR when face_frac ≥ `ir::MIN_FACE_FRAC` (25%), otherwise
    /// the user is too far for active-NIR to discriminate a live face
    /// from a wall photo.
    pub face_frac: Option<f32>,

    // --- head orientation (Phase B — ±15° gate) ---
    /// Estimated yaw (horizontal turn), degrees. 0 = frontal.
    pub yaw_deg: Option<f32>,
    /// Estimated pitch (vertical tilt), degrees. 0 = frontal.
    pub pitch_deg: Option<f32>,

    // --- reserved for future signals (not yet implemented) ---
    pub motion_score: Option<f32>,
    pub blink_score: Option<f32>,
    pub consistency_score: Option<f32>,
    pub depth_score: Option<f32>,
}

impl LivenessSignals {
    pub(crate) fn empty() -> Self {
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
            ir_eye_glint: None,
            face_frac: None,
            yaw_deg: None,
            pitch_deg: None,
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

static CACHED: std::sync::OnceLock<std::result::Result<LivenessEvaluator, String>> =
    std::sync::OnceLock::new();

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
                    return Err(LinuxHelloError::Biometrics(format!(
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
                    return Err(LinuxHelloError::Biometrics(
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

    pub fn cached() -> Result<&'static LivenessEvaluator> {
        CACHED
            .get_or_init(|| Self::from_env().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| LinuxHelloError::Biometrics(e.clone()))
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
        landmarks: &[[f32; 2]; 5],
        camera_path: &str,
        ir: Option<&image::GrayImage>,
        temporal_score: Option<f32>,
    ) -> Result<LivenessReport> {
        let mut signals = LivenessSignals::empty();
        signals.motion_score = temporal_score;
        tracing::debug!("liveness: temporal eye-motion score = {temporal_score:?}");

        // Head-orientation gate (WBF ±15°). Reject off-axis faces early —
        // reduces FAR (side-of-face spoofs) and improves ArcFace match
        // quality (recognition degrades off-axis).
        let (yaw, pitch) = orientation::estimate_pose(landmarks);
        signals.yaw_deg = Some(yaw);
        signals.pitch_deg = Some(pitch);
        if !orientation::is_frontal(yaw, pitch, orientation::MAX_ANGLE_DEG) {
            return Ok(LivenessReport {
                decision: LivenessDecision::Uncertain,
                reason: Some(format!(
                    "face not facing camera (yaw {yaw:.0}°, pitch {pitch:.0}°; \
                     need within ±{:.0}°)",
                    orientation::MAX_ANGLE_DEG,
                )),
                signals,
            });
        }

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

        // Fail-closed when IR is required but no frame was captured (sensor
        // unplugged/jammed, capture error, or a panicked capture thread coerced
        // to None upstream). Decline rather than silently fall back to the
        // weaker RGB-only path. Uncertain (not Spoof) so the caller retries /
        // falls back to password rather than treating it as an attack.
        if ir.is_none() && self.config.require_ir {
            return Ok(LivenessReport {
                decision: LivenessDecision::Uncertain,
                reason: Some(
                    "IR liveness required (LINHELLO_REQUIRE_IR) but no IR frame was available"
                        .to_string(),
                ),
                signals,
            });
        }

        // IR gate when a companion sensor is present. Policy derived from
        // calibration on Ben's ASUS WBF rig — see linhello-liveness/src/ir.rs
        // for thresholds and rationale.
        if let Some(ir_frame) = ir {
            let rgb_size = (frame.width(), frame.height());
            let s = ir::evaluate(ir_frame, bbox, rgb_size, landmarks);
            signals.ir_score = Some(s.ir_score);
            signals.ir_mean = Some(s.mean_face);
            signals.ir_std = Some(s.std_face);
            signals.ir_highlight_frac = Some(s.highlight_frac);
            signals.ir_face_bg_ratio = Some(s.face_bg_ratio);
            signals.ir_eye_glint = Some(s.eye_glint);

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

        // Passive temporal liveness: require eye micro-motion across the capture
        // burst. A static photo / still screen image shows none (its eye region is
        // identical frame-to-frame even when waved around, since patches are
        // landmark-aligned). Skipped when the burst couldn't be measured
        // (`temporal_score` None — too few detected frames) or disabled by env.
        // Uncertain (not Spoof) so a genuine user who held unusually still simply
        // retries / falls back to the password.
        if let Some(score) = temporal_score {
            if temporal_gate_enabled() && score < temporal_min() {
                return Ok(LivenessReport {
                    decision: LivenessDecision::Uncertain,
                    reason: Some(format!(
                        "no eye movement detected (motion {score:.1} < {:.1}) — look at the camera and blink; a still photo or screen reads like this",
                        temporal_min()
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
