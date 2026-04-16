//! Root-privileged service: enrollment, TPM sealing, and IPC over /run/aegyra.sock.

use aegyra_common::ipc::{LivenessSummary, Request, Response};
use aegyra_liveness::device_binding::{CameraBinding, DeviceIdentity};
use aegyra_common::client::socket_path;
use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let socket: PathBuf = parse_socket_arg().unwrap_or_else(socket_path);
    if socket.exists() {
        std::fs::remove_file(&socket)
            .with_context(|| format!("removing stale socket {}", socket.display()))?;
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding {}", socket.display()))?;
    // 0660 would be ideal with an `aegyra` group; until we ship that group
    // assignment, use 0666 and rely on the per-op uid check for privileged ops.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("chmod {}", socket.display()))?;

    tracing::info!("aegyrad listening on {}", socket.display());

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle(stream).await {
                tracing::warn!(error = %e, "connection error");
            }
        });
    }
}

async fn handle(stream: UnixStream) -> Result<()> {
    let peer_uid = stream.peer_cred().ok().and_then(|c| Some(c.uid()));
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(req) => dispatch(req, peer_uid).await,
        Err(e) => Response::Error {
            message: format!("malformed request: {e}"),
        },
    };

    let mut out =
        serde_json::to_vec(&response).context("serializing response")?;
    out.push(b'\n');
    write.write_all(&out).await?;
    write.flush().await?;
    Ok(())
}

async fn dispatch(req: Request, peer_uid: Option<u32>) -> Response {
    match req {
        Request::Status => task::spawn_blocking(do_status).await.unwrap_or_else(err),
        Request::Enroll { user, reset } => {
            if !is_root(peer_uid) {
                return forbidden("enroll");
            }
            task::spawn_blocking(move || do_enroll(&user, reset))
                .await
                .unwrap_or_else(err)
        }
        Request::Verify { user } => task::spawn_blocking(move || do_verify(&user))
            .await
            .unwrap_or_else(err),
        Request::Unseal { user } => {
            if !is_root(peer_uid) {
                return forbidden("unseal");
            }
            task::spawn_blocking(move || do_unseal(&user))
                .await
                .unwrap_or_else(err)
        }
        Request::Reseal => {
            if !is_root(peer_uid) {
                return forbidden("reseal");
            }
            task::spawn_blocking(do_reseal).await.unwrap_or_else(err)
        }
        Request::SealPassword { user, password } => {
            if !is_root(peer_uid) {
                return forbidden("seal_password");
            }
            task::spawn_blocking(move || do_seal_password(&user, password))
                .await
                .unwrap_or_else(err)
        }
        Request::UnsealPassword { user } => {
            if !is_root(peer_uid) {
                return forbidden("unseal_password");
            }
            task::spawn_blocking(move || do_unseal_password(&user))
                .await
                .unwrap_or_else(err)
        }
        Request::Diagnose => task::spawn_blocking(do_diagnose).await.unwrap_or_else(err),
        Request::LivenessTest => task::spawn_blocking(do_liveness_test).await.unwrap_or_else(err),
    }
}

fn is_root(uid: Option<u32>) -> bool {
    matches!(uid, Some(0))
}

fn parse_socket_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--socket" {
            return args.next().map(PathBuf::from);
        }
        if let Some(v) = a.strip_prefix("--socket=") {
            return Some(PathBuf::from(v));
        }
    }
    None
}

fn forbidden(op: &str) -> Response {
    Response::Error {
        message: format!("{op} requires root"),
    }
}

fn err(e: task::JoinError) -> Response {
    Response::Error {
        message: format!("worker panicked: {e}"),
    }
}

fn do_status() -> Response {
    Response::Status {
        security_level: aegyra_core::detect_security_level(),
        boot_mode: aegyra_secureboot::detect_boot_mode(),
        secure_boot: aegyra_secureboot::is_secure_boot_enabled(),
        loader: aegyra_secureboot::loader_identity(),
    }
}

fn do_enroll(user: &str, reset: bool) -> Response {
    // Capture + liveness + embed.
    let embedding = match aegyra_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let raw = embedding_to_bytes(&embedding);

    // Ensure per-user AES key exists (creates + TPM-seals on first enroll).
    let key = match aegyra_core::ensure_template_key(user) {
        Ok(k) => k,
        Err(e) => return Response::Error { message: format!("template key: {e}") },
    };

    // Load existing encrypted embeddings (if appending).
    let mut all_raw = if reset {
        Vec::new()
    } else {
        match aegyra_core::load_encrypted_embedding(user, &key) {
            Ok(existing) => existing.to_vec(),
            Err(_) => Vec::new(), // no enrollment yet
        }
    };
    all_raw.extend_from_slice(&raw);

    // Encrypt and persist.
    if let Err(e) = aegyra_core::save_encrypted_embedding(user, &all_raw, &key) {
        return Response::Error { message: format!("save enrollment: {e}") };
    }

    // Record camera identity (soft-SDCP). Overwritten on each enroll so
    // a hardware upgrade is handled by re-enrolling.
    save_camera_binding(user, &snapshot_camera_binding());

    let samples = all_raw.len() / (aegyra_biometrics::enroll::EMBEDDING_DIM * 4);
    Response::Enrolled { samples }
}

fn camera_binding_path(user: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(aegyra_common::CONFIG_ROOT)
        .join(user)
        .join("camera_binding.json")
}

fn snapshot_camera_binding() -> CameraBinding {
    use aegyra_biometrics::camera::{DEFAULT_DEVICE, DEFAULT_IR_DEVICE};
    CameraBinding {
        rgb: DeviceIdentity::from_device(DEFAULT_DEVICE)
            .unwrap_or_else(|| DeviceIdentity {
                vid: String::new(), pid: String::new(),
                serial: String::new(), name: "unknown".into(),
            }),
        ir: DeviceIdentity::from_device(DEFAULT_IR_DEVICE),
    }
}

fn save_camera_binding(user: &str, binding: &CameraBinding) {
    let path = camera_binding_path(user);
    if let Ok(json) = serde_json::to_string_pretty(binding) {
        let _ = std::fs::write(&path, json);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

fn check_camera_binding(user: &str) -> Result<(), String> {
    let path = camera_binding_path(user);
    if !path.exists() {
        return Ok(());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| format!("read binding: {e}"))?;
    let enrolled: CameraBinding =
        serde_json::from_str(&json).map_err(|e| format!("parse binding: {e}"))?;
    let current = snapshot_camera_binding();
    enrolled.verify(&current)
}

fn embedding_to_bytes(vec: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vec.len() * 4);
    for f in vec {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    bytes
}

fn do_verify(user: &str) -> Response {
    // Try encrypted path first; fall back to legacy unencrypted.
    let samples = match load_user_samples(user) {
        Ok(s) => s,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let live = match aegyra_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let r = aegyra_biometrics::match_against(&live, &samples);
    Response::Verified {
        matched: r.matched,
        score: r.score,
    }
}

/// Load enrolled samples, preferring encrypted storage. If the user has
/// a legacy `embedding.bin` and no encrypted store yet, auto-migrates:
/// generates + TPM-seals an AES key, encrypts the embeddings, deletes
/// the plaintext file. Falls back to legacy only if TPM is unreachable.
fn load_user_samples(user: &str) -> std::result::Result<Vec<Vec<f32>>, String> {
    // Soft-SDCP: verify camera hardware hasn't been swapped since enrollment.
    check_camera_binding(user)?;

    match aegyra_core::ensure_template_key(user) {
        Ok(key) => {
            let raw = aegyra_core::load_encrypted_embedding(user, &key)
                .map_err(|e| e.to_string())?;
            aegyra_biometrics::parse_embeddings(&raw).map_err(|e| e.to_string())
        }
        Err(e) => {
            tracing::warn!("template key unavailable ({e}), using legacy storage");
            aegyra_biometrics::enroll::load_embeddings(user).map_err(|e| e.to_string())
        }
    }
}

fn do_unseal(user: &str) -> Response {
    let samples = match load_user_samples(user) {
        Ok(s) => s,
        Err(e) => return Response::Error { message: e },
    };
    let live = match aegyra_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let r = aegyra_biometrics::match_against(&live, &samples);
    if !r.matched {
        return Response::Error {
            message: format!("face mismatch (score {:.4})", r.score),
        };
    }
    match aegyra_core::unseal_keyring_secret() {
        Ok(secret) => Response::Unsealed {
            secret: secret.to_vec(),
        },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_diagnose() -> Response {
    let path = aegyra_core::envelope_path();
    let envelope_present = path.exists();
    let security_level = aegyra_core::detect_security_level();

    if !envelope_present {
        return Response::Diagnosed {
            envelope_present: false,
            security_level,
            tracked_pcrs: Vec::new(),
            pcr_drift: None,
            tpm_error: None,
        };
    }

    let env = match aegyra_core::envelope::SealedEnvelope::load(&path) {
        Ok(e) => e,
        Err(e) => {
            return Response::Error {
                message: format!("envelope load: {e}"),
            }
        }
    };
    let tracked_pcrs = env.pcrs.clone();

    match aegyra_core::tpm::diagnose_pcrs(&env) {
        Ok(changed) => Response::Diagnosed {
            envelope_present: true,
            security_level,
            tracked_pcrs,
            pcr_drift: if changed.is_empty() { None } else { Some(changed) },
            tpm_error: None,
        },
        Err(e) => Response::Diagnosed {
            envelope_present: true,
            security_level,
            tracked_pcrs,
            pcr_drift: None,
            tpm_error: Some(e.to_string()),
        },
    }
}

fn do_liveness_test() -> Response {
    match aegyra_biometrics::run_liveness_test() {
        Ok(report) => {
            let decision = match report.decision {
                aegyra_liveness::LivenessDecision::Real => "real",
                aegyra_liveness::LivenessDecision::Spoof => "spoof",
                aegyra_liveness::LivenessDecision::Uncertain => "uncertain",
            };
            Response::LivenessChecked {
                summary: LivenessSummary {
                    decision: decision.into(),
                    spoof_prob: report.signals.spoof_prob,
                    ml_score: report.signals.ml_score,
                    device_score: report.signals.device_score,
                    device_name: report.signals.device_name,
                    device_driver: report.signals.device_driver,
                    ir_score: report.signals.ir_score,
                    ir_mean: report.signals.ir_mean,
                    ir_std: report.signals.ir_std,
                    ir_highlight_frac: report.signals.ir_highlight_frac,
                    ir_face_bg_ratio: report.signals.ir_face_bg_ratio,
                    face_frac: report.signals.face_frac,
                    yaw_deg: report.signals.yaw_deg,
                    pitch_deg: report.signals.pitch_deg,
                    reason: report.reason,
                },
            }
        }
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_reseal() -> Response {
    match aegyra_core::reseal_random_secret() {
        Ok(secret) => Response::Resealed { bytes: secret.len() },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_seal_password(user: &str, password: Vec<u8>) -> Response {
    // Wrap incoming bytes in Zeroizing so we wipe them regardless of which
    // branch returns.
    let password = zeroize::Zeroizing::new(password);
    match aegyra_core::seal_password(user, &password) {
        Ok(()) => Response::PasswordSealed,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_unseal_password(user: &str) -> Response {
    let samples = match load_user_samples(user) {
        Ok(s) => s,
        Err(e) => return Response::Error { message: e },
    };
    let live = match aegyra_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let r = aegyra_biometrics::match_against(&live, &samples);
    if !r.matched {
        return Response::Error {
            message: format!("face mismatch (score {:.4})", r.score),
        };
    }
    match aegyra_core::unseal_password(user) {
        Ok(secret) => Response::PasswordUnsealed {
            secret: secret.to_vec(),
        },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}
