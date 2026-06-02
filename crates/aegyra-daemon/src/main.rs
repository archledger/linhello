//! Root-privileged service: enrollment, TPM sealing, and IPC over /run/aegyra.sock.

use aegyra_common::ipc::{LivenessSummary, Request, Response, SecretBytes};
use aegyra_liveness::device_binding::{CameraBinding, DeviceIdentity};
use std::collections::HashMap;
use std::sync::Mutex;

mod capabilities;
mod users;

/// Unix group whose members may reach the socket for unprivileged ops
/// (status / verify / liveness-test). Privileged ops still require uid 0.
const SOCKET_GROUP: &str = "aegyra";

static TEMPLATE_KEY_CACHE: std::sync::OnceLock<Mutex<HashMap<String, zeroize::Zeroizing<Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn get_template_key_cache() -> &'static Mutex<HashMap<String, zeroize::Zeroizing<Vec<u8>>>> {
    TEMPLATE_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_template_key(user: &str) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let cache = get_template_key_cache();
    {
        let map = cache.lock().unwrap();
        if let Some(key) = map.get(user) {
            return Ok(key.clone());
        }
    }
    let key = aegyra_core::ensure_template_key(user).map_err(|e| e.to_string())?;
    {
        let mut map = cache.lock().unwrap();
        map.insert(user.to_string(), key.clone());
    }
    Ok(key)
}
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
    // Prefer `0660 root:aegyra` so only group members can reach the socket.
    // If the `aegyra` group doesn't exist yet, fall back to `0660` root-only
    // (privileged callers are root anyway) rather than a world-writable 0666 —
    // a world-writable socket lets any local process drive the camera and probe
    // the verifier. Operators who want unprivileged CLI access create the group
    // and add their user to it.
    match users::gid_for_group(SOCKET_GROUP) {
        Some(gid) => {
            if let Err(e) = users::chown(&socket, Some(0), Some(gid)) {
                tracing::warn!(error = %e, "could not chown socket to {SOCKET_GROUP}");
            }
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
                .with_context(|| format!("chmod {}", socket.display()))?;
        }
        None => {
            tracing::warn!(
                "group '{SOCKET_GROUP}' not found — socket restricted to root (0660). \
                 Create the group and add your user for unprivileged CLI access."
            );
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
                .with_context(|| format!("chmod {}", socket.display()))?;
        }
    }

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
    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
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
    // The request line may hold a password (SealPassword) and the response may
    // hold an unsealed secret (Unsealed/PasswordUnsealed); wipe both serialized
    // buffers so no plaintext lingers on this task's heap.
    use zeroize::Zeroize;
    out.zeroize();
    line.zeroize();
    Ok(())
}

async fn dispatch(req: Request, peer_uid: Option<u32>) -> Response {
    match req {
        Request::Status => task::spawn_blocking(do_status).await.unwrap_or_else(err),
        Request::Enroll { user, reset } => {
            if !is_root(peer_uid) {
                return forbidden("enroll");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_enroll(&user, reset))
                .await
                .unwrap_or_else(err)
        }
        Request::Verify { user } => {
            if let Some(r) = validate_user(&user) {
                return r;
            }
            // Scope to the caller's own account: root may verify anyone, but an
            // unprivileged caller may only verify itself. This closes the
            // cross-user score oracle (probing a victim's template to tune a
            // spoof) and limits camera use to one's own session.
            if !users::peer_may_act_as(peer_uid, &user) {
                return forbidden("verify (only your own account, or run as root)");
            }
            task::spawn_blocking(move || do_verify(&user))
                .await
                .unwrap_or_else(err)
        }
        Request::Unseal { user } => {
            if !is_root(peer_uid) {
                return forbidden("unseal");
            }
            if let Some(r) = validate_user(&user) {
                return r;
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
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_seal_password(&user, password))
                .await
                .unwrap_or_else(err)
        }
        Request::UnsealPassword { user } => {
            if !is_root(peer_uid) {
                return forbidden("unseal_password");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_unseal_password(&user))
                .await
                .unwrap_or_else(err)
        }
        Request::Diagnose => task::spawn_blocking(do_diagnose).await.unwrap_or_else(err),
        Request::Probe => task::spawn_blocking(|| Response::Capabilities {
            report: capabilities::probe(),
        })
        .await
        .unwrap_or_else(err),
        Request::LivenessTest => task::spawn_blocking(do_liveness_test).await.unwrap_or_else(err),
        Request::ResealUserEnvelopes { user } => {
            if !is_root(peer_uid) {
                return forbidden("reseal_user_envelopes");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_reseal_user_envelopes(&user))
                .await
                .unwrap_or_else(err)
        }
    }
}

fn is_root(uid: Option<u32>) -> bool {
    matches!(uid, Some(0))
}

/// Returns `Some(error_response)` if the request's `user` field is not a safe
/// single path component, else `None`. Checked before `user` is ever used to
/// build a path — defence-in-depth on top of `aegyra-core`'s path builders.
fn validate_user(user: &str) -> Option<Response> {
    aegyra_core::validate_user(user).err().map(|e| Response::Error {
        message: e.to_string(),
    })
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

    let key = match cached_template_key(user) {
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
    let rgb_path = aegyra_biometrics::camera::rgb_device();
    let ir_path = aegyra_biometrics::camera::ir_device();
    CameraBinding {
        rgb: DeviceIdentity::from_device(&rgb_path).unwrap_or_else(|| DeviceIdentity {
            vid: String::new(),
            pid: String::new(),
            serial: String::new(),
            name: "unknown".into(),
        }),
        ir: ir_path.and_then(|p| DeviceIdentity::from_device(&p)),
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

/// Load enrolled samples from encrypted (AES-256-GCM, TPM-sealed-key) storage.
///
/// Fails **closed**: if the template key cannot be unsealed (TPM unreachable,
/// PCR drift, corrupt envelope) we return an error rather than falling back to
/// an unauthenticated plaintext template. The auth path then declines and PAM
/// falls through to password — we never match a face against at-rest data that
/// the TPM hasn't vouched for.
fn load_user_samples(user: &str) -> std::result::Result<Vec<Vec<f32>>, String> {
    check_camera_binding(user)?;

    let key = cached_template_key(user)
        .map_err(|e| format!("template key unavailable ({e}); refusing plaintext fallback"))?;
    let raw = aegyra_core::load_encrypted_embedding(user, &key).map_err(|e| e.to_string())?;
    aegyra_biometrics::parse_embeddings(&raw).map_err(|e| e.to_string())
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
            secret: SecretBytes::new(secret.to_vec()),
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

fn do_reseal_user_envelopes(user: &str) -> Response {
    let mut pw_ok = false;
    let mut tk_ok = false;

    // Password envelope: unseal (current PCRs) → reseal.
    match aegyra_core::unseal_password(user) {
        Ok(plaintext) => match aegyra_core::seal_password(user, &plaintext) {
            Ok(()) => pw_ok = true,
            Err(e) => tracing::warn!("reseal password for {user}: {e}"),
        },
        Err(e) => tracing::warn!("unseal password for {user}: {e}"),
    }

    // Template-key envelope: unseal → reseal.
    match aegyra_core::unseal_template_key(user) {
        Ok(key) => {
            match aegyra_core::tpm::seal_secret(&key) {
                Ok(env) => {
                    if let Ok(path) = aegyra_core::template_key_path_pub(user) {
                        match env.save(&path) {
                            Ok(()) => {
                                tk_ok = true;
                                // Invalidate the daemon's cached key so next
                                // verify picks up the fresh envelope.
                                let cache = get_template_key_cache();
                                let mut map = cache.lock().unwrap();
                                map.remove(user);
                            }
                            Err(e) => tracing::warn!("save template key for {user}: {e}"),
                        }
                    }
                }
                Err(e) => tracing::warn!("reseal template key for {user}: {e}"),
            }
        }
        Err(e) => tracing::warn!("unseal template key for {user}: {e}"),
    }

    Response::UserEnvelopesResealed {
        password: pw_ok,
        template_key: tk_ok,
    }
}

fn do_seal_password(user: &str, password: SecretBytes) -> Response {
    // `password` zeroizes its buffer on drop, covering every return path.
    match aegyra_core::seal_password(user, password.expose()) {
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
            secret: SecretBytes::new(secret.to_vec()),
        },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}
