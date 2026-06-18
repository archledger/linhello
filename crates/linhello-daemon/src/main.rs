//! Root-privileged service: enrollment, TPM sealing, and IPC over /run/linhello.sock.

use linhello_common::ipc::{
    IdentifyCandidate, LivenessSummary, ProfileInfo, Request, Response, SecretBytes,
};
use linhello_liveness::device_binding::{CameraBinding, DeviceIdentity};
use std::collections::HashMap;
use std::sync::Mutex;

mod capabilities;
mod users;

/// Unix group whose members may reach the socket for unprivileged ops
/// (status / verify / liveness-test). Privileged ops still require uid 0.
use linhello_common::SOCKET_GROUP;

static TEMPLATE_KEY_CACHE: std::sync::OnceLock<Mutex<HashMap<String, zeroize::Zeroizing<Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn get_template_key_cache() -> &'static Mutex<HashMap<String, zeroize::Zeroizing<Vec<u8>>>> {
    TEMPLATE_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_template_key(user: &str) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let cache = get_template_key_cache();
    {
        let map = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = map.get(user) {
            return Ok(key.clone());
        }
    }
    let key = linhello_core::ensure_template_key(user).map_err(|e| e.to_string())?;
    {
        let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(user.to_string(), key.clone());
    }
    Ok(key)
}
use linhello_common::client::socket_path;
use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task;

#[tokio::main]
async fn main() -> Result<()> {
    // Default to an `info` floor so the auth-decision trail (UnsealPassword
    // outcomes, denials) lands in the journal without needing RUST_LOG set;
    // RUST_LOG still overrides for deeper debugging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let socket: PathBuf = parse_socket_arg().unwrap_or_else(socket_path);
    if socket.exists() {
        std::fs::remove_file(&socket)
            .with_context(|| format!("removing stale socket {}", socket.display()))?;
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Bind under a restrictive umask so the socket is never world-connectable,
    // even for the instant between bind() and the explicit chmod below.
    // SAFETY: umask is a simple process-wide mode set/get with no preconditions.
    let old_umask = unsafe { libc::umask(0o117) };
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding {}", socket.display()));
    // SAFETY: restoring the previous process umask; no preconditions.
    unsafe { libc::umask(old_umask) };
    let listener = listener?;
    // Prefer `0660 root:linhello` so only group members can reach the socket.
    // If the `linhello` group doesn't exist yet, fall back to `0660` root-only
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

    tracing::info!("linhellod listening on {}", socket.display());

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
    // Requests are tiny JSON lines. Cap the read so a client (any member of the
    // `linhello` group, given the 0660 socket) cannot stream an unterminated
    // line and exhaust the privileged daemon's memory. On overflow the read
    // returns a truncated, newline-less buffer that fails to parse — handled as
    // a malformed request below, never an OOM.
    const MAX_REQUEST_BYTES: u64 = 64 * 1024;
    let mut reader = BufReader::new(read.take(MAX_REQUEST_BYTES));
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
        Request::Authenticate { user, service } => {
            // Peer must be allowed to act as `user` (root for anyone; otherwise
            // only their own account — the KDE session-user unlock case). The
            // unseal-vs-verify decision and the root gate on releasing the secret
            // are made inside do_authenticate.
            if !users::peer_may_act_as(peer_uid, &user) {
                return forbidden("authenticate");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            let root = is_root(peer_uid);
            task::spawn_blocking(move || do_authenticate(&user, &service, root))
                .await
                .unwrap_or_else(err)
        }
        Request::AuthIntent { user, service } => {
            // Same peer gate as Authenticate, but this only reveals the policy
            // decision (no capture, no secret), so it's safe and cheap.
            if !users::peer_may_act_as(peer_uid, &user) {
                return forbidden("auth_intent");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            let root = is_root(peer_uid);
            task::spawn_blocking(move || do_auth_intent(&user, &service, root))
                .await
                .unwrap_or_else(err)
        }
        Request::PolicyStatus { user } => {
            // Pure policy read (no capture, no secret) — same own-uid/root gate
            // as AuthIntent so it can't leak another user's tier/enrollment.
            if !users::peer_may_act_as(peer_uid, &user) {
                return forbidden("policy_status");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_policy_status(&user))
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
        // Detection-only geometry for the enrollment positioning guide. No
        // secret, score, or pixels — unprivileged, like LivenessTest. Polled at
        // a few Hz by the CLI, so it must stay cheap (no embed/IR/anti-spoof).
        Request::PositionSample => {
            task::spawn_blocking(do_position_sample).await.unwrap_or_else(err)
        }
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
        // Metadata only (names, sample counts) — no biometrics, unprivileged.
        // The `has_password` flag is a sensitive oracle, so it is populated only
        // for callers entitled to act as the profile's user (see do_list_profiles).
        Request::ListProfiles => {
            task::spawn_blocking(move || do_list_profiles(peer_uid)).await.unwrap_or_else(err)
        }
        // 1:N identification is an identity oracle, so it is root-only —
        // an administrative/setup operation, like Enroll.
        Request::Identify => {
            if !is_root(peer_uid) {
                return forbidden("identify");
            }
            task::spawn_blocking(do_identify).await.unwrap_or_else(err)
        }
        Request::SetProfileName { user, name } => {
            if !is_root(peer_uid) {
                return forbidden("set_profile_name");
            }
            if let Some(r) = validate_user(&user) {
                return r;
            }
            task::spawn_blocking(move || do_set_profile_name(&user, &name))
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
/// build a path — defence-in-depth on top of `linhello-core`'s path builders.
fn validate_user(user: &str) -> Option<Response> {
    linhello_core::validate_user(user).err().map(|e| Response::Error {
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
        security_level: linhello_core::detect_security_level(),
        boot_mode: linhello_secureboot::detect_boot_mode(),
        secure_boot: linhello_secureboot::is_secure_boot_enabled(),
        loader: linhello_secureboot::loader_identity(),
    }
}

fn do_enroll(user: &str, reset: bool) -> Response {
    // Capture + liveness + embed.
    let embedding = match linhello_biometrics::capture_and_embed() {
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
        match linhello_core::load_encrypted_embedding(user, &key) {
            Ok(existing) => existing.to_vec(),
            Err(_) => Vec::new(), // no enrollment yet
        }
    };
    all_raw.extend_from_slice(&raw);

    // Encrypt and persist.
    if let Err(e) = linhello_core::save_encrypted_embedding(user, &all_raw, &key) {
        return Response::Error { message: format!("save enrollment: {e}") };
    }

    // Record camera identity (soft-SDCP). Overwritten on each enroll so
    // a hardware upgrade is handled by re-enrolling.
    save_camera_binding(user, &snapshot_camera_binding());

    let samples = all_raw.len() / (linhello_biometrics::enroll::EMBEDDING_DIM * 4);
    Response::Enrolled { samples }
}

fn camera_binding_path(user: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(linhello_common::CONFIG_ROOT)
        .join(user)
        .join("camera_binding.json")
}

fn snapshot_camera_binding() -> CameraBinding {
    let rgb_path = linhello_biometrics::camera::rgb_device();
    let ir_path = linhello_biometrics::camera::ir_device();
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

/// The enrolled camera binding for `user`, if any.
fn enrolled_binding(user: &str) -> Option<CameraBinding> {
    let json = std::fs::read_to_string(camera_binding_path(user)).ok()?;
    serde_json::from_str(&json).ok()
}

/// Hardware assurance tier for `user`, fixed by the camera they enrolled with: an
/// enrolled IR camera ⇒ Secure, else Convenience. (That the IR camera is *still*
/// present is enforced separately by `check_camera_binding`, so a Secure-tier
/// user who loses their IR camera fails closed to the password, never downgrades.)
fn user_tier(user: &str) -> linhello_common::biopolicy::Tier {
    use linhello_common::biopolicy::Tier;
    match enrolled_binding(user) {
        Some(b) if b.ir.is_some() => Tier::Secure,
        _ => Tier::Convenience,
    }
}

/// Effective tier after the `tier=auto|secure|convenience` config override in
/// `policy.conf` (the design's `tier.mode`). `auto` (default) uses the enrolled
/// hardware; `convenience` caps it down (useful for testing / a user who wants
/// no face-driven credential release even with IR present).
fn effective_tier(user: &str) -> linhello_common::biopolicy::Tier {
    use linhello_common::biopolicy::Tier;
    match linhello_common::config::read_kv("policy.conf", "tier").as_deref() {
        Some("convenience") => Tier::Convenience,
        Some("secure") => Tier::Secure,
        _ => user_tier(user),
    }
}

/// Whether `user` has a live (warm) logind session — i.e. a credential created a
/// session this boot, so a screen-unlock need not release the credential again.
/// Read from systemd's per-user state file on the *system* side (no session bus).
fn session_warm(user: &str) -> bool {
    let Some(uid) = users::uid_for_name(user) else {
        return false;
    };
    match std::fs::read_to_string(format!("/run/systemd/users/{uid}")) {
        Ok(text) => text.lines().any(|l| {
            l.strip_prefix("STATE=")
                .map(|s| matches!(s.trim(), "active" | "online"))
                .unwrap_or(false)
        }),
        Err(_) => false,
    }
}

/// Load the per-operation policy from `/etc/linhello/policy.conf` (kv: `key=off|
/// rgb|ir`), falling back to the secure defaults for any missing/invalid key.
fn current_policy() -> linhello_common::biopolicy::Policy {
    use linhello_common::biopolicy::{ModalityReq, Policy};
    let mut p = Policy::default();
    let get = |k: &str| {
        linhello_common::config::read_kv("policy.conf", k).and_then(|v| ModalityReq::parse(&v))
    };
    if let Some(v) = get("screen_unlock") {
        p.screen_unlock = v;
    }
    if let Some(v) = get("login") {
        p.login = v;
    }
    if let Some(v) = get("sudo") {
        p.sudo = v;
    }
    if let Some(v) = get("polkit") {
        p.polkit = v;
    }
    p
}

/// Tiered-policy authentication: classify the service, look up the tier + warm
/// state, decide, and route to the existing verify / unseal paths. Centralises
/// the decision the PAM module used to make by euid.
/// Pure decision: classify the service, look up the tier + warm state, decide,
/// and apply the non-root → no-unseal downgrade. Captures nothing and touches no
/// camera/TPM. Shared by `do_authenticate` (which then routes to capture) and the
/// `AuthIntent` pre-flight (which only reports whether the camera will engage), so
/// the "Looking for your face…" prompt can never disagree with the real decision.
fn plan_action(
    user: &str,
    service: &str,
    peer_is_root: bool,
) -> (linhello_common::biopolicy::Action, linhello_common::biopolicy::Tier, linhello_common::biopolicy::OperationClass, bool) {
    use linhello_common::biopolicy::{classify, decide, Action};
    let warm = session_warm(user);
    let class = classify(service, warm);
    let tier = effective_tier(user);
    let mut action = decide(class, tier, &current_policy());
    // Defence in depth: the sealed password is only ever released to a root peer
    // (the existing UnsealPassword rule). A non-root peer that somehow lands on
    // the unseal path is downgraded to a deny → password.
    if action == Action::Unseal && !peer_is_root {
        action = Action::Deny;
    }
    (action, tier, class, warm)
}

fn do_authenticate(user: &str, service: &str, peer_is_root: bool) -> Response {
    use linhello_common::biopolicy::Action;
    let (action, tier, class, warm) = plan_action(user, service, peer_is_root);
    tracing::info!(
        "Authenticate: user='{user}' service='{service}' tier={} class={class:?} warm={warm} root={peer_is_root} -> {action:?}",
        tier.as_str()
    );
    match action {
        Action::Deny => Response::Error {
            message: format!("face auth not permitted for '{service}' on the {} tier", tier.as_str()),
        },
        Action::Verify => do_verify(user),
        Action::Unseal => do_unseal_password(user),
    }
}

/// Pre-flight for the PAM prompt: report whether the upcoming `Authenticate` will
/// engage the camera, without capturing. `engage` is true for Verify/Unseal,
/// false for Deny — so PAM only says "Looking for your face…" when a camera will
/// actually light up (convenience-tier greeter login → Deny → silent password).
fn do_auth_intent(user: &str, service: &str, peer_is_root: bool) -> Response {
    use linhello_common::biopolicy::Action;
    let (action, tier, class, warm) = plan_action(user, service, peer_is_root);
    let label = match action {
        Action::Deny => "deny",
        Action::Verify => "verify",
        Action::Unseal => "unseal",
    };
    // Deny is logged at INFO: PAM short-circuits to the password without ever
    // calling Authenticate, so this is the *only* daemon-side record of a denied
    // attempt — keep the decision trail intact. The engage path (Verify/Unseal)
    // stays at DEBUG because the follow-up Authenticate will log the real result.
    if action == Action::Deny {
        tracing::info!(
            "AuthIntent: user='{user}' service='{service}' tier={} class={class:?} warm={warm} root={peer_is_root} -> deny (no camera; PAM defers to password)",
            tier.as_str()
        );
    } else {
        tracing::debug!(
            "AuthIntent: user='{user}' service='{service}' tier={} class={class:?} warm={warm} root={peer_is_root} -> {label} (engage=true)",
            tier.as_str()
        );
    }
    Response::AuthPlan {
        engage: action != Action::Deny,
        action: label.to_string(),
    }
}

/// Report the effective tier + per-operation policy for `user` (read-only). Runs
/// the same `decide()` the auth path uses, per operation class, so `doctor`/TUI
/// surface exactly what real auth would do. `warm` only affects how a *service*
/// maps to a class (`classify`), not the class→action decision, so the matrix is
/// warm-independent and we report it directly by class.
fn do_policy_status(user: &str) -> Response {
    use linhello_common::biopolicy::{decide, Action, OperationClass, Tier};
    let hardware = user_tier(user);
    let tier = effective_tier(user);
    let policy = current_policy();
    let enrolled = enrolled_binding(user).is_some();

    let row = |operation: &str, class: OperationClass| {
        let (action, effect) = match decide(class, tier, &policy) {
            Action::Verify => (
                "verify",
                "match only — unlocks the live session, no credential released",
            ),
            Action::Unseal => (
                "unseal",
                "match + IR liveness — releases your password to log in / elevate",
            ),
            Action::Deny => ("deny", "face not used — falls back to your password"),
        };
        linhello_common::ipc::OperationPolicy {
            operation: operation.to_string(),
            action: action.to_string(),
            effect: effect.to_string(),
        }
    };

    let ops = vec![
        row("Screen unlock", OperationClass::ScreenUnlock),
        row("Login (greeter)", OperationClass::Login),
        row("sudo / su / polkit", OperationClass::Elevation),
        row("ssh / remote", OperationClass::Remote),
        row("unknown service", OperationClass::Unknown),
    ];

    Response::PolicyStatus {
        tier: tier.as_str().to_string(),
        secure: tier == Tier::Secure,
        hardware_tier: hardware.as_str().to_string(),
        overridden: tier != hardware,
        enrolled,
        ops,
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
    let live = match linhello_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let r = linhello_biometrics::match_against(&live, &samples);
    Response::Verified {
        matched: r.matched,
        score: r.score,
        threshold: linhello_biometrics::match_threshold(),
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
    let raw = linhello_core::load_encrypted_embedding(user, &key).map_err(|e| e.to_string())?;
    linhello_biometrics::parse_embeddings(&raw).map_err(|e| e.to_string())
}

/// Per-profile friendly-name file. Not secret (it's a label), so 0644 — the
/// template and envelopes alongside it stay 0600.
fn profile_name_path(user: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(linhello_common::CONFIG_ROOT)
        .join(user)
        .join("display_name")
}

fn read_profile_name(user: &str) -> Option<String> {
    std::fs::read_to_string(profile_name_path(user))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Enrolled profiles: directories under `CONFIG_ROOT` holding a face template
/// (`embedding.enc`, or legacy `embedding.bin`). Sorted for stable output.
fn enrolled_profiles() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(linhello_common::CONFIG_ROOT) else {
        return out;
    };
    for ent in rd.flatten() {
        if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = ent.path();
        if dir.join("embedding.enc").exists() || dir.join("embedding.bin").exists() {
            if let Some(name) = ent.file_name().to_str() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

/// Best-effort sample count from the encrypted template's size, without
/// decrypting: layout is `[12B nonce][ciphertext + 16B GCM tag]` and the
/// plaintext is `samples × EMBEDDING_DIM × 4` (see `core::crypto`).
fn profile_sample_count(user: &str) -> usize {
    let stride = linhello_biometrics::enroll::EMBEDDING_DIM * 4;
    let enc = std::path::PathBuf::from(linhello_common::CONFIG_ROOT)
        .join(user)
        .join("embedding.enc");
    if let Ok(meta) = std::fs::metadata(&enc) {
        let overhead = 12 + 16;
        return (meta.len() as usize).saturating_sub(overhead) / stride;
    }
    // Legacy plaintext template: size is an exact multiple of the stride.
    let legacy = std::path::PathBuf::from(linhello_common::CONFIG_ROOT)
        .join(user)
        .join("embedding.bin");
    std::fs::metadata(&legacy)
        .map(|m| m.len() as usize / stride)
        .unwrap_or(0)
}

fn do_list_profiles(peer_uid: Option<u32>) -> Response {
    let profiles = enrolled_profiles()
        .into_iter()
        .map(|user| {
            // Whether a user has sealed their login password is a sensitive
            // oracle. Only reveal it to callers entitled to act as that user
            // (root, or the user themselves); others always see `false`.
            let has_password = users::peer_may_act_as(peer_uid, &user)
                && std::path::PathBuf::from(linhello_common::CONFIG_ROOT)
                    .join(&user)
                    .join("password_envelope.json")
                    .exists();
            ProfileInfo {
                name: read_profile_name(&user),
                samples: profile_sample_count(&user),
                has_password,
                user,
            }
        })
        .collect();
    Response::Profiles { profiles }
}

fn do_set_profile_name(user: &str, name: &str) -> Response {
    // Require the profile to exist so a typo doesn't create an orphan label.
    if !enrolled_profiles().iter().any(|u| u == user) {
        return Response::Error {
            message: format!("no enrolled profile '{user}'"),
        };
    }
    let path = profile_name_path(user);
    let trimmed = name.trim();
    let result = if trimmed.is_empty() {
        // Empty name clears the label.
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        std::fs::write(&path, format!("{trimmed}\n")).and_then(|()| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            }
            #[cfg(not(unix))]
            Ok(())
        })
    };
    match result {
        Ok(()) => Response::ProfileNameSet,
        Err(e) => Response::Error {
            message: format!("set profile name: {e}"),
        },
    }
}

/// 1:N identification — capture one live face and score it against every
/// enrolled profile, returning the best match and the full ranked list. Each
/// profile is loaded through the same fail-closed encrypted path as auth, so a
/// profile whose template key can't unseal is skipped (logged), not matched.
fn do_identify() -> Response {
    let profiles = enrolled_profiles();
    if profiles.is_empty() {
        return Response::Error {
            message: "no enrolled profiles to identify against".into(),
        };
    }
    let live = match linhello_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let mut candidates: Vec<IdentifyCandidate> = Vec::new();
    for user in &profiles {
        match load_user_samples(user) {
            Ok(samples) => {
                let r = linhello_biometrics::match_against(&live, &samples);
                candidates.push(IdentifyCandidate {
                    name: read_profile_name(user),
                    user: user.clone(),
                    score: r.score,
                });
            }
            Err(e) => {
                tracing::warn!("identify: skipping profile '{user}': {e}");
            }
        }
    }
    if candidates.is_empty() {
        return Response::Error {
            message: "no profile templates could be read (TPM/PCR state?)".into(),
        };
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    let threshold = linhello_biometrics::match_threshold();
    let best = candidates
        .first()
        .filter(|c| c.score >= threshold)
        .cloned();
    Response::Identified {
        best,
        threshold,
        candidates,
    }
}

fn do_unseal(user: &str) -> Response {
    let samples = match load_user_samples(user) {
        Ok(s) => s,
        Err(e) => return Response::Error { message: e },
    };
    let live = match linhello_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => return Response::Error { message: e.to_string() },
    };
    let r = linhello_biometrics::match_against(&live, &samples);
    if !r.matched {
        return Response::Error {
            message: format!("face mismatch (score {:.4})", r.score),
        };
    }
    match linhello_core::unseal_keyring_secret() {
        Ok(secret) => Response::Unsealed {
            secret: SecretBytes::new(secret.to_vec()),
        },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_diagnose() -> Response {
    let path = linhello_core::envelope_path();
    let envelope_present = path.exists();
    let security_level = linhello_core::detect_security_level();

    if !envelope_present {
        return Response::Diagnosed {
            envelope_present: false,
            security_level,
            tracked_pcrs: Vec::new(),
            pcr_drift: None,
            tpm_error: None,
        };
    }

    let env = match linhello_core::envelope::SealedEnvelope::load(&path) {
        Ok(e) => e,
        Err(e) => {
            return Response::Error {
                message: format!("envelope load: {e}"),
            }
        }
    };
    let tracked_pcrs = env.pcrs.clone();

    match linhello_core::tpm::diagnose_pcrs(&env) {
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
    match linhello_biometrics::run_liveness_test() {
        Ok(report) => {
            let decision = match report.decision {
                linhello_liveness::LivenessDecision::Real => "real",
                linhello_liveness::LivenessDecision::Spoof => "spoof",
                linhello_liveness::LivenessDecision::Uncertain => "uncertain",
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
                    ir_eye_glint: report.signals.ir_eye_glint,
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

fn do_position_sample() -> Response {
    match linhello_biometrics::capture_position_sample() {
        Ok(report) => Response::Position { report },
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_reseal() -> Response {
    match linhello_core::reseal_random_secret() {
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
    match linhello_core::unseal_password(user) {
        Ok(plaintext) => match linhello_core::seal_password(user, &plaintext) {
            Ok(()) => pw_ok = true,
            Err(e) => tracing::warn!("reseal password for {user}: {e}"),
        },
        Err(e) => tracing::warn!("unseal password for {user}: {e}"),
    }

    // Template-key envelope: unseal → reseal.
    match linhello_core::unseal_template_key(user) {
        Ok(key) => {
            match linhello_core::tpm::seal_secret(&key) {
                Ok(env) => {
                    if let Ok(path) = linhello_core::template_key_path_pub(user) {
                        match env.save(&path) {
                            Ok(()) => {
                                tk_ok = true;
                                // Invalidate the daemon's cached key so next
                                // verify picks up the fresh envelope.
                                let cache = get_template_key_cache();
                                let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
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
    match linhello_core::seal_password(user, password.expose()) {
        Ok(()) => Response::PasswordSealed,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    }
}

fn do_unseal_password(user: &str) -> Response {
    // Audit trail for the PAM keyring-unlock path. Every line carries the
    // "UnsealPassword" token so `scripts/linhello-keyring-diag` can prove a
    // face-driven login (vs a typed-password fallback) after a reboot. We log
    // the cosine score (not secret) but never the password or its length.
    tracing::info!("UnsealPassword: attempt for user '{user}'");
    let samples = match load_user_samples(user) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("UnsealPassword: no usable enrollment for '{user}': {e}");
            return Response::Error { message: e };
        }
    };
    let live = match linhello_biometrics::capture_and_embed() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("UnsealPassword: capture/liveness failed for '{user}': {e}");
            return Response::Error { message: e.to_string() };
        }
    };
    let r = linhello_biometrics::match_against(&live, &samples);
    if !r.matched {
        tracing::warn!(
            "UnsealPassword: face did not match for '{user}' (score {:.4}) -> denied",
            r.score
        );
        return Response::Error {
            message: format!("face mismatch (score {:.4})", r.score),
        };
    }
    match linhello_core::unseal_password(user) {
        Ok(secret) => {
            tracing::info!(
                "UnsealPassword: OK for '{user}', face matched (score {:.4}), password unsealed",
                r.score
            );
            Response::PasswordUnsealed {
                secret: SecretBytes::new(secret.to_vec()),
            }
        }
        // Case 3: biometrics passed but the TPM could not release the secret
        // (e.g. PCR drift). This is the line that explains a face login that
        // nonetheless leaves the keyring locked.
        Err(e) => {
            tracing::error!(
                "UnsealPassword: face matched for '{user}' (score {:.4}) but TPM unseal FAILED: {e}",
                r.score
            );
            Response::Error {
                message: e.to_string(),
            }
        }
    }
}
