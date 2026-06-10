//! Detect whether LinuxHello is already installed and configured on this host.
//!
//! Lets the setup wizard (and any `status`-style caller) tell a fresh machine
//! from one that already has LinuxHello deployed: binaries in place, the daemon
//! installed/running, face models present, a camera pinned, a calibrated
//! threshold, enrolled users, and login wiring. Every check is read-only —
//! detecting state never changes it.

use linhello_common::config;
use linhello_common::CONFIG_ROOT;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the daemon/CLI land, in the order `make install` (/usr/local) or a
/// distro package (/usr) would place them.
const BIN_DIRS: [&str; 2] = ["/usr/local/bin", "/usr/bin"];

/// The models LinuxHello can use, with their role, whether recognition requires
/// them, and whether LinuxHello ships them (vs the user fetching). buffalo_l's
/// detector + recognizer are user-fetched (InsightFace license); the anti-spoof
/// pair is shipped (Apache-2.0).
const MODEL_CATALOG: [(&str, &str, bool, bool); 4] = [
    ("det_10g.onnx", "detector (buffalo_l)", true, false),
    ("face.onnx", "recognizer (buffalo_l)", true, false),
    ("antispoof.onnx", "anti-spoof", false, true),
    ("antispoof_4.onnx", "anti-spoof (secondary)", false, true),
];

/// Live presence of one model file under `CONFIG_ROOT`.
#[derive(Clone)]
pub struct ModelStatus {
    pub file: &'static str,
    pub role: &'static str,
    /// Recognition can't run without it.
    pub required: bool,
    /// LinuxHello ships it (so the user shouldn't be told to fetch it).
    pub shipped: bool,
    pub present: bool,
}

/// A read-only snapshot of how far LinuxHello is deployed on this machine.
pub struct InstallState {
    pub cli_bin: Option<PathBuf>,
    pub daemon_bin: Option<PathBuf>,
    pub daemon_active: bool,
    pub daemon_enabled: bool,
    /// Per-model live presence (detector, recognizer, anti-spoof…).
    pub models: Vec<ModelStatus>,
    /// Required face models all present?
    pub models_present: bool,
    pub missing_models: Vec<&'static str>,
    /// `cameras.conf` exists (RGB/IR pinned rather than left to auto-detect).
    pub camera_configured: bool,
    /// Calibrated `match_threshold`, if `settings.conf` carries one.
    pub threshold: Option<String>,
    /// Users with a stored face template under `CONFIG_ROOT/<user>/`.
    pub enrolled_users: Vec<String>,
    /// PAM services with face login wired in, out of those inspected.
    pub pam_wired: usize,
    pub pam_total: usize,
}

impl InstallState {
    /// Inspect the host. Cheap enough to run on wizard startup.
    pub fn detect() -> Self {
        let cli_bin = find_bin("linhello");
        let daemon_bin = find_bin("linhellod");
        let (daemon_active, daemon_enabled) = systemd_state("linhellod");
        let models = model_states();
        let missing_models: Vec<&'static str> = models
            .iter()
            .filter(|m| m.required && !m.present)
            .map(|m| m.file)
            .collect();
        let models_present = missing_models.is_empty();
        let pam = crate::pamwire::status();
        InstallState {
            cli_bin,
            daemon_bin,
            daemon_active,
            daemon_enabled,
            models,
            models_present,
            missing_models,
            camera_configured: config::config_path("cameras.conf").exists(),
            threshold: config::read_kv("settings.conf", "match_threshold"),
            enrolled_users: enrolled_users(),
            pam_wired: pam.iter().filter(|s| s.wired).count(),
            pam_total: pam.len(),
        }
    }

    /// Binaries or the daemon unit are present — LinuxHello is *installed*.
    pub fn is_installed(&self) -> bool {
        self.cli_bin.is_some() || self.daemon_bin.is_some() || self.daemon_active
    }

    /// Installed *and* set up: at least one enrolled user. This is the line
    /// between "binaries are here" and "face login actually works for someone".
    pub fn is_configured(&self) -> bool {
        self.is_installed() && !self.enrolled_users.is_empty()
    }

    /// One-line verdict for the wizard header / a status line.
    pub fn headline(&self) -> String {
        if !self.is_installed() {
            return "No prior LinuxHello install detected — this is a fresh setup.".to_string();
        }
        if !self.is_configured() {
            let d = if self.daemon_active { "running" } else { "installed, not running" };
            return format!("LinuxHello is {d} but no face is enrolled yet.");
        }
        let who = self.enrolled_users.join(", ");
        let login = if self.pam_wired > 0 {
            format!("face login ON ({}/{} services)", self.pam_wired, self.pam_total)
        } else {
            "face login OFF".to_string()
        };
        format!("LinuxHello is already set up — enrolled: {who}; {login}.")
    }

    /// Detailed, labelled lines for a detection panel.
    pub fn detail_lines(&self) -> Vec<String> {
        let yn = |b: bool| if b { "yes" } else { "no" };
        let mut lines = vec![
            format!(
                "binaries     {}",
                match (&self.cli_bin, &self.daemon_bin) {
                    (Some(c), _) => c.display().to_string(),
                    (None, Some(d)) => d.display().to_string(),
                    (None, None) => "not found on PATH".to_string(),
                }
            ),
            format!(
                "daemon       active={} enabled={}",
                yn(self.daemon_active),
                yn(self.daemon_enabled)
            ),
            {
                let present = self.models.iter().filter(|m| m.present).count();
                let total = self.models.len();
                if self.models_present {
                    format!("models       {present}/{total} present")
                } else {
                    format!(
                        "models       {present}/{total} — need: {}",
                        self.missing_models.join(", ")
                    )
                }
            },
            format!("camera       {}", if self.camera_configured { "pinned (cameras.conf)" } else { "auto-detect (no cameras.conf)" }),
            format!("threshold    {}", self.threshold.clone().unwrap_or_else(|| "default 0.60".to_string())),
            format!(
                "enrolled     {}",
                if self.enrolled_users.is_empty() {
                    "none".to_string()
                } else {
                    self.enrolled_users.join(", ")
                }
            ),
            format!("login wiring {}/{} services", self.pam_wired, self.pam_total),
        ];
        if !self.is_installed() {
            lines.insert(0, "(nothing installed here yet)".to_string());
        }
        lines
    }
}

/// Required face models (detector + embedder). Anti-spoof is optional.
const REQUIRED_FOR_COPY: [(&str, bool); 3] = [
    ("det_10g.onnx", true),
    ("face.onnx", true),
    ("antispoof.onnx", false),
];

/// Files that must be present for a directory to count as a usable model bundle.
const BUNDLE_REQUIRED: [&str; 2] = ["det_10g.onnx", "face.onnx"];

/// Find a directory that already holds the required models so the installer can
/// copy them in instantly — no download, no path typing. Searched in order:
/// `$LINHELLO_MODELS_DIR`, `<source_root>/models`, `/usr/share/linhello/models`.
/// A bundle ships these out-of-band (size + model license keep them out of git).
pub fn bundled_models_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("LINHELLO_MODELS_DIR") {
        candidates.push(PathBuf::from(d));
    }
    if let Some(root) = source_root() {
        candidates.push(root.join("models"));
    }
    candidates.push(PathBuf::from("/usr/share/linhello/models"));
    candidates
        .into_iter()
        .find(|d| BUNDLE_REQUIRED.iter().all(|m| d.join(m).exists()))
}

/// Locate the source/build tree to install from: `$LINHELLO_SRC` (must hold a
/// Makefile), else derived from the running binary at
/// `<root>/target/release/linhello`. `None` if neither looks like the repo.
pub fn source_root() -> Option<PathBuf> {
    if let Ok(s) = std::env::var("LINHELLO_SRC") {
        let p = PathBuf::from(s);
        if p.join("Makefile").exists() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let root = exe.ancestors().nth(3)?.to_path_buf();
    root.join("Makefile").exists().then_some(root)
}

/// Wait until the daemon actually answers on its socket (systemctl returning
/// success only means the unit launched — the socket may not be up yet, or the
/// process may have crashed right after). Polls Status for up to ~10s.
fn wait_for_daemon() -> std::result::Result<(), String> {
    use linhello_common::ipc::{Request, Response};
    for _ in 0..20 {
        if let Ok(Response::Status { .. }) = crate::send(Request::Status) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // Surface WHY: the unit's state and its last journal lines.
    let why = Command::new("journalctl")
        .args(["-u", "linhellod", "-n", "5", "--no-pager", "-o", "cat"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "no journal output".to_string());
    Err(format!(
        "linhellod did not answer on its socket within 10s. Last journal lines:\n{why}"
    ))
}

/// Deploy the programs + daemon: run the repo Makefile's `install` target with
/// the prebuilt Rust artifacts (`CARGO=true` no-ops the cargo rebuild), then
/// enable + start the daemon and VERIFY it answers. Creates the `linhello`
/// socket group and adds `user` to it so the unprivileged CLI works. Requires
/// the source tree and `make`. Root-only (the TUI caller already runs as root).
///
/// The C PAM shim (`pam/pam_linhello.so`) is NOT no-op'd: the README flow only
/// runs `cargo build --release`, so on a fresh clone the shim doesn't exist yet
/// — and its compile embeds `-rpath $(PAMDIR)`, which is distro-specific, so a
/// shim built elsewhere could be wrong anyway. One small `cc` invocation.
pub fn deploy(user: &str) -> Result<Vec<String>, String> {
    let root = source_root().ok_or(
        "can't find the LinuxHello source tree — set LINHELLO_SRC, or run from the repo's \
         target/release; on a packaged system, install via your package manager instead",
    )?;
    deploy_from(&root, user)
}

/// `deploy` against an explicit source tree (the updater builds in a managed
/// clone that is not where the running binary lives).
pub fn deploy_from(root: &Path, user: &str) -> Result<Vec<String>, String> {
    // The Makefile's PAMDIR default is the Arch location; on Debian/Fedora the
    // PAM module dir differs — resolve it for the running distro so the greeter
    // can actually load the module after install.
    let pam_dir = linhello_common::platform::pam_module_dir();
    let out = Command::new("make")
        .current_dir(&root)
        .args(["install", "CARGO=true", &format!("PAMDIR={pam_dir}")])
        .output()
        .map_err(|e| format!("running make install: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "make install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut log = vec![
        format!("installed binaries + unit from {}", root.display()),
        format!("PAM module → {pam_dir}"),
    ];
    // Create the socket group so the user's own session can run the read-only
    // CLI (status/test/doctor) without sudo. Root/PAM never needs it.
    if Command::new("getent")
        .args(["group", "linhello"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        log.push("group 'linhello' already exists".to_string());
    } else if Command::new("groupadd")
        .args(["--system", "linhello"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        log.push("created group 'linhello' (socket access for the CLI)".to_string());
    }
    // Add the target user to the group automatically — the manual usermod step
    // was a setup hurdle. Disclosed in the log; membership applies at next login.
    if !user.is_empty() && user != "root" {
        let already = Command::new("id")
            .args(["-nG", user])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|g| g == "linhello")
            })
            .unwrap_or(false);
        if already {
            log.push(format!("'{user}' is already in the linhello group"));
        } else if Command::new("usermod")
            .args(["-aG", "linhello", user])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            log.push(format!(
                "added '{user}' to the linhello group (CLI without sudo; takes effect at next login)"
            ));
        } else {
            log.push(format!(
                "could not add '{user}' to the linhello group — run: sudo usermod -aG linhello {user}"
            ));
        }
    }
    run_systemctl(&["daemon-reload"]);
    // A prior crash-loop leaves the unit in start-limit-hit; clear it so this
    // (re)install can actually start the fixed daemon.
    run_systemctl(&["reset-failed", "linhellod"]);
    if !run_systemctl(&["enable", "--now", "linhellod"]) {
        return Err(
            "could not enable/start linhellod — check `systemctl status linhellod`".to_string(),
        );
    }
    // Don't claim success until the daemon actually answers — systemctl can
    // report a started unit whose process crashed immediately.
    wait_for_daemon()?;
    log.push("linhellod is running and answering on its socket".to_string());
    Ok(log)
}

/// Copy the face models from a directory into `CONFIG_ROOT`. The detector and
/// embedder are required; anti-spoof is copied if present. Returns a per-file
/// log, or an error naming the first missing required model.
pub fn copy_models_from(dir: &Path) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(CONFIG_ROOT).map_err(|e| format!("create {CONFIG_ROOT}: {e}"))?;
    let mut log = Vec::new();
    for (name, required) in REQUIRED_FOR_COPY {
        let src = dir.join(name);
        if !src.exists() {
            if required {
                return Err(format!("missing required model '{name}' in {}", dir.display()));
            }
            log.push(format!("optional {name}: not found, skipped"));
            continue;
        }
        let dst = Path::new(CONFIG_ROOT).join(name);
        std::fs::copy(&src, &dst).map_err(|e| format!("copy {name}: {e}"))?;
        log.push(format!("copied {name}"));
    }
    Ok(log)
}

const BIN_NAMES: [&str; 3] = ["linhello", "linhellod", "linhello-reseal-hook"];
const PAM_DIRS: [&str; 2] = ["/usr/lib/security", "/usr/lib64/security"];
/// Where `linhello update` fetches from.
const REPO_URL: &str = "https://github.com/archledger/linhello";
/// The clone `linhello update` manages when this install didn't come from one
/// (ZIP download, deleted checkout). Root-owned; nothing else touches it.
const MANAGED_SRC: &str = "/var/lib/linhello/src";

/// Update from GitHub: pull the latest source (reusing the git checkout we're
/// running from when there is one, else a managed clone), rebuild, reinstall
/// via `deploy_from`, and re-apply the existing PAM wiring so newly supported
/// services get wired. Enrollment, config, models, and PAM backups are never
/// touched. Root-only; build/git output streams to the caller's terminal.
pub fn update(user: &str) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let (root, fresh_clone) = match source_root().filter(|r| r.join(".git").exists()) {
        Some(r) => {
            log.push(format!("source: git checkout at {}", r.display()));
            (r, false)
        }
        None => {
            let managed = PathBuf::from(MANAGED_SRC);
            if managed.join(".git").exists() {
                log.push(format!("source: managed clone at {}", managed.display()));
                (managed, false)
            } else {
                if let Some(parent) = managed.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("creating {}: {e}", parent.display()))?;
                }
                log.push(format!("cloning {REPO_URL} -> {}", managed.display()));
                run_streamed(None, Path::new("/"), "git", &["clone", REPO_URL, MANAGED_SRC])?;
                (managed, true)
            }
        }
    };

    // Run git/cargo as the checkout's owner: keeps a user-owned dev repo free
    // of root-owned objects (and trips neither git's dubious-ownership check
    // nor a user-local cargo setup). The managed clone is root-owned -> root.
    let owner = dir_owner(&root);

    let before = git_head(&root, owner);
    if !fresh_clone {
        run_streamed(owner, &root, "git", &["pull", "--ff-only"])?;
    }
    let after = git_head(&root, owner);

    if !fresh_clone && before == after && installed_cli().is_some() {
        log.push(format!(
            "already up to date ({}) — nothing to do. (Force a reinstall from the TUI's \
             Install step if programs are damaged.)",
            after.as_deref().unwrap_or("unknown commit")
        ));
        return Ok(log);
    }

    log.push("building (cargo build --release)…".to_string());
    run_streamed(owner, &root, "cargo", &["build", "--release"])?;

    log.extend(deploy_from(&root, user)?);

    // Extend login wiring only when the operator had already opted in: re-run
    // enable (idempotent) so services this version newly supports get wired;
    // keep sudo exactly as opted.
    let st = crate::pamwire::status();
    if st.iter().any(|s| s.wired) {
        let sudo_wired = st
            .iter()
            .any(|s| s.wired && s.path.file_name().and_then(|n| n.to_str()) == Some("sudo"));
        match crate::pamwire::enable(sudo_wired, false) {
            Ok(changes) => log.extend(changes.iter().map(|c| c.describe())),
            Err(e) => log.push(format!("PAM wiring not re-applied: {e}")),
        }
    } else {
        log.push("login wiring untouched (none was enabled)".to_string());
    }

    log.push(format!(
        "updated {} -> {}",
        before.as_deref().unwrap_or("unknown"),
        after.as_deref().unwrap_or("unknown")
    ));
    Ok(log)
}

/// Owner uid of `path` when it isn't root — the uid update's git/cargo calls
/// should run as. `None` means "run as the current (root) user directly".
fn dir_owner(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.uid()).filter(|&u| u != 0)
}

/// Run `prog args` in `cwd`, output inherited (the user watches git/cargo
/// progress live). With `Some(uid)`, drops to that user via `sudo -u #uid`.
fn run_streamed(
    uid: Option<u32>,
    cwd: &Path,
    prog: &str,
    args: &[&str],
) -> Result<(), String> {
    let mut cmd = match uid {
        Some(u) => {
            let mut c = Command::new("sudo");
            c.arg("-u").arg(format!("#{u}")).arg(prog).args(args);
            c
        }
        None => {
            let mut c = Command::new(prog);
            c.args(args);
            c
        }
    };
    let status = cmd
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("running {prog}: {e} (is it installed system-wide?)"))?;
    if !status.success() {
        return Err(format!("{prog} {} failed (see output above)", args.join(" ")));
    }
    Ok(())
}

fn git_head(root: &Path, uid: Option<u32>) -> Option<String> {
    let out = match uid {
        Some(u) => Command::new("sudo")
            .args(["-u", &format!("#{u}"), "git", "rev-parse", "--short", "HEAD"])
            .current_dir(root)
            .output(),
        None => Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .current_dir(root)
            .output(),
    }
    .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The installed CLI binary, if any (distinguishes "source unchanged, nothing
/// to do" from "source unchanged but programs were never/no longer installed").
fn installed_cli() -> Option<PathBuf> {
    BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join("linhello"))
        .find(|p| p.exists())
}

const PAM_LIBS: [&str; 2] = ["pam_linhello.so", "liblinhello_pam.so"];
const UNIT_PATHS: [&str; 2] = [
    "/etc/systemd/system/linhellod.service",
    "/usr/lib/systemd/system/linhellod.service",
];
const PACMAN_HOOK: &str = "/etc/pacman.d/hooks/linhello-reseal.hook";

/// Human-readable preview of what an uninstall will do, for the confirm screen.
pub fn uninstall_plan(remove_models: bool) -> Vec<String> {
    let mut v = vec![
        "disable face login in every PAM stack (password login stays)".to_string(),
        "stop and disable the linhellod service".to_string(),
        "remove the linhello / linhellod / reseal-hook programs".to_string(),
        "remove the PAM modules (pam_linhello.so, liblinhello_pam.so)".to_string(),
        "remove the systemd unit and the pacman reseal hook".to_string(),
        "ERASE enrolled faces, TPM envelopes, and config in /etc/linhello".to_string(),
    ];
    if remove_models {
        v.push("also delete the ~190MB face models (re-fetch needed to reinstall)".to_string());
    } else {
        v.push("keep only the ~190MB face models (so a reinstall skips re-fetch)".to_string());
    }
    v
}

/// Remove LinuxHello from this host. PAM is unwired *first* so the module is
/// never deleted while a login stack still references it (which could wedge
/// login); if unwiring fails we abort before touching anything else. Best-effort
/// thereafter — every action is logged. Requires root (the caller, the TUI,
/// already runs as root).
pub fn uninstall(remove_models: bool) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    match crate::pamwire::disable(false) {
        Ok(changes) => log.push(format!("unwired face login from {} PAM file(s)", changes.len())),
        Err(e) => {
            return Err(format!(
                "could not unwire PAM ({e}); aborted before removing anything (login stays intact)"
            ))
        }
    }
    // Belt-and-suspenders: scrub any remaining pam_linhello reference (the
    // system-auth reseal line, a throwaway test service, stragglers) so the
    // module is never left referenced after it is deleted.
    scrub_pam_references(&mut log);

    if run_systemctl(&["disable", "--now", "linhellod"]) {
        log.push("stopped and disabled linhellod".to_string());
    } else {
        log.push("linhellod was not running / already disabled".to_string());
    }

    for dir in BIN_DIRS {
        for name in BIN_NAMES {
            remove_if(&Path::new(dir).join(name), &mut log);
        }
    }
    for dir in PAM_DIRS {
        for lib in PAM_LIBS {
            remove_if(&Path::new(dir).join(lib), &mut log);
        }
    }
    for p in UNIT_PATHS {
        remove_if(Path::new(p), &mut log);
    }
    remove_if(Path::new(PACMAN_HOOK), &mut log);
    run_systemctl(&["daemon-reload"]);

    // Always remove the data LinuxHello created — enrolled faces, envelopes,
    // and config — so an uninstall really does return the machine to clean.
    // The big .onnx models are the only thing optionally kept (re-fetching them
    // is the expensive part of a reinstall).
    remove_config_data(remove_models, &mut log);

    Ok(log)
}

/// Remove everything under `CONFIG_ROOT` — enrolled faces, TPM envelopes, and
/// config files — always. The `.onnx` models are removed only if `remove_models`
/// (they're large and slow to re-fetch). Finally drops the now-empty config dir.
fn remove_config_data(remove_models: bool, log: &mut Vec<String>) {
    let root = Path::new(CONFIG_ROOT);
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        let is_model = path.extension().map(|e| e == "onnx").unwrap_or(false);
        if is_model && !remove_models {
            log.push(format!(
                "kept model {}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
            ));
            continue;
        }
        let res = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match res {
            Ok(()) => log.push(format!("removed {}", path.display())),
            Err(e) => log.push(format!("could not remove {}: {e}", path.display())),
        }
    }
    // If nothing's left (models removed too), drop the directory itself.
    if std::fs::read_dir(root)
        .map(|mut r| r.next().is_none())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir(root);
        log.push(format!("removed {CONFIG_ROOT}"));
    }
}

/// Remove every `pam_linhello` reference left under `/etc/pam.d` (after the
/// per-distro `pamwire::disable` has done the structured unwiring). Drops the
/// throwaway `linhello-test` service entirely; for other files, strips the
/// referencing lines and keeps a `.pre-linhello-uninstall` backup. This is what
/// guarantees no stack references the module once it's deleted.
fn scrub_pam_references(log: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir("/etc/pam.d") else {
        return;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        // Never process our own backup files — they contain pam_linhello (they
        // are pre-scrub copies) and re-scrubbing them just compounds nested
        // `.pre-linhello-uninstall.pre-linhello-uninstall…` cruft.
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains(".pre-linhello") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !content.contains("pam_linhello") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("linhello-test") {
            if std::fs::remove_file(&path).is_ok() {
                log.push(format!("removed {}", path.display()));
            }
            continue;
        }
        // Override files WE materialized from a PAM vendor-dir copy (KDE
        // lockscreen): delete outright — there is no distro original in /etc
        // to preserve, and the service falls back to the vendor file.
        if crate::pamwire::is_created_override(&content) {
            if std::fs::remove_file(&path).is_ok() {
                log.push(format!("removed {} (was a linhello-created override)", path.display()));
            }
            continue;
        }
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| !l.contains("pam_linhello"))
            .collect();
        let mut cleaned = kept.join("\n");
        if content.ends_with('\n') {
            cleaned.push('\n');
        }
        let backup = format!("{}.pre-linhello-uninstall", path.display());
        if !Path::new(&backup).exists() {
            let _ = std::fs::copy(&path, &backup);
        }
        if std::fs::write(&path, cleaned).is_ok() {
            log.push(format!(
                "scrubbed pam_linhello from {} (backup {backup})",
                path.display()
            ));
        }
    }
}

fn remove_if(path: &Path, log: &mut Vec<String>) {
    match std::fs::remove_file(path) {
        Ok(()) => log.push(format!("removed {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log.push(format!("could not remove {}: {e}", path.display())),
    }
}

fn run_systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_bin(name: &str) -> Option<PathBuf> {
    BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.exists())
}

/// `(is-active, is-enabled)` for a systemd unit. A missing systemctl or unit
/// just reads as `(false, false)`.
fn systemd_state(unit: &str) -> (bool, bool) {
    let query = |verb: &str| {
        Command::new("systemctl")
            .args([verb, unit])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    (query("is-active"), query("is-enabled"))
}

/// Live per-model presence under `CONFIG_ROOT`, from the catalog.
fn model_states() -> Vec<ModelStatus> {
    MODEL_CATALOG
        .iter()
        .map(|&(file, role, required, shipped)| ModelStatus {
            file,
            role,
            required,
            shipped,
            present: Path::new(CONFIG_ROOT).join(file).exists(),
        })
        .collect()
}

/// Users with a stored face template (`embedding.enc`, or legacy
/// `embedding.bin`) under `CONFIG_ROOT/<user>/`. The per-user directory is
/// world-traversable (0755) so the `exists()` probe works without root even
/// though the template itself is 0600.
fn enrolled_users() -> Vec<String> {
    let mut users = Vec::new();
    let Ok(rd) = std::fs::read_dir(CONFIG_ROOT) else {
        return users;
    };
    for ent in rd.flatten() {
        if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = ent.path();
        if dir.join("embedding.enc").exists() || dir.join("embedding.bin").exists() {
            if let Some(name) = ent.file_name().to_str() {
                users.push(name.to_string());
            }
        }
    }
    users.sort();
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> InstallState {
        InstallState {
            cli_bin: None,
            daemon_bin: None,
            daemon_active: false,
            daemon_enabled: false,
            models: vec![],
            models_present: false,
            missing_models: vec![],
            camera_configured: false,
            threshold: None,
            enrolled_users: vec![],
            pam_wired: 0,
            pam_total: 0,
        }
    }

    #[test]
    fn fresh_machine_is_not_installed() {
        let s = state();
        assert!(!s.is_installed());
        assert!(!s.is_configured());
        assert!(s.headline().contains("fresh setup"));
    }

    #[test]
    fn installed_but_unenrolled() {
        let mut s = state();
        s.daemon_active = true;
        s.cli_bin = Some(PathBuf::from("/usr/bin/linhello"));
        assert!(s.is_installed());
        assert!(!s.is_configured());
        assert!(s.headline().contains("no face is enrolled"));
    }

    #[test]
    fn fully_configured() {
        let mut s = state();
        s.daemon_active = true;
        s.daemon_bin = Some(PathBuf::from("/usr/local/bin/linhellod"));
        s.enrolled_users = vec!["ben".into()];
        s.pam_wired = 2;
        s.pam_total = 3;
        assert!(s.is_configured());
        let h = s.headline();
        assert!(h.contains("already set up"));
        assert!(h.contains("ben"));
        assert!(h.contains("2/3"));
    }
}
