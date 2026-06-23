//! Detect whether LinuxHello is already installed and configured on this host.
//!
//! Lets the setup wizard (and any `status`-style caller) tell a fresh machine
//! from one that already has LinuxHello deployed: binaries in place, the daemon
//! installed/running, face models present, a camera pinned, a calibrated
//! threshold, enrolled users, and login wiring. Every check is read-only —
//! detecting state never changes it.

use linhello_common::config;
use linhello_common::platform::{self, PackageFormat};
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

/// SHA-1 fingerprint (40 hex chars, no spaces) of the **only** key trusted to
/// sign LinuxHello releases. `linhello update` builds and installs as root, so
/// it refuses any source whose release tag is not signed by exactly this key —
/// this is what neutralizes a repository/account takeover. Rotating the signing
/// key means changing this constant and shipping a new signed release.
const TRUSTED_SIGNER_FINGERPRINT: &str = "54C989C55B1FB5F26FDC55F7CC46D5CD5E601D4B";

/// ASCII-armored public key for [`TRUSTED_SIGNER_FINGERPRINT`], installed with
/// the rest of the config. The updater imports it into a dedicated, throwaway
/// keyring so signature verification depends only on this pinned key — never on
/// whatever happens to live in root's ambient GnuPG keyring.
const TRUSTED_SIGNER_KEY_PATH: &str = "/etc/linhello/trusted-signer.asc";

/// Update from GitHub: pull the latest source (reusing the git checkout we're
/// running from when there is one, else a managed clone), rebuild, reinstall
/// via `deploy_from`, and re-apply the existing PAM wiring so newly supported
/// services get wired. Enrollment, config, models, and PAM backups are never
/// touched. Root-only; build/git output streams to the caller's terminal.
pub fn update(user: &str) -> Result<Vec<String>, String> {
    let mut log = Vec::new();

    let (root, _fresh_clone) = match source_root().filter(|r| r.join(".git").exists()) {
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

    // We build only from a signed release tag, never an arbitrary branch HEAD.
    // Fetch tags from the trusted remote.
    run_streamed(owner, &root, "git", &["fetch", "--tags", "--force", "origin"])?;

    let tag = latest_release_tag(&root, owner)?.ok_or_else(|| {
        "no release tags found on the remote — nothing to update to".to_string()
    })?;
    log.push(format!("latest release tag: {tag}"));

    // HARD GATE: the tag must carry a valid signature from the pinned trusted
    // key. Any failure — missing key, missing/invalid signature, or a different
    // signer — aborts here. There is deliberately no override or prompt.
    verify_tag_signature(&root, owner, &tag)?;
    log.push(format!(
        "signature verified: {tag} signed by trusted key {TRUSTED_SIGNER_FINGERPRINT}"
    ));

    let tag_commit = rev_commit(&root, owner, &tag)?;
    let head_commit = rev_commit(&root, owner, "HEAD").unwrap_or_default();
    if head_commit == tag_commit && installed_cli().is_some() {
        log.push(format!(
            "already at {tag} ({}) and installed — nothing to do",
            short(&tag_commit)
        ));
        return Ok(log);
    }

    // Check out exactly the verified tag (detached) and build from it.
    run_streamed(owner, &root, "git", &["checkout", "--quiet", "--detach", &tag])?;
    log.push(format!("checked out {tag} ({})", short(&tag_commit)));

    // Install the way this distro expects: build + install the native package
    // (rpm/deb/pkg) when its build tooling is present, so the system tracks a
    // real package; otherwise fall back to the from-source `make install`.
    let fmt = platform::package_format();
    if fmt.build_tool().map(on_path).unwrap_or(false) {
        // Native package build. A failure here is a real error — propagate it
        // rather than silently falling back to a source install, which detaches
        // the system from package tracking (the cause of a split CLI/daemon
        // version where pacman still believes an older build is installed).
        let (pkg, blog) = build_native_package(&root, fmt)?;
        log.push(format!("distro {}: native {} package", platform::distro_family().as_str(), fmt.as_str()));
        log.extend(blog);
        log.extend(install_native_package(&pkg, fmt)?);
    } else {
        log.push(format!(
            "no native {} build tooling — installing from source (make install)",
            fmt.as_str()
        ));
        log.push("building (cargo build --release)…".to_string());
        run_streamed(owner, &root, "cargo", &["build", "--release"])?;
        log.extend(deploy_from(&root, user)?);
    }

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

    log.push(format!("updated to {tag} ({})", short(&tag_commit)));
    Ok(log)
}

/// Owner uid of `path` when it isn't root — the uid update's git/cargo calls
/// should run as. `None` means "run as the current (root) user directly".
fn dir_owner(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.uid()).filter(|&u| u != 0)
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

/// Workspace version from Cargo.toml at `root` (e.g. "0.1.0").
fn workspace_version(root: &Path) -> String {
    std::fs::read_to_string(root.join("Cargo.toml"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.trim_start().starts_with("version"))
                .and_then(|l| l.split('"').nth(1).map(str::to_string))
        })
        .unwrap_or_else(|| "0.0.0".to_string())
}

/// Newest file under `dir` (recursively, one level into subdirs) whose name
/// starts with `prefix` and ends with `suffix`.
fn newest_built(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    fn collect(dir: &Path, prefix: &str, suffix: &str, depth: u8, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && depth > 0 {
                collect(&p, prefix, suffix, depth - 1, out);
            } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                // Never the installable: makepkg's `-debug` split, rpm's
                // `-debuginfo`/`-debugsource`, deb's `-dbgsym`. These share the
                // `linhello-` prefix but carry no binaries.
                let is_debug = n.contains("-debug") || n.contains("-dbgsym");
                if n.starts_with(prefix) && n.ends_with(suffix) && !is_debug {
                    out.push(p.clone());
                }
            }
        }
    }
    let mut hits = Vec::new();
    collect(dir, prefix, suffix, 2, &mut hits);
    hits.sort();
    hits.pop()
}

/// Build the native package (rpm/deb/pkg) for `fmt` from the source at `root`,
/// returning its path. Gated on the build tool being present; the Fedora (rpm)
/// path is validated, the deb/pkg paths are authored but not yet build-tested.
pub fn build_native_package(
    root: &Path,
    fmt: PackageFormat,
) -> Result<(PathBuf, Vec<String>), String> {
    let tool = fmt
        .build_tool()
        .ok_or_else(|| "no native package format for this distro".to_string())?;
    if !on_path(tool) {
        return Err(format!(
            "`{tool}` not found — install it to build a {} package",
            fmt.as_str()
        ));
    }
    // When invoked as root (e.g. from `update`), drop to the repo owner so the
    // user-owned dev tree stays free of root-owned artifacts and git's
    // dubious-ownership check doesn't trip. When already running as the user,
    // build directly.
    let owner = if unsafe { libc::geteuid() } == 0 {
        dir_owner(root)
    } else {
        None
    };
    let ver = workspace_version(root);
    let mut log = vec![format!("building {} package v{ver}", fmt.as_str())];
    match fmt {
        PackageFormat::Rpm => {
            let top = root.join("target/rpmbuild");
            for d in ["SOURCES", "SPECS", "BUILD", "RPMS", "SRPMS", "BUILDROOT"] {
                std::fs::create_dir_all(top.join(d)).map_err(|e| e.to_string())?;
            }
            let tar = top.join(format!("SOURCES/linhello-{ver}.tar.gz"));
            run_streamed(
                owner,
                root,
                "git",
                &[
                    "archive",
                    "--format=tar.gz",
                    &format!("--prefix=linhello-{ver}/"),
                    "-o",
                    &tar.to_string_lossy(),
                    "HEAD",
                ],
            )?;
            run_streamed(
                owner,
                root,
                "rpmbuild",
                &[
                    "-bb",
                    "--nodeps",
                    "--define",
                    &format!("_topdir {}", top.display()),
                    "packaging/fedora/linhello.spec",
                ],
            )?;
            let rpm = newest_built(&top.join("RPMS"), "linhello-", ".rpm")
                .ok_or_else(|| "rpmbuild produced no rpm".to_string())?;
            log.push(format!("built {}", rpm.display()));
            Ok((rpm, log))
        }
        PackageFormat::Pkg => {
            // makepkg refuses to run as root, so the build must happen as an
            // unprivileged user. Prefer the checkout's owner; when building
            // from the root-owned managed clone there is no such user, so fall
            // back to whoever invoked sudo (SUDO_UID). Without either we cannot
            // proceed — surface that instead of silently degrading to source.
            let mk_uid = owner.or_else(sudo_uid).ok_or_else(|| {
                "makepkg cannot run as root and no unprivileged user was found \
                 (run via `sudo` so SUDO_USER is set, or build as a normal user)"
                    .to_string()
            })?;
            // Stage PKGBUILD + the source tarball in a dedicated build dir the
            // build user owns; the root-owned checkout itself stays untouched
            // and makepkg gets a writable working tree.
            let build = root.join("target/arch-build");
            let _ = std::fs::remove_dir_all(&build);
            std::fs::create_dir_all(&build)
                .map_err(|e| format!("creating {}: {e}", build.display()))?;
            // Own the dir before writing into it: when `owner` is the build
            // user, the owner-run `git archive` below needs write access here.
            run_streamed(None, &build, "chown", &[&mk_uid.to_string(), "."])?;
            let tar = build.join(format!("linhello-{ver}.tar.gz"));
            run_streamed(
                owner,
                root,
                "git",
                &[
                    "archive",
                    "--format=tar.gz",
                    &format!("--prefix=linhello-{ver}/"),
                    "-o",
                    &tar.to_string_lossy(),
                    "HEAD",
                ],
            )?;
            for f in ["PKGBUILD", "linhello.install"] {
                std::fs::copy(root.join("packaging/arch").join(f), build.join(f))
                    .map_err(|e| format!("staging {f}: {e}"))?;
            }
            // Normalise ownership of everything staged (the tarball is root-owned
            // when produced from the managed clone) so makepkg can read/write it.
            run_streamed(None, &build, "chown", &["-R", &mk_uid.to_string(), "."])?;
            run_makepkg(mk_uid, &build)?;
            let pkg = newest_built(&build, "linhello-", ".pkg.tar.zst")
                .ok_or_else(|| "makepkg produced no package".to_string())?;
            log.push(format!("built {} (as uid {mk_uid})", pkg.display()));
            Ok((pkg, log))
        }
        PackageFormat::Deb => {
            // dpkg-buildpackage expects ./debian at the source root.
            let dst = root.join("debian");
            run_streamed(owner, root, "cp", &["-rT", "packaging/debian", "debian"])?;
            let r = run_streamed(owner, root, "dpkg-buildpackage", &["-b", "-us", "-uc"]);
            let _ = std::fs::remove_dir_all(&dst);
            r?;
            let parent = root.parent().ok_or("no parent dir for .deb output")?;
            let deb = newest_built(parent, "linhello_", ".deb")
                .ok_or_else(|| "dpkg-buildpackage produced no .deb".to_string())?;
            log.push(format!("built {}", deb.display()));
            Ok((deb, log))
        }
        PackageFormat::Unknown => Err("no native package format for this distro".to_string()),
    }
}

/// Official InsightFace buffalo_l pack (detector + recognizer). HTTPS from the
/// upstream release is the trust anchor; the SHA-256s below pin the exact files.
const BUFFALO_URL: &str =
    "https://github.com/deepinsight/insightface/releases/download/v0.7/buffalo_l.zip";
/// Pinned SHA-256 of the two models we install (InsightFace buffalo_l v0.7).
/// Empty/PLACEHOLDER => verification skipped and the computed hash is printed.
const DET_SHA256: &str = "5838f7fe053675b1c7a08b633df49e7af5495cee0493c7dcf6697200b85b5b91";
const REC_SHA256: &str = "4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43";

fn sha256_of(path: &Path) -> Result<String, String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| format!("sha256sum: {e}"))?;
    if !out.status.success() {
        return Err("sha256sum failed".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string())
}

fn find_under(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, name: &str, depth: u8, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && depth > 0 {
                walk(&p, name, depth - 1, out);
            } else if p.file_name().and_then(|n| n.to_str()) == Some(name) {
                out.push(p);
            }
        }
    }
    walk(dir, name, 4, &mut out);
    out.pop()
}

fn verify_model(path: &Path, label: &str, pinned: &str, log: &mut Vec<String>) -> Result<(), String> {
    let got = sha256_of(path)?;
    if pinned.is_empty() || pinned.ends_with("PLACEHOLDER") {
        log.push(format!("{label} sha256 {got} (not pinned — verification skipped)"));
        return Ok(());
    }
    if got != pinned {
        return Err(format!(
            "{label} sha256 mismatch: got {got}, expected {pinned} — refusing to install"
        ));
    }
    log.push(format!("{label} sha256 verified"));
    Ok(())
}

/// `linhello fetch-models` — download the buffalo_l detector + recognizer from
/// the official InsightFace release, verify, and install them to /etc/linhello
/// (det_10g.onnx + face.onnx). The anti-spoof model already ships with the
/// package. Requires root.
pub fn fetch_models(force: bool) -> Result<Vec<String>, String> {
    let conf = Path::new(CONFIG_ROOT);
    let det = conf.join("det_10g.onnx");
    let face = conf.join("face.onnx");
    if !force && det.exists() && face.exists() {
        return Ok(vec![
            "buffalo_l models already present in /etc/linhello (use --force to re-fetch)".to_string(),
        ]);
    }
    for t in ["curl", "unzip", "sha256sum"] {
        if !on_path(t) {
            return Err(format!("`{t}` not found — install it and retry"));
        }
    }
    let mut log = Vec::new();
    let tmp = std::env::temp_dir().join(format!("linhello-models-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| format!("temp dir: {e}"))?;
    let result = (|| -> Result<Vec<String>, String> {
        let zip = tmp.join("buffalo_l.zip");
        log.push("downloading buffalo_l (~250 MB) from InsightFace v0.7…".to_string());
        run_streamed(
            None,
            &tmp,
            "curl",
            &["-fL", "--proto", "=https", "--tlsv1.2", "-o", &zip.to_string_lossy(), BUFFALO_URL],
        )?;
        let ex = tmp.join("x");
        run_streamed(None, &tmp, "unzip", &["-oq", &zip.to_string_lossy(), "-d", &ex.to_string_lossy()])?;
        let det_src = find_under(&ex, "det_10g.onnx").ok_or("det_10g.onnx not found in archive")?;
        let rec_src = find_under(&ex, "w600k_r50.onnx").ok_or("w600k_r50.onnx not found in archive")?;
        verify_model(&det_src, "detector (det_10g.onnx)", DET_SHA256, &mut log)?;
        verify_model(&rec_src, "recognizer (w600k_r50.onnx)", REC_SHA256, &mut log)?;
        std::fs::create_dir_all(conf).map_err(|e| format!("mkdir {}: {e}", conf.display()))?;
        for (src, dst) in [(&det_src, &det), (&rec_src, &face)] {
            std::fs::copy(src, dst).map_err(|e| format!("install {}: {e}", dst.display()))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o644));
        }
        log.push(format!("installed {} + {}", det.display(), face.display()));
        // Pick up the new models. `restart` (not `try-restart`) so it also starts
        // the daemon if it isn't running yet (e.g. right after a package install).
        if run_streamed(None, Path::new("/"), "systemctl", &["restart", "linhellod"]).is_ok() {
            log.push("restarted linhellod".to_string());
        }
        Ok(log.clone())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Official Microsoft ONNX Runtime prebuilt matching the `ort` crate ABI
/// (ort 2.0.0-rc.12 supports onnxruntime 1.17-1.24, so 1.24.x is the newest
/// matching runtime). HTTPS from the upstream release is the trust anchor; the
/// per-arch SHA-256s pin the exact tarballs.
const ORT_VERSION: &str = "1.24.4";
const ORT_X64_SHA256: &str = "3a211fbea252c1e66290658f1b735b772056149f28321e71c308942cdb54b747";
const ORT_AARCH64_SHA256: &str = "866109a9248d057671a039b9d725be4bd86888e3754140e6701ec621be9d4d7e";

/// `linhello fetch-onnx` — download the official Microsoft ONNX Runtime prebuilt
/// for this architecture and install `libonnxruntime.so*` into `/usr/local/lib`
/// (on linhello's loader search path), so distros that don't package it (Fedora,
/// Debian) get a working runtime in one command. Root-only.
pub fn fetch_onnx(force: bool) -> Result<Vec<String>, String> {
    if !force {
        if let Some(p) = platform::onnxruntime_dylib() {
            return Ok(vec![format!(
                "ONNX Runtime already present at {p} (use --force to reinstall)"
            )]);
        }
    }
    let (asset_arch, sha) = match std::env::consts::ARCH {
        "x86_64" => ("x64", ORT_X64_SHA256),
        "aarch64" => ("aarch64", ORT_AARCH64_SHA256),
        other => {
            return Err(format!(
                "no Microsoft ONNX Runtime prebuilt for arch '{other}' — build it or install \
                 libonnxruntime.so manually and set ORT_DYLIB_PATH"
            ))
        }
    };
    for t in ["curl", "tar", "sha256sum"] {
        if !on_path(t) {
            return Err(format!("`{t}` not found — install it and retry"));
        }
    }
    let stem = format!("onnxruntime-linux-{asset_arch}-{ORT_VERSION}");
    let url =
        format!("https://github.com/microsoft/onnxruntime/releases/download/v{ORT_VERSION}/{stem}.tgz");
    let mut log = Vec::new();
    let tmp = std::env::temp_dir().join(format!("linhello-onnx-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| format!("temp dir: {e}"))?;
    let result = (|| -> Result<Vec<String>, String> {
        let tgz = tmp.join("onnxruntime.tgz");
        log.push(format!(
            "downloading ONNX Runtime {ORT_VERSION} ({asset_arch}) from Microsoft…"
        ));
        run_streamed(
            None,
            &tmp,
            "curl",
            &["-fL", "--proto", "=https", "--tlsv1.2", "-o", &tgz.to_string_lossy(), &url],
        )?;
        verify_model(&tgz, &format!("onnxruntime {ORT_VERSION} ({asset_arch})"), sha, &mut log)?;
        run_streamed(
            None,
            &tmp,
            "tar",
            &["xzf", &tgz.to_string_lossy(), "-C", &tmp.to_string_lossy()],
        )?;
        // The versioned object is the real .so; .so.1 and .so are symlinks to it.
        let soname = format!("libonnxruntime.so.{ORT_VERSION}");
        let src = find_under(&tmp, &soname).ok_or_else(|| format!("{soname} not found in archive"))?;
        let libdir = Path::new("/usr/local/lib");
        std::fs::create_dir_all(libdir).map_err(|e| format!("mkdir {}: {e}", libdir.display()))?;
        let dst = libdir.join(&soname);
        std::fs::copy(&src, &dst).map_err(|e| format!("install {}: {e}", dst.display()))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755));
        // Recreate the ABI symlinks: libonnxruntime.so → .so.1 → .so.<version>.
        for link in ["libonnxruntime.so.1", "libonnxruntime.so"] {
            let lp = libdir.join(link);
            let _ = std::fs::remove_file(&lp);
            std::os::unix::fs::symlink(&soname, &lp).map_err(|e| format!("symlink {}: {e}", lp.display()))?;
        }
        log.push(format!("installed {} (+ .so.1, .so symlinks)", dst.display()));
        // Label it as a shared lib for SELinux, refresh the loader cache, and
        // restart the daemon so it loads the now-present runtime.
        let _ = run_streamed(None, Path::new("/"), "restorecon", &["-F", &dst.to_string_lossy()]);
        let _ = run_streamed(None, Path::new("/"), "ldconfig", &[]);
        if run_streamed(None, Path::new("/"), "systemctl", &["restart", "linhellod"]).is_ok() {
            log.push("ran ldconfig + restarted linhellod".to_string());
        }
        Ok(log.clone())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// Install a built native package via the distro's package manager (root).
pub fn install_native_package(pkg: &Path, fmt: PackageFormat) -> Result<Vec<String>, String> {
    let p = pkg.to_string_lossy().to_string();
    let (mgr, args): (&str, Vec<&str>) = match fmt {
        PackageFormat::Rpm => ("dnf", vec!["install", "-y", &p]),
        PackageFormat::Deb => ("apt-get", vec!["install", "-y", &p]),
        PackageFormat::Pkg => ("pacman", vec!["-U", "--noconfirm", &p]),
        PackageFormat::Unknown => return Err("no native package manager".to_string()),
    };
    run_streamed(None, Path::new("/"), mgr, &args)?;
    Ok(vec![format!("installed {} via {mgr}", pkg.display())])
}

/// Uid of the user who invoked `sudo`, when non-root. Lets a root-driven build
/// (e.g. `sudo linhello update` from the root-owned managed clone) fall back to
/// the real user for tooling that refuses to run as root, such as makepkg.
fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&u| u != 0)
}

/// Run makepkg as `uid` with output inherited. `-H` resets HOME to that user's
/// home so cargo's registry cache (under ~/.cargo) resolves; makepkg itself
/// hard-refuses to run as root, which is why this never uses uid 0.
fn run_makepkg(uid: u32, cwd: &Path) -> Result<(), String> {
    let status = Command::new("sudo")
        .arg("-u")
        .arg(format!("#{uid}"))
        .arg("-H")
        .arg("makepkg")
        .args(["-f", "--noconfirm"])
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("running makepkg: {e} (is base-devel installed?)"))?;
    if !status.success() {
        return Err("makepkg failed (see output above)".to_string());
    }
    Ok(())
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

/// Run `prog args` in `cwd` and capture its output (unlike `run_streamed`,
/// which inherits stdio for live progress). With `Some(uid)` it drops to that
/// user via `sudo -u #uid env …`, passing `envs` through (plain `sudo` scrubs
/// the environment, so the `env` wrapper is required to carry `GNUPGHOME`).
fn run_capture(
    uid: Option<u32>,
    cwd: &Path,
    prog: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<std::process::Output, String> {
    let mut cmd = match uid {
        Some(u) => {
            let mut c = Command::new("sudo");
            c.arg("-u").arg(format!("#{u}")).arg("env");
            for (k, v) in envs {
                c.arg(format!("{k}={v}"));
            }
            c.arg(prog).args(args);
            c
        }
        None => {
            let mut c = Command::new(prog);
            for (k, v) in envs {
                c.env(k, v);
            }
            c.args(args);
            c
        }
    };
    cmd.current_dir(cwd)
        .output()
        .map_err(|e| format!("running {prog}: {e} (is it installed system-wide?)"))
}

/// Highest-versioned `v*` release tag known locally (after a fetch), or `None`
/// if the repo has no release tags. Sorted by git's version ordering.
fn latest_release_tag(root: &Path, uid: Option<u32>) -> Result<Option<String>, String> {
    let out = run_capture(
        uid,
        root,
        "git",
        &["tag", "--list", "v*", "--sort=-version:refname"],
        &[],
    )?;
    if !out.status.success() {
        return Err("git tag --list failed (see output above)".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string))
}

/// Full commit hash a ref resolves to.
fn rev_commit(root: &Path, uid: Option<u32>, refname: &str) -> Result<String, String> {
    // `<tag>^{commit}` dereferences an annotated tag to its commit.
    let spec = format!("{refname}^{{commit}}");
    let out = run_capture(uid, root, "git", &["rev-parse", "--verify", &spec], &[])?;
    if !out.status.success() {
        return Err(format!("cannot resolve {refname} to a commit"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

/// Normalize a fingerprint for comparison: strip whitespace, uppercase.
fn normalize_fpr(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

/// Every fingerprint asserted by a `[GNUPG:] VALIDSIG` line in raw gpg status.
/// A VALIDSIG line means the signature is cryptographically valid for an
/// available key; its 1st field is the signing (sub)key fingerprint and its
/// last field is the primary-key fingerprint. We return both so a pinned
/// primary key still matches when a release is signed by a rotating subkey.
fn validsig_fingerprints(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let rest = match line.trim().strip_prefix("[GNUPG:] VALIDSIG ") {
            Some(r) => r,
            None => continue,
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if let Some(first) = fields.first() {
            out.push(normalize_fpr(first));
        }
        if let Some(last) = fields.last() {
            out.push(normalize_fpr(last));
        }
    }
    out
}

/// Verify `tag` carries a valid signature from the pinned trusted key. Fatal
/// error on any failure: bad pinned constant, missing trusted-key file,
/// missing/invalid signature, or a signature from a different key. No bypass.
fn verify_tag_signature(root: &Path, uid: Option<u32>, tag: &str) -> Result<(), String> {
    let pinned = normalize_fpr(TRUSTED_SIGNER_FINGERPRINT);
    if pinned.len() != 40 || !pinned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "TRUSTED_SIGNER_FINGERPRINT is not a 40-hex-char fingerprint; refusing to update"
                .to_string(),
        );
    }
    let key_path = Path::new(TRUSTED_SIGNER_KEY_PATH);
    if !key_path.exists() {
        return Err(format!(
            "trusted signer public key not found at {} — cannot verify the release \
             signature (export it with: gpg --export --armor {pinned} | sudo tee {})",
            key_path.display(),
            key_path.display(),
        ));
    }

    // Dedicated throwaway keyring so verification depends ONLY on the pinned
    // key, not on root's ambient GnuPG state. gpg requires 0700 on its home.
    let gnupghome = std::env::temp_dir().join(format!("linhello-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&gnupghome);
    std::fs::create_dir_all(&gnupghome)
        .map_err(|e| format!("creating verification keyring dir: {e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gnupghome, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("securing verification keyring dir: {e}"))?;
    }
    // When git/gpg runs as a non-root owner, the keyring dir must be theirs.
    if let Some(u) = uid {
        std::os::unix::fs::chown(&gnupghome, Some(u), None)
            .map_err(|e| format!("chowning verification keyring dir: {e}"))?;
    }

    let result = verify_tag_in_keyring(root, uid, tag, &gnupghome, key_path, &pinned);
    let _ = std::fs::remove_dir_all(&gnupghome);
    result
}

fn verify_tag_in_keyring(
    root: &Path,
    uid: Option<u32>,
    tag: &str,
    gnupghome: &Path,
    key_path: &Path,
    pinned: &str,
) -> Result<(), String> {
    let gh = gnupghome.to_string_lossy().to_string();
    let envs = [("GNUPGHOME", gh.as_str())];

    // Import only the pinned public key into the dedicated keyring.
    let imp = run_capture(
        uid,
        root,
        "gpg",
        &["--batch", "--quiet", "--import", &key_path.to_string_lossy()],
        &envs,
    )?;
    if !imp.status.success() {
        return Err(format!(
            "failed to import trusted signer key from {}: {}",
            key_path.display(),
            String::from_utf8_lossy(&imp.stderr).trim()
        ));
    }

    // Verify the tag. `--raw` prints machine-readable [GNUPG:] status to stderr.
    let out = run_capture(uid, root, "git", &["verify-tag", "--raw", tag], &envs)?;
    let status = String::from_utf8_lossy(&out.stderr);
    let fprs = validsig_fingerprints(&status);

    if fprs.is_empty() {
        return Err(format!(
            "release tag {tag} is not validly signed (no VALIDSIG from gpg) — refusing to \
             build untrusted code as root"
        ));
    }
    if !fprs.iter().any(|f| f == pinned) {
        return Err(format!(
            "release tag {tag} is signed by an untrusted key (got {:?}, expected {pinned}) — \
             refusing to build untrusted code as root",
            fprs
        ));
    }
    Ok(())
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
const UNIT_PATHS: [&str; 4] = [
    "/etc/systemd/system/linhellod.service",
    "/usr/lib/systemd/system/linhellod.service",
    // Camera/cgroup boot-race refresh oneshot (see 72-linhello-camera.rules).
    "/etc/systemd/system/linhellod-camera-refresh.service",
    "/usr/lib/systemd/system/linhellod-camera-refresh.service",
];
// udev rule that pulls in the refresh oneshot when a V4L node appears.
const UDEV_RULE_PATHS: [&str; 2] = [
    "/etc/udev/rules.d/72-linhello-camera.rules",
    "/usr/lib/udev/rules.d/72-linhello-camera.rules",
];
// system-sleep hook that try-restarts the daemon on resume (recovers a UVC
// camera wedged across suspend). systemd only scans the /usr/lib location.
const SLEEP_HOOK_PATHS: [&str; 1] = ["/usr/lib/systemd/system-sleep/linhello-resume"];
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
    for p in UDEV_RULE_PATHS {
        remove_if(Path::new(p), &mut log);
    }
    for p in SLEEP_HOOK_PATHS {
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

    #[test]
    fn pinned_fingerprint_is_well_formed() {
        let f = normalize_fpr(TRUSTED_SIGNER_FINGERPRINT);
        assert_eq!(f.len(), 40, "pinned fingerprint must be 40 hex chars");
        assert!(f.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn validsig_parses_signing_and_primary_fpr() {
        // Real `git verify-tag --raw` status (signing fpr first, primary last).
        let raw = "[GNUPG:] NEWSIG\n\
            [GNUPG:] GOODSIG CC46D5CD5E601D4B archledger <archledger@gmail.com>\n\
            [GNUPG:] VALIDSIG AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555 2026-06-15 1781 0 4 0 22 10 00 54C989C55B1FB5F26FDC55F7CC46D5CD5E601D4B\n\
            [GNUPG:] TRUST_UNDEFINED 0 pgp";
        let fprs = validsig_fingerprints(raw);
        // Both the signing (sub)key fpr and the primary fpr are surfaced.
        assert!(fprs.contains(&"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555".to_string()));
        assert!(fprs.contains(&"54C989C55B1FB5F26FDC55F7CC46D5CD5E601D4B".to_string()));
    }

    #[test]
    fn no_validsig_yields_no_fingerprints() {
        // ERRSIG/NO_PUBKEY (wrong or missing key) must NOT produce a match.
        let raw = "[GNUPG:] ERRSIG CC46D5CD5E601D4B 22 10 00 1781 9 54C9\n\
            [GNUPG:] NO_PUBKEY CC46D5CD5E601D4B";
        assert!(validsig_fingerprints(raw).is_empty());
    }

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
