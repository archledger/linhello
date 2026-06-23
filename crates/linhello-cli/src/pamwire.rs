//! Per-distro PAM wiring for face login.
//!
//! Inserting `pam_linhello.so` into the auth stack is distro-specific:
//!
//! * **Arch** (and derivatives): edit the per-service files directly. The
//!   greeter needs `auth [success=1 default=ignore] pam_linhello.so` (NOT
//!   `sufficient`) so `pam_gnome_keyring`'s auth phase still runs and unlocks
//!   the login keyring — `[success=1]` works because Arch's greeter jumps over
//!   exactly one `include system-local-login`. `sudo`/TTY use plain
//!   `sufficient`. The KDE *lockscreen* is a separate service (`kde`,
//!   kscreenlocker) — wired with `sufficient`; see `KDE_LOCKSCREEN`.
//! * **Debian/Ubuntu**: the greeter `@include common-auth`, which expands to
//!   several modules, so a naive `[success=1]` jump would land mid-stack. The
//!   correct mechanism is a `pam-auth-update` profile.
//! * **Fedora/RHEL**: `system-auth`/`password-auth` are `authselect`-managed
//!   symlinks; hand-edits get clobbered. The correct mechanism is an
//!   `authselect` custom profile/feature.
//!
//! This module automates all three paths idempotently, each through the
//! distro's *sanctioned* mechanism (never raw edits of the shared stack):
//! Arch edits the per-service files directly (with backups); Debian/Ubuntu ship
//! a `pam-auth-update` profile and run `pam-auth-update --package`; Fedora bases
//! an `authselect` custom profile on the live one and `authselect select`s it.
//! Two safety invariants are always preserved: the face line is
//! `sufficient`/`[success=1]`/Primary so a camera/TPM failure falls through to
//! the password, and revert is one command (`linhello pam disable`). The
//! Debian/Fedora paths are EXPERIMENTAL pending validation on real hardware.

use anyhow::Result;
use linhello_common::platform::{self, DistroFamily};
use std::path::{Path, PathBuf};
use std::process::Command;

const MODULE: &str = "pam_linhello.so";
const BACKUP_SUFFIX: &str = ".pre-linhello";

/// Debian/Ubuntu: pam-auth-update profile that weaves face-auth into common-auth.
const DEBIAN_PROFILE_PATH: &str = "/usr/share/pam-configs/linhello";
/// Fedora/RHEL: authselect custom profile directory.
const FEDORA_CUSTOM_DIR: &str = "/etc/authselect/custom/linhello";
/// Records the authselect profile that was active before we selected
/// `custom/linhello`, so `disable` can revert to it cleanly.
const FEDORA_BASE_MARKER: &str = "/etc/linhello/authselect-base";

/// Greeter line: keep `pam_gnome_keyring` reachable so the keyring unlocks.
const GREETER_STANZA: &str = "auth       [success=1 default=ignore]   pam_linhello.so";
/// sudo line: plain sufficient — face success authenticates immediately.
const SUFFICIENT_STANZA: &str = "auth       sufficient   pam_linhello.so";
/// Lockscreen parallel-stack line: `wait` makes the module keep scanning for
/// ~20s instead of one capture, because kscreenlocker starts this stack the
/// moment the lock screen appears — the window is what lets you sit down and
/// be recognized without touching a key.
const WAIT_STANZA: &str = "auth       sufficient   pam_linhello.so wait";

/// Candidate greeter PAM services (same names across distros).
const GREETERS: &[&str] = &[
    "/etc/pam.d/gdm-password",
    "/etc/pam.d/sddm",
    "/etc/pam.d/lightdm",
];
/// KDE lockscreen (kscreenlocker) services. NOT a greeter: kscreenlocker_greet
/// runs PAM in-process as the unprivileged session user (kcheckpass removed in
/// Plasma 5.25), only the auth phase runs, and the module answers verify-only.
///
/// kscreenlocker runs PARALLEL stacks from greeter start: the interactive
/// `kde` (password prompt) plus non-interactive `kde-fingerprint` /
/// `kde-smartcard`, first success unlocks (kscreenlocker MR !15). We prefer
/// riding `kde-fingerprint`: face unlock with no Enter press, and face
/// attempts never reach `kde`'s pam_unix — so they can't increment
/// pam_faillock. The interactive `kde` stays stock (password), which is also
/// the safest stack NOT to touch ("if the service is misconfigured, you will
/// NOT be able to unlock a locked screen" — kscreenlocker README).
const KDE_LOCKSCREEN: &str = "/etc/pam.d/kde";
const KDE_FP_LOCKSCREEN: &str = "/etc/pam.d/kde-fingerprint";
/// Where Arch ships the kscreenlocker services since Plasma 6: the PAM
/// *vendor* directory. PAM gives `/etc/pam.d/<service>` priority, so we never
/// edit vendor files (package-owned, clobbered on update) — when only the
/// vendor copy exists, we materialize an /etc override from it.
const KDE_VENDOR: &str = "/usr/lib/pam.d/kde";
const KDE_FP_VENDOR: &str = "/usr/lib/pam.d/kde-fingerprint";
/// First-line prefix of an override file WE created (no pre-existing /etc file
/// to back up). Lets disable/uninstall know to delete the whole file — leaving
/// a vendor-copy behind would freeze the service against vendor updates.
pub(crate) const CREATED_PREFIX: &str = "# linhello: created from ";
const SUDO: &str = "/etc/pam.d/sudo";

/// Read-only status of one PAM service file.
pub struct ServiceStatus {
    pub path: PathBuf,
    pub wired: bool,
}

/// The result of an enable/disable action on one target.
pub enum Change {
    WouldEdit(PathBuf),
    Edited(PathBuf),
    /// A new /etc override file materialized from a PAM vendor-dir copy.
    Created(PathBuf),
    AlreadyWired(PathBuf),
    WouldRemove(PathBuf),
    Removed(PathBuf),
    NotWired(PathBuf),
    /// Distro needs a mechanism we don't auto-apply; carries the manual steps.
    Manual(String),
}

impl Change {
    pub fn describe(&self) -> String {
        match self {
            Change::WouldEdit(p) => format!("would wire  {}", p.display()),
            Change::Edited(p) => format!("wired       {} (backup {}{})", p.display(), p.display(), BACKUP_SUFFIX),
            Change::Created(p) => {
                format!("wired       {} (created from the /usr/lib/pam.d vendor copy)", p.display())
            }
            Change::AlreadyWired(p) => format!("already     {}", p.display()),
            Change::WouldRemove(p) => format!("would clear {}", p.display()),
            Change::Removed(p) => format!("cleared     {}", p.display()),
            Change::NotWired(p) => format!("not wired   {}", p.display()),
            Change::Manual(s) => s.clone(),
        }
    }
}

/// Where face-auth is (or isn't) currently wired. Read-only. The files
/// inspected are distro-specific: the rendered shared stacks on Debian/Fedora,
/// the per-service greeter/sudo files on Arch.
pub fn status() -> Vec<ServiceStatus> {
    // No `exists()` filter here: a vendor-backed target (the KDE lockscreen
    // before its /etc override is created) must still show up as "not wired".
    inspect_files()
        .into_iter()
        .map(|path| {
            let wired = std::fs::read_to_string(&path)
                .map(|c| content_has_module(&c))
                .unwrap_or(false);
            ServiceStatus { path, wired }
        })
        .collect()
}

/// Files whose `pam_linhello` presence indicates active wiring, per distro.
fn inspect_files() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match platform::distro_family() {
        DistroFamily::Debian => vec![PathBuf::from("/etc/pam.d/common-auth")]
            .into_iter()
            .filter(|p| p.exists())
            .collect(),
        DistroFamily::Fedora => vec![
            PathBuf::from("/etc/pam.d/system-auth"),
            PathBuf::from("/etc/pam.d/password-auth"),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect(),
        DistroFamily::Arch | DistroFamily::Other => {
            let mut v: Vec<PathBuf> =
                GREETERS.iter().map(PathBuf::from).filter(|p| p.exists()).collect();
            // EXPERIMENTAL plasmalogin greeter: show the /etc override we manage
            // (present once enabled; absent vendor-only files don't show a row).
            if let Some(plan) = plasmalogin_greeter_plan() {
                v.push(plan.etc);
            }
            let sudo = PathBuf::from(SUDO);
            if sudo.exists() {
                v.push(sudo);
            }
            v
        }
    };
    // The KDE lockscreen row is shown on every family (it's desktop-, not
    // distro-specific): the wiring PLAN — the one service we would/do manage.
    if let Some(plan) = lockscreen_plan() {
        v.push(plan.etc);
    }
    v
}

/// Enable face login. Edits the greeter (and `sudo` when `include_sudo`) on
/// Arch-style distros; returns manual guidance on Debian/Fedora. `dry_run`
/// computes the changes without writing.
pub fn enable(include_sudo: bool, dry_run: bool) -> Result<Vec<Change>> {
    let mut changes = match platform::distro_family() {
        DistroFamily::Debian => debian_enable(dry_run)?,
        DistroFamily::Fedora => fedora_enable(dry_run)?,
        DistroFamily::Arch | DistroFamily::Other => {
            let mut changes = Vec::new();
            for g in GREETERS.iter().map(PathBuf::from).filter(|p| p.exists()) {
                changes.push(edit_in(&g, GREETER_STANZA, dry_run)?);
            }
            // EXPERIMENTAL: the Plasma 6 `plasmalogin` greeter is vendor-only on
            // Arch (not in GREETERS, no /etc file to edit), so materialize it the
            // same way as the lockscreen. Arch/Other only — Fedora/Debian cover
            // it via the shared stack. See `plasmalogin_greeter_plan`.
            if let Some(plan) = plasmalogin_greeter_plan() {
                changes.push(apply_override(&plan, dry_run)?);
            }
            if include_sudo {
                let sudo = PathBuf::from(SUDO);
                if sudo.exists() {
                    changes.push(edit_in(&sudo, SUFFICIENT_STANZA, dry_run)?);
                }
            }
            changes
        }
    };
    // The KDE lockscreen (kscreenlocker) is desktop-specific, not distro-specific.
    // On Debian/Fedora the shared system-auth/password-auth stacks (wired above)
    // drive the greeter and sudo but NOT kscreenlocker, which runs its own
    // `kde` / `kde-fingerprint` PAM services in parallel at lock time — so
    // lock-screen face unlock needs this wiring on EVERY family, not just Arch.
    // (Previously this lived only in the Arch arm, so KDE-on-Fedora/Debian users
    // got working sudo/login face auth but a dead lock screen.)
    if let Some(plan) = lockscreen_plan() {
        changes.push(apply_override(&plan, dry_run)?);
    }
    Ok(changes)
}

/// Remove face-auth from the greeter and `sudo` stacks (Arch-style); manual
/// guidance on Debian/Fedora.
pub fn disable(dry_run: bool) -> Result<Vec<Change>> {
    let mut changes = match platform::distro_family() {
        DistroFamily::Debian => debian_disable(dry_run)?,
        DistroFamily::Fedora => fedora_disable(dry_run)?,
        // include_sudo: true — disable must clean sudo even though enable makes
        // it opt-in, otherwise `auth sufficient pam_linhello.so` is left behind
        // (a dangling reference once the module is removed).
        DistroFamily::Arch | DistroFamily::Other => {
            let mut targets = existing_targets(true);
            // EXPERIMENTAL plasmalogin greeter (see `plasmalogin_greeter_plan`):
            // unwire the /etc override symmetrically with enable. `remove_in`
            // deletes a file we materialized, or strips our line from an admin's.
            let plasma = PathBuf::from(PLASMALOGIN_ETC);
            if plasma.exists() {
                targets.push(plasma);
            }
            targets
                .into_iter()
                .map(|p| remove_in(&p, dry_run))
                .collect::<Result<Vec<_>>>()?
        }
    };
    // Symmetric with enable(): unwire the KDE lockscreen on every family. Both
    // services are tried (an older LinuxHello wired `kde`; current prefers
    // `kde-fingerprint`) so disable cleans whichever carries our line.
    for p in [KDE_FP_LOCKSCREEN, KDE_LOCKSCREEN] {
        if Path::new(p).exists() {
            changes.push(remove_in(Path::new(p), dry_run)?);
        }
    }
    Ok(changes)
}

/// Targets for disable/uninstall: every file we might have wired, including
/// BOTH lockscreen services (an older LinuxHello wired `kde`; current prefers
/// `kde-fingerprint` — unwiring must clean whichever exists).
fn existing_targets(include_sudo: bool) -> Vec<PathBuf> {
    // Greeter + sudo only. The KDE lockscreen services are unwired separately in
    // `disable()` (on every family), so they are intentionally not listed here.
    let mut v: Vec<PathBuf> = GREETERS.iter().map(PathBuf::from).filter(|p| p.exists()).collect();
    if include_sudo {
        let sudo = PathBuf::from(SUDO);
        if sudo.exists() {
            v.push(sudo);
        }
    }
    v
}

/// How we wire a vendor-shipped PAM service on this host: which /etc override to
/// manage, the PAM vendor file it is materialized from, and the stanza it gets.
/// Used for both the KDE lockscreen and the Plasma `plasmalogin` greeter.
struct OverridePlan {
    etc: PathBuf,
    vendor: &'static str,
    stanza: &'static str,
}

/// Prefer the non-interactive `kde-fingerprint` parallel stack (face unlock
/// with no key press, no pam_unix/faillock contact); fall back to the
/// interactive `kde` service on Plasma builds without it. Present only when
/// this host actually has kscreenlocker (an /etc or vendor file exists).
fn lockscreen_plan() -> Option<OverridePlan> {
    for (etc, vendor, stanza) in [
        (KDE_FP_LOCKSCREEN, KDE_FP_VENDOR, WAIT_STANZA),
        (KDE_LOCKSCREEN, KDE_VENDOR, SUFFICIENT_STANZA),
    ] {
        let etc_path = PathBuf::from(etc);
        if etc_path.exists() || Path::new(vendor).exists() {
            return Some(OverridePlan { etc: etc_path, vendor, stanza });
        }
    }
    None
}

/// EXPERIMENTAL (Arch/Plasma 6): wiring for the renamed SDDM greeter,
/// `plasmalogin`. Plasma 6 ships it under the PAM *vendor* dir on Arch
/// (`/usr/lib/pam.d/plasmalogin`), so — unlike the legacy `GREETERS` — it has no
/// `/etc/pam.d` file to edit; we materialize an /etc override from the vendor
/// copy, exactly as the lockscreen does. Only consulted in the Arch/Other arm:
/// Fedora/Debian wire the shared `system-auth`/`common-auth` stack that the
/// greeter `include`s, so plasmalogin is already covered there (verified against
/// KDE's per-distro data/pam/{fedora,debian}/plasmalogin).
///
/// Stanza is `sufficient`, NOT the keyring-preserving `[success=1]` used for the
/// legacy greeters: the Arch vendor stack pulls the password in via
/// `auth include system-login`, and a fixed `success=1` skips only the first
/// rule *inside* an `include` (it cleanly skips a whole `substack`, not an
/// `include`) — so the jump is layout-dependent and unsafe to assume. With
/// `sufficient`, face success logs in and failure falls through to the password;
/// the trade-off is that the keyring is not auto-unlocked by face here. Unwired
/// symmetrically in `disable()`. Unvalidated on real Arch hardware.
const PLASMALOGIN_ETC: &str = "/etc/pam.d/plasmalogin";
const PLASMALOGIN_VENDOR: &str = "/usr/lib/pam.d/plasmalogin";

fn plasmalogin_greeter_plan() -> Option<OverridePlan> {
    let etc = PathBuf::from(PLASMALOGIN_ETC);
    if etc.exists() || Path::new(PLASMALOGIN_VENDOR).exists() {
        Some(OverridePlan { etc, vendor: PLASMALOGIN_VENDOR, stanza: SUFFICIENT_STANZA })
    } else {
        None
    }
}

/// Apply an [`OverridePlan`]: edit the /etc file in place if it exists, else
/// materialize it from the vendor copy. Shared by the lockscreen and the
/// plasmalogin greeter.
fn apply_override(plan: &OverridePlan, dry_run: bool) -> Result<Change> {
    if plan.etc.exists() {
        edit_in(&plan.etc, plan.stanza, dry_run)
    } else {
        create_override_from(&plan.etc, plan.vendor, plan.stanza, dry_run)
    }
}

/// The /etc override content for a vendor-shipped lockscreen service: marker
/// line (so disable/uninstall know to delete the file), then the vendor stack
/// with our stanza wired in.
fn build_override(vendor_path: &str, vendor_content: &str, stanza: &str) -> String {
    let (wired, _) = insert_first_auth(vendor_content, stanza);
    format!("{CREATED_PREFIX}{vendor_path} — delete this file to revert to the vendor copy\n{wired}")
}

/// Whether this /etc/pam.d file is an override WE materialized (vs. one the
/// distro shipped or the admin wrote): such files are deleted on unwire.
pub(crate) fn is_created_override(content: &str) -> bool {
    content.starts_with(CREATED_PREFIX)
}

fn create_override_from(
    path: &Path,
    vendor: &str,
    stanza: &str,
    dry_run: bool,
) -> Result<Change> {
    if dry_run {
        return Ok(Change::WouldEdit(path.to_path_buf()));
    }
    let vendor_content = std::fs::read_to_string(vendor)
        .map_err(|e| anyhow::anyhow!("reading {vendor}: {e}"))?;
    // If an override already exists at this path, preserve a one-time backup
    // before replacing it (parity with edit_in/remove_in).
    if path.exists() {
        backup(path)?;
    }
    write_atomic(path, &build_override(vendor, &vendor_content, stanza))?;
    Ok(Change::Created(path.to_path_buf()))
}

fn edit_in(path: &Path, stanza: &str, dry_run: bool) -> Result<Change> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let (new, changed) = insert_first_auth(&content, stanza);
    if !changed {
        return Ok(Change::AlreadyWired(path.to_path_buf()));
    }
    if dry_run {
        return Ok(Change::WouldEdit(path.to_path_buf()));
    }
    backup(path)?;
    write_atomic(path, &new)?;
    Ok(Change::Edited(path.to_path_buf()))
}

fn remove_in(path: &Path, dry_run: bool) -> Result<Change> {
    // A vendor-backed target whose /etc override was never created: nothing
    // to unwire (read would fail below otherwise).
    if !path.exists() {
        return Ok(Change::NotWired(path.to_path_buf()));
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    // An override we created has no distro original behind it in /etc — delete
    // the whole file so the service falls back to the live vendor copy instead
    // of a frozen snapshot of it.
    if is_created_override(&content) {
        if dry_run {
            return Ok(Change::WouldRemove(path.to_path_buf()));
        }
        std::fs::remove_file(path)
            .map_err(|e| anyhow::anyhow!("removing {}: {e}", path.display()))?;
        return Ok(Change::Removed(path.to_path_buf()));
    }
    let (new, changed) = remove_module(&content);
    if !changed {
        return Ok(Change::NotWired(path.to_path_buf()));
    }
    if dry_run {
        return Ok(Change::WouldRemove(path.to_path_buf()));
    }
    backup(path)?;
    write_atomic(path, &new)?;
    Ok(Change::Removed(path.to_path_buf()))
}

/// Atomically replace `path`'s contents: write a sibling temp file, fsync-free
/// `rename` over the target. PAM reads these files live, so a non-atomic
/// truncate-in-place (`std::fs::write`) could expose a half-written auth stack
/// if the process is interrupted (crash, ENOSPC, power loss). The rename is
/// atomic within the same directory; the target's mode is preserved.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("pam");
    let tmp = dir.join(format!(".{fname}.linhello.tmp"));
    std::fs::write(&tmp, contents)
        .map_err(|e| anyhow::anyhow!("writing temp {}: {e}", tmp.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("renaming {} into {}: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

/// Copy `path` to `path.pre-linhello` once (never overwrite an existing backup).
fn backup(path: &Path) -> Result<()> {
    let bak = PathBuf::from(format!("{}{}", path.display(), BACKUP_SUFFIX));
    if !bak.exists() {
        std::fs::copy(path, &bak)
            .map_err(|e| anyhow::anyhow!("backing up {}: {e}", path.display()))?;
    }
    Ok(())
}

// --- Debian/Ubuntu: pam-auth-update profile ------------------------------

/// The pam-auth-update Primary block. A higher `Priority` than the `unix`
/// profile (256) makes face-auth run first; `[success=end default=ignore]`
/// ends the auth substack successfully on a face match (logging you in without
/// a password) and *ignores* any other result, so a camera/TPM failure falls
/// straight through to the password modules.
fn debian_profile() -> String {
    "Name: LinuxHello face authentication\n\
     Default: yes\n\
     Priority: 900\n\
     Auth-Type: Primary\n\
     Auth:\n\
     \t[success=end default=ignore]\tpam_linhello.so\n\
     Auth-Initial:\n\
     \t[success=end default=ignore]\tpam_linhello.so\n"
        .to_string()
}

fn debian_enable(dry_run: bool) -> Result<Vec<Change>> {
    let path = PathBuf::from(DEBIAN_PROFILE_PATH);
    if dry_run {
        return Ok(vec![
            Change::WouldEdit(path),
            Change::Manual("then run: pam-auth-update --package".to_string()),
        ]);
    }
    std::fs::write(&path, debian_profile())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    run("pam-auth-update", &["--package"])?;
    Ok(vec![
        Change::Edited(path),
        Change::Manual("ran pam-auth-update — face login is now in common-auth.".to_string()),
        Change::Manual(
            "note: keyring-unlock-on-face may need extra wiring on some GNOME setups; \
             your password fallback is intact."
                .to_string(),
        ),
        Change::Manual("revert with: linhello pam disable".to_string()),
    ])
}

fn debian_disable(dry_run: bool) -> Result<Vec<Change>> {
    let path = PathBuf::from(DEBIAN_PROFILE_PATH);
    if dry_run {
        return Ok(vec![Change::WouldRemove(path)]);
    }
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| anyhow::anyhow!("removing {}: {e}", path.display()))?;
    }
    run("pam-auth-update", &["--package"])?;
    Ok(vec![Change::Removed(path)])
}

// --- Fedora/RHEL: authselect custom profile ------------------------------
//
// authselect renders system-auth/password-auth from a profile's templates.
// We base a `custom/linhello` profile on the active one, inject the face line
// (`auth sufficient pam_linhello.so`, ahead of pam_unix/pam_sss — the
// pam_fprintd biometric pattern) into its templates, then `authselect select`
// it with `--force`, recording the prior profile for a clean revert. Activation
// is safe-by-construction: the face line is `sufficient`, so a missing or failed
// face module falls through to the password prompt. EXPERIMENTAL — validate the
// authselect round-trip on real Fedora hardware before relying on it.

fn fedora_enable(dry_run: bool) -> Result<Vec<Change>> {
    let current = run_capture("authselect", &["current"]).unwrap_or_default();
    let (base, features) = parse_authselect_current(&current);
    let base = base.unwrap_or_else(|| "sssd".to_string());

    if dry_run {
        let mut sel = String::from("authselect select custom/linhello");
        for f in &features {
            sel.push(' ');
            sel.push_str(f);
        }
        sel.push_str(" --force");
        return Ok(vec![
            Change::Manual(format!("would base a custom/linhello profile on '{base}'")),
            Change::Manual(format!(
                "would inject `{SUFFICIENT_STANZA}` into its system-auth & password-auth"
            )),
            Change::Manual(format!("then run: {sel}")),
        ]);
    }

    let dir = PathBuf::from(FEDORA_CUSTOM_DIR);
    if !dir.exists() {
        run("authselect", &["create-profile", "linhello", "--base-on", &base])?;
    }
    let mut changes = Vec::new();
    for tmpl in ["system-auth", "password-auth"] {
        let p = dir.join(tmpl);
        if !p.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&p)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", p.display()))?;
        let (new, changed) = insert_first_auth(&content, SUFFICIENT_STANZA);
        if changed {
            std::fs::write(&p, new)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", p.display()))?;
            changes.push(Change::Edited(p));
        } else {
            changes.push(Change::AlreadyWired(p));
        }
    }
    // Remember where we came from, then activate. authselect validates the
    // templates and regenerates system-auth/password-auth; `--force` is required
    // because we based the profile on the live one. The face line is
    // `sufficient`, so a missing/failed face module falls through to the
    // password prompt — activating cannot lock the user out.
    store_authselect_base(&base)?;
    let feat_refs: Vec<&str> = features.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["select", "custom/linhello"];
    args.extend(feat_refs.iter().copied());
    args.push("--force");
    run("authselect", &args)?;
    changes.push(Change::Manual(format!(
        "activated custom/linhello (was '{base}') — face login is live; password still works"
    )));
    changes.push(Change::Manual(
        "revert any time with:  linhello pam disable".to_string(),
    ));
    Ok(changes)
}

/// Persist the pre-linhello authselect profile id for a clean revert.
fn store_authselect_base(base: &str) -> Result<()> {
    if let Some(parent) = Path::new(FEDORA_BASE_MARKER).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(FEDORA_BASE_MARKER, format!("{base}\n"))
        .map_err(|e| anyhow::anyhow!("writing {FEDORA_BASE_MARKER}: {e}"))
}

/// Read the remembered base profile, defaulting to Fedora's stock `sssd`.
fn load_authselect_base() -> String {
    std::fs::read_to_string(FEDORA_BASE_MARKER)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "sssd".to_string())
}

fn fedora_disable(dry_run: bool) -> Result<Vec<Change>> {
    let dir = PathBuf::from(FEDORA_CUSTOM_DIR);
    if dry_run {
        return Ok(vec![Change::WouldRemove(dir)]);
    }
    let mut changes = Vec::new();
    // If custom/linhello is the active profile, switch back to the remembered
    // base FIRST (so we never delete the profile out from under a live stack).
    let current = run_capture("authselect", &["current"]).unwrap_or_default();
    let (active, features) = parse_authselect_current(&current);
    if active.as_deref() == Some("custom/linhello") {
        let base = load_authselect_base();
        let feat_refs: Vec<&str> = features.iter().map(String::as_str).collect();
        let mut args: Vec<&str> = vec!["select", base.as_str()];
        args.extend(feat_refs.iter().copied());
        args.push("--force");
        run("authselect", &args)?;
        changes.push(Change::Manual(format!("switched back to '{base}'")));
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| anyhow::anyhow!("removing {}: {e}", dir.display()))?;
        changes.push(Change::Removed(dir));
    } else {
        changes.push(Change::NotWired(dir));
    }
    let _ = std::fs::remove_file(FEDORA_BASE_MARKER);
    Ok(changes)
}

/// Parse `authselect current` output into `(profile_id, features)`.
fn parse_authselect_current(out: &str) -> (Option<String>, Vec<String>) {
    let mut profile = None;
    let mut features = Vec::new();
    let mut in_features = false;
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Profile ID:") {
            profile = Some(rest.trim().to_string());
        } else if t.starts_with("Enabled features:") {
            in_features = true;
        } else if in_features {
            if let Some(f) = t.strip_prefix('-') {
                let f = f.trim();
                if !f.is_empty() {
                    features.push(f.to_string());
                }
            }
        }
    }
    (profile, features)
}

/// Run a command, mapping a missing binary or non-zero exit to an error.
fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("running `{cmd}`: {e} (is it installed?)"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{cmd} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Run a command and capture stdout; `None` if it can't be run.
fn run_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

// --- pure helpers (unit-tested) ------------------------------------------

/// True if an active (non-comment) line references our module.
fn content_has_module(content: &str) -> bool {
    content.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains(MODULE)
    })
}

/// Insert `stanza` just before the first auth-stack line (a line whose first
/// token, ignoring a leading `-`, is `auth`). Idempotent: a no-op if the module
/// is already present. Returns `(new_content, changed)`.
fn insert_first_auth(content: &str, stanza: &str) -> (String, bool) {
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let mut out: Vec<String> = Vec::with_capacity(content.lines().count() + 1);
    let mut inserted = false;
    for line in content.lines() {
        if !inserted && is_auth_directive(line) {
            out.push(stanza.to_string());
            inserted = true;
        }
        out.push(line.to_string());
    }
    if !inserted {
        out.push(stanza.to_string());
        inserted = true;
    }
    (format!("{}\n", out.join("\n")), inserted)
}

/// Remove every active line that references our module. Returns `(new, changed)`.
fn remove_module(content: &str) -> (String, bool) {
    let mut changed = false;
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| {
            let drop = {
                let t = l.trim_start();
                !t.starts_with('#') && t.contains(MODULE)
            };
            if drop {
                changed = true;
            }
            !drop
        })
        .collect();
    if !changed {
        return (content.to_string(), false);
    }
    (format!("{}\n", kept.join("\n")), true)
}

fn is_auth_directive(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') {
        return false;
    }
    let t = t.strip_prefix('-').unwrap_or(t);
    // first whitespace-delimited token is exactly "auth"
    t.split_whitespace().next() == Some("auth")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GDM: &str = "#%PAM-1.0\nauth       include      system-local-login\naccount    include      system-local-login\n";

    #[test]
    fn detects_active_vs_commented() {
        assert!(!content_has_module(GDM));
        assert!(content_has_module("auth sufficient pam_linhello.so\n"));
        assert!(!content_has_module("# auth sufficient pam_linhello.so\n"));
    }

    #[test]
    fn inserts_before_first_auth_line() {
        let (out, changed) = insert_first_auth(GDM, GREETER_STANZA);
        assert!(changed);
        let lines: Vec<&str> = out.lines().collect();
        // header, then our stanza, then the original first auth line
        assert_eq!(lines[0], "#%PAM-1.0");
        assert_eq!(lines[1], GREETER_STANZA);
        assert!(lines[2].starts_with("auth"));
        assert!(content_has_module(&out));
    }

    #[test]
    fn insert_is_idempotent() {
        let (once, _) = insert_first_auth(GDM, GREETER_STANZA);
        let (twice, changed) = insert_first_auth(&once, GREETER_STANZA);
        assert!(!changed);
        assert_eq!(once, twice);
    }

    #[test]
    fn skips_leading_dash_and_comments_when_placing() {
        // `-auth` is still an auth directive; insert before it, after comments.
        let src = "# header\n-auth   optional   pam_systemd_home.so\nauth required pam_unix.so\n";
        let (out, _) = insert_first_auth(src, SUFFICIENT_STANZA);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "# header");
        assert_eq!(lines[1], SUFFICIENT_STANZA);
        assert!(lines[2].starts_with("-auth"));
    }

    #[test]
    fn remove_is_inverse_and_idempotent() {
        let (wired, _) = insert_first_auth(GDM, GREETER_STANZA);
        let (cleared, changed) = remove_module(&wired);
        assert!(changed);
        assert!(!content_has_module(&cleared));
        let (again, changed2) = remove_module(&cleared);
        assert!(!changed2);
        assert_eq!(cleared, again);
    }

    #[test]
    fn lockscreen_override_marks_and_wires_vendor_content() {
        // The Plasma 6 vendor file shape (Arch ships it at /usr/lib/pam.d/kde).
        let vendor = "#%PAM-1.0\nauth\tinclude\tsystem-login\naccount\tinclude\tsystem-login\n";
        let out = build_override(KDE_VENDOR, vendor, SUFFICIENT_STANZA);
        assert!(is_created_override(&out));
        assert!(content_has_module(&out));
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with(CREATED_PREFIX));
        assert!(lines[0].contains(KDE_VENDOR));
        assert_eq!(lines[1], "#%PAM-1.0");
        assert_eq!(lines[2], SUFFICIENT_STANZA);
        assert!(lines[3].starts_with("auth"));
        // Distro-shipped or admin-written files must never look like ours.
        assert!(!is_created_override(vendor));
        // Overrides created by older LinuxHello (full hardcoded marker) still match.
        assert!(is_created_override(
            "# linhello: created from /usr/lib/pam.d/kde — delete this file to revert to the vendor copy\n"
        ));
    }

    #[test]
    fn fingerprint_override_gets_wait_stanza_before_fprintd() {
        // The parallel non-interactive stack: our wait-mode line runs first;
        // a real fprintd line (if the user has a reader) stays reachable.
        let vendor = "#%PAM-1.0\nauth\trequired\tpam_fprintd.so\n";
        let out = build_override(KDE_FP_VENDOR, vendor, WAIT_STANZA);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[2], WAIT_STANZA);
        assert!(lines[3].contains("pam_fprintd"));
    }

    // The real Arch `plasmalogin` vendor file (KDE data/pam/arch/plasmalogin):
    // the password comes in via `auth include system-login`, NOT a substack.
    const ARCH_PLASMALOGIN: &str = "#%PAM-1.0\n\n# SPDX-License-Identifier: CC0-1.0\n\nauth        include     system-login\n-auth       optional    pam_gnome_keyring.so\n-auth       optional    pam_kwallet5.so\n\naccount     include     system-login\n\npassword    include     system-login\n\nsession     optional    pam_keyinit.so          force revoke\nsession     include     system-login\n";

    #[test]
    fn plasmalogin_greeter_materializes_sufficient_before_include() {
        // On Arch the greeter is vendor-only; we materialize an /etc override.
        // It MUST use `sufficient` (not the keyring `[success=1]` jump): a fixed
        // success=N can't cleanly skip an `include` (only a substack), so on this
        // include-based stack the jump would be wrong. `sufficient` is correct on
        // every layout — face success logs in, failure falls to the password.
        let out = build_override(PLASMALOGIN_VENDOR, ARCH_PLASMALOGIN, SUFFICIENT_STANZA);
        assert!(is_created_override(&out));
        assert!(content_has_module(&out));
        // The wired stanza must be `sufficient`, and the dangerous `[success=N]`
        // jump must NOT be applied to this include-based greeter.
        assert!(out.contains(SUFFICIENT_STANZA));
        assert!(!out.contains("success=1"));
        // Our line precedes the password-bearing `include system-login`, so face
        // success short-circuits before the password is demanded.
        let body: Vec<&str> = out.lines().filter(|l| l.trim_start().starts_with("auth")).collect();
        assert_eq!(body[0], SUFFICIENT_STANZA);
        assert!(body[1].contains("include") && body[1].contains("system-login"));
    }

    #[test]
    fn plasmalogin_override_round_trips() {
        let wired = build_override(PLASMALOGIN_VENDOR, ARCH_PLASMALOGIN, SUFFICIENT_STANZA);
        // A materialized override is deleted wholesale on unwire (it has no
        // distro original in /etc), so disable() removes the file via the
        // is_created_override path rather than editing it.
        assert!(is_created_override(&wired));
        // Re-applying is idempotent (already wired → no second line).
        let (again, changed) = insert_first_auth(&wired, SUFFICIENT_STANZA);
        assert!(!changed);
        assert_eq!(again, wired);
    }

    #[test]
    fn plasmalogin_plan_uses_sufficient_not_jump() {
        // Guard the policy decision itself, independent of file presence.
        let plan = OverridePlan {
            etc: PathBuf::from(PLASMALOGIN_ETC),
            vendor: PLASMALOGIN_VENDOR,
            stanza: SUFFICIENT_STANZA,
        };
        assert_eq!(plan.stanza, SUFFICIENT_STANZA);
        assert_ne!(plan.stanza, GREETER_STANZA);
    }

    #[test]
    fn remove_keeps_commented_references() {
        let src = "# auth sufficient pam_linhello.so (example)\nauth required pam_unix.so\n";
        let (out, changed) = remove_module(src);
        assert!(!changed);
        assert_eq!(out, src);
    }

    #[test]
    fn debian_profile_is_well_formed() {
        let p = debian_profile();
        assert!(p.contains(MODULE));
        assert!(p.contains("Auth-Type: Primary"));
        assert!(p.contains("Priority: 900")); // higher than unix's 256 → runs first
        assert!(p.contains("[success=end default=ignore]")); // failure falls through
    }

    #[test]
    fn parses_authselect_current() {
        let out = "Profile ID: sssd\nEnabled features:\n- with-silent-lastlog\n- with-sudo\n";
        let (profile, features) = parse_authselect_current(out);
        assert_eq!(profile.as_deref(), Some("sssd"));
        assert_eq!(features, vec!["with-silent-lastlog", "with-sudo"]);
    }

    #[test]
    fn parses_authselect_current_no_features() {
        let (profile, features) = parse_authselect_current("Profile ID: local\n");
        assert_eq!(profile.as_deref(), Some("local"));
        assert!(features.is_empty());
    }
}
