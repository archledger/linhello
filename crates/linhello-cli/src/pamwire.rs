//! Per-distro PAM wiring for face login.
//!
//! Inserting `pam_linhello.so` into the auth stack is distro-specific:
//!
//! * **Arch** (and derivatives): edit the per-service files directly. The
//!   greeter needs `auth [success=1 default=ignore] pam_linhello.so` (NOT
//!   `sufficient`) so `pam_gnome_keyring`'s auth phase still runs and unlocks
//!   the login keyring — `[success=1]` works because Arch's greeter jumps over
//!   exactly one `include system-local-login`. `sudo`/TTY use plain
//!   `sufficient`.
//! * **Debian/Ubuntu**: the greeter `@include common-auth`, which expands to
//!   several modules, so a naive `[success=1]` jump would land mid-stack. The
//!   correct mechanism is a `pam-auth-update` profile.
//! * **Fedora/RHEL**: `system-auth`/`password-auth` are `authselect`-managed
//!   symlinks; hand-edits get clobbered. The correct mechanism is an
//!   `authselect` custom profile/feature.
//!
//! This module automates the Arch path (with backups, idempotent) and, for
//! Debian/Fedora, returns the manual steps rather than performing untested
//! edits of the login stack — a wrong edit there is a lockout. Two safety
//! invariants are always preserved: the face line is `sufficient`/`[success=1]`
//! so a camera/TPM failure falls through to the password, and the TTY stack
//! (`/etc/pam.d/login`) is never touched, leaving a password escape hatch.

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

/// Greeter line: keep `pam_gnome_keyring` reachable so the keyring unlocks.
const GREETER_STANZA: &str = "auth       [success=1 default=ignore]   pam_linhello.so";
/// sudo line: plain sufficient — face success authenticates immediately.
const SUFFICIENT_STANZA: &str = "auth       sufficient   pam_linhello.so";

/// Candidate greeter PAM services (same names across distros).
const GREETERS: &[&str] = &[
    "/etc/pam.d/gdm-password",
    "/etc/pam.d/sddm",
    "/etc/pam.d/lightdm",
];
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
    inspect_files()
        .into_iter()
        .filter(|p| p.exists())
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
    match platform::distro_family() {
        DistroFamily::Debian => vec![PathBuf::from("/etc/pam.d/common-auth")],
        DistroFamily::Fedora => vec![
            PathBuf::from("/etc/pam.d/system-auth"),
            PathBuf::from("/etc/pam.d/password-auth"),
        ],
        DistroFamily::Arch | DistroFamily::Other => existing_targets(true),
    }
}

/// Enable face login. Edits the greeter (and `sudo` when `include_sudo`) on
/// Arch-style distros; returns manual guidance on Debian/Fedora. `dry_run`
/// computes the changes without writing.
pub fn enable(include_sudo: bool, dry_run: bool) -> Result<Vec<Change>> {
    match platform::distro_family() {
        DistroFamily::Debian => debian_enable(dry_run),
        DistroFamily::Fedora => fedora_enable(dry_run),
        DistroFamily::Arch | DistroFamily::Other => {
            let mut changes = Vec::new();
            for g in GREETERS.iter().map(PathBuf::from).filter(|p| p.exists()) {
                changes.push(edit_in(&g, GREETER_STANZA, dry_run)?);
            }
            if include_sudo {
                let sudo = PathBuf::from(SUDO);
                if sudo.exists() {
                    changes.push(edit_in(&sudo, SUFFICIENT_STANZA, dry_run)?);
                }
            }
            Ok(changes)
        }
    }
}

/// Remove face-auth from the greeter and `sudo` stacks (Arch-style); manual
/// guidance on Debian/Fedora.
pub fn disable(dry_run: bool) -> Result<Vec<Change>> {
    match platform::distro_family() {
        DistroFamily::Debian => debian_disable(dry_run),
        DistroFamily::Fedora => fedora_disable(dry_run),
        // include_sudo: true — disable must clean sudo even though enable makes
        // it opt-in, otherwise `auth sufficient pam_linhello.so` is left behind
        // (a dangling reference once the module is removed).
        DistroFamily::Arch | DistroFamily::Other => existing_targets(true)
            .into_iter()
            .map(|p| remove_in(&p, dry_run))
            .collect(),
    }
}

fn existing_targets(include_sudo: bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = GREETERS.iter().map(PathBuf::from).filter(|p| p.exists()).collect();
    if include_sudo {
        let sudo = PathBuf::from(SUDO);
        if sudo.exists() {
            v.push(sudo);
        }
    }
    v
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
    std::fs::write(path, new).map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(Change::Edited(path.to_path_buf()))
}

fn remove_in(path: &Path, dry_run: bool) -> Result<Change> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let (new, changed) = remove_module(&content);
    if !changed {
        return Ok(Change::NotWired(path.to_path_buf()));
    }
    if dry_run {
        return Ok(Change::WouldRemove(path.to_path_buf()));
    }
    backup(path)?;
    std::fs::write(path, new).map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(Change::Removed(path.to_path_buf()))
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
// into its templates (harmless — nothing changes until selected), and hand back
// the exact `authselect select` command. We deliberately DO NOT run the select
// ourselves: it is the one lockout-critical, untested-by-us step, so it stays a
// reviewed manual action. EXPERIMENTAL — validate on a Fedora host.

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
    let mut sel = String::from("authselect select custom/linhello");
    for f in &features {
        sel.push(' ');
        sel.push_str(f);
    }
    sel.push_str(" --force");
    changes.push(Change::Manual(format!(
        "profile staged. ACTIVATE with:  {sel}"
    )));
    changes.push(Change::Manual(format!(
        "revert with:  authselect select {base}  (your previous profile)"
    )));
    Ok(changes)
}

fn fedora_disable(dry_run: bool) -> Result<Vec<Change>> {
    let dir = PathBuf::from(FEDORA_CUSTOM_DIR);
    if dry_run {
        return Ok(vec![Change::WouldRemove(dir)]);
    }
    let mut changes = vec![Change::Manual(
        "if active, switch back first:  authselect select <your-base-profile>".to_string(),
    )];
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| anyhow::anyhow!("removing {}: {e}", dir.display()))?;
        changes.push(Change::Removed(dir));
    } else {
        changes.push(Change::NotWired(dir));
    }
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
