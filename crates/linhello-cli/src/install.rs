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

/// Face models required for recognition (detector + embedder). Anti-spoof is
/// optional, so it isn't listed here.
const REQUIRED_MODELS: [&str; 2] = ["det_10g.onnx", "face.onnx"];

/// A read-only snapshot of how far LinuxHello is deployed on this machine.
pub struct InstallState {
    pub cli_bin: Option<PathBuf>,
    pub daemon_bin: Option<PathBuf>,
    pub daemon_active: bool,
    pub daemon_enabled: bool,
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
        let (models_present, missing_models) = model_state();
        let pam = crate::pamwire::status();
        InstallState {
            cli_bin,
            daemon_bin,
            daemon_active,
            daemon_enabled,
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
            if self.models_present {
                "models       present".to_string()
            } else {
                format!("models       MISSING: {}", self.missing_models.join(", "))
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

fn model_state() -> (bool, Vec<&'static str>) {
    let missing: Vec<&'static str> = REQUIRED_MODELS
        .iter()
        .copied()
        .filter(|m| !Path::new(CONFIG_ROOT).join(m).exists())
        .collect();
    (missing.is_empty(), missing)
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
