//! Fingerprint modality, backed by **fprintd** (the standard Linux fingerprint
//! service). linhello does not talk to the sensor directly — it drives fprintd,
//! which owns libfprint and the device.
//!
//! We deliberately avoid pulling in an async D-Bus stack (the rest of linhello
//! is dependency-light and the daemon runs sync `spawn_blocking` handlers).
//! Instead we use fprintd's shipped tooling with **absolute paths** (so PATH
//! can't be hijacked for the security-critical verify):
//!   * `busctl tree net.reactivated.Fprint` — is a reader present?
//!   * `busctl get-property … Device/0 name` — friendly device name
//!   * `fprintd-list <user>` — which fingers are enrolled
//!   * `fprintd-verify <user>` — run one verification
//!
//! This lets linhello detect, recommend, and (via PAM wiring) enable fingerprint
//! as a standalone **secure-tier** method. Verification itself is performed by
//! `pam_fprintd` in the PAM stack — linhello never claims the device, so it
//! coexists cleanly with the desktop greeter's native fingerprint prompt.

use std::path::PathBuf;
use std::process::Command;

const FPRINT_BUS: &str = "net.reactivated.Fprint";
const DEVICE0: &str = "/net/reactivated/Fprint/Device/0";

/// Resolve a tool to an absolute path under the standard system dirs. Returns
/// `None` if not installed. Absolute paths only — never trust `$PATH` for an
/// auth-critical helper.
fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .iter()
        .map(|d| PathBuf::from(d).join(name))
        .find(|p| p.exists())
}

fn busctl() -> Option<PathBuf> {
    tool("busctl")
}

/// True when fprintd's user tooling is installed (so we can enroll/verify).
pub fn fprintd_present() -> bool {
    tool("fprintd-verify").is_some() && tool("fprintd-list").is_some()
}

/// True when a fingerprint reader is registered with fprintd right now.
pub fn reader_present() -> bool {
    let Some(busctl) = busctl() else {
        return false;
    };
    let out = Command::new(busctl)
        .args(["--system", "tree", FPRINT_BUS])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).contains("/net/reactivated/Fprint/Device/")
        }
        _ => false,
    }
}

/// Friendly device name (e.g. "Synaptics Sensors"), if a reader is present.
pub fn device_name() -> Option<String> {
    let busctl = busctl()?;
    let out = Command::new(busctl)
        .args([
            "--system",
            "get-property",
            FPRINT_BUS,
            DEVICE0,
            "net.reactivated.Fprint.Device",
            "name",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Output looks like: `s "Synaptics Sensors"`
    let s = String::from_utf8_lossy(&out.stdout);
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

/// Whether the reader is usable for auth at all: tooling installed AND a reader
/// is present. (Enrollment is checked per-user via [`has_enrollment`].)
pub fn available() -> bool {
    fprintd_present() && reader_present()
}

/// List the fingers `user` has enrolled with fprintd. Empty when none (or when
/// fprintd is unavailable).
pub fn enrolled_fingers(user: &str) -> Vec<String> {
    let Some(list) = tool("fprintd-list") else {
        return Vec::new();
    };
    let Ok(out) = Command::new(list).arg(user).output() else {
        return Vec::new();
    };
    parse_enrolled_lines(&String::from_utf8_lossy(&out.stdout))
}

/// Parse the enrolled-finger names out of `fprintd-list` output, which prints
/// one ` - #N: <finger-name>` line per enrolled finger. Split out for testing.
fn parse_enrolled_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix('-')
                .map(str::trim)
                .filter(|r| r.starts_with('#'))
                .and_then(|r| r.split(':').nth(1))
                .map(|name| name.trim().to_string())
        })
        .collect()
}

/// True when `user` has at least one enrolled finger.
pub fn has_enrollment(user: &str) -> bool {
    !enrolled_fingers(user).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_line_parser() {
        // The real `fprintd-list` enrolled-finger line shape.
        let sample = "Fingerprints for user x on Synaptics (press):\n - #0: right-index-finger\n - #1: left-index-finger\n";
        assert_eq!(
            parse_enrolled_lines(sample),
            vec!["right-index-finger", "left-index-finger"]
        );
        assert!(parse_enrolled_lines("User x has no fingers enrolled for Synaptics.").is_empty());
    }
}
