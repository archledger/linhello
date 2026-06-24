//! "Is a newer LinuxHello release available?" — a lightweight, cached check.
//!
//! Source of truth per platform (the chosen hybrid policy):
//!   * Fedora — `dnf repoquery` against the enabled repos, since the Copr build
//!     is what `dnf upgrade` would actually install; falls back to the git tags
//!     if dnf can't answer (repo not enabled, stale metadata, etc.).
//!   * everything else — `git ls-remote --tags` on the GitHub repo: the newest
//!     signed `v*` tag, the same tags the source-install/update flow verifies.
//!
//! No HTTP-client dependency: we shell out to `git`/`dnf`, matching the rest of
//! the project. The result is cached for ~24h so the TUI's launch check costs at
//! most one network round-trip per day.

use linhello_common::platform::{distro_family, DistroFamily};
use std::cmp::Ordering;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Public GitHub repo whose signed `v*` tags are the release source of truth.
const REPO_URL: &str = "https://github.com/archledger/linhello";
/// Where the throttled check result lives (root-writable; best-effort).
const CACHE_PATH: &str = "/var/cache/linhello/update-check";
/// How long a cached result is trusted before a fresh check is made.
const CACHE_TTL: u64 = 24 * 60 * 60;

/// The version baked into this binary (no leading `v`), e.g. `0.5.1`.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The command that actually installs the update for *this* install — chosen by
/// how LinuxHello got here, not just the distro:
///   * a Copr/dnf (rpm-owned) install upgrades with `dnf`; `linhello update`
///     would build from source over a package-managed file.
///   * everything else (a source install on any distro, including Debian/Ubuntu/
///     Arch which have no auto-updating repo) uses the signed-tag source updater.
pub fn update_hint() -> &'static str {
    if distro_family() == DistroFamily::Fedora && rpm_installed() {
        "sudo dnf upgrade linhello"
    } else {
        "sudo linhello update"
    }
}

/// True when `linhello` is installed as an rpm package — i.e. it came from Copr
/// and is managed by dnf, so `dnf upgrade` is the right update path. (A source
/// install on Fedora has no rpm and uses the signed-tag updater instead.)
fn rpm_installed() -> bool {
    Command::new("rpm")
        .args(["-q", "linhello"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Result of an update check. `latest` is `None` when it couldn't be determined
/// (offline, no git/dnf, repo unreachable) — never treat that as "up to date".
pub struct UpdateStatus {
    pub current: String,
    pub latest: Option<String>,
}

impl UpdateStatus {
    /// True only when we positively know a newer version exists.
    pub fn newer_available(&self) -> bool {
        match &self.latest {
            Some(l) => cmp_version(l, &self.current) == Ordering::Greater,
            None => false,
        }
    }
}

/// Cached check for interactive use: returns a fresh-enough cached result when
/// one exists, otherwise performs a live check and refreshes the cache. Cheap to
/// call and safe to run on a background thread.
pub fn cached_status() -> UpdateStatus {
    if let Some(latest) = read_cache() {
        return UpdateStatus {
            current: current_version().to_string(),
            latest: Some(latest),
        };
    }
    live_status()
}

/// Live check that ignores the cache and refreshes it on success.
pub fn live_status() -> UpdateStatus {
    let latest = fetch_latest();
    if let Some(v) = &latest {
        write_cache(v);
    }
    UpdateStatus {
        current: current_version().to_string(),
        latest,
    }
}

/// Newest available version (no leading `v`), or `None` if undeterminable.
fn fetch_latest() -> Option<String> {
    // On Fedora consult BOTH the Copr cache and the released git tags and take
    // the newest: dnf's local metadata is frequently stale (it can name a build
    // older than what's already installed), so trusting it alone would let us
    // report a *downgrade* as the "latest". Elsewhere, the git tags are the only
    // source. Empty/failed sources just drop out of the max.
    let raw: Vec<String> = match distro_family() {
        DistroFamily::Fedora => [latest_dnf(), latest_git()].into_iter().flatten().collect(),
        _ => latest_git().into_iter().collect(),
    };
    raw.into_iter()
        .map(|v| strip_v(&v))
        .max_by(|a, b| cmp_version(a, b))
}

/// Newest `v*` tag on the remote, via a single `git ls-remote` (no clone).
fn latest_git() -> Option<String> {
    let out = Command::new("git")
        .args(["ls-remote", "--tags", "--refs", REPO_URL, "v*"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        // each line is "<sha>\trefs/tags/v0.5.1" — keep the last path segment.
        .filter_map(|l| l.rsplit('/').next())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .max_by(|a, b| cmp_version(a, b))
}

/// Newest `linhello` version in the enabled dnf repos' *cached* metadata, if any.
///
/// Runs cache-only (`-C`) with stdin closed so it never refreshes metadata and
/// therefore never blocks on an interactive GPG-key-import prompt — essential
/// for a background check. Staleness is corrected by [`fetch_latest`] taking the
/// max with the git tags.
fn latest_dnf() -> Option<String> {
    let out = Command::new("dnf")
        .args([
            "-q",
            "-C",
            "repoquery",
            "--available",
            "--latest-limit=1",
            "--qf=%{version}",
            "linhello",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        // Guard against any stray non-version chatter on stdout: a real version
        // starts with a digit.
        .find(|l| l.bytes().next().is_some_and(|b| b.is_ascii_digit()))
        .unwrap_or_default()
        .to_string();
    (!v.is_empty()).then_some(v)
}

fn strip_v(s: &str) -> String {
    s.trim().trim_start_matches(['v', 'V']).to_string()
}

/// Cached `latest` if the cache file exists, is non-empty, and is younger than
/// [`CACHE_TTL`]. A failed prior check is never cached, so it retries.
fn read_cache() -> Option<String> {
    let text = std::fs::read_to_string(CACHE_PATH).ok()?;
    let mut lines = text.lines();
    let ts: u64 = lines.next()?.trim().parse().ok()?;
    let latest = lines.next()?.trim().to_string();
    if latest.is_empty() || now().saturating_sub(ts) > CACHE_TTL {
        return None;
    }
    Some(latest)
}

fn write_cache(latest: &str) {
    if let Some(dir) = std::path::Path::new(CACHE_PATH).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(CACHE_PATH, format!("{}\n{}\n", now(), latest));
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Dotted-numeric version parse, tolerant of a `v` prefix and a release suffix
/// (`0.5.1-1.fc44`, `v0.5.1`, `0.5.1~rc1` → `[0, 5, 1]`). Non-numeric parts read
/// as 0 rather than failing the whole comparison.
fn parse_version(s: &str) -> Vec<u64> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+', '~', '_', ' ']).next().unwrap_or(s);
    core.split('.')
        .map(|p| p.trim().parse::<u64>().unwrap_or(0))
        .collect()
}

/// Compare two versions component-wise, treating missing trailing components as
/// 0 (so `0.5` == `0.5.0` and `0.5.1` > `0.5`).
fn cmp_version(a: &str, b: &str) -> Ordering {
    let (va, vb) = (parse_version(a), parse_version(b));
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert_eq!(cmp_version("0.5.1", "0.5.0"), Ordering::Greater);
        assert_eq!(cmp_version("v0.6.0", "0.5.9"), Ordering::Greater);
        assert_eq!(cmp_version("0.5.0", "0.5"), Ordering::Equal);
        assert_eq!(cmp_version("0.5.1-1.fc44", "0.5.1"), Ordering::Equal);
        assert_eq!(cmp_version("0.10.0", "0.9.0"), Ordering::Greater);
        assert_eq!(cmp_version("0.5.0", "0.5.1"), Ordering::Less);
    }

    #[test]
    fn newer_available_only_when_known() {
        let unknown = UpdateStatus {
            current: "0.5.0".into(),
            latest: None,
        };
        assert!(!unknown.newer_available());
        let newer = UpdateStatus {
            current: "0.5.0".into(),
            latest: Some("0.5.1".into()),
        };
        assert!(newer.newer_available());
        let same = UpdateStatus {
            current: "0.5.1".into(),
            latest: Some("0.5.1".into()),
        };
        assert!(!same.newer_available());
    }
}
