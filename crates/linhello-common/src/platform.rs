//! Distro/platform detection and resolution of the handful of filesystem
//! locations that actually vary across Linux distributions.
//!
//! Almost everything in LinuxHello uses fixed paths that are uniform across
//! distros (`/etc/linhello`, `/run/linhello.sock`, `/dev/tpmrm0`, the systemd
//! PCR-signature search dirs). Only the items resolved here genuinely differ:
//! where `libonnxruntime.so` lives, where PAM modules are installed, and which
//! initramfs/UKI builder rebuilds the boot image. Prefer probing the
//! filesystem (so derivatives and odd layouts work) and fall back to a
//! family-based default.

use std::path::{Path, PathBuf};

/// Coarse distro family, derived from `/etc/os-release`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroFamily {
    /// Arch and derivatives (Manjaro, EndeavourOS, CachyOS, …).
    Arch,
    /// Debian, Ubuntu, and derivatives (Mint, Pop!_OS, …).
    Debian,
    /// Fedora, RHEL, CentOS Stream, Rocky, Alma, …
    Fedora,
    /// Unrecognised.
    Other,
}

impl DistroFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            DistroFamily::Arch => "arch",
            DistroFamily::Debian => "debian",
            DistroFamily::Fedora => "fedora",
            DistroFamily::Other => "other",
        }
    }
}

/// Detect the distro family from `/etc/os-release` (`ID`, then `ID_LIKE`).
pub fn distro_family() -> DistroFamily {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    classify_os_release(&text)
}

fn classify_os_release(text: &str) -> DistroFamily {
    let o = parse_os_release(text);
    classify(&o.id, &o.id_like)
}

/// The identifying subset of `/etc/os-release`. `family()` derives the coarse
/// family; `label()` gives the best human name+version for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub id_like: String,
    pub name: String,
    pub pretty_name: String,
    pub version_id: String,
}

impl OsRelease {
    pub fn family(&self) -> DistroFamily {
        classify(&self.id, &self.id_like)
    }

    /// Best human label: `PRETTY_NAME`, else `NAME VERSION_ID`, else `ID`,
    /// else a generic fallback. E.g. "Fedora Linux 41 (Workstation Edition)".
    pub fn label(&self) -> String {
        if !self.pretty_name.is_empty() {
            return self.pretty_name.clone();
        }
        let nv = format!("{} {}", self.name, self.version_id);
        let nv = nv.trim();
        if !nv.is_empty() {
            return nv.to_string();
        }
        if !self.id.is_empty() {
            return self.id.clone();
        }
        "Linux (unknown)".to_string()
    }
}

/// Read and parse `/etc/os-release` for full OS identity.
pub fn os_release() -> OsRelease {
    parse_os_release(&std::fs::read_to_string("/etc/os-release").unwrap_or_default())
}

fn parse_os_release(text: &str) -> OsRelease {
    let mut o = OsRelease::default();
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once('=') else {
            continue;
        };
        let v = unquote(v);
        match k {
            "ID" => o.id = v,
            "ID_LIKE" => o.id_like = v,
            "NAME" => o.name = v,
            "PRETTY_NAME" => o.pretty_name = v,
            "VERSION_ID" => o.version_id = v,
            _ => {}
        }
    }
    o
}

fn classify(id: &str, id_like: &str) -> DistroFamily {
    let mut toks: Vec<String> = Vec::new();
    if !id.is_empty() {
        toks.push(id.to_ascii_lowercase());
    }
    toks.extend(id_like.split_whitespace().map(|s| s.to_ascii_lowercase()));
    let has = |names: &[&str]| toks.iter().any(|t| names.contains(&t.as_str()));

    // Check most-specific families first; ID_LIKE often lists the parent.
    if has(&["arch", "manjaro", "endeavouros", "cachyos", "arcolinux"]) {
        DistroFamily::Arch
    } else if has(&["fedora", "rhel", "centos", "rocky", "almalinux"]) {
        DistroFamily::Fedora
    } else if has(&["debian", "ubuntu", "linuxmint", "pop"]) {
        DistroFamily::Debian
    } else {
        DistroFamily::Other
    }
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// Resolve the path to `libonnxruntime.so` for the `ort` (load-dynamic) loader.
///
/// Returns the first existing candidate, including a versioned sibling
/// (`libonnxruntime.so.1.x.y`) when no unversioned symlink is present. Does
/// **not** consult `ORT_DYLIB_PATH` — callers that honour an explicit override
/// should check it first. Returns `None` if nothing is found.
pub fn onnxruntime_dylib() -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "/usr/lib/libonnxruntime.so",               // Arch
        "/usr/lib64/libonnxruntime.so",             // Fedora/RHEL
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so", // Debian/Ubuntu (amd64)
        "/usr/lib/aarch64-linux-gnu/libonnxruntime.so", // Debian/Ubuntu (arm64)
        "/usr/local/lib/libonnxruntime.so",         // self-built
    ];
    for c in CANDIDATES {
        if Path::new(c).exists() {
            return Some((*c).to_string());
        }
        if let Some(v) = versioned_sibling(c) {
            return Some(v);
        }
    }
    None
}

/// If `path` itself is absent but a versioned sibling exists in the same dir
/// (`<file>.1.16.3`), return that sibling's full path.
fn versioned_sibling(path: &str) -> Option<String> {
    let p = Path::new(path);
    let dir = p.parent()?;
    let file = p.file_name()?.to_str()?;
    let prefix = format!("{file}.");
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();
    // Deterministic pick (highest version sorts last lexically — good enough).
    hits.sort();
    hits.pop().map(|p| p.to_string_lossy().into_owned())
}

/// Directory PAM loadable modules are installed into. Probes for an existing
/// `pam_unix.so` (the most reliable signal) in the family's canonical order,
/// else returns the family default. Used by the installer and the upcoming
/// `--wire-pam` step.
///
/// Order matters per family: on Arch `/usr/lib64` is a compat symlink to
/// `/usr/lib`, so the canonical `/usr/lib/security` must be checked first; on
/// Fedora the real 64-bit modules live in `/usr/lib64/security`.
pub fn pam_module_dir() -> String {
    let ordered: &[&str] = match distro_family() {
        DistroFamily::Debian => &[
            "/lib/x86_64-linux-gnu/security",     // amd64
            "/usr/lib/x86_64-linux-gnu/security", // newer multiarch
            "/lib/aarch64-linux-gnu/security",    // arm64
            "/usr/lib/aarch64-linux-gnu/security",
            "/usr/lib/security",
        ],
        DistroFamily::Fedora => &["/usr/lib64/security", "/usr/lib/security"],
        DistroFamily::Arch => &["/usr/lib/security", "/usr/lib64/security"],
        DistroFamily::Other => &[
            "/usr/lib/security",
            "/usr/lib64/security",
            "/lib/x86_64-linux-gnu/security",
            "/usr/lib/x86_64-linux-gnu/security",
        ],
    };
    for c in ordered {
        if Path::new(c).join("pam_unix.so").exists() {
            return (*c).to_string();
        }
    }
    ordered[0].to_string()
}

/// Name of the initramfs/UKI builder for this distro, for docs and the reseal
/// trigger. Probes `PATH`; falls back to the family default.
pub fn initramfs_tool() -> &'static str {
    for (bin, name) in [
        ("mkinitcpio", "mkinitcpio"),
        ("dracut", "dracut"),
        ("update-initramfs", "update-initramfs"),
    ] {
        if on_path(bin) {
            return name;
        }
    }
    match distro_family() {
        DistroFamily::Debian => "update-initramfs",
        DistroFamily::Fedora => "dracut",
        DistroFamily::Arch => "mkinitcpio",
        DistroFamily::Other => "unknown",
    }
}

fn on_path(bin: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(bin).exists())
}

/// How face login is wired into PAM, which is the most distro-specific setup
/// step. See `linhello-cli`'s `pamwire` for the implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamMethod {
    /// Edit per-service `/etc/pam.d` files directly — automated. Arch & kin.
    EditPamD,
    /// A `pam-auth-update` profile woven into `common-auth`. Debian/Ubuntu.
    PamAuthUpdate,
    /// An `authselect` custom profile/feature. Fedora/RHEL.
    Authselect,
    /// No known mechanism — guided manual edit. Other.
    Manual,
}

impl PamMethod {
    pub fn label(self) -> &'static str {
        match self {
            PamMethod::EditPamD => "direct /etc/pam.d edits",
            PamMethod::PamAuthUpdate => "pam-auth-update profile",
            PamMethod::Authselect => "authselect custom profile",
            PamMethod::Manual => "manual PAM edit",
        }
    }

    /// True when LinuxHello applies the wiring itself; false when it prints
    /// guided steps for the user to run (the untested distro paths).
    pub fn automated(self) -> bool {
        matches!(self, PamMethod::EditPamD)
    }
}

fn pam_method_for(family: DistroFamily) -> PamMethod {
    match family {
        DistroFamily::Arch => PamMethod::EditPamD,
        DistroFamily::Debian => PamMethod::PamAuthUpdate,
        DistroFamily::Fedora => PamMethod::Authselect,
        DistroFamily::Other => PamMethod::Manual,
    }
}

/// PAM wiring method for the running OS.
pub fn pam_method() -> PamMethod {
    pam_method_for(distro_family())
}

/// The resolved, human-readable setup choices for the running OS — i.e. exactly
/// what LinuxHello will do on *this* machine. Surfaced in the wizard so a first
/// run on a new distro (Fedora, Ubuntu, …) shows which mechanisms apply before
/// anything is changed.
#[derive(Debug, Clone)]
pub struct SetupProfile {
    pub os_label: String,
    pub family: DistroFamily,
    pub pam_method: PamMethod,
    pub initramfs_tool: &'static str,
    pub pam_module_dir: String,
    pub onnxruntime: Option<String>,
}

pub fn setup_profile() -> SetupProfile {
    let os = os_release();
    SetupProfile {
        os_label: os.label(),
        family: os.family(),
        pam_method: pam_method(),
        initramfs_tool: initramfs_tool(),
        pam_module_dir: pam_module_dir(),
        onnxruntime: onnxruntime_dylib(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_arch() {
        let os = "NAME=\"Arch Linux\"\nID=arch\n";
        assert_eq!(classify_os_release(os), DistroFamily::Arch);
    }

    #[test]
    fn classifies_ubuntu_via_id_like() {
        let os = "ID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(classify_os_release(os), DistroFamily::Debian);
    }

    #[test]
    fn classifies_debian() {
        let os = "ID=debian\n";
        assert_eq!(classify_os_release(os), DistroFamily::Debian);
    }

    #[test]
    fn classifies_fedora() {
        let os = "ID=fedora\nID_LIKE=\"\"\n";
        assert_eq!(classify_os_release(os), DistroFamily::Fedora);
    }

    #[test]
    fn classifies_rhel_family_via_id_like() {
        let os = "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n";
        assert_eq!(classify_os_release(os), DistroFamily::Fedora);
    }

    #[test]
    fn classifies_manjaro_as_arch() {
        let os = "ID=manjaro\nID_LIKE=arch\n";
        assert_eq!(classify_os_release(os), DistroFamily::Arch);
    }

    #[test]
    fn unknown_is_other() {
        let os = "ID=void\n";
        assert_eq!(classify_os_release(os), DistroFamily::Other);
    }

    #[test]
    fn empty_os_release_is_other() {
        assert_eq!(classify_os_release(""), DistroFamily::Other);
    }

    #[test]
    fn quotes_are_stripped() {
        let os = "ID=\"fedora\"\n";
        assert_eq!(classify_os_release(os), DistroFamily::Fedora);
    }

    #[test]
    fn parses_fedora_label_and_version() {
        let os = "NAME=\"Fedora Linux\"\nVERSION_ID=41\n\
                  PRETTY_NAME=\"Fedora Linux 41 (Workstation Edition)\"\nID=fedora\n";
        let o = parse_os_release(os);
        assert_eq!(o.label(), "Fedora Linux 41 (Workstation Edition)");
        assert_eq!(o.version_id, "41");
        assert_eq!(o.family(), DistroFamily::Fedora);
        assert_eq!(pam_method_for(o.family()), PamMethod::Authselect);
    }

    #[test]
    fn ubuntu_label_falls_back_to_name_version_without_pretty_name() {
        let os = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n";
        let o = parse_os_release(os);
        assert_eq!(o.label(), "Ubuntu 24.04");
        assert_eq!(o.family(), DistroFamily::Debian);
        assert_eq!(pam_method_for(o.family()), PamMethod::PamAuthUpdate);
        assert!(!pam_method_for(o.family()).automated());
    }

    #[test]
    fn arch_pam_is_automated() {
        let os = "PRETTY_NAME=\"Arch Linux\"\nID=arch\n";
        let o = parse_os_release(os);
        assert_eq!(o.label(), "Arch Linux");
        assert_eq!(pam_method_for(o.family()), PamMethod::EditPamD);
        assert!(pam_method_for(o.family()).automated());
    }

    #[test]
    fn empty_os_release_label_is_generic() {
        assert_eq!(parse_os_release("").label(), "Linux (unknown)");
    }
}
