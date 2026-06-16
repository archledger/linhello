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

/// Linux Security Module governing this system, detected at runtime. This is
/// the axis that decides whether LinuxHello's SELinux policy module
/// (`etc/selinux/linhello.te`) applies: it MUST be loaded on SELinux systems
/// (Fedora/RHEL — without it the greeter/lock PAM domain `xdm_t` is denied the
/// daemon socket and face-auth silently falls back to a password) and must
/// NEVER be touched on others (Arch ships no such LSM; Debian/Ubuntu use
/// AppArmor). Detected from the kernel, not the distro family, so it stays
/// correct on derivatives and custom setups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityModule {
    /// SELinux is active. `enforcing` distinguishes enforcing from permissive.
    SeLinux { enforcing: bool },
    /// AppArmor is the active LSM.
    AppArmor,
    /// No major LSM detected (only DAC / capabilities).
    None,
}

impl SecurityModule {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityModule::SeLinux { enforcing: true } => "selinux (enforcing)",
            SecurityModule::SeLinux { enforcing: false } => "selinux (permissive)",
            SecurityModule::AppArmor => "apparmor",
            SecurityModule::None => "none",
        }
    }

    /// Whether LinuxHello's SELinux policy module should be installed here. True
    /// iff SELinux is active — enforcing OR permissive. We install on permissive
    /// too: a box can be switched to enforcing later, which would silently break
    /// greeter/lock face-auth if the policy were absent. False on AppArmor / no
    /// LSM, so the installer skips Arch, Ubuntu, etc. *by construction*.
    pub fn needs_selinux_policy(self) -> bool {
        matches!(self, SecurityModule::SeLinux { .. })
    }
}

/// Pure classifier (unit-testable, no filesystem). SELinux wins when selinuxfs's
/// `enforce` node is readable (it exists only when SELinux is enabled); else
/// AppArmor when its module flag reads `Y`; else none.
fn classify_security_module(
    selinux_enforce: Option<&str>,
    apparmor_enabled: Option<&str>,
) -> SecurityModule {
    if let Some(enforce) = selinux_enforce {
        return SecurityModule::SeLinux {
            enforcing: enforce.trim() == "1",
        };
    }
    if matches!(apparmor_enabled.map(str::trim), Some("Y") | Some("y")) {
        return SecurityModule::AppArmor;
    }
    SecurityModule::None
}

/// Detect the active LSM. SELinux via `/sys/fs/selinux/enforce` (present only
/// when selinuxfs is mounted, i.e. SELinux enabled); AppArmor via
/// `/sys/module/apparmor/parameters/enabled`.
pub fn security_module() -> SecurityModule {
    let selinux = std::fs::read_to_string("/sys/fs/selinux/enforce").ok();
    let apparmor = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled").ok();
    classify_security_module(selinux.as_deref(), apparmor.as_deref())
}

/// Loadable-module name LinuxHello's policy registers as (`semodule -l`).
pub const SELINUX_MODULE_NAME: &str = "linhello";

/// Candidate install locations of the shipped policy source `linhello.te`, in
/// resolution order — where `make install` will drop it once the SELinux step
/// is wired into packaging.
const SELINUX_TE_CANDIDATES: &[&str] = &[
    "/usr/share/linhello/selinux/linhello.te",
    "/etc/linhello/selinux/linhello.te",
];

/// A gated plan for installing the SELinux policy module. Obtained ONLY via
/// [`selinux_policy_plan`], which returns `None` on every non-SELinux system —
/// so an installer that drives it cannot run `semodule` on Arch / AppArmor
/// boxes even by mistake. The build/load steps are returned as data so a wizard
/// can print them (dry-run) or an installer can execute them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelinuxPolicyPlan {
    pub module_name: &'static str,
    pub source_te: PathBuf,
    pub enforcing: bool,
}

impl SelinuxPolicyPlan {
    /// The ordered shell steps to build `source_te` and load the module, with
    /// build artifacts written under `build_dir` (a scratch dir — the source
    /// may live in a read-only location). The same list is used for `--dry-run`
    /// display and for execution, so what's printed is exactly what runs.
    pub fn commands(&self, build_dir: &Path) -> Vec<String> {
        let te = self.source_te.display();
        let b = build_dir.display();
        let m = self.module_name;
        vec![
            format!("checkmodule -M -m -o {b}/{m}.mod {te}"),
            format!("semodule_package -o {b}/{m}.pp -m {b}/{m}.mod"),
            format!("semodule -i {b}/{m}.pp"),
            // Restart so the socket is recreated and relabeled by the policy's
            // file-type transition.
            "systemctl restart linhellod".to_string(),
        ]
    }
}

/// Install plan for LinuxHello's SELinux policy, gated on detection. `None`
/// (skip entirely) unless SELinux is active; otherwise the resolved source
/// `.te` (first existing candidate, else the primary default) and whether the
/// system is currently enforcing.
pub fn selinux_policy_plan() -> Option<SelinuxPolicyPlan> {
    let SecurityModule::SeLinux { enforcing } = security_module() else {
        return None;
    };
    let source_te = SELINUX_TE_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(SELINUX_TE_CANDIDATES[0]));
    Some(SelinuxPolicyPlan {
        module_name: SELINUX_MODULE_NAME,
        source_te,
        enforcing,
    })
}

/// How this distro triggers the post-update reseal of LinuxHello's TPM
/// envelopes after a kernel / bootloader / Secure-Boot change. The reseal
/// *script* is distro-agnostic; only the trigger mechanism that runs it varies,
/// which is why the Arch pacman hook must NOT be dropped on Fedora/Debian (it's
/// a dead file there) and vice-versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResealTrigger {
    /// Arch & derivatives: a libalpm hook in `/etc/pacman.d/hooks`.
    PacmanHook,
    /// Fedora/RHEL and other `kernel-install`-based distros: a plugin in
    /// `/etc/kernel/install.d` (dnf runs `kernel-install` on kernel changes).
    KernelInstall,
    /// Debian/Ubuntu: a kernel `postinst.d` script.
    KernelPostinst,
    /// Unknown distro — the user must wire a trigger manually.
    Manual,
}

impl ResealTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            ResealTrigger::PacmanHook => "pacman hook",
            ResealTrigger::KernelInstall => "kernel-install plugin",
            ResealTrigger::KernelPostinst => "kernel postinst.d script",
            ResealTrigger::Manual => "manual",
        }
    }

    /// Active install path of the trigger file for this mechanism, or `None`
    /// for `Manual`.
    pub fn hook_path(self) -> Option<&'static str> {
        match self {
            ResealTrigger::PacmanHook => Some("/etc/pacman.d/hooks/linhello-reseal.hook"),
            ResealTrigger::KernelInstall => Some("/etc/kernel/install.d/95-linhello.install"),
            ResealTrigger::KernelPostinst => Some("/etc/kernel/postinst.d/zz-linhello"),
            ResealTrigger::Manual => None,
        }
    }
}

fn reseal_trigger_for(family: DistroFamily) -> ResealTrigger {
    match family {
        DistroFamily::Arch => ResealTrigger::PacmanHook,
        DistroFamily::Fedora => ResealTrigger::KernelInstall,
        DistroFamily::Debian => ResealTrigger::KernelPostinst,
        DistroFamily::Other => ResealTrigger::Manual,
    }
}

/// Reseal trigger mechanism for the running OS.
pub fn reseal_trigger() -> ResealTrigger {
    reseal_trigger_for(distro_family())
}

/// Candidate install locations of the shared, distro-agnostic reseal script
/// (`make install` puts it in BINDIR), in resolution order.
const RESEAL_SCRIPT_CANDIDATES: &[&str] = &[
    "/usr/local/bin/linhello-reseal-hook",
    "/usr/bin/linhello-reseal-hook",
];

/// A gated plan for installing the post-update reseal trigger. `None` when the
/// distro has no known mechanism (so callers skip rather than drop a dead file),
/// else the trigger's active path and the resolved reseal-script it invokes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResealHookPlan {
    pub trigger: ResealTrigger,
    pub hook_path: PathBuf,
    pub script_path: PathBuf,
}

pub fn reseal_hook_plan() -> Option<ResealHookPlan> {
    let trigger = reseal_trigger();
    let hook_path = PathBuf::from(trigger.hook_path()?);
    let script_path = RESEAL_SCRIPT_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(RESEAL_SCRIPT_CANDIDATES[0]));
    Some(ResealHookPlan {
        trigger,
        hook_path,
        script_path,
    })
}

/// A build- or run-time dependency and its package name on each supported
/// distro family. Source: docs/design/cross-platform-and-setup-ux.md plus the
/// Fedora build deps validated during the port. An empty package name means
/// "no distro package — build it or fetch upstream" (notably Debian's ONNX
/// Runtime, which isn't in main).
#[derive(Debug, Clone, Copy)]
pub struct Dep {
    pub need: &'static str,
    /// true = needed to run the daemon; false = build-time only.
    pub runtime: bool,
    arch: &'static str,
    debian: &'static str,
    fedora: &'static str,
}

impl Dep {
    /// Package name on `family`, or `""` when there's no distro package.
    pub fn package(&self, family: DistroFamily) -> &'static str {
        match family {
            DistroFamily::Arch => self.arch,
            DistroFamily::Debian => self.debian,
            DistroFamily::Fedora => self.fedora,
            DistroFamily::Other => "",
        }
    }
}

/// LinuxHello's build + runtime dependencies with per-distro package names.
pub const DEPENDENCIES: &[Dep] = &[
    // Runtime.
    Dep { need: "TPM 2.0 TSS runtime", runtime: true, arch: "tpm2-tss", debian: "libtss2-tcti-device0", fedora: "tpm2-tss" },
    Dep { need: "ONNX Runtime", runtime: true, arch: "onnxruntime", debian: "", fedora: "onnxruntime" },
    Dep { need: "PAM runtime", runtime: true, arch: "pam", debian: "libpam0g", fedora: "pam" },
    Dep { need: "V4L cameras", runtime: true, arch: "v4l-utils", debian: "libv4l-0", fedora: "libv4l" },
    // Build-time (matches the validated Fedora deps: tpm2-tss-devel, openssl-devel, clang-devel, pam-devel).
    Dep { need: "Rust toolchain", runtime: false, arch: "rust", debian: "cargo", fedora: "cargo" },
    Dep { need: "TPM TSS headers", runtime: false, arch: "tpm2-tss", debian: "libtss2-dev", fedora: "tpm2-tss-devel" },
    Dep { need: "OpenSSL headers", runtime: false, arch: "openssl", debian: "libssl-dev", fedora: "openssl-devel" },
    Dep { need: "clang/bindgen", runtime: false, arch: "clang", debian: "libclang-dev", fedora: "clang-devel" },
    Dep { need: "PAM headers", runtime: false, arch: "pam", debian: "libpam0g-dev", fedora: "pam-devel" },
];

/// Native package format for this distro family — what `linhello` builds and
/// installs for the running OS, so each family gets a package specific to it
/// rather than a one-size source install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFormat {
    /// `.rpm` (rpmbuild + dnf) — Fedora/RHEL.
    Rpm,
    /// `.deb` (dpkg-buildpackage + apt) — Debian/Ubuntu.
    Deb,
    /// `.pkg.tar.zst` (makepkg + pacman) — Arch.
    Pkg,
    /// No known native packaging.
    Unknown,
}

impl PackageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            PackageFormat::Rpm => "rpm",
            PackageFormat::Deb => "deb",
            PackageFormat::Pkg => "pkg",
            PackageFormat::Unknown => "unknown",
        }
    }

    /// In-repo packaging definition directory for this format.
    pub fn packaging_dir(self) -> Option<&'static str> {
        match self {
            PackageFormat::Rpm => Some("packaging/fedora"),
            PackageFormat::Deb => Some("packaging/debian"),
            PackageFormat::Pkg => Some("packaging/arch"),
            PackageFormat::Unknown => None,
        }
    }

    /// The tool that builds this package format (used to gate the native path).
    pub fn build_tool(self) -> Option<&'static str> {
        match self {
            PackageFormat::Rpm => Some("rpmbuild"),
            PackageFormat::Deb => Some("dpkg-buildpackage"),
            PackageFormat::Pkg => Some("makepkg"),
            PackageFormat::Unknown => None,
        }
    }
}

fn package_format_for(family: DistroFamily) -> PackageFormat {
    match family {
        DistroFamily::Fedora => PackageFormat::Rpm,
        DistroFamily::Debian => PackageFormat::Deb,
        DistroFamily::Arch => PackageFormat::Pkg,
        DistroFamily::Other => PackageFormat::Unknown,
    }
}

/// Native package format for the running OS.
pub fn package_format() -> PackageFormat {
    package_format_for(distro_family())
}

/// The package-install command prefix for this distro family, e.g.
/// `sudo dnf install`. `None` when the package manager is unknown.
pub fn package_install_prefix() -> Option<&'static str> {
    match distro_family() {
        DistroFamily::Arch => Some("sudo pacman -S --needed"),
        DistroFamily::Debian => Some("sudo apt install"),
        DistroFamily::Fedora => Some("sudo dnf install"),
        DistroFamily::Other => None,
    }
}

/// One-line install command for `packages` on the running distro, skipping
/// empty names. `None` if the package manager is unknown or nothing's left.
pub fn install_command(packages: &[&str]) -> Option<String> {
    let prefix = package_install_prefix()?;
    let names: Vec<&str> = packages.iter().copied().filter(|p| !p.is_empty()).collect();
    if names.is_empty() {
        return None;
    }
    Some(format!("{prefix} {}", names.join(" ")))
}

/// Actionable hint for a missing ONNX Runtime on this distro (the most common
/// fresh-install failure), e.g. `sudo dnf install onnxruntime`.
pub fn onnxruntime_install_hint() -> String {
    let family = distro_family();
    let pkg = DEPENDENCIES
        .iter()
        .find(|d| d.need == "ONNX Runtime")
        .map(|d| d.package(family))
        .unwrap_or("");
    match install_command(&[pkg]) {
        Some(cmd) => cmd,
        None if family == DistroFamily::Debian => {
            "not packaged in Debian — build/download libonnxruntime.so and set ORT_DYLIB_PATH".into()
        }
        None => "install the onnxruntime package, or set ORT_DYLIB_PATH".into(),
    }
}

/// The resolved, human-readable setup choices for the running OS — i.e. exactly
/// what LinuxHello will do on *this* machine. Surfaced in the wizard so a first
/// run on a new distro (Fedora, Ubuntu, …) shows which mechanisms apply before
/// anything is changed.
#[derive(Debug, Clone)]
pub struct SetupProfile {
    pub os_label: String,
    pub family: DistroFamily,
    pub security_module: SecurityModule,
    pub pam_method: PamMethod,
    pub reseal_trigger: ResealTrigger,
    pub initramfs_tool: &'static str,
    pub pam_module_dir: String,
    pub onnxruntime: Option<String>,
}

pub fn setup_profile() -> SetupProfile {
    let os = os_release();
    SetupProfile {
        os_label: os.label(),
        family: os.family(),
        security_module: security_module(),
        pam_method: pam_method(),
        reseal_trigger: reseal_trigger(),
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

    #[test]
    fn selinux_enforce_node_classifies_enforcing_vs_permissive() {
        assert_eq!(
            classify_security_module(Some("1\n"), None),
            SecurityModule::SeLinux { enforcing: true }
        );
        assert_eq!(
            classify_security_module(Some("0"), None),
            SecurityModule::SeLinux { enforcing: false }
        );
    }

    #[test]
    fn apparmor_flag_classifies_only_when_no_selinux() {
        assert_eq!(
            classify_security_module(None, Some("Y\n")),
            SecurityModule::AppArmor
        );
        // SELinux present wins even if AppArmor flag is also set.
        assert_eq!(
            classify_security_module(Some("1"), Some("Y")),
            SecurityModule::SeLinux { enforcing: true }
        );
    }

    #[test]
    fn no_lsm_is_none() {
        assert_eq!(classify_security_module(None, None), SecurityModule::None);
        assert_eq!(classify_security_module(None, Some("N")), SecurityModule::None);
    }

    #[test]
    fn selinux_policy_gate_is_selinux_only() {
        // The whole point: install on SELinux (either mode), never elsewhere —
        // so Fedora/Ubuntu work doesn't reach the Arch / AppArmor path.
        assert!(SecurityModule::SeLinux { enforcing: true }.needs_selinux_policy());
        assert!(SecurityModule::SeLinux { enforcing: false }.needs_selinux_policy());
        assert!(!SecurityModule::AppArmor.needs_selinux_policy());
        assert!(!SecurityModule::None.needs_selinux_policy());
    }

    #[test]
    fn package_format_is_per_family() {
        assert_eq!(package_format_for(DistroFamily::Fedora), PackageFormat::Rpm);
        assert_eq!(package_format_for(DistroFamily::Debian), PackageFormat::Deb);
        assert_eq!(package_format_for(DistroFamily::Arch), PackageFormat::Pkg);
        assert_eq!(package_format_for(DistroFamily::Other), PackageFormat::Unknown);
        assert_eq!(PackageFormat::Rpm.packaging_dir(), Some("packaging/fedora"));
        assert_eq!(PackageFormat::Deb.build_tool(), Some("dpkg-buildpackage"));
        assert_eq!(PackageFormat::Unknown.packaging_dir(), None);
    }

    #[test]
    fn dep_packages_and_install_command_are_per_family() {
        let onnx = DEPENDENCIES.iter().find(|d| d.need == "ONNX Runtime").unwrap();
        assert_eq!(onnx.package(DistroFamily::Fedora), "onnxruntime");
        assert_eq!(onnx.package(DistroFamily::Arch), "onnxruntime");
        assert_eq!(onnx.package(DistroFamily::Debian), ""); // not packaged
        // install_command joins names after the family prefix and drops empties.
        let cmd = install_command(&["onnxruntime", "", "tpm2-tss"]);
        // (depends on the running distro's prefix; just assert structure if Some)
        if let Some(c) = cmd {
            assert!(c.contains("onnxruntime") && c.contains("tpm2-tss"));
            assert!(!c.contains("  ")); // empty name didn't leave a double space
        }
        // Every build dep has a Fedora package name (validated set).
        for d in DEPENDENCIES.iter().filter(|d| !d.runtime) {
            assert!(!d.package(DistroFamily::Fedora).is_empty(), "{} missing Fedora pkg", d.need);
        }
    }

    #[test]
    fn reseal_trigger_is_per_family() {
        // The whole point: the Arch pacman hook is never chosen on Fedora/Debian.
        assert_eq!(reseal_trigger_for(DistroFamily::Arch), ResealTrigger::PacmanHook);
        assert_eq!(reseal_trigger_for(DistroFamily::Fedora), ResealTrigger::KernelInstall);
        assert_eq!(reseal_trigger_for(DistroFamily::Debian), ResealTrigger::KernelPostinst);
        assert_eq!(reseal_trigger_for(DistroFamily::Other), ResealTrigger::Manual);
        // Each concrete mechanism maps to a distinct active install path.
        assert!(ResealTrigger::PacmanHook.hook_path().unwrap().contains("pacman.d"));
        assert!(ResealTrigger::KernelInstall.hook_path().unwrap().contains("kernel/install.d"));
        assert!(ResealTrigger::KernelPostinst.hook_path().unwrap().contains("postinst.d"));
        assert_eq!(ResealTrigger::Manual.hook_path(), None);
    }

    #[test]
    fn selinux_plan_commands_reference_the_te_and_module() {
        let plan = SelinuxPolicyPlan {
            module_name: SELINUX_MODULE_NAME,
            source_te: PathBuf::from("/usr/share/linhello/selinux/linhello.te"),
            enforcing: true,
        };
        let cmds = plan.commands(Path::new("/tmp/build"));
        assert!(cmds.iter().any(|c| c.contains("linhello.te")));
        assert!(cmds.iter().any(|c| c.starts_with("semodule -i /tmp/build/linhello.pp")));
        assert!(cmds.last().unwrap().contains("restart linhellod"));
    }
}
