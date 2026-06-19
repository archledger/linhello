//! Host capability probe — "does this machine have what LinuxHello needs?"
//!
//! Backs `Request::Probe` / `linhello doctor`. Checks the TPM, Secure Boot /
//! boot mode, signed-PCR-policy artifacts, RGB + IR cameras, the ONNX runtime,
//! and the model files. Each check is `required` or advisory; the report's
//! `can_run`/`degraded` helpers summarise overall readiness.

use linhello_common::ipc::{CapabilityCheck, CapabilityReport, CapabilityStatus};
use std::path::Path;

fn check(name: &str, status: CapabilityStatus, required: bool, detail: impl Into<String>) -> CapabilityCheck {
    CapabilityCheck {
        name: name.to_string(),
        status,
        required,
        detail: detail.into(),
    }
}

pub fn probe() -> CapabilityReport {
    let (rgb, ir) = camera_checks();
    let mut checks = vec![
        platform_check(),
        tpm_check(),
        secure_boot_check(),
        boot_mode_check(),
        signed_policy_check(),
        rgb,
        ir,
        onnxruntime_check(),
    ];
    checks.extend(model_checks());
    if let Some(fp) = fingerprint_check() {
        checks.push(fp);
    }
    CapabilityReport { checks }
}

/// Report the fingerprint reader and, when the face tier is RGB-only (no IR),
/// suggest fingerprint as a stronger complementary factor. Returns `None` (no
/// line) when no reader is present, to avoid clutter on machines without one.
fn fingerprint_check() -> Option<CapabilityCheck> {
    if !linhello_fingerprint::available() {
        return None;
    }
    let name = linhello_fingerprint::device_name().unwrap_or_else(|| "fingerprint reader".into());
    let rgb_only = linhello_biometrics::camera::ir_device().is_none();
    // State-neutral wording: this is a host probe, so it doesn't know whether a
    // finger is already enrolled. `linhello fingerprint status` shows that.
    let detail = if rgb_only {
        format!(
            "{name} present — a secure-tier method (screen unlock + login + sudo), \
             stronger than RGB-only face. Manage with `linhello fingerprint` \
             (RGB-only face stays available as a convenience option)."
        )
    } else {
        format!(
            "{name} present — a secure-tier alternative to IR face (both unlock \
             everything); choose either. Manage with `linhello fingerprint`."
        )
    };
    Some(check("Fingerprint", CapabilityStatus::Ok, false, detail))
}

fn tpm_check() -> CapabilityCheck {
    for dev in ["/dev/tpmrm0", "/dev/tpm0"] {
        if Path::new(dev).exists() {
            return check("TPM 2.0", CapabilityStatus::Ok, true, dev);
        }
    }
    check(
        "TPM 2.0",
        CapabilityStatus::Missing,
        true,
        "no /dev/tpmrm0 — a TPM 2.0 is required for hardware-backed sealing",
    )
}

fn secure_boot_check() -> CapabilityCheck {
    if linhello_secureboot::is_secure_boot_enabled() {
        check("Secure Boot", CapabilityStatus::Ok, false, "enabled")
    } else {
        check(
            "Secure Boot",
            CapabilityStatus::Warn,
            false,
            "disabled — TPM binding falls back to the weakest tier; enable for PCR-7 trust",
        )
    }
}

fn boot_mode_check() -> CapabilityCheck {
    use linhello_common::BootMode;
    match linhello_secureboot::detect_boot_mode() {
        BootMode::Uki => check(
            "Boot mode",
            CapabilityStatus::Ok,
            false,
            "UKI — eligible for signed PCR-11 policy",
        ),
        BootMode::Grub => check(
            "Boot mode",
            CapabilityStatus::Warn,
            false,
            "GRUB — signed PCR-11 policy needs a UKI; PCR-7 binding still works",
        ),
        BootMode::Unknown => check(
            "Boot mode",
            CapabilityStatus::Warn,
            false,
            "unknown bootloader",
        ),
    }
}

fn signed_policy_check() -> CapabilityCheck {
    if linhello_core::pcrsig::signed_policy_available() {
        check(
            "Signed PCR policy",
            CapabilityStatus::Ok,
            false,
            "systemd PCR signature + public key present — kernel updates won't require re-seal",
        )
    } else {
        check(
            "Signed PCR policy",
            CapabilityStatus::Warn,
            false,
            "not configured — using stable PCR-7 binding (coarser, but survives kernel updates)",
        )
    }
}

fn camera_checks() -> (CapabilityCheck, CapabilityCheck) {
    use linhello_biometrics::camera::{enumerate, ir_device, rgb_device, CameraKind};
    let cams = enumerate();
    // Canonicalize so a cameras.conf by-path/by-id symlink matches the real
    // /dev/videoN that `enumerate()` reports.
    let canon = |p: &str| {
        std::fs::canonicalize(p)
            .ok()
            .and_then(|q| q.to_str().map(str::to_string))
            .unwrap_or_else(|| p.to_string())
    };

    // Report the device the daemon will ACTUALLY bind (env → cameras.conf →
    // auto-detect), not a fresh independent auto-detect. Otherwise doctor can
    // show a different camera than the one auth uses — e.g. an unreadable
    // cameras.conf sends both to auto-detect, but a correct one diverges.
    let rgb_path = rgb_device();
    let rgb_node = canon(&rgb_path);
    let rgb_check = match cams.iter().find(|c| canon(&c.path) == rgb_node) {
        Some(c) if c.kind == CameraKind::Rgb && c.trusted => check(
            "RGB camera",
            CapabilityStatus::Ok,
            true,
            format!("{} ({})", c.name.as_deref().unwrap_or("camera"), rgb_node),
        ),
        Some(c) if c.kind == CameraKind::Rgb => check(
            "RGB camera",
            CapabilityStatus::Warn,
            true,
            format!("resolved {rgb_node} is untrusted (virtual?) — check cameras.conf"),
        ),
        Some(_) => check(
            "RGB camera",
            CapabilityStatus::Warn,
            true,
            format!("resolved {rgb_node} is not colour-capable — wrong cameras.conf `rgb=`"),
        ),
        None => check(
            "RGB camera",
            CapabilityStatus::Warn,
            true,
            format!(
                "resolved {rgb_path} not found among capture nodes — check cameras.conf / its SELinux label"
            ),
        ),
    };

    let ir_check = match ir_device() {
        Some(ir_path) => {
            let ir_node = canon(&ir_path);
            match cams.iter().find(|c| canon(&c.path) == ir_node) {
                Some(c) => check(
                    "IR camera",
                    CapabilityStatus::Ok,
                    false,
                    format!(
                        "{} ({}) — active-IR liveness available",
                        c.name.as_deref().unwrap_or("IR sensor"),
                        ir_node
                    ),
                ),
                None => check(
                    "IR camera",
                    CapabilityStatus::Warn,
                    false,
                    format!(
                        "resolved {ir_path} not found among capture nodes — check cameras.conf / its SELinux label"
                    ),
                ),
            }
        }
        None => check(
            "IR camera",
            CapabilityStatus::Warn,
            false,
            "no NIR sensor — active-IR anti-spoof disabled (ML anti-spoof still applies)",
        ),
    };

    (rgb_check, ir_check)
}

fn platform_check() -> CapabilityCheck {
    use linhello_common::platform;
    let lsm = platform::security_module();
    let selinux = if lsm.needs_selinux_policy() {
        " · SELinux policy module required"
    } else {
        ""
    };
    let detail = format!(
        "{} · pkg: {} · PAM modules: {} · initramfs: {} · reseal: {} · LSM: {}{}",
        platform::distro_family().as_str(),
        platform::package_format().as_str(),
        platform::pam_module_dir(),
        platform::initramfs_tool(),
        platform::reseal_trigger().as_str(),
        lsm.as_str(),
        selinux,
    );
    check("Platform", CapabilityStatus::Ok, false, detail)
}

fn onnxruntime_check() -> CapabilityCheck {
    // pyke `ort` (load-dynamic) dlopens libonnxruntime.so at runtime. Honour an
    // explicit override, else resolve via the shared per-distro candidate list.
    if let Some(p) = std::env::var_os("ORT_DYLIB_PATH") {
        if Path::new(&p).exists() {
            return check("ONNX runtime", CapabilityStatus::Ok, true, p.to_string_lossy());
        }
    }
    if let Some(p) = linhello_common::platform::onnxruntime_dylib() {
        return check("ONNX runtime", CapabilityStatus::Ok, true, p);
    }
    check(
        "ONNX runtime",
        CapabilityStatus::Missing,
        true,
        format!(
            "libonnxruntime.so not found — {}",
            linhello_common::platform::onnxruntime_install_hint()
        ),
    )
}

fn model_path(env: &str, default: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| default.to_string())
}

/// Where to get the buffalo_l detector/recognizer (not redistributed). Shown on
/// a missing-model FAIL so a fresh install is self-explanatory.
const BUFFALO_HINT: &str = " — in InsightFace buffalo_l (v0.7); \
    `linhello setup` installs it automatically if found in $LINHELLO_MODELS_DIR, \
    <repo>/models, or /usr/share/linhello/models — else fetch buffalo_l.zip from \
    github.com/deepinsight/insightface/releases/tag/v0.7";

fn model_checks() -> Vec<CapabilityCheck> {
    let models = [
        ("Face detector model", "LINHELLO_DET_MODEL", "/etc/linhello/det_10g.onnx", true, BUFFALO_HINT),
        ("Face embedder model", "LINHELLO_MODEL_PATH", "/etc/linhello/face.onnx", true, BUFFALO_HINT),
        (
            "Anti-spoof model",
            "LINHELLO_ANTISPOOF_MODEL",
            linhello_liveness::DEFAULT_ANTISPOOF_MODEL,
            true,
            " (required by default; set LINHELLO_REQUIRE_ANTISPOOF=0 to allow running without it)",
        ),
    ];
    models
        .iter()
        .map(|(name, env, default, required, note)| {
            let path = model_path(env, default);
            if Path::new(&path).exists() {
                check(name, CapabilityStatus::Ok, *required, path)
            } else {
                check(
                    name,
                    CapabilityStatus::Missing,
                    *required,
                    format!("missing at {path}{note}"),
                )
            }
        })
        .collect()
}
