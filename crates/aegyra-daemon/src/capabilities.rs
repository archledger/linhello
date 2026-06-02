//! Host capability probe — "does this machine have what Aegyra needs?"
//!
//! Backs `Request::Probe` / `aegyra doctor`. Checks the TPM, Secure Boot /
//! boot mode, signed-PCR-policy artifacts, RGB + IR cameras, the ONNX runtime,
//! and the model files. Each check is `required` or advisory; the report's
//! `can_run`/`degraded` helpers summarise overall readiness.

use aegyra_common::ipc::{CapabilityCheck, CapabilityReport, CapabilityStatus};
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
        tpm_check(),
        secure_boot_check(),
        boot_mode_check(),
        signed_policy_check(),
        rgb,
        ir,
        onnxruntime_check(),
    ];
    checks.extend(model_checks());
    CapabilityReport { checks }
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
    if aegyra_secureboot::is_secure_boot_enabled() {
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
    use aegyra_common::BootMode;
    match aegyra_secureboot::detect_boot_mode() {
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
    if aegyra_core::pcrsig::signed_policy_available() {
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
    use aegyra_biometrics::camera::{enumerate, CameraKind};
    let cams = enumerate();

    let rgb = cams
        .iter()
        .find(|c| c.kind == CameraKind::Rgb && c.trusted);
    let rgb_check = match rgb {
        Some(c) => check(
            "RGB camera",
            CapabilityStatus::Ok,
            true,
            format!("{} ({})", c.name.as_deref().unwrap_or("camera"), c.path),
        ),
        None => {
            // Distinguish "only an untrusted/virtual camera" from "none at all".
            if cams.iter().any(|c| c.kind == CameraKind::Rgb) {
                check(
                    "RGB camera",
                    CapabilityStatus::Warn,
                    true,
                    "only an untrusted (virtual?) camera found — set AEGYRA_RGB_DEVICE or cameras.conf",
                )
            } else {
                check(
                    "RGB camera",
                    CapabilityStatus::Missing,
                    true,
                    "no colour-capable capture device found",
                )
            }
        }
    };

    let ir = cams.iter().find(|c| c.kind == CameraKind::Ir);
    let ir_check = match ir {
        Some(c) => check(
            "IR camera",
            CapabilityStatus::Ok,
            false,
            format!(
                "{} ({}) — active-IR liveness available",
                c.name.as_deref().unwrap_or("IR sensor"),
                c.path
            ),
        ),
        None => check(
            "IR camera",
            CapabilityStatus::Warn,
            false,
            "no NIR sensor — active-IR anti-spoof disabled (ML anti-spoof still applies)",
        ),
    };

    (rgb_check, ir_check)
}

fn onnxruntime_check() -> CapabilityCheck {
    // pyke `ort` (load-dynamic) dlopens libonnxruntime.so at runtime.
    if let Some(p) = std::env::var_os("ORT_DYLIB_PATH") {
        if Path::new(&p).exists() {
            return check("ONNX runtime", CapabilityStatus::Ok, true, p.to_string_lossy());
        }
    }
    let candidates = [
        "/usr/lib/libonnxruntime.so",
        "/usr/lib64/libonnxruntime.so",
        "/usr/local/lib/libonnxruntime.so",
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
    ];
    for c in candidates {
        if glob_exists(c) {
            return check("ONNX runtime", CapabilityStatus::Ok, true, c);
        }
    }
    check(
        "ONNX runtime",
        CapabilityStatus::Missing,
        true,
        "libonnxruntime.so not found — install the `onnxruntime` package",
    )
}

/// True if `path` exists, or a versioned sibling (`path.1.x.y`) does.
fn glob_exists(path: &str) -> bool {
    if Path::new(path).exists() {
        return true;
    }
    let p = Path::new(path);
    let (Some(dir), Some(file)) = (p.parent(), p.file_name().and_then(|f| f.to_str())) else {
        return false;
    };
    let prefix = format!("{file}.");
    std::fs::read_dir(dir)
        .ok()
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        })
        .unwrap_or(false)
}

fn model_path(env: &str, default: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| default.to_string())
}

fn model_checks() -> Vec<CapabilityCheck> {
    let models = [
        ("Face detector model", "AEGYRA_DET_MODEL", "/etc/aegyra/det_10g.onnx", true, ""),
        ("Face embedder model", "AEGYRA_MODEL_PATH", "/etc/aegyra/face.onnx", true, ""),
        (
            "Anti-spoof model",
            "AEGYRA_ANTISPOOF_MODEL",
            aegyra_liveness::DEFAULT_ANTISPOOF_MODEL,
            true,
            " (required by default; set AEGYRA_REQUIRE_ANTISPOOF=0 to allow running without it)",
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
