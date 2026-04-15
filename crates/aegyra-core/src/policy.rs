//! PCR policy selection.
//!
//! * FULL   — Secure Boot on (PCR 7) and UKI-measured kernel (PCR 11).
//! * MEDIUM — Secure Boot on (PCR 7 only); legacy bootloader.
//! * BASIC  — no firmware trust anchor; TPM binding disabled.

use aegyra_common::{BootMode, SecurityLevel};

pub fn detect() -> SecurityLevel {
    let sb = aegyra_secureboot::is_secure_boot_enabled();
    let boot = aegyra_secureboot::detect_boot_mode();
    match (sb, boot) {
        (true, BootMode::Uki) => SecurityLevel::Full,
        (true, _) => SecurityLevel::Medium,
        _ => SecurityLevel::Basic,
    }
}

pub fn pcrs_for(level: SecurityLevel) -> &'static [u32] {
    match level {
        SecurityLevel::Full => &[7, 11],
        SecurityLevel::Medium => &[7],
        SecurityLevel::Basic => &[],
    }
}
