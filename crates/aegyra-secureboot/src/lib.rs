//! Boot-mode and Secure Boot detection via the Linux efivarfs + procfs.
//!
//! Detection is best-effort and never panics: on a non-EFI system, missing
//! efivars, or unreadable files we return conservative defaults.

use aegyra_common::BootMode;
use std::fs;
use std::path::Path;

const EFI_ROOT: &str = "/sys/firmware/efi";
const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// Global EFI SecureBoot variable: `SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`.
const SECUREBOOT_VAR: &str = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// `SetupMode` — when 1, the platform is in setup mode (keys not enrolled).
const SETUPMODE_VAR: &str = "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// systemd-stub writes this efivar when a UKI is booted.
/// GUID 4a67b082-0a4c-41cf-b6c7-440b29bb8c4f is the Loader interface.
const STUB_INFO_VAR: &str = "StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// systemd-boot writes this efivar when it is the active boot loader.
const LOADER_INFO_VAR: &str = "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// Detect whether the system booted via UEFI, and if so whether through a
/// Unified Kernel Image or a traditional bootloader (GRUB/systemd-boot/etc.).
pub fn detect_boot_mode() -> BootMode {
    if !Path::new(EFI_ROOT).exists() {
        return BootMode::Grub;
    }
    if efivar_exists(STUB_INFO_VAR) {
        return BootMode::Uki;
    }
    if efivar_exists(LOADER_INFO_VAR) || grub_artifacts_present() {
        return BootMode::Grub;
    }
    BootMode::Unknown
}

/// Returns true when firmware is in SetupMode (no platform keys enrolled).
/// Setup mode is the only state in which unprivileged PK/KEK/db writes are
/// accepted by the firmware.
pub fn is_setup_mode() -> bool {
    matches!(read_efivar_u8(SETUPMODE_VAR), Some(1))
}

/// Returns true when UEFI Secure Boot is active.
///
/// The efivar payload is 4 bytes of EFI attributes followed by the variable
/// data; for `SecureBoot` the data is a single byte (0 = off, 1 = on). If the
/// platform is in SetupMode, Secure Boot is not enforcing.
pub fn is_secure_boot_enabled() -> bool {
    let Some(secure) = read_efivar_u8(SECUREBOOT_VAR) else {
        return false;
    };
    let setup = read_efivar_u8(SETUPMODE_VAR).unwrap_or(0);
    secure == 1 && setup == 0
}

/// Best-effort identification of the active boot loader / stub.
pub fn loader_identity() -> Option<String> {
    read_efivar_utf16(STUB_INFO_VAR)
        .or_else(|| read_efivar_utf16(LOADER_INFO_VAR))
}

fn efivar_exists(name: &str) -> bool {
    Path::new(EFIVARS).join(name).exists()
}

fn read_efivar_bytes(name: &str) -> Option<Vec<u8>> {
    let bytes = fs::read(Path::new(EFIVARS).join(name)).ok()?;
    // First 4 bytes are UEFI variable attributes; strip them.
    if bytes.len() < 5 {
        return None;
    }
    Some(bytes[4..].to_vec())
}

fn read_efivar_u8(name: &str) -> Option<u8> {
    read_efivar_bytes(name).and_then(|b| b.first().copied())
}

fn read_efivar_utf16(name: &str) -> Option<String> {
    let data = read_efivar_bytes(name)?;
    if data.len() < 2 {
        return None;
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&u16s).ok()
}

fn grub_artifacts_present() -> bool {
    ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/default/grub"]
        .iter()
        .any(|p| Path::new(p).exists())
}
