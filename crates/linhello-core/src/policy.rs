//! PCR policy selection.
//!
//! LinuxHello binds its TPM secrets to one of three plans, chosen at seal time by
//! [`plan`]:
//!
//! * **Authorized** — a `PolicyAuthorize` over the systemd PCR-signing public
//!   key, covering **PCR 11 (the UKI measurement) only** — the exact set
//!   `ukify`/`systemd-measure` signs. Survives kernel updates because each new
//!   UKI ships a fresh signature for the new PCR 11. Chosen only when Secure
//!   Boot is on, the system booted a UKI, and signed artifacts
//!   (`/run/systemd/tpm2-pcr-{signature.json,public-key.pem}`) exist, and the
//!   public key matches the pinned trust anchor
//!   ([`crate::pcrsig::TRUSTED_PUBKEY_SPKI_SHA256`]). PCR 7 (Secure Boot state)
//!   is **not** folded in here — it is the separate literal gate below.
//!
//! * **Literal(PCR 7 only)** — a plain `PolicyPCR` over PCR 7. PCR 7 captures
//!   the Secure Boot state/keys, which do **not** change on a kernel/initrd
//!   update, so this *also* survives updates — at coarser granularity (any
//!   db-trusted kernel satisfies it, like BitLocker's default). This is the
//!   fallback whenever signed policy isn't available, and deliberately replaces
//!   the old fragile literal `[7, 11]` binding that broke on every kernel bump.
//!
//! * **None** — no Secure Boot anchor; TPM binding disabled.
//!
//! [`SecurityLevel`] is derived from the chosen plan for reporting.

use linhello_common::{BootMode, SecurityLevel};

/// PCRs covered by the signed (authorized) policy on a UKI system. systemd's
/// `ukify`/`systemd-measure` signs **PCR 11 only** (the UKI measurement), so the
/// `PolicyPCR` we replay at unseal must select exactly `[11]` to match a systemd
/// signature entry — a `[7, 11]` set never matched the `pcrs:[11]` signatures
/// systemd actually ships and so could never reach `Full`. PCR 7 (Secure Boot
/// state) is the separate literal gate ([`LITERAL_PCRS`]), not folded in here.
pub const AUTHORIZED_PCRS: &[u32] = &[11];
/// PCRs covered by linhello's *own* authorized signer on a non-UKI (GRUB)
/// system: PCR 7 (Secure Boot state). Unlike the literal PCR-7 binding, this is
/// self-healing — linhello re-signs the new PCR-7 policy after a firmware/dbx
/// update (while Secure Boot stays enabled), so face unlock survives without a
/// re-enroll. See [`crate::pcrsig`] for the signer.
pub const LINHELLO_SIGNED_PCRS: &[u32] = &[7];
/// PCRs covered by the literal fallback. PCR 7 only — stable across kernel
/// updates (unlike PCR 11).
pub const LITERAL_PCRS: &[u32] = &[7];

/// How a secret should be (or was) bound to the TPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPlan {
    /// `PolicyAuthorize` over `pcrs`, authorized by `pubkey_pem`.
    Authorized {
        pcrs: Vec<u32>,
        pubkey_pem: String,
        policy_ref: Vec<u8>,
    },
    /// Literal `PolicyPCR` over `pcrs` (stable PCRs only).
    Literal { pcrs: Vec<u32> },
    /// No TPM binding.
    None,
}

impl PolicyPlan {
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            // systemd-signed PCR 11 (full boot-chain measurement) is the
            // strongest tier; linhello's own PCR-7 signer is self-healing but
            // coarser (Secure-Boot-state only), so it reports Medium like the
            // literal PCR-7 binding it upgrades.
            PolicyPlan::Authorized { pcrs, .. } if pcrs.as_slice() == AUTHORIZED_PCRS => {
                SecurityLevel::Full
            }
            PolicyPlan::Authorized { .. } => SecurityLevel::Medium,
            PolicyPlan::Literal { .. } => SecurityLevel::Medium,
            PolicyPlan::None => SecurityLevel::Basic,
        }
    }

    /// PCRs replayed via `PolicyPCR` at unseal time.
    pub fn pcrs(&self) -> &[u32] {
        match self {
            PolicyPlan::Authorized { pcrs, .. } | PolicyPlan::Literal { pcrs } => pcrs,
            PolicyPlan::None => &[],
        }
    }
}

/// Decide the binding plan for *this* machine in *its current* state.
pub fn plan() -> PolicyPlan {
    let sb = linhello_secureboot::is_secure_boot_enabled();
    let boot = linhello_secureboot::detect_boot_mode();
    decide(
        sb,
        boot,
        crate::pcrsig::signed_policy_available(),
        || crate::pcrsig::load_pubkey_pem().ok(),
        // Lazily create the per-host signer only when the host-signed path is
        // actually selected, so machines on the systemd or literal paths never
        // grow a signing key.
        || crate::pcrsig::ensure_host_signing_key().ok(),
    )
}

/// Pure decision core, split out for testing. The pubkey loaders are only
/// invoked when their respective authorized path is otherwise viable.
fn decide(
    secure_boot: bool,
    boot: BootMode,
    signed_available: bool,
    load_systemd_pubkey: impl FnOnce() -> Option<String>,
    load_host_pubkey: impl FnOnce() -> Option<String>,
) -> PolicyPlan {
    if !secure_boot {
        return PolicyPlan::None;
    }
    // Strongest: a UKI with a trusted systemd PCR-11 signature.
    if matches!(boot, BootMode::Uki) && signed_available {
        if let Some(pubkey_pem) = load_systemd_pubkey() {
            return PolicyPlan::Authorized {
                pcrs: AUTHORIZED_PCRS.to_vec(),
                pubkey_pem,
                // systemd's signer uses an empty policy reference.
                policy_ref: Vec::new(),
            };
        }
    }
    // Secure Boot on, but no systemd-signed UKI (the common GRUB case, or a UKI
    // without signatures): bind PCR 7 under linhello's OWN authorized signer, so
    // a firmware/dbx update can be healed by re-signing rather than re-enrolling.
    if let Some(pubkey_pem) = load_host_pubkey() {
        return PolicyPlan::Authorized {
            pcrs: LINHELLO_SIGNED_PCRS.to_vec(),
            pubkey_pem,
            policy_ref: Vec::new(),
        };
    }
    // Last resort (host key could not be created): the original literal PCR-7
    // binding — correct, but not self-healing across Secure Boot changes.
    PolicyPlan::Literal {
        pcrs: LITERAL_PCRS.to_vec(),
    }
}

pub fn detect() -> SecurityLevel {
    plan().security_level()
}

/// Legacy helper retained for the diagnostics path: the PCRs a given level
/// binds. New code should use [`PolicyPlan::pcrs`].
pub fn pcrs_for(level: SecurityLevel) -> &'static [u32] {
    match level {
        SecurityLevel::Full => AUTHORIZED_PCRS,
        SecurityLevel::Medium => LITERAL_PCRS,
        SecurityLevel::Basic => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host signer "available" / "unavailable" helpers for readability.
    fn host_ok() -> Option<String> {
        Some("HOSTPEM".into())
    }
    fn host_none() -> Option<String> {
        None
    }

    #[test]
    fn no_secure_boot_is_none() {
        assert_eq!(
            decide(false, BootMode::Uki, true, || None, host_ok),
            PolicyPlan::None
        );
    }

    #[test]
    fn uki_with_signed_policy_is_authorized() {
        let plan = decide(true, BootMode::Uki, true, || Some("PEM".into()), host_ok);
        assert_eq!(
            plan,
            PolicyPlan::Authorized {
                pcrs: vec![11],
                pubkey_pem: "PEM".into(),
                policy_ref: Vec::new()
            }
        );
    }

    #[test]
    fn uki_without_signatures_uses_host_signed_pcr7() {
        // A UKI box with no systemd signature now binds PCR 7 under linhello's
        // OWN signer (self-healing) rather than a fragile literal.
        let plan = decide(true, BootMode::Uki, false, || None, host_ok);
        assert_eq!(
            plan,
            PolicyPlan::Authorized {
                pcrs: vec![7],
                pubkey_pem: "HOSTPEM".into(),
                policy_ref: Vec::new()
            }
        );
    }

    #[test]
    fn signed_but_systemd_pubkey_unreadable_uses_host_signed_pcr7() {
        let plan = decide(true, BootMode::Uki, true, || None, host_ok);
        assert_eq!(
            plan,
            PolicyPlan::Authorized {
                pcrs: vec![7],
                pubkey_pem: "HOSTPEM".into(),
                policy_ref: Vec::new()
            }
        );
    }

    #[test]
    fn secure_boot_grub_is_host_signed_pcr7() {
        // The crux of this change: a GRUB box with Secure Boot on now self-heals
        // via linhello's PCR-7 signer instead of the brittle literal binding.
        let plan = decide(true, BootMode::Grub, true, || Some("PEM".into()), host_ok);
        assert_eq!(
            plan,
            PolicyPlan::Authorized {
                pcrs: vec![7],
                pubkey_pem: "HOSTPEM".into(),
                policy_ref: Vec::new()
            }
        );
    }

    #[test]
    fn host_key_unavailable_falls_back_to_literal() {
        // If the host signing key can't be created, fall back to the original
        // literal PCR-7 binding rather than disabling TPM protection.
        let plan = decide(true, BootMode::Grub, false, || None, host_none);
        assert_eq!(plan, PolicyPlan::Literal { pcrs: vec![7] });
    }
}
