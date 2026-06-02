//! PCR policy selection.
//!
//! Aegyra binds its TPM secrets to one of three plans, chosen at seal time by
//! [`plan`]:
//!
//! * **Authorized** — a `PolicyAuthorize` over the systemd PCR-signing public
//!   key, covering PCR 7 (Secure Boot state) + PCR 11 (UKI). Survives kernel
//!   updates because each new UKI ships a fresh signature for the new PCR 11.
//!   Chosen only when Secure Boot is on, the system booted a UKI, and signed
//!   artifacts (`/run/systemd/tpm2-pcr-{signature.json,public-key.pem}`) exist.
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

use aegyra_common::{BootMode, SecurityLevel};

/// PCRs covered by the signed (authorized) policy on a UKI system.
pub const AUTHORIZED_PCRS: &[u32] = &[7, 11];
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
            PolicyPlan::Authorized { .. } => SecurityLevel::Full,
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
    let sb = aegyra_secureboot::is_secure_boot_enabled();
    let boot = aegyra_secureboot::detect_boot_mode();
    decide(sb, boot, crate::pcrsig::signed_policy_available(), || {
        crate::pcrsig::load_pubkey_pem().ok()
    })
}

/// Pure decision core, split out for testing. `load_pubkey` is only invoked
/// when the authorized path is otherwise viable.
fn decide(
    secure_boot: bool,
    boot: BootMode,
    signed_available: bool,
    load_pubkey: impl FnOnce() -> Option<String>,
) -> PolicyPlan {
    if !secure_boot {
        return PolicyPlan::None;
    }
    if matches!(boot, BootMode::Uki) && signed_available {
        if let Some(pubkey_pem) = load_pubkey() {
            return PolicyPlan::Authorized {
                pcrs: AUTHORIZED_PCRS.to_vec(),
                pubkey_pem,
                // systemd's signer uses an empty policy reference.
                policy_ref: Vec::new(),
            };
        }
    }
    // Secure Boot on, but no usable signed policy → bind PCR 7 only. Coarser
    // than signed PCR 11, but stable across kernel updates.
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

    #[test]
    fn no_secure_boot_is_none() {
        assert_eq!(decide(false, BootMode::Uki, true, || None), PolicyPlan::None);
    }

    #[test]
    fn uki_with_signed_policy_is_authorized() {
        let plan = decide(true, BootMode::Uki, true, || Some("PEM".into()));
        assert_eq!(
            plan,
            PolicyPlan::Authorized {
                pcrs: vec![7, 11],
                pubkey_pem: "PEM".into(),
                policy_ref: Vec::new()
            }
        );
    }

    #[test]
    fn uki_without_signatures_falls_back_to_pcr7_literal() {
        // The crux: a UKI box with no signed policy must NOT bind [7,11]
        // (which breaks on kernel update) — it binds PCR 7 only.
        let plan = decide(true, BootMode::Uki, false, || None);
        assert_eq!(plan, PolicyPlan::Literal { pcrs: vec![7] });
    }

    #[test]
    fn signed_but_pubkey_unreadable_falls_back() {
        let plan = decide(true, BootMode::Uki, true, || None);
        assert_eq!(plan, PolicyPlan::Literal { pcrs: vec![7] });
    }

    #[test]
    fn secure_boot_non_uki_is_pcr7_literal() {
        let plan = decide(true, BootMode::Grub, true, || Some("PEM".into()));
        assert_eq!(plan, PolicyPlan::Literal { pcrs: vec![7] });
    }
}
