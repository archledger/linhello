//! Tiered biometric authentication policy (pure decision logic).
//!
//! See `docs/design/tiered-biometric-policy.md`. The daemon classifies the
//! requesting PAM service, looks up the hardware tier and whether the session is
//! "warm" (a strong auth happened since boot), and decides whether to match-only
//! ([`Action::Verify`]), unseal the credential ([`Action::Unseal`]), or decline
//! ([`Action::Deny`] → PAM cascades to the password). Device-camera binding and
//! anti-downgrade live elsewhere (enforced via `check_camera_binding`).

use serde::{Deserialize, Serialize};

/// Hardware assurance tier, fixed at enrollment by the bound camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// RGB + working active-IR. May unseal the credential and authorize privilege
    /// elevation, behind IR active liveness.
    Secure,
    /// RGB only. Convenience unlock of an already-authenticated live session;
    /// **never** unseals the credential.
    Convenience,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Secure => "secure (RGB + active IR)",
            Tier::Convenience => "convenience (RGB only)",
        }
    }
}

/// What the requesting PAM service is trying to do, derived from its name (and,
/// for greeter services that drive both, whether the session is warm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    /// Unlock an already-authenticated live session (screen lock). The keyring is
    /// already open, so no credential release is needed.
    ScreenUnlock,
    /// Initial login at the greeter. Releases the credential to open the keyring.
    Login,
    /// Privilege elevation: sudo / su / polkit.
    Elevation,
    /// Remote / no local presence: sshd.
    Remote,
    /// Unrecognized service — fail safe.
    Unknown,
}

/// What the daemon should do for an authentication request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Match + liveness only; return success WITHOUT the credential (PAM grants
    /// with no `PAM_AUTHTOK`; the live session's keyring stays as-is).
    Verify,
    /// Match + IR active liveness, then unseal and return the credential.
    Unseal,
    /// Decline; PAM cascades to the password.
    Deny,
}

/// Minimum modality required for an operation class (or disabled).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModalityReq {
    /// Disabled — always defer to password for this operation.
    Off,
    /// RGB (with PAD) is sufficient.
    Rgb,
    /// Requires the secure (IR) tier.
    Ir,
}

impl ModalityReq {
    /// Parse a config value (`off` / `rgb` / `ir`); `None` if unrecognized.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(ModalityReq::Off),
            "rgb" => Some(ModalityReq::Rgb),
            "ir" => Some(ModalityReq::Ir),
            _ => None,
        }
    }
}

/// Per-operation policy. Defaults encode the agreed model: RGB may unlock a live
/// session; everything that releases the credential or elevates needs IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub screen_unlock: ModalityReq,
    pub login: ModalityReq,
    pub sudo: ModalityReq,
    pub polkit: ModalityReq,
    // ssh is always Deny and unknown is always Deny (fail-safe) — not tunable.
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            screen_unlock: ModalityReq::Rgb,
            login: ModalityReq::Ir,
            sudo: ModalityReq::Ir,
            polkit: ModalityReq::Ir,
        }
    }
}

// ── Multi-modality expressions (face / fingerprint / password) ───────────
//
// A per-operation policy value can now be an expression over modalities, so a
// machine with no IR can still get a strong factor from a fingerprint reader:
//   * `face`                  — face only (subject to the face tier, as before)
//   * `fingerprint`           — fprintd only
//   * `face|fingerprint`      — EITHER satisfies (alternation)
//   * `fingerprint+password`  — BOTH required (conjunction)
//   * `off`                   — disabled (defer to password)
// The grammar is disjunctive normal form: `A+B | C+D` = (A AND B) OR (C AND D).

/// An authentication modality linhello can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modality {
    /// Face match (camera; honours the RGB/IR face tier).
    Face,
    /// Fingerprint via fprintd.
    Fingerprint,
    /// The login password (enforced by PAM's password module, not linhello).
    Password,
}

impl Modality {
    fn parse(tok: &str) -> Option<Self> {
        match tok.trim().to_ascii_lowercase().as_str() {
            "face" => Some(Modality::Face),
            "fingerprint" | "finger" | "fp" => Some(Modality::Fingerprint),
            "password" | "passwd" | "pw" => Some(Modality::Password),
            _ => None,
        }
    }
}

/// A per-operation modality expression in DNF: a set of AND-groups, any of which
/// satisfies the operation. An empty `alternatives` means **off** (disabled).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModalityExpr {
    /// Each inner Vec is an AND-group; the outer Vec is OR over them.
    pub alternatives: Vec<Vec<Modality>>,
}

impl ModalityExpr {
    /// Parse `off` / `face` / `face|fingerprint` / `fingerprint+password` / … .
    /// Returns `None` on an unrecognized token so callers can fall back to a
    /// safe default rather than silently mis-parsing a security policy.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("off") || s.is_empty() {
            return Some(ModalityExpr::default());
        }
        let mut alternatives = Vec::new();
        for group in s.split('|') {
            let mut mods = Vec::new();
            for tok in group.split('+') {
                mods.push(Modality::parse(tok)?);
            }
            if mods.is_empty() {
                return None;
            }
            alternatives.push(mods);
        }
        Some(ModalityExpr { alternatives })
    }

    /// True when this operation is disabled.
    pub fn is_off(&self) -> bool {
        self.alternatives.is_empty()
    }

    /// True if any alternative uses `m`.
    pub fn uses(&self, m: Modality) -> bool {
        self.alternatives.iter().any(|g| g.contains(&m))
    }

    /// Given which biometric modalities can actually run right now
    /// (`face_ok`, `fingerprint_ok`), return the first AND-group that is
    /// *satisfiable* by the available biometrics (password is assumed available
    /// — PAM always offers it). `None` means nothing can satisfy this op, so PAM
    /// should fall straight through to the password. This is what the daemon
    /// uses to decide which sensors to engage.
    pub fn satisfiable_group(&self, face_ok: bool, fingerprint_ok: bool) -> Option<&[Modality]> {
        self.alternatives
            .iter()
            .find(|group| {
                group.iter().all(|m| match m {
                    Modality::Face => face_ok,
                    Modality::Fingerprint => fingerprint_ok,
                    Modality::Password => true,
                })
            })
            .map(|g| g.as_slice())
    }
}

/// Classify a PAM service into an operation class. `warm` disambiguates a
/// live-session screen unlock from a fresh greeter login when one service
/// (e.g. `gdm-password`) drives both.
pub fn classify(service: &str, warm: bool) -> OperationClass {
    match service {
        "sudo" | "su" | "su-l" | "runuser" | "polkit-1" => OperationClass::Elevation,
        "sshd" | "remote" => OperationClass::Remote,
        s if is_greeter_or_unlock(s) => {
            if warm {
                OperationClass::ScreenUnlock
            } else {
                OperationClass::Login
            }
        }
        _ => OperationClass::Unknown,
    }
}

/// Services that drive a graphical login and/or screen unlock across the
/// supported desktops. (Elevation/remote handled separately in `classify`.)
fn is_greeter_or_unlock(service: &str) -> bool {
    matches!(
        service,
        "gdm-password"
            | "gdm-fingerprint"
            | "gdm-smartcard"
            | "sddm"
            | "sddm-greeter"
            | "lightdm"
            | "lightdm-greeter"
            | "lightdm-autologin"
            | "login"
            | "system-local-login"
            | "kde"
            | "kscreensaver"
            | "kde-fingerprint"
            | "gnome-screensaver"
            | "xscreensaver"
            | "swaylock"
            | "hyprlock"
    )
}

/// Decide the action for a request. `tier` is the hardware ceiling; `policy`
/// gives the minimum modality per class. Anything that releases the credential
/// (Login) or elevates (Elevation) requires the Secure tier; ScreenUnlock is
/// verify-only and never unseals.
pub fn decide(class: OperationClass, tier: Tier, policy: &Policy) -> Action {
    match class {
        OperationClass::Remote | OperationClass::Unknown => Action::Deny,
        OperationClass::ScreenUnlock => match policy.screen_unlock {
            ModalityReq::Off => Action::Deny,
            ModalityReq::Rgb => Action::Verify, // both tiers can verify-only
            ModalityReq::Ir => {
                if tier == Tier::Secure {
                    Action::Verify
                } else {
                    Action::Deny
                }
            }
        },
        OperationClass::Login => unseal_if_secure(tier, policy.login),
        OperationClass::Elevation => unseal_if_secure(tier, policy.sudo),
    }
}

/// Credential-releasing / elevating ops: only the Secure tier may unseal, and
/// only when the policy isn't `Off`. Otherwise decline (→ password). The
/// Convenience tier can NEVER reach the unseal path.
fn unseal_if_secure(tier: Tier, req: ModalityReq) -> Action {
    if tier == Tier::Secure && req != ModalityReq::Off {
        Action::Unseal
    } else {
        Action::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_distinguishes_login_vs_unlock_by_warmth() {
        assert_eq!(classify("gdm-password", true), OperationClass::ScreenUnlock);
        assert_eq!(classify("gdm-password", false), OperationClass::Login);
        assert_eq!(classify("sudo", true), OperationClass::Elevation);
        assert_eq!(classify("polkit-1", false), OperationClass::Elevation);
        assert_eq!(classify("sshd", true), OperationClass::Remote);
        assert_eq!(classify("some-random-service", true), OperationClass::Unknown);
    }

    #[test]
    fn convenience_tier_never_unseals() {
        let p = Policy::default();
        // Live-session unlock is allowed (verify-only); everything that releases
        // the credential or elevates is denied → password.
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Convenience, &p), Action::Verify);
        assert_eq!(decide(OperationClass::Login, Tier::Convenience, &p), Action::Deny);
        assert_eq!(decide(OperationClass::Elevation, Tier::Convenience, &p), Action::Deny);
        // There is no (class, policy) input that yields Unseal on Convenience.
        for class in [
            OperationClass::ScreenUnlock,
            OperationClass::Login,
            OperationClass::Elevation,
            OperationClass::Remote,
            OperationClass::Unknown,
        ] {
            assert_ne!(decide(class, Tier::Convenience, &p), Action::Unseal);
        }
    }

    #[test]
    fn secure_tier_unseals_for_credential_ops() {
        let p = Policy::default();
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Secure, &p), Action::Verify);
        assert_eq!(decide(OperationClass::Login, Tier::Secure, &p), Action::Unseal);
        assert_eq!(decide(OperationClass::Elevation, Tier::Secure, &p), Action::Unseal);
    }

    #[test]
    fn remote_and_unknown_always_deny() {
        let p = Policy::default();
        for tier in [Tier::Secure, Tier::Convenience] {
            assert_eq!(decide(OperationClass::Remote, tier, &p), Action::Deny);
            assert_eq!(decide(OperationClass::Unknown, tier, &p), Action::Deny);
        }
    }

    #[test]
    fn policy_off_disables_an_operation() {
        let mut p = Policy::default();
        p.screen_unlock = ModalityReq::Off;
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Secure, &p), Action::Deny);
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Convenience, &p), Action::Deny);
    }

    #[test]
    fn modality_expr_parses_alternation_and_conjunction() {
        let either = ModalityExpr::parse("face|fingerprint").unwrap();
        assert_eq!(
            either.alternatives,
            vec![vec![Modality::Face], vec![Modality::Fingerprint]]
        );
        let both = ModalityExpr::parse("fingerprint+password").unwrap();
        assert_eq!(
            both.alternatives,
            vec![vec![Modality::Fingerprint, Modality::Password]]
        );
        assert!(ModalityExpr::parse("off").unwrap().is_off());
        assert!(ModalityExpr::parse("face").unwrap().uses(Modality::Face));
        // Aliases.
        assert_eq!(
            ModalityExpr::parse("fp+pw").unwrap().alternatives,
            vec![vec![Modality::Fingerprint, Modality::Password]]
        );
        // Unknown token → None (caller keeps the safe default).
        assert!(ModalityExpr::parse("retina").is_none());
        assert!(ModalityExpr::parse("face+").is_none());
    }

    #[test]
    fn satisfiable_group_picks_available_modalities() {
        let e = ModalityExpr::parse("face|fingerprint").unwrap();
        // No IR/face working, but a reader is enrolled → fingerprint alternative.
        assert_eq!(
            e.satisfiable_group(false, true),
            Some(&[Modality::Fingerprint][..])
        );
        // Face works → first alternative (face) wins.
        assert_eq!(e.satisfiable_group(true, false), Some(&[Modality::Face][..]));
        // Neither biometric available → nothing to engage (fall through to pw).
        assert_eq!(e.satisfiable_group(false, false), None);

        // Conjunction needs the biometric half present; password is implicit.
        let both = ModalityExpr::parse("fingerprint+password").unwrap();
        assert_eq!(
            both.satisfiable_group(false, true),
            Some(&[Modality::Fingerprint, Modality::Password][..])
        );
        assert_eq!(both.satisfiable_group(false, false), None);
    }

    #[test]
    fn screen_unlock_can_require_ir() {
        let mut p = Policy::default();
        p.screen_unlock = ModalityReq::Ir;
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Secure, &p), Action::Verify);
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Convenience, &p), Action::Deny);
    }
}
