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

// ── Unlock methods & tier selection (face / fingerprint) ─────────────────
//
// Methods are NOT combined. Each is a single authenticator with a fixed tier:
//   * FaceRgb      — RGB-only face → Convenience (live-session unlock only)
//   * FaceIr       — RGB+IR face   → Secure (login / sudo / polkit)
//   * Fingerprint  — fprintd       → Secure (login / sudo / polkit)
// linhello picks a sensible default for the detected hardware and lets the user
// switch to any other method their hardware supports (explaining the trade-off
// when they pick a weaker one).

/// A concrete unlock method, each tied to exactly one authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockMethod {
    /// RGB-only face — convenience tier.
    FaceRgb,
    /// RGB+IR face with active-IR liveness — secure tier.
    FaceIr,
    /// Fingerprint via fprintd — secure tier.
    Fingerprint,
}

impl UnlockMethod {
    /// The assurance tier this method provides.
    pub fn tier(self) -> Tier {
        match self {
            UnlockMethod::FaceRgb => Tier::Convenience,
            UnlockMethod::FaceIr | UnlockMethod::Fingerprint => Tier::Secure,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            UnlockMethod::FaceRgb => "face-rgb",
            UnlockMethod::FaceIr => "face-ir",
            UnlockMethod::Fingerprint => "fingerprint",
        }
    }

    /// Human label for prompts / doctor.
    pub fn label(self) -> &'static str {
        match self {
            UnlockMethod::FaceRgb => "face (RGB only, convenience)",
            UnlockMethod::FaceIr => "face (RGB + IR, secure)",
            UnlockMethod::Fingerprint => "fingerprint (secure)",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "face-rgb" | "rgb" => Some(UnlockMethod::FaceRgb),
            "face-ir" | "ir" => Some(UnlockMethod::FaceIr),
            "fingerprint" | "finger" | "fp" => Some(UnlockMethod::Fingerprint),
            _ => None,
        }
    }
}

/// Which methods this host can actually offer right now (hardware present and,
/// for biometrics, enrolled). Derived by the daemon from camera + fprintd probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AvailableMethods {
    /// RGB camera usable for face.
    pub face_rgb: bool,
    /// IR camera present (secure face possible).
    pub face_ir: bool,
    /// Fingerprint reader present with at least one enrolled finger.
    pub fingerprint: bool,
}

impl AvailableMethods {
    /// Every method the user may select on this host, strongest tier first.
    /// (FaceRgb is always offered when an RGB camera exists, as the
    /// convenience-tier opt-down.)
    pub fn selectable(self) -> Vec<UnlockMethod> {
        let mut v = Vec::new();
        if self.face_ir {
            v.push(UnlockMethod::FaceIr);
        }
        if self.fingerprint {
            v.push(UnlockMethod::Fingerprint);
        }
        if self.face_rgb {
            v.push(UnlockMethod::FaceRgb);
        }
        v
    }

    /// The method linhello defaults to: a secure method when one exists,
    /// otherwise the convenience RGB face. `None` means no biometric method is
    /// available at all (password only). When BOTH secure methods exist the
    /// default is `FaceIr` but the user is expected to be offered the choice
    /// (see [`needs_user_choice`]).
    pub fn default_method(self) -> Option<UnlockMethod> {
        if self.face_ir {
            Some(UnlockMethod::FaceIr)
        } else if self.fingerprint {
            Some(UnlockMethod::Fingerprint)
        } else if self.face_rgb {
            Some(UnlockMethod::FaceRgb)
        } else {
            None
        }
    }

    /// True when two distinct *secure* methods exist (IR face AND fingerprint),
    /// so linhello should let the user pick rather than silently defaulting.
    pub fn needs_user_choice(self) -> bool {
        self.face_ir && self.fingerprint
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
    fn method_tiers_are_correct() {
        assert_eq!(UnlockMethod::FaceRgb.tier(), Tier::Convenience);
        assert_eq!(UnlockMethod::FaceIr.tier(), Tier::Secure);
        assert_eq!(UnlockMethod::Fingerprint.tier(), Tier::Secure);
        assert_eq!(UnlockMethod::parse("fp"), Some(UnlockMethod::Fingerprint));
        assert_eq!(UnlockMethod::parse("face_ir"), Some(UnlockMethod::FaceIr));
        assert_eq!(UnlockMethod::parse("nope"), None);
    }

    #[test]
    fn rgb_only_defaults_to_convenience() {
        let av = AvailableMethods { face_rgb: true, face_ir: false, fingerprint: false };
        assert_eq!(av.default_method(), Some(UnlockMethod::FaceRgb));
        assert!(!av.needs_user_choice());
        assert_eq!(av.selectable(), vec![UnlockMethod::FaceRgb]);
    }

    #[test]
    fn rgb_plus_fingerprint_defaults_to_secure_fingerprint() {
        // The user's example: RGB-only camera + fingerprint → default to the
        // secure fingerprint method, but still offer RGB-only as an opt-down.
        let av = AvailableMethods { face_rgb: true, face_ir: false, fingerprint: true };
        assert_eq!(av.default_method(), Some(UnlockMethod::Fingerprint));
        assert!(!av.needs_user_choice()); // only one secure method
        assert_eq!(
            av.selectable(),
            vec![UnlockMethod::Fingerprint, UnlockMethod::FaceRgb]
        );
    }

    #[test]
    fn ir_only_is_secure_face() {
        let av = AvailableMethods { face_rgb: true, face_ir: true, fingerprint: false };
        assert_eq!(av.default_method(), Some(UnlockMethod::FaceIr));
        assert!(!av.needs_user_choice());
    }

    #[test]
    fn ir_and_fingerprint_lets_user_choose() {
        // Both secure → linhello should prompt rather than silently picking.
        let av = AvailableMethods { face_rgb: true, face_ir: true, fingerprint: true };
        assert!(av.needs_user_choice());
        assert_eq!(
            av.selectable(),
            vec![UnlockMethod::FaceIr, UnlockMethod::Fingerprint, UnlockMethod::FaceRgb]
        );
    }

    #[test]
    fn no_biometrics_means_password_only() {
        let av = AvailableMethods::default();
        assert_eq!(av.default_method(), None);
        assert!(av.selectable().is_empty());
    }

    #[test]
    fn screen_unlock_can_require_ir() {
        let mut p = Policy::default();
        p.screen_unlock = ModalityReq::Ir;
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Secure, &p), Action::Verify);
        assert_eq!(decide(OperationClass::ScreenUnlock, Tier::Convenience, &p), Action::Deny);
    }
}
