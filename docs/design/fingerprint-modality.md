# LinuxHello: Fingerprint as a First-Class Secure-Tier Method

**Status:** **Phase 1 implemented** (tier/method model, detection, suggestion,
CLI + `pam_fprintd` wiring). Phase 2 (greeter method-chooser) is deferred — see §5.
**Goal:** Treat fingerprint as a standalone **secure-tier** unlock method
(equal to IR face), never combined with face. linhello picks a sensible default
for the detected hardware, lets the user switch to any method their hardware
supports, and explains the trade-off when they pick a weaker one.

---

## 1. Why

The convenience tier (RGB only, no active-IR liveness) never releases the
credential and never elevates — it only verify-unlocks a live session. Many such
laptops (e.g. this ThinkPad) ship a **fingerprint reader**, which *is* strong
enough for login/sudo. So when linhello detects "RGB-only face **and** a
fingerprint reader," it should suggest fingerprint and let the user opt in —
without forcing it, and without weakening the face-only path for anyone else.

## 2. Backend: fprintd, not a new driver

linhello does **not** talk to the sensor directly. It drives **fprintd** (the
standard Linux fingerprint service that owns libfprint), so there is exactly one
owner of the hardware and no device-claim fights with `pam_fprintd`. To stay
dependency-light (the rest of linhello avoids an async D-Bus stack) and keep the
daemon's sync `spawn_blocking` model, the backend (`crates/linhello-fingerprint`)
uses fprintd's shipped tooling via **absolute paths** (no `$PATH` trust on the
auth-critical verify):

| Need | Mechanism |
|---|---|
| Reader present? | `busctl tree net.reactivated.Fprint` → has `…/Device/N` |
| Device name | `busctl get-property … Device/0 name` |
| Enrolled fingers | `fprintd-list <user>` |
| Verify | `fprintd-verify <user>` → parse `verify-match` |

(A future swap to a typed `zbus` client is possible without changing callers.)

## 3. Methods & tiers — NOT combined

Each method is a single authenticator with a fixed tier
(`linhello_common::biopolicy::UnlockMethod`):

| Method | Tier | Can unlock |
|---|---|---|
| `face-rgb` | Convenience | live-session screen unlock only |
| `face-ir` | Secure | screen unlock + login + sudo + polkit |
| `fingerprint` | Secure | screen unlock + login + sudo + polkit |

Methods are **never** combined (no `face+fingerprint`, no `fingerprint+password`).
A single secure method already unlocks everything; the password is always the
universal fallback (enforced by PAM), so it needs no explicit conjunction.

`AvailableMethods` (what the host detects: RGB cam, IR cam, enrolled fingerprint)
drives selection:

| Detected | Default | User may also pick |
|---|---|---|
| RGB only | `face-rgb` (convenience) | — |
| RGB + fingerprint | **`fingerprint`** (secure) | `face-rgb` (convenience, with limits explained) |
| RGB + IR | `face-ir` (secure) | `face-rgb` |
| RGB + IR + fingerprint | `face-ir` (secure) — **user is asked**, both are secure | `fingerprint`, `face-rgb` |

`default_method()` / `selectable()` / `needs_user_choice()` implement this. The
chosen method is recorded in `/etc/linhello/policy.conf` (`method = …`).

## 4. Mechanism: fprintd via `pam_fprintd`

Fingerprint verification is done by **`pam_fprintd`** in the PAM stack, *not* by
linhello. linhello detects the reader, recommends the tier/method, and **wires
`pam_fprintd`** for the fingerprint method (per distro). This is the standard
integration, avoids any device-claim fight, and is what lets the desktop greeter
show fingerprint natively. The face method stays handled by `pam_linhello`.

## 5. What ships in Phase 1

- `linhello-fingerprint` crate: `available()`, `reader_present()`,
  `device_name()`, `enrolled_fingers()`, `has_enrollment()` (detection only —
  verification belongs to `pam_fprintd`).
- `UnlockMethod` / `AvailableMethods` tier-selection model in `biopolicy`,
  unit-tested.
- `doctor`: a **Fingerprint** line framing it as a secure-tier method (the
  default on RGB-only machines, or an equal alternative to IR face).
- CLI: `linhello fingerprint status` (reader, methods, default, suggestion) and
  `linhello fingerprint enable` (enroll via `fprintd-enroll`, then wire
  `pam_fprintd`: `pam-auth-update --enable fprintd` on Debian; authselect
  feature on Fedora; manual stanza guidance elsewhere).
- **Wizards**: both the headless `setup` and the **TUI** (`linhello tui`) now
  include a fingerprint step. The TUI gains a dedicated **Fingerprint** screen
  (after Identify, before Password) that shows the reader, the detected
  methods/tiers, the recommended default, and — on `e` — suspends the
  full-screen view to run the interactive `fprintd-enroll` + PAM wiring, then
  resumes. It is an optional step (does not gate progression).

RGB-only face is unchanged; fingerprint is additive and opt-in.

## 6. Phase 2 roadmap

1. **`method` in policy.conf**: have the daemon read the chosen method and
   reflect it in `doctor`/`policy-status` (the per-method PAM wiring already
   makes it functional; this is reporting/consistency).
2. **Greeter method-chooser** ("like Windows 11"): investigate per-desktop. On
   GDM, fingerprint + password appear natively once `pam_fprintd` is wired; a
   polished click-to-choose chooser is limited by the greeter, not linhello.
   KDE/SDDM differ. Deferred until the core is validated in the field.
4. **Validation**: end-to-end login/sudo with a physically enrolled finger
   (Phase 1 validated detection + the tier-selection model; live auth runs
   through `pam_fprintd`).
