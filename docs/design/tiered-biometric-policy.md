# Tiered Biometric Policy (hardware-adaptive RGB / RGB+IR)

Status: **implemented** — shipped in v0.3.0 (originally scoped 2026-06-17 as a
design proposal). This doc now describes the as-built system; the design rationale
is preserved below. Supersedes the binary `LINHELLO_REQUIRE_IR` behaviour.
Rationale and evidence: [`rgb-liveness-research.md`](rgb-liveness-research.md).

## 1. Problem & goals

linhello must work on the hardware people actually have. Most laptops are
**RGB-only** (no IR/depth/structured-light). Today `LINHELLO_REQUIRE_IR`
hard-fails there, so linhello is unusable on the majority of machines.

But the research is unambiguous: software-only RGB presentation-attack detection
(PAD) — including the MiniFASNet/Silent-Face class we ship — collapses from
~1.6% ACER in-dataset to **12–14% HTER across unseen cameras/lighting** (best-in-
class domain-generalisation still ~10%). Single-frame passive PAD is explicitly
"suitable only [for] use cases where the transactions are low valued and the
sensor platform is trusted and secured." A general-purpose UVC webcam is an
untrusted, uncertifiable sensor, and **releasing the TPM-sealed login password is
a high-value, crypto-bound transaction.** Every certified system (Windows Hello,
Face ID, Pixel) relies on IR/depth hardware; the standards encode this — Android
reserves crypto/Keystore for **Class 3 "Strong" (SAR ≤7%)** and relegates
weak/insecure pipelines to **Class 1 "Convenience" (SAR 20–30%), device-unlock
only, never releasing keys.**

**Goal:** adapt to detected hardware and gate operations by *what they cost*:

- **RGB+IR machines** → a "secure" tier (≈ Class 3 aspiration): face may unseal
  the password and authorise privilege elevation, backed by IR active liveness.
- **RGB-only machines** → a "convenience" tier (≈ Class 1): face may unlock an
  **already-authenticated live session** *without ever unsealing the password*,
  and must defer to the password for everything else.

**Non-goals:** claiming RGB-only is "secure"; meeting FIDO/ISO 30107-3/Android
Class 3 on RGB-only (not achievable on uncertifiable hardware); active
screen-flashing PAD (the daemon has no display and the lock screen is owned by
the compositor — architecturally unavailable).

## 2. The core insight — gate on credential release, not the PAM service name

The decision axis is **"does this operation release the sealed secret or elevate
privilege?"** not "which greeter is it." On GNOME a single PAM service
(`gdm-password`) drives *both* login and screen-unlock, so the service name alone
is insufficient.

| Operation | Releases credential? | Tier required | RGB-only outcome |
|---|---|---|---|
| Unlock an already-logged-in session (screen lock) | No — keyring already open from login | **RGB-OK** (verify-only) | **Allow** (no unseal) |
| Initial login at greeter | Yes — unseals password to open keyring | **IR (secure)** | Deny → password |
| `sudo` / `su` / `polkit-1` | Privilege elevation (uses unsealed password) | **IR (secure)** | Deny → password |
| `sshd` / remote | No local presence | **Never** | Deny |
| unknown service | — | **Deny (fail-safe)** | Deny → password |

**Why this is self-consistent and safe:** the convenience tier *never calls the
TPM unseal path*. So an RGB-only machine **cannot** perform any credential-
releasing operation by face — it is structurally forced to the password for
login/sudo. This mirrors Android exactly: after reboot you must enter the
credential once (here: the greeter login, which RGB-only can't do by face, so you
type the password); that login creates the session and opens the keyring; only
*then* can the weak modality unlock the (now warm) session.

## 3. Two auth modes

| Mode | What it does | Used for | TPM? |
|---|---|---|---|
| **Verify** | Capture → match embedding → liveness/PAD check → return REAL/MATCH boolean. **Never touches the sealed envelope.** | Live-session screen unlock (both tiers) | No |
| **Unseal** | Verify **+ require IR active liveness** → unseal the TPM envelope → return the password as `PAM_AUTHTOK`. | Login, sudo, polkit (secure tier only) | Yes |

For a screen unlock, `Verify` returning success makes the PAM stack grant
(`auth sufficient pam_linhello.so`) **without setting `PAM_AUTHTOK`**; the keyring
is already open from login, so nothing needs the password. This is the small but
essential architectural change that makes RGB-only defensible.

## 4. "Warm session" detection (strong-auth-since-boot)

`Verify`-unlock is permitted only when the session is **warm**: a strong
authentication (credential or IR-face) has occurred for this user since boot.
linhello does not need to see the password — it uses **systemd-logind** on the
*system* bus (the daemon is root; no session-bus access needed):

- **Primary signal:** does the target uid have an `active`/`online` logind
  session? A graphical session only exists because a credential created it this
  boot. Read `sd_uid_get_state(uid)` (libsystemd) or `/run/systemd/users/<uid>`
  → `STATE=`. A screen-unlock by definition has a live (locked) session; a fresh
  greeter login does not.
- **Optional Android-style re-arming:** require a fresh strong auth after
  `strong_reauth_after_hours` (default 12) or after N consecutive RGB unlocks.
  The daemon stamps the last strong-auth time per user (it sees every `Unseal`;
  for password-only logins it treats "session created" as the strong event).
- **Known edge — autologin:** with autologin a session exists with *no* credential
  entered. `doctor` warns, and `screen_unlock=rgb` is downgraded to require a
  one-time strong auth (or the keyring-unlocked cross-check, §9) before the first
  RGB unlock. Safer default on autologin systems: convenience tier off.

SELinux: `linhellod_t` needs to read logind state — add `init_read_state` /
`systemd_read_unit_files`-equivalent (or read `/run/systemd/users`) to
`etc/selinux/linhello-daemon.te`.

## 5. Hardware tier detection

Reuse the existing IR detection (`doctor`'s "active-IR liveness available" vs "no
NIR sensor"). The tier must reflect **working** active-IR — a dark IR stream with
the emitter off is *not* the secure tier (we fought for emitter activation;
`ir_emitter.rs`). So:

- `Tier::Secure` (RGB+IR) ⟺ a configured IR device produces a live IR-liveness
  signal (IR score / eye-glint above threshold during a probe), **and** the
  emitter activates. Surfaced as a capability.
- `Tier::Convenience` (RGB) otherwise.

A machine with an IR sensor whose emitter can't be driven falls back to
Convenience (honest).

## 5a. Device integrity & anti-downgrade (ALREADY IMPLEMENTED — do not rebuild)

The camera is bound to the enrollment ("soft-SDCP"). At enroll, the daemon
snapshots each camera's USB identity — **vid, pid, serial** — into
`/etc/linhello/<user>/camera_binding.json` (`linhello-liveness::device_binding`).
The check is **enforced in the auth path**: `do_unseal_password` and `do_verify`
both call `load_user_samples()`, which calls `check_camera_binding()` →
`CameraBinding::verify()` before any match. Consequences, which satisfy the
stated requirements directly:

- **No device swap.** A different camera (vid/pid/serial mismatch) makes
  `load_user_samples` fail → face auth declines → password → **re-enroll
  required.** Exact-unit when a serial is present.
- **No silent downgrade / disconnect = dark.** `verify()` returns
  *"IR camera was present at enrollment but is now missing"* when an
  enrolled IR camera is gone → face auth declines → password. A secure-tier
  machine that loses its (USB) IR camera therefore goes to password, never to
  RGB-convenience on some other sensor. Reconnect → works again.

**Caveat (honest, surface in `doctor`):** serial-less webcams (e.g. NexiGo N930W,
`serial=""`) bind at **model level** (vid/pid/name) only — two identical units
are indistinguishable. No per-unit USB identifier exists for them; this is the
ceiling, not a bug. Devices exposing a serial get true exact-unit binding.

The tier in §5 therefore composes with binding: **tier is fixed at enrollment by
the bound camera's capability.** Losing that camera fails safe (password); it is
never re-derived from whatever sensor happens to be present.

## 6. IPC protocol changes (`crates/linhello-common/src/ipc.rs`)

Policy lives in the daemon; the PAM module just passes context and reacts. As
shipped, `Authenticate` was **added alongside** the existing `Verify` / `Unseal` /
`UnsealPassword` requests (those are retained; `Authenticate` routes to the same
verify / unseal paths after the policy decision):

```rust
// Tiered PAM entry point (service from pam_get_item(PAM_SERVICE)):
Request::Authenticate { user: String, service: String }

// Pre-flight: same classify → tier → decide, but no capture — so the PAM module
// only prints "Looking for your face…" when the daemon would actually engage:
Request::AuthIntent { user: String, service: String }
    -> Response::AuthPlan { engage: bool, action }

// Read-only tier/policy report that backs `doctor` and the TUI (§11):
Request::PolicyStatus { user: String }
    -> Response::PolicyStatus { tier, secure, hardware_tier, overridden,
                                enrolled, hardware_ready, hardware_note, ops }

// Authenticate resolves to one of:
Response::PasswordUnsealed { secret: SecretBytes }  // secure tier: set PAM_AUTHTOK, PAM_SUCCESS
Response::Verified { matched, score, threshold }    // convenience: PAM_SUCCESS, NO AUTHTOK
Response::Error { message: String }                 // denial / any error → PAM_IGNORE → password
```

(`ResealUserEnvelopes`, `Probe`, etc. are unchanged. Note there is no
`Response::Denied`; denials are `Response::Error`.)

## 7. Daemon policy engine (`crates/linhello-daemon`)

```text
on Authenticate { user, service }:
    class  = classify(service)              // ScreenUnlock | Login | Elevation | Remote | Unknown
    tier   = hardware_tier()                // Secure | Convenience
    warm   = logind_session_active(user)    // STATE=active|online for the uid
                                            // (the reauth-window AND is a future P1 add — §10)
    action = policy.decide(class, tier, warm)   // Verify | Unseal | Deny
    match action:
      Deny           -> Error{message}            // never starts the camera/ML
      Verify         -> capture+match+PAD (RGB-hardened); ok -> Verified else Error
      Unseal         -> require IR liveness; capture+match+IR; ok -> unseal -> PasswordUnsealed else Error
```

`classify(service)` maps the per-distro service names linhello already enumerates
(`pamwire`): greeter/unlock services → ScreenUnlock or Login (disambiguated by
`warm`/logind), `sudo|su|polkit-1` → Elevation, `sshd|remote` → Remote, else
Unknown. **Deny short-circuits before loading buffalo_l or opening the camera** —
no inference, no IR strobe, for a denied request.

Crucially: in `Tier::Convenience`, `Unseal` is **never** a possible action — even
for login/sudo the engine returns `Deny` (→ password). The TPM unseal code path
is only reachable from `Tier::Secure`.

## 8. PAM module (`pam/pam_linhello.c` + `crates/linhello-pam`)

**As shipped, the decision moved into the daemon, keyed on service + tier + warm.**
The prior behaviour this replaced split the two modes by **euid** in
`pam_sm_authenticate`: a non-root caller (e.g. KDE kscreenlocker as the session
user) ran Verify (no AUTHTOK); a root caller (gdm-session-worker, sudo) unsealed
the password → AUTHTOK. That heuristic did no hardware-tier gating, and on
**GNOME the lock screen runs as root**, so a screen-unlock would *unseal the
password* — exactly the Class-1-violating credential release §2 stops. Now the
PAM module passes `PAM_SERVICE` and the daemon decides:

1. `pam_get_item(pamh, PAM_SERVICE, &svc)`; if missing → return `PAM_IGNORE`
   (fail-safe to password). `svc` is sent in `Authenticate`.
2. On `PasswordUnsealed{secret}` → `pam_set_item(PAM_AUTHTOK)` + return `PAM_SUCCESS`.
3. On `Verified` → return `PAM_SUCCESS` (do **not** set AUTHTOK).
4. On `Error` / any decline → return `PAM_IGNORE` so the stack cascades to
   `pam_unix` (password). Never `PAM_AUTH_ERR` (that would just be a logged
   failure; IGNORE is cleaner and the password is always the floor).

The shipped PAM line stays `auth sufficient pam_linhello.so`, so success grants
and decline/deny cascades — unchanged wiring.

## 9. PAD hardening for the convenience (RGB) tier

The research says these are marginal but cheap, and they harden the one tier we
actually trust least. Apply **only** to RGB `Verify` (IR path already stronger):

1. **Multi-frame consensus** — the burst we already capture must agree REAL across
   N frames (kills single-frame noise; current MiniFASNet `real_score` is jittery
   0.54–0.84).
2. **Eyes-open / gaze** — from the detector's landmarks (SCRFD 5-pt; optionally
   add iris): require open eyes looking at the camera. Cheap, low friction.
3. **Modality-specific threshold** — a *stricter* spoof threshold for the RGB
   tier than the IR tier (we trust it less). New `LINHELLO_SPOOF_THRESHOLD_RGB`.
4. **Screen-replay heuristics (optional, phase 2)** — moiré / bezel / over-uniform
   specular tells from the existing frames.
5. **Keyring cross-check (optional)** — as a secondary warm signal / autologin
   guard, confirm the login keyring is unlocked before an RGB unlock.

No rPPG (defeated by video), no depth-from-motion per-unlock (friction; weak), no
recognition-stack swap (buffalo_l/ArcFace already ≥ FaceNet).

## 10. Configuration (`/etc/linhello/policy.conf`, `key=value`)

Matches the project's existing kv config style (`cameras.conf`, …), read via
`config::read_kv`. Implemented in P0:

```ini
# Tier override (the design's tier.mode): auto | secure | convenience.
# auto (default) = the enrolled hardware; convenience caps it down.
tier=auto

# Minimum modality per operation class: off | rgb | ir.
screen_unlock=rgb     # rgb ⇒ verify-only, never unseals
login=ir              # rgb can't unseal anyway ⇒ password
sudo=ir
polkit=ir
# ssh and unknown services are always denied (fail-safe; not tunable).
```

Defaults (no file) are the conservative model: IR for everything that releases
the credential or elevates; RGB only for live-session unlock; deny the unknown.

P1 additions (not yet implemented): warm-reauth timeout / autologin guard, and
the RGB PAD-hardening knobs (multi-frame consensus, eyes-open, RGB-specific spoof
threshold).

## 11. `doctor` / honesty surfacing

`doctor` reports the **detected tier** and the **effective policy**, in plain
language:

```
Biometric tier : convenience (RGB only — no working IR sensor)
  screen unlock: face  (convenience — resists casual photo/screen, NOT a
                        motivated attacker; never releases your password)
  login / sudo : password required (IR sensor needed for face here)
```

vs on RGB+IR:

```
Biometric tier : secure (RGB + active IR)
  screen unlock / login / sudo : face (IR active liveness)
```

This is the load-bearing honesty: the convenience tier is labelled as such, and
the user is told exactly what it does and doesn't defend.

## 12. Security analysis (mapping to the standards)

- **Convenience tier = Android Class 1 equivalent.** Insecure/uncertifiable
  sensor, device-unlock-only, **never releases keys** (we enforce no-unseal).
  Threat covered: opportunistic photo/screen at a *locked, already-logged-in*
  machine. Not covered: motivated attacker with a good print/replay — but the
  blast radius is a session whose keyring is already open and which the attacker
  with physical access could often reach anyway; **no credential, no root.**
- **Secure tier ≈ Android Class 3 aspiration.** IR active liveness gates unseal
  and elevation. IR defeats the accessible photo/LCD-replay attacks (IR doesn't
  render in photos/screens); not absolute (cf. CVE-2021-34466 IR-printout), but
  an order of magnitude above RGB.
- **Why the daemon, not the PAM client, holds policy:** the service name is set
  by the caller, but the socket is `root:linhello 0660` — only already-privileged
  callers (sudo, gdm-session-worker-as-root) can reach the daemon at all, so an
  unprivileged process can't present `service=gdm-password` to get the lax tier.
- **Password is always the floor.** Every deny/decline/error → `PAM_IGNORE` →
  `pam_unix`. TTY (Ctrl-Alt-F2) untouched.

## 13. Failure / fallback behaviour

Any uncertainty fails to the password, never opens access: missing service,
unknown service, daemon unreachable, capture/liveness failure, cold session for a
convenience-tier unlock, IR required but absent → all `Denied`/`PAM_IGNORE`.

## 14. Phasing

- **P0 (enables RGB machines):** Verify mode + `Authenticate{service}` IPC + the
  policy engine + logind warm-check + capability tier + config + `doctor`. Ships
  RGB-only convenience unlock and removes the hard `REQUIRE_IR` wall. Secure tier
  = today's behaviour routed through the engine.
- **P1 (hardening):** RGB PAD adds (multi-frame, eyes-open, modality threshold),
  reauth timeout, autologin guard, SELinux logind rule.
- **P2 (optional):** screen-replay heuristics, keyring cross-check, per-op config
  UI in the TUI.

## 15. Test plan (this box can cover both tiers)

This machine has working RGB **and** active IR (NexiGo, emitter validated), so:

- **Secure tier:** IR present → login/sudo unseal works (regression of today).
- **Convenience tier (forced):** set `tier.mode = "convenience"` (or hide the IR
  device) → screen-unlock succeeds via `Verify` with **no `UnsealPassword` in the
  daemon log**; login/sudo by face are **Denied → password**; cold-boot (no warm
  session) screen-unlock is **Denied**.
- **Policy/PAD unit tests:** `classify(service)`, `decide(class,tier,warm)`,
  multi-frame consensus, fail-safe on unknown service.
- **SELinux:** confirm zero `linhellod_t` AVCs for the logind read under enforcing.

## 16. Open questions

1. Measure the *actual* shipped pipeline (buffalo_l + MiniFASNet) APCER/BPCER on
   this box's webcam in varied lighting — replace borrowed benchmark numbers with
   a real number for the convenience tier (research open-question #1).
2. Exact logind signal portability across non-systemd setups (rare for the target
   distros; fall back to keyring-unlocked check).
3. Whether `screen_unlock` should default `off` (most conservative) and require an
   explicit opt-in, given the convenience tier still grants session access.
