# LinuxHello: Fingerprint as a First-Class Modality

**Status:** **Phase 1 implemented** (detection, suggestion, modality-expression
engine, CLI). Phase 2 (daemon auth orchestration + PAM composition) is
roadmapped below.
**Goal:** On machines with an **RGB-only** camera (no IR → convenience tier),
let the user add a **fingerprint** as a stronger factor, while keeping RGB-only
face fully usable for those who prefer it. Fingerprint becomes a first-class
modality the policy engine can require, suggest, and combine with face/password.

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

## 3. Policy model: modality expressions

`policy.conf` per-operation values become expressions over
`{face, fingerprint, password}` in disjunctive normal form
(`linhello_common::biopolicy::ModalityExpr`):

```
screen_unlock = face|fingerprint     # EITHER unlocks
sudo          = fingerprint          # touch to elevate
login         = fingerprint+password # BOTH required
polkit        = off                  # always password
```

`|` is alternation (any AND-group satisfies); `+` is conjunction (all of the
group). `ModalityExpr::satisfiable_group(face_ok, fingerprint_ok)` picks the
first group the currently-available biometrics can satisfy, so the daemon knows
which sensors to engage and when to fall through to the password.

## 4. What ships in Phase 1

- `linhello-fingerprint` crate: `available()`, `reader_present()`,
  `device_name()`, `enrolled_fingers()`, `has_enrollment()`, `verify()`.
- `doctor`: a **Fingerprint** line — on RGB-only machines it suggests enrolling
  a fingerprint as a stronger factor; otherwise notes it as an optional second
  factor. Absent reader → no line (no clutter).
- CLI: `linhello fingerprint status` (reader, tier, enrolled fingers) and
  `linhello fingerprint enable` (guides `fprintd-enroll`).
- `ModalityExpr` parser + decision helper, unit-tested.

RGB-only face is unchanged: fingerprint is purely additive and opt-in.

## 5. Phase 2 roadmap (daemon orchestration + PAM)

1. **policy.conf**: parse the per-operation values as `ModalityExpr` (keep the
   existing `off/rgb/ir` face values working — map them onto `face` expressions).
2. **Daemon** `do_authenticate` / `do_auth_intent`: compute
   `face_ok` (tier + enrollment) and `fingerprint_ok`
   (`linhello_fingerprint::has_enrollment`), pick the satisfiable group, and
   engage the modalities in order (face capture, then fingerprint `verify`),
   returning success only when a full AND-group passes. Convenience-tier
   credential release stays gated: a biometric group that includes `password`
   (or any login/elevation op) still defers the secret to PAM's password module.
3. **PAM**: the `password` conjunct is enforced by composing `pam_unix` after
   `pam_linhello` (linhello cannot verify passwords itself). The PAM-wiring layer
   (`pamwire.rs`) emits the right stanza ordering per the policy. `pam_fprintd`
   is **not** added to the stack — linhello owns the fingerprint modality.
4. **Enrollment UX**: offer fingerprint in `setup` when RGB-only + reader, and
   record per-user opt-in.
5. **Validation**: end-to-end with a really-enrolled finger on the Synaptics
   reader (Phase 1 validated detection + the no-enrollment fall-through; a live
   match needs a physically enrolled print).
