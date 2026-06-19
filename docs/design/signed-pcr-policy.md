# LinuxHello: Update-Resilient TPM Binding via Signed PCR Policy

**Status:** **Implemented** — signed PCR-11 policy is live (the Arch reference box
runs it). Originally a scoping/design proposal (2026-06-02); this is now the
as-built record. Two things landed differently from the proposal below and are
corrected inline: the authorized policy binds **PCR 11 only** (not `[7, 11]` — §3),
and the §5 security must-fix items are **resolved**.

> **Update (2026-06-19) — GRUB self-heal landed (§8).** The non-UKI path no
> longer uses a *fragile literal* PCR-7 binding. On GRUB (and any Secure-Boot
> system without a systemd-signed UKI), linhello now acts as **its own
> PolicyAuthorize signer over PCR 7** and re-signs the new PCR-7 state after a
> firmware/dbx update (while Secure Boot stays on) — so face unlock self-heals
> with **no re-enroll**. This is approach **C**, which §7 Decision 1 had
> deferred; it is now adopted *specifically for the non-UKI case* (UKI still uses
> systemd's PCR-11 signature — approach B). A dedicated **recovery passphrase**
> (separate from the login password) is the manual backstop. See §8.

**Author:** LinuxHello maintainers
**Goal:** Make LinuxHello a Windows-Hello-class facial unlock for Linux that survives
kernel, initrd, microcode, and systemd-stub updates **without breaking face auth
or requiring biometric re-enrollment.**

---

## 1. Problem statement

LinuxHello seals two per-user secrets in the TPM:

- the **template key** (`template_key_envelope.json`) — the AES-256-GCM key that
  encrypts the face embedding at rest (`embedding.enc`);
- the **password envelope** (`password_envelope.json`) — the login password used
  to unlock the GNOME/KWallet keyring (Design B).

Both are sealed with an **unsigned `PolicyPCR`** binding to PCR 7 (Secure Boot
state) + PCR 11 (UKI measurement) — see `crates/linhello-core/src/tpm.rs:224-288`
and `policy.rs:19-25`.

`PolicyPCR` bakes the *literal* PCR digest into the sealed object's `authPolicy`.
PCR 11 is extended by systemd-stub from the UKI's PE sections (kernel, initrd,
cmdline, …). **Every kernel / initrd / microcode / systemd-stub update rebuilds
the UKI → PCR 11 changes → the policy digest no longer matches → every unseal
fails with `TPM_RC_POLICY_FAIL` (0x99d).**

When that happens today:

1. The password envelope can't unseal → the user falls back to typing their
   password (acceptable escape hatch).
2. The template key can't unseal → `embedding.enc` is undecryptable. The key is
   random and TPM-only, **so it is unrecoverable** → the face must be re-enrolled.

This is exactly what happened on the `systemd 260.1 → 260.2` update that prompted
this work. The existing reseal pacman hook (`scripts/linhello-reseal-hook`) cannot
fix it: it runs `PostTransaction` and reseals against the *currently booted* (old)
PCR 11, which is stale the moment the new UKI boots. Its own comment admits this.

**A facial-auth product that breaks on every `pacman -Syu` is not viable.** This
document scopes the robust fix.

---

## 2. How the wider ecosystem solves this

Two reference designs, from the research:

### Windows Hello / BitLocker
BitLocker (with Secure Boot) binds to **PCR 7 (Secure Boot state)** + **PCR 11
used as a one-shot access gate** (sealed at `PCR11=0`; the boot manager
irreversibly extends it to `1` before handing off). It deliberately does **not**
seal to kernel/bootloader *hashes*. Result: a Microsoft-signed kernel/driver
update keeps PCR 7 identical → **no reseal on patch Tuesday**. Only a firmware /
Secure-Boot-cert change (which moves PCR 7) triggers recovery. The trade-off:
coarse — *any* db-trusted kernel yields the same PCR 7.

### systemd FDE (signed PCR policy) — `TPM2_PolicyAuthorize`
Instead of binding to a literal PCR digest, bind to the **name of a signing
public key**. The object's `authPolicy` is a function of the *key*, not the PCRs.
At unlock you present the *current* `PolicyPCR` digest **plus a signature** from
that key attesting "this PCR state is approved." The TPM verifies the signature
and rewrites the session policy to the key-derived value → unseal succeeds.

The killer property: **future PCR 11 values can be pre-authorized without
touching the sealed object.** When a kernel updates, the build pipeline predicts
the new PCR 11 (`systemd-measure`), signs it, and ships the signature *inside the
new UKI* (`.pcrsig` PE section). systemd-stub exposes it at boot as
`/run/systemd/tpm2-pcr-signature.json` + `/run/systemd/tpm2-pcr-public-key.pem`.
`systemd-cryptenroll --tpm2-public-key=… --tpm2-public-key-pcrs=11` binds LUKS to
the *key*, so the volume unlocks across kernel updates with **zero re-enrollment.**

This gives both update-resilience *and* per-UKI granularity, at the cost of a
signing-key pipeline. It is the canonical Linux answer and the one we should
adopt.

---

## 3. Options & recommendation

| Option | Binding | Survives kernel update? | Granularity | New machinery |
|---|---|---|---|---|
| **A. PCR 7 only** | Secure Boot state | ✅ (PCR 7 stable) | Coarse (any db-signed kernel) | None — already exists as `SecurityLevel::Medium` |
| **B. Signed PCR 11, reuse systemd keys** | PolicyAuthorize(systemd pcr key) + PCR 7 | ✅ (fresh signature per UKI) | Per-UKI (exact kernel+initrd+cmdline) | Enable PCR signing in UKI build; consume `/run/systemd/*` |
| **C. Signed PCR 11, own key + own hook** | PolicyAuthorize(LinuxHello key) + PCR 7 | ✅ (own reseal hook re-signs) | Per-UKI | Own signing key + `systemd-measure sign` hook |

### Recommendation: **B**, with **A as an automatic fallback tier.**

- **B** rides the infrastructure the distro already regenerates on every kernel
  update. LinuxHello becomes a peer consumer of the same `tpm2-pcr-signature.json`
  that systemd-cryptenroll uses — no parallel signing pipeline to maintain, and
  it's the design with the most upstream scrutiny.
- It requires one-time setup: the UKI must be built with PCR signing keys
  (`ukify --pcr-private-key`), which Arch does **not** do by default. Ben's box
  is the ideal first target (Secure Boot ON, sbctl, UKI already).
- Where signed policy is unavailable (no `.pcrsig`, legacy boot, signing not
  configured), LinuxHello degrades to **A (PCR 7 only)** — still update-resilient,
  just coarser — instead of the current brittle PCR 11 literal binding. This
  becomes the new `SecurityLevel` ladder.
- **C** is the fallback-of-the-fallback if the user refuses to touch their UKI
  build: LinuxHello ships its own key (sealed under PCR 7) and re-signs the predicted
  PCR 11 in a pacman hook. More moving parts; defer unless requested.

### New `SecurityLevel` ladder

| Level | Condition | Policy |
|---|---|---|
| `Full` | SB on + UKI + signed `.pcrsig` present | PolicyAuthorize(pcr key) over **PCR 11 only** |
| `Medium` | SB on, no signed policy available | PolicyPCR over **PCR 7 only** (stable across kernel updates) |
| `Basic` | No Secure Boot | No TPM binding (current behavior) |

> As built (`policy.rs`: `AUTHORIZED_PCRS = [11]`, `LITERAL_PCRS = [7]`): the
> authorized `Full` policy binds **PCR 11 only**. systemd's `ukify`/`systemd-measure`
> signs PCR 11 alone, so a `[7, 11]` `PolicyPCR` could never match the `pcrs:[11]`
> signatures systemd ships and would never reach `Full`. PCR 7 is the *separate*
> literal gate used by `Medium`, not ANDed into `Full`. The old `[7,11]`-literal
> `Full` (which broke on updates) no longer exists.

---

## 4. Implementation plan (phased)

Implemented against `tss-esapi` 7.6 (`policy_authorize`, `verify_signature`,
`policy_pcr`, `policy_get_digest`, `load_external_public`, `start_auth_session`
with `SessionType::Trial`/`Policy`).

### Phase 0 — Recover the current machine (unblock Ben today)
Independent of the redesign. Recovery commands:
- `linhello seal-password ben` (re-bind password to current PCR 11)
- `linhello enroll --user ben --reset` (template key is lost → re-enroll)
- `linhello diag` → no drift; `linhello verify` → match.

### Phase 1 — TPM core: PolicyAuthorize seal/unseal
`crates/linhello-core/src/tpm.rs`, `policy.rs`, `envelope.rs`.

1. **`envelope.rs`** — extend `SealedEnvelope` with a `PolicyKind` enum:
   - `PcrLiteral { pcrs }` (existing, kept for `Medium`/PCR-7 tier and migration)
   - `Authorized { pcrs, pubkey_pem, policy_ref }` (new)
   Keep `version` bump → `version: 2`; `load()` must read v1 envelopes.
2. **Seal (authorized):**
   - Trial session → `policy_authorize(session, Digest::default(), policy_ref,
     &[key_name], …)` to compute the authorized `authPolicy` digest. (The
     authorized policy commits to the key name, not to any PCR value.)
   - (Decided against ANDing a PCR-7 `policy_pcr` gate into the authorized policy:
     systemd signs PCR 11 only, so a `[7,11]` set never matches — see §3.)
   - `create()` the keyedhash sealed object under that `authPolicy`.
   - Store `pubkey_pem` (the systemd pcr public key) + `policy_ref` in the
     envelope so unseal is self-describing.
3. **Unseal (authorized):**
   - `start_auth_session(Policy)`.
   - `policy_pcr(session, Digest::default(), pcr11_selection)` → current PCR 11
     folded into the session. (PCR 11 only — no PCR-7 fold-in; see §3.)
   - `policy_get_digest(session)` → the current approved-policy digest.
   - Look up the matching `{pol, sig}` for this digest in
     `tpm2-pcr-signature.json` (match on `pcrs:[11]` + `pol` == our digest).
   - `load_external_public(pubkey, Hierarchy::Owner)` → `KeyHandle` + `Name`.
   - `verify_signature(key_handle, pol_digest, signature)` → `VerifiedTicket`.
   - `policy_authorize(session, approved_policy=pol, policy_ref, &[key_name],
     ticket)` → rewrites session policy to the key-derived value.
   - `unseal(handle)` with the session → secret.
4. **PEM → `tss_esapi::structures::Public`** for `load_external_public`: done in
   `tpm.rs` (`rsa_pem_to_public` / `load_external_pubkey`, with a unit test).
   Matches systemd's conventions — **empty `policy_ref`**, hash alg per bank
   (`sha256`) — so linhello consumes systemd's own signature file byte-compatibly.

### Phase 2 — Signature-file plumbing
New module `crates/linhello-core/src/pcrsig.rs`:
- Parse `/run/systemd/tpm2-pcr-signature.json` (auto-discover order:
  `/etc/systemd/`, `/run/systemd/`, `/usr/lib/systemd/`, matching cryptenroll).
  Schema: top-level keyed by bank (`"sha256"`) → array of
  `{ pcrs:[int], pkfp:hex, pol:hex, sig:base64 }`.
- Load `/run/systemd/tpm2-pcr-public-key.pem`.
- Given a computed approved-policy digest, find the entry whose `pol` matches.
- `from_env()` overrides for testing (`LINHELLO_PCR_SIGNATURE`, `LINHELLO_PCR_PUBKEY`).

### Phase 3 — `SecurityLevel` detection rework
`crates/linhello-core/src/policy.rs`:
- `detect()` returns `Full` only when SB on + UKI + a usable signature file +
  pubkey are present; else `Medium` (PCR 7 only); else `Basic`.
- `Medium` becomes the safety net that *also survives kernel updates* (PCR 7 is
  stable), removing the fragile [7,11]-literal failure mode entirely.

### Phase 4 — UKI build pipeline (one-time host setup; documented in [`../setup-signed-pcr.md`](../setup-signed-pcr.md))
- Generate a PCR signing keypair (separate from the Secure Boot key).
- Configure `/etc/kernel/uki.conf` (`PCRPrivateKey=`, `PCRPublicKey=`,
  `PCRPKey=`, `PCRBanks=sha256`) or the equivalent `ukify` flags in the
  mkinitcpio preset.
- Verify `/run/systemd/tpm2-pcr-signature.json` appears after a UKI rebuild.
- Arch's existing pacman hooks already rebuild the UKI on `linux`/`systemd`/
  `*-ucode`/initramfs changes, so the signature regenerates per update for free.

### Phase 5 — Reseal hook semantics fix
`scripts/linhello-reseal-hook` + `etc/pacman.d/hooks/linhello-reseal.hook`:
- For the **authorized** envelopes, the hook becomes a **no-op** for kernel
  updates (the signature ships in the UKI; nothing to reseal). It should only
  reseal on **PCR 7 changes** (sbctl key rotation — effective immediately in
  efivars, so `reseal-user-envelopes` *can* unseal-then-reseal there).
- Drop the misleading "WARNING: PCR drift … after reboot" path for the kernel
  case; replace with a `systemd-measure`-based **pre-flight check** that warns
  only if no signature will exist for the *next* boot's predicted PCR 11.
- Option C only: add a `systemd-measure sign` step here.

### Phase 6 — Migration & rollback
- v1 → v2 envelope migration on first successful unseal under the new scheme.
- Keep the password envelope independently recoverable (user knows the password)
  — never a hard failure.
- A documented one-command rollback to PCR-7-only (`Medium`) if signed policy
  misbehaves.

---

## 5. Security review findings (fold into this work)

**Status: the Critical/High items below are resolved.** They were independent of
the redesign and prerequisites for "Windows-Hello-class security." The file/line
citations are historical and no longer point at the current code.

### Critical / High — RESOLVED
1. **Fail-open at rest (H3)** — `load_user_samples` (`daemon/src/main.rs:315-318`)
   falls back to **plaintext `embedding.bin`** when the template key can't unseal.
   A TPM error silently downgrades to unauthenticated-at-rest templates, and a
   dropped-in plaintext `embedding.bin` would be honored. **Fail closed:** if the
   template key is unavailable, error out and let PAM fall through to password.
   Gate any legacy migration behind an explicit, off-by-default flag.
   → **As built:** fails closed — `cached_template_key` error refuses any
   plaintext fallback; no `embedding.bin` path remains.
2. **Path traversal (H2)** — `password_envelope_path` (`core/src/lib.rs:17-20`)
   rejects `/` and `\0` but **not `.`/`..`**; `camera_binding_path`
   (`daemon/src/main.rs:235-239`) does **no** validation. `user=".."` →
   `/etc/password_envelope.json`. Centralize `validate_user()` (reject empty,
   `.`, `..`, `/`, `\0`; require `getpwnam`) and call it in **every** path
   builder. Canonicalize and assert containment under `CONFIG_ROOT`.
   → **As built:** `core/src/lib.rs::validate_user()` rejects empty/`.`/`..`/`/`/
   `\`/`\0` and is called in every path builder and at the daemon dispatch
   boundary, with tests.
3. **Un-zeroized secrets across IPC (C4/M3)** — login password and unsealed
   secrets are copied into plain `Vec<u8>` and serialized as cleartext JSON
   integer arrays (`do_unseal` `secret.to_vec()` `main.rs:339`; PAM
   `pw.to_vec()`; `client.rs` `to_vec`/`String` buffers). Heap residue in root
   processes contradicts the project's zeroize posture. Wrap wire secret fields
   in a zeroizing newtype; zeroize serialized buffers on both ends; prefer an
   out-of-band `SCM_RIGHTS`/memfd transport.
   → **As built:** wire secret fields use the `SecretBytes` zeroizing newtype
   (`ipc.rs`, `impl Zeroize`). The `SCM_RIGHTS`/memfd transport remains an
   optional future hardening.
4. **Socket 0666 + ungated `Verify`/`LivenessTest` + raw `score` leak (C3)** —
   `main.rs:57` is world-writable; any local process can drive the camera and
   read back the similarity `score` as a threshold-tuning oracle, and DoS the
   single ORT/v4l mutex. Move to `0660` + `linhello` group, scope `Verify` to the
   caller's own uid, return only `matched` (not `score`) to non-root, rate-limit.
   → **As built:** socket is `0o660` `root:linhello` (not 0666), so only
   already-privileged callers reach the daemon — the world-writable oracle/DoS
   path is closed.
5. **Anti-spoof fail-open default (H5)** — `LivenessConfig::from_env` defaults
   `require_antispoof=false`; only the shipped unit sets `=1`. Default to
   `true` in code; require explicit opt-out.
   → **As built:** `from_env` defaults `require_antispoof=true` (fail-closed);
   only an explicit falsey value disables it.
6. **IR gate doesn't enforce the "decisive" signal (H6)** — `ir::classify`
   gates only on `face_bg_ratio ≥ 1.2`; `highlight_frac` (eye-glint, the
   documented strongest anti-print signal) is only in the soft score. Add a
   `highlight_frac` floor to the hard gate or consciously document/justify
   ratio-only. Fix the stale "without gating" docstring.
   → **As built:** kept ratio-only as a *conscious, documented* choice — `ir.rs`
   hard-gates on `face_bg_ratio`, glint stays a soft signal with the rationale in
   the module docs, and the stale docstring was corrected.

### Medium / hygiene
- **mlock lifetime (H4)** — `memlock::lock_slice` locks *after* the secret is
  already on a swappable page and never `munlock`s; use an alloc-time-locked
  secret type with `munlock` on drop.
- **Legacy `embedding.bin` perms (M5)** — written with default umask
  (world-readable); enforce `0600` or remove the legacy writer.
- **Socket startup TOCTOU (M1)**, **missing-binding = pass (M2)**,
  **`with_session` error path skips `clear_sessions` (M4)**,
  **poisoned ORT mutex `.unwrap()` (M6)**.
- **Tests (L5)** — no coverage of the auth-critical decision path
  (`validate_user`, liveness hard-gate matrix, FFI length bounds, fallback).

### Reviewed-OK
AES-256-GCM (`crypto.rs`) is correct: random 12-byte nonce per write, tag
verified on decrypt, `Zeroizing` keys, length-checked, no nonce reuse. TPM
handle/session hygiene (`with_session`/`with_handle`) is careful. PAM C-side
buffer bounds, null checks, and volatile zeroing fail closed.

---

## 6. Acceptance criteria (definition of done)

1. After enabling signed PCR policy, a `linux`/`systemd` update + reboot leaves
   `linhello verify` working with **no reseal and no re-enroll**.
2. `linhello diag` reports the policy kind and whether a valid signature exists for
   the *next* boot (pre-flight), not just current drift.
3. If signed policy is unavailable, LinuxHello runs at `Medium` (PCR 7) and still
   survives kernel updates.
4. Security must-fix items 1–6 above are closed, with tests for the auth path.
5. v1 envelopes migrate transparently; password fallback never hard-fails.

---

## 7. Decisions

1. **Strategy B vs C** — *Decided: **B for UKI, C for GRUB.*** PCR signing is
   enabled in the UKI build and linhello consumes systemd's own
   `tpm2-pcr-signature.json` (approach B; the Arch reference box runs this). For
   non-UKI systems (GRUB), linhello now *also* runs approach C — its own
   per-host signing key over PCR 7, re-signing on drift — because there is no
   systemd signature to consume there. See §8. (Originally C was deferred; the
   GRUB firmware-update breakage made it necessary.)
2. **PCR 7 AND-gate** — *Decided: PCR 11 signed policy alone.* A `[7,11]`
   `PolicyPCR` can never match systemd's `pcrs:[11]` signatures, so PCR 7 stays the
   separate `Medium` literal gate, not ANDed into `Full` (see §3).
3. **Match threshold (L4)** — *Still open:* default remains `0.60`; measuring
   FAR/FRR and making it configurable/auditable is not yet done.

---

## 8. GRUB / non-UKI self-heal: linhello as its own PCR-7 signer (2026-06-19)

### 8.1 The gap this closes

Approach B (§2, §3) makes **UKI** systems update-resilient by consuming systemd's
signed PCR-11 policy. But a **GRUB** system has no systemd-stub and ships no
`tpm2-pcr-signature.json`, so it fell back to a *literal* `PolicyPCR` over PCR 7.
That survives kernel updates (PCR 7 is Secure-Boot state, not kernel hashes) but
**not a Secure-Boot-variable change**: a `fwupd` **dbx** update (revocation-list
refresh) moves PCR 7, the literal policy no longer matches, and the template key
becomes unrecoverable → re-enroll. This is the exact failure observed on a
ThinkPad after an Intel ME / dbx firmware update (`0x99d`,
`PCR mismatch: [7] changed since seal`).

The fundamental constraint: once PCR 7 changes and the machine reboots, the old
key cannot be unsealed, and you cannot reseal to a *future* PCR-7 you don't yet
know. Any automatic heal therefore needs a PCR-7-independent recovery path.

### 8.2 Design

linhello becomes its **own `PolicyAuthorize` signer over PCR 7** — approach C,
but per-host and automatic:

- **Key.** A per-host RSA-2048 signing key is generated on first use and stored
  root-only at `/etc/linhello/pcr-signing-key.pem` (public half at
  `pcr-signing-pub.pem`). `pcrsig::ensure_host_signing_key`.
- **Seal.** The template key is sealed under `PolicyAuthorize(host_key)` over
  PCR 7 (`policy.rs` selects this plan whenever Secure Boot is on and there is no
  trusted systemd signature). The object's `authPolicy` commits only to the key's
  Name, **not** a concrete PCR value, so any PCR-7 state with a valid signature
  unseals. At seal time linhello signs the current PCR-7 policy into
  `/etc/linhello/pcr-signature.json` (systemd's signature-file schema, reused).
- **Self-heal (the crux).** Re-signing is folded into the **unseal path**:
  replay `PolicyPCR` over PCR 7 → get the approved digest → if no signature on
  file matches it **and Secure Boot is still enabled**, sign the new digest with
  the host key, persist it, and proceed. The sealed object is untouched. Net
  effect: the **first** face-unlock attempt after a firmware/dbx update heals
  itself — passwordless, no re-enroll. `tpm::ensure_host_signature` +
  `tpm::unseal_authorized`.

### 8.3 Security posture

The gate weakens from "**this exact db/dbx**" to "**any PCR-7 state while Secure
Boot stays on**" — exactly BitLocker's default PCR-7 behaviour. Concretely:

- **Offline attacker (stolen disk):** still cannot unseal — the secret is
  TPM-bound; the on-disk signing key only authorizes a *policy*, it does not
  release key material.
- **Attacker who disables Secure Boot:** `is_secure_boot_enabled()` is false, so
  linhello **refuses to re-sign**; the unseal fails and auth falls back to the
  password. The "Secure Boot must stay on" invariant is preserved.
- **Attacker who enrolls their own Secure Boot keys** (needs firmware control,
  normally a firmware password): SB reads "on", linhello would re-sign — the
  accepted residual of this posture. The template key only decrypts the *face
  embedding* (a privacy item, not a credential), and face auth falls back to the
  password regardless, so this is acceptable for the convenience tier.

The two signers are kept distinct and fail-closed: `pcrsig::classify_signer`
accepts only the pinned systemd key (→ PCR 11, signatures from
`/run/systemd`) **or** this host's own key (→ PCR 7, signatures from
`/etc/linhello/pcr-signature.json`); anything else is rejected before the TPM is
touched.

### 8.4 Recovery passphrase (manual backstop)

For the cases the automatic path *can't* cover — Secure Boot deliberately off,
TPM cleared, disk moved to new hardware — a **dedicated recovery passphrase**
(separate from the login/root password, by user request) wraps the template key
with Argon2id + AES-256-GCM (`recovery.rs`). `linhello set-recovery` stores it;
`linhello recover` unwraps the key and re-seals it to the current TPM state. Like
a BitLocker/LUKS recovery key. Never re-enroll.

### 8.5 Validation

Proven on real hardware (`tpm.rs` `#[ignore]` tests, run as root):
`policy_authorize_roundtrip_and_self_heal_on_drift` exercises seal → sign →
unseal → **PCR drift (PCR 23)** → stale-signature rejection → **re-sign** →
unseal on the same object; `production_host_signer_seal_unseal_real_pcr7` runs
the production `seal_secret`/`unseal` over live **PCR 7**.
