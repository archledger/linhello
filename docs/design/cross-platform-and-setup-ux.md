# Cross-platform support & setup UX — design / roadmap

Status: **design only, nothing implemented.** Scoped 2026-06-02. LinuxHello is
currently built and tested only on Arch. This document plans four related
efforts:

1. Run on **Debian/Ubuntu** and **Fedora/RHEL**, not just Arch.
2. Work under both **systemd-boot** and **GRUB** (Secure Boot is required).
3. A **setup TUI** to replace the linear `linhello setup` prompts.
4. A **live camera-positioning guide** during enrollment.

The first two are "portability"; the last two are "setup UX." They are
independent and can land in any order, but the recommended sequencing is at the
end.

---

## 1. Cross-distro support (Debian/Ubuntu, Fedora/RHEL)

### 1.1 What is actually Arch-specific today

Grounded inventory (file:line) of every distro assumption:

**Install paths (defaults assume Arch layout)**
- `Makefile:14` `PREFIX ?= /usr/local`, `Makefile:16` `PAMDIR ?= /usr/lib/security`,
  `Makefile:17` `SYSTEMDDIR ?= /etc/systemd/system`.
  - PAM module dir differs: Arch/Fedora `/usr/lib64/security` or `/usr/lib/security`;
    **Debian/Ubuntu `/lib/x86_64-linux-gnu/security`** (multiarch triplet).
- `etc/systemd/linhellod.service:9` hardcodes `ExecStart=/usr/local/bin/linhellod`
  — breaks a packaged `/usr/bin` install.
- `scripts/migrate-to-linhello.sh:112` hardcodes `/usr/lib/security/pam_*.so`.

**Distro-stable paths (already portable, leave alone)**
- `CONFIG_ROOT=/etc/linhello` (`linhello-common/src/lib.rs:41`),
  `SOCKET_PATH=/run/linhello.sock` (`:40`), `/dev/tpmrm0` (`tpm.rs:46`).
- ONNX dylib search already multi-distro: `capabilities.rs:168-173` checks
  `/usr/lib`, `/usr/lib64`, `/usr/lib/x86_64-linux-gnu`, `/usr/local/lib`. But the
  two *default* constants are Arch-only: `ort_init.rs:11` and
  `antispoof.rs:29` = `/usr/lib/libonnxruntime.so`.
- systemd PCR-signature search is already correct cross-distro:
  `pcrsig.rs:29` = `/etc/systemd`, `/run/systemd`, `/usr/lib/systemd`.

**Packaging / package-manager (Arch-only)**
- `packaging/arch/PKGBUILD` — `depends=('tpm2-tss' 'pam' 'v4l-utils' 'onnxruntime' …)`,
  `optdepends=('sbctl …')`. Package names differ per distro (see 1.4).
- `etc/pacman.d/hooks/linhello-reseal.hook` — pacman-only; triggers on `linux*`,
  `systemd`, `mkinitcpio`, `sbctl`. No equivalent exists for apt/dnf.
  - `mkinitcpio` is Arch's initramfs tool. Debian = `initramfs-tools`
    (`update-initramfs`), Fedora = `dracut`.
  - `Exec = /usr/local/bin/linhello-reseal-hook` — path again.
- `scripts/migrate-to-linhello.sh:89` references `yay` (AUR helper).

**Secure Boot tooling (Arch-only)**
- `linhello-cli/src/main.rs:94-180` wraps **`sbctl`** for the whole `secureboot`
  subcommand; `:140` bails with `pacman -S sbctl`. sbctl is effectively
  Arch/openSUSE. Debian uses `sbsigntools`/`mokutil`; Fedora uses `mokutil` +
  `pesign`/`sbsigntools`. (See §2.3.)

**PAM stack file layout (the genuinely hard one — see 1.3)**
- `migrate-to-linhello.sh:95-102` edits `gdm-password`, `sudo`, **`system-auth`**.
  `system-auth` exists on Arch and Fedora but **not Debian** (Debian uses
  `common-auth`/`common-password`). Fedora's is managed by **authselect** and
  hand-edits get clobbered.

**Docs**
- `docs/setup-signed-pcr.md` uses `pacman -S …` and `mkinitcpio -P`.

### 1.2 Strategy — a small `platform` abstraction + per-distro packaging

Two layers:

**(a) Runtime platform detection (one new module, `linhello-common::platform`).**
Detect distro family once (read `/etc/os-release` `ID`/`ID_LIKE`) and resolve the
handful of variable paths:
- `pam_module_dir()` → `/usr/lib/security` (arch/fedora) | `/lib/$(triplet)/security` (debian).
- `onnxruntime_default()` → first existing of the known dylib paths (reuse the
  `capabilities.rs` list; promote it to the shared module and have
  `ort_init.rs`/`antispoof.rs` call it instead of the Arch constant).
- `initramfs_tool()` → `mkinitcpio` | `dracut` | `update-initramfs` (for docs and
  the reseal hook).
- Most paths (`/etc/linhello`, `/run`, `/dev/tpmrm0`, systemd dirs) are already
  uniform — do **not** over-abstract them.

This keeps the binaries distro-agnostic; only packaging picks the install prefix.

**(b) Build-time install correctness.** Make the systemd unit's `ExecStart` and
the reseal-hook `Exec` use the configured prefix instead of `/usr/local/bin`.
Simplest: template them at `make install` (substitute `@BINDIR@`), or set
`ExecStart=/usr/bin/linhellod` for packaged builds and keep `/usr/local/bin` only
for the dev `make install`. Packaging always passes `PREFIX=/usr`.

### 1.3 PAM integration per distro — the hard part

Face auth is wired by inserting `pam_linhello.so` (sufficient, before
`pam_unix`) into the auth stack and relying on `pam_gnome_keyring use_authtok`
downstream. The *module* is portable; *where you insert it* is not:

- **Arch:** edit `/etc/pam.d/{gdm-password,sudo,system-auth}` (current approach).
- **Debian/Ubuntu:** there is no `system-auth`. The shared stack is
  `/etc/pam.d/common-auth` (+ `common-password` for the chauthtok reseal hook).
  GDM uses `gdm-password` which `@include common-auth`. **Never** hand-edit
  `common-auth` directly on Debian — it's managed by `pam-auth-update`
  (profiles in `/usr/share/pam-configs/`). The clean path is to **ship a
  pam-config profile** (`/usr/share/pam-configs/linhello`) and let
  `pam-auth-update` weave it in.
- **Fedora/RHEL:** `/etc/pam.d/{system-auth,password-auth}` are **symlinks
  managed by `authselect`**. Editing them is overwritten on the next
  `authselect` run. The clean path is an **authselect feature/custom profile**
  (or document `authselect` integration); fall back to a clearly-marked manual
  edit only if authselect isn't in use.

**Recommendation:** abstract the PAM wiring behind `linhello setup --wire-pam`
(or the TUI's PAM step) that branches on distro:
`pam-auth-update` profile (Debian) / authselect (Fedora) / direct stanza edit
with backup (Arch). Always preserve the two safety invariants that already make
this non-lockout: `pam_linhello` is `sufficient` (face miss → password), and the
TTY path (`/etc/pam.d/login`) is left untouched. Ship per-distro example stacks
under `share/linhello/pam.d/` (the repo already has `etc/pam.d/examples/` for
gdm/sddm/lightdm/system-login — extend with Debian/Fedora variants).

### 1.4 Packaging per distro

| Distro | Format | Channel | Notes |
|---|---|---|---|
| Arch | PKGBUILD (exists) | AUR | already done; just needs sha256 pin + signing |
| Debian/Ubuntu | `.deb` (`debian/` dir, dpkg-buildpackage) | PPA or release `.deb` | `debhelper`; maintainer scripts (`postinst`/`prerm`) replace the `.install` scriptlet; `pam-auth-update` in `postinst` |
| Fedora/RHEL | `.rpm` (`.spec`) | **COPR** | `%post`/`%postun` scriptlets; authselect integration |

Dependency name map (for the spec/control files):

| Need | Arch | Debian/Ubuntu | Fedora/RHEL |
|---|---|---|---|
| TPM TSS runtime | `tpm2-tss` | `libtss2-tcti-device0` | `tpm2-tss` |
| ONNX Runtime | `onnxruntime` | (often self-built / `libonnxruntime`) | `onnxruntime` (RPMFusion/COPR) |
| PAM | `pam` | `libpam0g` | `pam` |
| V4L | `v4l-utils` | `libv4l-0` | `libv4l` |
| SB enroll (optional) | `sbctl` | `sbsigntool`,`mokutil` | `mokutil`,`pesign` |
| UKI gen (optional) | `systemd-ukify` | `systemd-ukify` | `systemd-ukify`/`dracut` |

The per-distro reseal trigger replaces the pacman hook:
- Debian: `dpkg` trigger or an apt `DPkg::Post-Invoke` hook, **or** simpler — a
  `kernel-install` plugin / a systemd path-unit watching the ESP. (A systemd
  path-unit on `boot/EFI/Linux/*` is the most distro-portable replacement for the
  pacman hook and could supersede it on Arch too.)
- Fedora: `kernel-install` plugin (`/etc/kernel/install.d/`) or dnf plugin.

**ONNX Runtime is the biggest packaging friction** — it's not in Debian main and
Fedora needs RPMFusion/COPR. Options: vendor a known-good `libonnxruntime.so` via
a `linhello-onnxruntime` companion, or document the upstream download. This ties
into the out-of-band models story (`linhello fetch-models`, deferred from the
update-channel discussion).

### 1.5 Phase plan (portability)

1. Add `platform` module (os-release detect + path resolution); replace the
   Arch-only onnxruntime constants. Fix `ExecStart`/hook paths. *(No behavior
   change on Arch.)*
2. PAM wiring abstraction + per-distro example stacks.
3. Debian `.deb` + `pam-auth-update` profile; smoke-test on Ubuntu LTS.
4. Fedora `.spec` + COPR + authselect; smoke-test.
5. Replace pacman reseal hook with a portable systemd path-unit (works
   everywhere, including Arch).

---

## 2. Bootloaders & Secure Boot (systemd-boot + GRUB)

### 2.1 Key insight: the tier is driven by **UKI**, not the bootloader

`detect_boot_mode()` (`linhello-secureboot/src/lib.rs:28-39`) keys on the
**`StubInfo` efivar**, which **systemd-stub** writes when a UKI boots — regardless
of whether systemd-boot, GRUB, or rEFInd launched it. So `BootMode::Grub` really
means *"traditional vmlinuz+initrd, no systemd-stub"*, not "the GRUB bootloader."

The policy tiering (`policy.rs:81-98`) already follows from this:
- **Full** (`PolicyAuthorize([7,11])`) — SB on **+ UKI present + signed PCR sig**.
  PCR 11 is extended *by systemd-stub* from the UKI's PE sections, and the signed
  policy survives kernel updates (the whole point of `signed-pcr-policy.md`).
- **Medium** (`PolicyPCR([7])`) — SB on, no UKI/signed policy. PCR 7 = Secure Boot
  state only; **stable across kernel updates**. This is where GRUB-with-traditional-
  kernel lands today, and it already works (`policy.rs` test `secure_boot_non_uki_is_pcr7_literal`).
- **Basic** — no Secure Boot → no TPM binding.

**Consequence:** there are really three deployment shapes, and we already handle
two of them. We do **not** need parallel GRUB PCR-8/9 machinery.

| Boot shape | Common on | Tier | Action |
|---|---|---|---|
| systemd-boot + signed UKI | Arch (our dev box) | Full | works |
| GRUB **chainloading a signed UKI** | Fedora (UKI path), advanced Debian | Full | works *if* StubInfo set — verify |
| GRUB + traditional vmlinuz/initrd | **Debian/Ubuntu default, Fedora default** | Medium (PCR-7) | works, document it |

### 2.2 Why not bind GRUB's own PCRs (4/8/9) for a "Full" tier?

GRUB measures kernel/initrd/cmdline into PCR 8/9 (and itself into 4). We could
bind those literally — but that recreates exactly the kernel-update-breakage the
signed-PCR work *removed*: every kernel/initrd change re-extends 8/9 → unseal
fails → re-enroll. GRUB has **no signed-PCR-policy equivalent** to systemd-stub's
`.pcrsig`. So a "GRUB Full tier" would be strictly worse (fragile) than the PCR-7
Medium tier we already give it. **Recommendation: do not implement it.** For users
who want Full tier, the answer is "boot a signed UKI" (which GRUB can chainload),
not "measure GRUB's PCRs."

So the bootloader work is **not** about PCR machinery. It's two things:

### 2.3 Secure Boot **key enrollment** tooling abstraction (the real bootloader work)

`secureboot` subcommand is 100% `sbctl` (`main.rs:94-180`). To run on Debian/
Fedora we need a tool-agnostic seam:
- Define a small internal trait/enum `SbEnroller { Sbctl, Mokutil, Manual }`,
  pick per `which`/distro.
- **Arch/openSUSE:** sbctl (current).
- **Fedora/RHEL:** Secure Boot is normally already enrolled with the vendor/MS
  keys + Fedora's CA; user binaries are signed via **MOK** (`mokutil --import`) +
  `pesign`/`sbsigntools`. Often the right move is *don't touch PK/KEK* at all —
  just enroll a MOK for the signed UKI.
- **Debian/Ubuntu:** same MOK model (`mokutil`, `sbsigntools`, `update-secureboot-policy`).
- Honest fallback: detect SB state via the existing efivar reads
  (`is_secure_boot_enabled()`, `is_setup_mode()` — already portable) and, if no
  supported tool is present, print distro-specific manual instructions rather than
  failing.

**Recommendation:** keep `linhello secureboot` but make it advisory/branching;
on Debian/Fedora default to the MOK workflow and never rewrite platform keys.

### 2.4 UKI generation per distro (for users who want Full tier)

`docs/setup-signed-pcr.md` assumes `mkinitcpio -P`. Generalize the doc/tooling:
- Arch: `mkinitcpio` (UKI preset) or `ukify`.
- Fedora: `dracut --uefi` / `kernel-install` (Fedora is moving to UKIs natively).
- Debian/Ubuntu: `ukify` + `kernel-install`, or `dracut`.
The signing knobs (`ukify --pcr-private-key`, `/etc/kernel/uki.conf` with
`PCRBanks=sha256`) are **systemd-ukify**, hence already cross-distro — only the
initramfs/UKI builder differs. `pcrsig.rs` consumes systemd's output unchanged.

### 2.5 Phase plan (bootloaders)

1. **Verify** the "GRUB chainloads signed UKI → StubInfo set → Full tier" path on
   real hardware/VM. If StubInfo is set, no code change needed — just docs.
2. Abstract `secureboot` behind an enroller seam; add the MOK workflow for
   Debian/Fedora; keep sbctl for Arch.
3. Generalize `setup-signed-pcr.md` to dracut/kernel-install; keep PCR-7 Medium as
   the documented, supported default for traditional-boot users.
4. Capabilities/`doctor` copy already messages GRUB correctly
   (`capabilities.rs:75`) — extend it to name the recommended path per detected
   distro.

---

## 3. Setup TUI

### 3.1 What exists

`linhello setup` (`main.rs:405-461`) is a 4-step linear flow (probe → pick cameras
→ calibrate threshold → optional enroll) using bare `println!`/`prompt_line`/
`prompt_yes` (`:181-194`) and `rpassword` for secrets. **No TUI crate is a
dependency** (no ratatui/crossterm/dialoguer). The CLI already links
`linhello-biometrics` (for `camera::enumerate()`), talks to the daemon via
`client::request`, and does config I/O via `linhello-common::config` (cameras.conf,
settings.conf). Every setup operation is either a local action or a single daemon
round-trip — there is **no long-lived interactive session to restructure**, which
makes a TUI a clean wrapper.

### 3.2 Recommended approach

- **Crate:** `ratatui` + `crossterm` (de-facto standard, pure-Rust, no ncurses
  dep — important for the minimal-dependency security posture). For a lighter
  first step, `dialoguer`+`indicatif` give nicer prompts/spinners without a
  full-screen app; but the camera guide (§4) wants a redrawing full-screen
  surface, so **ratatui is the better target** and the two efforts share it.
- **Architecture:** the TUI is a *view* over the **existing** daemon IPC + local
  ops. Do not move logic into the TUI — wrap `run_setup`'s steps as discrete
  state-machine screens: `Probe → Cameras → (NEW) Position/Enroll → Calibrate →
  PAM-wiring → Done`. Reuse `Request::Probe`, `camera::enumerate`,
  `Request::Verify/Enroll`, `config::write_kv`.
- **Keep the headless path.** `linhello setup` must still work over a plain TTY/
  SSH (no TUI) — gate the full-screen UI on `stdout().is_terminal()` and a
  `--no-tui` flag, falling back to the current linear prompts. This also matters
  because setup runs as **root**; the TUI must run fine under `sudo`.
- **Scope creep guard:** the TUI is a setup/enrollment aid, not a daily driver.
  v1 = the wizard + the camera guide (§4). Status/doctor/diag stay as plain CLI
  output (they're already good); optionally add a read-only `linhello tui`
  dashboard later.

### 3.3 New PAM-wiring step

Fold §1.3's per-distro PAM wiring into the wizard as an explicit, opt-in screen
("Enable face login for GDM / sudo?") that shows exactly what it will change, backs
up first, and reminds the user of the password/TTY escape hatch. This is the
single biggest setup-friction reducer and the riskiest manual step today.

---

## 4. Live camera-positioning guide for enrollment

### 4.1 The problem and the constraint

Today the user opens a separate camera app to confirm framing, then runs
`linhello enroll` blind. We want an in-terminal guide that shows whether the face
is framed correctly *before* grabbing the embedding.

**Hard architectural constraint:** the **daemon owns the camera** and the design
deliberately **never sends image pixels over IPC** — `LivenessSummary`
(`ipc.rs:149-167`) carries only geometry/decision signals. We should preserve
that (privilege separation + no secret/biometric pixels on the socket).

### 4.2 Everything a guide needs is already computed

From `detect::Face` (`detect.rs:28-32`): `bbox [x1,y1,x2,y2]`, 5 `landmarks`,
detection `score`, and `faces.len()`. Plus derived geometry that already exists:
- `face_frac = bbox_w / frame_w` (`liveness lib.rs:323`), threshold
  `MIN_FACE_FRAC = 0.15` (`ir.rs:55`) → **too far / move closer**.
- `estimate_pose(landmarks) → (yaw,pitch)` (`orientation.rs:21`), gate
  `MAX_ANGLE_DEG = 18°` (`:16`) → **look straight at camera** (+ which way).
- bbox center vs frame center → **off-center left/right/up/down**.
- `faces.len()==0` → **no face**, `>1` → **multiple faces**.
Detection is **separable from embedding** (`Detector::detect()` is standalone) and
fast (~20-30 ms cached) → a ~10-15 Hz guidance loop is feasible.

### 4.3 Two ways to wire it — recommendation

**Option A (recommended): daemon-polled geometry, abstract guide.**
Add a lightweight `Request::PositionSample` → `Response::Position { face_count,
bbox, frame_w, frame_h, yaw, pitch, face_frac, guidance: String }`. The TUI polls
it at ~10 Hz during the enroll screen and renders an **abstract** guide: a frame
rectangle with the detected face box drawn inside it, directional arrows, and a
status line ("move closer", "turn left a little", "hold still — capturing"). When
framing is good for N consecutive samples, trigger the real `Request::Enroll`.
- Pros: no pixels over IPC; camera stays solely in the privileged daemon; fits the
  existing one-shot IPC (it's just a fast poll, not true streaming); works even if
  the invoking user isn't in the `video` group.
- Cons: new request/response variant; the "preview" is an abstract box, not a
  photographic image.

**Option B: CLI direct-capture pixel preview.**
The CLI already links `linhello-biometrics`, so it *could* call `capture_frame()`
+ `detect()` itself and render actual pixels (half-block/sixel/ASCII). Pros:
real camera image, no IPC change. Cons: needs the user in `video` group; risks V4L
contention with the daemon; pushes ONNX/camera work into the CLI process; ships
biometric pixels into the CLI. **Not recommended** as the default — but a `--pixel-
preview` could be offered for users who specifically want to see the actual image.

**Recommendation:** ship **Option A**. An abstract, instructional guide ("face too
low, move up"; box turning green when centered) is arguably *better* UX in a
terminal than a smeary ASCII photo, and it respects the privilege boundary. Offer
Option B later as an opt-in for the "I want to see the real camera" case.

### 4.4 Guidance mapping (the signals → messages)

```
faces == 0            → "No face detected — center yourself in front of the camera"
faces  > 1            → "Multiple faces — only you should be in frame"
face_frac < 0.15      → "Move closer"
face_frac > ~0.6      → "Move back a little"
|yaw| > 18            → yaw>0 ? "Turn slightly left" : "Turn slightly right"
|pitch| > 18          → pitch>0 ? "Tilt your head down" : "Tilt your head up"
bbox off-center       → arrow toward center ("move left/right/up/down")
all good for N frames → "Hold still…" then auto-capture sample
```
Reuse the exact thresholds the auth path uses so "the guide says good" ⇒ "enroll
will accept." Wire this into both `linhello setup`'s enroll step and standalone
`linhello enroll` (guide unless `--no-tui`/non-TTY).

### 4.5 Phase plan (camera guide)

1. Add `Request::PositionSample`/`Response::Position` (daemon: capture→detect→
   geometry, no embed; reuse `capture_detect_live`). Plain-text CLI first: print
   live guidance lines (no full-screen) to validate the signal loop.
2. Render it in the ratatui enroll screen (frame box + face box + arrows + status).
3. Auto-capture on sustained good framing; fold into `setup`.
4. Optional `--pixel-preview` (Option B) later.

---

## Recommended sequencing across all four

1. **Portability foundation** (§1.5 steps 1-2): `platform` module + path/onnx
   fixes + PAM-wiring abstraction. Unblocks everything else and is low-risk on Arch.
2. **Camera-positioning guide, Option A, plain-text first** (§4.5 step 1) — high
   user value, self-contained, no distro work needed.
3. **Setup TUI** (§3) wrapping the wizard, with the camera guide as its enroll
   screen and the PAM-wiring step.
4. **Debian `.deb`** then **Fedora `.rpm`/COPR** (§1.5 steps 3-4), each with a
   real smoke test, plus the portable systemd path-unit reseal trigger (§1.5 step 5).
5. **Bootloader**: verify GRUB+UKI Full-tier path; abstract `secureboot` to MOK for
   Debian/Fedora; generalize the signed-PCR doc (§2.5). Mostly docs + the enroller
   seam; no new PCR machinery.

Out of scope here (tracked separately): the update/release channel (AUR + signed
GitHub releases) — revisit after portability, since `.deb`/`.rpm`/COPR are the
same release artifacts.
