<div align="center">

<img src="assets/banner.svg" alt="LinuxHello — Windows Hello for Linux, face unlock with TPM-backed security" width="720">

**Windows Hello for Linux** — face unlock for your login screen, keyring, and sudo.

[![License](https://img.shields.io/github/license/archledger/linhello?color=4c8eda)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-333?logo=linux&logoColor=white)](#-what-you-need)
[![Windows Hello for Linux](https://img.shields.io/badge/Windows_Hello-for_Linux-0078D6?logo=windows&logoColor=white)](#)
[![Stars](https://img.shields.io/github/stars/archledger/linhello?style=flat&color=f5c518)](https://github.com/archledger/linhello/stargazers)

</div>

A modern, Rust-based alternative to [Howdy](https://github.com/boltgolt/howdy): your password isn't replaced — it's sealed in your computer's TPM chip and released only when your face matches, with hardware-checked anti-spoofing. If the camera, TPM, or anything else fails, you just type your password like normal. **You can never be locked out.**

<!-- Tip: a short demo GIF here sells the project instantly — drop one at assets/demo.gif and reference it as ![demo](assets/demo.gif) -->

## 🧰 What you need

- **A TPM 2.0 chip — required** (it's what seals your secrets). Most PCs since
  ~2016 have one; check with `ls /dev/tpm*`.
- **A webcam.** A Windows Hello **IR** camera unlocks the headline features —
  face **login, sudo, and keyring** — via the "secure" tier with active-IR
  anti-spoofing. A plain **RGB-only** webcam still works, but only to unlock an
  *already-logged-in* session (the "convenience" tier); face login/sudo then fall
  back to your password.
- **…or a fingerprint reader.** On RGB-only laptops (no IR), a fingerprint is a
  **secure-tier** method on its own — it unlocks the screen, login, **and** sudo,
  the same as IR face. linhello detects it and can set it up for you (it drives
  `fprintd`); see [Fingerprint](#-fingerprint-instead-of-or-alongside-face).
- **Secure Boot — recommended.** With it, your secrets are bound to your boot
  state (the `Medium`/`Full` tiers); without it linhello still runs, but at its
  weakest TPM tier (no boot-state binding). **Firmware/dbx updates don't break
  face unlock** — on GRUB, linhello re-signs its PCR-7 policy automatically.
- **Arch Linux, Fedora, or Debian/Ubuntu.** All three ship signed packages;
  Debian/Ubuntu was build-tested on Ubuntu 26.04 (install → daemon auto-starts →
  `doctor` READY → face screen-unlock confirmed).

## ⚡ Install

### Fedora

**Recommended — install from the COPR.** `dnf` pulls every dependency (including
ONNX Runtime, which isn't in Fedora's main repos) and updates ride along with
`dnf upgrade`:

```sh
sudo dnf copr enable archledger/linhello
sudo dnf install linhello        # daemon + ONNX Runtime, pulled automatically

sudo linhello fetch-models       # the ~250 MB face models (one time)
sudo linhello tui                # enroll your face + wire up login
```

The daemon starts on install, so `linhello doctor` works right away. Updates:
just `sudo dnf upgrade`.

<details><summary>Alternative — install the release RPM directly (no COPR)</summary>

Download the `.fcNN.x86_64.rpm` from the
[latest release](https://github.com/archledger/linhello/releases/latest), then:

```sh
sudo dnf install ./linhello-*.fc*.x86_64.rpm
sudo linhello fetch-onnx         # ONNX Runtime isn't in Fedora's main repos
sudo linhello fetch-models
sudo linhello tui
```
</details>

### Debian / Ubuntu

Download the `_amd64.deb` from the
[latest release](https://github.com/archledger/linhello/releases/latest), then
let `apt` install it and pull its dependencies. The daemon starts on install, so
`linhello doctor` works right away:

```sh
# 1. Install the package (resolves dependencies; daemon auto-starts)
sudo apt install ./linhello_*_amd64.deb

# 2. ONNX Runtime isn't in the Debian/Ubuntu repos — fetch the matching prebuild
sudo linhello fetch-onnx

# 3. Face-recognition models (~250 MB, one time)
sudo linhello fetch-models

# 4. Set up — pick your camera, enroll, and wire up login (via pam-auth-update)
sudo linhello tui
```

Verified on Ubuntu 26.04 (amd64): the `.deb` installs, the daemon auto-starts,
`linhello doctor` reports READY, and face screen-unlock works through
`pam-auth-update`. Login wiring uses your distro's `pam-auth-update` profile, so
the password (and TTY) escape hatch is always preserved.

> **Building the .deb yourself** (instead of the release artifact): from a clone,
> `cp -rT packaging/debian debian && dpkg-buildpackage -us -uc -b` produces
> `../linhello_<ver>_amd64.deb`. Needs `debhelper`, `cargo`/`rustc`, and `clang`.

### Arch Linux

Build the native package and install it with `pacman`, so the system tracks it
like any other package and updates ride along with `sudo linhello update`:

```sh
# 1. Dependencies (makepkg also pulls build deps automatically, but these are
#    the runtime + build set the package declares)
sudo pacman -S --needed base-devel git rust clang tpm2-tss onnxruntime v4l-utils

# 2. Build + install the package
git clone https://github.com/archledger/linhello
cd linhello
make dist                         # rolls packaging/arch/linhello-<ver>.tar.gz from HEAD
cd packaging/arch
makepkg -si                       # builds linhello-*.pkg.tar.zst and installs it

# 3. Start the daemon (Arch doesn't auto-start it on install)
sudo systemctl enable --now linhellod

# 4. Face-recognition models (~250 MB, one time)
sudo linhello fetch-models

# 5. Set up — pick your camera, enroll, and wire up login
sudo linhello tui
```

`onnxruntime` is the one model dependency Arch packages for you — the
`onnxruntime-cuda` build works too, since it provides `onnxruntime`. The wizard
checks your hardware, picks your camera, enrolls your face, and wires up login —
one step at a time, showing you every change it makes to your system.

### Set up from the CLI (instead of the wizard)

`linhello tui` runs all of this interactively. If you'd rather drive it step by
step — for scripting, headless work, or just to see each piece — every stage has
a plain command (all of these need `sudo`):

```sh
sudo linhello doctor                # check TPM, camera(s), fingerprint, models, ONNX — should say READY

# ── Option A: face ──────────────────────────────────────────────────────
sudo linhello enroll --user "$USER" # look at the camera and hold still (captures 5 samples)
sudo linhello test                  # confirm it recognizes you (safe; can't lock you out)
# Wire face login into your PAM stacks — greeter + lock screen, plus sudo with --sudo.
# Add --dry-run first to preview the exact edits without changing anything:
sudo linhello pam enable --sudo
sudo linhello seal-password         # seal your login password so face login unlocks the keyring

# ── Option B: fingerprint ───────────────────────────────────────────────
# A standalone secure-tier method — the secure choice on RGB-only laptops.
# Enrolls a finger and wires pam_fprintd for login/sudo (password stays a fallback):
sudo linhello fingerprint enable
sudo linhello fingerprint add --name "Right thumb"   # add more fingers, named (Android-style)
linhello fingerprint status                          # reader, enrolled fingers, active method
sudo linhello fingerprint disable                    # stop using it; face/password resume

# ── Recovery passphrase (recommended) ───────────────────────────────────
# A dedicated backstop, SEPARATE from your login password, for the rare cases
# the automatic TPM self-heal can't cover (Secure Boot off, TPM cleared, disk moved):
sudo linhello set-recovery
sudo linhello recover               # later: restore the template key + re-seal it (no re-enroll)

linhello pam status                 # show what face login is currently wired
sudo linhello pam disable           # remove face login again (password login always stays)
```

Pick the method that fits your hardware — linhello defaults sensibly (fingerprint
is the secure default on RGB-only machines; IR face on machines with an IR camera)
and you can switch any time. The chosen method lives in
`/etc/linhello/policy.conf` (`method = face-rgb|face-ir|fingerprint|auto`); setting
`fingerprint` suppresses the face prompt, and vice-versa. Re-run
`sudo linhello enroll` anytime to add face samples (glasses on/off, varied
lighting). Password login and the TTY console (Ctrl+Alt+F2) are never touched, so
you always have a way in.

## 🎯 Everyday commands

```sh
linhello test                 # does it recognize me right now?
linhello doctor               # is everything healthy?
linhello fingerprint status   # fingerprint reader / enrolled fingers / method
sudo linhello tui             # re-run setup, manage profiles, or uninstall
```

## 🔄 Update

```sh
sudo linhello update
```

Pulls the latest LinuxHello from GitHub, rebuilds, and reinstalls in place —
it works even if you originally installed from a ZIP download (it keeps its
own clone under `/var/lib/linhello/src`). Your enrolled faces, configuration,
models, and login wiring are never touched; wiring is only *extended* if a new
version supports a login service yours didn't (and only if you had wiring
enabled).

## 🔒 Security in one paragraph

Face templates are encrypted (AES-256-GCM) with a key that only your TPM can
release — and, when Secure Boot is enabled, only while your boot state is
untampered (the `Medium`/`Full` tiers; without Secure Boot the key is still
TPM-sealed but not bound to boot state). Anti-spoofing rejects photos and virtual
cameras. **Neither kernel nor firmware/dbx updates break it** — on a UKI the
binding follows systemd's signed PCR-11 policy, and on GRUB linhello signs its
own PCR-7 policy and re-signs it automatically after a firmware update (while
Secure Boot stays on). A dedicated **recovery passphrase** (separate from your
login password — `linhello set-recovery` / `linhello recover`) is the manual
backstop for the rare cases that can't self-heal. The TTY console login is never
touched, so there's always a way in. Details:
[`docs/design/signed-pcr-policy.md`](docs/design/signed-pcr-policy.md).

### Security tiers (what face auth is allowed to do)

LinuxHello adapts to your camera, and `linhello doctor` shows exactly which tier
you're on and what each operation does:

- **Secure tier** — **IR face** (RGB + working active-IR) **or a fingerprint**.
  Either can log you in, unlock your keyring, and authorize `sudo`/`polkit`:
  IR liveness makes face-spoofing hard, and a fingerprint is a strong factor on
  its own. This is the Windows Hello-equivalent posture.
- **Convenience tier** — RGB-only face (most laptops, no IR or fingerprint). Face
  **unlocks an already open session** (screen unlock) but **never releases your
  password** — login and `sudo` fall back to typing it. RGB-alone can't be trusted
  to release credentials, so it structurally won't.

Anything remote (ssh) or unrecognized is always declined → password. Tune the
per-operation policy in `/etc/linhello/policy.conf` (keys `screen_unlock`,
`login`, `sudo`, `polkit` = `off`|`rgb`|`ir`; `tier` = `auto`|`secure`|
`convenience`; `method` = `face-rgb`|`face-ir`|`fingerprint`|`auto`); defaults are
the safe ones above. Rationale and evidence:
[`docs/design/tiered-biometric-policy.md`](docs/design/tiered-biometric-policy.md).

### 🫆 Fingerprint — instead of, or alongside, face

If your machine has a fingerprint reader, linhello treats it as a **standalone
secure-tier method** (never blended with face — you pick one). It's especially
useful on RGB-only laptops, where it's the *only* way to reach the secure tier.

```sh
linhello fingerprint status        # reader, enrolled fingers, the recommended method
sudo linhello fingerprint enable   # enroll a finger + wire it for login/sudo
sudo linhello fingerprint add --name "Right thumb"   # add more, with Android-style names
sudo linhello fingerprint disable  # stop using it; face/password resume
```

Verification runs through the standard `fprintd`/`pam_fprintd` (so the greeter
shows the fingerprint prompt natively), wired per distro automatically. When
fingerprint is your chosen method, the face prompt is suppressed. Your password
always works as a fallback. The `setup` wizard and `linhello tui` offer it too.

## 🆚 Compared to Howdy

[Howdy](https://github.com/boltgolt/howdy) is the established, widely-packaged
face-unlock tool for Linux and well worth a look. LinuxHello takes a different
approach in a few respects:

|                  | LinuxHello                                                   | Howdy                                                          |
|------------------|-------------------------------------------------------------|---------------------------------------------------------------|
| Language         | Rust                                                        | Python (+ C++)                                                |
| Credential model | Password sealed in the **TPM**, released on a face match    | PAM module that returns success on a face match (no TPM)       |
| Anti-spoofing    | Bundles a liveness model that rejects photos/virtual cameras | Its own docs note a well-printed photo can be enough to fool it |
| Face recognition | InsightFace ONNX (ArcFace + SCRFD)                          | dlib / `face_recognition`                                     |
| Second factor    | **Fingerprint** as a standalone secure-tier method (via fprintd) | Face only                                                |
| Update-resilience| Survives kernel **and** firmware/dbx updates (auto re-sign) | A boot/firmware change can require re-enrolling               |
| Maturity         | New                                                         | Mature, widely packaged                                       |

## 🧹 Uninstall

```sh
sudo linhello uninstall --yes
```

Removes everything (PAM is unwired first — password login is never at risk).

## 📜 License

GPL-3.0-or-later. Bundled anti-spoof models: Apache-2.0 ([notice](models/antispoof.NOTICE)).
Face-recognition models (buffalo_l) are downloaded directly by the user from the upstream [InsightFace](https://github.com/deepinsight/insightface) repository. These weights are subject to InsightFace's non-commercial research license and are intended solely for personal, non-commercial use by the end-user.

## 📚 Citations and Attributions

This project provides automated plumbing for state-of-the-art biometrics and
face anti-spoofing research. If you use this software, please acknowledge the
foundational upstream research works.

### InsightFace — ArcFace (buffalo_l recognizer, `w600k_r50`)

```bibtex
@inproceedings{deng2019arcface,
  title={ArcFace: Additive Angular Margin Loss for Deep Face Recognition},
  author={Deng, Jiankang and Guo, Jia and Xue, Niannan and Zafeiriou, Stefanos},
  booktitle={Proceedings of the IEEE/CVF Conference on Computer Vision and Pattern Recognition (CVPR)},
  pages={4690--4699},
  year={2019}
}
```

### InsightFace — SCRFD (buffalo_l detector, `det_10g`)

```bibtex
@article{guo2021sample,
  title={Sample and Computation Redistribution for Efficient Face Detection},
  author={Guo, Jia and Deng, Jiankang and Lattas, Alexandros and Zafeiriou, Stefanos},
  journal={arXiv preprint arXiv:2105.04714},
  year={2021}
}
```

> This is InsightFace's officially requested citation form (the paper was
> subsequently accepted at ICLR 2022).

See the [InsightFace README](https://github.com/deepinsight/insightface/blob/master/README.md)
for the project's full citation and attribution requests.

### Silent-Face-Anti-Spoofing

```bibtex
@misc{silentface2020,
  author       = {Minivision},
  title        = {Silent-Face-Anti-Spoofing: Real-time Face Anti-Spoofing Framework},
  year         = {2020},
  publisher    = {GitHub},
  howpublished = {\url{https://github.com/minivision-ai/Silent-Face-Anti-Spoofing}}
}
```
