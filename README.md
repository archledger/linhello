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

- A TPM 2.0 chip (most PCs since ~2016 — check: `ls /dev/tpm*`)
- A webcam (a Windows Hello IR camera is a bonus, not required)
- Arch Linux (Debian/Ubuntu/Fedora support is experimental)

## ⚡ Install

```sh
# 1. Dependencies
sudo pacman -S --needed tpm2-tss onnxruntime v4l-utils base-devel rust

# 2. Get the code and build
git clone https://github.com/archledger/linhello
cd linhello
cargo build --release

# 3. Get the face-recognition models (~250 MB, one time)
curl -L -o /tmp/buffalo_l.zip \
    https://github.com/deepinsight/insightface/releases/download/v0.7/buffalo_l.zip
unzip -d /tmp/buffalo_l /tmp/buffalo_l.zip
mkdir -p models
cp /tmp/buffalo_l/det_10g.onnx   models/
cp /tmp/buffalo_l/w600k_r50.onnx models/face.onnx

# 4. Run the setup wizard — it does everything else
sudo target/release/linhello tui
```

The wizard installs the daemon, checks your hardware, picks your camera, enrolls
your face, and wires up login — one step at a time, showing you every change it
makes to your system.

## 🎯 Everyday commands

```sh
linhello test        # does it recognize me right now?
linhello doctor      # is everything healthy?
sudo linhello tui    # re-run setup, manage profiles, or uninstall
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
release, and only when your machine's boot state (Secure Boot) is untampered.
Anti-spoofing rejects photos and virtual cameras. Kernel updates don't break it.
The TTY console login is never touched, so there's always a way in. Details:
[`docs/design/signed-pcr-policy.md`](docs/design/signed-pcr-policy.md).

### Security tiers (what face auth is allowed to do)

LinuxHello adapts to your camera, and `linhello doctor` shows exactly which tier
you're on and what each operation does:

- **Secure tier** — RGB **plus a working active-IR** camera. Face can log you in,
  unlock your keyring, and authorize `sudo`/`polkit`, because IR liveness makes
  spoofing hard. This is the Windows Hello-equivalent posture.
- **Convenience tier** — RGB only (most laptops). Face **unlocks an already
  open session** (screen unlock) but **never releases your password** — login and
  `sudo` fall back to typing it. RGB-alone can't be trusted to release
  credentials, so it structurally won't.

Anything remote (ssh) or unrecognized is always declined → password. Tune the
per-operation policy in `/etc/linhello/policy.conf` (keys `screen_unlock`,
`login`, `sudo`, `polkit` = `off`|`rgb`|`ir`; `tier` = `auto`|`secure`|
`convenience`); defaults are the safe ones above. Rationale and evidence:
[`docs/design/tiered-biometric-policy.md`](docs/design/tiered-biometric-policy.md).

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
