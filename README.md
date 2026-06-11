# LinuxHello

**Face login for Linux** — like Windows Hello. Look at your camera to unlock your login screen, keyring, and sudo.

Your password isn't replaced — it's sealed in your computer's TPM chip and released when your face matches. If the camera, TPM, or anything else fails, you just type your password like normal. **You can never be locked out.**

## What you need

- A TPM 2.0 chip (most PCs since ~2016 — check: `ls /dev/tpm*`)
- A webcam (a Windows Hello IR camera is a bonus, not required)
- Arch Linux (Debian/Ubuntu/Fedora support is experimental)

## Install

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

## Everyday commands

```sh
linhello test        # does it recognize me right now?
linhello doctor      # is everything healthy?
sudo linhello tui    # re-run setup, manage profiles, or uninstall
```

## Update

```sh
sudo linhello update
```

Pulls the latest LinuxHello from GitHub, rebuilds, and reinstalls in place —
it works even if you originally installed from a ZIP download (it keeps its
own clone under `/var/lib/linhello/src`). Your enrolled faces, configuration,
models, and login wiring are never touched; wiring is only *extended* if a new
version supports a login service yours didn't (and only if you had wiring
enabled).

## Security in one paragraph

Face templates are encrypted (AES-256-GCM) with a key that only your TPM can
release, and only when your machine's boot state (Secure Boot) is untampered.
Anti-spoofing rejects photos and virtual cameras. Kernel updates don't break it.
The TTY console login is never touched, so there's always a way in. Details:
[`docs/design/signed-pcr-policy.md`](docs/design/signed-pcr-policy.md).

## Uninstall

```sh
sudo linhello uninstall --yes
```

Removes everything (PAM is unwired first — password login is never at risk).

## License

GPL-3.0-or-later. Bundled anti-spoof models: Apache-2.0 ([notice](models/antispoof.NOTICE)).
Face-recognition models (buffalo_l) are downloaded directly by the user from the upstream [InsightFace](https://github.com/deepinsight/insightface) repository. These weights are subject to InsightFace's non-commercial research license and are intended solely for personal, non-commercial use by the end-user.

## Citations and Attributions

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
@inproceedings{guo2022scrfd,
  title={Sample and Computation Redistribution for Efficient Face Detection},
  author={Guo, Jia and Deng, Jiankang and Lattas, Alexandros and Zafeiriou, Stefanos},
  booktitle={International Conference on Learning Representations (ICLR)},
  year={2022}
}
```

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
