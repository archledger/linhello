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
