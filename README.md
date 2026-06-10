# LinuxHello

**Windows Hello–style face login for Linux** — TPM-backed facial authentication that unlocks your login screen, keyring, and sudo. Your face never replaces your password; it *releases* it, sealed in your TPM, so everything that works today keeps working.

- **TPM 2.0 sealed secrets** — your login password and face-template key are sealed against your machine's boot state (Secure Boot PCRs). Stolen files are useless off-machine.
- **Encrypted face templates** — embeddings are AES-256-GCM encrypted at rest; the key lives only in the TPM.
- **Anti-spoofing** — MiniFASNet liveness (ships with LinuxHello), virtual-camera rejection, head-orientation gating, and IR signals on Windows Hello–class cameras.
- **Fail-safe by design** — face auth is always a *fallback-to-password* layer. A dead camera, missing TPM, or failed update degrades to your normal password, never a lockout. The TTY login is never touched.
- **Survives kernel updates** — secrets bind to Secure Boot state (PCR 7), not kernel hashes, so `pacman -Syu` doesn't break face login. A pacman hook re-seals automatically when Secure Boot keys rotate.

## Requirements

| | |
|---|---|
| **TPM 2.0** | `/dev/tpmrm0` (check: `ls /dev/tpm*`) |
| **Camera** | Any UVC webcam; IR (Windows Hello) cameras add liveness signals |
| **OS** | Arch Linux (primary). Debian/Ubuntu and Fedora are experimental |
| **Toolchain** | rust/cargo, gcc, make, pkg-config (source builds) |

System libraries (Arch): `sudo pacman -S --needed tpm2-tss onnxruntime v4l-utils base-devel rust`

## Install

```sh
git clone https://github.com/archledger/linhello
cd linhello
cargo build --release

# Fetch the face models (~250 MB, one-time — see models/README.md for details)
curl -L -o /tmp/buffalo_l.zip \
    https://github.com/deepinsight/insightface/releases/download/v0.7/buffalo_l.zip
unzip -d /tmp/buffalo_l /tmp/buffalo_l.zip
mkdir -p models
cp /tmp/buffalo_l/det_10g.onnx   models/det_10g.onnx
cp /tmp/buffalo_l/w600k_r50.onnx models/face.onnx

sudo make install          # installs binaries, PAM module, daemon, anti-spoof models
sudo systemctl enable --now linhellod
```

> The detector/recognizer models are from InsightFace's **buffalo_l** pack and are
> **not** redistributed here (upstream license). The anti-spoof models (Apache-2.0)
> ship in this repo. The installer auto-detects models placed in `<repo>/models/`.

## Set up

```sh
sudo linhello tui
```

The full-screen wizard walks every step and shows exactly what it changes on your
system: host check → camera selection → face enrollment (guided, with live framing
hints) → threshold calibration → identify test → **seal your login password** →
wire face login into PAM. Each step is gated, so you can't end up half-configured.

Prefer headless? `sudo linhello setup` does the same without the UI.

Useful commands:

```sh
linhello detect          # is LinuxHello installed/configured here? (exit 0/10/20)
linhello doctor          # full hardware/software readiness report
linhello test            # safe self-test: does it recognize you right now?
linhello identify        # 1:N — whose face is this?
sudo linhello pam status # where face login is wired
sudo linhello uninstall  # full removal (PAM unwired first; password login untouched)
```

## How it works

```
camera → SCRFD face detect → liveness (MiniFASNet + IR + orientation)
       → ArcFace embedding → cosine match vs encrypted template
       → TPM unseal login password → PAM_AUTHTOK → keyring unlocks
```

A small PAM module (`pam_linhello.so`) asks the root daemon (`linhellod`) to
verify your face and release the TPM-sealed password. If anything declines —
no face, spoof suspicion, TPM drift — PAM falls through to the normal password
prompt. `/etc/pam.d/login` (TTY) is never modified, so there is always an escape
hatch.

Security details: `docs/design/signed-pcr-policy.md`. Cross-distro plans:
`docs/design/cross-platform-and-setup-ux.md`.

## Uninstall

```sh
sudo linhello uninstall --yes          # removes everything incl. enrolled faces
sudo linhello uninstall --keep-models --yes   # keep the big models for reinstall
```

PAM is unwired *before* the module is removed, so login can't be left referencing
a missing library. Password login is unaffected throughout.

## License

GPL-3.0-or-later. Shipped anti-spoof models are Apache-2.0 (see
`models/antispoof.NOTICE`). InsightFace buffalo_l models are user-fetched and
remain under their upstream license.
