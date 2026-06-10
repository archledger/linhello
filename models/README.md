# LinuxHello face models

The biometrics pipeline loads up to three ONNX models at runtime:

| Role        | Env var                   | Default path                    | File                                       |
|-------------|---------------------------|---------------------------------|--------------------------------------------|
| Detector    | `LINHELLO_DET_MODEL`        | `/etc/linhello/det_10g.onnx`      | `det_10g.onnx`                             |
| Recognizer  | `LINHELLO_MODEL_PATH`       | `/etc/linhello/face.onnx`         | `w600k_r50.onnx` (rename to `face.onnx`)   |
| Anti-spoof  | `LINHELLO_ANTISPOOF_MODEL`  | `/etc/linhello/antispoof.onnx`    | MiniFASNet `2.7_80x80` ONNX (optional — see below) |

Detector + recognizer both ship inside the `buffalo_l` pack from InsightFace.
Anti-spoof is a separate model from `minivision-ai/Silent-Face-Anti-Spoofing`.

> **The models are NOT distributed with LinuxHello** (size + upstream
> licensing). Obtain them from the official sources below. The setup wizard
> (`linhello tui` / `linhello setup`) makes this painless: if it finds the model
> files in a directory it knows about, it copies them in automatically — no
> typing, no download prompt. It looks, in order, at:
>
> 1. `$LINHELLO_MODELS_DIR`
> 2. `<repo>/models/` (next to the source tree the installer runs from)
> 3. `/usr/share/linhello/models/`
>
> Drop `det_10g.onnx`, `face.onnx` (and optionally `antispoof.onnx`) into any of
> those and the installer handles the rest. `make models-bundle` packs the models
> already on a working machine into a tarball you can carry to another box — a
> convenience for *your own* deployments, not a redistribution channel.

## Installing buffalo_l

```sh
# ~250 MB download
curl -L -o /tmp/buffalo_l.zip \
    https://github.com/deepinsight/insightface/releases/download/v0.7/buffalo_l.zip

unzip -d /tmp/buffalo_l /tmp/buffalo_l.zip

sudo mkdir -p /etc/linhello
sudo install -m 0644 /tmp/buffalo_l/det_10g.onnx     /etc/linhello/det_10g.onnx
sudo install -m 0644 /tmp/buffalo_l/w600k_r50.onnx   /etc/linhello/face.onnx
```

Or, for a dev run without root, place them anywhere and point the two env vars:

```sh
export LINHELLO_DET_MODEL=/path/to/det_10g.onnx
export LINHELLO_MODEL_PATH=/path/to/w600k_r50.onnx
linhello enroll
```

## The anti-spoof model ships with LinuxHello

Unlike buffalo_l, the MiniFASNet anti-spoof models are **Apache-2.0** and small
(~1.9 MB each), so they ship in this repo (`models/antispoof.onnx`,
`models/antispoof_4.onnx`) and `make install` deploys them to `/etc/linhello`
automatically. **No PyTorch, no conversion, nothing to download** — that's why
a fresh install doesn't need the heavy toolchain.

Without this model LinuxHello would still recognize faces, but a printed photo
of the enrolled user would pass; with it, MiniFASNet scores a spoof probability
on every verify and the daemon rejects frames above `LINHELLO_SPOOF_THRESHOLD`
(default 0.5). The daemon is fail-closed by default, so the bundled model
keeps that protection on out of the box.

Provenance + checksums are in `models/antispoof.NOTICE` and `models/SHA256SUMS`
— **verify them**, since a tampered liveness model would silently always say
"real". To rebuild from the upstream `.pth` weights yourself (and confirm the
checksums match):

```sh
# one-time (~2 GB on Arch) — only needed if you want to re-derive the models
sudo pacman -S python-pytorch git
python3 scripts/convert_antispoof.py antispoof.onnx
sha256sum -c models/SHA256SUMS
```

Tune or disable:

```sh
# Loosen the threshold (easier to pass; more spoofs slip through):
export LINHELLO_SPOOF_THRESHOLD=0.7

# Fail-closed if the model is missing (production):
export LINHELLO_REQUIRE_ANTISPOOF=1

# Inspect raw scores on the current camera:
linhello liveness-test
```

A virtual-camera check (`v4l2loopback`, OBS Virtual Cam) runs unconditionally
and does not require any model.
