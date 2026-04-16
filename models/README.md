# Aegyra face models

The biometrics pipeline loads up to three ONNX models at runtime:

| Role        | Env var                   | Default path                    | File                                       |
|-------------|---------------------------|---------------------------------|--------------------------------------------|
| Detector    | `AEGYRA_DET_MODEL`        | `/etc/aegyra/det_10g.onnx`      | `det_10g.onnx`                             |
| Recognizer  | `AEGYRA_MODEL_PATH`       | `/etc/aegyra/face.onnx`         | `w600k_r50.onnx` (rename to `face.onnx`)   |
| Anti-spoof  | `AEGYRA_ANTISPOOF_MODEL`  | `/etc/aegyra/antispoof.onnx`    | MiniFASNet `2.7_80x80` ONNX (optional — see below) |

Detector + recognizer both ship inside the `buffalo_l` pack from InsightFace.
Anti-spoof is a separate model from `minivision-ai/Silent-Face-Anti-Spoofing`.

## Installing buffalo_l

```sh
# ~250 MB download
curl -L -o /tmp/buffalo_l.zip \
    https://github.com/deepinsight/insightface/releases/download/v0.7/buffalo_l.zip

unzip -d /tmp/buffalo_l /tmp/buffalo_l.zip

sudo mkdir -p /etc/aegyra
sudo install -m 0644 /tmp/buffalo_l/det_10g.onnx     /etc/aegyra/det_10g.onnx
sudo install -m 0644 /tmp/buffalo_l/w600k_r50.onnx   /etc/aegyra/face.onnx
```

Or, for a dev run without root, place them anywhere and point the two env vars:

```sh
export AEGYRA_DET_MODEL=/path/to/det_10g.onnx
export AEGYRA_MODEL_PATH=/path/to/w600k_r50.onnx
aegyra enroll
```

## Installing the anti-spoof model (optional but recommended)

Without this model Aegyra still performs face recognition, but a printed photo
of the enrolled user's face will pass. With it, MiniFASNet scores a spoof
probability on every verify and the daemon rejects frames above
`AEGYRA_SPOOF_THRESHOLD` (default 0.5).

The MiniFASNet `2.7_80x80_MiniFASNetV2` model from
`minivision-ai/Silent-Face-Anti-Spoofing` is expected. Input is `[1,3,80,80]`
BGR float32 (0–255, no mean/std); output is three logits with class 1 = real.

Upstream ships `.pth` weights, not ONNX. Convert them yourself — we don't
trust third-party mirrors for a security-critical gate, because a tampered
model that always outputs "real" would silently defeat liveness:

```sh
# one-time (~2 GB on Arch)
sudo pacman -S python-pytorch git

# from the aegyra repo root
python3 scripts/convert_antispoof.py antispoof.onnx

# install
sudo install -m 0644 antispoof.onnx /etc/aegyra/antispoof.onnx
sudo systemctl restart aegyrad
aegyra liveness-test     # should now print a real spoof_prob
```

Tune or disable:

```sh
# Loosen the threshold (easier to pass; more spoofs slip through):
export AEGYRA_SPOOF_THRESHOLD=0.7

# Fail-closed if the model is missing (production):
export AEGYRA_REQUIRE_ANTISPOOF=1

# Inspect raw scores on the current camera:
aegyra liveness-test
```

A virtual-camera check (`v4l2loopback`, OBS Virtual Cam) runs unconditionally
and does not require any model.
