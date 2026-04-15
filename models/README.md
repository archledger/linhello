# Aegyra face models (InsightFace buffalo_l)

The biometrics pipeline loads two ONNX models at runtime:

| Role        | Env var              | Default path                   | File            |
|-------------|----------------------|--------------------------------|-----------------|
| Detector    | `AEGYRA_DET_MODEL`   | `/etc/aegyra/det_10g.onnx`     | `det_10g.onnx`  |
| Recognizer  | `AEGYRA_MODEL_PATH`  | `/etc/aegyra/face.onnx`        | `w600k_r50.onnx` (rename to `face.onnx`) |

Both ship inside the `buffalo_l` pack distributed by InsightFace.

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
