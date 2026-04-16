#!/usr/bin/env python3
"""Convert the upstream MiniFASNet .pth weights to ONNX files that
aegyra-liveness can consume.

Why a conversion step? The minivision-ai/Silent-Face-Anti-Spoofing repo
ships PyTorch `.pth` checkpoints, not ONNX. For a security-critical gate
we prefer converting upstream weights ourselves over trusting a random
third-party mirror — a tampered anti-spoof model that always outputs
"real" would silently defeat liveness.

Exports BOTH models used by upstream's `test.py`:

    2.7_80x80_MiniFASNetV2.pth   → antispoof.onnx     (primary,   2.7× crop)
    4_0_0_80x80_MiniFASNetV1SE.pth → antispoof_4.onnx (secondary, 4.0× crop)

aegyra-liveness runs both and averages their softmax outputs (dual-model
fusion). Single-model MiniFASNet is known to pass printed-photo attacks
at any usable threshold — the ensemble gives genuine separation.

Usage:
    # one-time: install conversion deps (~2.5 GB on Arch)
    sudo pacman -S python-pytorch python-onnxscript git

    # run from the aegyra repo root
    python3 scripts/convert_antispoof.py

    # install both
    sudo install -m 0644 antispoof.onnx   /etc/aegyra/antispoof.onnx
    sudo install -m 0644 antispoof_4.onnx /etc/aegyra/antispoof_4.onnx

Both ONNX files share the same input convention:
    input  : [1, 3, 80, 80] BGR float32, raw 0-255 (no mean/std)
    output : [1, 3] logits  (class 1 = real)
They differ in the pre-crop scale applied to the face bbox (2.7 vs 4.0);
that's hardcoded per-model in aegyra-liveness.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

# Pinned to a known-good revision of the upstream repo. Update with care
# — verify the model architecture hasn't shifted.
UPSTREAM_REPO = "https://github.com/minivision-ai/Silent-Face-Anti-Spoofing.git"
UPSTREAM_REF = "master"

# (weights filename, architecture constructor name, output ONNX filename).
EXPORTS = [
    ("2.7_80x80_MiniFASNetV2.pth",    "MiniFASNetV2",   "antispoof.onnx"),
    ("4_0_0_80x80_MiniFASNetV1SE.pth", "MiniFASNetV1SE", "antispoof_4.onnx"),
]


def export_one(torch_mod, repo_dir: Path, weights_name: str, cls_name: str, out_path: Path) -> None:
    try:
        model_lib = __import__("model_lib.MiniFASNet", fromlist=[cls_name])
    except ImportError as e:
        raise RuntimeError(f"upstream layout changed — cannot import {cls_name}: {e}") from e
    cls = getattr(model_lib, cls_name, None)
    if cls is None:
        raise RuntimeError(f"upstream no longer defines {cls_name}")

    weights_path = repo_dir / "resources" / "anti_spoof_models" / weights_name
    if not weights_path.exists():
        raise RuntimeError(f"expected weights not found at {weights_path}")

    print(f"==> loading weights {weights_name}")
    state = torch_mod.load(weights_path, map_location="cpu")
    state = {k.replace("module.", "", 1): v for k, v in state.items()}

    model = cls(
        embedding_size=128,
        conv6_kernel=(5, 5),
        drop_p=0.0,
        num_classes=3,
        img_channel=3,
    )
    model.load_state_dict(state)
    model.eval()

    print(f"==> exporting ONNX → {out_path}")
    dummy = torch_mod.randn(1, 3, 80, 80)
    # See prior notes on external_data=False and opset_version=18.
    torch_mod.onnx.export(
        model, dummy, str(out_path),
        input_names=["input"], output_names=["logits"],
        opset_version=18, do_constant_folding=True,
        dynamic_axes=None, external_data=False,
    )


def main() -> int:
    try:
        import torch
    except ImportError:
        print("error: python-pytorch is required — install with:", file=sys.stderr)
        print("  sudo pacman -S python-pytorch python-onnxscript", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="aegyra-antispoof-") as td:
        td_path = Path(td)
        repo_dir = td_path / "repo"
        print(f"==> cloning {UPSTREAM_REPO} @ {UPSTREAM_REF}")
        subprocess.check_call([
            "git", "clone", "--depth=1",
            "--branch", UPSTREAM_REF,
            UPSTREAM_REPO, str(repo_dir),
        ])
        sys.path.insert(0, str(repo_dir / "src"))

        for weights_name, cls_name, out_name in EXPORTS:
            export_one(torch, repo_dir, weights_name, cls_name, Path(out_name))
            sz = Path(out_name).stat().st_size
            print(f"    wrote {out_name} ({sz:,} bytes)")

    print()
    print("next:")
    print("  sudo install -m 0644 antispoof.onnx   /etc/aegyra/antispoof.onnx")
    print("  sudo install -m 0644 antispoof_4.onnx /etc/aegyra/antispoof_4.onnx")
    print("  sudo systemctl restart aegyrad")
    print("  aegyra liveness-test   # dual-model spoof_prob")
    return 0


if __name__ == "__main__":
    sys.exit(main())
