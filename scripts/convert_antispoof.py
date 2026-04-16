#!/usr/bin/env python3
"""Convert the upstream MiniFASNet .pth weights to an ONNX file that
aegyra-liveness can consume.

Why a conversion step? The minivision-ai/Silent-Face-Anti-Spoofing repo
ships PyTorch `.pth` checkpoints, not ONNX. For a security-critical gate
we prefer converting upstream weights ourselves over trusting a random
third-party mirror — a tampered anti-spoof model that always outputs
"real" would silently defeat liveness.

Usage:
    # one-time: install conversion deps (~2 GB on Arch)
    sudo pacman -S python-pytorch git

    # run from the aegyra repo root
    python3 scripts/convert_antispoof.py [output.onnx]

    # install
    sudo install -m 0644 antispoof.onnx /etc/aegyra/antispoof.onnx

The exported model matches the conventions hardcoded in
crates/aegyra-liveness/src/antispoof.rs:
    input  : [1, 3, 80, 80], BGR float32, raw 0-255 (no mean/std)
    output : [1, 3] logits  (class 1 = real)
    scaled : 2.7× crop around face bbox before resizing

If you change the source weights (e.g. swap in the 4.0× model), update
those constants in antispoof.rs to match.
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

# The 2.7× scale MiniFASNetV2 is the smallest single-model choice that gives
# reasonable accuracy. Swap for 4_0_0_80x80_MiniFASNetV1SE.pth if you want
# the V1SE architecture (also update the architecture constructor below).
WEIGHTS_NAME = "2.7_80x80_MiniFASNetV2.pth"


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("antispoof.onnx")

    try:
        import torch  # noqa: F401  # checked lazily for a better error message
    except ImportError:
        print("error: python-pytorch is required — install with:", file=sys.stderr)
        print("  sudo pacman -S python-pytorch", file=sys.stderr)
        return 2

    import torch

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
        try:
            # Upstream module path. If this import fails, the repo layout has
            # drifted — verify with `ls src/model_lib/` in the clone.
            from model_lib.MiniFASNet import MiniFASNetV2  # type: ignore
        except ImportError as e:
            print(f"error: upstream layout changed — cannot import MiniFASNetV2: {e}",
                  file=sys.stderr)
            return 3

        weights_path = repo_dir / "resources" / "anti_spoof_models" / WEIGHTS_NAME
        if not weights_path.exists():
            print(f"error: expected weights not found at {weights_path}", file=sys.stderr)
            return 4

        print(f"==> loading weights {WEIGHTS_NAME}")
        state = torch.load(weights_path, map_location="cpu")
        # minivision checkpoints are saved via DataParallel — strip `module.` prefix.
        state = {k.replace("module.", "", 1): v for k, v in state.items()}

        model = MiniFASNetV2(
            embedding_size=128,
            conv6_kernel=(5, 5),
            drop_p=0.0,
            num_classes=3,
            img_channel=3,
        )
        model.load_state_dict(state)
        model.eval()

        print(f"==> exporting ONNX → {out_path}")
        dummy = torch.randn(1, 3, 80, 80)
        # `external_data=False` keeps the whole model in one file (the dynamo
        # exporter otherwise spills tensors to a sidecar `<out>.data`, which
        # onnxruntime then refuses to find unless installed alongside).
        #
        # `opset_version=18` matches what the current torch exporter can
        # produce; newer is fine for our onnxruntime 1.17+.
        torch.onnx.export(
            model,
            dummy,
            str(out_path),
            input_names=["input"],
            output_names=["logits"],
            opset_version=18,
            do_constant_folding=True,
            dynamic_axes=None,
            external_data=False,
        )

    sz = out_path.stat().st_size
    print(f"wrote {out_path} ({sz:,} bytes)")
    print()
    print("next:")
    print(f"  sudo install -m 0644 {out_path} /etc/aegyra/antispoof.onnx")
    print("  sudo systemctl restart aegyrad")
    print("  aegyra liveness-test   # should now print a real spoof_prob")
    return 0


if __name__ == "__main__":
    sys.exit(main())
