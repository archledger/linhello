#!/usr/bin/env bash
# Build source RPMs for the LinuxHello COPR: the daemon (linhello) plus its
# ONNX Runtime dependency (not in Fedora's main repos). Upload the results with
#   copr-cli build <you>/linhello <srpm>
# building onnxruntime first so linhello's weak dependency resolves.
#
# Usage: packaging/fedora/build-srpms.sh [git-ref]   (default: HEAD)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
top="$repo/target/rpmbuild"
ver="$(grep -m1 '^Version:' "$here/linhello.spec" | awk '{print $2}')"
ortver="$(grep -m1 '%global ortver' "$here/onnxruntime.spec" | awk '{print $3}')"
case "$(uname -m)" in
  x86_64)  ortarch=x64 ;;
  aarch64) ortarch=aarch64 ;;
  *) echo "unsupported arch $(uname -m) — Microsoft ships no ONNX Runtime prebuilt" >&2; exit 1 ;;
esac

mkdir -p "$top/SOURCES" "$top/SRPMS"

# linhello source tarball from a clean ref (pass a release tag for a release build).
ref="${1:-HEAD}"
git -C "$repo" archive --format=tar.gz --prefix="linhello-$ver/" \
    -o "$top/SOURCES/linhello-$ver.tar.gz" "$ref"

# Official Microsoft ONNX Runtime prebuilt (cached after first download).
ort_tgz="$top/SOURCES/onnxruntime-linux-$ortarch-$ortver.tgz"
[ -f "$ort_tgz" ] || curl -fsSL --proto '=https' --tlsv1.2 -o "$ort_tgz" \
    "https://github.com/microsoft/onnxruntime/releases/download/v$ortver/onnxruntime-linux-$ortarch-$ortver.tgz"

rpmbuild -bs --define "_topdir $top" "$here/onnxruntime.spec"
rpmbuild -bs --define "_topdir $top" "$here/linhello.spec"

echo
echo "Built SRPMs (upload onnxruntime first):"
ls -1 "$top"/SRPMS/*.src.rpm
