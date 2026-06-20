# Publishing LinuxHello to a Fedora COPR

[COPR](https://copr.fedorainfracloud.org/) is Fedora's community build/repo
service. A LinuxHello COPR lets Fedora users install **and update** through `dnf`
the way they expect, with dependencies resolved natively:

```sh
sudo dnf copr enable archledger/linhello
sudo dnf install linhello          # pulls onnxruntime + the rest automatically
# updates ride along with normal `sudo dnf upgrade`
```

The COPR ships **two** packages, because ONNX Runtime isn't in Fedora's main
repositories:

| Package      | Spec                  | What it is |
|--------------|-----------------------|------------|
| `onnxruntime`| `onnxruntime/onnxruntime.spec`    | Official Microsoft prebuilt `libonnxruntime.so`, version-matched to the `ort` crate LinuxHello is built against (1.22.x ↔ ort 2.0.0-rc.10). |
| `linhello`   | `linhello.spec`       | The daemon/CLI/PAM module. `Recommends: onnxruntime`, so `dnf` pulls it from the same COPR by default. |

> **Layout note:** `onnxruntime.spec` lives in its **own subdirectory**
> (`packaging/fedora/onnxruntime/`), leaving exactly one `.spec` directly under
> `packaging/fedora/`. This is deliberate: Packit's `copr_build` hands COPR the
> spec's directory, and COPR's auto-SRPM step aborts with *"too many specfiles"*
> if it finds more than one `.spec` there. Don't move `onnxruntime.spec` back up
> beside `linhello.spec` — it breaks the Packit-driven COPR build.

## One-time: create the project

Requires a [Fedora account](https://accounts.fedoraproject.org/) and
`sudo dnf install copr-cli`, then `copr-cli` authenticated via the API token from
<https://copr.fedorainfracloud.org/api/>.

```sh
copr-cli create linhello \
    --chroot fedora-44-x86_64 \
    --chroot fedora-rawhide-x86_64 \
    --enable-net on \
    --description "Windows Hello-style face authentication for Linux"
```

**Network must be on** (`--enable-net on`, or the project's *Settings → Build
options*): `linhello.spec`'s `cargo build` fetches crates from crates.io inside
the chroot. (The stricter, network-free alternative is to `cargo vendor` the
dependencies into the SRPM — not done yet.) `onnxruntime` itself builds offline
— its tarball is bundled in the SRPM.

(Add `fedora-NN-aarch64` chroots later — `onnxruntime/onnxruntime.spec` already supports
aarch64; `build-srpms.sh` must then be run on/for that arch.)

## Each release: build + upload

From a clean checkout (pass the signed release tag so the SRPM matches the
release exactly):

```sh
packaging/fedora/build-srpms.sh v0.3.0          # -> target/rpmbuild/SRPMS/*.src.rpm

# Build onnxruntime FIRST so linhello's weak dep resolves in the same repo:
copr-cli build linhello target/rpmbuild/SRPMS/onnxruntime-*.src.rpm
copr-cli build linhello target/rpmbuild/SRPMS/linhello-*.src.rpm
```

`onnxruntime` only needs rebuilding when its pinned version changes (i.e. when a
LinuxHello release bumps the `ort` crate). `linhello` is rebuilt every release.

> COPR builds each SRPM in a clean mock chroot. `onnxruntime/onnxruntime.spec` just unpacks
> the bundled prebuilt (no network). `linhello.spec` compiles the Rust workspace,
> which fetches crates — hence `--enable-net on` above.

## Automated builds from releases (Packit)

`linhello` is rebuilt automatically on every release by [Packit](https://packit.dev),
configured in [`.packit.yaml`](../../.packit.yaml). When a signed `v*` tag is
pushed and `release.yml` publishes the GitHub Release, Packit submits a COPR
build of `linhello` for that exact tag (it generates the source tarball from the
tag, so the build always matches the released commit).

**One-time setup:** install the **Packit** GitHub App on the repository
(<https://github.com/marketplace/packit-as-a-service>) and grant it access to
`archledger/linhello`. The COPR project (`archledger/linhello`) and its
`fedora-44-x86_64` chroot already exist, so no further COPR-side config is
needed; Packit submits builds into it.

**`onnxruntime` is *not* automated.** Its source is Microsoft's external prebuilt
binary (not this repo), so Packit's git-archive source generation doesn't apply.
Rebuild it manually only when its pinned version changes — i.e. when a release
bumps the `ort` crate ABI (e.g. 1.22.0 → 1.24.4 for `ort` rc.10 → rc.12):

```sh
packaging/fedora/build-srpms.sh v<tag>
copr-cli build linhello target/rpmbuild/SRPMS/onnxruntime-*.src.rpm   # before linhello
```

So a normal release is fully automatic; an ABI-bump release is one extra manual
`onnxruntime` upload, then Packit handles `linhello`.

## Verifying a build locally first

`build-srpms.sh` produces the exact SRPMs COPR consumes. To dry-run a full build
the way COPR does (clean chroot), use mock:

```sh
sudo dnf install mock
mock -r fedora-44-x86_64 target/rpmbuild/SRPMS/onnxruntime-*.src.rpm
mock -r fedora-44-x86_64 target/rpmbuild/SRPMS/linhello-*.src.rpm
```
