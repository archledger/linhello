# Packaging

LinuxHello ships a native package per foundational distro family, so each OS
gets artifacts specific to it rather than a one-size source install:

| Family | Format | Definition | Notes |
|--------|--------|------------|-------|
| Fedora / RHEL | `.rpm` | [`fedora/linhello.spec`](fedora/linhello.spec) | Confines the daemon in its own SELinux domain (`linhellod_t`). Built + runtime-validated on Fedora 44. |
| Arch | `.pkg.tar.zst` | [`arch/PKGBUILD`](arch/PKGBUILD) + `arch/linhello.install` | No SELinux; pacman reseal hook. |
| Debian / Ubuntu | `.deb` | [`debian/`](debian/) | AppArmor distro — no SELinux module. **Authored, not yet build-tested.** |

All three reuse the project's `make install` with distro-appropriate paths
(PAM dir, unit dir), and rely on the same per-distro **gates** in
`linhello-common::platform`:

- `package_format()` — which format this distro uses (rpm/deb/pkg).
- `reseal_trigger()` — pacman hook vs kernel-install vs postinst.d.
- `security_module()` / `selinux_policy_plan()` — SELinux only where enforcing.
- sysusers.d `linhello` group (uniform across systemd distros).

## Building

`linhello` detects the distro and builds the right package:

```sh
linhello package              # build the native package for this distro
sudo linhello package --install
```

`linhello update` uses the same detection: it builds + installs the native
package when the build tooling is present, otherwise falls back to a
from-source `make install`.

Manual builds:

```sh
# Fedora
rpmbuild -bb packaging/fedora/linhello.spec     # Source0 from `git archive`
# Arch
make dist && (cd packaging/arch && makepkg -si)
# Debian (from a Debian box)
cp -rT packaging/debian debian && dpkg-buildpackage -b -us -uc
```

ONNX Runtime is the one dependency not packaged everywhere (not in Debian/Fedora
main; Arch has it). Options, in order of smoothness:

- **Fedora COPR** — ships a version-matched `onnxruntime` RPM
  ([`fedora/onnxruntime/onnxruntime.spec`](fedora/onnxruntime/onnxruntime.spec)) alongside `linhello`, so
  `dnf install linhello` pulls it natively. See [`fedora/COPR.md`](fedora/COPR.md).
- **`linhello fetch-onnx`** — one command that downloads + installs the official
  Microsoft prebuilt matching our ABI (the fallback for direct-RPM/source installs).
- `linhello deps` prints the per-distro names; the daemon reports an actionable
  hint if the runtime is missing.

## Fedora COPR

`dnf install linhello` + `dnf upgrade` for end users, with deps resolved
natively. Build the source RPMs (`packaging/fedora/build-srpms.sh`) and push them
with `copr-cli` — full walkthrough in [`fedora/COPR.md`](fedora/COPR.md).

## Releasing

`linhello update` only installs from a tag signed by the pinned release key, and
verifies it against `trusted-signer.asc` (installed to `/etc/linhello/`). So a
release needs the **public key shipped in the repo** and a **signed tag**:

1. One-time — export the public key on the signing box and commit it:

   ```sh
   gpg --export --armor <FINGERPRINT> > packaging/trusted-signer.asc
   ```

   (The fingerprint is pinned in `crates/linhello-cli/src/install.rs` as
   `TRUSTED_SIGNER_FINGERPRINT`.) The packages install it to
   `/etc/linhello/trusted-signer.asc`; without it `update` cannot verify.

2. Per release — bump the version everywhere it's pinned: `Cargo.toml`
   (workspace), `Makefile` `DIST_VERSION`, `packaging/arch/PKGBUILD` `pkgver`, and
   `packaging/fedora/linhello.spec` (plus the spec changelog). Commit, then create
   and **GPG-sign** the tag on the box that holds the key:

   ```sh
   git tag -s v0.2.0 -m 'linhello 0.2.0'
   git push origin v0.2.0
   ```

3. CI (`.github/workflows/release.yml`) verifies the tag against the committed
   key, builds the package, and attaches it to the GitHub Release. CI never
   signs — signing stays on the maintainer's machine.

Keep the tag and every pinned version (`Cargo.toml`, `Makefile` `DIST_VERSION`,
PKGBUILD `pkgver`, spec) plus the changelog in lockstep.

