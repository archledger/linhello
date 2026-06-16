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
main); see `linhello deps` for the per-distro names and install command.
