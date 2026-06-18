# Skip auto debuginfo extraction: these are Rust release binaries and we strip
# via cargo; the rpm debuginfo pass adds friction without value for a COPR build.
%global debug_package %{nil}

%global selinuxtype targeted

Name:           linhello
Version:        0.3.2
Release:        1%{?dist}
Summary:        TPM-backed face authentication for Linux (Windows Hello-style)

License:        GPL-3.0-or-later
URL:            https://github.com/archledger/linhello
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

# Build deps — match `linhello deps --only build` for Fedora.
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  clang
BuildRequires:  clang-devel
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconf-pkg-config
BuildRequires:  tpm2-tss-devel
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel

# Runtime deps — match `linhello deps --only runtime` for Fedora.
Requires:       tpm2-tss
Requires:       pam
Requires:       libv4l
# ONNX Runtime is not in Fedora main (RPMFusion/COPR or self-built). The daemon
# dlopens it and reports an actionable error if absent, so keep it weak rather
# than block install on a package the user may have provided out of band.
Recommends:     onnxruntime

# SELinux policy scriptlet requirements (semodule, restorecon, policy store).
%{?selinux_requires}

# systemd scriptlet requirements.
%{?systemd_requires}
Requires(pre):  shadow-utils

%description
LinuxHello adds Windows Hello-style face login to Linux: a small daemon performs
IR/RGB face recognition with anti-spoofing and unseals a TPM-sealed copy of your
password to satisfy PAM, so the greeter, lock screen and sudo can authenticate by
face while the password remains a fallback.

This package confines the daemon in its own SELinux domain (linhellod_t) and
creates the `linhello` group used for unprivileged CLI access to the control
socket. Face login is not wired into PAM automatically — run `linhello pam
enable` (and `linhello setup`) after install.

%prep
%autosetup -n %{name}-%{version}

%build
# Rust workspace + the C PAM shim (cargo fetches crates; needs network — vendor
# or use rust2rpm for an offline Koji build). PAMDIR must match the install
# step: it is baked into pam_linhello.so's RUNPATH so it can dlopen
# liblinhello_pam.so from the 64-bit security dir.
%make_build all PAMDIR=%{_libdir}/security

# SELinux daemon-confinement policy module (linhellod_t).
make -C etc/selinux -f %{_datadir}/selinux/devel/Makefile linhello-daemon.pp

%check
# Hardware-free unit tests (TPM/policy/platform logic; biometrics/camera tests
# need devices and are skipped here).
cargo test --release -p linhello-common -p linhello-core

%install
# Reuse the project's DESTDIR-safe installer with Fedora paths. PAM modules go in
# the 64-bit security dir; the systemd unit in the system unit dir. The sysusers
# runtime call inside `make install` is skipped under DESTDIR.
%make_install \
    PREFIX=%{_prefix} \
    BINDIR=%{_bindir} \
    PAMDIR=%{_libdir}/security \
    SYSTEMDDIR=%{_unitdir} \
    CONFDIR=%{_sysconfdir}/%{name}

# Ship the built SELinux policy module for the scriptlets to load.
install -Dm644 etc/selinux/linhello-daemon.pp \
    %{buildroot}%{_datadir}/selinux/packages/linhello-daemon.pp

# Generated %%files list: always the SELinux module, plus the trusted release
# key only when `make install` shipped it (packaging/trusted-signer.asc was
# committed). Keeps the build green either way and avoids an empty -f list.
echo "%{_datadir}/selinux/packages/linhello-daemon.pp" > extra-files.txt
if [ -f %{buildroot}%{_sysconfdir}/%{name}/trusted-signer.asc ]; then
    echo "%config(noreplace) %{_sysconfdir}/%{name}/trusted-signer.asc" >> extra-files.txt
fi

%files -f extra-files.txt
%license LICENSE
%doc README.md
%{_bindir}/linhellod
%{_bindir}/linhello
%{_bindir}/linhello-reseal-hook
%dir %{_libdir}/security
%{_libdir}/security/pam_linhello.so
%{_libdir}/security/liblinhello_pam.so
%{_unitdir}/linhellod.service
%{_sysusersdir}/linhello.conf
%{_datadir}/%{name}/
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/antispoof.onnx
%config(noreplace) %{_sysconfdir}/%{name}/antispoof_4.onnx
%{_sysconfdir}/%{name}/selinux/

%pre
# Create the `linhello` group before files land (sysusers.d also ships it; this
# guarantees ordering for the socket-group chown on first daemon start).
getent group linhello >/dev/null || groupadd -r linhello || :

%post
%systemd_post linhellod.service
# Load the daemon SELinux module and relabel the binary/config so the daemon
# transitions into linhellod_t. The runtime socket is labeled by the policy's
# file-type transition when the daemon (re)creates it.
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/linhello-daemon.pp
if %{_sbindir}/selinuxenabled 2>/dev/null; then
    %{_sbindir}/restorecon -R %{_bindir}/linhellod %{_sysconfdir}/%{name} || :
    %{_sbindir}/restorecon %{_rundir}/linhello.sock 2>/dev/null || :
fi
# Enable + start the daemon now (after the SELinux module is loaded and the
# binary relabeled, so it transitions into linhellod_t). The daemon binds its
# socket lazily — no face models or ONNX Runtime are needed at startup — so this
# is safe immediately after install: `linhello doctor` works right away and face
# auth is ready on the next boot. Non-fatal so a sandbox/container install that
# can't talk to systemd still succeeds.
%{_bindir}/systemctl enable --now linhellod.service >/dev/null 2>&1 || :

%preun
%systemd_preun linhellod.service

%postun
%systemd_postun_with_restart linhellod.service
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} linhello-daemon
fi

%posttrans
%selinux_relabel_post -s %{selinuxtype}

%changelog
* Thu Jun 18 2026 archledger <archledger236@gmail.com> - 0.3.2-1
- Arch packaging/update fix: `linhello package`/`update` no longer mis-select the
  makepkg `-debug` split (which carries no binaries) as the installable. PKGBUILD
  now builds a single stripped package (options=!debug) and the package picker
  skips -debug/-dbgsym artifacts. No functional change on Fedora.

* Thu Jun 18 2026 archledger <archledger236@gmail.com> - 0.3.1-1
- Fedora install polish: %post now enables + starts the daemon (so `linhello
  doctor` works immediately); new `linhello fetch-onnx` installs the matching
  ONNX Runtime where it isn't packaged; `linhello deps` routes ONNX to fetch-onnx
  instead of a non-existent Fedora package; fetch-models reliably restarts the
  daemon. Groundwork for the Fedora COPR (native dnf install/update with deps).

* Wed Jun 17 2026 archledger <archledger236@gmail.com> - 0.3.0-1
- Hardware-adaptive tiered biometric policy: Secure tier (RGB + working IR)
  unseals the TPM password for login/sudo/polkit; Convenience tier (RGB-only)
  verifies for live-session screen unlock but never unseals credentials.
- Daemon-centralised verify/unseal/deny decision (classify service + tier +
  warm logind session), replacing the PAM euid heuristic.
- Pre-flight auth-intent so the "Looking for your face..." prompt only shows
  when the camera will actually engage.
- Honor cameras.conf across reboots (canonicalize symlink device paths,
  readable-config warning).
- SELinux: linhellod_t reads logind warm-session state and Secure Boot state
  (efivarfs); device-probe retry to ride out Windows-Hello USB resets.

* Tue Jun 16 2026 archledger <archledger236@gmail.com> - 0.2.0-1
- Fedora port milestone: confined daemon SELinux domain (linhellod_t,
  runtime-validated), per-distro reseal trigger, sysusers group, dependency
  surfacing, `linhello fetch-models`, PAM rpath fix, TUI wiring-status fix.

* Tue Jun 16 2026 archledger <archledger236@gmail.com> - 0.1.0-1
- Initial Fedora package: confined daemon (linhellod_t), sysusers group,
  systemd unit, PAM module. Face login wired via `linhello pam enable`.
