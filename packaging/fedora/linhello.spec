# Skip auto debuginfo extraction: these are Rust release binaries and we strip
# via cargo; the rpm debuginfo pass adds friction without value for a COPR build.
%global debug_package %{nil}

%global selinuxtype targeted

Name:           linhello
Version:        0.5.1
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
# than block install on a package the user may have provided out of band. The
# >= 1.24 floor matches the ABI linhello is built against (the ort 2.0.0-rc.12
# crate, which supports ONNX Runtime 1.17-1.24; the COPR ships 1.24.x) so a fresh
# install pulls a compatible runtime — raise it alongside any ort crate bump.
Recommends:     onnxruntime >= 1.24

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
# Copr/mock builders intermittently fail the crates.io sparse-index fetch with
# `download of config.json failed / curl failed` (HTTP/2 multiplexing against the
# registry is flaky under build-farm network contention). Harden the fetch so a
# transient blip retries instead of failing the whole build: many retries, and
# plain serial HTTP/1.1 connections to the registry. These only affect cargo's
# network step; the resulting binaries are identical.
export CARGO_NET_RETRY=10
export CARGO_HTTP_MULTIPLEXING=false

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
    UDEVDIR=%{_udevrulesdir} \
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
%{_unitdir}/linhellod-camera-refresh.service
%{_udevrulesdir}/72-linhello-camera.rules
%attr(0755,root,root) %{_systemd_util_dir}/system-sleep/linhello-resume
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
# Activate the camera-refresh udev rule now, not just at next boot: reload the
# rules and replay video4linux add events so a live install picks up the webcam
# and (via the rule's SYSTEMD_WANTS) refreshes the daemon's device access.
udevadm control --reload-rules >/dev/null 2>&1 || :
udevadm trigger --subsystem-match=video4linux --action=add >/dev/null 2>&1 || :

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
* Wed Jun 24 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.5.1-1
- Profiles: create named profiles to enroll into. `linhello enroll --user NAME`
  makes a SEPARATE profile, and a new `--name "Label"` sets its friendly display
  name in one step; in the setup TUI, the Profiles screen's `a` key now types a
  new profile name and targets it for enrollment (Tab → Enroll captures into it).
- TUI fix: the Profiles-screen delete prompt and result no longer overflow the
  fixed footer (long messages clipped against the border); they now appear in the
  scrollable Activity panel, and any long footer status is ellipsis-clipped to one
  line.

* Tue Jun 23 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.5.0-1
- Recover face auth after suspend/resume. UVC webcams commonly fail to resume
  from USB suspend, leaving the camera present but wedged — the greeter hung on
  "Looking for your face…" with no camera engaging and survived reboots until the
  camera power-cycled. Fixed three ways: (1) bound the previously-unbounded camera
  enumeration/resolution with a deadline (shared with the capture deadline) so a
  frozen camera can never hang the PAM stack — it degrades to the password within
  seconds; (2) log the screen-unlock Verify outcome + elapsed time, which was
  silent and made the failure undiagnosable; (3) add a systemd system-sleep hook
  that try-restarts linhellod on resume to re-open the camera and re-resolve its
  cgroup device access (the camera-refresh udev rule only fires on a re-enumerate,
  which a resume often skips).
- Fix face unlock failing with "Device or resource busy": the KDE lock screen runs
  two PAM stacks at once (`kde` + `kde-fingerprint`), so two captures opened the
  camera simultaneously and the loser got EBUSY. Camera I/O is now serialised
  process-wide so concurrent verifies queue instead of colliding.
- Detect a hardware camera privacy switch (`V4L2_CID_PRIVACY`). When the camera
  is blocked by the privacy key/shutter the sensor returns blank frames, which
  previously surfaced as a baffling "no face detected" that no reboot could fix.
  Capture now fails fast with a clear "camera privacy switch is ON — toggle the
  camera-privacy key (e.g. Fn+F10)" message, and `doctor` flags it on the RGB/IR
  rows (plus a hint when a kill-switch/eShutter removes the camera entirely).
- Tell the user at the greeter/lock screen WHY face unlock didn't run (camera
  privacy switch on, or no camera detected) instead of a silent password
  fall-through; and auto re-engage once the camera is unblocked (the kde-fingerprint
  retry stack re-attempts and the daemon re-reads camera state each try).
- Stronger anti-spoofing / liveness:
  * ML anti-spoof is now median-aggregated across a short capture burst, so a
    single noisy frame no longer false-rejects a live user (observed spoof_prob
    spiking to ~1.0 on one frame); a real photo/screen, spoofy on every frame,
    still rejects. Tunable via LINHELLO_ANTISPOOF_FRAMES (1 = legacy single-frame).
  * New enrollment-calibrated active-IR liveness gate. Enrollment records the live
    user's own IR signature — face/background brightness ratio, corneal eye-glint,
    and a depth/curvature cue (center-vs-edge IR brightness: a 3-D face is
    center-bright, a flat photo/screen is uniform) — into a per-profile envelope.
    Auth then requires the live IR to stay within it, which catches printed photos
    AND glossy screens (the depth cue rejects a flat screen even when it fakes the
    brightness ratio) without the absolute thresholds that false-rejected live
    users before. Additive to the ML gate (both must pass); fail-closed; opt-in via
    re-enrollment; escape hatch LINHELLO_IR_GATE=0. Legacy profiles are unaffected
    until re-enrolled.
- A doctor/`linhello test` now surfaces the median spoof score, the IR cues, and
  the camera privacy state.

* Tue Jun 23 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.5-1
- `linhello update`: build the Arch native package as an unprivileged user.
  When updating from the root-owned managed clone (/var/lib/linhello/src),
  makepkg was invoked as root and hard-refuses to run, so the native build
  failed and the updater silently fell back to a from-source `make install` —
  leaving binaries in /usr/local/bin and a unit in /etc/systemd/system while the
  package manager still tracked the older build. The package is now built as the
  checkout owner (or the sudo invoker) in a dedicated user-owned build dir, and a
  native-build failure is surfaced instead of degrading to a source install.
  (Arch-only path; rpm/deb builds are unchanged.)

* Tue Jun 23 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.4-1
- Fedora KDE / Plasma 6 lock screen + login fixes. Three independent bugs:
  (1) the daemon now classifies the Plasma 6.4 `plasmalogin` greeter (and its
  -greeter/-autologin variants) as login/unlock instead of Unknown→deny, so
  reboot login via plasmalogin works; (2) the KDE lock screen, which runs PAM as
  the user, is wired on Fedora/Debian (not just Arch) and `setup`/`pam enable`
  (and the TUI wizard) now add the user to the `linhello` group so the
  unprivileged greeter can reach the 0660 root:linhello socket; (3) a camera
  cgroup device boot-race is closed with a udev rule + oneshot that refreshes the
  daemon's device access once the webcam enumerates (the daemon could start
  before the USB camera registered major 81, yielding EPERM on /dev/video0 with
  no SELinux AVC).
- Packaging: reload udev rules and replay video4linux add events on install, so
  the camera-refresh rule takes effect on a live install without a reboot.
- TUI wizard parity with `linhello setup`: it now installs the SELinux policy +
  reseal hook (previously only displayed them), adds the socket-group membership
  unconditionally, offers a recovery passphrase, and confirms the login password
  (typed twice) before sealing it.
- Experimental: Arch `plasmalogin` greeter PAM wiring (unvalidated on hardware).

* Sat Jun 20 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.3-1
- SELinux: allow the confined daemon (linhellod_t) to run `busctl` and chat with
  fprintd over the system D-Bus. The fingerprint capability probe shells out to
  `busctl` (net.reactivated.Fprint); under enforcing this was denied { execute }
  on /usr/bin/busctl, and the repeated probe flooded setroubleshoot. Adds
  corecmd_exec_bin + dbus_system_bus_client + fprintd_dbus_chat to the daemon
  policy module. Validated on Fedora 44 (enforcing): the probe path runs with
  zero AVCs.

* Sat Jun 20 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.2-1
- Floor the onnxruntime weak dependency at `>= 1.24` so a dnf upgrade can't pair
  linhello (built against ort 2.0.0-rc.12 / ONNX Runtime 1.24.x) with a pre-1.24
  onnxruntime, which would break the runtime ABI. Packaging only; no code change.

* Sat Jun 20 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.1-1
- Rebuild against the ort 2.0.0-rc.12 crate and ONNX Runtime 1.24.4 (the COPR's
  onnxruntime package moves 1.22.0 -> 1.24.4 to match). rc.12 gates its bound API
  surface behind `api-NN` features, so the `ort` dependency now selects `api-24`
  explicitly under default-features = off. No user-facing behavior change.

* Fri Jun 19 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.4.0-1
- Self-healing TPM binding on GRUB systems (PolicyAuthorize policy re-signed on
  the first unlock after a PCR-7 move, e.g. an fwupd dbx update), automatic
  boot-mode detection (UKI PCR-11 vs GRUB PCR-7), a dedicated recovery
  passphrase (`linhello set-recovery` / `recover`), and fingerprint as a
  standalone secure-tier unlock method via fprintd (named fingerprints,
  duplicate detection, per-distro pam_fprintd wiring, TUI/setup integration).

* Thu Jun 18 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.3.2-1
- Arch packaging/update fix: `linhello package`/`update` no longer mis-select the
  makepkg `-debug` split (which carries no binaries) as the installable. PKGBUILD
  now builds a single stripped package (options=!debug) and the package picker
  skips -debug/-dbgsym artifacts. No functional change on Fedora.

* Thu Jun 18 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.3.1-1
- Fedora install polish: %post now enables + starts the daemon (so `linhello
  doctor` works immediately); new `linhello fetch-onnx` installs the matching
  ONNX Runtime where it isn't packaged; `linhello deps` routes ONNX to fetch-onnx
  instead of a non-existent Fedora package; fetch-models reliably restarts the
  daemon. Groundwork for the Fedora COPR (native dnf install/update with deps).

* Wed Jun 17 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.3.0-1
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

* Tue Jun 16 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.2.0-1
- Fedora port milestone: confined daemon SELinux domain (linhellod_t,
  runtime-validated), per-distro reseal trigger, sysusers group, dependency
  surfacing, `linhello fetch-models`, PAM rpath fix, TUI wiring-status fix.

* Tue Jun 16 2026 wisbendji fimerlus <archledger236@gmail.com> - 0.1.0-1
- Initial Fedora package: confined daemon (linhellod_t), sysusers group,
  systemd unit, PAM module. Face login wired via `linhello pam enable`.
