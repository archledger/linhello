# Microsoft ONNX Runtime — official prebuilt shared library, repackaged for the
# LinuxHello COPR. ONNX Runtime is not in Fedora's main repositories, so the COPR
# ships it here; the version tracks the ABI LinuxHello's `ort` crate is built
# against (ort 2.0.0-rc.12 supports onnxruntime 1.17-1.24, so 1.24.x is the
# newest matching runtime), so `dnf install linhello` resolves a working runtime
# natively.
#
# This is a prebuilt binary (no compile): skip debuginfo, the strip pass, and the
# build-id requirement so RPM doesn't try to process the vendor .so.
%global debug_package %{nil}
%global __strip /bin/true
%global _missing_build_ids_terminate_build 0
%global ortver 1.24.4

# Microsoft's per-arch asset naming (x64 / aarch64).
%ifarch x86_64
%global ortarch x64
%endif
%ifarch aarch64
%global ortarch aarch64
%endif

Name:           onnxruntime
Version:        %{ortver}
Release:        1%{?dist}
Summary:        ONNX Runtime CPU inferencing library (official Microsoft prebuilt)

License:        MIT
URL:            https://onnxruntime.ai/
Source0:        https://github.com/microsoft/onnxruntime/releases/download/v%{ortver}/onnxruntime-linux-%{ortarch}-%{ortver}.tgz

# Microsoft publishes prebuilt Linux binaries only for these arches.
ExclusiveArch:  x86_64 aarch64

%description
Repackaged official Microsoft ONNX Runtime (CPU execution provider) shared
library. Provided by the LinuxHello COPR because ONNX Runtime is not in Fedora's
main repositories; the packaged version tracks the ABI LinuxHello is built
against (the `ort` 2.0.0-rc.12 crate, which supports ONNX Runtime 1.17-1.24) so
face authentication works out of the box.

%prep
%autosetup -n onnxruntime-linux-%{ortarch}-%{ortver}

%build
# Prebuilt binary — nothing to compile.

%install
install -d %{buildroot}%{_libdir}
# The versioned object is the real file; .so.1 and .so are ABI symlinks to it.
install -m0755 lib/libonnxruntime.so.%{ortver} %{buildroot}%{_libdir}/libonnxruntime.so.%{ortver}
ln -s libonnxruntime.so.%{ortver} %{buildroot}%{_libdir}/libonnxruntime.so.1
ln -s libonnxruntime.so.%{ortver} %{buildroot}%{_libdir}/libonnxruntime.so

%files
%license LICENSE
%doc README.md ThirdPartyNotices.txt VERSION_NUMBER
%{_libdir}/libonnxruntime.so.%{ortver}
%{_libdir}/libonnxruntime.so.1
%{_libdir}/libonnxruntime.so

%changelog
* Sat Jun 20 2026 archledger <archledger236@gmail.com> - 1.24.4-1
- Update to the official Microsoft ONNX Runtime 1.24.4 prebuilt (CPU) to match
  the ort 2.0.0-rc.12 ABI (rc.12 supports ONNX Runtime 1.17-1.24; 1.24.4 is the
  newest in that range).

* Thu Jun 18 2026 archledger <archledger236@gmail.com> - 1.22.0-1
- Repackage the official Microsoft ONNX Runtime 1.22.0 prebuilt (CPU) for the
  LinuxHello COPR — matches the ort 2.0.0-rc.10 ABI.
