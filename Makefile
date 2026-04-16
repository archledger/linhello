# Aegyra install layout.
#
# Paths are tuned for Arch-style distros (PAM modules under /usr/lib/security,
# systemd units under /etc/systemd/system). Override any of the *DIR vars for
# packaging with DESTDIR.
#
# Targets:
#   make               — build everything (release)
#   make pam           — build just pam_faceauth.so
#   make install       — install binaries, PAM module, systemd unit, config dir
#   make check         — cargo check + clippy

DESTDIR      ?=
PREFIX       ?= /usr/local
BINDIR       ?= $(PREFIX)/bin
PAMDIR       ?= /usr/lib/security
SYSTEMDDIR   ?= /etc/systemd/system
CONFDIR      ?= /etc/aegyra
CARGO        ?= cargo
CC           ?= cc
CFLAGS       ?= -O2 -fPIC -Wall -Wextra
CARGO_TARGET_DIR ?= target
export CARGO_TARGET_DIR
TARGET_DIR   ?= $(CARGO_TARGET_DIR)/release
PAM_SO       := pam/pam_faceauth.so

# aegyra-pam ships as libaegyra_pam.so (cdylib). pam_faceauth.so dlopens it.
RUST_PAM_LIB := $(TARGET_DIR)/libaegyra_pam.so

.PHONY: all build pam install check clean dist

# Version must match pkgver in packaging/arch/PKGBUILD.
DIST_VERSION ?= 0.1.0
DIST_PREFIX  := aegyra-$(DIST_VERSION)
DIST_TARBALL := packaging/arch/$(DIST_PREFIX).tar.gz

all: build pam

build:
	$(CARGO) build --release --workspace

pam: $(PAM_SO)

# -rpath pins libaegyra_pam.so next to pam_faceauth.so inside $(PAMDIR) so the
# dynamic linker finds it at PAM load time (that directory isn't on the default
# search path).
$(PAM_SO): pam/pam_faceauth.c $(RUST_PAM_LIB)
	$(CC) $(CFLAGS) -shared -o $@ $< \
	    -L$(TARGET_DIR) -l:libaegyra_pam.so -lpam \
	    -Wl,-rpath,$(PAMDIR)

$(RUST_PAM_LIB): build

check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace --no-deps -- -D warnings

install: all
	install -Dm755 $(TARGET_DIR)/aegyrad    $(DESTDIR)$(BINDIR)/aegyrad
	install -Dm755 $(TARGET_DIR)/aegyra     $(DESTDIR)$(BINDIR)/aegyra
	install -Dm755 $(RUST_PAM_LIB)          $(DESTDIR)$(PAMDIR)/libaegyra_pam.so
	install -Dm755 $(PAM_SO)                $(DESTDIR)$(PAMDIR)/pam_faceauth.so
	install -Dm644 etc/systemd/aegyrad.service \
	    $(DESTDIR)$(SYSTEMDDIR)/aegyrad.service
	install -Dm644 etc/pam.d/aegyra-auth \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/aegyra-auth
	install -Dm644 etc/pam.d/examples/gdm-password \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/examples/gdm-password
	install -Dm644 etc/pam.d/examples/sudo \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/examples/sudo
	install -Dm644 etc/pam.d/examples/sddm \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/examples/sddm
	install -Dm644 etc/pam.d/examples/lightdm \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/examples/lightdm
	install -Dm644 etc/pam.d/examples/system-login \
	    $(DESTDIR)$(PREFIX)/share/aegyra/pam.d/examples/system-login
	install -Dm755 scripts/aegyra-reseal-hook \
	    $(DESTDIR)$(BINDIR)/aegyra-reseal-hook
	install -Dm644 etc/pacman.d/hooks/aegyra-reseal.hook \
	    $(DESTDIR)/etc/pacman.d/hooks/aegyra-reseal.hook
	install -dm755 $(DESTDIR)$(CONFDIR)
	@echo
	@echo "Installed. Next:"
	@echo "  systemctl daemon-reload && systemctl enable --now aegyrad"
	@echo "  cp /path/to/det_10g.onnx  $(CONFDIR)/det_10g.onnx"
	@echo "  cp /path/to/w600k_r50.onnx $(CONFDIR)/face.onnx"
	@echo "  aegyra enroll --user \$$USER"
	@echo "  PAM examples in $(PREFIX)/share/aegyra/pam.d/"

clean:
	$(CARGO) clean
	rm -f $(PAM_SO)

# `make dist` produces a source tarball usable by packaging/arch/PKGBUILD
# in a clean chroot (`extra-x86_64-build`). Uses `git archive` so only
# tracked files land in the tarball — no /target, no local envelopes.
dist: $(DIST_TARBALL)

$(DIST_TARBALL):
	@if [ -n "$$(git status --porcelain)" ]; then \
	    echo "refusing to roll dist tarball with a dirty tree — commit or stash first"; \
	    exit 1; \
	fi
	git archive --format=tar.gz --prefix=$(DIST_PREFIX)/ -o $@ HEAD
	@echo "wrote $@"
