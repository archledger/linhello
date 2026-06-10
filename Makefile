# LinuxHello install layout.
#
# Paths are tuned for Arch-style distros (PAM modules under /usr/lib/security,
# systemd units under /etc/systemd/system). Override any of the *DIR vars for
# packaging with DESTDIR.
#
# Targets:
#   make               — build everything (release)
#   make pam           — build just pam_linhello.so
#   make install       — install binaries, PAM module, systemd unit, config dir
#   make check         — cargo check + clippy

DESTDIR      ?=
PREFIX       ?= /usr/local
BINDIR       ?= $(PREFIX)/bin
PAMDIR       ?= /usr/lib/security
SYSTEMDDIR   ?= /etc/systemd/system
CONFDIR      ?= /etc/linhello
CARGO        ?= cargo
CC           ?= cc
CFLAGS       ?= -O2 -fPIC -Wall -Wextra
CARGO_TARGET_DIR ?= target
export CARGO_TARGET_DIR
TARGET_DIR   ?= $(CARGO_TARGET_DIR)/release
PAM_SO       := pam/pam_linhello.so

# linhello-pam ships as liblinhello_pam.so (cdylib). pam_linhello.so dlopens it.
RUST_PAM_LIB := $(TARGET_DIR)/liblinhello_pam.so

.PHONY: all build pam install check clean dist

# Version must match pkgver in packaging/arch/PKGBUILD.
DIST_VERSION ?= 0.1.0
DIST_PREFIX  := linhello-$(DIST_VERSION)
DIST_TARBALL := packaging/arch/$(DIST_PREFIX).tar.gz

all: build pam

build:
	$(CARGO) build --release --workspace

pam: $(PAM_SO)

# -rpath pins liblinhello_pam.so next to pam_linhello.so inside $(PAMDIR) so the
# dynamic linker finds it at PAM load time (that directory isn't on the default
# search path).
$(PAM_SO): pam/pam_linhello.c $(RUST_PAM_LIB)
	$(CC) $(CFLAGS) -shared -o $@ $< \
	    -L$(TARGET_DIR) -l:liblinhello_pam.so -lpam \
	    -Wl,-rpath,$(PAMDIR)

$(RUST_PAM_LIB): build

check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace --no-deps -- -D warnings

install: all
	install -Dm755 $(TARGET_DIR)/linhellod    $(DESTDIR)$(BINDIR)/linhellod
	install -Dm755 $(TARGET_DIR)/linhello     $(DESTDIR)$(BINDIR)/linhello
	install -Dm755 $(RUST_PAM_LIB)          $(DESTDIR)$(PAMDIR)/liblinhello_pam.so
	install -Dm755 $(PAM_SO)                $(DESTDIR)$(PAMDIR)/pam_linhello.so
	sed 's|/usr/local/bin|$(BINDIR)|g' etc/systemd/linhellod.service \
	    | install -Dm644 /dev/stdin $(DESTDIR)$(SYSTEMDDIR)/linhellod.service
	install -Dm644 etc/pam.d/linhello-auth \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/linhello-auth
	install -Dm644 etc/pam.d/examples/gdm-password \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/examples/gdm-password
	install -Dm644 etc/pam.d/examples/sudo \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/examples/sudo
	install -Dm644 etc/pam.d/examples/sddm \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/examples/sddm
	install -Dm644 etc/pam.d/examples/lightdm \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/examples/lightdm
	install -Dm644 etc/pam.d/examples/system-login \
	    $(DESTDIR)$(PREFIX)/share/linhello/pam.d/examples/system-login
	install -Dm755 scripts/linhello-reseal-hook \
	    $(DESTDIR)$(BINDIR)/linhello-reseal-hook
	sed 's|/usr/local/bin|$(BINDIR)|g' etc/pacman.d/hooks/linhello-reseal.hook \
	    | install -Dm644 /dev/stdin $(DESTDIR)/etc/pacman.d/hooks/linhello-reseal.hook
	install -dm755 $(DESTDIR)$(CONFDIR)
	@echo
	@echo "Installed. Next:"
	@echo "  systemctl daemon-reload && systemctl enable --now linhellod"
	@echo "  cp /path/to/det_10g.onnx  $(CONFDIR)/det_10g.onnx"
	@echo "  cp /path/to/w600k_r50.onnx $(CONFDIR)/face.onnx"
	@echo "  linhello enroll --user \$$USER"
	@echo "  PAM examples in $(PREFIX)/share/linhello/pam.d/"

# Package the installed, tested face models into a shippable bundle so a new
# user can install them instantly (no slow download / hunting for files). The
# models live out of git (size + model license) — MODELS_SRC defaults to the
# system config dir where they are deployed. `linhello`'s installer auto-detects
# an unpacked bundle at <repo>/models, /usr/share/linhello/models, or
# $LINHELLO_MODELS_DIR.
MODELS_SRC   ?= $(CONFDIR)
MODELS_BUNDLE ?= packaging/linhello-models.tar.gz
models-bundle:
	@for m in det_10g.onnx face.onnx antispoof.onnx; do \
	    [ -f "$(MODELS_SRC)/$$m" ] || { echo "missing $(MODELS_SRC)/$$m"; exit 1; }; \
	done
	mkdir -p $(dir $(MODELS_BUNDLE))
	tar -C $(MODELS_SRC) -czf $(MODELS_BUNDLE) det_10g.onnx face.onnx antispoof.onnx
	@echo "wrote $(MODELS_BUNDLE) (ship as a release asset; unpack to <repo>/models or /usr/share/linhello/models)"

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
