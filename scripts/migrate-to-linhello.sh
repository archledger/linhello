#!/usr/bin/env bash
# migrate-to-linhello.sh — migrate a live Aegyra install to LinuxHello.
#
# Safe by design:
#   * TPM envelopes are sealed to PCR policy, NOT to their path, so moving
#     /etc/aegyra -> /etc/linhello preserves them (no re-enroll / re-seal).
#   * Every PAM file we touch is backed up to <file>.pre-linhello.
#   * The PAM module swap is GATED behind a successful pamtester face check,
#     so we never point GDM/sudo at a broken module.
#   * Face modules stay sufficient/optional/[success=1], so even a failure
#     falls through to your password. /etc/pam.d/login (TTY escape hatch) is
#     never modified.
#
# Run from the repo root AS ROOT, after `make && make pam` as your user:
#     cd ~/aegyra && sudo ./scripts/migrate-to-linhello.sh
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0"; exit 1; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
USER_NAME="${SUDO_USER:-ben}"
TARGET="target/release"
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# --- 0. preflight ----------------------------------------------------------
for f in "$TARGET/linhellod" "$TARGET/linhello" "$TARGET/liblinhello_pam.so" pam/pam_linhello.so; do
  [ -f "$f" ] || { echo "missing build artifact: $f — run 'make && make pam' first"; exit 1; }
done

# --- 1. stop the old daemon ------------------------------------------------
say "stopping old aegyrad"
systemctl disable --now aegyrad.service 2>/dev/null || true
pkill -9 -x aegyrad 2>/dev/null || true
rm -f /run/aegyra.sock

# --- 2. move config dir (preserves envelopes + models) ---------------------
say "moving /etc/aegyra -> /etc/linhello"
if [ -d /etc/aegyra ] && [ ! -e /etc/linhello ]; then
  mv /etc/aegyra /etc/linhello
elif [ -d /etc/aegyra ] && [ -d /etc/linhello ]; then
  echo "both /etc/aegyra and /etc/linhello exist — merging missing files only"
  cp -an /etc/aegyra/. /etc/linhello/ && rm -rf /etc/aegyra
else
  echo "/etc/aegyra absent; ensuring /etc/linhello exists"
  install -dm755 /etc/linhello
fi
ls -la /etc/linhello/ "/etc/linhello/$USER_NAME/" 2>/dev/null || true

# --- 3. install new artifacts (CARGO=true: do NOT rebuild as root) ---------
say "installing linhello binaries / PAM / unit / hook"
make install CARGO=true CC=true

# --- 4. start the new daemon ----------------------------------------------
say "starting linhellod"
systemctl daemon-reload
systemctl enable --now linhellod.service
sleep 2
systemctl --no-pager --full status linhellod | head -6 || true
[ -S /run/linhello.sock ] && echo "socket: $(stat -c '%A %U:%G' /run/linhello.sock) /run/linhello.sock"

say "daemon self-check (doctor + diag — no face needed)"
/usr/local/bin/linhello doctor || true
/usr/local/bin/linhello diag || true

# --- 5. pamtester GATE (needs your face) -----------------------------------
say "PAM validation — look at the camera when prompted"
cat > /etc/pam.d/linhello-test <<EOF
auth     sufficient   pam_linhello.so
auth     required     pam_deny.so
account  required     pam_permit.so
EOF
PAM_OK=0
if command -v pamtester >/dev/null 2>&1; then
  # A single frame misses ~1/3 of the time (borderline liveness / score just
  # under threshold), so retry — we only need ONE clean success to prove the
  # module path works end-to-end.
  for attempt in 1 2 3 4 5 6; do
    echo "  pamtester attempt $attempt/6 — look at the camera, hold still..."
    if pamtester linhello-test "$USER_NAME" authenticate; then
      echo "pamtester: SUCCESS — pam_linhello.so works"
      PAM_OK=1
      break
    fi
    echo "  miss (liveness/score) — repositioning, retrying"
    sleep 1
  done
  [ "$PAM_OK" = 1 ] || echo "pamtester: all 6 attempts failed — NOT swapping (login untouched)."
else
  echo "pamtester not installed (yay -S pamtester). Skipping auto-swap."
fi

# --- 6. swap live PAM stack (only if the gate passed) ----------------------
if [ "${PAM_OK}" = 1 ]; then
  say "swapping pam_faceauth.so -> pam_linhello.so in /etc/pam.d"
  for f in gdm-password sudo system-auth; do
    p="/etc/pam.d/$f"
    if [ -f "$p" ] && grep -q 'pam_faceauth.so' "$p"; then
      cp -a "$p" "$p.pre-linhello"
      sed -i 's/pam_faceauth\.so/pam_linhello.so/g' "$p"
      echo "  updated $p (backup $p.pre-linhello)"
    fi
  done
  echo "left /etc/pam.d/login untouched (TTY escape hatch)"
else
  echo "Re-run after fixing pam_linhello (the old pam_faceauth.so is still installed and active)."
fi

# --- 7. remove stale aegyra artifacts (only once swap succeeded) -----------
if [ "${PAM_OK}" = 1 ]; then
  say "removing stale aegyra artifacts"
  rm -f /usr/local/bin/aegyra /usr/local/bin/aegyrad /usr/local/bin/aegyra-reseal-hook
  rm -f /usr/lib/security/pam_faceauth.so /usr/lib/security/libaegyra_pam.so
  rm -f /etc/systemd/system/aegyrad.service /etc/pacman.d/hooks/aegyra-reseal.hook
  rm -f /etc/pam.d/aegyra-test
  systemctl daemon-reload
fi

say "done"
echo "Verify now (socket is root-only, so use sudo for CLI checks):"
echo "  sudo linhello status && sudo linhello diag   # envelopes present, zero drift"
echo "  sudo linhello test                           # recognizes you"
echo "  sudo -k && sudo -v                           # face-auth, no password"
echo
echo "Then REBOOT and log in with your FACE ONLY, and run (as your normal user):"
echo "  ~/aegyra/scripts/linhello-keyring-diag"
