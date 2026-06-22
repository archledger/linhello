//! `linhello` — user-facing CLI. All operations are dispatched to the `linhellod`
//! daemon over /run/linhello.sock; the CLI itself holds no secrets.

use linhello_common::client;
use linhello_common::ipc::{CapabilityReport, CapabilityStatus, Request, Response, SecretBytes};
use linhello_common::SOCKET_GROUP;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

mod install;
mod pamwire;
mod tui;

#[derive(Parser)]
#[command(name = "linhello", version, about = "LinuxHello control CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Status,
    /// Detect whether LinuxHello is already installed and set up on this host
    /// (binaries, daemon, models, camera, enrolled users, login wiring). Local
    /// and read-only — needs no daemon and no root. Exit status: 0 = already
    /// configured, 10 = installed but not enrolled, 20 = nothing installed.
    Detect,
    /// List the enrolled profiles (identities with a stored face), their
    /// friendly names, sample counts, and whether they can unlock a keyring.
    Profiles,
    /// Look at the camera: identify which enrolled profile your face matches
    /// (1:N). Tells you "this face belongs to <profile>" with the score, or
    /// reports no match. Root-only (it reveals identity).
    Identify,
    /// Give an enrolled profile a friendly name (e.g. "Ben — work"). An empty
    /// name clears it. Root-only.
    ProfileName {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
    },
    /// Remove LinuxHello from this host: unwire PAM (password login stays), stop
    /// + disable the daemon, delete the programs/PAM module/unit/hook, and erase
    /// enrolled faces + config in /etc/linhello. The big face models are removed
    /// too unless `--keep-models`. Requires `--yes` to actually run. Root-only.
    Uninstall {
        /// Keep the ~190MB .onnx models (so a reinstall skips re-fetch).
        #[arg(long)]
        keep_models: bool,
        /// Actually perform it (without this, only the plan is printed).
        #[arg(long)]
        yes: bool,
    },
    /// Update LinuxHello from GitHub: pull the latest source (managing its own
    /// clone under /var/lib/linhello/src when this install didn't come from a
    /// git checkout), rebuild, reinstall the programs + daemon, and re-apply
    /// your existing login wiring. Enrolled faces, config, models, and PAM
    /// backups are never touched. Root-only.
    Update,
    /// First-run wizard: pick your webcam, calibrate the match threshold against
    /// your own live scores, and (optionally) enroll. Writes
    /// /etc/linhello/{cameras.conf,settings.conf} and restarts the daemon, so
    /// run it with sudo.
    Setup,
    /// Look directly at the camera and hold still — captures several face
    /// samples and saves your encrypted model. Default appends to existing
    /// samples (enroll glasses-on / glasses-off / varied lighting; auth takes
    /// the best match). `--reset` wipes prior samples first.
    Enroll {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        reset: bool,
        /// How many face samples to capture this run.
        #[arg(long, default_value = "5")]
        samples: u32,
    },
    /// Safe recognition self-test: captures one frame and tells you whether
    /// LinuxHello recognizes you. It does NOT drive any login prompt and
    /// cannot lock you out — use it freely after `enroll` or `setup`.
    Test {
        #[arg(long)]
        user: Option<String>,
    },
    Verify {
        #[arg(long)]
        user: Option<String>,
    },
    /// Seal your login password under the current PCR policy so face-auth
    /// can release it at login and pam_gnome_keyring can unlock the
    /// existing keyring via `use_authtok`. Re-run after changing your
    /// login password.
    SealPassword {
        #[arg(long)]
        user: Option<String>,
    },
    /// Fingerprint modality (via fprintd). On RGB-only machines, fingerprint is
    /// a stronger factor than face alone — `status` shows the reader/enrollment,
    /// `enable` guides enrollment. Face/RGB-only keeps working regardless.
    Fingerprint {
        #[command(subcommand)]
        action: FpAction,
    },
    /// Set (or replace) a dedicated recovery passphrase for your face template,
    /// separate from your login password. It's the manual backstop the automatic
    /// TPM self-heal can't cover (Secure Boot turned off, TPM cleared, disk
    /// moved). Like a BitLocker/LUKS recovery key — store it somewhere safe.
    SetRecovery {
        #[arg(long)]
        user: Option<String>,
    },
    /// Restore face unlock from your recovery passphrase: unwraps the template
    /// key and re-seals it to the current TPM state. No re-enrollment. Use when
    /// face unlock is wedged and the automatic self-heal didn't kick in.
    Recover {
        #[arg(long)]
        user: Option<String>,
    },
    Reseal,
    Secureboot {
        #[command(subcommand)]
        action: SbAction,
    },
    Diag,
    /// Probe this machine for the hardware/software LinuxHello needs (TPM, Secure
    /// Boot, RGB/IR cameras, ONNX runtime, models) and report readiness.
    Doctor,
    /// Full-screen setup wizard (TUI). Same steps as `setup`, but interactive.
    /// Requires a terminal; falls back to `linhello setup` when piped.
    Tui,
    /// Wire face login into the system PAM stacks (per distro), or report/remove
    /// it. Edits /etc/pam.d on Arch (with backups); prints the pam-auth-update /
    /// authselect steps on Debian/Fedora. The password + TTY escape always stay.
    Pam {
        #[command(subcommand)]
        action: PamAction,
    },
    /// Manage the SELinux policy module that lets the GDM greeter / GNOME lock
    /// screen reach the daemon (needed only on SELinux systems — Fedora/RHEL).
    /// A no-op by design on Arch / AppArmor distros.
    Selinux {
        #[command(subcommand)]
        action: SelinuxAction,
    },
    /// Manage the post-update reseal trigger that refreshes TPM envelopes after
    /// kernel/boot changes. Installs the right mechanism per distro (pacman hook
    /// on Arch, kernel-install on Fedora, postinst.d on Debian).
    ResealHook {
        #[command(subcommand)]
        action: ResealHookAction,
    },
    /// List LinuxHello's build + runtime dependencies with this distro's package
    /// names and the install command. Read-only; no daemon/root needed.
    Deps {
        /// Show only build-time or only runtime dependencies.
        #[arg(long, value_parser = ["build", "runtime"])]
        only: Option<String>,
    },
    /// Download the buffalo_l face models (detector + recognizer) from the
    /// official InsightFace release, verify, and install them to /etc/linhello.
    /// The anti-spoof model already ships with the package. Requires root.
    FetchModels {
        /// Re-fetch even if the models are already present.
        #[arg(long)]
        force: bool,
    },
    /// Download + install the ONNX Runtime shared library (the official Microsoft
    /// prebuild matching this linhello's ABI) into /usr/local/lib. For distros
    /// that don't package it (Fedora, Debian); on Arch use `pacman -S onnxruntime`.
    /// Requires root.
    FetchOnnx {
        /// Reinstall even if an ONNX Runtime is already present.
        #[arg(long)]
        force: bool,
    },
    /// Build the native package for this distro (rpm/deb/pkg, auto-detected) from
    /// the source checkout. With --install, install it via the package manager
    /// (needs root). This is what `update` uses to pick the right package.
    Package {
        /// Override the auto-detected format.
        #[arg(long, value_parser = ["auto", "rpm", "deb", "pkg"])]
        format: Option<String>,
        /// Install the built package via the native package manager.
        #[arg(long)]
        install: bool,
    },
    /// Live face-framing guide: shows whether the camera sees your face and
    /// guides you into position (distance, centering, head angle) before you
    /// enroll — so you don't have to open a separate camera app first. Polls
    /// the daemon a few times a second; press Ctrl-C to stop. `--once` prints a
    /// single reading and exits (useful for scripting/tests).
    Position {
        #[arg(long)]
        once: bool,
    },
    /// Capture one frame and print raw liveness signals (ML spoof score,
    /// camera trust). Use to tune `LINHELLO_SPOOF_THRESHOLD` or diagnose
    /// false rejects.
    LivenessTest,
    /// Run N consecutive verify cycles and report FRR, score statistics,
    /// and per-run latency. Measures real-world false-reject rate against
    /// WBF targets (FRR < 10% with liveness).
    /// Unseal + reseal all per-user TPM envelopes (password + template key)
    /// under current PCR state. Called by the pacman hook after kernel or
    /// bootloader updates. Requires root.
    ResealUserEnvelopes {
        #[arg(long)]
        user: String,
    },
    Benchmark {
        #[arg(long)]
        user: Option<String>,
        /// Number of verify cycles to run.
        #[arg(long, default_value = "20")]
        runs: u32,
        /// Seconds between runs (allows repositioning).
        #[arg(long, default_value = "2")]
        interval: u32,
    },
}

#[derive(Subcommand)]
enum FpAction {
    /// Show the fingerprint reader, fprintd availability, and enrolled fingers.
    Status {
        #[arg(long)]
        user: Option<String>,
    },
    /// Guide fingerprint enrollment (runs `fprintd-enroll`) so it can be used
    /// as a factor alongside or instead of RGB-only face.
    Enable {
        #[arg(long)]
        user: Option<String>,
    },
    /// Stop using fingerprint as the unlock method (unwire pam_fprintd, let face
    /// resume). Keeps the enrolled finger so it can be re-enabled later.
    Disable {
        #[arg(long)]
        user: Option<String>,
    },
    /// Enroll an ADDITIONAL fingerprint under a friendly name (Android-style).
    /// Warns and refuses if the scanned finger is already enrolled.
    Add {
        /// Friendly name for this finger (prompted if omitted), e.g. "Right thumb".
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
}

#[derive(Subcommand)]
enum SbAction {
    /// Show sbctl key-enrollment state alongside the firmware view.
    Status,
    /// Generate a PK/KEK/db set with sbctl and enroll them (requires firmware
    /// SetupMode plus root).
    Setup {
        /// Skip enrolling Microsoft's UEFI CA alongside our PK. Only use this
        /// if you're willing to re-sign every OpROM on peripheral cards.
        #[arg(long)]
        no_microsoft: bool,
    },
    /// Sign one or more EFI binaries with sbctl and record them for later
    /// re-signing. Requires root.
    Sign {
        /// Paths to sign (typically your UKI under /boot or /efi).
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Run `sbctl verify` — list any EFI binaries on the ESP that aren't
    /// signed by your enrolled keys.
    Verify,
    /// Run `sbctl list-files` — show the sbctl signing record.
    List,
}

#[derive(Subcommand)]
enum PamAction {
    /// Show which PAM services currently have face-auth wired in.
    Status,
    /// Wire face-auth into the graphical greeter (and optionally sudo).
    Enable {
        /// Also wire face-auth into `sudo`.
        #[arg(long)]
        sudo: bool,
        /// Show what would change without editing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove face-auth from the PAM stacks.
    Disable {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SelinuxAction {
    /// Show the active LSM, whether the policy is needed here, and whether the
    /// linhello module is currently loaded.
    Status,
    /// Build and load the linhello SELinux policy module. No-op on non-SELinux
    /// systems. Requires root unless --dry-run.
    Install {
        /// Show the exact commands without running anything.
        #[arg(long)]
        dry_run: bool,
        /// Path to linhello.te to build from. Defaults to the installed policy
        /// source; use this to point at the repo's etc/selinux/linhello.te
        /// before packaging ships it to a system location.
        #[arg(long)]
        from: Option<String>,
    },
    /// Unload the linhello SELinux policy module. Requires root unless --dry-run.
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ResealHookAction {
    /// Show the per-distro trigger mechanism and whether it's installed.
    Status,
    /// Install the post-update reseal trigger for this distro. No-op on distros
    /// with no known mechanism. Requires root unless --dry-run.
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the reseal trigger. Requires root unless --dry-run.
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
}

fn current_user() -> Result<String> {
    if let Ok(u) = std::env::var("SUDO_USER") {
        if !u.is_empty() && u != "root" {
            return Ok(u);
        }
    }
    std::env::var("USER").context("USER env var not set")
}

fn send(req: Request) -> Result<Response> {
    client::request(&req).map_err(|e| anyhow::anyhow!("daemon: {e}"))
}

/// Detect which unlock methods this host can offer (hardware + enrollment).
pub(crate) fn available_methods(user: &str) -> linhello_common::biopolicy::AvailableMethods {
    use linhello_common::biopolicy::AvailableMethods;
    use linhello_fingerprint as fp;
    AvailableMethods {
        // An RGB camera is assumed present if any capture device resolves; the
        // daemon's camera binding is authoritative, but for advice this is fine.
        face_rgb: !linhello_biometrics::camera::enumerate().is_empty(),
        face_ir: linhello_biometrics::camera::ir_device().is_some(),
        fingerprint: fp::available() && fp::has_enrollment(user),
        fingerprint_capable: fp::available(),
    }
}

/// Print the unlock methods, their tiers, the default, and the suggestion.
fn fingerprint_status(user: &str) {
    use linhello_common::biopolicy::UnlockMethod;
    use linhello_fingerprint as fp;

    let reader = if fp::available() {
        fp::device_name().unwrap_or_else(|| "fingerprint reader".into())
    } else if fp::fprintd_present() {
        "none registered".into()
    } else {
        "fprintd not installed".into()
    };
    let fingers = fp::enrolled_fingers(user);
    let av = available_methods(user);

    println!("reader        : {reader}");
    if fp::available() {
        if fingers.is_empty() {
            println!("enrolled      : no fingers — run `linhello fingerprint enable`");
        } else {
            println!("enrolled      : {} finger(s)", fingers.len());
            for slot in &fingers {
                match fingerprint_name(user, slot) {
                    Some(name) => println!("                • {name}  [{slot}]"),
                    None => println!("                • {slot}"),
                }
            }
        }
    }
    println!("face camera   : {}", if av.face_ir { "RGB + IR" } else { "RGB only" });
    println!();

    let recommended = av.recommended_method();
    let active = av.default_method();
    match recommended {
        None => println!("no biometric method available — password only."),
        Some(rec) => {
            println!("recommended   : {} [{:?} tier]", rec.label(), rec.tier());
            // Show what actually works right now only when it differs from the
            // recommendation (e.g. a reader is present but not enrolled yet).
            if active != recommended {
                match active {
                    Some(act) => println!(
                        "active now    : {} — until you set up the recommended method",
                        act.label()
                    ),
                    None => println!("active now    : password only — nothing set up yet"),
                }
            }
            let others: Vec<&str> = av
                .selectable()
                .into_iter()
                .filter(|&m| Some(m) != recommended)
                .map(UnlockMethod::label)
                .collect();
            if !others.is_empty() {
                println!("alternatives  : {}", others.join("; "));
            }
            if av.needs_user_choice() {
                println!(
                    "\nBoth face (IR) and fingerprint are secure-tier — choose either. \
                     Set with `/etc/linhello/policy.conf` key `method = face-ir|fingerprint`."
                );
            } else if matches!(rec, UnlockMethod::Fingerprint) {
                if fp::has_enrollment(user) {
                    println!(
                        "\nFingerprint is the secure method here (screen + login + sudo). \
                         You can opt down to RGB-only face (convenience) — `method = face-rgb`."
                    );
                } else {
                    println!(
                        "\nThis machine is RGB-only for face, so fingerprint is the secure choice \
                         (screen + login + sudo). Set it up: `linhello fingerprint enable`. \
                         RGB-only face (convenience: screen unlock only) keeps working meanwhile."
                    );
                }
            }
        }
    }
}

/// Enroll a fingerprint and wire `pam_fprintd` so fingerprint becomes a
/// secure-tier login/sudo method. Password (and any configured face) keep
/// working; this is additive and reversible.
pub(crate) fn fingerprint_enable(user: &str) -> Result<()> {
    use linhello_common::platform::{self, DistroFamily};
    use linhello_fingerprint as fp;

    if !fp::fprintd_present() {
        bail!("fprintd is not installed. Install fprintd + libpam-fprintd, then retry.");
    }
    if !fp::reader_present() {
        bail!("no fingerprint reader is registered with fprintd.");
    }

    // 1. Enroll the first finger (named), unless one already exists.
    if fp::has_enrollment(user) {
        println!("{user} already has an enrolled fingerprint; skipping enrollment.");
        println!("(add more with `linhello fingerprint add`.)");
    } else if !enroll_named_finger(user, None)? {
        bail!("no fingerprint was enrolled; nothing was wired.");
    }

    // 2. Wire pam_fprintd per distro so the greeter/sudo offer it. Password
    //    always remains (the fprintd PAM profile is sufficient, never required).
    println!("\nWiring fingerprint into PAM (password stays as fallback)…");
    match platform::distro_family() {
        DistroFamily::Debian => {
            // libpam-fprintd ships the `fprintd` pam-auth-update profile.
            if !std::path::Path::new("/usr/share/pam-configs/fprintd").exists() {
                bail!("libpam-fprintd is not installed (no /usr/share/pam-configs/fprintd). \
                       Install it (`apt install libpam-fprintd`) and retry.");
            }
            let st = Command::new("pam-auth-update")
                .args(["--enable", "fprintd"])
                .status()
                .context("running pam-auth-update")?;
            if !st.success() {
                bail!("pam-auth-update --enable fprintd failed; run it manually to review.");
            }
            println!("enabled the `fprintd` pam-auth-update profile.");
        }
        DistroFamily::Fedora => {
            // authselect owns system-auth/password-auth on Fedora; enabling its
            // fingerprint feature wires pam_fprintd the supported way.
            let enabled = Command::new("authselect")
                .args(["enable-feature", "with-fingerprint"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let applied = enabled
                && Command::new("authselect")
                    .arg("apply-changes")
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            if applied {
                println!("enabled the authselect `with-fingerprint` feature.");
            } else {
                println!("Could not run authselect automatically — enable it manually:");
                println!("  sudo authselect enable-feature with-fingerprint");
                println!("  sudo authselect apply-changes");
            }
        }
        DistroFamily::Arch | DistroFamily::Other => {
            println!("Add `auth sufficient pam_fprintd.so` above pam_unix in the relevant");
            println!("/etc/pam.d files (e.g. system-local-login, sudo, and your greeter),");
            println!("or use your distro's helper if it has one.");
        }
    }

    // Record fingerprint as the active method so the daemon disables face — the
    // greeter/lock screen will say "Place your finger…" (pam_fprintd), not
    // "Looking for your face…". The TTY/password fallback is untouched.
    if let Err(e) = linhello_common::config::write_kv("policy.conf", "method", "fingerprint") {
        println!("note: could not record method in policy.conf: {e}");
    }

    println!(
        "\nDone. Fingerprint is now your secure-tier method (screen unlock + login + sudo),\n\
         and face prompts are suppressed. Your password still works everywhere.\n\
         To switch back to face: `sudo linhello fingerprint disable`."
    );
    Ok(())
}

/// Stop using fingerprint as the unlock method: unwire pam_fprintd and clear the
/// `method` override so face (per the detected tier) resumes. The enrolled
/// finger is kept (re-enable any time); to also erase it, `fprintd-delete`.
pub(crate) fn fingerprint_disable(user: &str) -> Result<()> {
    use linhello_common::platform::{self, DistroFamily};
    let _ = user;
    println!("Disabling fingerprint as the unlock method (enrollment is kept)…");
    match platform::distro_family() {
        DistroFamily::Debian => {
            let st = Command::new("pam-auth-update")
                .args(["--disable", "fprintd"])
                .status()
                .context("running pam-auth-update")?;
            if !st.success() {
                bail!("pam-auth-update --disable fprintd failed; run it manually to review.");
            }
            println!("removed the `fprintd` pam-auth-update profile.");
        }
        DistroFamily::Fedora => {
            let disabled = Command::new("authselect")
                .args(["disable-feature", "with-fingerprint"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let applied = disabled
                && Command::new("authselect")
                    .arg("apply-changes")
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            if applied {
                println!("disabled the authselect `with-fingerprint` feature.");
            } else {
                println!("Disable manually: `sudo authselect disable-feature with-fingerprint && sudo authselect apply-changes`");
            }
        }
        DistroFamily::Arch | DistroFamily::Other => {
            println!("Remove the `auth … pam_fprintd.so` line(s) you added to /etc/pam.d.");
        }
    }
    // Clear the method override → face resumes per the detected tier.
    if let Err(e) = linhello_common::config::write_kv("policy.conf", "method", "auto") {
        println!("note: could not update policy.conf: {e}");
    }
    println!(
        "\nDone. Face auth resumes (per your camera tier); the finger prompt is removed.\n\
         Your enrolled fingerprint is kept — re-enable with `linhello fingerprint enable`."
    );
    Ok(())
}

// ── Friendly fingerprint names (Android-style), layered over fprintd slots ──

fn fp_names_file(user: &str) -> String {
    format!("{user}/fingerprints.conf")
}

/// Friendly name for an enrolled finger slot, if the user gave one.
pub(crate) fn fingerprint_name(user: &str, slot: &str) -> Option<String> {
    linhello_common::config::read_kv(&fp_names_file(user), slot).filter(|s| !s.is_empty())
}

fn set_fingerprint_name(user: &str, slot: &str, name: &str) {
    // The per-user dir exists after face enrollment, but a fingerprint-only user
    // may not have it yet — create it (root-only) so write_kv doesn't fail.
    let dir = std::path::Path::new(linhello_common::CONFIG_ROOT).join(user);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("warning: could not create {}: {e}", dir.display());
        return;
    }
    if let Err(e) = linhello_common::config::write_kv(&fp_names_file(user), slot, name) {
        eprintln!("warning: could not save the fingerprint name: {e}");
    }
}

/// Enroll one additional fingerprint under a friendly name, refusing duplicates.
/// Returns Ok(true) if a finger was enrolled, Ok(false) if skipped (duplicate or
/// user declined). Used by both `fingerprint add` and first-time `enable`.
fn enroll_named_finger(user: &str, name: Option<String>) -> Result<bool> {
    use linhello_fingerprint::{self as fp, EnrollOutcome};

    let Some(slot) = fp::free_finger(user) else {
        bail!("all ten finger slots are already enrolled — remove one with `fprintd-delete` first.");
    };

    // Friendly name (prompt if not supplied and stdin is interactive).
    let name = match name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => {
            print!("Name for this fingerprint (e.g. \"Right thumb\"): ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).ok();
            let s = s.trim().to_string();
            if s.is_empty() {
                slot.replace('-', " ")
            } else {
                s
            }
        }
    };

    println!("Enrolling \"{name}\" — touch the sensor repeatedly until complete…");
    // fprintd refuses (enroll-duplicate) if this finger is already enrolled, so
    // the duplicate check is native and reliable — no extra pre-scan touch.
    match fp::enroll_finger(user, slot) {
        EnrollOutcome::Enrolled => {
            set_fingerprint_name(user, slot, &name);
            println!("✓ enrolled \"{name}\" ({slot}).");
            Ok(true)
        }
        EnrollOutcome::Duplicate => {
            let existing: Vec<String> = fp::enrolled_fingers(user)
                .iter()
                .map(|s| match fingerprint_name(user, s) {
                    Some(n) => format!("{n} [{s}]"),
                    None => s.clone(),
                })
                .collect();
            println!(
                "✗ That finger is already enrolled (you have: {}). Not saving a duplicate.",
                existing.join(", ")
            );
            Ok(false)
        }
        EnrollOutcome::Failed(why) => bail!("enrollment did not complete ({why}); nothing saved."),
    }
}

/// Prompt for a recovery passphrase (with confirmation) and ask the daemon to
/// wrap `user`'s template key under it. Shared by `set-recovery` and `setup`.
fn set_recovery_interactive(user: &str) -> Result<()> {
    use zeroize::Zeroize;
    let mut pw = rpassword::prompt_password("Recovery passphrase: ")
        .context("reading passphrase from TTY")?
        .into_bytes();
    let mut confirm = rpassword::prompt_password("Confirm: ")
        .context("reading passphrase confirmation")?
        .into_bytes();
    let matched = pw == confirm;
    confirm.zeroize();
    if !matched {
        pw.zeroize();
        bail!("passphrases do not match");
    }
    if pw.is_empty() {
        pw.zeroize();
        bail!("recovery passphrase must not be empty");
    }
    let resp = send(Request::SaveRecovery {
        user: user.to_string(),
        passphrase: SecretBytes::new(std::mem::take(&mut pw)),
    });
    pw.zeroize();
    match resp? {
        Response::RecoverySaved => {
            println!("recovery passphrase set for {user}");
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn sbctl_installed() -> bool {
    Command::new("sbctl")
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_sbctl(args: &[&str]) -> Result<()> {
    let status = Command::new("sbctl")
        .args(args)
        .status()
        .with_context(|| format!("spawning sbctl {}", args.join(" ")))?;
    if !status.success() {
        bail!("sbctl {} exited with {}", args.join(" "), status);
    }
    Ok(())
}

fn secureboot_status() -> Result<()> {
    let sb = linhello_secureboot::is_secure_boot_enabled();
    let setup_mode = linhello_secureboot::is_setup_mode();
    let loader = linhello_secureboot::loader_identity();

    println!("secure boot    : {sb}");
    println!("setup mode     : {setup_mode}");
    if let Some(l) = loader {
        println!("loader         : {l}");
    }

    if sbctl_installed() {
        println!("--- sbctl status ---");
        let _ = Command::new("sbctl").arg("status").status();
    } else {
        println!("sbctl          : not installed");
    }
    Ok(())
}

fn require_root(op: &str) -> Result<()> {
    // SAFETY: libc::getuid is a read-only syscall with no preconditions.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        bail!("`{op}` must run as root (got uid {uid}) — re-run with sudo");
    }
    Ok(())
}

/// Print the host's LinuxHello install/configuration state and exit with a
/// machine-readable status code (0 configured / 10 installed-not-enrolled /
/// 20 not installed). Read-only; no daemon or root required.
fn detect_cmd() -> ! {
    let st = install::InstallState::detect();
    println!("{}", st.headline());
    println!();
    for line in st.detail_lines() {
        println!("  {line}");
    }
    let code = if st.is_configured() {
        0
    } else if st.is_installed() {
        10
    } else {
        20
    };
    std::process::exit(code);
}

/// `linhello profiles` — list enrolled identities.
fn profiles_cmd() -> Result<()> {
    match send(Request::ListProfiles)? {
        Response::Profiles { profiles } => {
            if profiles.is_empty() {
                println!("no enrolled profiles yet — run `linhello enroll` or `linhello setup`");
                return Ok(());
            }
            println!("{:<16} {:<22} {:>7}  keyring", "profile", "name", "samples");
            for p in profiles {
                println!(
                    "{:<16} {:<22} {:>7}  {}",
                    p.user,
                    p.name.as_deref().unwrap_or("—"),
                    p.samples,
                    if p.has_password { "yes" } else { "no" },
                );
            }
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// `linhello identify` — 1:N "which face is this".
fn identify_cmd() -> Result<()> {
    println!("Look at the camera…");
    match send(Request::Identify)? {
        Response::Identified {
            best,
            threshold,
            candidates,
        } => {
            match &best {
                Some(c) => {
                    let label = c.name.clone().unwrap_or_else(|| c.user.clone());
                    println!(
                        "This face belongs to: {label} (profile '{}', score {:.3} ≥ {:.2})",
                        c.user, c.score, threshold
                    );
                }
                None => {
                    let top = candidates.first();
                    match top {
                        Some(c) => println!(
                            "No match — closest was '{}' at {:.3} (need {:.2}).",
                            c.user, c.score, threshold
                        ),
                        None => println!("No match."),
                    }
                }
            }
            if candidates.len() > 1 {
                println!("\nall candidates (best first):");
                for c in &candidates {
                    let nm = c.name.as_deref().unwrap_or("—");
                    println!("  {:<16} {:<20} {:.3}", c.user, nm, c.score);
                }
            }
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// `linhello profile-name --user U --name N` — set/clear a friendly name.
fn profile_name_cmd(user: &str, name: &str) -> Result<()> {
    match send(Request::SetProfileName {
        user: user.to_string(),
        name: name.to_string(),
    })? {
        Response::ProfileNameSet => {
            if name.trim().is_empty() {
                println!("cleared name for profile '{user}'");
            } else {
                println!("profile '{user}' is now named \"{}\"", name.trim());
            }
            Ok(())
        }
        Response::Error { message } => bail!(message),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// `linhello uninstall [--keep-models] [--yes]` — headless full removal.
fn uninstall_cmd(remove_models: bool, yes: bool) -> Result<()> {
    require_root("uninstall")?;
    println!("Uninstalling LinuxHello will:");
    for step in install::uninstall_plan(remove_models) {
        println!("  • {step}");
    }
    if !yes {
        println!("\nNothing done. Re-run with --yes to perform it.");
        return Ok(());
    }
    println!();
    match install::uninstall(remove_models) {
        Ok(log) => {
            for l in log {
                println!("  {l}");
            }
            println!("\nDone. Password login is unaffected.");
            Ok(())
        }
        Err(e) => bail!(e),
    }
}

fn update_cmd() -> Result<()> {
    require_root("update")?;
    let user = current_user()?;
    match install::update(&user) {
        Ok(log) => {
            for l in log {
                println!("  {l}");
            }
            println!("\nUpdate complete. Enrollment, config, and PAM backups were untouched.");
            Ok(())
        }
        Err(e) => bail!(e),
    }
}

/// Read one trimmed line from stdin. Empty on EOF.
fn prompt_line(msg: &str) -> Result<String> {
    print!("{msg}");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).context("reading stdin")?;
    Ok(s.trim().to_string())
}

/// y/N confirmation; defaults to false on empty/EOF.
fn prompt_yes(msg: &str) -> bool {
    let ans = prompt_line(msg).unwrap_or_default().to_ascii_lowercase();
    ans == "y" || ans == "yes"
}

fn print_capability_report(report: &CapabilityReport) {
    for c in &report.checks {
        let tag = match c.status {
            CapabilityStatus::Ok => "[ OK ]",
            CapabilityStatus::Warn => "[WARN]",
            CapabilityStatus::Missing if c.required => "[FAIL]",
            CapabilityStatus::Missing => "[ -- ]",
        };
        println!("{tag} {:<20} {}", c.name, c.detail);
    }
}

/// Ask the daemon for the effective tier + per-operation policy and print it, so
/// `doctor` shows what face auth actually does on this machine (sourced from the
/// daemon, so it can't drift from the real decision path). Best-effort: if the
/// daemon is unreachable or too old to answer, print nothing — the capability
/// report already covers hardware, and this must never fail `doctor`.
fn print_policy_status() {
    let Ok(user) = current_user() else { return };
    let Ok(Response::PolicyStatus {
        tier,
        secure,
        hardware_tier,
        overridden,
        enrolled,
        hardware_ready,
        hardware_note,
        ops,
    }) = send(Request::PolicyStatus { user })
    else {
        return;
    };
    // A Secure tier whose IR camera is currently missing is degraded right now.
    let tag = if secure && hardware_ready { "[ OK ]" } else { "[WARN]" };
    println!("{tag} {:<20} {}", "Biometric tier", tier);
    if !hardware_ready && !hardware_note.is_empty() {
        println!("       {:<20} ⚠ {hardware_note}", "");
    }
    if overridden {
        println!("       {:<20} forced by policy.conf — hardware is {hardware_tier}", "");
    }
    if !enrolled {
        println!("       {:<20} no face enrolled yet — run `linhello setup`", "");
    }
    for op in ops {
        println!("       · {:<19}{:<8}{}", op.operation, op.action, op.effect);
    }
    println!("       · {:<19}{}", "configure", "/etc/linhello/policy.conf (keys: method, tier, screen_unlock, login, sudo, polkit)");
}

/// Guided face capture: prints instructions and captures `samples` frames,
/// each a `Request::Enroll`. `reset` wipes prior samples on the first
/// *successful* capture so a no-face miss doesn't leave the model half-cleared.
fn enroll_guided(user: &str, reset: bool, samples: u32) -> Result<()> {
    println!("Enrolling {user}.");
    println!("Sit at your normal distance, look directly at the camera, and hold still.");
    if reset {
        println!("(--reset: your existing samples will be replaced.)");
    }
    println!("Capturing {samples} sample(s) — vary pose/expression slightly between each.");
    println!();

    let mut reset_pending = reset;
    let mut total = 0usize;
    let mut captured = 0u32;
    for i in 1..=samples {
        if i > 1 {
            std::thread::sleep(Duration::from_millis(800));
        }
        print!("  [{i}/{samples}] capturing... ");
        std::io::stdout().flush().ok();
        match send(Request::Enroll {
            user: user.to_string(),
            reset: reset_pending,
        })? {
            Response::Enrolled { samples: s } => {
                reset_pending = false;
                total = s;
                captured += 1;
                println!("ok (stored: {s})");
            }
            Response::Error { message } => println!("skipped — {message}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }
    println!();
    if captured == 0 {
        bail!("no samples captured — is your face in view and well lit? try again");
    }
    println!("Done — {total} sample(s) stored for {user}.");
    println!("Next: run `linhello test` to confirm recognition.");
    Ok(())
}

fn restart_daemon() -> Result<()> {
    print!("  restarting linhellod... ");
    std::io::stdout().flush().ok();
    let status = Command::new("systemctl")
        .args(["restart", "linhellod"])
        .status()
        .context("running systemctl restart linhellod")?;
    if !status.success() {
        println!("failed");
        bail!("systemctl restart linhellod exited with {status}");
    }
    // Let the daemon re-bind the socket and warm the ONNX models.
    std::thread::sleep(Duration::from_secs(2));
    println!("ok");
    Ok(())
}

/// Pick the RGB (and optional IR) camera from the enumerated nodes.
fn choose_cameras(
    cams: &[linhello_biometrics::camera::CameraInfo],
) -> Result<(String, Option<String>)> {
    use linhello_biometrics::camera::CameraKind;
    if cams.is_empty() {
        bail!("no /dev/video* capture devices found");
    }
    println!("  detected video devices:");
    for c in cams {
        let kind = match c.kind {
            CameraKind::Rgb => "RGB",
            CameraKind::Ir => "IR",
            CameraKind::Unknown => "?",
        };
        let trust = if c.trusted { "" } else { "  (untrusted/virtual)" };
        println!(
            "    {:<14} {:<4} {}{}  [{}]",
            c.path,
            kind,
            c.name.as_deref().unwrap_or("?"),
            trust,
            c.fourccs.join(",")
        );
    }
    println!();

    let rgb_candidates: Vec<&linhello_biometrics::camera::CameraInfo> = cams
        .iter()
        .filter(|c| c.kind == CameraKind::Rgb && c.trusted)
        .collect();
    let rgb = match rgb_candidates.as_slice() {
        [] => {
            let p = prompt_line("  no trusted RGB camera auto-detected. Enter RGB device path: ")?;
            if p.is_empty() {
                bail!("no RGB camera selected");
            }
            p
        }
        [only] => {
            println!(
                "  RGB camera: {} ({})",
                only.path,
                only.name.as_deref().unwrap_or("?")
            );
            only.path.clone()
        }
        many => {
            for (i, c) in many.iter().enumerate() {
                println!("    {}) {} ({})", i + 1, c.path, c.name.as_deref().unwrap_or("?"));
            }
            let sel = prompt_line(&format!("  pick RGB camera [1-{}] (default 1): ", many.len()))?;
            let idx = sel.parse::<usize>().unwrap_or(1).clamp(1, many.len()) - 1;
            many[idx].path.clone()
        }
    };

    let ir_candidates: Vec<&linhello_biometrics::camera::CameraInfo> =
        cams.iter().filter(|c| c.kind == CameraKind::Ir).collect();
    let ir = match ir_candidates.as_slice() {
        [] => {
            println!("  IR camera: none (liveness uses the RGB anti-spoof model)");
            None
        }
        [only] => {
            println!("  IR camera: {}", only.path);
            Some(only.path.clone())
        }
        many => {
            for (i, c) in many.iter().enumerate() {
                println!("    {}) {}", i + 1, c.path);
            }
            let sel = prompt_line(&format!(
                "  pick IR camera [1-{}] (default 1, 0=none): ",
                many.len()
            ))?;
            match sel.parse::<usize>().unwrap_or(1) {
                0 => None,
                n => Some(many[n.clamp(1, many.len()) - 1].path.clone()),
            }
        }
    };
    Ok((rgb, ir))
}

/// Capture a handful of genuine matches and recommend a threshold below the
/// weakest one, then persist it to settings.conf.
fn calibrate_threshold(user: &str) -> Result<()> {
    const N: u32 = 8;
    println!("  Capturing {N} samples to measure your genuine match scores.");
    println!("  Look at the camera and stay roughly still; small movements are fine.");
    let mut scores: Vec<f32> = Vec::new();
    for i in 1..=N {
        if i > 1 {
            std::thread::sleep(Duration::from_millis(600));
        }
        print!("    [{i}/{N}] ");
        std::io::stdout().flush().ok();
        match send(Request::Verify { user: user.to_string() }) {
            Ok(Response::Verified { score, .. }) => {
                println!("score {score:.3}");
                scores.push(score);
            }
            Ok(Response::Error { message }) => println!("skip — {message}"),
            Ok(other) => bail!("unexpected response: {other:?}"),
            Err(e) => println!("skip — {e}"),
        }
    }
    if scores.len() < 3 {
        println!("  Not enough good captures to recommend a threshold; keeping current value.");
        return Ok(());
    }
    let min = scores.iter().cloned().fold(f32::INFINITY, f32::min);
    let mean = scores.iter().sum::<f32>() / scores.len() as f32;
    let rec = (min - 0.05).clamp(0.45, 0.75);
    println!();
    println!("  genuine scores: min {min:.3}, mean {mean:.3}  (n={})", scores.len());
    println!("  recommended threshold: {rec:.2}  (a margin below your weakest genuine match)");
    let ans = prompt_line(&format!(
        "  accept {rec:.2}? [Y/n], or type a value 0.45-0.85: "
    ))?;
    let chosen = if ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
    {
        rec
    } else if let Ok(v) = ans.parse::<f32>() {
        v.clamp(0.30, 0.95)
    } else {
        println!("  not understood; using recommended {rec:.2}");
        rec
    };
    linhello_common::config::write_kv("settings.conf", "match_threshold", &format!("{chosen:.2}"))
        .map_err(|e| anyhow::anyhow!("writing settings.conf: {e}"))?;
    println!("  saved match_threshold={chosen:.2} to /etc/linhello/settings.conf");
    Ok(())
}

fn run_setup() -> Result<()> {
    require_root("setup")?;
    println!("LinuxHello setup");
    println!("================\n");

    // Step 1 — readiness (reuse the daemon's capability report).
    println!("Step 1/5 — checking hardware & software readiness");
    match send(Request::Probe) {
        Ok(Response::Capabilities { report }) => {
            print_capability_report(&report);
            if !report.can_run() {
                bail!("a required capability is missing (see [FAIL]) — fix it and re-run setup");
            }
        }
        Ok(Response::Error { message }) => bail!(message),
        Ok(other) => bail!("unexpected response: {other:?}"),
        Err(e) => bail!("cannot reach linhellod ({e}) — check `systemctl status linhellod`"),
    }
    println!();

    // Step 2 — platform integration: the SELinux policy (greeter/lock access),
    // the post-update reseal trigger, and the socket-group membership. The first
    // two are per-distro gated; each is a no-op where it doesn't apply.
    println!("Step 2/5 — platform integration (SELinux, reseal hook, group)");
    selinux_setup_step()?;
    reseal_hook_setup_step()?;
    group_membership_setup_step();
    println!();

    // Step 3 — camera selection, persisted to cameras.conf.
    println!("Step 3/5 — choose your camera");
    let cams = linhello_biometrics::camera::enumerate();
    let (rgb, ir) = choose_cameras(&cams)?;
    linhello_biometrics::camera::write_cameras_conf(&rgb, ir.as_deref())?;
    println!(
        "  saved: rgb={rgb}{}",
        ir.as_deref().map(|p| format!(", ir={p}")).unwrap_or_default()
    );
    restart_daemon()?; // bind the chosen devices before calibrating
    println!();

    // Step 4 — threshold calibration (needs an existing enrollment to score
    // against; if none, we skip and let enrollment happen first).
    let user = current_user()?;
    println!("Step 4/5 — calibrate the match threshold");
    if prompt_yes(&format!(
        "  calibrate against {user}'s enrolled face now? (skip if not enrolled yet) [y/N] "
    )) {
        calibrate_threshold(&user)?;
        restart_daemon()?;
    } else {
        println!("  skipped — using default/current threshold. Re-run setup after enrolling to tune.");
    }
    println!();

    // Step 5 — optional enrollment.
    println!("Step 5/5 — enrollment");
    let enrolled = if prompt_yes(&format!("  enroll {user}'s face now? [y/N] ")) {
        enroll_guided(&user, false, 5)?;
        true
    } else {
        println!("  skipped — run `linhello enroll` when ready.");
        false
    };

    // Optional recovery passphrase — the manual backstop for the rare cases the
    // automatic TPM self-heal can't cover. Only offered once a template key
    // exists to wrap (i.e. after enrollment).
    if enrolled {
        println!();
        println!(
            "Recovery passphrase (optional) — a backstop, SEPARATE from your login\n\
             password, for when the automatic self-heal can't run (Secure Boot off,\n\
             TPM cleared, disk moved). Without it, those rare cases need a re-enroll."
        );
        if prompt_yes("  set a recovery passphrase now? [y/N] ") {
            if let Err(e) = set_recovery_interactive(&user) {
                println!("  recovery passphrase not set: {e}");
                println!("  you can set one later with `sudo linhello set-recovery`.");
            }
        } else {
            println!("  skipped — set one later with `sudo linhello set-recovery`.");
        }
    }

    // Optional — fingerprint (a standalone secure-tier method). Offered when a
    // reader is present, especially valuable on RGB-only machines where face is
    // convenience-tier only.
    if linhello_fingerprint::available() {
        let av = available_methods(&user);
        println!();
        if !av.face_ir {
            println!(
                "Optional — a fingerprint reader was detected. On this RGB-only machine, \n\
                 fingerprint is a SECURE-tier method (screen unlock + login + sudo), stronger \n\
                 than RGB-only face (convenience: screen unlock only)."
            );
        } else {
            println!(
                "Optional — a fingerprint reader was detected. It's a secure-tier alternative \n\
                 to IR face (both unlock everything); you can use either."
            );
        }
        if prompt_yes("  set up fingerprint now (enroll + wire pam_fprintd)? [y/N] ") {
            if let Err(e) = fingerprint_enable(&user) {
                println!("  fingerprint setup did not finish: {e}");
                println!("  you can set it up later with `sudo linhello fingerprint enable`.");
            }
        } else {
            println!("  skipped — set up later with `sudo linhello fingerprint enable`.");
        }
    }

    println!("\nSetup complete. Try `linhello test`.");
    Ok(())
}

fn require_sbctl() -> Result<()> {
    if !sbctl_installed() {
        bail!("sbctl not found on PATH — install it (pacman -S sbctl) and re-run");
    }
    Ok(())
}

fn secureboot_sign(paths: &[String]) -> Result<()> {
    require_root("sign")?;
    require_sbctl()?;
    for p in paths {
        if !std::path::Path::new(p).exists() {
            bail!("no such file: {p}");
        }
        println!("==> sbctl sign -s {p}");
        run_sbctl(&["sign", "-s", p])?;
    }
    println!();
    println!("signed {} file(s). run `linhello secureboot verify` to confirm.", paths.len());
    Ok(())
}

fn secureboot_verify() -> Result<()> {
    require_root("verify")?;
    require_sbctl()?;
    let status = Command::new("sbctl").arg("verify").status()?;
    if !status.success() {
        // `sbctl verify` exits non-zero when unsigned files exist — surface that
        // distinctly instead of as a command failure.
        bail!("sbctl verify reported unsigned files (exit {status})");
    }
    Ok(())
}

fn secureboot_list() -> Result<()> {
    require_root("list")?;
    require_sbctl()?;
    let status = Command::new("sbctl").arg("list-files").status()?;
    if !status.success() {
        bail!("sbctl list-files exited with {status}");
    }
    Ok(())
}

fn secureboot_setup(enroll_microsoft: bool) -> Result<()> {
    require_root("setup")?;
    require_sbctl()?;

    let sb_on = linhello_secureboot::is_secure_boot_enabled();
    let setup_mode = linhello_secureboot::is_setup_mode();

    if sb_on && !setup_mode {
        bail!(
            "firmware is not in SetupMode and Secure Boot is already on. \
             To re-enroll, clear factory keys in firmware setup first, then reboot and retry."
        );
    }
    if !setup_mode {
        println!(
            "warning: firmware reports it is not in SetupMode. sbctl enroll-keys will likely fail."
        );
        println!("if it does, reboot into firmware setup, clear PK/KEK/db, and retry.");
    }

    println!("==> sbctl create-keys (idempotent)");
    run_sbctl(&["create-keys"])?;

    let enroll_args: &[&str] = if enroll_microsoft {
        &["enroll-keys", "--microsoft"]
    } else {
        &["enroll-keys"]
    };
    println!("==> sbctl {}", enroll_args.join(" "));
    run_sbctl(enroll_args)?;

    println!();
    println!("keys enrolled. next steps:");
    println!("  1. sbctl sign -s <path-to-UKI>     # sign every EFI binary you boot");
    println!("  2. sbctl verify                    # list any remaining unsigned binaries");
    println!("  3. reboot; enable Secure Boot in firmware if not already on");
    println!("  4. linhello reseal                   # bind the keyring secret to PCR 7 under the new keys");
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Update => update_cmd()?,
        Cmd::Setup => run_setup()?,
        Cmd::Detect => detect_cmd(),
        Cmd::Uninstall { keep_models, yes } => uninstall_cmd(!keep_models, yes)?,
        Cmd::Profiles => profiles_cmd()?,
        Cmd::Identify => identify_cmd()?,
        Cmd::ProfileName { user, name } => profile_name_cmd(&user, &name)?,
        Cmd::Status => match send(Request::Status)? {
            Response::Status {
                security_level,
                boot_mode,
                secure_boot,
                loader,
            } => {
                println!("security level : {security_level:?}");
                println!("boot mode      : {boot_mode:?}");
                println!("secure boot    : {secure_boot}");
                if let Some(l) = loader {
                    println!("loader         : {l}");
                }
            }
            other => bail!("unexpected response: {other:?}"),
        },
        Cmd::Enroll { user, reset, samples } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            enroll_guided(&user, reset, samples.max(1))?;
        }
        Cmd::Verify { user } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            match send(Request::Verify { user })? {
                Response::Verified { matched, score, threshold } => {
                    println!("match: {matched}  score: {score:.4}  threshold: {threshold:.4}");
                    if !matched {
                        std::process::exit(1);
                    }
                }
                Response::Error { message } => bail!(message),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Test { user } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            println!("Looking for your face — this is a safe test and cannot lock you out.");
            match send(Request::Verify { user: user.clone() })? {
                Response::Verified { matched, score, threshold } => {
                    if matched {
                        println!(
                            "\u{2713} Recognized you, {user}  (score {score:.2} \u{2265} threshold {threshold:.2})"
                        );
                    } else {
                        println!(
                            "\u{2717} Did not recognize you  (score {score:.2} < threshold {threshold:.2})"
                        );
                        println!("  Login is unaffected. Sit at your usual distance and try again,");
                        println!("  run `linhello enroll` to add samples, or `linhello setup` to retune.");
                        std::process::exit(1);
                    }
                }
                Response::Error { message } => {
                    // A capture/liveness miss is a normal test outcome, not a crash.
                    println!("\u{2717} {message}");
                    println!("  (This is only a test — your login is unaffected.)");
                    std::process::exit(1);
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::SealPassword { user } => {
            use zeroize::Zeroize;
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            let prompt = format!("Login password for {user}: ");
            let mut pw = rpassword::prompt_password(&prompt)
                .context("reading password from TTY")?
                .into_bytes();
            let mut confirm = rpassword::prompt_password("Confirm: ")
                .context("reading password confirmation")?
                .into_bytes();
            let matched = pw == confirm;
            confirm.zeroize();
            if !matched {
                pw.zeroize();
                bail!("passwords do not match");
            }
            // IPC request takes ownership of the password buffer inside a
            // zeroizing `SecretBytes`, which wipes it on drop (and the client
            // wipes the serialized JSON after the write).
            let resp = send(Request::SealPassword {
                user: user.clone(),
                password: SecretBytes::new(std::mem::take(&mut pw)),
            });
            pw.zeroize(); // belt-and-suspenders; take() already emptied it
            match resp? {
                Response::PasswordSealed => println!("password sealed for {user}"),
                Response::Error { message } => bail!(message),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Fingerprint { action } => match action {
            FpAction::Status { user } => {
                let user = user.map(Ok).unwrap_or_else(current_user)?;
                fingerprint_status(&user);
            }
            FpAction::Enable { user } => {
                let user = user.map(Ok).unwrap_or_else(current_user)?;
                fingerprint_enable(&user)?;
            }
            FpAction::Disable { user } => {
                let user = user.map(Ok).unwrap_or_else(current_user)?;
                fingerprint_disable(&user)?;
            }
            FpAction::Add { name, user } => {
                let user = user.map(Ok).unwrap_or_else(current_user)?;
                if !linhello_fingerprint::available() {
                    bail!("no fingerprint reader detected (or fprintd not installed).");
                }
                if enroll_named_finger(&user, name)? {
                    println!("Added. See all with `linhello fingerprint status`.");
                }
            }
        },
        Cmd::SetRecovery { user } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            println!(
                "Set a recovery passphrase for {user}'s face template.\n\
                 This is SEPARATE from your login password and is your backstop if\n\
                 the automatic TPM self-heal can't run (Secure Boot off, TPM cleared,\n\
                 disk moved). Store it somewhere safe — like a BitLocker recovery key."
            );
            set_recovery_interactive(&user)?;
        }
        Cmd::Recover { user } => {
            use zeroize::Zeroize;
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            let mut pw = rpassword::prompt_password(format!("Recovery passphrase for {user}: "))
                .context("reading passphrase from TTY")?
                .into_bytes();
            let resp = send(Request::RestoreFromRecovery {
                user: user.clone(),
                passphrase: SecretBytes::new(std::mem::take(&mut pw)),
            });
            pw.zeroize();
            match resp? {
                Response::RecoveryRestored => println!(
                    "restored {user}: template key re-sealed to the current TPM state. \
                     Try `linhello test`."
                ),
                Response::Error { message } => bail!(message),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Reseal => match send(Request::Reseal)? {
            Response::Resealed { bytes } => println!("sealed {bytes} bytes"),
            Response::Error { message } => bail!(message),
            other => bail!("unexpected response: {other:?}"),
        },
        Cmd::Secureboot { action } => match action {
            SbAction::Status => secureboot_status()?,
            SbAction::Setup { no_microsoft } => secureboot_setup(!no_microsoft)?,
            SbAction::Sign { paths } => secureboot_sign(&paths)?,
            SbAction::Verify => secureboot_verify()?,
            SbAction::List => secureboot_list()?,
        },
        Cmd::LivenessTest => match send(Request::LivenessTest)? {
            Response::LivenessChecked { summary } => {
                let fmt_opt = |v: Option<f32>| {
                    v.map(|x| format!("{x:.3}")).unwrap_or_else(|| "n/a".into())
                };
                let fmt_opt_n = |v: Option<f32>, prec: usize| {
                    v.map(|x| format!("{x:.*}", prec))
                        .unwrap_or_else(|| "n/a".into())
                };
                println!("ML spoof_prob  : {}", fmt_opt(summary.spoof_prob));
                println!("ML real_score  : {}", fmt_opt(summary.ml_score));
                println!(
                    "device trust   : {:.2}  ({}, driver={})",
                    summary.device_score,
                    summary.device_name.as_deref().unwrap_or("?"),
                    summary.device_driver.as_deref().unwrap_or("?"),
                );
                println!(
                    "IR score       : {}  (face/bg {}, mean {}, std {}, hi {})",
                    fmt_opt(summary.ir_score),
                    fmt_opt_n(summary.ir_face_bg_ratio, 2),
                    fmt_opt_n(summary.ir_mean, 1),
                    fmt_opt_n(summary.ir_std, 1),
                    fmt_opt_n(summary.ir_highlight_frac, 3),
                );
                println!("IR eye-glint   : {}", fmt_opt_n(summary.ir_eye_glint, 1));
                println!(
                    "face coverage  : {}",
                    summary
                        .face_frac
                        .map(|v| format!("{:.0}% of frame", v * 100.0))
                        .unwrap_or_else(|| "n/a".into())
                );
                println!(
                    "orientation    : yaw {}°, pitch {}°",
                    fmt_opt_n(summary.yaw_deg, 0),
                    fmt_opt_n(summary.pitch_deg, 0),
                );
                println!("decision       : {}", summary.decision.to_uppercase());
                if let Some(r) = summary.reason {
                    println!("reason         : {r}");
                }
                if summary.decision != "real" {
                    std::process::exit(1);
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected response: {other:?}"),
        },
        Cmd::ResealUserEnvelopes { user } => {
            match send(Request::ResealUserEnvelopes { user: user.clone() })? {
                Response::UserEnvelopesResealed { password, template_key } => {
                    println!(
                        "resealed {user}: password={}, template_key={}",
                        if password { "ok" } else { "skipped" },
                        if template_key { "ok" } else { "skipped" },
                    );
                }
                Response::Error { message } => bail!(message),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Benchmark { user, runs, interval } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            println!("LinuxHello FRR Benchmark");
            println!("user     : {user}");
            println!("runs     : {runs}");
            println!("interval : {interval}s");
            println!();

            let mut passed = 0u32;
            let mut failed_match = 0u32;
            let mut failed_liveness = 0u32;
            let mut no_face = 0u32;
            let mut other_err = 0u32;
            let mut scores: Vec<f32> = Vec::new();
            let mut latencies: Vec<f64> = Vec::new();

            for i in 1..=runs {
                let t0 = std::time::Instant::now();
                let resp = send(Request::Verify { user: user.clone() });
                let elapsed = t0.elapsed().as_secs_f64();
                latencies.push(elapsed);

                match resp {
                    Ok(Response::Verified { matched, score, .. }) => {
                        if matched {
                            passed += 1;
                            scores.push(score);
                            print!("  [{i:>3}/{runs}] PASS  score={score:.4}");
                        } else {
                            failed_match += 1;
                            scores.push(score);
                            print!("  [{i:>3}/{runs}] FAIL  score={score:.4}");
                        }
                    }
                    Ok(Response::Error { message }) => {
                        if message.contains("no face") {
                            no_face += 1;
                            print!("  [{i:>3}/{runs}] NOFACE");
                        } else if message.contains("liveness") || message.contains("move closer")
                            || message.contains("not facing") || message.contains("IR")
                        {
                            failed_liveness += 1;
                            print!("  [{i:>3}/{runs}] LIVE  {message}");
                        } else {
                            other_err += 1;
                            print!("  [{i:>3}/{runs}] ERR   {message}");
                        }
                    }
                    Err(e) => {
                        other_err += 1;
                        print!("  [{i:>3}/{runs}] ERR   {e}");
                    }
                    _ => {
                        other_err += 1;
                        print!("  [{i:>3}/{runs}] ERR   unexpected response");
                    }
                }
                println!("  ({elapsed:.2}s)");

                if i < runs {
                    std::thread::sleep(std::time::Duration::from_secs(interval as u64));
                }
            }

            let total = runs;
            let frr_match = failed_match as f64 / total as f64 * 100.0;
            let frr_all = (failed_match + failed_liveness + no_face) as f64 / total as f64 * 100.0;

            println!();
            println!("Results:");
            println!("  Passed          : {passed}/{total} ({:.1}%)", passed as f64 / total as f64 * 100.0);
            println!("  Match failures  : {failed_match}/{total} ({frr_match:.1}%)");
            println!("  Liveness rejects: {failed_liveness}/{total}");
            println!("  No face         : {no_face}/{total}");
            if other_err > 0 {
                println!("  Other errors    : {other_err}/{total}");
            }

            if !scores.is_empty() {
                let n = scores.len() as f32;
                let mean = scores.iter().sum::<f32>() / n;
                let min = scores.iter().cloned().fold(f32::INFINITY, f32::min);
                let max = scores.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                let var = scores.iter().map(|s| (s - mean).powi(2)).sum::<f32>() / n;
                println!();
                println!("Score statistics (all detected runs):");
                println!("  Mean : {mean:.4}");
                println!("  Min  : {min:.4}");
                println!("  Max  : {max:.4}");
                println!("  Std  : {:.4}", var.sqrt());
            }

            if !latencies.is_empty() {
                let n = latencies.len() as f64;
                let mean = latencies.iter().sum::<f64>() / n;
                let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
                let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                println!();
                println!("Latency:");
                println!("  Mean : {mean:.2}s");
                println!("  Min  : {min:.2}s");
                println!("  Max  : {max:.2}s");
            }

            println!();
            println!("WBF targets:");
            println!("  FRR (match only)       : {frr_match:.1}%  (target < 5%)  {}", if frr_match < 5.0 { "PASS" } else { "FAIL" });
            println!("  FRR (including liveness): {frr_all:.1}%  (target < 10%) {}", if frr_all < 10.0 { "PASS" } else { "FAIL" });
        }
        Cmd::Diag => match send(Request::Diagnose)? {
            Response::Diagnosed {
                envelope_present,
                security_level,
                tracked_pcrs,
                pcr_drift,
                tpm_error,
            } => {
                println!("security level : {security_level:?}");
                println!("envelope       : {}", if envelope_present { "present" } else { "missing" });
                if envelope_present {
                    println!("tracked PCRs   : {tracked_pcrs:?}");
                    match pcr_drift {
                        None if tpm_error.is_none() => println!("pcr drift      : none"),
                        Some(changed) => println!("pcr drift      : {changed:?} CHANGED"),
                        None => {}
                    }
                    if let Some(e) = tpm_error {
                        println!("tpm error      : {e}");
                    }
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected response: {other:?}"),
        },
        Cmd::Doctor => match send(Request::Probe)? {
            Response::Capabilities { report } => {
                print_capability_report(&report);
                print_policy_status();
                println!();
                if !report.can_run() {
                    println!("verdict: CANNOT RUN — a required capability is missing (see [FAIL]).");
                    std::process::exit(1);
                } else if report.degraded() {
                    println!("verdict: READY (degraded) — reduced security/features; see [WARN].");
                } else {
                    println!("verdict: READY — all required capabilities present.");
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected response: {other:?}"),
        },
        Cmd::Position { once } => run_position(once)?,
        Cmd::Tui => {
            require_root("tui")?;
            let user = current_user().unwrap_or_default();
            tui::run(user)?;
        }
        Cmd::Pam { action } => match action {
            PamAction::Status => pam_status_cmd(),
            PamAction::Enable { sudo, dry_run } => pam_enable_cmd(sudo, dry_run)?,
            PamAction::Disable { dry_run } => pam_disable_cmd(dry_run)?,
        },
        Cmd::Selinux { action } => match action {
            SelinuxAction::Status => selinux_status_cmd(),
            SelinuxAction::Install { dry_run, from } => selinux_install_cmd(dry_run, from)?,
            SelinuxAction::Uninstall { dry_run } => selinux_uninstall_cmd(dry_run)?,
        },
        Cmd::ResealHook { action } => match action {
            ResealHookAction::Status => reseal_hook_status_cmd(),
            ResealHookAction::Install { dry_run } => reseal_hook_install_cmd(dry_run)?,
            ResealHookAction::Uninstall { dry_run } => reseal_hook_uninstall_cmd(dry_run)?,
        },
        Cmd::Deps { only } => deps_cmd(only.as_deref()),
        Cmd::FetchModels { force } => {
            require_root("fetch-models")?;
            for l in install::fetch_models(force).map_err(|e| anyhow::anyhow!(e))? {
                println!("  {l}");
            }
        }
        Cmd::FetchOnnx { force } => {
            require_root("fetch-onnx")?;
            for l in install::fetch_onnx(force).map_err(|e| anyhow::anyhow!(e))? {
                println!("  {l}");
            }
        }
        Cmd::Package { format, install } => package_cmd(format.as_deref(), install)?,
    }
    Ok(())
}

fn pam_status_cmd() {
    let status = pamwire::status();
    if status.is_empty() {
        println!("no greeter/sudo PAM services found under /etc/pam.d");
        return;
    }
    println!("face-auth PAM wiring:");
    for s in status {
        println!("  [{}] {}", if s.wired { "on " } else { "off" }, s.path.display());
    }
}

fn pam_enable_cmd(sudo: bool, dry_run: bool) -> Result<()> {
    if !dry_run {
        require_root("pam enable")?;
    }
    for c in pamwire::enable(sudo, dry_run)? {
        println!("  {}", c.describe());
    }
    if !dry_run {
        // Wiring alone isn't enough for the KDE/Plasma lock screen: kscreenlocker
        // runs PAM as the *user*, not root, so `pam_linhello` can only reach the
        // 0660 root:linhello socket if the user is in the `linhello` group. sudo
        // and the display-manager greeter run PAM as root and don't need this, so
        // the missing membership silently breaks only the lock screen. `pam enable`
        // already runs as root, so fix it here too (not just in `setup`).
        println!();
        println!("Socket group (lock-screen access):");
        group_membership_setup_step();
    }
    if !dry_run {
        println!();
        println!("Escape hatch preserved: face-auth is a fallback — if the camera or TPM");
        println!("is unavailable you can still type your password, and the TTY login");
        println!("(Ctrl+Alt+F2) is left untouched. `linhello pam disable` reverts this.");
    }
    Ok(())
}

fn pam_disable_cmd(dry_run: bool) -> Result<()> {
    if !dry_run {
        require_root("pam disable")?;
    }
    for c in pamwire::disable(dry_run)? {
        println!("  {}", c.describe());
    }
    Ok(())
}

/// True if `bin` is found in any PATH directory (no execution).
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

/// Run a shell command string, streaming its output; error if it fails.
fn run_shell(cmd: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .with_context(|| format!("spawning: {cmd}"))?;
    if !status.success() {
        bail!("command failed ({status}): {cmd}");
    }
    Ok(())
}

/// Which linhello SELinux policy is loaded — the packaged confined-daemon module
/// (`linhello-daemon`) or the minimal greeter-access module (`linhello`); either
/// satisfies greeter access. Returns the loaded module's name. The outer `None`
/// means it can't be determined (semodule missing, or the policy store isn't
/// readable — it's root-only, so an unprivileged query returns `None`, not a
/// false "not loaded"); `Some(None)` means determined-and-not-loaded.
fn selinux_module_loaded() -> Option<Option<&'static str>> {
    use linhello_common::platform::{SELINUX_DAEMON_MODULE_NAME, SELINUX_MODULE_NAME};
    if !on_path("semodule") {
        return None;
    }
    let out = Command::new("semodule").arg("-l").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let loaded = |name: &str| text.lines().any(|l| l.trim() == name);
    // Prefer the daemon module name when both happen to be present.
    Some(if loaded(SELINUX_DAEMON_MODULE_NAME) {
        Some(SELINUX_DAEMON_MODULE_NAME)
    } else if loaded(SELINUX_MODULE_NAME) {
        Some(SELINUX_MODULE_NAME)
    } else {
        None
    })
}

fn selinux_status_cmd() {
    use linhello_common::platform;
    let lsm = platform::security_module();
    println!("LSM            : {}", lsm.as_str());
    println!("policy needed  : {}", lsm.needs_selinux_policy());
    match selinux_module_loaded() {
        Some(Some(name)) => println!("module loaded  : yes ({name})"),
        Some(None) => println!("module loaded  : no"),
        None => println!("module loaded  : unknown (run as root, or semodule unavailable)"),
    }
    if std::fs::metadata("/run/linhello.sock").is_ok() {
        println!("socket         : /run/linhello.sock present");
    }
    if lsm.needs_selinux_policy() && selinux_module_loaded() == Some(None) {
        println!();
        println!("Greeter/lock face-auth needs the policy here. Install it with:");
        println!("  sudo linhello selinux install");
    }
}

fn selinux_install_cmd(dry_run: bool, from: Option<String>) -> Result<()> {
    use linhello_common::platform;

    let Some(mut plan) = platform::selinux_policy_plan() else {
        println!(
            "This system does not use SELinux ({}) — no policy to install.",
            platform::security_module().as_str()
        );
        return Ok(());
    };
    if let Some(p) = from {
        plan.source_te = PathBuf::from(p);
    }
    if !plan.source_te.exists() {
        bail!(
            "policy source not found at {} — pass --from <path to linhello.te> \
             (e.g. the repo's etc/selinux/linhello.te) or install the linhello data files",
            plan.source_te.display()
        );
    }
    if dry_run {
        let build = std::env::temp_dir().join(format!("linhello-selinux-{}", std::process::id()));
        println!(
            "Would install SELinux module `{}` (source {}, enforcing={}):",
            plan.module_name,
            plan.source_te.display(),
            plan.enforcing
        );
        for c in &plan.commands(&build) {
            println!("  {c}");
        }
        println!();
        println!("Re-run as root without --dry-run to apply.");
        return Ok(());
    }

    require_root("selinux install")?;
    println!(
        "Installing SELinux module `{}` from {} …",
        plan.module_name,
        plan.source_te.display()
    );
    apply_selinux_plan(&plan)?;

    println!();
    println!("Done. Verify with:  ls -Z /run/linhello.sock   (expect …:linhello_runtime_t)");
    if !plan.enforcing {
        println!("Note: SELinux is permissive now; the module is in place for when you enforce.");
    }
    Ok(())
}

/// Build and load the policy described by `plan`: verify tooling, build in a
/// scratch dir, run the commands, clean up. Assumes root and a present source;
/// shared by `selinux install` and the `setup` step.
fn apply_selinux_plan(plan: &linhello_common::platform::SelinuxPolicyPlan) -> Result<()> {
    for tool in ["checkmodule", "semodule_package", "semodule"] {
        if !on_path(tool) {
            bail!(
                "required tool `{tool}` not found — install the SELinux policy tools \
                 (Fedora: `dnf install checkpolicy policycoreutils`)"
            );
        }
    }
    let build = std::env::temp_dir().join(format!("linhello-selinux-{}", std::process::id()));
    std::fs::create_dir_all(&build)
        .with_context(|| format!("creating build dir {}", build.display()))?;
    let result = (|| {
        for c in &plan.commands(&build) {
            println!("  $ {c}");
            run_shell(c)?;
        }
        Ok::<(), anyhow::Error>(())
    })();
    let _ = std::fs::remove_dir_all(&build);
    result
}

/// Embedded trigger template for a given reseal mechanism (shipped in the repo
/// under etc/; baked into the binary so install needs no companion files).
fn reseal_hook_template(trigger: linhello_common::platform::ResealTrigger) -> &'static str {
    use linhello_common::platform::ResealTrigger;
    match trigger {
        ResealTrigger::PacmanHook => {
            include_str!("../../../etc/pacman.d/hooks/linhello-reseal.hook")
        }
        ResealTrigger::KernelInstall => {
            include_str!("../../../etc/kernel/install.d/95-linhello.install")
        }
        ResealTrigger::KernelPostinst => include_str!("../../../etc/kernel/postinst.d/zz-linhello"),
        ResealTrigger::Manual => "",
    }
}

/// Write the reseal trigger to its active path. The kernel-install / postinst
/// scripts must be executable; the pacman hook is a plain config file.
fn write_reseal_hook(plan: &linhello_common::platform::ResealHookPlan) -> Result<()> {
    use linhello_common::platform::ResealTrigger;
    use std::os::unix::fs::PermissionsExt;

    let content = reseal_hook_template(plan.trigger)
        .replace("/usr/local/bin/linhello-reseal-hook", &plan.script_path.display().to_string());
    if let Some(parent) = plan.hook_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&plan.hook_path, content)
        .with_context(|| format!("writing {}", plan.hook_path.display()))?;
    let mode = match plan.trigger {
        ResealTrigger::KernelInstall | ResealTrigger::KernelPostinst => 0o755,
        _ => 0o644,
    };
    std::fs::set_permissions(&plan.hook_path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {} {}", mode, plan.hook_path.display()))?;
    Ok(())
}

fn reseal_hook_status_cmd() {
    use linhello_common::platform;
    match platform::reseal_hook_plan() {
        None => println!(
            "reseal trigger : none for this distro ({}) — reseal manually after kernel updates",
            platform::distro_family().as_str()
        ),
        Some(plan) => {
            println!("reseal trigger : {} ({})", plan.trigger.as_str(), plan.hook_path.display());
            println!("installed      : {}", if plan.hook_path.exists() { "yes" } else { "no" });
            println!(
                "reseal script  : {} ({})",
                plan.script_path.display(),
                if plan.script_path.exists() { "present" } else { "MISSING" }
            );
        }
    }
}

fn reseal_hook_install_cmd(dry_run: bool) -> Result<()> {
    use linhello_common::platform;
    let Some(plan) = platform::reseal_hook_plan() else {
        println!(
            "No known reseal trigger for this distro ({}) — nothing to install. \
             Reseal manually after kernel updates with `sudo linhello reseal-user-envelopes`.",
            platform::distro_family().as_str()
        );
        return Ok(());
    };
    if dry_run {
        println!(
            "Would install the {} → {} (invokes {}).",
            plan.trigger.as_str(),
            plan.hook_path.display(),
            plan.script_path.display()
        );
        return Ok(());
    }
    require_root("reseal-hook install")?;
    if !plan.script_path.exists() {
        println!(
            "note: reseal script not found at {} yet — install it (make install) so the \
             trigger has something to run.",
            plan.script_path.display()
        );
    }
    write_reseal_hook(&plan)?;
    println!("installed {} → {}", plan.trigger.as_str(), plan.hook_path.display());
    Ok(())
}

fn reseal_hook_uninstall_cmd(dry_run: bool) -> Result<()> {
    use linhello_common::platform;
    let Some(plan) = platform::reseal_hook_plan() else {
        println!("No known reseal trigger for this distro — nothing to remove.");
        return Ok(());
    };
    if dry_run {
        println!("Would remove {}", plan.hook_path.display());
        return Ok(());
    }
    require_root("reseal-hook uninstall")?;
    if plan.hook_path.exists() {
        std::fs::remove_file(&plan.hook_path)
            .with_context(|| format!("removing {}", plan.hook_path.display()))?;
        println!("removed {}", plan.hook_path.display());
    } else {
        println!("not installed — nothing to remove ({})", plan.hook_path.display());
    }
    Ok(())
}

/// `linhello package` — build (and optionally install) the native package for
/// this distro, picked by detection.
fn package_cmd(format: Option<&str>, install: bool) -> Result<()> {
    use linhello_common::platform::{self, PackageFormat};
    let fmt = match format {
        None | Some("auto") => platform::package_format(),
        Some("rpm") => PackageFormat::Rpm,
        Some("deb") => PackageFormat::Deb,
        Some("pkg") => PackageFormat::Pkg,
        Some(o) => bail!("unknown format `{o}`"),
    };
    if fmt == PackageFormat::Unknown {
        bail!("no native package format for this distro ({})", platform::distro_family().as_str());
    }
    if install {
        require_root("package --install")?;
    }
    let root = install::source_root()
        .ok_or_else(|| anyhow::anyhow!("no source checkout found to build from"))?;
    let (pkg, log) = install::build_native_package(&root, fmt).map_err(|e| anyhow::anyhow!(e))?;
    for l in log {
        println!("  {l}");
    }
    if install {
        for l in install::install_native_package(&pkg, fmt).map_err(|e| anyhow::anyhow!(e))? {
            println!("  {l}");
        }
    } else {
        println!("\nBuilt: {}\nInstall it with: sudo linhello package --install", pkg.display());
    }
    Ok(())
}

/// `linhello deps` — per-distro dependency package names + the install command.
fn deps_cmd(only: Option<&str>) {
    use linhello_common::platform;
    let family = platform::distro_family();
    println!("Dependencies for {} ({})", platform::os_release().label(), family.as_str());
    let sections: &[(&str, bool)] = match only {
        Some("runtime") => &[("Runtime", true)],
        Some("build") => &[("Build-time", false)],
        _ => &[("Runtime", true), ("Build-time", false)],
    };
    for (title, runtime) in sections {
        println!("\n{title}:");
        let mut pkgs: Vec<&str> = Vec::new();
        for d in platform::DEPENDENCIES.iter().filter(|d| d.runtime == *runtime) {
            let p = d.package(family);
            let shown = if p.is_empty() {
                "(no distro package — build/fetch upstream)"
            } else {
                p
            };
            println!("  {:<22} {shown}", d.need);
            if !p.is_empty() {
                pkgs.push(p);
            }
        }
        match platform::install_command(&pkgs) {
            Some(cmd) => println!("  → {cmd}"),
            None => println!("  → install the above with your package manager"),
        }
    }
    if platform::DEPENDENCIES
        .iter()
        .any(|d| d.need == "ONNX Runtime" && d.package(family).is_empty())
    {
        println!(
            "\nnote: ONNX Runtime isn't in {}'s main repos — run `sudo linhello fetch-onnx` to \
             install the matching prebuilt (or build it and set ORT_DYLIB_PATH).",
            family.as_str()
        );
    }
}

/// `setup` step: add the current login user to the `linhello` group so they can
/// run the unprivileged CLI without sudo. The group itself is created
/// declaratively (sysusers.d, via `make install` / packaging); this only adds
/// membership, which takes effect at the user's next login. Uniform across
/// distros (systemd everywhere), so not gated.
fn group_membership_setup_step() {
    let user = current_user().unwrap_or_default();
    if user.is_empty() || user == "root" {
        return;
    }
    let group_exists = Command::new("getent")
        .args(["group", SOCKET_GROUP])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !group_exists {
        println!(
            "  '{SOCKET_GROUP}' group missing — create it with: \
             sudo systemd-sysusers (or sudo groupadd -r {SOCKET_GROUP})"
        );
        return;
    }
    let already = Command::new("id")
        .args(["-nG", &user])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == SOCKET_GROUP)
        })
        .unwrap_or(false);
    if already {
        println!("  '{user}' is already in the {SOCKET_GROUP} group.");
        return;
    }
    match Command::new("usermod").args(["-aG", SOCKET_GROUP, &user]).status() {
        Ok(s) if s.success() => println!(
            "  added '{user}' to the {SOCKET_GROUP} group — log out and back in for the \
             unprivileged CLI (sudo works now)."
        ),
        _ => println!(
            "  could not add '{user}' to the {SOCKET_GROUP} group — run: \
             sudo usermod -aG {SOCKET_GROUP} {user}"
        ),
    }
}

/// `setup` step: install the post-update reseal trigger for this distro, gated
/// via `reseal_hook_plan()`. Silent skip when the distro has no known mechanism;
/// never fails setup.
fn reseal_hook_setup_step() -> Result<()> {
    use linhello_common::platform;
    let Some(plan) = platform::reseal_hook_plan() else {
        println!("  no known kernel-update trigger for this distro — reseal manually after updates.");
        return Ok(());
    };
    if plan.hook_path.exists() {
        println!("  reseal trigger already installed ({}).", plan.trigger.as_str());
        return Ok(());
    }
    println!(
        "  keeps TPM envelopes valid across kernel/boot updates via the {}.",
        plan.trigger.as_str()
    );
    if prompt_yes("  install it now? [y/N] ") {
        write_reseal_hook(&plan)?;
        println!("  installed → {}", plan.hook_path.display());
    } else {
        println!("  skipped — run `sudo linhello reseal-hook install` later.");
    }
    Ok(())
}

/// `setup` step: install the SELinux policy if this is a SELinux system and it
/// isn't already loaded. Gated via `selinux_policy_plan()` — a silent no-op on
/// Arch / AppArmor. Never fails setup over a missing source; it points the user
/// at the manual command instead.
fn selinux_setup_step() -> Result<()> {
    use linhello_common::platform;
    let Some(plan) = platform::selinux_policy_plan() else {
        println!("  SELinux not in use on this system — no policy needed.");
        return Ok(());
    };
    if let Some(Some(name)) = selinux_module_loaded() {
        println!("  SELinux policy `{name}` already installed.");
        return Ok(());
    }
    if !plan.source_te.exists() {
        println!("  policy source not found at {} —", plan.source_te.display());
        println!("  install later with: sudo linhello selinux install --from <path to linhello.te>");
        return Ok(());
    }
    println!("  the greeter/lock screen needs the linhello SELinux policy to reach the daemon.");
    if prompt_yes("  install it now? [y/N] ") {
        apply_selinux_plan(&plan)?;
        println!("  installed — socket relabeled to linhello_runtime_t.");
    } else {
        println!("  skipped — run `sudo linhello selinux install` before greeter/lock face login.");
    }
    Ok(())
}

fn selinux_uninstall_cmd(dry_run: bool) -> Result<()> {
    let module = linhello_common::platform::SELINUX_MODULE_NAME;
    let cmds = [
        format!("semodule -r {module}"),
        "systemctl restart linhellod".to_string(),
    ];
    if dry_run {
        println!("Would unload SELinux module `{module}`:");
        for c in &cmds {
            println!("  {c}");
        }
        return Ok(());
    }
    require_root("selinux uninstall")?;
    if selinux_module_loaded() == Some(None) {
        println!("Module `{module}` is not loaded — nothing to do.");
        return Ok(());
    }
    for c in &cmds {
        println!("  $ {c}");
        run_shell(c)?;
    }
    Ok(())
}

/// Live framing guide. Polls `PositionSample` and renders one-line guidance.
/// Exits after the framing has been good for a short streak (or immediately
/// with `--once`).
fn run_position(once: bool) -> Result<()> {
    use linhello_common::ipc::PositionReport;
    use std::io::Write;

    let render = |r: &PositionReport| -> String {
        let ir = if r.ir_present {
            format!(
                "ir {:>3.0}/{:.1}",
                r.ir_brightness.unwrap_or(0.0),
                r.ir_face_bg.unwrap_or(0.0)
            )
        } else {
            "ir --".to_string()
        };
        let nums = match (r.face_frac, r.yaw_deg, r.pitch_deg) {
            (Some(f), Some(y), Some(p)) => format!(
                "q{:>3}%  face {:>3.0}%  yaw {:>+5.1}  pitch {:>+5.1}  lum {:>3.0}  {ir}",
                r.quality,
                f * 100.0,
                y,
                p,
                r.brightness.unwrap_or(0.0),
            ),
            _ => format!("faces: {}  {ir}", r.face_count),
        };
        let mark = if r.well_framed { "OK " } else { "..." };
        // Pad to a fixed width so the carriage-return overwrite leaves no
        // stale characters when the message shrinks.
        format!("[{mark}] {:<46} {:<46}", r.guidance, nums)
    };

    if once {
        match send(Request::PositionSample)? {
            Response::Position { report } => {
                println!("{}", render(&report).trim_end());
                if !report.well_framed {
                    std::process::exit(1);
                }
            }
            Response::Error { message } => bail!(message),
            other => bail!("unexpected response: {other:?}"),
        }
        return Ok(());
    }

    println!("Live framing guide — position your face; press Ctrl-C when done.\n");
    let mut good_streak = 0u32;
    loop {
        match send(Request::PositionSample) {
            Ok(Response::Position { report }) => {
                print!("\r{}", render(&report));
                let _ = std::io::stdout().flush();
                good_streak = if report.well_framed { good_streak + 1 } else { 0 };
                if good_streak >= 5 {
                    println!("\n\nWell framed for a moment — you're set. Run `linhello enroll` to capture.");
                    break;
                }
            }
            Ok(Response::Error { message }) => {
                print!("\r[err] {message:<74}");
                let _ = std::io::stdout().flush();
            }
            Ok(other) => bail!("unexpected response: {other:?}"),
            Err(e) => {
                eprintln!("\ndaemon: {e}");
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
    Ok(())
}
