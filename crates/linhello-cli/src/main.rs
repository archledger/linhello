//! `linhello` — user-facing CLI. All operations are dispatched to the `linhellod`
//! daemon over /run/linhello.sock; the CLI itself holds no secrets.

use linhello_common::client;
use linhello_common::ipc::{CapabilityReport, CapabilityStatus, Request, Response, SecretBytes};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write as _;
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
    println!("Step 1/4 — checking hardware & software readiness");
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

    // Step 2 — camera selection, persisted to cameras.conf.
    println!("Step 2/4 — choose your camera");
    let cams = linhello_biometrics::camera::enumerate();
    let (rgb, ir) = choose_cameras(&cams)?;
    linhello_biometrics::camera::write_cameras_conf(&rgb, ir.as_deref())?;
    println!(
        "  saved: rgb={rgb}{}",
        ir.as_deref().map(|p| format!(", ir={p}")).unwrap_or_default()
    );
    restart_daemon()?; // bind the chosen devices before calibrating
    println!();

    // Step 3 — threshold calibration (needs an existing enrollment to score
    // against; if none, we skip and let enrollment happen first).
    let user = current_user()?;
    println!("Step 3/4 — calibrate the match threshold");
    if prompt_yes(&format!(
        "  calibrate against {user}'s enrolled face now? (skip if not enrolled yet) [y/N] "
    )) {
        calibrate_threshold(&user)?;
        restart_daemon()?;
    } else {
        println!("  skipped — using default/current threshold. Re-run setup after enrolling to tune.");
    }
    println!();

    // Step 4 — optional enrollment.
    println!("Step 4/4 — enrollment");
    if prompt_yes(&format!("  enroll {user}'s face now? [y/N] ")) {
        enroll_guided(&user, false, 5)?;
    } else {
        println!("  skipped — run `linhello enroll` when ready.");
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
