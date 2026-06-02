//! `aegyra` — user-facing CLI. All operations are dispatched to the `aegyrad`
//! daemon over /run/aegyra.sock; the CLI itself holds no secrets.

use aegyra_common::client;
use aegyra_common::ipc::{CapabilityStatus, Request, Response, SecretBytes};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(name = "aegyra", version, about = "Aegyra control CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Status,
    /// Capture a face sample. Default appends to any existing samples so you
    /// can enroll separate frames for glasses-on / glasses-off / etc; auth
    /// takes the best match across all of them. `--reset` wipes prior
    /// samples and stores just this one.
    Enroll {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        reset: bool,
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
    /// Probe this machine for the hardware/software Aegyra needs (TPM, Secure
    /// Boot, RGB/IR cameras, ONNX runtime, models) and report readiness.
    Doctor,
    /// Capture one frame and print raw liveness signals (ML spoof score,
    /// camera trust). Use to tune `AEGYRA_SPOOF_THRESHOLD` or diagnose
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
    let sb = aegyra_secureboot::is_secure_boot_enabled();
    let setup_mode = aegyra_secureboot::is_setup_mode();
    let loader = aegyra_secureboot::loader_identity();

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
        bail!("secureboot {op} must run as root (got uid {uid})");
    }
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
    println!("signed {} file(s). run `aegyra secureboot verify` to confirm.", paths.len());
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

    let sb_on = aegyra_secureboot::is_secure_boot_enabled();
    let setup_mode = aegyra_secureboot::is_setup_mode();

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
    println!("  4. aegyra reseal                   # bind the keyring secret to PCR 7 under the new keys");
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
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
        Cmd::Enroll { user, reset } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            match send(Request::Enroll {
                user: user.clone(),
                reset,
            })? {
                Response::Enrolled { samples } => {
                    println!("enrolled: {user} ({samples} sample{})",
                        if samples == 1 { "" } else { "s" });
                }
                Response::Error { message } => bail!(message),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Cmd::Verify { user } => {
            let user = user.map(Ok).unwrap_or_else(current_user)?;
            match send(Request::Verify { user })? {
                Response::Verified { matched, score } => {
                    println!("match: {matched}  score: {score:.4}");
                    if !matched {
                        std::process::exit(1);
                    }
                }
                Response::Error { message } => bail!(message),
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
            println!("Aegyra FRR Benchmark");
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
                    Ok(Response::Verified { matched, score }) => {
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
                for c in &report.checks {
                    let tag = match c.status {
                        CapabilityStatus::Ok => "[ OK ]",
                        CapabilityStatus::Warn => "[WARN]",
                        CapabilityStatus::Missing if c.required => "[FAIL]",
                        CapabilityStatus::Missing => "[ -- ]",
                    };
                    println!("{tag} {:<20} {}", c.name, c.detail);
                }
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
    }
    Ok(())
}
