//! Terminal UI setup wizard.
//!
//! A full-screen, step-by-step front-end over the same daemon IPC and local
//! operations that `linhello setup` drives headlessly. The TUI is a *view*: it
//! holds no logic the CLI doesn't already have, it just ports the wizard's
//! blocking prompt loops onto an event loop. It must only run on an interactive
//! terminal (it also runs as root), so `run()` refuses a non-TTY and the
//! headless `linhello setup` remains the fallback.
//!
//! All seven screens drive real data: the Welcome screen detects whether
//! LinuxHello is already installed/configured on this host (see [`crate::install`])
//! so it reads as a fresh setup or a reconfigure; Host-check renders the live
//! daemon `Probe`; Cameras lists and pins real `/dev/video*` devices;
//! Calibrate samples genuine `Verify` scores; Enroll runs the live
//! `PositionSample` framing guide with auto-capture; and the Login-wiring
//! screen reflects and edits the real per-distro PAM state.

use linhello_biometrics::camera::{self, CameraInfo, CameraKind};
use linhello_common::config;
use linhello_common::ipc::{
    CapabilityReport, CapabilityStatus, IdentifyCandidate, OperationPolicy, PositionReport,
    ProfileInfo, Request, Response, SecretBytes,
};
use zeroize::Zeroize;
use linhello_common::platform;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, Padding, Paragraph, Wrap},
    Frame,
};

/// Shared chrome styling so every screen reads as one cohesive, premium surface.
/// Soft rounded corners + a muted hairline border + generous interior padding —
/// the breathing room is what makes the TUI feel composed rather than like a
/// raw log.
const HAIRLINE: Color = Color::DarkGray;
/// Max content width. We deliberately do NOT stretch to fill wide monitors; a
/// focused, centered column reads far cleaner.
const MAX_WIDTH: u16 = 90;
/// Max content height, so the app floats centered with margin on tall screens
/// instead of pinning to the top-left corner.
const MAX_HEIGHT: u16 = 40;
/// How many terminal rows a line of display-width `w` occupies once wrapped into
/// `inner` columns (>=1). Used to size scrolling against wrapped content.
fn wrapped_rows(w: u16, inner: u16) -> u16 {
    if inner == 0 {
        1
    } else {
        (w.max(1) + inner - 1) / inner
    }
}

/// A rounded, hairline-bordered block — the base for every framed surface.
fn surface() -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(HAIRLINE))
}
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Welcome,
    Install,
    Doctor,
    Cameras,
    Profiles,
    Enroll,
    Calibrate,
    Identify,
    Fingerprint,
    Password,
    Pam,
    Done,
    /// Off the wizard path — reached from Welcome with `u`, returns with Esc.
    Uninstall,
}

impl Screen {
    fn name(self) -> &'static str {
        match self {
            Screen::Welcome => "Welcome",
            Screen::Install => "Install",
            Screen::Doctor => "Host check",
            Screen::Cameras => "Cameras",
            Screen::Profiles => "Profiles",
            Screen::Enroll => "Enroll",
            Screen::Calibrate => "Calibrate",
            Screen::Identify => "Identify",
            Screen::Fingerprint => "Fingerprint",
            Screen::Password => "Password",
            Screen::Pam => "Login wiring",
            Screen::Done => "Done",
            Screen::Uninstall => "Uninstall",
        }
    }
}

/// The linear wizard path. `Uninstall` is intentionally excluded — it is a side
/// screen, not a step.
const ORDER: [Screen; 12] = [
    Screen::Welcome,
    Screen::Install,
    Screen::Doctor,
    Screen::Cameras,
    Screen::Profiles,
    Screen::Enroll,
    Screen::Calibrate,
    Screen::Identify,
    Screen::Fingerprint,
    Screen::Password,
    Screen::Pam,
    Screen::Done,
];

/// Threshold-calibration progress. Sampling advances one `Verify` per event-loop
/// tick so the UI never freezes during the multi-second capture run.
enum CalState {
    Idle,
    Sampling { scores: Vec<f32>, attempts: u32 },
    Review { scores: Vec<f32>, rec: f32, input: String },
    Saved { value: f32 },
    NotEnough,
}

const CAL_TARGET: usize = 8; // genuine scores wanted
const CAL_MAX_ATTEMPTS: u32 = 16; // give up if too many misses

/// Guided enrollment: poll the live framing guide, and once the frame is good
/// quality for a short streak, run a 3-2-1 countdown and capture a sample —
/// repeating until `ENROLL_TARGET` samples are collected.
enum EnrollState {
    Idle,
    Framing { captured: u32, streak: u32 },
    Countdown { captured: u32, left: u8 },
    Done { captured: u32 },
    Failed(String),
}

const ENROLL_TARGET: u32 = 5;
const ENROLL_QUAL_MIN: u8 = 70; // auto-capture quality floor
const ENROLL_STREAK: u32 = 3; // good frames in a row before the countdown

/// "Which face is this" test on the Identify screen.
enum IdentifyState {
    Idle,
    Running,
    Done {
        best: Option<IdentifyCandidate>,
        threshold: f32,
        candidates: Vec<IdentifyCandidate>,
    },
    Failed(String),
}

/// Destructive uninstall flow. Two gates: arm with `x`, then type the word to
/// confirm. Enrolled faces + config are ALWAYS removed; `remove_models` decides
/// whether the big ~190MB .onnx models are deleted too.
enum UninstallState {
    Idle { remove_models: bool },
    Confirm { remove_models: bool, input: String },
    Working,
    Done { log: Vec<String> },
    Failed(String),
}

const UNINSTALL_WORD: &str = "REMOVE";
const ACTIVITY_MAX: usize = 200;

/// Seal-the-login-password step. The typed password (masked on screen) is
/// TPM-sealed via `SealPassword`, creating the envelope `pam_linhello` unseals
/// to set `PAM_AUTHTOK` — the linchpin for keyring unlock AND for face-auth to
/// satisfy sudo/greeter at all.
enum PasswordStep {
    Entry { input: String },
    /// Re-enter the password to confirm it — `first` holds the original entry so
    /// a typo can't silently seal the wrong password.
    Confirm { first: String, input: String },
    Sealed,
    Failed(String),
}

/// Install step: deploy the programs + daemon, then make sure the face models
/// are present (copied from a directory the user points at).
enum InstallStep {
    /// Showing the plan / current state.
    Idle,
    /// Editing the directory to copy models from.
    ModelPath { input: String },
    Done { log: Vec<String> },
    Failed(String),
}

/// Decoded [`Response::PolicyStatus`] for the Host-check panel: the effective
/// tier and what face auth does per operation (sourced from the daemon, so it
/// matches real auth behaviour).
struct PolicyView {
    tier: String,
    secure: bool,
    overridden: bool,
    hardware_tier: String,
    enrolled: bool,
    hardware_ready: bool,
    hardware_note: String,
    ops: Vec<OperationPolicy>,
}

struct App {
    screen: Screen,
    user: String,
    /// Detected deployment state of this host (fresh vs. already set up).
    install: crate::install::InstallState,
    /// Host probe result from the daemon. `None` until fetched; `Err` carries a
    /// human-readable failure.
    report: Option<Result<CapabilityReport, String>>,
    /// Effective biometric tier + per-operation policy from the daemon, fetched
    /// alongside the probe. `None` when unavailable (old/unreachable daemon) —
    /// the panel is simply omitted then.
    policy: Option<PolicyView>,
    /// Vertical scroll offset (in wrapped rows) for the Host-check body — it can
    /// exceed the fixed MAX_HEIGHT budget once the tier/policy panel is included.
    doctor_scroll: u16,
    /// Last-rendered wrapped-row count / visible-row count of the Host-check
    /// body, so ↑/↓ can clamp scrolling to the real (post-wrap) content height.
    doctor_content_rows: std::cell::Cell<u16>,
    doctor_view_rows: std::cell::Cell<u16>,
    /// How many wrapped rows the Activity log is scrolled UP from the newest
    /// (0 = following the latest). Lets the user review prior actions.
    activity_scroll_up: u16,
    /// Last-rendered wrapped-row / visible-row counts for the Activity panel, to
    /// clamp `activity_scroll_up` to the real content height.
    activity_content_rows: std::cell::Cell<u16>,
    activity_view_rows: std::cell::Cell<u16>,
    cameras: Vec<CameraInfo>,
    cam_cursor: usize,
    sel_rgb: Option<String>,
    sel_ir: Option<String>,
    cal: CalState,
    enroll: EnrollState,
    /// Latest framing sample shown on the Enroll screen.
    enroll_last: Option<PositionReport>,
    /// Current PAM wiring status (refreshed on entering the Pam screen).
    pam: Vec<crate::pamwire::ServiceStatus>,
    /// Result/guidance lines from the last enable/disable action.
    pam_note: Vec<String>,
    /// Enrolled profiles (refreshed on entering the Profiles screen).
    profiles: Vec<ProfileInfo>,
    profile_cursor: usize,
    /// Which profile the Enroll step targets.
    active_profile: String,
    /// When `Some`, the Profiles screen is editing the highlighted profile's name.
    name_input: Option<String>,
    /// When `Some(user)`, the Profiles screen is awaiting y/N confirmation to
    /// permanently delete that profile.
    delete_confirm: Option<String>,
    identify: IdentifyState,
    password: PasswordStep,
    uninstall: UninstallState,
    install_step: InstallStep,
    /// Rolling log of what the software has actually done to the system —
    /// shown live in the activity bar so the user can see every change.
    activity: Vec<String>,
    /// Throttle for the live re-detection poll (real-time host state).
    last_poll: Instant,
    /// Set true once the user explicitly saves a camera selection this session
    /// (or an existing cameras.conf is present) — gates leaving the Cameras step.
    cameras_saved: bool,
    /// Fingerprint reader name (None when no reader / fprintd absent), snapshot.
    fp_reader: Option<String>,
    /// Enrolled fingers for the active profile, snapshot at screen entry.
    fp_enrolled: Vec<String>,
    /// Detected unlock methods (camera tiers + fingerprint), snapshot at entry —
    /// so the render path never spawns busctl/fprintd/camera probes.
    fp_methods: linhello_common::biopolicy::AvailableMethods,
    /// (slot, friendly name) for each enrolled finger, snapshot at entry.
    fp_named: Vec<(String, Option<String>)>,
    /// Configured `method` from policy.conf (e.g. "fingerprint" / "auto"), snapshot.
    fp_method: String,
    /// Set by the Fingerprint screen to ask the event loop to suspend the TUI
    /// and run the interactive enroll + PAM-wiring flow, then resume.
    pending_fp_enable: bool,
    /// Set by the Login-wiring screen to ask the event loop to suspend and run
    /// the platform-integration steps (SELinux policy + reseal hook) that print
    /// and prompt, then resume. Mirrors `setup`'s step 2.
    pending_platform_setup: bool,
    /// Set by the Done screen to ask the event loop to suspend and run the
    /// interactive recovery-passphrase entry, then resume.
    pending_recovery: bool,
    /// Whether socket-group membership has been ensured this session (done once
    /// on entering the Login-wiring screen, regardless of the PAM action).
    group_ensured: bool,
    status: String,
    should_quit: bool,
}

impl App {
    fn new(user: String) -> Self {
        let cameras = camera::enumerate();
        // Seed selection from the current config, else the same auto-detect
        // defaults the headless wizard would pick (first trusted RGB / first IR).
        let sel_rgb = config::read_kv("cameras.conf", "rgb").or_else(|| {
            cameras
                .iter()
                .find(|c| c.kind == CameraKind::Rgb && c.trusted)
                .map(|c| c.path.clone())
        });
        let sel_ir = config::read_kv("cameras.conf", "ir").or_else(|| {
            cameras
                .iter()
                .find(|c| c.kind == CameraKind::Ir)
                .map(|c| c.path.clone())
        });
        // An existing cameras.conf means the camera choice is already made, so
        // the Cameras step is satisfied without forcing a re-save.
        let cameras_saved = config::config_path("cameras.conf").exists();
        let active_profile = user.clone();
        App {
            screen: Screen::Welcome,
            policy: None,
            doctor_scroll: 0,
            doctor_content_rows: std::cell::Cell::new(0),
            doctor_view_rows: std::cell::Cell::new(0),
            activity_scroll_up: 0,
            activity_content_rows: std::cell::Cell::new(0),
            activity_view_rows: std::cell::Cell::new(0),
            user,
            install: crate::install::InstallState::detect(),
            report: None,
            cameras,
            cam_cursor: 0,
            sel_rgb,
            sel_ir,
            cal: CalState::Idle,
            enroll: EnrollState::Idle,
            enroll_last: None,
            pam: Vec::new(),
            pam_note: Vec::new(),
            profiles: Vec::new(),
            profile_cursor: 0,
            active_profile,
            name_input: None,
            delete_confirm: None,
            identify: IdentifyState::Idle,
            password: PasswordStep::Entry {
                input: String::new(),
            },
            uninstall: UninstallState::Idle { remove_models: true },
            install_step: InstallStep::Idle,
            activity: Vec::new(),
            last_poll: Instant::now(),
            cameras_saved,
            fp_reader: None,
            fp_enrolled: Vec::new(),
            fp_methods: linhello_common::biopolicy::AvailableMethods::default(),
            fp_named: Vec::new(),
            fp_method: "auto".into(),
            pending_fp_enable: false,
            pending_platform_setup: false,
            pending_recovery: false,
            group_ensured: false,
            status: String::new(),
            should_quit: false,
        }
    }

    fn step_index(&self) -> usize {
        ORDER.iter().position(|s| *s == self.screen).unwrap_or(0)
    }

    /// Record a system-affecting action so the user can see, live, exactly what
    /// the software is doing to their machine. The newest line also becomes the
    /// footer status.
    fn log_activity(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.status = msg.clone();
        // A new action snaps the log back to the newest line, so whatever just
        // happened is always visible (the user can Shift+↑ to review history).
        self.activity_scroll_up = 0;
        self.activity.push(msg);
        if self.activity.len() > ACTIVITY_MAX {
            let drop = self.activity.len() - ACTIVITY_MAX;
            self.activity.drain(0..drop);
        }
    }

    /// Whether the current step is complete enough to advance. `Err(reason)`
    /// blocks `next()` and shows the reason; `Ok(())` allows it. This is the
    /// phased-progression gate: you can't skip past a step that isn't done.
    fn gate(&self) -> Result<(), &'static str> {
        match self.screen {
            Screen::Install => {
                if !self.install.is_installed() {
                    Err("install first — press i to deploy")
                } else if !self.install.daemon_active {
                    Err("the daemon isn't running — press i to deploy/start it")
                } else if !self.install.models_present {
                    Err("required face models missing — press m to copy them in")
                } else {
                    Ok(())
                }
            }
            Screen::Doctor => match &self.report {
                Some(Ok(r)) if r.can_run() => Ok(()),
                Some(Ok(_)) => Err("host can't run LinuxHello — fix the [FAIL] item first"),
                _ => Err("probe the host first (press r)"),
            },
            Screen::Cameras => {
                if self.cameras_saved {
                    Ok(())
                } else {
                    Err("pick an RGB camera and press s to save before continuing")
                }
            }
            Screen::Enroll => {
                if self.active_profile_enrolled() {
                    Ok(())
                } else {
                    Err("enroll at least one face sample first (press Enter)")
                }
            }
            Screen::Password => {
                if matches!(self.password, PasswordStep::Sealed)
                    || self.active_profile_has_password()
                {
                    Ok(())
                } else {
                    Err("seal your login password first — it's what unlocks the keyring and sudo")
                }
            }
            // Welcome / Profiles / Calibrate / Identify / Pam / Done are optional
            // to advance past.
            _ => Ok(()),
        }
    }

    /// Has the active profile got at least one stored sample (enrolled this
    /// session, or already enrolled before the wizard started)?
    fn active_profile_enrolled(&self) -> bool {
        matches!(self.enroll, EnrollState::Done { .. })
            || self.profiles.iter().any(|p| p.user == self.active_profile && p.samples > 0)
            || self.install.enrolled_users.contains(&self.active_profile)
    }

    fn next(&mut self) {
        // The footer shows the lock + reason live, so a blocked step just stays
        // put — no transient status stamp needed.
        if self.gate().is_err() {
            return;
        }
        let mut i = self.step_index();
        while i + 1 < ORDER.len() {
            i += 1;
            if self.screen_applicable(ORDER[i]) {
                self.screen = ORDER[i];
                self.on_enter();
                return;
            }
        }
    }

    fn prev(&mut self) {
        let mut i = self.step_index();
        while i > 0 {
            i -= 1;
            if self.screen_applicable(ORDER[i]) {
                self.screen = ORDER[i];
                self.on_enter();
                return;
            }
        }
    }

    /// Whether a wizard step applies to this host. The TPM password-seal
    /// (`Password`) exists only so SECURE-tier **face** can release the login
    /// password (keyring unlock / sudo-without-prompt). On an RGB-only
    /// (convenience) face tier, face never unseals, so the step is meaningless —
    /// skip it. (Fingerprint, the secure method here, uses pam_fprintd, not this
    /// TPM password envelope.)
    fn screen_applicable(&self, screen: Screen) -> bool {
        match screen {
            Screen::Password => linhello_biometrics::camera::ir_device().is_some(),
            _ => true,
        }
    }

    /// Lazy side-effects when a screen becomes active. Re-detects the install
    /// state every time so the wizard reflects reality live (e.g. right after an
    /// uninstall or install), rather than a stale snapshot from startup.
    fn on_enter(&mut self) {
        // Start each step on a clean slate: drop any stale status from the
        // previous screen and close any half-open inline edit.
        self.status.clear();
        self.name_input = None;
        self.install = crate::install::InstallState::detect();
        match self.screen {
            Screen::Doctor => {
                self.doctor_scroll = 0;
                self.refresh_probe();
            }
            Screen::Cameras => {
                self.cameras = camera::enumerate();
                self.cam_cursor = self.cam_cursor.min(self.cameras.len().saturating_sub(1));
            }
            Screen::Profiles => self.refresh_profiles(),
            Screen::Password => {
                self.refresh_profiles();
                if self.active_profile_has_password() {
                    self.password = PasswordStep::Sealed;
                } else if !matches!(self.password, PasswordStep::Entry { .. }) {
                    self.password = PasswordStep::Entry {
                        input: String::new(),
                    };
                }
            }
            Screen::Pam => {
                self.pam = crate::pamwire::status();
                // Ensure socket-group membership unconditionally on reaching the
                // Login-wiring screen — not only when the user hits enable. A
                // returning user whose PAM is already wired but who isn't in the
                // `linhello` group still needs this, or the lock screen (which
                // runs PAM as the user) can't reach the 0660 root:linhello
                // socket. Headless `setup` does it unconditionally too. Once per
                // session; idempotent.
                if !self.group_ensured {
                    self.group_ensured = true;
                    for line in crate::ensure_socket_group_membership() {
                        self.log_activity(line);
                    }
                }
            }
            Screen::Fingerprint => self.refresh_fingerprint(),
            _ => {}
        }
    }

    /// Snapshot the fingerprint reader + this profile's enrolled fingers (the
    /// Fingerprint screen renders from these, to avoid spawning busctl/fprintd
    /// on every 200ms redraw).
    fn refresh_fingerprint(&mut self) {
        self.fp_reader = if linhello_fingerprint::available() {
            Some(
                linhello_fingerprint::device_name()
                    .unwrap_or_else(|| "fingerprint reader".into()),
            )
        } else {
            None
        };
        self.fp_enrolled = linhello_fingerprint::enrolled_fingers(&self.active_profile);
        self.fp_methods = crate::available_methods(&self.active_profile);
        self.fp_named = self
            .fp_enrolled
            .iter()
            .map(|s| (s.clone(), crate::fingerprint_name(&self.active_profile, s)))
            .collect();
        self.fp_method = linhello_common::config::read_kv("policy.conf", "method")
            .unwrap_or_else(|| "auto".into());
    }

    fn fingerprint_key(&mut self, code: KeyCode) {
        if matches!(code, KeyCode::Char('e')) {
            if !linhello_fingerprint::available() {
                self.status =
                    "no fingerprint reader detected (or fprintd not installed)".into();
                return;
            }
            // The actual enroll is interactive (touch the sensor) and pam-auth-update
            // needs a normal terminal, so the event loop suspends the TUI to run it.
            self.pending_fp_enable = true;
        }
    }

    /// Does the active profile already have a sealed login-password envelope?
    fn active_profile_has_password(&self) -> bool {
        self.profiles
            .iter()
            .any(|p| p.user == self.active_profile && p.has_password)
    }

    fn refresh_profiles(&mut self) {
        if let Ok(Response::Profiles { profiles }) = crate::send(Request::ListProfiles) {
            self.profiles = profiles;
            self.profile_cursor = self.profile_cursor.min(self.profiles.len().saturating_sub(1));
        }
    }

    fn pam_apply(&mut self, enable: bool, sudo: bool) {
        let res = if enable {
            crate::pamwire::enable(sudo, false)
        } else {
            crate::pamwire::disable(false)
        };
        match res {
            Ok(changes) => {
                self.pam_note = changes.iter().map(|c| c.describe()).collect();
                let verb = if enable { "enabling" } else { "disabling" };
                self.log_activity(format!("{verb} face login in PAM:"));
                for c in &changes {
                    self.log_activity(format!("   {}", c.describe()));
                }
                // Socket-group membership (so the user-run lock screen can reach
                // the 0660 root:linhello socket) is handled unconditionally when
                // the Login-wiring screen is entered — see `on_enter` — so it
                // applies even when PAM is already wired and the user never hits
                // enable. No need to repeat it here.
            }
            Err(e) => {
                self.pam_note = vec![format!("error: {e}")];
                self.log_activity(format!("PAM change failed: {e}"));
            }
        }
        self.pam = crate::pamwire::status();
        self.install = crate::install::InstallState::detect();
    }

    fn refresh_probe(&mut self) {
        self.report = Some(match crate::send(Request::Probe) {
            Ok(Response::Capabilities { report }) => Ok(report),
            Ok(other) => Err(format!("unexpected response: {other:?}")),
            Err(e) => Err(e.to_string()),
        });
        // Effective tier + per-op policy, sourced from the daemon. Best-effort:
        // leave `None` (panel omitted) if the daemon is old or unreachable.
        self.policy = match crate::send(Request::PolicyStatus {
            user: self.user.clone(),
        }) {
            Ok(Response::PolicyStatus {
                tier,
                secure,
                hardware_tier,
                overridden,
                enrolled,
                hardware_ready,
                hardware_note,
                ops,
            }) => Some(PolicyView {
                tier,
                secure,
                overridden,
                hardware_tier,
                enrolled,
                hardware_ready,
                hardware_note,
                ops,
            }),
            _ => None,
        };
        // A live refresh must not move the user's view: keep the scroll where it
        // is, only clamping it if the content got shorter. (Resetting to top is
        // done explicitly on entering the screen / re-probing with `r`.)
        self.doctor_scroll = self.doctor_scroll.min(self.doctor_max_scroll());
    }

    /// Restart the daemon without printing (the TUI owns the screen). Returns a
    /// human-readable error string on failure.
    fn restart_daemon_quiet() -> Result<(), String> {
        let status = Command::new("systemctl")
            .args(["restart", "linhellod"])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("systemctl exited {status}"));
        }
        // Let the daemon re-bind the socket and warm the ONNX models.
        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Activity-log scrollback is global (the panel shows on every screen):
        // Shift+↑/↓ (and Shift+PgUp/PgDn) review prior actions without colliding
        // with the per-screen ↑/↓ navigation.
        if mods.contains(KeyModifiers::SHIFT) {
            match code {
                KeyCode::Up => {
                    self.activity_scroll_up =
                        (self.activity_scroll_up + 1).min(self.activity_max_scroll());
                    return;
                }
                KeyCode::Down => {
                    self.activity_scroll_up = self.activity_scroll_up.saturating_sub(1);
                    return;
                }
                KeyCode::PageUp => {
                    self.activity_scroll_up =
                        (self.activity_scroll_up + 5).min(self.activity_max_scroll());
                    return;
                }
                KeyCode::PageDown => {
                    self.activity_scroll_up = self.activity_scroll_up.saturating_sub(5);
                    return;
                }
                _ => {}
            }
        }

        // Uninstall is a modal side-screen with its own keys (Esc leaves it);
        // wizard navigation does not apply there.
        if self.screen == Screen::Uninstall {
            self.uninstall_key(code);
            return;
        }

        // Modal delete-confirmation on the Profiles screen captures EVERY key
        // until resolved (y = delete, anything else = cancel) — no accidental
        // navigation can leave a destructive action half-done.
        if self.screen == Screen::Profiles && self.delete_confirm.is_some() {
            self.delete_confirm_key(code);
            return;
        }

        // Universal step navigation — arrows OR Tab, on EVERY step (including
        // text-entry ones; arrows/Tab are never valid text input). This is the
        // single consistent way to move, and it's what the footer advertises.
        match code {
            KeyCode::Tab | KeyCode::Right => {
                self.next();
                return;
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.prev();
                return;
            }
            _ => {}
        }

        // Focused text-entry sub-states consume the remaining keys (Char /
        // Backspace / Enter / Esc); navigation above already had first refusal.
        if self.screen == Screen::Profiles && self.name_input.is_some() {
            self.name_edit_key(code);
            return;
        }
        if self.screen == Screen::Install && matches!(self.install_step, InstallStep::ModelPath { .. })
        {
            self.install_key(code);
            return;
        }
        if self.screen == Screen::Password
            && matches!(
                self.password,
                PasswordStep::Entry { .. } | PasswordStep::Confirm { .. }
            )
        {
            self.password_key(code);
            return;
        }

        // Global keys.
        match code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
                return;
            }
            _ => {}
        }
        // Screen-specific handling.
        match self.screen {
            Screen::Welcome if matches!(code, KeyCode::Char('u')) => {
                self.screen = Screen::Uninstall;
                self.uninstall = UninstallState::Idle { remove_models: true };
            }
            Screen::Install => self.install_key(code),
            Screen::Cameras => self.cameras_key(code),
            Screen::Profiles => self.profiles_key(code),
            Screen::Calibrate => self.calibrate_key(code),
            Screen::Enroll => self.enroll_key(code),
            Screen::Identify => self.identify_key(code),
            Screen::Password => self.password_key(code),
            Screen::Pam => self.pam_key(code),
            Screen::Fingerprint => self.fingerprint_key(code),
            // Recovery passphrase — the manual backstop, separate from the login
            // password, for when the automatic TPM self-heal can't run. Entry is
            // interactive (typed twice), so the event loop suspends for it.
            Screen::Done if matches!(code, KeyCode::Char('r')) => self.pending_recovery = true,
            Screen::Doctor if matches!(code, KeyCode::Up) => {
                self.doctor_scroll = self.doctor_scroll.saturating_sub(1);
            }
            Screen::Doctor if matches!(code, KeyCode::Down) => {
                self.doctor_scroll = (self.doctor_scroll + 1).min(self.doctor_max_scroll());
            }
            Screen::Doctor if matches!(code, KeyCode::PageUp) => {
                self.doctor_scroll = self.doctor_scroll.saturating_sub(10);
            }
            Screen::Doctor if matches!(code, KeyCode::PageDown) => {
                self.doctor_scroll = (self.doctor_scroll + 10).min(self.doctor_max_scroll());
            }
            Screen::Doctor if matches!(code, KeyCode::Char('r')) => self.refresh_probe(),
            // Self-heal: when the daemon is down, the user can have the wizard
            // start it rather than being told to go run systemctl themselves.
            Screen::Doctor if matches!(code, KeyCode::Char('s')) => {
                self.log_activity("starting linhellod service (systemctl start)…");
                match Self::restart_daemon_quiet() {
                    Ok(()) => self.log_activity("started linhellod"),
                    Err(e) => self.log_activity(format!("could not start linhellod: {e}")),
                }
                self.refresh_probe();
            }
            _ => match code {
                KeyCode::Enter | KeyCode::Right => self.next(),
                KeyCode::Left => self.prev(),
                _ => {}
            },
        }
    }

    /// Install screen: deploy binaries+daemon (`i`), then copy in the models
    /// (`m` / path entry). Both block briefly; fine for a one-shot.
    fn install_key(&mut self, code: KeyCode) {
        let step = std::mem::replace(&mut self.install_step, InstallStep::Idle);
        match step {
            InstallStep::Idle => match code {
                KeyCode::Char('i') => {
                    self.log_activity("installing programs + daemon (make install)…");
                    let target_user = self.user.clone();
                    match crate::install::deploy(&target_user) {
                        Ok(mut log) => {
                            for l in &log {
                                self.log_activity(l.clone());
                            }
                            self.install = crate::install::InstallState::detect();
                            if self.install.models_present {
                                log.push("face models already in place".to_string());
                                self.install_step = InstallStep::Done { log };
                            } else if let Some(dir) = crate::install::bundled_models_dir() {
                                // Bundled models found — copy them automatically.
                                self.log_activity(format!(
                                    "found bundled models in {} — installing them",
                                    dir.display()
                                ));
                                match crate::install::copy_models_from(&dir) {
                                    Ok(mlog) => {
                                        for l in &mlog {
                                            self.log_activity(l.clone());
                                        }
                                        log.extend(mlog);
                                        self.install = crate::install::InstallState::detect();
                                        match Self::restart_daemon_quiet() {
                                            Ok(()) => self.log_activity("restarted linhellod service"),
                                            Err(e) => self.log_activity(format!("daemon restart failed: {e}")),
                                        }
                                        self.install_step = InstallStep::Done { log };
                                    }
                                    Err(e) => {
                                        self.log_activity(format!("bundled copy failed: {e}"));
                                        self.install_step = InstallStep::ModelPath {
                                            input: dir.display().to_string(),
                                        };
                                    }
                                }
                            } else {
                                self.log_activity("models missing — point me at the .onnx folder");
                                self.install_step = InstallStep::ModelPath {
                                    input: String::new(),
                                };
                            }
                        }
                        Err(e) => {
                            self.log_activity(format!("install failed: {e}"));
                            self.install_step = InstallStep::Failed(e);
                        }
                    }
                }
                KeyCode::Char('m') => {
                    self.install_step = InstallStep::ModelPath {
                        input: String::new(),
                    };
                    self.status = "type the models folder, Enter to copy".to_string();
                }
                KeyCode::Right => self.next(),
                KeyCode::Left => self.prev(),
                _ => {}
            },
            InstallStep::ModelPath { mut input } => match code {
                KeyCode::Char(c) => {
                    input.push(c);
                    self.install_step = InstallStep::ModelPath { input };
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.install_step = InstallStep::ModelPath { input };
                }
                KeyCode::Esc => {
                    self.status = "model copy cancelled".to_string();
                    self.install_step = InstallStep::Idle;
                }
                KeyCode::Enter => {
                    let dir = std::path::PathBuf::from(input.trim());
                    self.log_activity(format!("copying models from {} → /etc/linhello", dir.display()));
                    match crate::install::copy_models_from(&dir) {
                        Ok(log) => {
                            for l in &log {
                                self.log_activity(l.clone());
                            }
                            self.install = crate::install::InstallState::detect();
                            match Self::restart_daemon_quiet() {
                                Ok(()) => self.log_activity("restarted linhellod service"),
                                Err(e) => self.log_activity(format!("daemon restart failed: {e}")),
                            }
                            self.install_step = InstallStep::Done { log };
                        }
                        Err(e) => {
                            self.log_activity(format!("model copy failed: {e}"));
                            self.install_step = InstallStep::ModelPath { input };
                        }
                    }
                }
                _ => self.install_step = InstallStep::ModelPath { input },
            },
            // Terminal states: i redoes, arrows navigate.
            other => match code {
                KeyCode::Char('i') => self.install_step = InstallStep::Idle,
                KeyCode::Right => {
                    self.install_step = other;
                    self.next();
                }
                KeyCode::Left => {
                    self.install_step = other;
                    self.prev();
                }
                _ => self.install_step = other,
            },
        }
    }

    /// Profiles screen: navigate, set the active (enroll-target) profile, and
    /// start/commit a name edit.
    fn profiles_key(&mut self, code: KeyCode) {
        let len = self.profiles.len();
        match code {
            KeyCode::Up => self.profile_cursor = self.profile_cursor.saturating_sub(1),
            KeyCode::Down => {
                self.profile_cursor = (self.profile_cursor + 1).min(len.saturating_sub(1))
            }
            // Make the highlighted profile the enroll target.
            KeyCode::Char('s') => {
                if let Some(p) = self.profiles.get(self.profile_cursor) {
                    self.active_profile = p.user.clone();
                    self.status = format!("enroll target: {}", p.user);
                }
            }
            // New profile: enroll under a typed name on the next step. Here we
            // just set the active profile to a fresh login-user name via input.
            KeyCode::Char('a') => {
                self.active_profile = self.user.clone();
                self.status = format!(
                    "enroll target set to your login '{}' — go to Enroll (Tab)",
                    self.user
                );
            }
            // Rename the highlighted profile.
            KeyCode::Char('n') => {
                if let Some(p) = self.profiles.get(self.profile_cursor) {
                    self.name_input = Some(p.name.clone().unwrap_or_default());
                    self.status = format!("naming '{}' — type, Enter to save, Esc to cancel", p.user);
                }
            }
            // Delete the highlighted profile (asks y/N — see delete_confirm_key).
            KeyCode::Char('d') => {
                if let Some(p) = self.profiles.get(self.profile_cursor) {
                    self.delete_confirm = Some(p.user.clone());
                    self.status = format!(
                        "DELETE profile '{}' ({} samples)? press y to confirm, any other key to cancel",
                        p.user, p.samples
                    );
                }
            }
            KeyCode::Char('r') => self.refresh_profiles(),
            KeyCode::Right => self.next(),
            KeyCode::Left => self.prev(),
            _ => {}
        }
    }

    /// Editing a profile's friendly name (Profiles screen, `name_input` is Some).
    fn name_edit_key(&mut self, code: KeyCode) {
        let Some(buf) = self.name_input.as_mut() else { return };
        match code {
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Esc => {
                self.name_input = None;
                self.status = "name edit cancelled".to_string();
            }
            KeyCode::Enter => {
                let name = self.name_input.take().unwrap_or_default();
                if let Some(p) = self.profiles.get(self.profile_cursor) {
                    let user = p.user.clone();
                    match crate::send(Request::SetProfileName {
                        user: user.clone(),
                        name: name.clone(),
                    }) {
                        Ok(Response::ProfileNameSet) => {
                            self.log_activity(format!(
                                "set name of profile '{user}' → \"{name}\" (/etc/linhello/{user}/display_name)"
                            ));
                            self.refresh_profiles();
                        }
                        Ok(Response::Error { message }) => self.status = format!("error: {message}"),
                        Ok(other) => self.status = format!("unexpected: {other:?}"),
                        Err(e) => self.status = format!("error: {e}"),
                    }
                }
            }
            _ => {}
        }
    }

    /// Awaiting y/N to permanently delete the profile in `delete_confirm`.
    /// Only `y`/`Y` deletes; every other key cancels.
    fn delete_confirm_key(&mut self, code: KeyCode) {
        let Some(user) = self.delete_confirm.take() else { return };
        if !matches!(code, KeyCode::Char('y') | KeyCode::Char('Y')) {
            self.status = "delete cancelled — nothing erased".to_string();
            return;
        }
        match crate::send(Request::DeleteProfile { user: user.clone() }) {
            Ok(Response::ProfileDeleted { user, samples }) => {
                self.log_activity(format!(
                    "deleted profile '{user}' ({samples} samples erased) — removed /etc/linhello/{user}/"
                ));
                // If the enroll target was just deleted, fall back to the login user.
                if self.active_profile == user {
                    self.active_profile = self.user.clone();
                }
                self.profile_cursor = 0;
                self.refresh_profiles();
            }
            Ok(Response::Error { message }) => self.status = format!("error: {message}"),
            Ok(other) => self.status = format!("unexpected: {other:?}"),
            Err(e) => self.status = format!("error: {e}"),
        }
    }

    /// Identify screen: `i` runs a 1:N "which face is this" test.
    fn identify_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('i') | KeyCode::Enter
                if !matches!(self.identify, IdentifyState::Running) =>
            {
                self.identify = IdentifyState::Running;
                self.status = "identifying — look at the camera…".to_string();
            }
            KeyCode::Right => self.next(),
            KeyCode::Left => self.prev(),
            _ => {}
        }
    }

    /// Password screen: type the login password (masked) and seal it to the TPM
    /// so face-auth can unlock the keyring and satisfy sudo/greeter.
    fn password_key(&mut self, code: KeyCode) {
        let step = std::mem::replace(
            &mut self.password,
            PasswordStep::Entry {
                input: String::new(),
            },
        );
        match step {
            PasswordStep::Entry { mut input } => match code {
                KeyCode::Char(c) => {
                    input.push(c);
                    self.password = PasswordStep::Entry { input };
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.password = PasswordStep::Entry { input };
                }
                KeyCode::Esc => {
                    input.zeroize();
                    self.status = "password entry cleared".to_string();
                    self.password = PasswordStep::Entry {
                        input: String::new(),
                    };
                }
                KeyCode::Enter => {
                    if input.is_empty() {
                        self.status = "type your login password first".to_string();
                        self.password = PasswordStep::Entry { input };
                        return;
                    }
                    // Confirm before sealing: a sealed typo would silently hand
                    // the wrong password to the login screen and never unlock.
                    self.status = "re-enter the same password to confirm".to_string();
                    self.password = PasswordStep::Confirm {
                        first: input,
                        input: String::new(),
                    };
                }
                _ => self.password = PasswordStep::Entry { input },
            },
            PasswordStep::Confirm { mut first, mut input } => match code {
                KeyCode::Char(c) => {
                    input.push(c);
                    self.password = PasswordStep::Confirm { first, input };
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.password = PasswordStep::Confirm { first, input };
                }
                KeyCode::Esc => {
                    first.zeroize();
                    input.zeroize();
                    self.status = "password entry cleared".to_string();
                    self.password = PasswordStep::Entry {
                        input: String::new(),
                    };
                }
                KeyCode::Enter => {
                    if input != first {
                        first.zeroize();
                        input.zeroize();
                        self.status = "passwords do not match — start over".to_string();
                        self.password = PasswordStep::Entry {
                            input: String::new(),
                        };
                        return;
                    }
                    let user = self.active_profile.clone();
                    let secret = SecretBytes::new(first.clone().into_bytes());
                    first.zeroize();
                    input.zeroize();
                    self.password = match crate::send(Request::SealPassword {
                        user: user.clone(),
                        password: secret,
                    }) {
                        Ok(Response::PasswordSealed) => {
                            self.log_activity(format!(
                                "sealed {user}'s login password to the TPM → /etc/linhello/{user}/password_envelope.json"
                            ));
                            self.install = crate::install::InstallState::detect();
                            PasswordStep::Sealed
                        }
                        Ok(Response::Error { message }) => {
                            self.log_activity(format!("seal password failed: {message}"));
                            PasswordStep::Failed(message)
                        }
                        Ok(other) => PasswordStep::Failed(format!("unexpected: {other:?}")),
                        Err(e) => PasswordStep::Failed(e.to_string()),
                    };
                }
                _ => self.password = PasswordStep::Confirm { first, input },
            },
            // Sealed / Failed: r re-enters, arrows navigate.
            other => match code {
                KeyCode::Char('r') => {
                    self.password = PasswordStep::Entry {
                        input: String::new(),
                    }
                }
                KeyCode::Right => {
                    self.password = other;
                    self.next();
                }
                KeyCode::Left => {
                    self.password = other;
                    self.prev();
                }
                _ => self.password = other,
            },
        }
    }

    /// Uninstall side screen: arm with `x`, toggle data wipe with `d`, type the
    /// confirmation word, Esc to back out.
    fn uninstall_key(&mut self, code: KeyCode) {
        let state = std::mem::replace(&mut self.uninstall, UninstallState::Working);
        match state {
            UninstallState::Idle { remove_models } => match code {
                KeyCode::Char('d') => {
                    self.uninstall = UninstallState::Idle { remove_models: !remove_models };
                }
                KeyCode::Char('x') => {
                    self.uninstall = UninstallState::Confirm {
                        remove_models,
                        input: String::new(),
                    };
                    self.status = format!("type {UNINSTALL_WORD} to confirm, Esc to cancel");
                }
                KeyCode::Esc => {
                    self.uninstall = UninstallState::Idle { remove_models };
                    self.screen = Screen::Welcome;
                    self.on_enter();
                }
                _ => self.uninstall = UninstallState::Idle { remove_models },
            },
            UninstallState::Confirm {
                remove_models,
                mut input,
            } => match code {
                KeyCode::Char(c) => {
                    input.push(c);
                    self.uninstall = UninstallState::Confirm { remove_models, input };
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.uninstall = UninstallState::Confirm { remove_models, input };
                }
                KeyCode::Esc => {
                    self.uninstall = UninstallState::Idle { remove_models };
                    self.status = "uninstall cancelled".to_string();
                }
                KeyCode::Enter => {
                    if input.trim() == UNINSTALL_WORD {
                        // Perform it. Blocks briefly; fine for a one-shot.
                        self.log_activity("uninstalling LinuxHello…");
                        match crate::install::uninstall(remove_models) {
                            Ok(log) => {
                                for l in &log {
                                    self.log_activity(l.clone());
                                }
                                self.install = crate::install::InstallState::detect();
                                self.uninstall = UninstallState::Done { log };
                            }
                            Err(e) => {
                                self.log_activity(format!("uninstall aborted: {e}"));
                                self.uninstall = UninstallState::Failed(e);
                            }
                        }
                    } else {
                        self.status = format!("type exactly {UNINSTALL_WORD}");
                        self.uninstall = UninstallState::Confirm { remove_models, input };
                    }
                }
                _ => self.uninstall = UninstallState::Confirm { remove_models, input },
            },
            // Terminal/working states: Esc returns to Welcome, else stay.
            other => {
                if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
                    self.screen = Screen::Welcome;
                    self.uninstall = UninstallState::Idle { remove_models: true };
                    self.on_enter();
                } else {
                    self.uninstall = other;
                }
            }
        }
    }

    fn enroll_key(&mut self, code: KeyCode) {
        let can_start = matches!(
            self.enroll,
            EnrollState::Idle | EnrollState::Done { .. } | EnrollState::Failed(_)
        );
        match code {
            KeyCode::Enter | KeyCode::Char('c') if can_start => {
                self.enroll = EnrollState::Framing { captured: 0, streak: 0 };
                self.enroll_last = None;
                self.status = "enrolling — follow the cues".to_string();
            }
            KeyCode::Right => self.next(),
            KeyCode::Left => self.prev(),
            _ => {}
        }
    }

    fn poll_position(&self) -> Option<PositionReport> {
        match crate::send(Request::PositionSample) {
            Ok(Response::Position { report }) => Some(report),
            _ => None,
        }
    }

    fn do_enroll_capture(&self) -> Result<(), String> {
        match crate::send(Request::Enroll {
            user: self.active_profile.clone(),
            reset: false,
        }) {
            Ok(Response::Enrolled { .. }) => Ok(()),
            Ok(Response::Error { message }) => Err(message),
            Ok(other) => Err(format!("unexpected response: {other:?}")),
            Err(e) => Err(e.to_string()),
        }
    }

    fn pam_key(&mut self, code: KeyCode) {
        match code {
            // After wiring login, run the platform integration (SELinux policy
            // + reseal hook) that makes the greeter/lock screen actually reach
            // the daemon and keeps TPM envelopes valid across kernel updates —
            // the same step `setup` runs. It prints/prompts, so it's deferred to
            // the event loop, which suspends the TUI for it.
            KeyCode::Char('e') => {
                self.pam_apply(true, false);
                self.pending_platform_setup = true;
            }
            KeyCode::Char('a') => {
                self.pam_apply(true, true);
                self.pending_platform_setup = true;
            }
            // Run platform integration on its own — for the returning user whose
            // PAM is already wired but who still needs the SELinux policy / hook.
            KeyCode::Char('p') => self.pending_platform_setup = true,
            KeyCode::Char('d') => self.pam_apply(false, false),
            KeyCode::Right => self.next(),
            KeyCode::Left => self.prev(),
            _ => {}
        }
    }

    fn cameras_key(&mut self, code: KeyCode) {
        let len = self.cameras.len();
        match code {
            KeyCode::Up => self.cam_cursor = self.cam_cursor.saturating_sub(1),
            KeyCode::Down => self.cam_cursor = (self.cam_cursor + 1).min(len.saturating_sub(1)),
            KeyCode::Char('r') => {
                if let Some(p) = self.cameras.get(self.cam_cursor).map(|c| c.path.clone()) {
                    self.status = format!("RGB = {p}");
                    self.sel_rgb = Some(p);
                }
            }
            KeyCode::Char('i') => {
                if let Some(p) = self.cameras.get(self.cam_cursor).map(|c| c.path.clone()) {
                    self.status = format!("IR = {p}");
                    self.sel_ir = Some(p);
                }
            }
            KeyCode::Char('n') => {
                self.sel_ir = None;
                self.status = "IR cleared".to_string();
            }
            KeyCode::Char('s') => self.save_cameras(),
            KeyCode::Right => self.next(),
            KeyCode::Left => self.prev(),
            _ => {}
        }
    }

    fn save_cameras(&mut self) {
        let Some(rgb) = self.sel_rgb.clone() else {
            self.status = "pick an RGB camera first (press r)".to_string();
            return;
        };
        match camera::write_cameras_conf(&rgb, self.sel_ir.as_deref()) {
            Ok(()) => {
                self.cameras_saved = true;
                let ir = self
                    .sel_ir
                    .as_deref()
                    .map(|p| format!(", ir={p}"))
                    .unwrap_or_default();
                self.log_activity(format!("wrote /etc/linhello/cameras.conf (rgb={rgb}{ir})"));
                match Self::restart_daemon_quiet() {
                    Ok(()) => self.log_activity("restarted linhellod service"),
                    Err(e) => self.log_activity(format!("daemon restart failed: {e}")),
                }
            }
            Err(e) => self.log_activity(format!("could not write cameras.conf: {e}")),
        }
    }

    fn calibrate_key(&mut self, code: KeyCode) {
        // Take the state out so we can both read its fields and reassign it
        // without a borrow conflict; restore at the end.
        let mut cal = std::mem::replace(&mut self.cal, CalState::Idle);
        let mut nav = 0i8;
        let mut save_val: Option<f32> = None;
        match &mut cal {
            CalState::Idle | CalState::NotEnough | CalState::Saved { .. } => match code {
                KeyCode::Char('c') => {
                    cal = CalState::Sampling {
                        scores: Vec::new(),
                        attempts: 0,
                    }
                }
                KeyCode::Right => nav = 1,
                KeyCode::Left => nav = -1,
                _ => {}
            },
            CalState::Sampling { .. } => {} // ignore input while sampling
            CalState::Review { rec, input, .. } => match code {
                KeyCode::Char(ch) if ch.is_ascii_digit() || ch == '.' => input.push(ch),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Enter => {
                    let r = *rec;
                    save_val = Some(if input.trim().is_empty() {
                        r
                    } else {
                        input.trim().parse::<f32>().unwrap_or(r).clamp(0.30, 0.95)
                    });
                }
                _ => {}
            },
        }
        // Apply the save outside the borrow of `cal`.
        if let Some(v) = save_val {
            match config::write_kv("settings.conf", "match_threshold", &format!("{v:.2}")) {
                Ok(()) => {
                    self.log_activity(format!(
                        "wrote match_threshold={v:.2} → /etc/linhello/settings.conf"
                    ));
                    match Self::restart_daemon_quiet() {
                        Ok(()) => self.log_activity("restarted linhellod service"),
                        Err(e) => self.log_activity(format!("daemon restart failed: {e}")),
                    }
                    cal = CalState::Saved { value: v };
                }
                Err(e) => self.log_activity(format!("could not write settings.conf: {e}")),
            }
        }
        self.cal = cal;
        match nav {
            1 => self.next(),
            -1 => self.prev(),
            _ => {}
        }
    }

    /// Advance any in-progress, time-based work (calibration sampling, guided
    /// enrollment). Called once per event-loop iteration.
    /// Real-time host detection: rescan ~1/s so the wizard always reflects what
    /// is actually present right now — models dropped into /etc/linhello,
    /// cameras hot-plugged over USB, the daemon started/stopped — rather than a
    /// snapshot from when the screen was entered.
    fn poll_live(&mut self) {
        self.install = crate::install::InstallState::detect();
        let cams = camera::enumerate();
        if cams.len() != self.cameras.len() {
            self.log_activity(format!(
                "cameras changed: {} device(s) now present",
                cams.len()
            ));
        }
        self.cameras = cams;
        if self.cam_cursor >= self.cameras.len() {
            self.cam_cursor = self.cameras.len().saturating_sub(1);
        }
        // On screens backed by a daemon round-trip or external state, keep those
        // live too while the user is looking at them (not just on first entry).
        match self.screen {
            Screen::Doctor => {
                // Note a hardware-readiness transition (e.g. IR camera unplugged
                // or reconnected) in the activity log — transparency for why face
                // auth may start/stop falling back to the password.
                let was_ready = self.policy.as_ref().map(|p| p.hardware_ready);
                self.refresh_probe();
                if let (Some(was), Some(p)) = (was_ready, self.policy.as_ref()) {
                    if was && !p.hardware_ready && !p.hardware_note.is_empty() {
                        let note = p.hardware_note.clone();
                        self.log_activity(note);
                    } else if !was && p.hardware_ready {
                        self.log_activity("IR camera reconnected — secure tier fully active again");
                    }
                }
            }
            Screen::Profiles => self.refresh_profiles(),
            Screen::Pam => self.pam = crate::pamwire::status(),
            _ => {}
        }
    }

    fn tick(&mut self) {
        if self.last_poll.elapsed() >= Duration::from_secs(1) {
            self.poll_live();
            self.last_poll = Instant::now();
        }
        if self.screen == Screen::Enroll {
            self.tick_enroll();
            return;
        }
        if self.screen == Screen::Identify {
            if matches!(self.identify, IdentifyState::Running) {
                self.identify = match crate::send(Request::Identify) {
                    Ok(Response::Identified {
                        best,
                        threshold,
                        candidates,
                    }) => {
                        self.status = "identified".to_string();
                        IdentifyState::Done {
                            best,
                            threshold,
                            candidates,
                        }
                    }
                    Ok(Response::Error { message }) => IdentifyState::Failed(message),
                    Ok(other) => IdentifyState::Failed(format!("unexpected: {other:?}")),
                    Err(e) => IdentifyState::Failed(e.to_string()),
                };
            }
            return;
        }
        if self.screen != Screen::Calibrate {
            return;
        }
        let taken = std::mem::replace(&mut self.cal, CalState::Idle);
        let CalState::Sampling {
            mut scores,
            mut attempts,
        } = taken
        else {
            self.cal = taken; // not sampling — restore unchanged
            return;
        };
        // One verify per tick keeps the UI responsive.
        attempts += 1;
        if let Ok(Response::Verified { score, .. }) =
            crate::send(Request::Verify { user: self.user.clone() })
        {
            scores.push(score);
        }
        self.status = format!("calibrating… {}/{CAL_TARGET}", scores.len());
        if scores.len() >= CAL_TARGET || attempts >= CAL_MAX_ATTEMPTS {
            if scores.len() < 3 {
                self.cal = CalState::NotEnough;
            } else {
                let min = scores.iter().copied().fold(f32::INFINITY, f32::min);
                let rec = (min - 0.05).clamp(0.45, 0.75);
                self.cal = CalState::Review {
                    scores,
                    rec,
                    input: String::new(),
                };
            }
        } else {
            self.cal = CalState::Sampling { scores, attempts };
        }
    }

    /// Drive the guided-enrollment state machine one step (one framing poll, and
    /// a capture when the countdown elapses).
    fn tick_enroll(&mut self) {
        let good = |r: &Option<PositionReport>| {
            r.as_ref().map(|p| p.well_framed && p.quality >= ENROLL_QUAL_MIN).unwrap_or(false)
        };
        let taken = std::mem::replace(&mut self.enroll, EnrollState::Idle);
        match taken {
            EnrollState::Framing { captured, mut streak } => {
                self.enroll_last = self.poll_position();
                if good(&self.enroll_last) {
                    streak += 1;
                } else {
                    streak = 0;
                }
                self.enroll = if streak >= ENROLL_STREAK {
                    EnrollState::Countdown { captured, left: 3 }
                } else {
                    EnrollState::Framing { captured, streak }
                };
            }
            EnrollState::Countdown { captured, left } => {
                self.enroll_last = self.poll_position();
                if !good(&self.enroll_last) {
                    // Quality dropped — cancel the countdown.
                    self.enroll = EnrollState::Framing { captured, streak: 0 };
                } else if left <= 1 {
                    match self.do_enroll_capture() {
                        Ok(()) => {
                            let n = captured + 1;
                            self.log_activity(format!(
                                "stored face sample {n}/{ENROLL_TARGET} (encrypted) → /etc/linhello/{}/embedding.enc",
                                self.active_profile
                            ));
                            self.enroll = if n >= ENROLL_TARGET {
                                // Reflect the new enrollment in live detection.
                                self.install = crate::install::InstallState::detect();
                                EnrollState::Done { captured: n }
                            } else {
                                EnrollState::Framing { captured: n, streak: 0 }
                            };
                        }
                        Err(e) => {
                            self.log_activity(format!("enroll capture failed: {e}"));
                            self.enroll = EnrollState::Failed(e);
                        }
                    }
                } else {
                    self.enroll = EnrollState::Countdown { captured, left: left - 1 };
                }
            }
            other => self.enroll = other,
        }
    }

    fn render(&self, frame: &mut Frame) {
        // Constrain to a focused, centered column instead of stretching edge to
        // edge — the single biggest lever for a calm, premium feel on wide and
        // tall monitors alike.
        let [area] = Layout::horizontal([Constraint::Max(MAX_WIDTH)])
            .flex(Flex::Center)
            .areas(frame.area());
        let [area] = Layout::vertical([Constraint::Max(MAX_HEIGHT)])
            .flex(Flex::Center)
            .areas(area);

        let chunks = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(6), // activity bar
            Constraint::Length(5), // footer (nav + actions + status legend)
        ])
        .split(area);

        let header_line = if self.screen == Screen::Uninstall {
            Line::from(vec![Span::styled(
                " Uninstall LinuxHello ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )])
        } else {
            Line::from(vec![
                Span::styled(
                    format!(" step {}/{} ", self.step_index() + 1, ORDER.len()),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  "),
                Span::styled(
                    self.screen.name(),
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
            ])
        };
        let header = Paragraph::new(header_line).block(
            surface()
                .title(" LinuxHello setup ")
                .padding(Padding::horizontal(2)),
        );
        frame.render_widget(header, chunks[0]);

        self.render_body(frame, chunks[1]);
        self.render_activity(frame, chunks[2]);

        self.render_footer(frame, chunks[3]);
    }

    /// The always-visible key legend — the single source of truth for how to
    /// move and what each step lets you do, plus a live "can I continue?" line.
    /// Three rows so a first-time user is never left guessing.
    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let key = |s: &'static str| {
            Span::styled(
                s,
                Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            )
        };
        let dim = |s: &'static str| Span::styled(s, Style::default().fg(Color::DarkGray));
        let lab = |s: &'static str| Span::styled(s, Style::default().fg(Color::Gray));

        // Uninstall is a modal with different rules — show its own legend.
        if self.screen == Screen::Uninstall {
            let lines = vec![
                Line::from(vec![key("Esc"), dim("   cancel and return to Welcome")]),
                Line::from(vec![
                    key("x"),
                    dim("  arm, then type "),
                    key("REMOVE"),
                    dim("  to confirm"),
                ]),
                Line::from(Span::styled(
                    "⚠ permanently deletes enrolled faces + config",
                    Style::default().fg(Color::Red),
                )),
            ];
            let p = Paragraph::new(lines).block(surface().padding(Padding::horizontal(2)));
            frame.render_widget(p, area);
            return;
        }

        // Row 1 — universal navigation, identical on every step.
        let mut nav_spans = vec![
            key("←"),
            dim(" back    "),
            key("→"),
            dim(" next    "),
            key("Tab"),
            dim("/"),
            key("⇧Tab"),
            dim(" move    "),
            key("Enter"),
            dim(" confirm    "),
            key("q"),
            dim(" quit"),
        ];
        // Surface the activity scrollback only once there's history off-screen.
        if self.activity_max_scroll() > 0 {
            nav_spans.push(dim("    "));
            nav_spans.push(key("⇧↑/↓"));
            nav_spans.push(dim(" activity log"));
        }
        let nav = Line::from(nav_spans);

        // Row 2 — what THIS step lets you do.
        let hints = self.key_hints();
        let actions = if hints.is_empty() {
            Line::from(dim("on this step:   nothing to set — just continue"))
        } else {
            let mut spans = vec![dim("on this step:   ")];
            for (i, (k, label)) in hints.iter().enumerate() {
                if i > 0 {
                    spans.push(dim("    "));
                }
                spans.push(key(k));
                spans.push(Span::raw(" "));
                spans.push(lab(label));
            }
            Line::from(spans)
        };

        // Row 3 — live "can I move on?" feedback. The gate reason names the exact
        // key to press, so a blocked user is never stuck.
        let status = match self.gate() {
            Err(reason) => Line::from(vec![
                Span::styled("🔒 ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    reason,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
            Ok(()) if !self.status.is_empty() => Line::from(vec![
                dim("• "),
                Span::styled(self.status.clone(), Style::default().fg(Color::Gray)),
            ]),
            Ok(()) => Line::from(vec![
                Span::styled("✓ ", Style::default().fg(Color::Green)),
                dim("ready — press "),
                key("→"),
                dim(" or "),
                key("Tab"),
                dim(" to continue"),
            ]),
        };

        let p =
            Paragraph::new(vec![nav, actions, status]).block(surface().padding(Padding::horizontal(2)));
        frame.render_widget(p, area);
    }

    /// Per-step action keys (excluding the universal nav keys), surfaced in the
    /// footer so every actionable key is discoverable.
    fn key_hints(&self) -> Vec<(&'static str, &'static str)> {
        match self.screen {
            Screen::Welcome => vec![("u", "uninstall")],
            Screen::Install => vec![("i", "deploy / start"), ("m", "copy models")],
            Screen::Doctor => vec![("r", "re-probe"), ("s", "start daemon")],
            Screen::Cameras => vec![
                ("↑↓", "highlight"),
                ("r", "set RGB"),
                ("i", "set IR"),
                ("n", "clear IR"),
                ("s", "save"),
            ],
            Screen::Profiles => vec![
                ("↑↓", "highlight"),
                ("s", "set enroll target"),
                ("n", "rename"),
                ("d", "delete"),
                ("r", "refresh"),
            ],
            Screen::Enroll => vec![("Enter", "start enrolling")],
            Screen::Calibrate => vec![("c", "calibrate")],
            Screen::Identify => vec![("Enter", "identify me")],
            Screen::Password => vec![("type", "password"), ("Enter", "confirm → seal"), ("Esc", "clear")],
            Screen::Pam => vec![
                ("e", "enable greeter"),
                ("a", "enable + sudo"),
                ("p", "platform setup"),
                ("d", "disable"),
            ],
            Screen::Fingerprint => vec![("e", "enroll + enable fingerprint")],
            Screen::Done => vec![("r", "recovery passphrase")],
            Screen::Uninstall => vec![],
        }
    }

    /// The activity bar: a live, plain-language feed of every change the
    /// software makes to the system, so the user can always see what is being
    /// done to their machine. Shows the most recent entries (newest last).
    fn render_activity(&self, frame: &mut Frame, area: Rect) {
        // Build the full log as wrapped lines, then scroll within it so the user
        // can Shift+↑/↓ back through prior actions (default follows the newest).
        let lines: Vec<Line> = if self.activity.is_empty() {
            vec![Line::from(
                "Nothing changed yet. Any file the software touches will be listed here."
                    .dim()
                    .italic(),
            )]
        } else {
            self.activity
                .iter()
                .map(|m| {
                    Line::from(vec![
                        Span::styled("→ ", Style::default().fg(Color::Blue)),
                        Span::raw(m.clone()),
                    ])
                })
                .collect()
        };

        let inner_w = area.width.saturating_sub(2 + 4); // borders + horizontal(2)
        let view_rows = area.height.saturating_sub(2); // borders only
        let content_rows: u16 = lines
            .iter()
            .map(|l| wrapped_rows(l.width() as u16, inner_w))
            .sum();
        self.activity_content_rows.set(content_rows);
        self.activity_view_rows.set(view_rows);

        let max_scroll = content_rows.saturating_sub(view_rows);
        let up = self.activity_scroll_up.min(max_scroll);
        let offset = max_scroll - up; // wrapped-row offset from the top

        // Title hint: show scroll affordance only when there's history off-screen.
        let title = if max_scroll > 0 {
            let pos = if up == 0 { "newest" } else { "↑ history" };
            format!(" ● Activity — what LinuxHello is doing (Shift+↑/↓ scroll · {pos}) ")
        } else {
            " ● Activity — what LinuxHello is doing to your system (newest last) ".to_string()
        };
        let block = surface()
            .title(title)
            .border_style(Style::default().fg(Color::Blue))
            .padding(Padding::horizontal(2));
        let p = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((offset, 0));
        frame.render_widget(p, area);
    }

    fn render_body(&self, frame: &mut Frame, area: Rect) {
        match self.screen {
            Screen::Welcome => self.body_welcome(frame, area),
            Screen::Install => self.body_install(frame, area),
            Screen::Doctor => self.body_doctor(frame, area),
            Screen::Cameras => self.body_cameras(frame, area),
            Screen::Profiles => self.body_profiles(frame, area),
            Screen::Enroll => self.body_enroll(frame, area),
            Screen::Calibrate => self.body_calibrate(frame, area),
            Screen::Identify => self.body_identify(frame, area),
            Screen::Password => self.body_password(frame, area),
            Screen::Pam => self.body_pam(frame, area),
            Screen::Fingerprint => self.body_fingerprint(frame, area),
            Screen::Uninstall => self.body_uninstall(frame, area),
            Screen::Done => {
                let enrolled = !self.install.enrolled_users.is_empty()
                    || matches!(self.enroll, EnrollState::Done { .. });
                let mut lines = vec![
                    Line::from("You're set.".bold()),
                    Line::from(""),
                    Line::from("Host checked, camera saved, threshold calibrated."),
                ];
                if enrolled {
                    lines.push(Line::from(
                        "Run `linhello test` any time to confirm recognition.",
                    ));
                    lines.push(Line::from(
                        "On IR hardware, active-IR liveness is calibrated from your samples — face"
                            .dim(),
                    ));
                    lines.push(Line::from(
                        "unlock rejects photos/screens that don't match your live IR signature."
                            .dim(),
                    ));
                } else {
                    lines.push(Line::from(
                        "No face enrolled yet — go back a step to enroll, or run `linhello enroll`."
                            .yellow(),
                    ));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Optional: press r to set a recovery passphrase — a backstop, separate from",
                ));
                lines.push(Line::from(
                    "your login password, for when the automatic TPM self-heal can't run.",
                ));
                lines.push(Line::from(""));
                lines.push(Line::from("Press q to exit.".italic()));
                self.body_paragraph(frame, area, lines)
            }
        }
    }

    /// One-line "Detected OS → setup path" summary for the Welcome screen.
    fn os_summary_line(&self) -> Line<'static> {
        let p = platform::setup_profile();
        Line::from(vec![
            Span::styled("Detected OS: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                p.os_label,
                Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   ·   setup: {} · PAM via {}", p.family.as_str(), p.pam_method.label()),
                Style::default().fg(Color::DarkGray),
            ),
        ])
    }

    /// Full "what LinuxHello will do on this OS" panel for the Host-check screen.
    fn os_setup_panel(&self) -> Vec<Line<'static>> {
        let p = platform::setup_profile();
        let pam = if p.pam_method.automated() {
            format!("{}  (applied automatically)", p.pam_method.label())
        } else {
            format!("{}  (guided steps — not auto-applied yet)", p.pam_method.label())
        };
        let onnx = p
            .onnxruntime
            .unwrap_or_else(|| "not found — install onnxruntime".to_string());
        let security = if p.security_module.needs_selinux_policy() {
            format!("{}  (SELinux policy module will be installed)", p.security_module.as_str())
        } else {
            format!("{}  (no SELinux policy needed)", p.security_module.as_str())
        };
        vec![
            Line::from(vec![
                Span::styled("Detected OS:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    p.os_label,
                    Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("   (family: {})", p.family.as_str()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(Span::styled(
                "Setup path for this OS:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("  PAM wiring     {pam}")),
            Line::from(format!("  security       {security}")),
            Line::from(format!("  reseal hook    {}", p.reseal_trigger.as_str())),
            Line::from(format!("  initramfs/UKI  {}", p.initramfs_tool)),
            Line::from(format!("  PAM modules    {}", p.pam_module_dir)),
            Line::from(format!("  onnxruntime    {onnx}")),
        ]
    }

    fn body_welcome(&self, frame: &mut Frame, area: Rect) {
        let st = &self.install;
        let headline = st.headline();
        let head_color = if !st.is_installed() {
            Color::Cyan
        } else if st.is_configured() {
            Color::Green
        } else {
            Color::Yellow
        };
        let mut lines = vec![
            Line::from("Welcome to LinuxHello — TPM-backed face login.".bold()),
            Line::from(""),
            self.os_summary_line(),
            Line::from(""),
            Line::from(Span::styled(
                headline,
                Style::default().fg(head_color).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];
        // Detected-state panel.
        for d in st.detail_lines() {
            lines.push(Line::from(Span::styled(
                format!("  {d}"),
                Style::default().fg(Color::Gray),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Target user: {}", self.user)));
        lines.push(Line::from(""));
        // Adapt the next-step hint to what's already here.
        let hint = if st.is_configured() {
            "Already set up. Tab through to re-pick a camera, recalibrate, or re-enroll."
        } else if st.is_installed() {
            "Installed but not enrolled. Tab through to pick a camera and enroll your face."
        } else {
            "This wizard checks hardware, picks a camera, calibrates, and enrolls. Nothing changes until you confirm."
        };
        lines.push(Line::from(hint.italic()));
        lines.push(Line::from(""));
        lines.push(Line::from("Tab to move between steps; q to quit.".italic()));
        if st.is_installed() {
            lines.push(Line::from(Span::styled(
                "Press u to uninstall LinuxHello.",
                Style::default().fg(Color::Red),
            )));
        }
        self.body_paragraph(frame, area, lines);
    }

    fn body_install(&self, frame: &mut Frame, area: Rect) {
        let st = &self.install;
        let lines: Vec<Line> = match &self.install_step {
            InstallStep::Idle => {
                let installed = st.is_installed() && st.daemon_active;
                let mut v = vec![
                    Line::from("Install LinuxHello".bold()),
                    Line::from(""),
                ];
                if installed && st.models_present {
                    v.push(Line::from(
                        "Already installed and the daemon is running.".green(),
                    ));
                    v.push(Line::from("Tab to continue to setup, or press i to redeploy."));
                    v.push(Line::from(""));
                    v.push(Line::from(
                        "Newer LinuxHello on GitHub? Quit and run: sudo linhello update".dark_gray(),
                    ));
                } else {
                    v.push(Line::from("This deploys the programs + daemon, then the face models:"));
                    v.push(Line::from(""));
                    let mark = |ok: bool| if ok { "✓" } else { "·" };
                    v.push(Line::from(format!(
                        "  {} binaries + daemon installed",
                        mark(st.is_installed())
                    )));
                    v.push(Line::from(format!(
                        "  {} daemon running",
                        mark(st.daemon_active)
                    )));
                    v.push(Line::from("  models (live):"));
                    for m in &st.models {
                        let (sym, color) = if m.present {
                            ("✓", Color::Green)
                        } else if m.required {
                            ("✗", Color::Yellow)
                        } else {
                            ("·", Color::DarkGray)
                        };
                        let note = if m.present {
                            "installed"
                        } else if m.shipped {
                            "ships with LinuxHello (installed on deploy)"
                        } else {
                            "fetch buffalo_l — see models/README.md"
                        };
                        v.push(Line::from(vec![
                            Span::raw("    "),
                            Span::styled(sym, Style::default().fg(color)),
                            Span::raw(format!(" {:<18} {:<24} {note}", m.file, m.role)),
                        ]));
                    }
                    v.push(Line::from(""));
                    // Adaptive guidance — only ask for what is actually missing.
                    if st.models_present {
                        v.push(Line::from("  ✓ all required models present.".green()));
                    } else if let Some(dir) = crate::install::bundled_models_dir() {
                        v.push(Line::from(
                            format!("  ✓ models found in {} — deploy will install them", dir.display())
                                .green(),
                        ));
                    } else {
                        v.push(Line::from(
                            "  → fetch buffalo_l (det_10g.onnx + face.onnx) per models/README.md, then it auto-installs".yellow(),
                        ));
                    }
                    v.push(Line::from(""));
                    v.push(Line::from(
                        "i = install everything    m = copy models from a folder".bold(),
                    ));
                    v.push(Line::from(
                        "    installs programs + PAM module, creates the linhello group and adds you,"
                            .dim(),
                    ));
                    v.push(Line::from(
                        "    starts the daemon (verified), installs models — every action shown below"
                            .dim(),
                    ));
                    if let Some(root) = crate::install::source_root() {
                        v.push(Line::from(
                            format!("source tree: {}", root.display()).dim(),
                        ));
                    } else {
                        v.push(Line::from(
                            "no source tree found — set LINHELLO_SRC, or install via your package manager"
                                .yellow(),
                        ));
                    }
                }
                v
            }
            InstallStep::ModelPath { input } => vec![
                Line::from("Copy face models".bold()),
                Line::from(""),
                Line::from("Folder holding det_10g.onnx, face.onnx (+ optional antispoof.onnx):"),
                Line::from(""),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(input.clone(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("▏", Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
                Line::from("Enter to copy, Esc to cancel.".italic()),
            ],
            InstallStep::Done { log } => {
                let mut v = vec![Line::from("Installed.".green().bold()), Line::from("")];
                for l in log {
                    v.push(Line::from(format!("  {l}")));
                }
                v.push(Line::from(""));
                v.push(Line::from("Tab to continue to setup.".italic()));
                v
            }
            InstallStep::Failed(e) => vec![
                Line::from("Install problem.".red().bold()),
                Line::from(""),
                Line::from(e.clone()),
                Line::from(""),
                Line::from("Fix the issue and press i to retry.".italic()),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    fn body_profiles(&self, frame: &mut Frame, area: Rect) {
        if let Some(buf) = &self.name_input {
            // Name-edit overlay.
            let target = self
                .profiles
                .get(self.profile_cursor)
                .map(|p| p.user.as_str())
                .unwrap_or("?");
            self.body_paragraph(
                frame,
                area,
                vec![
                    Line::from(format!("Name profile '{target}'").bold()),
                    Line::from(""),
                    Line::from(vec![
                        Span::raw("Friendly name: "),
                        Span::styled(buf.clone(), Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled("▏", Style::default().fg(Color::Gray)),
                    ]),
                    Line::from(""),
                    Line::from("Enter to save, Esc to cancel.".italic()),
                ],
            );
            return;
        }
        let mut lines = vec![
            Line::from("Profiles — enrolled faces on this machine".bold()),
            Line::from(""),
        ];
        if self.profiles.is_empty() {
            lines.push(Line::from("No profiles enrolled yet.".yellow()));
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "Enroll target is your login '{}'. Tab to the Enroll step.",
                self.active_profile
            )));
        } else {
            for (i, p) in self.profiles.iter().enumerate() {
                let active = p.user == self.active_profile;
                let marker = if active { "▶ " } else { "  " };
                let nm = p.name.as_deref().unwrap_or("—");
                let row = format!(
                    "{marker}{:<14} {:<20} {} samples{}",
                    p.user,
                    nm,
                    p.samples,
                    if p.has_password { ", keyring" } else { "" },
                );
                let line = Line::from(row);
                lines.push(if i == self.profile_cursor {
                    line.style(Style::default().add_modifier(Modifier::REVERSED))
                } else if active {
                    line.style(Style::default().fg(Color::Green))
                } else {
                    line
                });
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Enroll target: {}", self.active_profile).green()));
        lines.push(Line::from(""));
        lines.push(Line::from(
            "↑/↓ pick · s = enroll-target · n = name · a = use my login · r = refresh".italic(),
        ));
        self.body_paragraph(frame, area, lines);
    }

    fn body_identify(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match &self.identify {
            IdentifyState::Idle => vec![
                Line::from("Identify — which face is this?".bold()),
                Line::from(""),
                Line::from("Press i to capture and match your face against every"),
                Line::from("enrolled profile. Tells you who it is (or no match)."),
                Line::from(""),
                Line::from("Press i to start, or Tab to skip.".italic()),
            ],
            IdentifyState::Running => vec![
                Line::from("Look at the camera…".bold().green()),
                Line::from(""),
                Line::from("Capturing and matching against all profiles."),
            ],
            IdentifyState::Done {
                best,
                threshold,
                candidates,
            } => {
                let mut v = match best {
                    Some(c) => {
                        let label = c.name.clone().unwrap_or_else(|| c.user.clone());
                        vec![
                            Line::from("Match!".green().bold()),
                            Line::from(""),
                            Line::from(format!(
                                "This face belongs to: {label}  (profile '{}')",
                                c.user
                            )),
                            Line::from(format!("score {:.3} ≥ threshold {:.2}", c.score, threshold)),
                        ]
                    }
                    None => vec![
                        Line::from("No match.".yellow().bold()),
                        Line::from(""),
                        Line::from(format!("Nobody cleared the {threshold:.2} threshold.")),
                    ],
                };
                if !candidates.is_empty() {
                    v.push(Line::from(""));
                    v.push(Line::from("ranked candidates:".bold()));
                    for c in candidates {
                        let nm = c.name.as_deref().unwrap_or("—");
                        v.push(Line::from(format!("  {:<14} {:<18} {:.3}", c.user, nm, c.score)));
                    }
                }
                v.push(Line::from(""));
                v.push(Line::from("Press i to test again, or Tab to continue.".italic()));
                v
            }
            IdentifyState::Failed(e) => vec![
                Line::from("Identify failed.".red().bold()),
                Line::from(""),
                Line::from(e.clone()),
                Line::from(""),
                Line::from("Press i to retry.".italic()),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    fn body_uninstall(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match &self.uninstall {
            UninstallState::Idle { remove_models } | UninstallState::Confirm { remove_models, .. } => {
                let mut v = vec![
                    Line::from("Uninstall LinuxHello".red().bold()),
                    Line::from(""),
                    Line::from("This will:".bold()),
                ];
                for step in crate::install::uninstall_plan(*remove_models) {
                    v.push(Line::from(format!("  • {step}")));
                }
                v.push(Line::from(""));
                v.push(Line::from(
                    "Enrolled faces + config are ALWAYS removed. Password login keeps working."
                        .italic(),
                ));
                v.push(Line::from(""));
                v.push(Line::from(vec![
                    Span::raw("Also delete the ~190MB face models: "),
                    if *remove_models {
                        Span::styled(
                            "YES",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::styled("no (keep for reinstall)", Style::default().fg(Color::Green))
                    },
                    Span::raw("   (d to toggle)"),
                ]));
                v.push(Line::from(""));
                match &self.uninstall {
                    UninstallState::Confirm { input, .. } => {
                        v.push(Line::from(vec![
                            Span::styled(
                                format!("Type {UNINSTALL_WORD} to confirm: "),
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(input.clone(), Style::default().add_modifier(Modifier::BOLD)),
                            Span::styled("▏", Style::default().fg(Color::Gray)),
                        ]));
                        v.push(Line::from("Enter to execute, Esc to cancel.".italic()));
                    }
                    _ => {
                        v.push(Line::from(
                            "Press x to begin uninstall, Esc to go back.".bold(),
                        ));
                    }
                }
                v
            }
            UninstallState::Working => vec![Line::from("Uninstalling…".bold())],
            UninstallState::Done { log } => {
                let mut v = vec![Line::from("Uninstalled.".green().bold()), Line::from("")];
                for l in log {
                    v.push(Line::from(format!("  {l}")));
                }
                v.push(Line::from(""));
                v.push(Line::from("Press Esc to return, q to quit.".italic()));
                v
            }
            UninstallState::Failed(e) => vec![
                Line::from("Uninstall problem.".red().bold()),
                Line::from(""),
                Line::from(e.clone()),
                Line::from(""),
                Line::from("Press Esc to return.".italic()),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    fn body_paragraph(&self, frame: &mut Frame, area: Rect, lines: Vec<Line>) {
        // Generous interior whitespace (4 cols / 1 row) is what gives every text
        // screen its clean, Apple-like margin — text never touches the frame.
        let block = surface().padding(Padding::symmetric(4, 1));

        // Size the card to its content and float it centered, so the frame hugs
        // the text instead of trapping a tall void beneath it. Width budget =
        // borders (2) + horizontal padding (4+4); height = wrap-aware row count
        // + vertical padding (1+1) + borders (2).
        let inner_w = area.width.saturating_sub(2 + 8).max(1);
        let rows: u16 = lines
            .iter()
            .map(|l| (l.width() as u16).max(1).div_ceil(inner_w))
            .sum();
        let card_h = rows.saturating_add(4).min(area.height);
        let [card] = Layout::vertical([Constraint::Length(card_h)])
            .flex(Flex::Center)
            .areas(area);

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
        frame.render_widget(p, card);
    }

    /// "What face auth does on this machine" panel for the Host-check screen,
    /// built from the daemon's effective tier + per-operation policy. Empty when
    /// the daemon didn't answer (old/unreachable) — the section is then omitted.
    fn policy_panel(&self) -> Vec<Line<'static>> {
        let Some(p) = &self.policy else {
            return Vec::new();
        };
        let summary = if p.secure {
            "login & sudo release your password by face; screen unlock just verifies"
        } else {
            "screen unlock verifies by face; login & sudo fall back to your password"
        };
        // A Secure tier whose IR camera is missing right now is degraded: keep the
        // tier label but colour it as a warning and explain the live fallback.
        let tier_color = if p.secure && p.hardware_ready {
            Color::Green
        } else {
            Color::Yellow
        };
        let mut lines = vec![
            Line::from(Span::styled(
                "What face auth does on this machine:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::raw("  tier   "),
                Span::styled(
                    p.tier.clone(),
                    Style::default().fg(tier_color).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                format!("         {summary}"),
                Style::default().fg(Color::DarkGray),
            )),
        ];
        if !p.hardware_ready && !p.hardware_note.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("         ⚠ {}", p.hardware_note),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        }
        if p.overridden {
            lines.push(Line::from(Span::styled(
                format!("         forced by policy.conf — hardware is {}", p.hardware_tier),
                Style::default().fg(Color::Yellow),
            )));
        }
        if !p.enrolled {
            lines.push(Line::from(Span::styled(
                "         no face enrolled yet — finish setup to activate".to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        for op in &p.ops {
            let color = match op.action.as_str() {
                "unseal" => Color::Green,
                "verify" => Color::Cyan,
                _ => Color::DarkGray,
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {:<21}", op.operation)),
                Span::styled(
                    format!("{:<8}", op.action),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(op.effect.clone(), Style::default().fg(Color::DarkGray)),
            ]));
        }
        lines
    }

    fn body_doctor(&self, frame: &mut Frame, area: Rect) {
        match &self.report {
            None => self.body_paragraph(frame, area, vec![Line::from("Probing host…")]),
            Some(Err(e)) => self.body_paragraph(
                frame,
                area,
                vec![
                    Line::from("Could not reach the daemon:".red().bold()),
                    Line::from(""),
                    Line::from(e.clone()),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("s", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(" = start the daemon for me    "),
                        Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(" = retry the probe"),
                    ]),
                    Line::from(""),
                    Line::from(
                        "(If starting fails, go back a step — Install will show why.)".italic(),
                    ),
                ],
            ),
            Some(Ok(report)) => {
                // The OS panel + checks + tier/policy + verdict exceed the fixed
                // MAX_HEIGHT body budget, so render as a scrollable paragraph that
                // wraps (no truncated lines). Record the wrapped-row geometry so
                // ↑/↓ can clamp to the real content height (scroll is in wrapped
                // rows, matching ratatui's post-wrap offset).
                let lines = self.doctor_lines(report);
                let inner_w = area.width.saturating_sub(2 + 8); // borders + symmetric(4,_)
                let view_rows = area.height.saturating_sub(2 + 2); // borders + symmetric(_,1)
                let content_rows: u16 = lines
                    .iter()
                    .map(|l| wrapped_rows(l.width() as u16, inner_w))
                    .sum();
                self.doctor_content_rows.set(content_rows);
                self.doctor_view_rows.set(view_rows);
                let para = Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((self.doctor_scroll, 0))
                    .block(
                        surface()
                            .title(" host capabilities (r: re-probe · ↑/↓ scroll) ")
                            .padding(Padding::symmetric(4, 1)),
                    );
                frame.render_widget(para, area);
            }
        }
    }

    /// All lines of the Host-check body: detected-OS/setup panel, the probe
    /// checks, the tier/policy panel, and the verdict. Shared by the renderer and
    /// the scroll clamp so they agree on the content height.
    fn doctor_lines(&self, report: &CapabilityReport) -> Vec<Line<'static>> {
        let mut lines = self.os_setup_panel();
        // Lead with the security tier/policy — the headline — so it's visible
        // without scrolling; the longer capability list follows below it.
        let policy = self.policy_panel();
        if !policy.is_empty() {
            lines.push(Line::from(""));
            lines.extend(policy);
        }
        lines.push(Line::from(""));
        lines.extend(report.checks.iter().map(|c| {
            let (sym, color) = match c.status {
                CapabilityStatus::Ok => ("[ OK ]", Color::Green),
                CapabilityStatus::Warn => ("[WARN]", Color::Yellow),
                CapabilityStatus::Missing => ("[FAIL]", Color::Red),
            };
            Line::from(vec![
                Span::styled(sym, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::raw(format!("  {:<20} {}", c.name, c.detail)),
            ])
        }));
        let verdict = if !report.can_run() {
            Line::from("verdict: CANNOT RUN — a required capability is missing.".red().bold())
        } else if report.degraded() {
            Line::from("verdict: READY (degraded) — see [WARN].".yellow())
        } else {
            Line::from("verdict: READY.".green().bold())
        };
        lines.push(Line::from(""));
        lines.push(verdict);
        lines
    }

    /// Largest valid `doctor_scroll`, from the wrapped-row geometry recorded at
    /// the last render (so it accounts for line wrapping, not just line count).
    fn doctor_max_scroll(&self) -> u16 {
        self.doctor_content_rows
            .get()
            .saturating_sub(self.doctor_view_rows.get())
    }

    /// Largest valid `activity_scroll_up`, from the wrapped-row geometry recorded
    /// at the last Activity render.
    fn activity_max_scroll(&self) -> u16 {
        self.activity_content_rows
            .get()
            .saturating_sub(self.activity_view_rows.get())
    }

    fn body_cameras(&self, frame: &mut Frame, area: Rect) {
        if self.cameras.is_empty() {
            self.body_paragraph(
                frame,
                area,
                vec![
                    Line::from("No cameras detected.".red()),
                    Line::from("Connect a UVC webcam and check you can read /dev/video*."),
                ],
            );
            return;
        }
        let items: Vec<ListItem> = self
            .cameras
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut tags = String::new();
                if self.sel_rgb.as_deref() == Some(c.path.as_str()) {
                    tags.push_str(" «RGB");
                }
                if self.sel_ir.as_deref() == Some(c.path.as_str()) {
                    tags.push_str(" «IR");
                }
                let row = format!(
                    "{:<6} {:<26} {:<14} {}{}",
                    format!("{:?}", c.kind),
                    c.name.as_deref().unwrap_or("?"),
                    c.path,
                    if c.trusted { "trusted" } else { "untrusted" },
                    tags,
                );
                let item = ListItem::new(Line::from(row));
                if i == self.cam_cursor {
                    item.style(Style::default().add_modifier(Modifier::REVERSED))
                } else {
                    item
                }
            })
            .collect();
        let title = format!(
            " cameras — ↑/↓ move · r=set RGB · i=set IR · n=clear IR · s=save   [rgb={}, ir={}] ",
            self.sel_rgb.as_deref().unwrap_or("none"),
            self.sel_ir.as_deref().unwrap_or("none"),
        );
        let list = List::new(items).block(
            surface().title(title).padding(Padding::symmetric(4, 1)),
        );
        frame.render_widget(list, area);
    }

    fn body_calibrate(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match &self.cal {
            CalState::Idle => vec![
                Line::from("Threshold calibration".bold()),
                Line::from(""),
                Line::from("Measures your genuine match scores and recommends a"),
                Line::from("match_threshold a margin below your weakest match."),
                Line::from("Needs an existing enrollment to score against."),
                Line::from(""),
                Line::from("Press c to start, or Tab to skip.".italic()),
            ],
            CalState::Sampling { scores, .. } => {
                let mut v = vec![
                    Line::from("Calibrating — look at the camera and hold roughly still.".bold()),
                    Line::from(""),
                    Line::from(format!("collected {}/{CAL_TARGET}", scores.len())),
                ];
                let shown = scores
                    .iter()
                    .map(|s| format!("{s:.3}"))
                    .collect::<Vec<_>>()
                    .join("  ");
                v.push(Line::from(shown));
                v
            }
            CalState::Review { scores, rec, input } => {
                let min = scores.iter().copied().fold(f32::INFINITY, f32::min);
                let mean = scores.iter().sum::<f32>() / scores.len() as f32;
                vec![
                    Line::from("Calibration complete".bold()),
                    Line::from(""),
                    Line::from(format!(
                        "genuine scores: min {min:.3}, mean {mean:.3}  (n={})",
                        scores.len()
                    )),
                    Line::from(format!("recommended threshold: {rec:.2}").green()),
                    Line::from(""),
                    Line::from(vec![
                        Span::raw("Enter to accept, or type 0.45–0.85 then Enter: "),
                        Span::styled(input.clone(), Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled("▏", Style::default().fg(Color::Gray)),
                    ]),
                ]
            }
            CalState::Saved { value } => vec![
                Line::from("Saved.".green().bold()),
                Line::from(""),
                Line::from(format!(
                    "match_threshold = {value:.2}  →  /etc/linhello/settings.conf"
                )),
                Line::from(""),
                Line::from("Tab to continue. Press c to recalibrate.".italic()),
            ],
            CalState::NotEnough => vec![
                Line::from("Not enough good captures.".yellow().bold()),
                Line::from(""),
                Line::from("Keeping the current threshold. Make sure you're enrolled and"),
                Line::from("well lit, then press c to retry — or Tab to skip."),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    fn body_enroll(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match &self.enroll {
            EnrollState::Idle => vec![
                Line::from("Guided enrollment".bold()),
                Line::from(""),
                Line::from(format!(
                    "We'll capture {ENROLL_TARGET} samples. Just follow the cues —"
                )),
                Line::from("capture happens automatically when you're well framed."),
                Line::from("Between shots, vary slightly (small turn, glasses on/off)."),
                Line::from(""),
                Line::from("Press Enter to begin.".italic()),
            ],
            EnrollState::Framing { captured, .. } | EnrollState::Countdown { captured, .. } => {
                let mut v = vec![Line::from(progress_line(*captured)), Line::from("")];
                let q = self.enroll_last.as_ref().map(|r| r.quality).unwrap_or(0);
                v.push(Line::from(format!("Quality {}", quality_bar(q))));
                v.push(Line::from(""));
                v.extend(self.enroll_checklist());
                v.push(Line::from(""));
                if let EnrollState::Countdown { left, .. } = &self.enroll {
                    v.push(Line::from(format!("Hold it — capturing in {left}…").green().bold()));
                } else {
                    let g = self
                        .enroll_last
                        .as_ref()
                        .map(|r| r.guidance.clone())
                        .unwrap_or_else(|| "Looking for your face…".to_string());
                    v.push(Line::from(g.bold()));
                }
                v
            }
            EnrollState::Done { captured } => vec![
                Line::from("Enrollment complete.".green().bold()),
                Line::from(""),
                Line::from(format!("Captured {captured} samples for {}.", self.user)),
                Line::from("Run `linhello test` to confirm recognition."),
                Line::from(""),
                Line::from("Press Enter to enroll again, or Tab to finish.".italic()),
            ],
            EnrollState::Failed(e) => vec![
                Line::from("Enrollment problem.".red().bold()),
                Line::from(""),
                Line::from(e.clone()),
                Line::from(""),
                Line::from("Press Enter to retry.".italic()),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    /// Positive cue checklist derived from the latest framing sample.
    fn enroll_checklist(&self) -> Vec<Line<'static>> {
        let r = self.enroll_last.as_ref();
        let check = |ok: bool, label: &str| {
            let (sym, color) = if ok { ("✓", Color::Green) } else { ("·", Color::DarkGray) };
            Line::from(vec![
                Span::styled(sym, Style::default().fg(color)),
                Span::raw(format!(" {label}")),
            ])
        };
        let face = r.map(|r| r.face_count == 1).unwrap_or(false);
        let dist = r.and_then(|r| r.face_frac).map(|f| (0.15..=0.60).contains(&f)).unwrap_or(false);
        let pose = r
            .map(|r| r.yaw_deg.unwrap_or(99.0).abs() <= 18.0 && r.pitch_deg.unwrap_or(99.0).abs() <= 18.0)
            .unwrap_or(false);
        let light = r.and_then(|r| r.brightness).map(|b| (55.0..=230.0).contains(&b)).unwrap_or(false);
        let ready = r.map(|r| r.well_framed).unwrap_or(false);
        let mut lines = vec![
            check(face, "Face detected"),
            check(dist, "Good distance"),
            check(pose, "Facing the camera"),
            check(light, "Lighting OK"),
        ];
        // Only surface the IR row when an IR sensor is actually present.
        if r.map(|r| r.ir_present).unwrap_or(false) {
            let ir_ok = r.and_then(|r| r.ir_face_bg).map(|x| x >= 1.1).unwrap_or(false);
            lines.push(check(ir_ok, "IR sees your face"));
        }
        lines.push(check(ready, "Ready to capture"));
        lines
    }

    fn body_password(&self, frame: &mut Frame, area: Rect) {
        let lines: Vec<Line> = match &self.password {
            PasswordStep::Entry { input } => vec![
                Line::from("Seal your login password".bold()),
                Line::from(""),
                Line::from(format!(
                    "LinuxHello seals {}'s login password in the TPM. When your face",
                    self.active_profile
                )),
                Line::from("matches, it hands that password to the login screen so your keyring"),
                Line::from("unlocks — and it's what lets face-auth satisfy sudo without a prompt."),
                Line::from(""),
                Line::from("Without this, face-auth can't unlock anything and sudo keeps".yellow()),
                Line::from("asking for your password.".yellow()),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Login password: "),
                    Span::styled(
                        "•".repeat(input.chars().count()),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("▏", Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
                Line::from("Type it (hidden), Enter to continue. Esc clears. It is never written to disk in the clear.".italic()),
            ],
            PasswordStep::Confirm { input, .. } => vec![
                Line::from("Confirm your login password".bold()),
                Line::from(""),
                Line::from("Type the same password again to make sure there's no typo —"),
                Line::from("a sealed typo would silently fail to unlock anything later."),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Confirm password: "),
                    Span::styled(
                        "•".repeat(input.chars().count()),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("▏", Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
                Line::from("Enter to seal. Esc starts over.".italic()),
            ],
            PasswordStep::Sealed => vec![
                Line::from("Password sealed.".green().bold()),
                Line::from(""),
                Line::from(format!(
                    "{}'s login password is sealed in the TPM. Face-auth can now unlock",
                    self.active_profile
                )),
                Line::from("the keyring and satisfy sudo. Re-run `r` if you change your password."),
                Line::from(""),
                Line::from("Tab to continue to Login wiring.".italic()),
            ],
            PasswordStep::Failed(e) => vec![
                Line::from("Couldn't seal the password.".red().bold()),
                Line::from(""),
                Line::from(e.clone()),
                Line::from(""),
                Line::from("Press r to try again.".italic()),
            ],
        };
        self.body_paragraph(frame, area, lines);
    }

    fn body_pam(&self, frame: &mut Frame, area: Rect) {
        let distro = platform::distro_family().as_str();
        // Face login is wired when any non-sudo PAM target is wired. On
        // Fedora/Debian that's system-auth/password-auth/common-auth — which the
        // greeter includes — not a per-service "login screen" file; on Arch it
        // is those per-service files. sudo is the only optional extra, so only
        // it is excluded here.
        let greeter_on = self.pam.iter().any(|s| s.wired && pam_role(&s.path) != "sudo");
        let mut lines = vec![
            Line::from("Login wiring — connect face auth into your login".bold()),
            Line::from(""),
            Line::from("LinuxHello works by adding one line to your login's PAM stack so"),
            Line::from("your face can stand in for the password (and unlock the keyring)."),
            Line::from("Every change is backed up and listed in the Activity bar below."),
            Line::from(""),
            Line::from("What it wires:".bold()),
            Line::from("  • login screen — face unlock + keyring  (needed for LinuxHello)"),
            Line::from("  • lock screen — face unlock  (adds you to the 'linhello' group)"),
            Line::from("  • sudo — face for sudo prompts  (optional)"),
            Line::from(
                "  • platform integration — SELinux policy + reseal hook  (p, or auto on enable)",
            ),
            Line::from(""),
        ];
        if self.pam.is_empty() {
            lines.push(Line::from("No greeter/sudo PAM services found under /etc/pam.d.".yellow()));
        } else {
            lines.push(Line::from("Current wiring:".bold()));
            for s in &self.pam {
                let (tag, color) = if s.wired {
                    ("[ on ]", Color::Green)
                } else {
                    ("[ off]", Color::DarkGray)
                };
                lines.push(Line::from(vec![
                    Span::styled(tag, Style::default().fg(color)),
                    Span::raw(format!(" {:<26} {}", pam_role(&s.path), s.path.display())),
                ]));
            }
        }
        lines.push(Line::from(""));
        // Tell the user clearly whether the needed wiring is in place.
        if greeter_on {
            lines.push(Line::from(
                "✓ Face login is wired into your login screen.".green(),
            ));
        } else {
            lines.push(Line::from(
                "✗ Face login is NOT wired yet — press e to set it up.".yellow(),
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "[{distro}]   e = enable   a = enable + sudo   p = platform setup   d = remove"
        )));
        lines.push(Line::from(
            "Password login always keeps working; the TTY login is never touched.".italic(),
        ));
        self.body_paragraph(frame, area, lines);
    }

    fn body_fingerprint(&self, frame: &mut Frame, area: Rect) {
        let av = self.fp_methods;
        let mut lines = vec![
            Line::from("Fingerprint — a secure-tier unlock method".bold()),
            Line::from(""),
            Line::from("Fingerprint is a standalone secure method (like IR face): it can unlock"),
            Line::from("the screen, the login screen, and sudo. It is NOT combined with face —"),
            Line::from("pick whichever you prefer; your password always still works."),
            Line::from(""),
        ];
        match &self.fp_reader {
            None => {
                lines.push(Line::from(
                    "No fingerprint reader detected (or fprintd not installed).".yellow(),
                ));
                lines.push(Line::from(
                    "This step is optional — continue with face / password.",
                ));
            }
            Some(name) => {
                lines.push(Line::from(format!("reader   : {name}")));
                if self.fp_named.is_empty() {
                    lines.push(Line::from(format!("enrolled : none   (profile: {})", self.active_profile)));
                } else {
                    lines.push(Line::from(format!(
                        "enrolled : {} finger(s)   (profile: {})",
                        self.fp_named.len(),
                        self.active_profile
                    )));
                    for (slot, fname) in &self.fp_named {
                        match fname {
                            Some(n) => lines.push(Line::from(format!("             • {n}  [{slot}]"))),
                            None => lines.push(Line::from(format!("             • {slot}"))),
                        }
                    }
                }
                lines.push(Line::from(format!(
                    "face cam : {}",
                    if av.face_ir { "RGB + IR" } else { "RGB only" }
                )));
                // Reflect the configured method so the user sees whether face is
                // currently suppressed in favour of fingerprint.
                if self.fp_method == "fingerprint" {
                    lines.push(Line::from(
                        "method   : fingerprint — face prompts are suppressed".to_string().green(),
                    ));
                } else {
                    lines.push(Line::from(format!("method   : {} (face active)", self.fp_method)));
                }
                lines.push(Line::from(""));
                // Recommendation is based on what the HARDWARE supports (so a
                // reader that isn't enrolled yet still recommends fingerprint),
                // shown distinctly from what is actually usable right now.
                let recommended = av.recommended_method();
                let active = av.default_method();
                if let Some(rec) = recommended {
                    lines.push(Line::from(vec![
                        Span::raw("recommended : "),
                        Span::styled(rec.label(), Style::default().fg(Color::Green)),
                    ]));
                    if active != recommended {
                        if let Some(act) = active {
                            lines.push(Line::from(format!(
                                "active now  : {}  (until you set up the recommended method)",
                                act.label()
                            )));
                        }
                    }
                }
                lines.push(Line::from(""));
                if self.fp_enrolled.is_empty() {
                    if !av.face_ir {
                        lines.push(Line::from(
                            "✗ Press e to enroll a finger + enable it — the SECURE option here"
                                .yellow(),
                        ));
                        lines.push(Line::from(
                            "  (screen unlock + login + sudo). RGB-only face is convenience-tier:"
                                .yellow(),
                        ));
                        lines.push(Line::from("  it only unlocks an already-open session.".yellow()));
                    } else {
                        lines.push(Line::from(
                            "✗ Press e to enroll a finger — a secure alternative to IR face."
                                .yellow(),
                        ));
                    }
                } else {
                    lines.push(Line::from(
                        "✓ Fingerprint enrolled — secure tier active. Press e to re-wire if needed."
                            .green(),
                    ));
                }
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Pressing e briefly leaves the wizard to run the guided enrollment.".italic(),
        ));
        self.body_paragraph(frame, area, lines);
    }
}

/// Human role of a PAM file for the wiring screen.
fn pam_role(path: &std::path::Path) -> &'static str {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("sudo") => "sudo",
        Some("system-auth") | Some("password-auth") | Some("common-auth") => "system auth",
        _ => "login screen",
    }
}

fn progress_line(captured: u32) -> String {
    let done = captured.min(ENROLL_TARGET) as usize;
    let dots: String = "●".repeat(done) + &"○".repeat(ENROLL_TARGET as usize - done);
    format!("Captured {captured}/{ENROLL_TARGET}   {dots}")
}

fn quality_bar(q: u8) -> String {
    let filled = (q as usize * 10 / 100).min(10);
    format!("[{}{}] {:>3}%", "█".repeat(filled), "░".repeat(10 - filled), q)
}

/// Launch the TUI setup wizard. Refuses a non-interactive terminal.
pub fn run(user: String) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "the TUI needs an interactive terminal; use `linhello setup` for the headless wizard"
        );
    }
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, user);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, user: String) -> anyhow::Result<()> {
    let mut app = App::new(user);
    app.on_enter();
    while !app.should_quit {
        terminal.draw(|frame| app.render(frame))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key.code, key.modifiers);
                }
            }
        }
        if app.pending_fp_enable {
            app.pending_fp_enable = false;
            run_fingerprint_enable_suspended(terminal, &app.active_profile);
            app.refresh_fingerprint();
        }
        if app.pending_platform_setup {
            app.pending_platform_setup = false;
            run_platform_setup_suspended(terminal);
            app.pam = crate::pamwire::status();
            app.install = crate::install::InstallState::detect();
        }
        if app.pending_recovery {
            app.pending_recovery = false;
            run_recovery_suspended(terminal, &app.active_profile);
        }
        app.tick();
    }
    Ok(())
}

/// Suspend the full-screen TUI, run the interactive fingerprint enroll + PAM
/// wiring in the normal terminal (fprintd-enroll needs to prompt; pam-auth-update
/// needs a cooked terminal), then re-enter the alternate screen.
fn run_fingerprint_enable_suspended(terminal: &mut ratatui::DefaultTerminal, user: &str) {
    use std::io::Write;
    ratatui::restore();
    println!("\n— LinuxHello: set up fingerprint —\n");
    match crate::fingerprint_enable(user) {
        Ok(()) => println!("\nFingerprint set up."),
        Err(e) => println!("\nFingerprint setup did not finish: {e}"),
    }
    print!("\nPress Enter to return to the wizard… ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    *terminal = ratatui::init();
}

/// Suspend the TUI to run the platform-integration steps that `setup` runs:
/// install the SELinux policy (so the greeter/lock screen can reach the daemon)
/// and the post-update reseal hook. Both print progress and prompt y/N, which
/// needs a normal terminal — hence the suspend. No-ops on distros where they
/// don't apply.
fn run_platform_setup_suspended(terminal: &mut ratatui::DefaultTerminal) {
    use std::io::Write;
    ratatui::restore();
    println!("\n— LinuxHello: platform integration (SELinux, reseal hook) —\n");
    if let Err(e) = crate::selinux_setup_step() {
        println!("  SELinux step did not finish: {e}");
    }
    if let Err(e) = crate::reseal_hook_setup_step() {
        println!("  reseal-hook step did not finish: {e}");
    }
    print!("\nPress Enter to return to the wizard… ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    *terminal = ratatui::init();
}

/// Suspend the TUI to set a recovery passphrase (typed twice, masked). The
/// prompt reads from the TTY, so the full-screen UI is torn down for it.
fn run_recovery_suspended(terminal: &mut ratatui::DefaultTerminal, user: &str) {
    use std::io::Write;
    ratatui::restore();
    println!("\n— LinuxHello: recovery passphrase —\n");
    println!(
        "A backstop SEPARATE from your login password, for when the automatic\n\
         self-heal can't run (Secure Boot off, TPM cleared, disk moved).\n"
    );
    match crate::set_recovery_interactive(user) {
        Ok(()) => println!("\nRecovery passphrase set."),
        Err(e) => println!("\nRecovery passphrase not set: {e}"),
    }
    print!("\nPress Enter to return to the wizard… ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    *terminal = ratatui::init();
}
