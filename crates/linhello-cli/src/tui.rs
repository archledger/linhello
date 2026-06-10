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
    CapabilityReport, CapabilityStatus, IdentifyCandidate, PositionReport, ProfileInfo, Request,
    Response,
};
use linhello_common::platform;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::process::Command;
use std::time::Duration;

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
            Screen::Pam => "Login wiring",
            Screen::Done => "Done",
            Screen::Uninstall => "Uninstall",
        }
    }
}

/// The linear wizard path. `Uninstall` is intentionally excluded — it is a side
/// screen, not a step.
const ORDER: [Screen; 10] = [
    Screen::Welcome,
    Screen::Install,
    Screen::Doctor,
    Screen::Cameras,
    Screen::Profiles,
    Screen::Enroll,
    Screen::Calibrate,
    Screen::Identify,
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
/// confirm. `remove_data` decides whether enrolled faces/models under
/// /etc/linhello are also wiped.
enum UninstallState {
    Idle { remove_data: bool },
    Confirm { remove_data: bool, input: String },
    Working,
    Done { log: Vec<String> },
    Failed(String),
}

const UNINSTALL_WORD: &str = "REMOVE";

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

struct App {
    screen: Screen,
    user: String,
    /// Detected deployment state of this host (fresh vs. already set up).
    install: crate::install::InstallState,
    /// Host probe result from the daemon. `None` until fetched; `Err` carries a
    /// human-readable failure.
    report: Option<Result<CapabilityReport, String>>,
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
    identify: IdentifyState,
    uninstall: UninstallState,
    install_step: InstallStep,
    /// Set true once the user explicitly saves a camera selection this session
    /// (or an existing cameras.conf is present) — gates leaving the Cameras step.
    cameras_saved: bool,
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
            identify: IdentifyState::Idle,
            uninstall: UninstallState::Idle { remove_data: false },
            install_step: InstallStep::Idle,
            cameras_saved,
            status: String::new(),
            should_quit: false,
        }
    }

    fn step_index(&self) -> usize {
        ORDER.iter().position(|s| *s == self.screen).unwrap_or(0)
    }

    /// Whether the current step is complete enough to advance. `Err(reason)`
    /// blocks `next()` and shows the reason; `Ok(())` allows it. This is the
    /// phased-progression gate: you can't skip past a step that isn't done.
    fn gate(&self) -> Result<(), &'static str> {
        match self.screen {
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
        if let Err(reason) = self.gate() {
            self.status = format!("⛔ {reason}");
            return;
        }
        let i = self.step_index();
        if i + 1 < ORDER.len() {
            self.screen = ORDER[i + 1];
            self.on_enter();
        }
    }

    fn prev(&mut self) {
        let i = self.step_index();
        if i > 0 {
            self.screen = ORDER[i - 1];
            self.on_enter();
        }
    }

    /// Lazy side-effects when a screen becomes active. Re-detects the install
    /// state every time so the wizard reflects reality live (e.g. right after an
    /// uninstall or install), rather than a stale snapshot from startup.
    fn on_enter(&mut self) {
        self.install = crate::install::InstallState::detect();
        match self.screen {
            Screen::Doctor if self.report.is_none() => self.refresh_probe(),
            Screen::Cameras => {
                self.cameras = camera::enumerate();
                self.cam_cursor = self.cam_cursor.min(self.cameras.len().saturating_sub(1));
            }
            Screen::Profiles => self.refresh_profiles(),
            Screen::Pam => self.pam = crate::pamwire::status(),
            _ => {}
        }
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
                self.status = if enable { "applied: face login enabled" } else { "applied: face login disabled" }.to_string();
            }
            Err(e) => self.pam_note = vec![format!("error: {e}")],
        }
        self.pam = crate::pamwire::status();
        self.install = crate::install::InstallState::detect();
    }

    fn refresh_probe(&mut self) {
        self.report = Some(match crate::send(Request::Probe) {
            Ok(Response::Capabilities { report }) => {
                self.status = "host probed".to_string();
                Ok(report)
            }
            Ok(other) => Err(format!("unexpected response: {other:?}")),
            Err(e) => Err(e.to_string()),
        });
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

    fn on_key(&mut self, code: KeyCode) {
        // Text-entry modes swallow keys first, so 'q'/Tab become input or
        // local actions rather than quitting/navigating.
        if self.screen == Screen::Profiles && self.name_input.is_some() {
            self.name_edit_key(code);
            return;
        }
        if self.screen == Screen::Install && matches!(self.install_step, InstallStep::ModelPath { .. })
        {
            self.install_key(code);
            return;
        }
        if self.screen == Screen::Uninstall {
            self.uninstall_key(code);
            return;
        }

        // Global keys.
        match code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
                return;
            }
            KeyCode::Tab => {
                self.next();
                return;
            }
            KeyCode::BackTab => {
                self.prev();
                return;
            }
            _ => {}
        }
        // Screen-specific handling.
        match self.screen {
            Screen::Welcome if matches!(code, KeyCode::Char('u')) => {
                self.screen = Screen::Uninstall;
                self.uninstall = UninstallState::Idle { remove_data: false };
            }
            Screen::Install => self.install_key(code),
            Screen::Cameras => self.cameras_key(code),
            Screen::Profiles => self.profiles_key(code),
            Screen::Calibrate => self.calibrate_key(code),
            Screen::Enroll => self.enroll_key(code),
            Screen::Identify => self.identify_key(code),
            Screen::Pam => self.pam_key(code),
            Screen::Doctor if matches!(code, KeyCode::Char('r')) => self.refresh_probe(),
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
                    self.status = "deploying… (running make install)".to_string();
                    match crate::install::deploy() {
                        Ok(mut log) => {
                            self.install = crate::install::InstallState::detect();
                            if self.install.models_present {
                                log.push("face models already in place".to_string());
                                self.status = "installed".to_string();
                                self.install_step = InstallStep::Done { log };
                            } else {
                                self.status =
                                    "deployed — now give me the folder holding the .onnx models"
                                        .to_string();
                                self.install_step = InstallStep::ModelPath {
                                    input: String::new(),
                                };
                            }
                        }
                        Err(e) => self.install_step = InstallStep::Failed(e),
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
                    match crate::install::copy_models_from(&dir) {
                        Ok(log) => {
                            self.install = crate::install::InstallState::detect();
                            let _ = Self::restart_daemon_quiet();
                            self.status = "models installed; daemon restarted".to_string();
                            self.install_step = InstallStep::Done { log };
                        }
                        Err(e) => {
                            self.status = format!("error: {e}");
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
                            self.status = format!("named '{user}': {name}");
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

    /// Uninstall side screen: arm with `x`, toggle data wipe with `d`, type the
    /// confirmation word, Esc to back out.
    fn uninstall_key(&mut self, code: KeyCode) {
        let state = std::mem::replace(&mut self.uninstall, UninstallState::Working);
        match state {
            UninstallState::Idle { remove_data } => match code {
                KeyCode::Char('d') => {
                    self.uninstall = UninstallState::Idle { remove_data: !remove_data };
                }
                KeyCode::Char('x') => {
                    self.uninstall = UninstallState::Confirm {
                        remove_data,
                        input: String::new(),
                    };
                    self.status = format!("type {UNINSTALL_WORD} to confirm, Esc to cancel");
                }
                KeyCode::Esc => {
                    self.uninstall = UninstallState::Idle { remove_data };
                    self.screen = Screen::Welcome;
                    self.on_enter();
                }
                _ => self.uninstall = UninstallState::Idle { remove_data },
            },
            UninstallState::Confirm {
                remove_data,
                mut input,
            } => match code {
                KeyCode::Char(c) => {
                    input.push(c);
                    self.uninstall = UninstallState::Confirm { remove_data, input };
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.uninstall = UninstallState::Confirm { remove_data, input };
                }
                KeyCode::Esc => {
                    self.uninstall = UninstallState::Idle { remove_data };
                    self.status = "uninstall cancelled".to_string();
                }
                KeyCode::Enter => {
                    if input.trim() == UNINSTALL_WORD {
                        // Perform it. Blocks briefly; fine for a one-shot.
                        match crate::install::uninstall(remove_data) {
                            Ok(log) => {
                                self.install = crate::install::InstallState::detect();
                                self.uninstall = UninstallState::Done { log };
                            }
                            Err(e) => self.uninstall = UninstallState::Failed(e),
                        }
                    } else {
                        self.status = format!("type exactly {UNINSTALL_WORD}");
                        self.uninstall = UninstallState::Confirm { remove_data, input };
                    }
                }
                _ => self.uninstall = UninstallState::Confirm { remove_data, input },
            },
            // Terminal/working states: Esc returns to Welcome, else stay.
            other => {
                if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
                    self.screen = Screen::Welcome;
                    self.uninstall = UninstallState::Idle { remove_data: false };
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
            KeyCode::Char('e') => self.pam_apply(true, false),
            KeyCode::Char('a') => self.pam_apply(true, true),
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
                self.status = match Self::restart_daemon_quiet() {
                    Ok(()) => format!("saved rgb={rgb}{ir}; daemon restarted"),
                    Err(e) => format!("saved cameras.conf; restart failed: {e}"),
                };
            }
            Err(e) => self.status = format!("save failed: {e}"),
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
                    self.status = match Self::restart_daemon_quiet() {
                        Ok(()) => format!("saved match_threshold={v:.2}; daemon restarted"),
                        Err(e) => format!("saved match_threshold={v:.2}; restart failed: {e}"),
                    };
                    cal = CalState::Saved { value: v };
                }
                Err(e) => self.status = format!("save failed: {e}"),
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
    fn tick(&mut self) {
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
                            self.status = format!("captured {n}/{ENROLL_TARGET}");
                            self.enroll = if n >= ENROLL_TARGET {
                                // Reflect the new enrollment in live detection.
                                self.install = crate::install::InstallState::detect();
                                EnrollState::Done { captured: n }
                            } else {
                                EnrollState::Framing { captured: n, streak: 0 }
                            };
                        }
                        Err(e) => self.enroll = EnrollState::Failed(e),
                    }
                } else {
                    self.enroll = EnrollState::Countdown { captured, left: left - 1 };
                }
            }
            other => self.enroll = other,
        }
    }

    fn render(&self, frame: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

        let header_line = if self.screen == Screen::Uninstall {
            Line::from(vec![Span::styled(
                " Uninstall LinuxHello ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )])
        } else {
            Line::from(vec![
                Span::raw(format!(" step {}/{}: ", self.step_index() + 1, ORDER.len())),
                Span::styled(
                    self.screen.name(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ])
        };
        let header =
            Paragraph::new(header_line).block(Block::bordered().title(" LinuxHello setup "));
        frame.render_widget(header, chunks[0]);

        self.render_body(frame, chunks[1]);

        let key = |k: &'static str| {
            Span::styled(
                format!(" {k} "),
                Style::default().fg(Color::Black).bg(Color::Gray),
            )
        };
        let footer = Paragraph::new(Line::from(vec![
            key("Tab"),
            Span::raw(" next  "),
            key("⇧Tab"),
            Span::raw(" back  "),
            key("q"),
            Span::raw(" quit    "),
            Span::styled(self.status.clone(), Style::default().fg(Color::DarkGray)),
        ]))
        .block(Block::bordered());
        frame.render_widget(footer, chunks[2]);
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
            Screen::Pam => self.body_pam(frame, area),
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
                } else {
                    lines.push(Line::from(
                        "No face enrolled yet — go back a step to enroll, or run `linhello enroll`."
                            .yellow(),
                    ));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Press q to exit.".italic()));
                self.body_paragraph(frame, area, lines)
            }
        }
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
                    v.push(Line::from(format!(
                        "  {} face models present{}",
                        mark(st.models_present),
                        if st.models_present {
                            String::new()
                        } else {
                            format!(" (missing: {})", st.missing_models.join(", "))
                        }
                    )));
                    v.push(Line::from(""));
                    v.push(Line::from(
                        "i = deploy binaries + daemon    m = copy models from a folder".bold(),
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
            UninstallState::Idle { remove_data } | UninstallState::Confirm { remove_data, .. } => {
                let mut v = vec![
                    Line::from("Uninstall LinuxHello".red().bold()),
                    Line::from(""),
                    Line::from("This will:".bold()),
                ];
                for step in crate::install::uninstall_plan(*remove_data) {
                    v.push(Line::from(format!("  • {step}")));
                }
                v.push(Line::from(""));
                v.push(Line::from(
                    "Your password login keeps working — only face auth is removed.".italic(),
                ));
                v.push(Line::from(""));
                v.push(Line::from(vec![
                    Span::raw("Also erase enrolled faces + models in /etc/linhello: "),
                    if *remove_data {
                        Span::styled("YES", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                    } else {
                        Span::styled("no", Style::default().fg(Color::Green))
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
        let p = Paragraph::new(lines)
            .block(Block::bordered())
            .wrap(Wrap { trim: false });
        frame.render_widget(p, area);
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
                    Line::from("Is linhellod running? Press r to retry.".italic()),
                ],
            ),
            Some(Ok(report)) => {
                let mut items: Vec<ListItem> = report
                    .checks
                    .iter()
                    .map(|c| {
                        let (sym, color) = match c.status {
                            CapabilityStatus::Ok => ("[ OK ]", Color::Green),
                            CapabilityStatus::Warn => ("[WARN]", Color::Yellow),
                            CapabilityStatus::Missing => ("[FAIL]", Color::Red),
                        };
                        ListItem::new(Line::from(vec![
                            Span::styled(
                                sym,
                                Style::default().fg(color).add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(format!("  {:<20} {}", c.name, c.detail)),
                        ]))
                    })
                    .collect();
                let verdict = if !report.can_run() {
                    Line::from("verdict: CANNOT RUN — a required capability is missing.".red().bold())
                } else if report.degraded() {
                    Line::from("verdict: READY (degraded) — see [WARN].".yellow())
                } else {
                    Line::from("verdict: READY.".green().bold())
                };
                items.push(ListItem::new(Line::from("")));
                items.push(ListItem::new(verdict));
                let list = List::new(items).block(Block::bordered().title(" host capabilities (r: re-probe) "));
                frame.render_widget(list, area);
            }
        }
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
        let list = List::new(items).block(Block::bordered().title(title));
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

    fn body_pam(&self, frame: &mut Frame, area: Rect) {
        let distro = platform::distro_family().as_str();
        let mut lines = vec![
            Line::from("Enable face login".bold()),
            Line::from(""),
            Line::from(format!("Distro family: {distro}    e=enable · a=enable+sudo · d=disable")),
            Line::from(""),
        ];
        if self.pam.is_empty() {
            lines.push(Line::from("No greeter/sudo PAM services found under /etc/pam.d.".yellow()));
        } else {
            lines.push(Line::from("Current wiring:".bold()));
            for s in &self.pam {
                let (tag, color) = if s.wired {
                    ("[on ]", Color::Green)
                } else {
                    ("[off]", Color::DarkGray)
                };
                lines.push(Line::from(vec![
                    Span::styled(tag, Style::default().fg(color)),
                    Span::raw(format!(" {}", s.path.display())),
                ]));
            }
        }
        if !self.pam_note.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from("Last action:".bold()));
            for n in &self.pam_note {
                lines.push(Line::from(format!("  {n}")));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Face-auth is a fallback (password still works); the TTY login is left alone.".italic(),
        ));
        self.body_paragraph(frame, area, lines);
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
                    app.on_key(key.code);
                }
            }
        }
        app.tick();
    }
    Ok(())
}
