//! Integration tests for the linhellod IPC wire protocol.
//!
//! Each test spawns a fresh daemon against a throw-away socket under /tmp,
//! exercises one interaction, and tears the daemon down. Uses only paths
//! that don't require real hardware (no camera, no TPM): Status, malformed
//! requests, and root-gating.
//!
//! Intentionally skipped here (hardware-dependent — cover with on-device
//! smoke tests): Enroll, Verify, Unseal, SealPassword, UnsealPassword,
//! Reseal, LivenessTest.

use linhello_common::client;
use linhello_common::ipc::{Request, Response, SecretBytes};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn spawn() -> Self {
        let pid = std::process::id();
        // Cargo-nextest-style parallelism friendly: unique per test + pid.
        let n = rand_suffix();
        let socket = PathBuf::from(format!("/tmp/linhellod-it-{pid}-{n}.sock"));
        let _ = std::fs::remove_file(&socket);

        let bin = env!("CARGO_BIN_EXE_linhellod");
        let child = Command::new(bin)
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn linhellod");

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if socket.exists() {
                return Daemon { child, socket };
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        panic!("linhellod socket did not appear at {}", socket.display());
    }

    fn request(&self, req: &Request) -> Response {
        client::request_at(&self.socket, req, Duration::from_secs(3))
            .expect("ipc request")
    }

    /// Send a raw line over the socket and read one line back. Bypasses the
    /// typed client to test error paths on bad input.
    fn raw(&self, line: &[u8]) -> String {
        let mut s = UnixStream::connect(&self.socket).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(line).unwrap();
        s.flush().unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        buf
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn rand_suffix() -> u64 {
    // SystemTime-based uniqueness is fine for per-test sockets; no crypto need.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
        ^ (std::process::id() as u64)
}

#[test]
fn status_roundtrip() {
    let d = Daemon::spawn();
    match d.request(&Request::Status) {
        Response::Status { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn malformed_json_returns_error() {
    let d = Daemon::spawn();
    let got = d.raw(b"this is not json\n");
    assert!(
        got.contains("\"kind\":\"error\"") || got.contains("\"kind\": \"error\""),
        "expected error response, got: {got}"
    );
    assert!(got.contains("malformed request"), "missing reason: {got}");
}

#[test]
fn privileged_op_from_non_root_is_forbidden() {
    // This test process runs as the invoking user (uid != 0 during
    // `cargo test`). The daemon's peer_cred() check should reject Reseal,
    // SealPassword, Unseal, UnsealPassword, and Enroll.
    assert_ne!(
        unsafe { libc::getuid() },
        0,
        "this test is meaningless when run as root"
    );

    let d = Daemon::spawn();
    for req in [
        Request::Reseal,
        Request::Enroll {
            user: "nobody".into(),
            reset: false,
        },
        Request::Unseal {
            user: "nobody".into(),
        },
        Request::UnsealPassword {
            user: "nobody".into(),
        },
        Request::SealPassword {
            user: "nobody".into(),
            password: SecretBytes::new(vec![1, 2, 3]),
        },
    ] {
        match d.request(&req) {
            Response::Error { message } => {
                assert!(
                    message.contains("requires root"),
                    "expected root-gate error for {req:?}, got: {message}"
                );
            }
            other => panic!("privileged op {req:?} leaked through: {other:?}"),
        }
    }
}

#[test]
fn policy_status_returns_wire_shape() {
    // PolicyStatus for our own account (own uid) is permitted and reads no
    // hardware. Verify the wire shape and that every per-op row carries a
    // recognized action. (Unenrolled in the test env → Convenience tier, but we
    // assert structure, not the specific tier, to stay hardware-independent.)
    let user = match std::env::var("USER").or_else(|_| std::env::var("LOGNAME")) {
        Ok(u) if !u.is_empty() && u != "root" => u,
        _ => return, // can't determine a non-root username here; skip
    };
    let d = Daemon::spawn();
    match d.request(&Request::PolicyStatus { user }) {
        Response::PolicyStatus { ops, .. } => {
            assert_eq!(ops.len(), 5, "expected five operation rows, got {}", ops.len());
            assert!(
                ops.iter().any(|o| o.operation.contains("Screen unlock")),
                "missing the screen-unlock row"
            );
            for o in &ops {
                assert!(
                    matches!(o.action.as_str(), "verify" | "unseal" | "deny"),
                    "unexpected action {:?} for {:?}",
                    o.action,
                    o.operation
                );
                assert!(!o.effect.is_empty(), "empty effect for {:?}", o.operation);
            }
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn diagnose_returns_wire_shape() {
    // We don't control /etc/linhello state from a unit test, so just verify
    // the wire shape: Diagnose must return a `Diagnosed {..}` (never an
    // Error for normal state) regardless of whether an envelope exists.
    let d = Daemon::spawn();
    match d.request(&Request::Diagnose) {
        Response::Diagnosed { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}
