//! Blocking client for the linhello daemon socket.
//!
//! Used by both the CLI (from the user's session) and the PAM module (from
//! the PAM stack as root). One request per connection: the client sends a
//! newline-terminated JSON Request and reads a newline-terminated Response.

use crate::ipc::{Request, Response};
use crate::{LinuxHelloError, Result, SOCKET_PATH};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve the daemon socket path, honouring `LINHELLO_SOCKET` for dev/test.
pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os("LINHELLO_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(SOCKET_PATH))
}

pub fn request(req: &Request) -> Result<Response> {
    request_at(&socket_path(), req, DEFAULT_TIMEOUT)
}

pub fn request_with_timeout(req: &Request, timeout: Duration) -> Result<Response> {
    request_at(&socket_path(), req, timeout)
}

/// Connect to the socket with a bounded wait. `UnixStream::connect` itself has
/// no timeout, so a stalled listener (backlog full, accept() stuck) would
/// otherwise hang the caller — e.g. freeze a login/sudo prompt — indefinitely.
/// We connect on a detached helper thread and give up after `timeout`.
fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(&p));
    });
    match rx.recv_timeout(timeout) {
        Ok(res) => res.map_err(LinuxHelloError::Io),
        Err(_) => Err(LinuxHelloError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out connecting to linhello daemon socket",
        ))),
    }
}

pub fn request_at(path: &Path, req: &Request, timeout: Duration) -> Result<Response> {
    let mut stream = connect_with_timeout(path, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    use zeroize::Zeroize;

    let mut line = serde_json::to_vec(req).map_err(|e| LinuxHelloError::Serde(e.to_string()))?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    // The request may carry a password (SealPassword); wipe the serialized form.
    line.zeroize();

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    if buf.is_empty() {
        return Err(LinuxHelloError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        )));
    }
    let parsed = serde_json::from_str(&buf).map_err(|e| LinuxHelloError::Serde(e.to_string()));
    // The response may carry an unsealed secret; wipe the raw JSON now that the
    // bytes live inside a zeroizing `SecretBytes` in the parsed value.
    buf.zeroize();
    parsed
}
