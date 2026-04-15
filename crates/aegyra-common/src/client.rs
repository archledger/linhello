//! Blocking client for the aegyra daemon socket.
//!
//! Used by both the CLI (from the user's session) and the PAM module (from
//! the PAM stack as root). One request per connection: the client sends a
//! newline-terminated JSON Request and reads a newline-terminated Response.

use crate::ipc::{Request, Response};
use crate::{AegyraError, Result, SOCKET_PATH};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve the daemon socket path, honouring `AEGYRA_SOCKET` for dev/test.
pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os("AEGYRA_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(SOCKET_PATH))
}

pub fn request(req: &Request) -> Result<Response> {
    request_at(&socket_path(), req, DEFAULT_TIMEOUT)
}

pub fn request_with_timeout(req: &Request, timeout: Duration) -> Result<Response> {
    request_at(Path::new(SOCKET_PATH), req, timeout)
}

pub fn request_at(path: &Path, req: &Request, timeout: Duration) -> Result<Response> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut line = serde_json::to_vec(req).map_err(|e| AegyraError::Serde(e.to_string()))?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    if buf.is_empty() {
        return Err(AegyraError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        )));
    }
    serde_json::from_str(&buf).map_err(|e| AegyraError::Serde(e.to_string()))
}
