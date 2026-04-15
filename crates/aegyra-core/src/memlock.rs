//! Memory-protection helpers: mlock + MADV_DONTDUMP on a buffer so the
//! plaintext secret cannot be swapped to disk or included in a core dump.
//!
//! Failures here are reported but not fatal: on systems that disallow mlock
//! for the calling user we still want auth to work. Callers should also rely
//! on `Zeroizing` for post-use scrubbing.

use aegyra_common::Result;

pub fn lock_slice(buf: &[u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let ptr = buf.as_ptr() as *mut libc::c_void;
    let len = buf.len();
    unsafe {
        // Best-effort; RLIMIT_MEMLOCK may reject small allocations for unprivileged users.
        if libc::mlock(ptr, len) != 0 {
            tracing::debug!("mlock failed: {}", std::io::Error::last_os_error());
        }
        if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
            tracing::debug!("madvise DONTDUMP failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}
