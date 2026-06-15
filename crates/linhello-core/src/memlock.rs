//! Memory-protection helpers: mlock + MADV_DONTDUMP on a buffer so the
//! plaintext secret cannot be swapped to disk or included in a core dump.
//!
//! Failures here are reported but not fatal: on systems that disallow mlock
//! for the calling user we still want auth to work. Callers should also rely
//! on `Zeroizing` for post-use scrubbing.

use linhello_common::Result;

pub fn lock_slice(buf: &[u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let ptr = buf.as_ptr() as *mut libc::c_void;
    let len = buf.len();
    unsafe {
        // Best-effort; RLIMIT_MEMLOCK may reject allocations for unprivileged
        // users. Surface failures at warn level (not debug): when this fails the
        // plaintext secret can be paged to swap or land in a core dump, which
        // the caller's API contract otherwise implies cannot happen.
        if libc::mlock(ptr, len) != 0 {
            tracing::warn!(
                "mlock failed ({}); secret may be swappable — raise RLIMIT_MEMLOCK",
                std::io::Error::last_os_error()
            );
        }
        if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
            tracing::warn!(
                "madvise DONTDUMP failed ({}); secret may appear in core dumps",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}
