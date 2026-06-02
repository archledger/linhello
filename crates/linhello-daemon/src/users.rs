//! Minimal, thread-safe passwd/group lookups via libc reentrant calls.
//!
//! Used to (a) resolve the `linhello` group so the socket can be `0660 root:linhello`
//! instead of world-writable, and (b) map a connecting peer's uid to the
//! username it is allowed to operate on (so an unprivileged caller can only
//! act on its own account). `getpwnam`/`getgrnam` use a shared static buffer
//! and are not safe under the daemon's concurrent request handling, so we use
//! the `_r` variants with a caller-owned buffer.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

/// Resolve a username to its uid. Returns `None` if the user does not exist
/// or the name can't be represented as a C string.
pub fn uid_for_name(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; `buf` is
    // sized and owned here; `result` is set to point into `pwd` on success.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

/// Resolve a group name to its gid. Returns `None` if absent.
pub fn gid_for_group(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: see `uid_for_name`.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

/// `chown` a path, leaving uid/gid unchanged where `None`. Returns the OS
/// error on failure.
pub fn chown(path: &std::path::Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let uid = uid.unwrap_or(u32::MAX); // (uid_t)-1 == "no change"
    let gid = gid.unwrap_or(u32::MAX);
    // SAFETY: `cpath` is a valid NUL-terminated string for the call's duration.
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// True if `peer_uid` is allowed to act on `user`: root may act on anyone;
/// any other uid may only act on the account that owns that uid; an unknown
/// peer (no SO_PEERCRED) may act on no one.
pub fn peer_may_act_as(peer_uid: Option<u32>, user: &str) -> bool {
    match peer_uid {
        Some(0) => true,
        Some(uid) => uid_for_name(user) == Some(uid),
        None => false,
    }
}
