//! FFI bridge between the C PAM module and the Rust security core.
//!
//! The C caller provides a username and a stack buffer; we round-trip through
//! the linhellod daemon to run face verification and unseal the TPM secret, then
//! write it into the buffer. Secrets never live on the Rust heap across the
//! boundary for longer than this call.

use linhello_common::client;
use linhello_common::ipc::{Request, Response, SecretBytes};
use std::ffi::CStr;
use std::slice;

/// Verify the named user and unseal the keyring secret into `buf`.
/// Returns bytes written, or -1 on error.
///
/// # Safety
/// `user` must be a NUL-terminated C string. `buf` must point to at least
/// `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn linhello_unseal_keyring(
    user: *const libc::c_char,
    buf: *mut u8,
    len: usize,
) -> i32 {
    if user.is_null() || buf.is_null() || len == 0 {
        return -1;
    }
    let user = match CStr::from_ptr(user).to_str() {
        Ok(s) if !s.is_empty() => s.to_owned(),
        _ => return -1,
    };
    let dst = slice::from_raw_parts_mut(buf, len);

    match client::request(&Request::UnsealPassword { user }) {
        Ok(Response::PasswordUnsealed { secret }) => {
            let bytes = secret.expose();
            if bytes.len() > dst.len() {
                return -1;
            }
            dst[..bytes.len()].copy_from_slice(bytes);
            bytes.len() as i32
            // `secret` (SecretBytes) is wiped on drop at end of scope.
        }
        _ => -1,
    }
}

/// Verify the named user's face WITHOUT unsealing any secret. Returns 0 on a
/// liveness-gated match, -1 otherwise.
///
/// This is the unprivileged auth path. The daemon only releases the sealed
/// password to a root peer, but `Verify` is allowed for a caller asking about
/// its own uid — exactly the KDE lockscreen situation: kscreenlocker runs PAM
/// as the session user, and an in-session unlock needs no PAM_AUTHTOK (the
/// wallet/keyring is already open). Verify runs the same capture + liveness +
/// match pipeline as the unseal path; only the password release differs.
///
/// # Safety
/// `user` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn linhello_verify_face(user: *const libc::c_char) -> i32 {
    if user.is_null() {
        return -1;
    }
    let user = match CStr::from_ptr(user).to_str() {
        Ok(s) if !s.is_empty() => s.to_owned(),
        _ => return -1,
    };
    match client::request(&Request::Verify { user }) {
        Ok(Response::Verified { matched: true, .. }) => 0,
        _ => -1,
    }
}

/// Tiered-policy authentication (the entry point pam_linhello uses). Sends the
/// PAM service name so the daemon can classify the operation, look up the
/// hardware tier + warm-session state, and decide. Returns:
///   * `n > 0` — unseal: `n` secret bytes written to `buf`; caller sets
///               PAM_AUTHTOK (login / keyring unlock).
///   * `0`     — verify: a liveness-gated match with **no** secret released;
///               caller returns PAM_SUCCESS without AUTHTOK (live-session unlock).
///   * `-1`    — denied or error; caller cascades to the password.
///
/// # Safety
/// `user` and `service` must be NUL-terminated C strings. `buf` must point to at
/// least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn linhello_authenticate(
    user: *const libc::c_char,
    service: *const libc::c_char,
    buf: *mut u8,
    len: usize,
) -> i32 {
    if user.is_null() || service.is_null() || buf.is_null() || len == 0 {
        return -1;
    }
    let user = match CStr::from_ptr(user).to_str() {
        Ok(s) if !s.is_empty() => s.to_owned(),
        _ => return -1,
    };
    let service = match CStr::from_ptr(service).to_str() {
        Ok(s) => s.to_owned(),
        _ => return -1,
    };
    let dst = slice::from_raw_parts_mut(buf, len);
    match client::request(&Request::Authenticate { user, service }) {
        Ok(Response::PasswordUnsealed { secret }) => {
            let bytes = secret.expose();
            if bytes.len() > dst.len() {
                return -1;
            }
            dst[..bytes.len()].copy_from_slice(bytes);
            bytes.len() as i32
        }
        Ok(Response::Verified { matched: true, .. }) => 0,
        _ => -1,
    }
}

/// Pre-flight for [`linhello_authenticate`]: ask the daemon whether this
/// (user, service) will actually engage the camera, WITHOUT capturing. Lets the
/// PAM module decide whether to announce "Looking for your face…". Returns:
///   * `1`  — the camera will engage (Verify or Unseal); show the prompt.
///   * `0`  — policy deny (e.g. convenience-tier greeter login / sudo): no camera
///            will light up; stay silent and cascade to the password.
///   * `-1` — daemon unreachable or error; treat as "no capture" (stay silent).
///
/// When the camera would engage but is currently unusable (hardware privacy
/// switch on, or no camera detected), a short user-facing reason is written into
/// `msg` (NUL-terminated, truncated to `msg_len`) so the PAM module can show it at
/// the greeter instead of "Looking for your face…". `msg[0]` is set to `\0` first,
/// so an empty string means "camera ready, no notice". `msg` may be null.
///
/// # Safety
/// `user` and `service` must be NUL-terminated C strings. `msg`, if non-null, must
/// point to at least `msg_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn linhello_auth_will_capture(
    user: *const libc::c_char,
    service: *const libc::c_char,
    msg: *mut u8,
    msg_len: usize,
) -> i32 {
    // Start with an empty notice so the caller never reads stale stack bytes.
    if !msg.is_null() && msg_len > 0 {
        *msg = 0;
    }
    if user.is_null() || service.is_null() {
        return -1;
    }
    let user = match CStr::from_ptr(user).to_str() {
        Ok(s) if !s.is_empty() => s.to_owned(),
        _ => return -1,
    };
    let service = match CStr::from_ptr(service).to_str() {
        Ok(s) => s.to_owned(),
        _ => return -1,
    };
    match client::request(&Request::AuthIntent { user, service }) {
        Ok(Response::AuthPlan { engage, camera_notice, .. }) => {
            if let Some(notice) = camera_notice {
                write_cstr(msg, msg_len, &notice);
            }
            if engage {
                1
            } else {
                0
            }
        }
        _ => -1,
    }
}

/// Write `s` into a C buffer as a NUL-terminated string, truncated to fit. No-op
/// if `dst` is null or `dst_len` is 0.
///
/// # Safety
/// `dst`, if non-null, must point to at least `dst_len` writable bytes.
unsafe fn write_cstr(dst: *mut u8, dst_len: usize, s: &str) {
    if dst.is_null() || dst_len == 0 {
        return;
    }
    let buf = slice::from_raw_parts_mut(dst, dst_len);
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst_len - 1);
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
}

/// Reseal `password` as the user's login password envelope. Called from the
/// PAM `password` stack after the new token has been accepted by the upstream
/// module, so the face-auth path stays in lockstep with the real password.
///
/// Returns 0 on success, -1 on error. The input buffer is zeroed before
/// return regardless of outcome.
///
/// # Safety
/// `user` must be a NUL-terminated C string. `password` must point to `len`
/// readable (and writable, for zeroing) bytes.
#[no_mangle]
pub unsafe extern "C" fn linhello_reseal_password(
    user: *const libc::c_char,
    password: *mut u8,
    len: usize,
) -> i32 {
    if user.is_null() || password.is_null() || len == 0 {
        return -1;
    }
    let user_str = match CStr::from_ptr(user).to_str() {
        Ok(s) if !s.is_empty() => s.to_owned(),
        _ => return -1,
    };

    // Copy into an owned Vec that will be zeroized on drop, then zero the
    // caller's buffer immediately so the plaintext never lingers at two sites.
    let src = slice::from_raw_parts_mut(password, len);
    let pw = SecretBytes::new(src.to_vec());
    for b in src.iter_mut() {
        std::ptr::write_volatile(b, 0);
    }

    match client::request(&Request::SealPassword {
        user: user_str,
        password: pw,
    }) {
        Ok(Response::PasswordSealed) => 0,
        _ => -1,
    }
}

/// Zero a caller-provided buffer.
///
/// # Safety
/// `buf` must point to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn linhello_zero_buf(buf: *mut u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    let s = slice::from_raw_parts_mut(buf, len);
    for b in s.iter_mut() {
        std::ptr::write_volatile(b, 0);
    }
}
