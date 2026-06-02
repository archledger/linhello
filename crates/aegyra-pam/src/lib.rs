//! FFI bridge between the C PAM module and the Rust security core.
//!
//! The C caller provides a username and a stack buffer; we round-trip through
//! the aegyrad daemon to run face verification and unseal the TPM secret, then
//! write it into the buffer. Secrets never live on the Rust heap across the
//! boundary for longer than this call.

use aegyra_common::client;
use aegyra_common::ipc::{Request, Response, SecretBytes};
use std::ffi::CStr;
use std::slice;

/// Verify the named user and unseal the keyring secret into `buf`.
/// Returns bytes written, or -1 on error.
///
/// # Safety
/// `user` must be a NUL-terminated C string. `buf` must point to at least
/// `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn faceauth_unseal_keyring(
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
pub unsafe extern "C" fn faceauth_reseal_password(
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
pub unsafe extern "C" fn faceauth_zero_buf(buf: *mut u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    let s = slice::from_raw_parts_mut(buf, len);
    for b in s.iter_mut() {
        std::ptr::write_volatile(b, 0);
    }
}
