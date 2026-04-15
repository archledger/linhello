//! FFI bridge between the C PAM module and the Rust security core.
//!
//! The C caller provides a username and a stack buffer; we round-trip through
//! the aegyrad daemon to run face verification and unseal the TPM secret, then
//! write it into the buffer. Secrets never live on the Rust heap across the
//! boundary for longer than this call.

use aegyra_common::client;
use aegyra_common::ipc::{Request, Response};
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

    match client::request(&Request::Unseal { user }) {
        Ok(Response::Unsealed { secret }) => {
            if secret.len() > dst.len() {
                return -1;
            }
            dst[..secret.len()].copy_from_slice(&secret);
            secret.len() as i32
        }
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
