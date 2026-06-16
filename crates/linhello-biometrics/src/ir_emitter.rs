//! Active-IR emitter activation for Windows-Hello-class UVC cameras.
//!
//! Many USB Windows-Hello camera modules (e.g. the NexiGo HelloCam N930W) pair a
//! greyscale NIR sensor with an 850nm illuminator that the Linux `uvcvideo`
//! driver does **not** drive: on Windows the camera's companion driver pulses
//! the emitter through a vendor UVC Extension Unit (XU) control, but on Linux
//! nothing issues that control, so the IR frames come back black and liveness
//! sees no IR signal at all.
//!
//! This module replays that XU `SET_CUR` write — the same mechanism as
//! `linux-enable-ir-emitter` — right after linhello opens its own IR stream, so
//! the emitter is lit for our capture burst. Doing it in-process (rather than
//! relying on an external one-shot service) means it survives a camera that
//! resets the control on each open, and keeps linhello self-contained.
//!
//! It is strictly best-effort: a camera that lacks the control, or any ioctl
//! error, is logged at debug and otherwise ignored — liveness then degrades to
//! RGB-only, exactly as it did before this existed.

use std::os::raw::c_int;

/// `UVC_SET_CUR` request code (UVC spec, 4.2).
const UVC_SET_CUR: u8 = 0x01;

/// `struct uvc_xu_control_query` from `linux/uvcvideo.h`.
#[repr(C)]
struct UvcXuControlQuery {
    unit: u8,
    selector: u8,
    query: u8,
    size: u16,
    data: *mut u8,
}

/// `UVCIOC_CTRL_QUERY` = `_IOWR('u', 0x21, struct uvc_xu_control_query)`.
/// Encoded with the kernel ioctl layout: dir(2) | size(14) | type(8) | nr(8).
const fn uvcioc_ctrl_query() -> libc::c_ulong {
    const DIR_RW: libc::c_ulong = 3; // _IOC_READ | _IOC_WRITE
    let size = core::mem::size_of::<UvcXuControlQuery>() as libc::c_ulong;
    (DIR_RW << 30) | (size << 16) | ((b'u' as libc::c_ulong) << 8) | 0x21
}

/// An XU control to apply: which unit/selector and the `SET_CUR` payload.
#[derive(Clone)]
struct EmitterControl {
    unit: u8,
    selector: u8,
    payload: Vec<u8>,
}

/// Built-in known-device table, matched on the V4L card name (substring).
/// Values must be verified on real hardware before being added here.
fn known_control(card: &str) -> Option<EmitterControl> {
    // NexiGo HelloCam N930W: XU unit 4 / selector 6, byte[2] = 2 lights the
    // emitter (1 = default/off, 3 = off). Verified on-hardware 2026-06-16
    // (Fedora 44): raw GREY frame mean 0.04 -> 25.8 once applied.
    if card.contains("N930W") {
        return Some(EmitterControl {
            unit: 4,
            selector: 6,
            payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0],
        });
    }
    None
}

/// Parse `LINHELLO_IR_EMITTER` = `unit:selector:b,b,b,...` (each byte decimal or
/// `0x`-hex), an explicit override for any camera. Returns `None` if unset/empty.
fn env_control() -> Option<EmitterControl> {
    let raw = std::env::var("LINHELLO_IR_EMITTER").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut parts = raw.split(':');
    let unit = parse_u8(parts.next()?)?;
    let selector = parse_u8(parts.next()?)?;
    let payload: Vec<u8> = parts
        .next()?
        .split(',')
        .filter_map(|b| parse_u8(b))
        .collect();
    if payload.is_empty() {
        return None;
    }
    Some(EmitterControl {
        unit,
        selector,
        payload,
    })
}

fn parse_u8(s: &str) -> Option<u8> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Light the active-IR emitter on the already-open device `fd` for the camera
/// named `card`, if we have a control for it. Best-effort — errors are logged at
/// debug and otherwise ignored.
///
/// Precedence: `LINHELLO_IR_EMITTER=off` (or `none`) disables activation; an
/// explicit `LINHELLO_IR_EMITTER=unit:sel:bytes` overrides; otherwise the
/// built-in [`known_control`] table is consulted by card name.
pub fn enable(fd: c_int, card: &str) {
    match std::env::var("LINHELLO_IR_EMITTER").ok().as_deref().map(str::trim) {
        Some("off") | Some("none") => return,
        _ => {}
    }

    let Some(ctrl) = env_control().or_else(|| known_control(card)) else {
        tracing::debug!(card, "no active-IR emitter control known for this camera; leaving emitter untouched");
        return;
    };

    // `data` is borrowed mutably by the kernel for the duration of the ioctl.
    let mut payload = ctrl.payload.clone();
    let mut query = UvcXuControlQuery {
        unit: ctrl.unit,
        selector: ctrl.selector,
        query: UVC_SET_CUR,
        size: payload.len() as u16,
        data: payload.as_mut_ptr(),
    };

    // SAFETY: `fd` is a valid open V4L2/UVC device fd owned by the caller for the
    // duration of this call; `query` and its `data` buffer outlive the ioctl.
    let rc = unsafe {
        libc::ioctl(
            fd,
            uvcioc_ctrl_query(),
            &mut query as *mut UvcXuControlQuery,
        )
    };

    if rc < 0 {
        tracing::debug!(
            card,
            unit = ctrl.unit,
            selector = ctrl.selector,
            err = %std::io::Error::last_os_error(),
            "active-IR emitter XU SET_CUR failed (camera may not need it); IR liveness may be unavailable"
        );
    } else {
        tracing::debug!(
            card,
            unit = ctrl.unit,
            selector = ctrl.selector,
            "active-IR emitter enabled via UVC extension-unit control"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_number_matches_uvcioc_ctrl_query() {
        // _IOWR('u', 0x21, struct uvc_xu_control_query) with a 16-byte struct
        // on LP64 == 0xC0107521.
        assert_eq!(core::mem::size_of::<UvcXuControlQuery>(), 16);
        assert_eq!(uvcioc_ctrl_query(), 0xC010_7521);
    }

    #[test]
    fn known_n930w_control() {
        let c = known_control("NexiGo HelloCam N930W Camera: N").expect("N930W known");
        assert_eq!((c.unit, c.selector), (4, 6));
        assert_eq!(c.payload, vec![1, 3, 2, 0, 0, 0, 0, 0, 0]);
        assert!(known_control("Integrated Camera").is_none());
    }

    #[test]
    fn parse_u8_decimal_and_hex() {
        assert_eq!(parse_u8("2"), Some(2));
        assert_eq!(parse_u8("0x0a"), Some(10));
        assert_eq!(parse_u8(" 255 "), Some(255));
        assert_eq!(parse_u8("256"), None);
    }
}
