//! One-time initialization of the ONNX Runtime library.
//!
//! We use the `load-dynamic` feature, so ORT is located at runtime from
//! `ORT_DYLIB_PATH` or, failing that, the first `libonnxruntime.so` found
//! across the known per-distro locations (see `linhello_common::platform`).

use crate::bio_err;
use linhello_common::Result;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn ensure_initialized() -> Result<()> {
    let mut err: Option<String> = None;
    INIT.call_once(|| {
        if std::env::var_os("ORT_DYLIB_PATH").is_none() {
            if let Some(path) = linhello_common::platform::onnxruntime_dylib() {
                std::env::set_var("ORT_DYLIB_PATH", path);
            }
        }
        if let Err(e) = ort::init().with_name("linhello").commit() {
            err = Some(format!("ort init: {e}"));
        }
    });
    if let Some(e) = err {
        return Err(bio_err(e));
    }
    Ok(())
}
