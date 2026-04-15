//! One-time initialization of the ONNX Runtime library.
//!
//! We use the `load-dynamic` feature, so ORT is located at runtime from
//! `ORT_DYLIB_PATH` or a sensible Linux default (`/usr/lib/libonnxruntime.so`).

use crate::bio_err;
use aegyra_common::Result;
use std::sync::Once;

static INIT: Once = Once::new();
static DEFAULT_DYLIB: &str = "/usr/lib/libonnxruntime.so";

pub fn ensure_initialized() -> Result<()> {
    let mut err: Option<String> = None;
    INIT.call_once(|| {
        if std::env::var_os("ORT_DYLIB_PATH").is_none()
            && std::path::Path::new(DEFAULT_DYLIB).exists()
        {
            std::env::set_var("ORT_DYLIB_PATH", DEFAULT_DYLIB);
        }
        if let Err(e) = ort::init().with_name("aegyra").commit() {
            err = Some(format!("ort init: {e}"));
        }
    });
    if let Some(e) = err {
        return Err(bio_err(e));
    }
    Ok(())
}
