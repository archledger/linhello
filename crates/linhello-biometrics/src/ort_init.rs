//! One-time initialization of the ONNX Runtime library.
//!
//! We use the `load-dynamic` feature, so ORT is located at runtime from
//! `ORT_DYLIB_PATH` or, failing that, the first `libonnxruntime.so` found
//! across the known per-distro locations (see `linhello_common::platform`).

use crate::bio_err;
use linhello_common::Result;
use std::sync::OnceLock;

/// The outcome of the single init attempt. Stored (not just attempted once and
/// forgotten) so every later call reports the same actionable error instead of
/// a misleading `Ok` after a failed first init.
static INIT_RESULT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

pub fn ensure_initialized() -> Result<()> {
    let outcome = INIT_RESULT.get_or_init(|| {
        if std::env::var_os("ORT_DYLIB_PATH").is_none() {
            match linhello_common::platform::onnxruntime_dylib() {
                Some(path) => std::env::set_var("ORT_DYLIB_PATH", path),
                None => {
                    // Make the most common fresh-install failure actionable
                    // instead of a bare dlopen error — with this distro's
                    // package name / install command.
                    return Err(format!(
                        "libonnxruntime.so not found — {}",
                        linhello_common::platform::onnxruntime_install_hint()
                    ));
                }
            }
        }
        // ort rc.12: commit() returns bool (false = an environment was already
        // committed) and defers dylib loading to the first Session, so it can't
        // report a missing/broken libonnxruntime here. The dylib-presence probe
        // above keeps the common failure actionable; any genuine load error still
        // surfaces when a Session is built (callers map it there).
        ort::init().with_name("linhello").commit();
        Ok(())
    });
    outcome.clone().map_err(bio_err)
}
