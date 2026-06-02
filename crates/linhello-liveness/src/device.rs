//! V4L device trust heuristic.
//!
//! Reads `/sys/class/video4linux/<node>/name` and `.../device/driver` to
//! recognise virtual cameras (v4l2loopback, OBS Virtual Cam, snd-aloop,
//! etc). We score:
//!
//!   1.0 — driver looks like a real USB/PCI webcam (uvcvideo, ipu3-cio2,
//!         intel_ipu6, pwc, gspca_*, v4l2_pci)
//!   0.0 — driver or name screams virtual (v4l2loopback, obs, fakewebcam)
//!   0.5 — anything else (future kernel driver we don't recognise yet —
//!         don't fail-closed on a benign unknown)
//!
//! This is a heuristic, not cryptographic proof — a determined attacker with
//! root can of course fake sysfs. Its purpose is to stop the commodity attack
//! path: `modprobe v4l2loopback; ffmpeg -re -i face.mp4 -f v4l2 /dev/video9`.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DeviceTrust {
    pub score: f32,
    pub name: Option<String>,
    pub driver: Option<String>,
}

const VIRTUAL_DRIVERS: &[&str] = &["v4l2 loopback", "v4l2loopback"];
const VIRTUAL_NAME_FRAGMENTS: &[&str] = &[
    "v4l2loopback",
    "obs virtual",
    "obs-camera",
    "dummy",
    "fakewebcam",
    "virtual camera",
    "virtualcam",
];
const REAL_DRIVERS: &[&str] = &[
    "uvcvideo", "ipu3-cio2", "intel_ipu6", "ipu6", "pwc", "v4l2 pci", "v4l2_pci",
];

pub fn validate_camera_device(device_path: &str) -> DeviceTrust {
    let node = Path::new(device_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if node.is_empty() {
        return DeviceTrust {
            score: 0.5,
            name: None,
            driver: None,
        };
    }

    let sys_base = Path::new("/sys/class/video4linux").join(node);
    let name = read_trim(&sys_base.join("name"));
    let driver = read_driver(&sys_base);

    let drv_lc = driver.as_deref().unwrap_or("").to_ascii_lowercase();
    let name_lc = name.as_deref().unwrap_or("").to_ascii_lowercase();

    let is_virtual = VIRTUAL_DRIVERS.iter().any(|v| drv_lc.contains(v))
        || VIRTUAL_NAME_FRAGMENTS.iter().any(|v| name_lc.contains(v));
    if is_virtual {
        return DeviceTrust { score: 0.0, name, driver };
    }

    let is_real = REAL_DRIVERS.iter().any(|v| drv_lc.contains(v));
    let score = if is_real { 1.0 } else { 0.5 };
    DeviceTrust { score, name, driver }
}

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// `/sys/class/video4linux/<node>/device/driver` is a symlink whose target's
/// basename is the driver name (e.g. `uvcvideo`).
fn read_driver(base: &Path) -> Option<String> {
    let link = base.join("device").join("driver");
    fs::read_link(&link)
        .ok()
        .and_then(|t| t.file_name().map(|s| s.to_string_lossy().into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_uncertain() {
        let t = validate_camera_device("");
        assert_eq!(t.score, 0.5);
    }
}
