//! Camera device identity for soft-SDCP binding.
//!
//! At enrollment we snapshot the USB identity (VID, PID, serial) of the
//! cameras that produced the frames. At verify we re-read sysfs and
//! reject if any of these changed — a sign that the original camera was
//! swapped for a rogue device feeding pre-recorded frames.
//!
//! This is NOT cryptographic device attestation (real SDCP uses a
//! per-chip certificate + challenge-response). It raises the bar: an
//! attacker must either modify sysfs (requires root) or present a USB
//! device with the exact same descriptor tuple.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub name: String,
}

impl DeviceIdentity {
    /// Read identity for a v4l device (e.g. `/dev/video0`) by walking
    /// its sysfs ancestry up to the USB device node.
    pub fn from_device(device_path: &str) -> Option<Self> {
        // Windows-Hello shared-USB cameras (e.g. NexiGo N930W) briefly USB-reset
        // when their IR stream opens, transiently removing the sysfs node. A
        // single failed read must NOT be read as "camera gone" (it would fail
        // the binding check and decline auth), so retry a few times to ride out
        // a re-enumeration before concluding the device is genuinely absent.
        for attempt in 0..6 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if let Some(id) = Self::probe(device_path) {
                return Some(id);
            }
        }
        None
    }

    fn probe(device_path: &str) -> Option<Self> {
        // Resolve symlinks (e.g. /dev/v4l/by-path/… or by-id/…) to the real
        // /dev/videoN node so the sysfs lookup below uses the kernel node name.
        // Stable by-path nodes are how cameras.conf survives boot renumbering;
        // without this the basename would be the symlink name (no sysfs entry)
        // and binding would wrongly fail. Falls back to the path as given.
        let real = std::fs::canonicalize(device_path).unwrap_or_else(|_| PathBuf::from(device_path));
        let node = real.file_name()?.to_str()?;
        let sys = Path::new("/sys/class/video4linux").join(node);
        let name = read_trim(&sys.join("name"))?;

        let real = std::fs::canonicalize(sys.join("device")).ok()?;
        let mut p = real.as_path();
        loop {
            let vid_path = p.join("idVendor");
            if vid_path.exists() {
                let vid = read_trim(&vid_path)?;
                let pid = read_trim(&p.join("idProduct"))?;
                let serial = read_trim(&p.join("serial")).unwrap_or_default();
                return Some(DeviceIdentity { vid, pid, serial, name });
            }
            p = p.parent()?;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraBinding {
    pub rgb: DeviceIdentity,
    pub ir: Option<DeviceIdentity>,
}

impl CameraBinding {
    /// Check whether `current` matches `self`. Returns `Ok(())` on match,
    /// `Err(reason)` describing which field diverged.
    pub fn verify(&self, current: &CameraBinding) -> Result<(), String> {
        check_device("RGB", &self.rgb, &current.rgb)?;
        match (&self.ir, &current.ir) {
            (Some(enrolled), Some(current_ir)) => check_device("IR", enrolled, current_ir),
            (Some(_), None) => Err("IR camera was present at enrollment but is now missing".into()),
            // IR absent at enroll, present now — OK (upgrade, not attack)
            _ => Ok(()),
        }
    }
}

fn check_device(label: &str, enrolled: &DeviceIdentity, current: &DeviceIdentity) -> Result<(), String> {
    if enrolled.vid != current.vid {
        return Err(format!("{label} camera VID changed: enrolled {}, now {}", enrolled.vid, current.vid));
    }
    if enrolled.pid != current.pid {
        return Err(format!("{label} camera PID changed: enrolled {}, now {}", enrolled.pid, current.pid));
    }
    if !enrolled.serial.is_empty() && enrolled.serial != current.serial {
        return Err(format!("{label} camera serial changed: enrolled {}, now {}", enrolled.serial, current.serial));
    }
    Ok(())
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}
