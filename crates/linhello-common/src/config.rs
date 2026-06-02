//! Tiny `key=value` config files under [`CONFIG_ROOT`](crate::CONFIG_ROOT)
//! (e.g. `cameras.conf`, `settings.conf`). Blank lines and `#` comments are
//! ignored. These hold operator-tunable knobs the `linhello setup` wizard
//! writes and the daemon reads — secrets never live here (those are sealed
//! envelopes elsewhere).

use crate::{Result, CONFIG_ROOT};
use std::path::PathBuf;

/// Absolute path to a config file under `CONFIG_ROOT`.
pub fn config_path(file: &str) -> PathBuf {
    std::path::Path::new(CONFIG_ROOT).join(file)
}

/// Read a single key from a `key=value` file under `CONFIG_ROOT`. Returns the
/// trimmed value, or `None` if the file is missing, the key is absent, or the
/// value is empty.
pub fn read_kv(file: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(config_path(file)).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Insert or update `key=value` in a `key=value` file under `CONFIG_ROOT`,
/// preserving every other line (including comments). Creates the file at mode
/// 0600 if absent. The parent `CONFIG_ROOT` directory must already exist.
pub fn write_kv(file: &str, key: &str, val: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = config_path(file);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        let is_target = !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == key);
        if is_target {
            if !replaced {
                out.push_str(&format!("{key}={val}\n"));
                replaced = true;
            }
            // Drop any duplicate keys.
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        out.push_str(&format!("{key}={val}\n"));
    }

    std::fs::write(&path, out)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kv_with_comments_and_blanks() {
        let txt = "# header\n\n  rgb = /dev/video1 \nir=/dev/video3\n# trailing\n";
        let dir = std::env::temp_dir().join(format!("lh-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("cameras.conf");
        std::fs::write(&f, txt).unwrap();
        // exercise the parser directly (read_kv hardcodes CONFIG_ROOT, so test
        // the pure logic via a temp file read here).
        let read = |key: &str| -> Option<String> {
            let text = std::fs::read_to_string(&f).ok()?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    if k.trim() == key {
                        let v = v.trim();
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
            None
        };
        assert_eq!(read("rgb").as_deref(), Some("/dev/video1"));
        assert_eq!(read("ir").as_deref(), Some("/dev/video3"));
        assert_eq!(read("missing"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
