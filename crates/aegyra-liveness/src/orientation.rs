//! Head-orientation estimation from 5 facial landmarks.
//!
//! SCRFD's landmark order: [left_eye, right_eye, nose, left_mouth,
//! right_mouth]. We estimate yaw (horizontal turn) and pitch (vertical
//! tilt) from geometric ratios between nose position and eye/mouth
//! midpoints. These are approximate (no 3D model solve), but more than
//! adequate for a ±15° frontal-face gate.
//!
//! Convention: positive yaw = face turned to the CAMERA'S right (user's
//! left). Positive pitch = face tilted up.

/// Maximum angular deviation from frontal in any axis for a valid
/// authentication frame. WBF specifies ±15°.
pub const MAX_ANGLE_DEG: f32 = 15.0;

/// Approximate yaw and pitch (degrees) from 5 landmarks.
///
/// Returns `(yaw, pitch)` where 0,0 is perfectly frontal.
pub fn estimate_pose(lm: &[[f32; 2]; 5]) -> (f32, f32) {
    let [le, re, nose, lm_pt, rm_pt] = lm;

    // --- Yaw ---
    // Compare horizontal distance from nose to each eye. Frontal face
    // has roughly equal distances; turning moves the nose toward one eye.
    let d_left = (nose[0] - le[0]).abs();
    let d_right = (re[0] - nose[0]).abs();
    let denom_yaw = d_left + d_right;
    let yaw_ratio = if denom_yaw > 1.0 {
        (d_right - d_left) / denom_yaw
    } else {
        0.0
    };
    // Linear approximation: at 90° profile, one distance collapses to 0
    // → ratio = ±1.0. Map linearly: ratio ≈ sin(yaw) ≈ yaw for small
    // angles, and ratio ~0.5 at ~30° in practice. Scale factor ~60°
    // maps the usable range. Good enough inside ±30°; we only gate at 15.
    let yaw_deg = yaw_ratio * 60.0;

    // --- Pitch ---
    // Compare vertical distance nose→eye-center vs nose→mouth-center.
    // Looking up: nose moves toward eyes → nose_to_eyes shrinks.
    let eye_cy = (le[1] + re[1]) / 2.0;
    let mouth_cy = (lm_pt[1] + rm_pt[1]) / 2.0;
    let nose_to_eyes = nose[1] - eye_cy; // positive when nose is below eyes (normal)
    let nose_to_mouth = mouth_cy - nose[1]; // positive when mouth is below nose (normal)
    let denom_pitch = (nose_to_eyes.abs() + nose_to_mouth.abs()).max(1.0);
    let pitch_ratio = (nose_to_eyes - nose_to_mouth) / denom_pitch;
    let pitch_deg = pitch_ratio * 60.0;

    (yaw_deg, pitch_deg)
}

/// Check whether estimated yaw and pitch are both within `max_deg`.
pub fn is_frontal(yaw_deg: f32, pitch_deg: f32, max_deg: f32) -> bool {
    yaw_deg.abs() <= max_deg && pitch_deg.abs() <= max_deg
}

#[cfg(test)]
mod tests {
    use super::*;

    // ArcFace canonical template — perfectly frontal face at 112×112.
    const FRONTAL: [[f32; 2]; 5] = [
        [38.2946, 51.6963],
        [73.5318, 51.5014],
        [56.0252, 71.7366],
        [41.5493, 92.3655],
        [70.7299, 92.2041],
    ];

    #[test]
    fn frontal_is_near_zero() {
        let (yaw, pitch) = estimate_pose(&FRONTAL);
        assert!(yaw.abs() < 5.0, "yaw {yaw} should be near 0");
        assert!(pitch.abs() < 5.0, "pitch {pitch} should be near 0");
        assert!(is_frontal(yaw, pitch, MAX_ANGLE_DEG));
    }

    #[test]
    fn shifted_nose_gives_yaw() {
        let mut lm = FRONTAL;
        // Move nose 15px toward the left eye → simulates ~15-20° yaw.
        lm[2][0] -= 15.0;
        let (yaw, _) = estimate_pose(&lm);
        assert!(yaw.abs() > 10.0, "yaw {yaw} should be significant");
    }

    #[test]
    fn shifted_nose_gives_pitch() {
        let mut lm = FRONTAL;
        // Move nose 10px upward → simulates looking up.
        lm[2][1] -= 10.0;
        let (_, pitch) = estimate_pose(&lm);
        assert!(pitch < -5.0, "pitch {pitch} should be negative (looking up)");
    }
}
