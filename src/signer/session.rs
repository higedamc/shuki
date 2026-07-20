//! Device login-session marker (owned by `leaf/nsd-session-auth`).
//!
//! After a successful NSD login challenge, `<data_dir>/.device_session`
//! records *who* confirmed and *when*:
//! `{ "npub": "<bech32>", "authed_at": <unix secs> }`.
//!
//! The marker contains **no secret material** — it is only the identity's
//! public npub plus a timestamp. Deleting or corrupting it can never leak
//! anything; it merely forces the next invocation to re-confirm on the
//! device. The file is still written `0600` (atomic tmp + rename) to match
//! the rest of the data dir.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShukiError};

/// Marker file name inside the data dir.
const SESSION_FILE: &str = ".device_session";
/// Temp file used while atomically replacing the marker.
const SESSION_TMP: &str = ".tmp-device_session";
/// Tolerated forward clock skew: a marker stamped further in the future
/// than this is treated as invalid (clock rollback / tampering).
const MAX_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Serialize, Deserialize)]
struct SessionMarker {
    npub: String,
    authed_at: u64,
}

/// Current unix time in seconds (0 if the clock is before the epoch).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a still-live login session exists for `npub`.
///
/// Never errors or panics — any of the following simply yields `false`
/// (i.e. "re-confirm on the device"): missing or corrupt marker file,
/// npub mismatch, expiry (`now >= authed_at + timeout_secs`), a zero
/// timeout, or a marker stamped in the future beyond the skew tolerance.
pub fn is_valid(data_dir: &Path, npub: &str, timeout_secs: u64) -> bool {
    if timeout_secs == 0 {
        return false;
    }
    let bytes = match fs::read(data_dir.join(SESSION_FILE)) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let marker: SessionMarker = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if marker.npub != npub {
        return false;
    }
    let now = unix_now();
    if marker.authed_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return false;
    }
    now < marker.authed_at.saturating_add(timeout_secs)
}

/// Record a fresh login session for `npub` (stamped "now").
///
/// Atomic write (tmp + rename), `0600` on unix; the data dir is created if
/// missing.
pub fn record(data_dir: &Path, npub: &str) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let marker = SessionMarker {
        npub: npub.to_owned(),
        authed_at: unix_now(),
    };
    let json = serde_json::to_vec(&marker)
        .map_err(|e| ShukiError::Other(format!("serialize device session: {e}")))?;
    atomic_write(
        &data_dir.join(SESSION_TMP),
        &data_dir.join(SESSION_FILE),
        &json,
    )
}

/// Remove the session marker. Idempotent: a missing marker is `Ok`.
pub fn clear(data_dir: &Path) -> Result<()> {
    match fs::remove_file(data_dir.join(SESSION_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Atomic write: tmp file created `0600` on unix, fsync, rename over the
/// target. Local mirror of the store's atomic-write pattern (the store's
/// internals are deliberately not exported).
fn atomic_write(tmp: &Path, target: &Path, contents: &[u8]) -> Result<()> {
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(tmp)?;
        // If the tmp file already existed (leftover from a crash),
        // OpenOptions `mode` does not apply; re-assert 0600 explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(tmp, target) {
        // Best effort: do not leave the tmp file behind on failure.
        let _ = fs::remove_file(tmp);
        return Err(e.into());
    }
    // Best effort: persist the rename itself by fsyncing the directory.
    #[cfg(unix)]
    if let Some(dir) = target.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPUB: &str = "npub1zvxkq3jwv2yfxwv7t2z0tuuq6a0kdyv2mfmev6t9zjmalphzu6dq7q35xk";

    /// Write a marker with an arbitrary `authed_at` (bypasses `record`).
    fn write_marker(dir: &Path, npub: &str, authed_at: u64) {
        let json = serde_json::to_vec(&SessionMarker {
            npub: npub.to_owned(),
            authed_at,
        })
        .unwrap();
        fs::write(dir.join(SESSION_FILE), json).unwrap();
    }

    #[test]
    fn fresh_record_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), NPUB).unwrap();
        assert!(is_valid(dir.path(), NPUB, 900));
        // No tmp file left behind.
        assert!(!dir.path().join(SESSION_TMP).exists());
    }

    #[test]
    fn missing_file_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_valid(dir.path(), NPUB, 900));
    }

    #[test]
    fn expired_session_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path(), NPUB, unix_now().saturating_sub(901));
        assert!(!is_valid(dir.path(), NPUB, 900));
        // …but a longer timeout would still cover it.
        assert!(is_valid(dir.path(), NPUB, 3600));
    }

    #[test]
    fn different_npub_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), NPUB).unwrap();
        assert!(!is_valid(dir.path(), "npub1other", 900));
    }

    #[test]
    fn corrupt_json_is_invalid_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(SESSION_FILE), b"{ not json").unwrap();
        assert!(!is_valid(dir.path(), NPUB, 900));
        // Wrong shape (valid JSON, missing fields) is invalid too.
        fs::write(dir.path().join(SESSION_FILE), b"{\"npub\":1}").unwrap();
        assert!(!is_valid(dir.path(), NPUB, 900));
    }

    #[test]
    fn zero_timeout_is_always_invalid() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), NPUB).unwrap();
        assert!(!is_valid(dir.path(), NPUB, 0));
    }

    #[test]
    fn future_timestamp_beyond_skew_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path(), NPUB, unix_now() + MAX_CLOCK_SKEW_SECS + 10);
        assert!(!is_valid(dir.path(), NPUB, 900));
        // Small skew inside the tolerance is accepted.
        write_marker(dir.path(), NPUB, unix_now() + 5);
        assert!(is_valid(dir.path(), NPUB, 900));
    }

    #[cfg(unix)]
    #[test]
    fn marker_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), NPUB).unwrap();
        let mode = fs::metadata(dir.path().join(SESSION_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "session marker must be 0600");
    }

    #[test]
    fn clear_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        // Clearing a non-existent marker is fine…
        clear(dir.path()).unwrap();
        record(dir.path(), NPUB).unwrap();
        clear(dir.path()).unwrap();
        assert!(!is_valid(dir.path(), NPUB, 900));
        // …and clearing twice is fine too.
        clear(dir.path()).unwrap();
    }

    #[test]
    fn record_creates_data_dir_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub").join("data");
        record(&nested, NPUB).unwrap();
        assert!(is_valid(&nested, NPUB, 900));
        // Re-recording (existing target) works via the atomic path.
        record(&nested, NPUB).unwrap();
        assert!(is_valid(&nested, NPUB, 900));
    }
}
