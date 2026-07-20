//! sync_state.json read/write helpers (owned by `leaf/store-fs-files`).
//!
//! Holds the (de)serialization for [`SyncState`] plus the shared atomic-write
//! primitive (tmp file created 0600 + fsync + rename) used by the whole
//! filesystem store.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::error::{Result, ShukiError};

use super::SyncState;

/// File name of the sync-state file inside the store root.
pub(crate) const SYNC_STATE_FILE: &str = "sync_state.json";
/// Temp file name used while atomically replacing `sync_state.json`.
const SYNC_STATE_TMP: &str = ".tmp-sync_state.json";

/// Atomically write `contents` to `target`: write to `tmp` (created with mode
/// 0600 on unix), fsync, then rename over `target`. `tmp` and `target` must be
/// on the same filesystem (they share a parent directory here).
pub(crate) fn atomic_write(tmp: &Path, target: &Path, contents: &[u8]) -> Result<()> {
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(tmp)?;
        // If the tmp file already existed (leftover from a crash), OpenOptions
        // `mode` does not apply; re-assert 0600 explicitly.
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

/// Load `<root>/sync_state.json`. Missing file → `Ok(SyncState::default())`;
/// unreadable JSON → [`ShukiError::Corrupt`].
pub(crate) fn load(root: &Path) -> Result<SyncState> {
    let path = root.join(SYNC_STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SyncState::default()),
        Err(e) => return Err(e.into()),
    };
    serde_json::from_slice(&bytes).map_err(|e| ShukiError::Corrupt(format!("sync_state.json: {e}")))
}

/// Atomically save `<root>/sync_state.json` (0600).
pub(crate) fn save(root: &Path, s: &SyncState) -> Result<()> {
    let json = serde_json::to_vec_pretty(s)
        .map_err(|e| ShukiError::Corrupt(format!("sync_state.json serialize: {e}")))?;
    atomic_write(
        &root.join(SYNC_STATE_TMP),
        &root.join(SYNC_STATE_FILE),
        &json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::EntrySyncState;

    #[test]
    fn missing_file_yields_default() {
        let dir = tempfile::tempdir().unwrap();
        let s = load(dir.path()).unwrap();
        assert!(s.entries.is_empty());
        assert_eq!(s.last_sync_at, None);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SyncState {
            last_sync_at: Some(1_753_000_000),
            ..Default::default()
        };
        s.entries.insert(
            "ab12".into(),
            EntrySyncState {
                event_id: Some("deadbeef".into()),
                event_created_at: Some(42),
                dirty: true,
            },
        );
        save(dir.path(), &s).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.last_sync_at, Some(1_753_000_000));
        let e = &loaded.entries["ab12"];
        assert_eq!(e.event_id.as_deref(), Some("deadbeef"));
        assert_eq!(e.event_created_at, Some(42));
        assert!(e.dirty);
        // No tmp file left behind.
        assert!(!dir.path().join(SYNC_STATE_TMP).exists());
    }

    #[test]
    fn corrupt_file_is_corrupt_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SYNC_STATE_FILE), b"{not json!").unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, ShukiError::Corrupt(_)), "got: {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &SyncState::default()).unwrap();
        let mode = std::fs::metadata(dir.path().join(SYNC_STATE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
