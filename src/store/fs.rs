//! Filesystem [`super::VaultStore`] (owned by `leaf/store-fs-files`).
//!
//! Layout: `<root>/store/<d_tag>.nip44` (0600) + `<root>/sync_state.json`;
//! `<root>` created 0700. Writes are atomic (tmp file + rename).

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Result, ShukiError};

use super::syncstate;
use super::{CipherEntry, SyncState, VaultStore};

/// File extension for ciphertext entry files.
const ENTRY_EXT: &str = "nip44";
/// Prefix of in-flight temp files inside `<root>/store/`.
const TMP_PREFIX: &str = ".tmp-";
/// Maximum accepted `d_tag` length (hex chars). HMAC-SHA256 tags are 64.
const MAX_D_TAG_LEN: usize = 128;

pub struct FsVaultStore {
    root: PathBuf,
}

impl FsVaultStore {
    /// Open (creating directories if needed, enforcing permissions).
    pub fn open(root: &Path) -> Result<Self> {
        create_private_dir(root)?;
        create_private_dir(&root.join("store"))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn store_dir(&self) -> PathBuf {
        self.root.join("store")
    }

    /// Path of the entry file for an already-validated `d_tag`.
    fn entry_path(&self, d_tag: &str) -> PathBuf {
        self.store_dir().join(format!("{d_tag}.{ENTRY_EXT}"))
    }
}

/// Create `dir` if missing, private to the owner (0700 on unix). On an
/// existing directory the mode is re-asserted.
fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Path-traversal guard: a `d_tag` is only ever used as a filename after this
/// check. Accepts exactly lowercase hex, 1..=128 chars; rejects everything
/// else (`..`, separators, uppercase, empty, non-hex) as [`ShukiError::Corrupt`].
fn validate_d_tag(d_tag: &str) -> Result<()> {
    let ok = !d_tag.is_empty()
        && d_tag.len() <= MAX_D_TAG_LEN
        && d_tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ShukiError::Corrupt(format!(
            "invalid d_tag (must be lowercase hex, 1..={MAX_D_TAG_LEN} chars): {d_tag:?}"
        )))
    }
}

/// `Some(d_tag)` if `file_name` is a valid entry file name (`<hex>.nip44`).
fn entry_d_tag_from_file_name(file_name: &str) -> Option<&str> {
    let stem = file_name.strip_suffix(&format!(".{ENTRY_EXT}"))?;
    validate_d_tag(stem).ok()?;
    Some(stem)
}

impl VaultStore for FsVaultStore {
    fn list(&self) -> Result<Vec<CipherEntry>> {
        let mut out = Vec::new();
        for dirent in fs::read_dir(self.store_dir())? {
            let dirent = dirent?;
            let name = dirent.file_name();
            // Skip temp files, foreign extensions, invalid stems — never fail.
            let Some(name) = name.to_str() else { continue };
            let Some(d_tag) = entry_d_tag_from_file_name(name) else {
                continue;
            };
            if !dirent.file_type()?.is_file() {
                continue;
            }
            let payload = fs::read_to_string(dirent.path())?;
            out.push(CipherEntry {
                d_tag: d_tag.to_owned(),
                payload,
            });
        }
        out.sort_by(|a, b| a.d_tag.cmp(&b.d_tag));
        Ok(out)
    }

    fn get(&self, d_tag: &str) -> Result<Option<CipherEntry>> {
        validate_d_tag(d_tag)?;
        match fs::read_to_string(self.entry_path(d_tag)) {
            Ok(payload) => Ok(Some(CipherEntry {
                d_tag: d_tag.to_owned(),
                payload,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&self, entry: &CipherEntry) -> Result<()> {
        validate_d_tag(&entry.d_tag)?;
        let tmp = self
            .store_dir()
            .join(format!("{TMP_PREFIX}{}", entry.d_tag));
        syncstate::atomic_write(
            &tmp,
            &self.entry_path(&entry.d_tag),
            entry.payload.as_bytes(),
        )
    }

    fn remove(&self, d_tag: &str) -> Result<()> {
        validate_d_tag(d_tag)?;
        match fs::remove_file(self.entry_path(d_tag)) {
            Ok(()) => Ok(()),
            // Idempotent: removing a missing entry is fine.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn load_sync_state(&self) -> Result<SyncState> {
        syncstate::load(&self.root)
    }

    fn save_sync_state(&self, s: &SyncState) -> Result<()> {
        syncstate::save(&self.root, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store(dir: &tempfile::TempDir) -> FsVaultStore {
        FsVaultStore::open(&dir.path().join("vault")).unwrap()
    }

    fn entry(d_tag: &str, payload: &str) -> CipherEntry {
        CipherEntry {
            d_tag: d_tag.into(),
            payload: payload.into(),
        }
    }

    #[test]
    fn put_get_roundtrip_and_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);

        store.put(&entry("ab01", "ciphertext-v1")).unwrap();
        assert_eq!(store.get("ab01").unwrap().unwrap().payload, "ciphertext-v1");

        // Overwrite replaces the payload.
        store.put(&entry("ab01", "ciphertext-v2")).unwrap();
        assert_eq!(store.get("ab01").unwrap().unwrap().payload, "ciphertext-v2");

        // File contains exactly the payload string.
        let raw = std::fs::read_to_string(dir.path().join("vault/store/ab01.nip44")).unwrap();
        assert_eq!(raw, "ciphertext-v2");
    }

    #[test]
    fn get_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        assert!(store.get("deadbeef").unwrap().is_none());
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        store.put(&entry("0f", "x")).unwrap();
        store.remove("0f").unwrap();
        assert!(store.get("0f").unwrap().is_none());
        // Second removal of a now-missing entry is Ok.
        store.remove("0f").unwrap();
    }

    #[test]
    fn list_roundtrip_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        store.put(&entry("ff", "pf")).unwrap();
        store.put(&entry("aa", "pa")).unwrap();
        store.put(&entry("0b", "p0")).unwrap();
        let all = store.list().unwrap();
        let tags: Vec<_> = all.iter().map(|e| e.d_tag.as_str()).collect();
        assert_eq!(tags, ["0b", "aa", "ff"]);
        assert_eq!(all[1].payload, "pa");
    }

    #[test]
    fn list_skips_tmp_leftovers_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        store.put(&entry("abcd", "keep")).unwrap();
        let store_dir = dir.path().join("vault/store");
        // Simulated crash leftover + files with bad names/extensions.
        std::fs::write(store_dir.join(".tmp-abcd"), "partial").unwrap();
        std::fs::write(store_dir.join("notes.txt"), "junk").unwrap();
        std::fs::write(store_dir.join("XYZ.nip44"), "junk").unwrap();
        std::fs::write(store_dir.join("AB.nip44"), "junk").unwrap();
        std::fs::write(store_dir.join(".nip44"), "junk").unwrap();
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].d_tag, "abcd");
        assert_eq!(all[0].payload, "keep");
    }

    #[test]
    fn invalid_d_tags_rejected_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        let bad = [
            "../evil",
            "..",
            ".",
            "",
            "AB12",   // uppercase
            "abcg",   // non-hex letter
            "ab/cd",  // path separator
            "ab\\cd", // backslash
            "/etc/passwd",
            "ab cd",          // space
            "ab.nip44",       // dot
            &"a".repeat(129), // too long
        ];
        for tag in bad {
            assert!(
                matches!(store.get(tag), Err(ShukiError::Corrupt(_))),
                "get accepted {tag:?}"
            );
            assert!(
                matches!(store.put(&entry(tag, "x")), Err(ShukiError::Corrupt(_))),
                "put accepted {tag:?}"
            );
            assert!(
                matches!(store.remove(tag), Err(ShukiError::Corrupt(_))),
                "remove accepted {tag:?}"
            );
        }
        // Nothing escaped into the tree.
        assert!(store.list().unwrap().is_empty());
        // Boundary values are fine.
        store.put(&entry("0", "min")).unwrap();
        store.put(&entry(&"a".repeat(128), "max")).unwrap();
    }

    #[test]
    fn sync_state_via_trait() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir);
        // Missing file → default.
        assert!(store.load_sync_state().unwrap().entries.is_empty());
        let s = SyncState {
            last_sync_at: Some(7),
            ..Default::default()
        };
        store.save_sync_state(&s).unwrap();
        assert_eq!(store.load_sync_state().unwrap().last_sync_at, Some(7));
        // Corrupt file → Corrupt error, never a panic.
        std::fs::write(dir.path().join("vault/sync_state.json"), b"[oops").unwrap();
        assert!(matches!(
            store.load_sync_state(),
            Err(ShukiError::Corrupt(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_permissions_0700_dirs_0600_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let store = FsVaultStore::open(&root).unwrap();
        store.put(&entry("ab", "x")).unwrap();
        store.save_sync_state(&SyncState::default()).unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("store")), 0o700);
        assert_eq!(mode(&root.join("store/ab.nip44")), 0o600);
        assert_eq!(mode(&root.join("sync_state.json")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_reasserts_permissions_on_existing_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        std::fs::create_dir_all(root.join("store")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root.join("store"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        FsVaultStore::open(&root).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("store")), 0o700);
    }
}
