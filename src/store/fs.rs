//! Filesystem [`super::VaultStore`] (owned by `leaf/store-fs-files`).
//!
//! Layout: `<root>/store/<d_tag>.nip44` (0600) + `<root>/sync_state.json`;
//! `<root>` created 0700. Writes are atomic (tmp file + rename).

use std::path::Path;

use crate::error::Result;

pub struct FsVaultStore {
    _private: (),
}

impl FsVaultStore {
    /// Open (creating directories if needed, enforcing permissions).
    pub fn open(_root: &Path) -> Result<Self> {
        todo!("leaf/store-fs-files")
    }
}
