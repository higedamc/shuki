//! [`super::Vault`] implementation (owned by `leaf/vault-core-service`).
//!
//! Uses `Signer::self_conversation_key` once, caches it (zeroizing), and runs
//! NIP-44 host-side per entry. If the signer returns `Unsupported`, falls
//! back to per-entry `signer.nip44_encrypt/decrypt` with our own pubkey.

use std::sync::Arc;

use crate::signer::Signer;
use crate::store::VaultStore;

pub struct VaultService {
    _private: (),
}

impl VaultService {
    pub fn new(_signer: Arc<dyn Signer>, _store: Arc<dyn VaultStore>) -> Self {
        todo!("leaf/vault-core-service")
    }
}
