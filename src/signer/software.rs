//! Software signer backed by the OS keychain (owned by `leaf/signer-software-keyring`).
//!
//! Contract: keychain service = `"shuki"`, account = the npub (allows multiple
//! identities later). The nsec is loaded from the keychain per operation into
//! zeroizing memory and dropped immediately; only the (constant) self
//! conversation key is cached for the process lifetime.

use crate::error::Result;

pub const KEYCHAIN_SERVICE: &str = "shuki";

pub struct SoftwareSigner {
    _private: (),
}

impl SoftwareSigner {
    /// Load the signer for the identity stored in the keychain.
    pub async fn load() -> Result<Self> {
        todo!("leaf/signer-software-keyring")
    }
}
