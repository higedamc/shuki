//! CSPRNG password generation (owned by `leaf/crypto-core-primitives`).

use crate::domain::SecretField;
use crate::error::Result;

/// Character-class spec for generated passwords.
#[derive(Clone, Debug)]
pub struct PassSpec {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PassSpec {
    fn default() -> Self {
        Self {
            length: 24,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a password from OS randomness; guarantees at least one character
/// of every enabled class (errors if no class enabled or length too short).
pub fn generate(_spec: &PassSpec) -> Result<SecretField> {
    todo!("leaf/crypto-core-primitives")
}
