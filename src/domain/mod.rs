//! Pure domain types: no IO, no crypto, no async.

pub mod entry;
pub mod path;
pub mod tree;

pub use entry::{Entry, EntryFields, SecretField};
pub use path::VaultPath;
pub use tree::VaultTree;
