#![forbid(unsafe_code)]
//! shuki — pass-like tree-structured password manager with Nostr sync.
//!
//! Architecture: CLI/TUI → [`vault::Vault`] → [`signer::Signer`] + [`store::VaultStore`],
//! plus [`sync::SyncApi`] for Nostr relay push/pull. All contracts (traits, wire schema)
//! are frozen in Phase 0; leaf branches implement bodies only.

pub mod cli;
pub mod clipboard;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod signer;
pub mod store;
pub mod sync;
pub mod testutil;
pub mod tui;
pub mod vault;

pub use error::{Result, ShukiError};
