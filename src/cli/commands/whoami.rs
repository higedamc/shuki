//! `shuki whoami`: print the logged-in identity and environment.
//!
//! Never hard-fails just because the signing device is unplugged: in NSD
//! mode a failed connect degrades to "unavailable" and the rest of the
//! report (signer, config path, data dir, relays) is still printed.

use std::path::Path;

use nostr::ToBech32 as _;

use crate::cli::Ui;
use crate::config::{Config, SignerConfig};
use crate::error::Result;
use crate::signer::keysetup;
use crate::signer::nsd::NsdSigner;
use crate::signer::Signer as _;

/// Identity resolution outcome (never an `Err`: whoami always prints).
pub(crate) enum IdentityStatus {
    Known {
        npub: String,
        hex: String,
    },
    /// Software mode with no key in the keychain yet.
    NotInitialized,
    /// NSD mode with the device not connected / not answering.
    Unavailable,
}

/// Human-readable signer backend label.
pub(crate) fn signer_label(signer: &SignerConfig) -> String {
    match signer {
        SignerConfig::Software => "software (OS keychain)".to_owned(),
        SignerConfig::Nsd { port: Some(port) } => format!("nsd (port {port})"),
        SignerConfig::Nsd { port: None } => "nsd (port autodetect)".to_owned(),
    }
}

/// Render the whoami report (testable without keychain or device).
pub(crate) fn format_whoami(
    identity: &IdentityStatus,
    signer: &str,
    config_path: &Path,
    data_dir: &Path,
    relay_count: usize,
) -> String {
    let mut s = String::new();
    match identity {
        IdentityStatus::Known { npub, hex } => {
            s.push_str(&format!("npub:   {npub}\n"));
            s.push_str(&format!("pubkey: {hex}\n"));
        }
        IdentityStatus::NotInitialized => {
            s.push_str("npub:   (not initialized — run: shuki init)\n");
        }
        IdentityStatus::Unavailable => {
            s.push_str("npub:   unavailable (device not connected)\n");
        }
    }
    s.push_str(&format!("signer: {signer}\n"));
    s.push_str(&format!("config: {}\n", config_path.display()));
    s.push_str(&format!("data:   {}\n", data_dir.display()));
    s.push_str(&format!("relays: {relay_count} configured\n"));
    s
}

fn known(pk: nostr::PublicKey) -> IdentityStatus {
    IdentityStatus::Known {
        npub: pk.to_bech32().expect("npub bech32 is infallible"),
        hex: pk.to_hex(),
    }
}

pub(crate) async fn run(config: &Config, ui: &mut Ui<'_>) -> Result<()> {
    let identity = match &config.signer {
        SignerConfig::Software => match keysetup::stored_public_key().await? {
            Some(pk) => known(pk),
            None => IdentityStatus::NotInitialized,
        },
        SignerConfig::Nsd { port } => match NsdSigner::connect(port.clone()).await {
            Ok(signer) => match signer.public_key().await {
                Ok(pk) => known(pk),
                Err(_) => IdentityStatus::Unavailable,
            },
            Err(_) => IdentityStatus::Unavailable,
        },
    };
    let out = format_whoami(
        &identity,
        &signer_label(&config.signer),
        &Config::config_path(),
        &config.resolve_data_dir(),
        config.relays.len(),
    );
    write!(ui.out, "{out}")?;
    Ok(())
}
