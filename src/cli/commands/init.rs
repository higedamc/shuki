//! `shuki init` — identity setup + initial config.

use nostr::nips::nip19::ToBech32 as _;

use crate::cli::Ui;
use crate::config::{Config, SignerConfig};
use crate::error::{Result, ShukiError};
use crate::signer::keysetup;

use super::validate_relay_url;

pub(crate) async fn run(
    ui: &mut Ui<'_>,
    config: &mut Config,
    nsd: bool,
    import_nsec: bool,
    import_ncryptsec: bool,
    relays: Vec<String>,
) -> Result<()> {
    if keysetup::stored_public_key().await?.is_some() {
        return Err(ShukiError::AlreadyExists(
            "an identity is already set up; use `shuki key import` to replace it, \
             or point SHUKI_DATA_DIR / data_dir at a different directory"
                .into(),
        ));
    }
    for url in &relays {
        validate_relay_url(url.trim())?;
    }

    if nsd {
        config.signer = SignerConfig::Nsd { port: None };
        writeln!(
            ui.out,
            "Configured NSD (Nostr Signing Device) signing; the device is \
             detected and validated on first use."
        )?;
    } else {
        config.signer = SignerConfig::Software;
        let pk = if import_nsec {
            let nsec = ui.prompter.prompt_secret("nsec: ")?;
            keysetup::import_nsec(nsec).await?
        } else if import_ncryptsec {
            let nc = ui.prompter.prompt_secret("ncryptsec: ")?;
            let pw = ui.prompter.prompt_secret("passphrase: ")?;
            keysetup::import_ncryptsec(nc.expose(), pw).await?
        } else {
            keysetup::generate_and_store().await?
        };
        let npub = pk
            .to_bech32()
            .map_err(|e| ShukiError::Crypto(e.to_string()))?;
        writeln!(
            ui.out,
            "\nYour Nostr public key:\n\n  {npub}\n\nBack up the secret key with `shuki key export` (NIP-49 ncryptsec)."
        )?;
    }

    for url in relays {
        let url = url.trim().to_owned();
        if !config.relays.contains(&url) {
            config.relays.push(url);
        }
    }
    config.save()?;
    writeln!(
        ui.out,
        "Config written to {}.",
        Config::config_path().display()
    )?;
    Ok(())
}
