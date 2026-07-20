//! `shuki key export` / `shuki key import`.

use nostr::nips::nip19::ToBech32 as _;

use crate::cli::Ui;
use crate::domain::SecretField;
use crate::error::{Result, ShukiError};
use crate::signer::keysetup;

use super::prompt_secret_twice;

pub(crate) async fn export(ui: &mut Ui<'_>) -> Result<()> {
    let pw = prompt_secret_twice(ui.prompter, "export passphrase")?;
    let ncryptsec = keysetup::export_ncryptsec(pw, 16).await?;
    writeln!(ui.out, "{ncryptsec}")?;
    Ok(())
}

pub(crate) async fn import(ui: &mut Ui<'_>, value: Option<String>) -> Result<()> {
    let raw = match value {
        Some(v) => SecretField::new(v),
        None => ui
            .prompter
            .prompt_secret("key (nsec1… / 64-hex / ncryptsec1…): ")?,
    };
    let v = raw.expose().trim();
    let pk = if v.starts_with("ncryptsec1") {
        let pw = ui.prompter.prompt_secret("passphrase: ")?;
        keysetup::import_ncryptsec(v, pw).await?
    } else if v.starts_with("nsec1") || (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        keysetup::import_nsec(SecretField::new(v.to_owned())).await?
    } else {
        return Err(ShukiError::Config(
            "unrecognized key format (expected nsec1…, 64-char hex, or ncryptsec1…)".into(),
        ));
    };
    let npub = pk
        .to_bech32()
        .map_err(|e| ShukiError::Crypto(e.to_string()))?;
    writeln!(ui.out, "Imported key; npub: {npub}")?;
    Ok(())
}
