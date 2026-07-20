//! `shuki lock`: end the device login session early.
//!
//! Clears the `.device_session` marker in the configured data dir, so the
//! next vault use requires a fresh confirmation on the signing device.
//! Idempotent: succeeds even when no session exists. In software-signer
//! mode there is no device session, but any leftover marker is still
//! cleared (e.g. after switching backends).

use crate::cli::Ui;
use crate::config::{Config, SignerConfig};
use crate::error::Result;
use crate::signer::session;

pub(crate) fn run(config: &Config, ui: &mut Ui<'_>) -> Result<()> {
    session::clear(&config.resolve_data_dir())?;
    if matches!(config.signer, SignerConfig::Software) {
        writeln!(
            ui.out,
            "note: the software signer has no device session; cleared any leftover marker"
        )?;
    }
    writeln!(
        ui.out,
        "device session cleared — next use requires confirmation on the device"
    )?;
    Ok(())
}
