//! `shuki net …`: view/switch the network mode and test relay connectivity.
//!
//! Standalone (no vault, no signer): mode switches only mutate + save the
//! [`Config`]; `net test` builds a relay client straight from the config via
//! [`crate::sync::relays::build_client`].

use crate::cli::Ui;
use crate::config::{Config, NetMode, DEFAULT_SOCKS5_ADDR};
use crate::error::{Result, ShukiError};
use crate::sync::relays;

/// Whether this binary was compiled with the embedded-tor (`tor`) feature.
pub(crate) fn tor_feature_built() -> bool {
    cfg!(feature = "tor")
}

/// Human-readable label for a [`NetMode`].
pub(crate) fn mode_label(net: &NetMode) -> String {
    match net {
        NetMode::Clearnet => "clearnet".to_owned(),
        NetMode::Socks5 { addr } => format!("socks5 (proxy {addr})"),
        NetMode::Tor => "tor (embedded)".to_owned(),
    }
}

pub(crate) fn show(config: &Config, ui: &mut Ui<'_>) -> Result<()> {
    writeln!(ui.out, "mode:   {}", mode_label(&config.net))?;
    let tor = if tor_feature_built() {
        "available (built with --features tor)"
    } else {
        "not built in (rebuild with --features tor)"
    };
    writeln!(ui.out, "embedded tor: {tor}")?;
    writeln!(ui.out, "relays: {} configured", config.relays.len())?;
    for r in &config.relays {
        writeln!(ui.out, "  {r}")?;
    }
    Ok(())
}

pub(crate) fn set_clearnet(config: &mut Config, ui: &mut Ui<'_>) -> Result<()> {
    config.net = NetMode::Clearnet;
    config.save()?;
    writeln!(ui.out, "Network mode set to clearnet.")?;
    Ok(())
}

pub(crate) fn set_tor(config: &mut Config, ui: &mut Ui<'_>) -> Result<()> {
    config.net = NetMode::Socks5 {
        addr: DEFAULT_SOCKS5_ADDR.to_owned(),
    };
    config.save()?;
    writeln!(
        ui.out,
        "Network mode set to socks5 (proxy {DEFAULT_SOCKS5_ADDR})."
    )?;
    writeln!(
        ui.out,
        "This expects a Tor daemon running locally (its SOCKS5 port is \
         {DEFAULT_SOCKS5_ADDR} by default)."
    )?;
    Ok(())
}

pub(crate) fn set_socks5(config: &mut Config, ui: &mut Ui<'_>, addr: &str) -> Result<()> {
    let addr = addr.trim();
    // Same parse `build_client` performs, so a saved address never fails
    // later at connect time.
    addr.parse::<std::net::SocketAddr>().map_err(|e| {
        ShukiError::Config(format!(
            "invalid socks5 proxy address {addr:?} (expected host:port, \
             e.g. 127.0.0.1:9050): {e}"
        ))
    })?;
    config.net = NetMode::Socks5 {
        addr: addr.to_owned(),
    };
    config.save()?;
    writeln!(ui.out, "Network mode set to socks5 (proxy {addr}).")?;
    Ok(())
}

pub(crate) fn set_embedded(config: &mut Config, ui: &mut Ui<'_>) -> Result<()> {
    config.net = NetMode::Tor;
    config.save()?;
    writeln!(ui.out, "Network mode set to tor (embedded).")?;
    if !tor_feature_built() {
        writeln!(
            ui.out,
            "warning: this binary was built WITHOUT the `tor` feature — sync \
             will error until you rebuild with `cargo install --path . \
             --features tor` (or switch back with `shuki net clearnet`)."
        )?;
    }
    Ok(())
}

pub(crate) async fn test(config: &Config, ui: &mut Ui<'_>) -> Result<()> {
    writeln!(
        ui.out,
        "checking {} relay(s) via {}…",
        config.relays.len(),
        mode_label(&config.net)
    )?;
    let client = relays::build_client(config).await?;
    let statuses = relays::relay_statuses(&client, &config.relays).await;
    client.disconnect().await;

    let mut ok = 0usize;
    for (url, outcome) in &statuses {
        match outcome {
            None => {
                ok += 1;
                writeln!(ui.out, "✓ {url}")?;
            }
            Some(why) => writeln!(ui.out, "✗ {url}: {why}")?,
        }
    }
    writeln!(ui.out, "{ok}/{} relay(s) reachable", statuses.len())?;
    if ok == 0 {
        return Err(ShukiError::Relay(
            "no relay reachable through the current network mode".into(),
        ));
    }
    Ok(())
}
