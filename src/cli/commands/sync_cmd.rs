//! sync / restore handlers + relay list management (config-only).

use crate::cli::{AppContext, Ui};
use crate::config::Config;
use crate::error::{Result, ShukiError};
use crate::sync::SyncReport;

use super::validate_relay_url;

pub(crate) async fn sync(ctx: &AppContext, ui: &mut Ui<'_>) -> Result<()> {
    let report = ctx.sync.sync().await?;
    write!(ui.out, "{}", format_report(&report))?;
    Ok(())
}

pub(crate) async fn restore(ctx: &AppContext, ui: &mut Ui<'_>, yes: bool) -> Result<()> {
    if !yes {
        if !ui.prompter.is_interactive() {
            return Err(ShukiError::Cancelled);
        }
        let go = ui.prompter.confirm(
            "Restore fetches ALL shuki events for this key from the relays \
             and merges them into the local vault. Continue?",
        )?;
        if !go {
            return Err(ShukiError::Cancelled);
        }
    }
    let report = ctx.sync.restore_all().await?;
    write!(ui.out, "{}", format_report(&report))?;
    Ok(())
}

pub(crate) fn format_report(r: &SyncReport) -> String {
    let mut s = format!(
        "pushed: {}\npulled: {}\ntombstones applied: {}\nconflicts (last-write-wins): {}\n",
        r.pushed, r.pulled, r.tombstones_applied, r.conflicts_lww
    );
    if !r.errors.is_empty() {
        s.push_str(&format!("{} error(s):\n", r.errors.len()));
        for (what, msg) in &r.errors {
            s.push_str(&format!("  {what}: {msg}\n"));
        }
    }
    s
}

pub(crate) fn relay_add(config: &mut Config, ui: &mut Ui<'_>, url: &str) -> Result<()> {
    let url = url.trim();
    validate_relay_url(url)?;
    if config.relays.iter().any(|r| r == url) {
        writeln!(ui.out, "Relay already configured: {url}")?;
        return Ok(());
    }
    config.relays.push(url.to_owned());
    config.save()?;
    writeln!(ui.out, "Added relay {url}.")?;
    Ok(())
}

pub(crate) fn relay_rm(config: &mut Config, ui: &mut Ui<'_>, url: &str) -> Result<()> {
    let url = url.trim();
    let Some(idx) = config.relays.iter().position(|r| r == url) else {
        return Err(ShukiError::NotFound(format!("relay not configured: {url}")));
    };
    config.relays.remove(idx);
    config.save()?;
    writeln!(ui.out, "Removed relay {url}.")?;
    Ok(())
}

pub(crate) fn relay_ls(config: &Config, ui: &mut Ui<'_>) -> Result<()> {
    if config.relays.is_empty() {
        writeln!(ui.out, "(no relays configured)")?;
        return Ok(());
    }
    for r in &config.relays {
        writeln!(ui.out, "{r}")?;
    }
    Ok(())
}
