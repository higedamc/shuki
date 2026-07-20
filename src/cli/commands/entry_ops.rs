//! Entry-level handlers: ls, show, insert, generate, edit, rm, mv, find.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{AppContext, Ui};
use crate::crypto::passgen::{self, PassSpec};
use crate::domain::{Entry, EntryFields, VaultPath, VaultTree};
use crate::error::{Result, ShukiError};

use super::prompt_secret_twice;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn ls(ctx: &AppContext, ui: &mut Ui<'_>, path: Option<&str>) -> Result<()> {
    let paths = ctx.vault.list_paths().await?;
    let tree = VaultTree::build(&paths);
    let rendered = match path {
        None => tree.render_text(None),
        Some(p) => {
            let vp = VaultPath::parse(p)?;
            let r = tree.render_text(Some(&vp));
            if r.is_empty() {
                return Err(ShukiError::NotFound(p.to_owned()));
            }
            r
        }
    };
    write!(ui.out, "{rendered}")?;
    Ok(())
}

/// `pass show` contract: the password is the first stdout line so
/// `shuki show p | head -1` pipes cleanly. `-c` copies instead of printing.
pub(crate) async fn show(ctx: &AppContext, ui: &mut Ui<'_>, path: &str, clip: bool) -> Result<()> {
    let vp = VaultPath::parse(path)?;
    let entry = ctx.vault.get(&vp).await?;
    if clip {
        let pw = entry
            .fields
            .password
            .as_ref()
            .ok_or_else(|| ShukiError::NotFound(format!("no password stored at {vp}")))?;
        let clipboard = ctx.clipboard.as_ref().ok_or_else(|| {
            ShukiError::Clipboard("clipboard unavailable; drop -c to print instead".into())
        })?;
        clipboard.copy_secret(pw)?;
        writeln!(
            ui.out,
            "Copied {vp} to clipboard; clearing in {}s.",
            ctx.config.clipboard_clear_secs
        )?;
    }
    write!(ui.out, "{}", format_entry(&entry, !clip))?;
    Ok(())
}

/// Render an entry for `show`. Password first (only when
/// `include_password`), then username / url / notes when present.
pub(crate) fn format_entry(entry: &Entry, include_password: bool) -> String {
    let mut s = String::new();
    if include_password {
        if let Some(pw) = &entry.fields.password {
            s.push_str(pw.expose());
            s.push('\n');
        }
    }
    if let Some(u) = &entry.fields.username {
        s.push_str(&format!("username: {u}\n"));
    }
    if let Some(u) = &entry.fields.url {
        s.push_str(&format!("url: {u}\n"));
    }
    if let Some(n) = &entry.fields.notes {
        s.push_str("notes:\n");
        s.push_str(n.expose());
        if !n.expose().ends_with('\n') {
            s.push('\n');
        }
    }
    s
}

pub(crate) async fn insert(
    ctx: &AppContext,
    ui: &mut Ui<'_>,
    path: &str,
    username: Option<String>,
    url: Option<String>,
    multiline_notes: bool,
) -> Result<()> {
    let vp = VaultPath::parse(path)?;
    let password = prompt_secret_twice(ui.prompter, &format!("password for {vp}"))?;
    let notes = if multiline_notes {
        let n = ui
            .prompter
            .read_multiline_secret("Enter notes, finish with EOF (Ctrl-D):")?;
        (!n.is_empty()).then_some(n)
    } else {
        None
    };
    let entry = Entry {
        path: vp.clone(),
        fields: EntryFields {
            password: Some(password),
            username,
            url,
            notes,
            custom: Default::default(),
        },
        updated_at: now_unix(),
    };
    ctx.vault.put(entry).await?;
    writeln!(ui.out, "Inserted {vp}.")?;
    Ok(())
}

pub(crate) struct GenerateOpts {
    pub path: String,
    pub length: usize,
    pub no_symbols: bool,
    pub no_clip: bool,
    pub username: Option<String>,
    pub url: Option<String>,
}

pub(crate) async fn generate(ctx: &AppContext, ui: &mut Ui<'_>, opts: GenerateOpts) -> Result<()> {
    let vp = VaultPath::parse(&opts.path)?;
    // Fail before storing anything if we cannot hand the password over.
    if !opts.no_clip && ctx.clipboard.is_none() {
        return Err(ShukiError::Clipboard(
            "clipboard unavailable; use --no-clip to print to stdout".into(),
        ));
    }
    let spec = PassSpec {
        length: opts.length,
        symbols: !opts.no_symbols,
        ..PassSpec::default()
    };
    let password = passgen::generate(&spec)?;
    let entry = Entry {
        path: vp.clone(),
        fields: EntryFields {
            password: Some(password.clone()),
            username: opts.username,
            url: opts.url,
            notes: None,
            custom: Default::default(),
        },
        updated_at: now_unix(),
    };
    ctx.vault.put(entry).await?;
    if opts.no_clip {
        writeln!(ui.out, "{}", password.expose())?;
    } else {
        let clipboard = ctx.clipboard.as_ref().ok_or_else(|| {
            ShukiError::Clipboard("clipboard unavailable; use --no-clip to print to stdout".into())
        })?;
        clipboard.copy_secret(&password)?;
        writeln!(
            ui.out,
            "Generated {} chars at {vp}; copied to clipboard, clearing in {}s.",
            opts.length, ctx.config.clipboard_clear_secs
        )?;
    }
    Ok(())
}

/// Field-by-field interactive edit; empty input keeps the current value.
/// Deliberately no `$EDITOR`/tempfile flow: that would put plaintext
/// secrets on disk, which shuki bans.
pub(crate) async fn edit(ctx: &AppContext, ui: &mut Ui<'_>, path: &str) -> Result<()> {
    let vp = VaultPath::parse(path)?;
    let mut entry = ctx.vault.get(&vp).await?;

    let cur = entry.fields.username.clone().unwrap_or_default();
    let user = ui.prompter.prompt_line(&format!("username [{cur}]: "))?;
    if !user.trim().is_empty() {
        entry.fields.username = Some(user.trim().to_owned());
    }

    let cur = entry.fields.url.clone().unwrap_or_default();
    let url = ui.prompter.prompt_line(&format!("url [{cur}]: "))?;
    if !url.trim().is_empty() {
        entry.fields.url = Some(url.trim().to_owned());
    }

    let pw = ui
        .prompter
        .prompt_secret("password (empty keeps current): ")?;
    if !pw.is_empty() {
        entry.fields.password = Some(pw);
    }

    let notes = ui.prompter.prompt_secret("notes (empty keeps current): ")?;
    if !notes.is_empty() {
        entry.fields.notes = Some(notes);
    }

    entry.updated_at = now_unix();
    ctx.vault.put(entry).await?;
    writeln!(ui.out, "Updated {vp}.")?;
    Ok(())
}

pub(crate) async fn rm(ctx: &AppContext, ui: &mut Ui<'_>, path: &str, force: bool) -> Result<()> {
    let vp = VaultPath::parse(path)?;
    if !force {
        if !ui.prompter.is_interactive() {
            return Err(ShukiError::Cancelled);
        }
        if !ui.prompter.confirm(&format!("Delete {vp}?"))? {
            return Err(ShukiError::Cancelled);
        }
    }
    ctx.vault.remove(&vp).await?;
    writeln!(ui.out, "Removed {vp}.")?;
    Ok(())
}

pub(crate) async fn mv(ctx: &AppContext, ui: &mut Ui<'_>, from: &str, to: &str) -> Result<()> {
    let from = VaultPath::parse(from)?;
    let to = VaultPath::parse(to)?;
    ctx.vault.rename(&from, &to).await?;
    writeln!(ui.out, "Moved {from} -> {to}.")?;
    Ok(())
}

pub(crate) async fn find(ctx: &AppContext, ui: &mut Ui<'_>, query: &str) -> Result<()> {
    let matches = ctx.vault.find(query).await?;
    for p in matches {
        writeln!(ui.out, "{p}")?;
    }
    Ok(())
}
