//! CLI surface (owned by `leaf/cli-commands-all`).
//!
//! Commands: init, ls, show [-c], insert, generate, edit, rm, mv, find,
//! sync, restore, relay add/rm/ls, net show/clearnet/tor/socks5/embedded/test,
//! key export/import, whoami. No args → TUI (dispatched by `main.rs` in the
//! integration phase).
//!
//! # `main.rs` integration
//!
//! ```ignore
//! let cli = Cli::parse();
//! let mut config = Config::load()?;
//! match cli.command {
//!     None => run_tui(...),
//!     Some(cmd) if !cli::needs_vault(&cmd) => {
//!         // Init / Key / Relay: no vault, no signer, no network.
//!         cli::dispatch_standalone(cmd, &mut config).await?;
//!     }
//!     Some(cmd) => {
//!         let mut ctx = cli::AppContext { vault, sync, clipboard, config };
//!         cli::dispatch(cmd, &mut ctx).await?;
//!     }
//! }
//! ```
//!
//! [`dispatch`] opens the vault itself for entry commands; `main.rs` only
//! constructs the [`AppContext`]. `clipboard: None` means "no clipboard
//! available" (headless): commands that need one fail with a hint instead.

pub mod commands;

use std::io::Write;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use crate::clipboard::Clipboard;
use crate::config::Config;
use crate::domain::SecretField;
use crate::error::{Result, ShukiError};
use crate::sync::SyncApi;
use crate::vault::Vault;

/// Top-level argument parser. `command == None` → interactive TUI.
#[derive(Parser)]
#[command(
    name = "shuki",
    version,
    about = "pass-like password manager with Nostr sync"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Set up the signing identity and write the initial config
    Init {
        /// Use a NSD (Nostr Signing Device) over USB serial instead of a
        /// software key in the OS keychain
        #[arg(long, conflicts_with_all = ["import_nsec", "import_ncryptsec"])]
        nsd: bool,
        /// Import an existing bech32 nsec (prompted, never an argument)
        #[arg(long, conflicts_with = "import_ncryptsec")]
        import_nsec: bool,
        /// Import a NIP-49 ncryptsec backup (prompts for the passphrase)
        #[arg(long)]
        import_ncryptsec: bool,
        /// Relay URL to add to the config (repeatable)
        #[arg(long)]
        relay: Vec<String>,
    },
    /// List entries as a tree (optionally below PATH)
    Ls { path: Option<String> },
    /// Print an entry; -c copies the password instead of printing it
    Show {
        path: String,
        /// Copy the password to the clipboard instead of printing it
        #[arg(short = 'c', long)]
        clip: bool,
    },
    /// Add an entry, prompting for the password (never echoed)
    Insert {
        path: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Also read multiline notes from stdin until EOF
        #[arg(long)]
        multiline_notes: bool,
    },
    /// Generate a password, store it, and copy it to the clipboard
    Generate {
        path: String,
        /// Password length
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Exclude symbol characters
        #[arg(long)]
        no_symbols: bool,
        /// Print the password to stdout instead of copying it
        #[arg(long)]
        no_clip: bool,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    /// Edit an entry field by field (empty input keeps the current value)
    Edit { path: String },
    /// Delete an entry (tombstoned so the deletion syncs)
    Rm {
        path: String,
        /// Skip the confirmation prompt
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Rename/move an entry
    Mv { from: String, to: String },
    /// Case-insensitive substring search over entry paths
    Find { query: String },
    /// Push dirty entries and pull remote changes from the relays
    Sync,
    /// Disaster recovery: fetch ALL shuki events by this key and merge them
    Restore {
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Manage the relay list in the config
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Show or switch the network mode (clearnet / Tor) and test relays
    Net {
        #[command(subcommand)]
        cmd: NetCmd,
    },
    /// Export/import the signing key
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Show the logged-in identity (npub, signer backend, config, relays)
    Whoami,
}

#[derive(Subcommand)]
pub enum RelayCmd {
    /// Add a relay URL (ws:// or wss://)
    Add { url: String },
    /// Remove a relay URL
    Rm { url: String },
    /// List configured relays
    Ls,
}

#[derive(Subcommand)]
pub enum NetCmd {
    /// Show the current mode, embedded-tor build support, and relay list
    Show,
    /// Connect directly (no proxy)
    Clearnet,
    /// Route through an external Tor daemon (SOCKS5 at 127.0.0.1:9050)
    Tor,
    /// Route through a custom SOCKS5 proxy
    Socks5 {
        /// Proxy address as host:port, e.g. 127.0.0.1:9150
        addr: String,
    },
    /// Use the embedded Tor client (requires a `--features tor` build)
    Embedded,
    /// Try to connect to every configured relay through the current mode
    Test,
}

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Print the key as a NIP-49 ncryptsec (prompts for a passphrase)
    Export,
    /// Import an nsec / hex secret key / ncryptsec into the keychain
    Import {
        /// The key; prompted (never echoed) when omitted
        value: Option<String>,
    },
}

/// Everything a vault-backed command needs. Built by `main.rs` (DI).
pub struct AppContext {
    pub vault: Arc<dyn Vault>,
    pub sync: Arc<dyn SyncApi>,
    /// `None` on headless systems; clipboard-dependent commands then fail
    /// with a hint to use their print variant.
    pub clipboard: Option<Arc<Clipboard>>,
    pub config: Config,
}

/// Whether `main.rs` must build an [`AppContext`] (vault + signer + sync)
/// before dispatching. `false` for Init / Key / Relay / Net / Whoami, which
/// only touch the [`Config`] and the keychain (whoami additionally probes an
/// NSD device, and `net test` opens relay connections — but neither needs a
/// vault or signer) — route those through [`dispatch_standalone`].
pub fn needs_vault(cmd: &Command) -> bool {
    !matches!(
        cmd,
        Command::Init { .. }
            | Command::Key { .. }
            | Command::Relay { .. }
            | Command::Net { .. }
            | Command::Whoami
    )
}

/// Run a vault-backed command (entry ops + sync/restore). Also accepts the
/// standalone commands (delegated to [`dispatch_standalone`] semantics), so
/// `main.rs` may route everything here once a context exists.
pub async fn dispatch(cmd: Command, ctx: &mut AppContext) -> Result<()> {
    let mut prompter = StdPrompter;
    let mut out = std::io::stdout();
    let mut ui = Ui {
        prompter: &mut prompter,
        out: &mut out,
    };
    dispatch_with(cmd, ctx, &mut ui).await
}

/// Run a command that needs no vault: Init, Key export/import, Relay
/// add/rm/ls, Whoami. Mutates + saves `config` where applicable.
pub async fn dispatch_standalone(cmd: Command, config: &mut Config) -> Result<()> {
    let mut prompter = StdPrompter;
    let mut out = std::io::stdout();
    let mut ui = Ui {
        prompter: &mut prompter,
        out: &mut out,
    };
    dispatch_standalone_with(cmd, config, &mut ui).await
}

async fn dispatch_with(cmd: Command, ctx: &mut AppContext, ui: &mut Ui<'_>) -> Result<()> {
    match cmd {
        Command::Init { .. }
        | Command::Relay { .. }
        | Command::Net { .. }
        | Command::Key { .. }
        | Command::Whoami => dispatch_standalone_with(cmd, &mut ctx.config, ui).await,
        Command::Sync => commands::sync_cmd::sync(ctx, ui).await,
        Command::Restore { yes } => commands::sync_cmd::restore(ctx, ui, yes).await,
        cmd => {
            ctx.vault.open().await?;
            match cmd {
                Command::Ls { path } => commands::entry_ops::ls(ctx, ui, path.as_deref()).await,
                Command::Show { path, clip } => {
                    commands::entry_ops::show(ctx, ui, &path, clip).await
                }
                Command::Insert {
                    path,
                    username,
                    url,
                    multiline_notes,
                } => {
                    commands::entry_ops::insert(ctx, ui, &path, username, url, multiline_notes)
                        .await
                }
                Command::Generate {
                    path,
                    length,
                    no_symbols,
                    no_clip,
                    username,
                    url,
                } => {
                    let opts = commands::entry_ops::GenerateOpts {
                        path,
                        length,
                        no_symbols,
                        no_clip,
                        username,
                        url,
                    };
                    commands::entry_ops::generate(ctx, ui, opts).await
                }
                Command::Edit { path } => commands::entry_ops::edit(ctx, ui, &path).await,
                Command::Rm { path, force } => commands::entry_ops::rm(ctx, ui, &path, force).await,
                Command::Mv { from, to } => commands::entry_ops::mv(ctx, ui, &from, &to).await,
                Command::Find { query } => commands::entry_ops::find(ctx, ui, &query).await,
                _ => unreachable!("standalone commands handled above"),
            }
        }
    }
}

async fn dispatch_standalone_with(
    cmd: Command,
    config: &mut Config,
    ui: &mut Ui<'_>,
) -> Result<()> {
    match cmd {
        Command::Init {
            nsd,
            import_nsec,
            import_ncryptsec,
            relay,
        } => commands::init::run(ui, config, nsd, import_nsec, import_ncryptsec, relay).await,
        Command::Relay { cmd } => match cmd {
            RelayCmd::Add { url } => commands::sync_cmd::relay_add(config, ui, &url),
            RelayCmd::Rm { url } => commands::sync_cmd::relay_rm(config, ui, &url),
            RelayCmd::Ls => commands::sync_cmd::relay_ls(config, ui),
        },
        Command::Net { cmd } => match cmd {
            NetCmd::Show => commands::net_cmd::show(config, ui),
            NetCmd::Clearnet => commands::net_cmd::set_clearnet(config, ui),
            NetCmd::Tor => commands::net_cmd::set_tor(config, ui),
            NetCmd::Socks5 { addr } => commands::net_cmd::set_socks5(config, ui, &addr),
            NetCmd::Embedded => commands::net_cmd::set_embedded(config, ui),
            NetCmd::Test => commands::net_cmd::test(config, ui).await,
        },
        Command::Key { cmd } => match cmd {
            KeyCmd::Export => commands::key_cmd::export(ui).await,
            KeyCmd::Import { value } => commands::key_cmd::import(ui, value).await,
        },
        Command::Whoami => commands::whoami::run(config, ui).await,
        _ => Err(ShukiError::Other(
            "internal: this command needs a vault; route it through `dispatch`".into(),
        )),
    }
}

/// Interactive input abstraction so handlers are testable without a tty.
pub(crate) trait Prompter: Send {
    /// No-echo secret prompt (rpassword).
    fn prompt_secret(&mut self, prompt: &str) -> Result<SecretField>;
    /// Echoed single-line prompt (prompt on stderr, read from stdin).
    fn prompt_line(&mut self, prompt: &str) -> Result<String>;
    /// y/N confirmation; only `y`/`yes` (case-insensitive) is `true`.
    fn confirm(&mut self, prompt: &str) -> Result<bool>;
    /// Read stdin to EOF after printing `banner` (multiline notes).
    fn read_multiline_secret(&mut self, banner: &str) -> Result<SecretField>;
    /// Whether stdin is a tty (confirmations possible).
    fn is_interactive(&self) -> bool;
}

/// Production [`Prompter`]: rpassword + stdin/stderr.
struct StdPrompter;

impl Prompter for StdPrompter {
    fn prompt_secret(&mut self, prompt: &str) -> Result<SecretField> {
        rpassword::prompt_password(prompt)
            .map(SecretField::new)
            .map_err(ShukiError::Store)
    }

    fn prompt_line(&mut self, prompt: &str) -> Result<String> {
        let mut err = std::io::stderr();
        write!(err, "{prompt}")?;
        err.flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn confirm(&mut self, prompt: &str) -> Result<bool> {
        let ans = self.prompt_line(&format!("{prompt} [y/N] "))?;
        Ok(matches!(
            ans.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }

    fn read_multiline_secret(&mut self, banner: &str) -> Result<SecretField> {
        eprintln!("{banner}");
        let s = std::io::read_to_string(std::io::stdin())?;
        Ok(SecretField::new(s))
    }

    fn is_interactive(&self) -> bool {
        use std::io::IsTerminal as _;
        std::io::stdin().is_terminal()
    }
}

/// Bundled prompter + output writer handed to every handler.
pub(crate) struct Ui<'a> {
    pub(crate) prompter: &'a mut dyn Prompter,
    pub(crate) out: &'a mut (dyn Write + Send),
}

#[cfg(test)]
mod tests;
