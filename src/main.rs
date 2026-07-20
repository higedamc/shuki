//! Entrypoint: parses the CLI, builds the dependency graph (signer → store →
//! vault → sync), and dispatches to a command handler or the TUI.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use shuki::cli::{self, AppContext, Cli};
use shuki::clipboard::Clipboard;
use shuki::config::{Config, SignerConfig};
use shuki::signer::nsd::NsdSigner;
use shuki::signer::software::SoftwareSigner;
use shuki::signer::Signer;
use shuki::store::fs::FsVaultStore;
use shuki::sync::engine::SyncEngine;
use shuki::vault::service::VaultService;

#[tokio::main]
async fn main() {
    // Logs go to stderr; secrets are never logged (enforced per-module).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("shuki: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> shuki::Result<()> {
    let mut config = Config::load()?;

    match cli.command {
        // Init / Key / Relay need no vault, signer, or network.
        Some(cmd) if !cli::needs_vault(&cmd) => cli::dispatch_standalone(cmd, &mut config).await,
        other => {
            let signer: Arc<dyn Signer> = match &config.signer {
                SignerConfig::Software => Arc::new(SoftwareSigner::load().await?),
                SignerConfig::Nsd { port } => Arc::new(NsdSigner::connect(port.clone()).await?),
            };
            let store = Arc::new(FsVaultStore::open(&config.resolve_data_dir())?);
            let vault = Arc::new(VaultService::new(signer.clone(), store.clone()));
            let sync = Arc::new(SyncEngine::new(signer, store, config.clone()));
            let clipboard = Some(Arc::new(Clipboard::new(Duration::from_secs(
                config.clipboard_clear_secs,
            ))));

            match other {
                Some(cmd) => {
                    let mut ctx = AppContext {
                        vault,
                        sync,
                        clipboard,
                        config,
                    };
                    cli::dispatch(cmd, &mut ctx).await
                }
                None => shuki::tui::run(vault, sync, clipboard, config).await,
            }
        }
    }
}
