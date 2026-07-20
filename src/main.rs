//! Entrypoint: parses the CLI, builds the dependency graph (signer → store →
//! vault → sync), and dispatches to a command handler or the TUI.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use nostr::ToBech32 as _;

use shuki::cli::{self, AppContext, Cli};
use shuki::clipboard::Clipboard;
use shuki::config::{Config, SignerConfig};
use shuki::signer::nsd::NsdSigner;
use shuki::signer::session;
use shuki::signer::software::SoftwareSigner;
use shuki::signer::Signer;
use shuki::store::fs::FsVaultStore;
use shuki::sync::engine::SyncEngine;
use shuki::tui::Identity;
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
        // Everything else (entry commands, sync/restore, TUI) opens the vault.
        other => {
            let signer: Arc<dyn Signer> = match &config.signer {
                SignerConfig::Software => Arc::new(SoftwareSigner::load().await?),
                SignerConfig::Nsd { port } => {
                    let nsd = NsdSigner::connect(port.clone()).await?;
                    if config.device_auth_on_open {
                        // Physical-presence login with a session lifetime:
                        // the first vault use requires a button press on the
                        // device; a valid session marker (same npub, not
                        // expired) skips the challenge until it times out or
                        // `shuki lock` clears it. Publishing events still
                        // always confirms on-device (`/sign-message`).
                        let npub = nsd
                            .public_key()
                            .await?
                            .to_bech32()
                            .expect("npub bech32 is infallible");
                        let data_dir = config.resolve_data_dir();
                        let need = config.device_auth_timeout_secs == 0
                            || !session::is_valid(
                                &data_dir,
                                &npub,
                                config.device_auth_timeout_secs,
                            );
                        if need {
                            // Runs before the TUI enters raw mode, so plain
                            // stderr is fine.
                            eprintln!("shuki: confirm login on your signing device…");
                            nsd.authenticate().await.map_err(|e| match e {
                                shuki::ShukiError::DeviceRejected => shuki::ShukiError::Device(
                                    "login rejected on the signing device".into(),
                                ),
                                e => e,
                            })?;
                            if config.device_auth_timeout_secs > 0 {
                                // Best effort: a marker write failure must not
                                // abort a successfully confirmed login.
                                if let Err(e) = session::record(&data_dir, &npub) {
                                    tracing::warn!("failed to record device session: {e}");
                                }
                            }
                        } else {
                            tracing::debug!("device session valid; skipping login challenge");
                        }
                    }
                    Arc::new(nsd)
                }
            };
            let store = Arc::new(FsVaultStore::open(&config.resolve_data_dir())?);
            let vault = Arc::new(VaultService::new(signer.clone(), store.clone()));
            let sync = Arc::new(SyncEngine::new(signer.clone(), store, config.clone()));
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
                None => {
                    let npub = signer
                        .public_key()
                        .await?
                        .to_bech32()
                        .expect("npub bech32 is infallible");
                    let signer_label = match config.signer {
                        SignerConfig::Software => "software",
                        SignerConfig::Nsd { .. } => "nsd",
                    };
                    let identity = Identity {
                        npub,
                        signer_label: signer_label.to_owned(),
                    };
                    shuki::tui::run(vault, sync, clipboard, config, identity).await
                }
            }
        }
    }
}
