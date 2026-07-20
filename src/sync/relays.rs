//! nostr-sdk `Client` construction per [`crate::config::NetMode`] + NIP-65
//! helpers (owned by `leaf/sync-nostr-engine`).
//!
//! The client is ALWAYS built without a nostr-sdk signer: shuki never hands
//! keys to the SDK. Every event is pre-signed through our [`Signer`] trait and
//! published via `client.send_event(&event)`.

use std::time::Duration;

use nostr::nips::nip65;
use nostr::{EventBuilder, Filter, Kind, PublicKey, RelayUrl};
use nostr_sdk::client::Connection;
use nostr_sdk::{Client, ClientOptions};

use crate::config::{Config, NetMode};
use crate::error::{Result, ShukiError};
use crate::signer::Signer;

/// Timeout for relay fetches.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for at least one relay connection after `connect()`.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

/// Build a connected [`Client`] for `config.relays` honoring `config.net`.
///
/// Errors if no relays are configured. The returned client has NO signer —
/// callers publish pre-signed events only.
pub async fn build_client(config: &Config) -> Result<Client> {
    if config.relays.is_empty() {
        return Err(ShukiError::Config(
            "no relays configured; add at least one relay".into(),
        ));
    }

    let client = match &config.net {
        NetMode::Clearnet => Client::default(),
        NetMode::Socks5 { addr } => {
            let proxy = addr.parse().map_err(|e| {
                ShukiError::Config(format!("invalid socks5 proxy address {addr:?}: {e}"))
            })?;
            let conn = Connection::new().proxy(proxy);
            let opts = ClientOptions::new().connection(conn);
            Client::builder().opts(opts).build()
        }
        NetMode::Tor => embedded_tor_client()?,
    };

    for url in &config.relays {
        client
            .add_relay(url.as_str())
            .await
            .map_err(|e| ShukiError::Config(format!("invalid relay url {url:?}: {e}")))?;
    }
    client.connect().await;
    client.wait_for_connection(CONNECT_WAIT).await;
    Ok(client)
}

#[cfg(feature = "tor")]
fn embedded_tor_client() -> Result<Client> {
    let conn = Connection::new().embedded_tor();
    let opts = ClientOptions::new().connection(conn);
    Ok(Client::builder().opts(opts).build())
}

#[cfg(not(feature = "tor"))]
fn embedded_tor_client() -> Result<Client> {
    Err(ShukiError::Config(
        "embedded tor not compiled in; rebuild with --features tor or use socks5 mode".into(),
    ))
}

/// Publish our relay list as a NIP-65 kind-10002 event, signed by `signer`.
pub async fn publish_relay_list(
    client: &Client,
    signer: &dyn Signer,
    relays: &[String],
) -> Result<()> {
    let mut list: Vec<(RelayUrl, Option<nip65::RelayMetadata>)> = Vec::with_capacity(relays.len());
    for r in relays {
        let url = RelayUrl::parse(r)
            .map_err(|e| ShukiError::Config(format!("invalid relay url {r:?}: {e}")))?;
        list.push((url, None));
    }

    let pk = signer.public_key().await?;
    let unsigned = EventBuilder::relay_list(list).build(pk);
    let event = signer.sign_event(unsigned).await?;
    send_signed(client, &event).await
}

/// Fetch `author`'s NIP-65 relay list (kind 10002) and return the relay URLs.
/// Returns an empty vec when no relay list event is found.
pub async fn fetch_relay_list(client: &Client, author: PublicKey) -> Result<Vec<String>> {
    let filter = Filter::new().author(author).kind(Kind::RelayList).limit(1);
    let events = client
        .fetch_events(filter, FETCH_TIMEOUT)
        .await
        .map_err(|e| ShukiError::Relay(format!("fetch relay list: {e}")))?;
    let Some(event) = events.first() else {
        return Ok(Vec::new());
    };
    Ok(nip65::extract_relay_list(event)
        .map(|(url, _)| url.to_string())
        .collect())
}

/// Publish a pre-signed event, mapping "no relay accepted it" to an error.
pub async fn send_signed(client: &Client, event: &nostr::Event) -> Result<()> {
    let out = client
        .send_event(event)
        .await
        .map_err(|e| ShukiError::Relay(format!("send event: {e}")))?;
    if out.success.is_empty() {
        return Err(ShukiError::Relay(format!(
            "event accepted by no relay: {:?}",
            out.failed
        )));
    }
    Ok(())
}
