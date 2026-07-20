//! NSD (Nostr Signing Device) signer (owned by `leaf/signer-nsd-serial`).
//!
//! Protocol (verified against lnbits/nostr-signing-device firmware):
//! USB serial 9600 baud, newline-delimited ASCII, responses echo the command:
//! `"<cmd> <payload>\n"`. Commands: `/public-key`, `/sign-message <hash>`
//! (BIP-340, physical confirmation, may return `Rejected`), `/shared-secret
//! <pubkey>` (raw ECDH x-coordinate), `/ping <tok>` → `/ping 0 <deviceId>`.
//! Informational log lines are interleaved and must be skipped.
//!
//! Design: a dedicated std thread owns the serial port; async methods talk to
//! it via mpsc + oneshot channels. Sign requests use a long timeout and the
//! caller is told to confirm on-device.

pub mod protocol;
pub mod transport;

use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use nostr::nips::nip44::v2::ConversationKey;
use nostr::nips::nip44::{self, v2 as nip44v2};
use nostr::secp256k1::schnorr::Signature;
use nostr::{Event, PublicKey, UnsignedEvent};
use tokio::sync::{mpsc, oneshot, OnceCell};
use zeroize::Zeroizing;

use crate::crypto::nip44_compat::conversation_key_from_shared_x;
use crate::error::{Result, ShukiError};
use crate::signer::{Signer, SignerKind};

use transport::SerialTransport;

/// Connect-time `/ping` handshake budget (device answers instantly when
/// unlocked and on the right port).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
/// `/ping`, `/public-key`, `/shared-secret` — no user interaction required.
const SHORT_TIMEOUT: Duration = Duration::from_secs(6);
/// `/sign-message` — the user must physically press the device button.
const SIGN_TIMEOUT: Duration = Duration::from_secs(120);

/// One wire round-trip handed to the serial worker thread.
struct WireRequest {
    /// Framed request line (no trailing newline).
    line: String,
    /// Command token the response must echo; other lines are skipped.
    expected_cmd: &'static str,
    timeout: Duration,
    /// Response payload (zeroizing: `/shared-secret` payloads are secret).
    reply: oneshot::Sender<Result<Zeroizing<String>>>,
}

/// [`Signer`] backed by a Nostr Signing Device on USB serial. The nsec never
/// touches the host; signing requires a physical button press.
pub struct NsdSigner {
    tx: mpsc::UnboundedSender<WireRequest>,
    device_pubkey: OnceCell<PublicKey>,
    self_conv_key: OnceCell<ConversationKey>,
}

impl NsdSigner {
    /// Connect to the device. `port == None` → autodetect: enumerate serial
    /// ports, `/ping` each with a short timeout.
    ///
    /// Performs the `/ping` handshake and prefetches + caches the device
    /// public key.
    pub async fn connect(port: Option<String>) -> Result<Self> {
        let (name, transport): (String, Box<dyn SerialTransport>) = match port {
            Some(p) => {
                let t = transport::open_port(&p)?;
                (p, t)
            }
            None => {
                let (n, t) = transport::autodetect(HANDSHAKE_TIMEOUT)?;
                (n, Box::new(t))
            }
        };
        tracing::debug!(port = %name, "nsd: serial port open");
        let signer = Self::with_transport(transport)?;
        signer.handshake().await?;
        let pk = signer.device_public_key().await?;
        tracing::debug!(pubkey = %pk, "nsd: connected");
        Ok(signer)
    }

    /// Build a signer over an arbitrary [`SerialTransport`] without any
    /// handshake. Test/advanced use — [`Self::connect`] is the normal entry
    /// point. The device public key is fetched lazily on first use.
    pub fn with_transport(transport: Box<dyn SerialTransport>) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        thread::Builder::new()
            .name("nsd-serial".into())
            .spawn(move || worker_loop(transport, rx))
            .map_err(|e| ShukiError::Device(format!("spawn serial worker: {e}")))?;
        Ok(Self {
            tx,
            device_pubkey: OnceCell::new(),
            self_conv_key: OnceCell::new(),
        })
    }

    /// Queue one round-trip on the worker thread and await its reply.
    async fn request(
        &self,
        line: String,
        expected_cmd: &'static str,
        timeout: Duration,
    ) -> Result<Zeroizing<String>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WireRequest {
                line,
                expected_cmd,
                timeout,
                reply: reply_tx,
            })
            .map_err(|_| ShukiError::Device("serial worker thread exited".into()))?;
        reply_rx
            .await
            .map_err(|_| ShukiError::Device("serial worker dropped the request".into()))?
    }

    /// `/ping` handshake with a short timeout.
    async fn handshake(&self) -> Result<()> {
        let token = ping_token();
        match self
            .request(
                protocol::frame_ping(&token),
                protocol::CMD_PING,
                HANDSHAKE_TIMEOUT,
            )
            .await
        {
            Ok(payload) => {
                let device_id = protocol::parse_ping_payload(&payload).ok_or_else(|| {
                    ShukiError::Device("malformed ping response from device".into())
                })?;
                tracing::debug!(device_id = %device_id, "nsd: ping handshake ok");
                Ok(())
            }
            Err(ShukiError::DeviceTimeout) => {
                tracing::warn!(
                    "NSD did not answer the ping handshake — device locked or wrong port?"
                );
                Err(ShukiError::DeviceTimeout)
            }
            Err(e) => Err(e),
        }
    }

    /// `/public-key`, fetched once and cached.
    async fn device_public_key(&self) -> Result<PublicKey> {
        let pk = self
            .device_pubkey
            .get_or_try_init(|| async {
                let payload = self
                    .request(
                        protocol::frame_public_key(),
                        protocol::CMD_PUBLIC_KEY,
                        SHORT_TIMEOUT,
                    )
                    .await?;
                let hex = protocol::parse_public_key_payload(&payload)?;
                PublicKey::from_hex(&hex).map_err(|e| {
                    ShukiError::Device(format!("device returned an invalid public key: {e}"))
                })
            })
            .await?;
        Ok(*pk)
    }

    /// `/shared-secret <peer>` → raw ECDH x-coordinate (zeroizing). The hex
    /// payload is zeroized when the request reply is dropped here.
    async fn shared_secret_x(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        let payload = self
            .request(
                protocol::frame_shared_secret(&peer.to_hex())?,
                protocol::CMD_SHARED_SECRET,
                SHORT_TIMEOUT,
            )
            .await?;
        protocol::parse_shared_secret_payload(&payload)
    }

    /// NIP-44 v2 conversation key for `peer`. The self key is served from
    /// the cache; other peers cost one `/shared-secret` round-trip.
    async fn conversation_key_for(&self, peer: &PublicKey) -> Result<ConversationKey> {
        if *peer == self.device_public_key().await? {
            return self.self_conversation_key().await;
        }
        let x = self.shared_secret_x(peer).await?;
        Ok(conversation_key_from_shared_x(&x))
    }
}

#[async_trait]
impl Signer for NsdSigner {
    fn kind(&self) -> SignerKind {
        SignerKind::Nsd
    }

    async fn public_key(&self) -> Result<PublicKey> {
        self.device_public_key().await
    }

    async fn sign_event(&self, mut unsigned: UnsignedEvent) -> Result<Event> {
        let device_pk = self.device_public_key().await?;
        if unsigned.pubkey != device_pk {
            return Err(ShukiError::Device(
                "event pubkey does not match the connected device".into(),
            ));
        }
        // Compute the event id if absent; the device signs exactly this hash.
        let id = unsigned.id();
        tracing::info!("confirm the signing request on the device");
        let payload = self
            .request(
                protocol::frame_sign_message(&id.to_hex())?,
                protocol::CMD_SIGN_MESSAGE,
                SIGN_TIMEOUT,
            )
            .await?;
        match protocol::parse_sign_payload(&payload)? {
            protocol::SignOutcome::Rejected => Err(ShukiError::DeviceRejected),
            protocol::SignOutcome::Signature(sig_hex) => {
                let sig: Signature = sig_hex.parse().map_err(|e| {
                    ShukiError::Device(format!("device returned an invalid signature: {e}"))
                })?;
                // `add_signature` verifies the schnorr signature against the id.
                let event = unsigned.add_signature(sig).map_err(|e| {
                    ShukiError::Device(format!("device signature failed verification: {e}"))
                })?;
                // Belt and braces: full event verification (id + signature).
                event.verify().map_err(|e| {
                    ShukiError::Device(format!("signed event failed verification: {e}"))
                })?;
                Ok(event)
            }
        }
    }

    async fn self_conversation_key(&self) -> Result<ConversationKey> {
        let ck = self
            .self_conv_key
            .get_or_try_init(|| async {
                let pk = self.device_public_key().await?;
                let x = self.shared_secret_x(&pk).await?;
                Ok::<_, ShukiError>(conversation_key_from_shared_x(&x))
            })
            .await?;
        Ok(*ck)
    }

    async fn nip44_encrypt(&self, peer: &PublicKey, plaintext: &[u8]) -> Result<String> {
        let ck = self.conversation_key_for(peer).await?;
        let bytes = nip44v2::encrypt_to_bytes(&ck, plaintext)
            .map_err(|e| ShukiError::Crypto(format!("nip44 encrypt: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    async fn nip44_decrypt(&self, peer: &PublicKey, payload: &str) -> Result<Zeroizing<Vec<u8>>> {
        let ck = self.conversation_key_for(peer).await?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| ShukiError::Crypto(format!("nip44 payload base64: {e}")))?;
        let version = *bytes
            .first()
            .ok_or_else(|| ShukiError::Crypto("nip44 payload is empty".into()))?;
        nip44::Version::try_from(version)
            .map_err(|e| ShukiError::Crypto(format!("nip44 payload: {e}")))?;
        let plaintext = nip44v2::decrypt_to_bytes(&ck, &bytes)
            .map_err(|e| ShukiError::Crypto(format!("nip44 decrypt: {e}")))?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Worker thread: owns the transport, serializes wire round-trips.
fn worker_loop(
    mut transport: Box<dyn SerialTransport>,
    mut rx: mpsc::UnboundedReceiver<WireRequest>,
) {
    while let Some(req) = rx.blocking_recv() {
        let result = run_request(transport.as_mut(), &req);
        // Receiver may have been dropped (caller cancelled); ignore.
        let _ = req.reply.send(result);
    }
    tracing::debug!("nsd: serial worker exiting");
}

/// One write + read-until-matching-echo round-trip with a deadline.
fn run_request(
    transport: &mut dyn SerialTransport,
    req: &WireRequest,
) -> Result<Zeroizing<String>> {
    transport.write_line(&req.line)?;
    let deadline = Instant::now() + req.timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ShukiError::DeviceTimeout);
        }
        match transport.read_line(remaining)? {
            None => return Err(ShukiError::DeviceTimeout),
            Some(line) => {
                // Wrap so unexpected secret-bearing lines are zeroized too.
                let line = Zeroizing::new(line);
                if let Some(payload) = protocol::parse_line(req.expected_cmd, &line) {
                    return Ok(Zeroizing::new(payload.to_string()));
                }
                // Content deliberately not logged: could carry secrets.
                tracing::trace!(
                    awaiting = req.expected_cmd,
                    "nsd: skipping interleaved line"
                );
            }
        }
    }
}

/// Ping token: uniqueness is irrelevant (the firmware does not echo it);
/// wall-clock millis keep it short and human-greppable in device logs.
fn ping_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{millis:x}")
}

#[cfg(test)]
mod tests {
    use super::protocol::{CMD_PUBLIC_KEY, CMD_SHARED_SECRET};
    use super::transport::{MockLine, MockTransport};
    use super::*;
    use nostr::{Keys, Kind, Timestamp};

    const SHARED_X_HEX: &str = "8e83dd852f7d4bf7b04b54810a0105a5261984fe574b3a5b748a09c1d024ba17";

    fn unsigned_event(keys: &Keys) -> UnsignedEvent {
        UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from(1_700_000_000u64),
            Kind::TextNote,
            [],
            "ciphertext",
        )
    }

    /// Script the `/public-key` exchange for `keys`' pubkey.
    fn public_key_exchange(keys: &Keys) -> (String, Vec<MockLine>) {
        (
            CMD_PUBLIC_KEY.to_string(),
            vec![MockLine::line(format!(
                "{CMD_PUBLIC_KEY} {}",
                keys.public_key().to_hex()
            ))],
        )
    }

    #[tokio::test]
    async fn handshake_ok_with_noise() {
        let mock = MockTransport::new().expect_prefix(
            "/ping ",
            vec![
                MockLine::line("firmware log line"),
                MockLine::line("/ping"), // unsolicited bare ping
                MockLine::line("/ping 0 nsd-dev-1"),
            ],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        signer.handshake().await.unwrap();
    }

    #[tokio::test]
    async fn handshake_timeout_maps_to_device_timeout() {
        let mock = MockTransport::new().expect_prefix("/ping ", vec![MockLine::Timeout]);
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(matches!(
            signer.handshake().await,
            Err(ShukiError::DeviceTimeout)
        ));
    }

    #[tokio::test]
    async fn public_key_is_fetched_once_and_cached() {
        let keys = Keys::generate();
        let (w, r) = public_key_exchange(&keys);
        // Script holds exactly ONE exchange: a second wire fetch would error.
        let mock = MockTransport::new().expect(w, r);
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        let pk1 = signer.public_key().await.unwrap();
        let pk2 = signer.public_key().await.unwrap();
        assert_eq!(pk1, keys.public_key());
        assert_eq!(pk1, pk2);
    }

    #[tokio::test]
    async fn sign_event_happy_path_with_noise() {
        let keys = Keys::generate();
        let unsigned = unsigned_event(&keys);
        // Pre-sign host-side to obtain a valid schnorr signature for the id.
        let expected = unsigned.clone().sign_with_keys(&keys).unwrap();
        let id_hex = unsigned.clone().id().to_hex();

        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("/sign-message {id_hex}"),
            vec![
                MockLine::line("/log please confirm on device"),
                MockLine::line("/ping"), // unsolicited
                MockLine::line(format!("{CMD_PUBLIC_KEY} deadbeef")), // wrong cmd echo
                MockLine::line(format!("/sign-message {}", expected.sig)),
            ],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        let event = signer.sign_event(unsigned).await.unwrap();
        assert_eq!(event.sig, expected.sig);
        assert_eq!(event.pubkey, keys.public_key());
        event.verify().unwrap();
    }

    #[tokio::test]
    async fn sign_event_rejected_on_device() {
        let keys = Keys::generate();
        let unsigned = unsigned_event(&keys);
        let id_hex = unsigned.clone().id().to_hex();
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("/sign-message {id_hex}"),
            vec![MockLine::line("/sign-message Rejected")],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(matches!(
            signer.sign_event(unsigned).await,
            Err(ShukiError::DeviceRejected)
        ));
    }

    #[tokio::test]
    async fn sign_event_timeout() {
        let keys = Keys::generate();
        let unsigned = unsigned_event(&keys);
        let id_hex = unsigned.clone().id().to_hex();
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new()
            .expect(w, r)
            .expect(format!("/sign-message {id_hex}"), vec![MockLine::Timeout]);
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(matches!(
            signer.sign_event(unsigned).await,
            Err(ShukiError::DeviceTimeout)
        ));
    }

    #[tokio::test]
    async fn sign_event_disconnect_maps_to_device_error() {
        let keys = Keys::generate();
        let unsigned = unsigned_event(&keys);
        let id_hex = unsigned.clone().id().to_hex();
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("/sign-message {id_hex}"),
            vec![MockLine::Disconnect],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(matches!(
            signer.sign_event(unsigned).await,
            Err(ShukiError::Device(_))
        ));
    }

    #[tokio::test]
    async fn sign_event_invalid_signature_from_device_fails_verification() {
        let keys = Keys::generate();
        let other = Keys::generate();
        let unsigned = unsigned_event(&keys);
        let id_hex = unsigned.clone().id().to_hex();
        // Well-formed but wrong signature: signs a DIFFERENT event id.
        let wrong_sig = unsigned_event(&other).sign_with_keys(&other).unwrap().sig;
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("/sign-message {id_hex}"),
            vec![MockLine::line(format!("/sign-message {wrong_sig}"))],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(matches!(
            signer.sign_event(unsigned).await,
            Err(ShukiError::Device(_))
        ));
    }

    #[tokio::test]
    async fn sign_event_rejects_foreign_pubkey_before_touching_the_wire() {
        let keys = Keys::generate();
        let other = Keys::generate();
        let (w, r) = public_key_exchange(&keys);
        // No /sign-message exchange scripted: reaching the wire would error
        // with "unexpected write", not the pubkey-mismatch message.
        let mock = MockTransport::new().expect(w, r);
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        let err = signer.sign_event(unsigned_event(&other)).await.unwrap_err();
        match err {
            ShukiError::Device(msg) => assert!(msg.contains("does not match")),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn shared_secret_plumbing_returns_zeroizing_x() {
        let keys = Keys::generate();
        let peer = Keys::generate().public_key();
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("{CMD_SHARED_SECRET} {}", peer.to_hex()),
            vec![
                MockLine::line("/log computing ecdh"),
                MockLine::line(format!("{CMD_SHARED_SECRET} {SHARED_X_HEX}")),
            ],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        // warm the pubkey cache to keep the script order deterministic
        signer.public_key().await.unwrap();
        let x = signer.shared_secret_x(&peer).await.unwrap();
        assert_eq!(x[0], 0x8e);
        assert_eq!(x[31], 0x17);
    }

    #[tokio::test]
    async fn worker_survives_a_failed_request() {
        let keys = Keys::generate();
        // First request times out; the next one succeeds on the same worker.
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new()
            .expect_prefix("/ping ", vec![MockLine::Timeout])
            .expect(w, r);
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        assert!(signer.handshake().await.is_err());
        assert_eq!(signer.public_key().await.unwrap(), keys.public_key());
    }

    #[tokio::test]
    async fn self_conversation_key_is_cached() {
        let keys = Keys::generate();
        let pk_hex = keys.public_key().to_hex();
        let (w, r) = public_key_exchange(&keys);
        // Exactly ONE /shared-secret exchange: a second fetch would error.
        let mock = MockTransport::new().expect(w, r).expect(
            format!("{CMD_SHARED_SECRET} {pk_hex}"),
            vec![MockLine::line(format!(
                "{CMD_SHARED_SECRET} {SHARED_X_HEX}"
            ))],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        let ck1 = signer.self_conversation_key().await.unwrap();
        let ck2 = signer.self_conversation_key().await.unwrap();
        assert_eq!(ck1.as_bytes(), ck2.as_bytes());
    }

    #[tokio::test]
    async fn nip44_self_roundtrip() {
        let keys = Keys::generate();
        let pk = keys.public_key();
        let (w, r) = public_key_exchange(&keys);
        let mock = MockTransport::new().expect(w, r).expect(
            format!("{CMD_SHARED_SECRET} {}", pk.to_hex()),
            vec![MockLine::line(format!(
                "{CMD_SHARED_SECRET} {SHARED_X_HEX}"
            ))],
        );
        let signer = NsdSigner::with_transport(mock.boxed()).unwrap();
        let payload = signer.nip44_encrypt(&pk, b"secret entry").await.unwrap();
        let plain = signer.nip44_decrypt(&pk, &payload).await.unwrap();
        assert_eq!(&*plain, b"secret entry");
    }
}
