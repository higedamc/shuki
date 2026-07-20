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

use crate::error::Result;

pub struct NsdSigner {
    _private: (),
}

impl NsdSigner {
    /// Connect to the device. `port == None` → autodetect: enumerate serial
    /// ports, `/ping` each with a short timeout.
    pub async fn connect(_port: Option<String>) -> Result<Self> {
        todo!("leaf/signer-nsd-serial")
    }
}
