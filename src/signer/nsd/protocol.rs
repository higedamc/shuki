//! Pure NSD wire codec — framing and response parsing, no IO
//! (owned by `leaf/signer-nsd-serial`).
//!
//! Wire format (lnbits/nostr-signing-device firmware): newline-delimited
//! ASCII lines over 9600-baud USB serial. Requests are `<cmd> [arg]`,
//! responses echo the command token: `"<cmd> <payload>"`. The device
//! interleaves unsolicited lines (informational logs, bare `/ping`), so the
//! reader must skip every line whose first token is not the awaited command.

use zeroize::Zeroizing;

use crate::error::{Result, ShukiError};

/// `/ping <token>` → `/ping 0 <deviceId>`.
pub const CMD_PING: &str = "/ping";
/// `/public-key` → `/public-key <64-hex x-only pubkey>`.
pub const CMD_PUBLIC_KEY: &str = "/public-key";
/// `/sign-message <64-hex event id>` → `/sign-message <128-hex schnorr sig>`
/// or `/sign-message Rejected` (physical button confirmation required).
pub const CMD_SIGN_MESSAGE: &str = "/sign-message";
/// `/shared-secret <64-hex pubkey>` → `/shared-secret <64-hex raw ECDH x>`.
pub const CMD_SHARED_SECRET: &str = "/shared-secret";

/// Firmware's rejection payload for `/sign-message`.
const REJECTED: &str = "Rejected";

// ---------------------------------------------------------------------------
// Request framing (no trailing newline — the transport appends it)
// ---------------------------------------------------------------------------

/// Frame a `/ping` request. The token is not echoed back by the firmware;
/// it only has to be a non-empty ASCII word.
pub fn frame_ping(token: &str) -> String {
    format!("{CMD_PING} {token}")
}

/// Frame a `/public-key` request.
pub fn frame_public_key() -> String {
    CMD_PUBLIC_KEY.to_string()
}

/// Frame a `/sign-message` request. `event_id_hex` must be the 64-hex event
/// id (sha256 of the serialized event); normalized to lowercase.
pub fn frame_sign_message(event_id_hex: &str) -> Result<String> {
    let id = validate_hex(event_id_hex, 64, "event id")?;
    Ok(format!("{CMD_SIGN_MESSAGE} {id}"))
}

/// Frame a `/shared-secret` request. `pubkey_hex` must be a 64-hex x-only
/// public key; normalized to lowercase.
pub fn frame_shared_secret(pubkey_hex: &str) -> Result<String> {
    let pk = validate_hex(pubkey_hex, 64, "public key")?;
    Ok(format!("{CMD_SHARED_SECRET} {pk}"))
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Match one received line against the awaited command.
///
/// Returns the payload when `line` is `"<expected_cmd> <payload>"`.
/// Returns `None` for anything to be skipped: log lines, unsolicited or
/// echoed other commands, bare command tokens without payload (e.g. the
/// device's unsolicited bare `/ping`), and empty lines.
pub fn parse_line<'a>(expected_cmd: &str, line: &'a str) -> Option<&'a str> {
    let line = line.trim();
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next()?;
    if cmd != expected_cmd {
        return None;
    }
    let payload = parts.next()?.trim();
    if payload.is_empty() {
        return None;
    }
    Some(payload)
}

/// Parse a `/ping` response payload `"0 <deviceId>"`.
///
/// Returns the device id (possibly empty when the firmware omits it), or
/// `None` when the payload does not look like a ping answer.
pub fn parse_ping_payload(payload: &str) -> Option<String> {
    let mut parts = payload.splitn(2, ' ');
    if parts.next()? != "0" {
        return None;
    }
    Some(parts.next().unwrap_or("").trim().to_string())
}

/// Parse a `/public-key` response payload into a lowercase 64-hex string.
pub fn parse_public_key_payload(payload: &str) -> Result<String> {
    validate_hex(payload, 64, "public key")
}

/// Outcome of a `/sign-message` round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    /// 128-hex BIP-340 schnorr signature (lowercase).
    Signature(String),
    /// The user rejected the request on the device.
    Rejected,
}

/// Parse a `/sign-message` response payload: either `Rejected` or a
/// 128-hex schnorr signature.
pub fn parse_sign_payload(payload: &str) -> Result<SignOutcome> {
    if payload.eq_ignore_ascii_case(REJECTED) {
        return Ok(SignOutcome::Rejected);
    }
    Ok(SignOutcome::Signature(validate_hex(
        payload,
        128,
        "schnorr signature",
    )?))
}

/// Parse a `/shared-secret` response payload (64-hex raw ECDH x-coordinate)
/// into zeroizing bytes. Error messages never contain the payload.
pub fn parse_shared_secret_payload(payload: &str) -> Result<Zeroizing<[u8; 32]>> {
    if payload.len() != 64 || !payload.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ShukiError::Device(
            "malformed shared-secret response from device".into(),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, chunk) in payload.as_bytes().chunks_exact(2).enumerate() {
        out[i] = hex_val(chunk[0]) << 4 | hex_val(chunk[1]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Nibble value of a validated ASCII hex digit.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => unreachable!("caller validated hex"),
    }
}

/// Require exactly `expected_len` hex chars; return lowercase. The offending
/// value is intentionally not included in the error message.
fn validate_hex(s: &str, expected_len: usize, what: &str) -> Result<String> {
    if s.len() == expected_len && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(ShukiError::Device(format!(
            "invalid {what}: expected {expected_len} hex chars"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const HEX128: &str = "908a15e46fb4d8675bab026fc230a0e3542bed13f8532bab614b3f74b2ed206c\
                          8020be9bbaf9a30decd5a5dcd6d874db31688f4e0287322d2b45bf2ac058ce53";

    #[test]
    fn framing_table() {
        assert_eq!(frame_ping("tok1"), "/ping tok1");
        assert_eq!(frame_public_key(), "/public-key");
        assert_eq!(
            frame_sign_message(HEX64).unwrap(),
            format!("/sign-message {HEX64}")
        );
        assert_eq!(
            frame_shared_secret(HEX64).unwrap(),
            format!("/shared-secret {HEX64}")
        );
        // Uppercase input is normalized to lowercase on the wire.
        assert_eq!(
            frame_sign_message(&HEX64.to_ascii_uppercase()).unwrap(),
            format!("/sign-message {HEX64}")
        );
    }

    #[test]
    fn framing_rejects_malformed_hex() {
        let bad: &[&str] = &[
            "",                            // empty
            "abcd",                        // too short
            &HEX64[..63],                  // one char short
            &format!("{HEX64}0"),          // one char long
            "zz\u{308}",                   // non-hex, non-ascii
            &format!("{}g", &HEX64[..63]), // non-hex char
        ];
        for input in bad {
            assert!(frame_sign_message(input).is_err(), "input: {input:?}");
            assert!(frame_shared_secret(input).is_err(), "input: {input:?}");
        }
    }

    #[test]
    fn parse_line_table() {
        // (expected_cmd, line, want)
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("/public-key", &format!("/public-key {HEX64}"), Some(HEX64)),
            // CRLF / whitespace tolerated
            (
                "/public-key",
                &format!("/public-key {HEX64}\r"),
                Some(HEX64),
            ),
            (
                "/public-key",
                &format!("  /public-key {HEX64}  "),
                Some(HEX64),
            ),
            // wrong command → skip
            ("/sign-message", &format!("/public-key {HEX64}"), None),
            // log/noise lines → skip
            ("/sign-message", "/log signing something", None),
            ("/sign-message", "device booted", None),
            // unsolicited bare /ping → skip even when awaiting /ping
            ("/ping", "/ping", None),
            ("/ping", "/ping 0 nsd-device", Some("0 nsd-device")),
            // bare awaited command without payload → skip
            ("/public-key", "/public-key", None),
            ("/public-key", "/public-key   ", None),
            // empty line → skip
            ("/public-key", "", None),
            ("/public-key", "\r", None),
            // rejection payload passes through
            ("/sign-message", "/sign-message Rejected", Some("Rejected")),
        ];
        for (cmd, line, want) in cases {
            assert_eq!(parse_line(cmd, line), *want, "cmd={cmd:?} line={line:?}");
        }
    }

    #[test]
    fn parse_ping_payload_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("0 nsd-abc123", Some("nsd-abc123")),
            ("0", Some("")),
            ("0 ", Some("")),
            ("1 nsd-abc123", None),
            ("pong", None),
            ("", None),
        ];
        for (payload, want) in cases {
            assert_eq!(
                parse_ping_payload(payload),
                want.map(str::to_string),
                "payload={payload:?}"
            );
        }
    }

    #[test]
    fn parse_public_key_payload_table() {
        assert_eq!(parse_public_key_payload(HEX64).unwrap(), HEX64);
        // uppercase normalized
        assert_eq!(
            parse_public_key_payload(&HEX64.to_ascii_uppercase()).unwrap(),
            HEX64
        );
        for bad in ["", "abcd", &HEX64[..63], "not-a-key"] {
            assert!(parse_public_key_payload(bad).is_err(), "input: {bad:?}");
        }
    }

    #[test]
    fn parse_sign_payload_table() {
        assert_eq!(
            parse_sign_payload(HEX128).unwrap(),
            SignOutcome::Signature(HEX128.to_string())
        );
        assert_eq!(
            parse_sign_payload(&HEX128.to_ascii_uppercase()).unwrap(),
            SignOutcome::Signature(HEX128.to_string())
        );
        assert_eq!(
            parse_sign_payload("Rejected").unwrap(),
            SignOutcome::Rejected
        );
        assert_eq!(
            parse_sign_payload("rejected").unwrap(),
            SignOutcome::Rejected
        );
        for bad in ["", HEX64, &HEX128[..127], "garbage"] {
            assert!(parse_sign_payload(bad).is_err(), "input: {bad:?}");
        }
    }

    #[test]
    fn parse_shared_secret_payload_roundtrip() {
        let x = parse_shared_secret_payload(HEX64).unwrap();
        assert_eq!(x[0], 0x3b);
        assert_eq!(x[31], 0x9d);
        // uppercase accepted
        let x2 = parse_shared_secret_payload(&HEX64.to_ascii_uppercase()).unwrap();
        assert_eq!(*x, *x2);
    }

    #[test]
    fn parse_shared_secret_payload_rejects_malformed() {
        for bad in ["", "abcd", &HEX64[..63], HEX128, "Rejected"] {
            let err = parse_shared_secret_payload(bad).unwrap_err();
            // Error message must not leak the payload.
            assert!(
                !err.to_string().contains(bad) || bad.is_empty(),
                "leaked: {bad:?}"
            );
        }
    }
}
