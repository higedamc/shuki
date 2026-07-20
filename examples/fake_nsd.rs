//! A fake Nostr Signing Device for end-to-end testing without hardware.
//!
//! Speaks the NSD serial protocol over a PTY (create a pair with e.g.
//! `socat pty,raw,echo=0,link=/tmp/nsd-app pty,raw,echo=0,link=/tmp/nsd-dev`),
//! performing REAL secp256k1 operations (BIP-340 signing, ECDH) with a
//! process-local test key — so the full shuki stack (serial transport,
//! protocol codec, NIP-44 bridge) can be exercised against it.
//!
//! Usage: `cargo run --example fake_nsd -- <pty-path> [nsec-hex-or-bech32]`
//! Without a key argument a fresh one is generated; the npub is printed.
//! NEVER use this with a real key: it auto-confirms every signing request.

use std::io::{BufRead, BufReader, Write};

use nostr::secp256k1::ecdh::shared_secret_point;
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::{Keypair, Message, Parity, PublicKey as FullPublicKey, Secp256k1};
use nostr::{Keys, SecretKey, ToBech32};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: fake_nsd <pty-path> [nsec]");
        std::process::exit(2);
    });
    let keys = match args.next() {
        Some(k) => Keys::new(SecretKey::parse(&k).expect("invalid key argument")),
        None => Keys::generate(),
    };
    eprintln!(
        "fake_nsd: serving {} as {}",
        path,
        keys.public_key().to_bech32().expect("bech32")
    );

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open pty");
    let mut writer = dev.try_clone().expect("clone pty handle");
    let reader = BufReader::new(dev);

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, keys.secret_key());
    let pubkey_hex = keys.public_key().to_hex();

    // Unsolicited noise on connect — clients must skip it.
    let _ = writeln!(writer, "/log fake-nsd ready");

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("fake_nsd: read error: {e}");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or_default();
        let arg = parts.next().unwrap_or_default().trim();
        eprintln!("fake_nsd: <- {cmd}");

        let reply: String = match cmd {
            "/ping" => "/ping 0 fake-nsd-e2e".to_string(),
            "/public-key" => format!("/public-key {pubkey_hex}"),
            "/sign-message" => match hex32(arg) {
                Some(digest) => {
                    let msg = Message::from_digest(digest);
                    let sig: Signature = secp.sign_schnorr(&msg, &keypair);
                    format!("/sign-message {sig}")
                }
                None => "/sign-message Rejected".to_string(),
            },
            "/shared-secret" => match hex32(arg) {
                Some(pk_bytes) => match x_only_to_full(&pk_bytes) {
                    Some(full) => {
                        let point = shared_secret_point(&full, keys.secret_key());
                        let x_hex: String =
                            point[..32].iter().map(|b| format!("{b:02x}")).collect();
                        format!("/shared-secret {x_hex}")
                    }
                    None => "/log invalid pubkey".to_string(),
                },
                None => "/log invalid pubkey".to_string(),
            },
            _ => continue,
        };
        eprintln!(
            "fake_nsd: -> {}",
            reply.split(' ').next().unwrap_or_default()
        );
        if writeln!(writer, "{reply}").is_err() {
            break;
        }
    }
    eprintln!("fake_nsd: peer closed, exiting");
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

fn x_only_to_full(x: &[u8; 32]) -> Option<FullPublicKey> {
    let xonly = nostr::secp256k1::XOnlyPublicKey::from_slice(x).ok()?;
    Some(FullPublicKey::from_x_only_public_key(xonly, Parity::Even))
}
