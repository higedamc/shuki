# shuki

A `pass`-like, tree-structured password manager with **Nostr backup/sync** and
**hardware signer support** (NSD — Nostr Signing Device). CLI + TUI, written
in Rust.

```
shuki
├── bank
│   └── main
└── web
    ├── example.com
    └── github.com
```

## Design

- **One Nostr identity is the root of everything.** Entries are encrypted
  with NIP-44 v2 *self-encryption* (conversation key with your own pubkey);
  sync events are signed with the same key. Restoring on a new machine needs
  only your nsec (or your NSD).
- **Ciphertext-only at rest.** The local store holds exactly the NIP-44
  payload strings that get published to relays (`store/<dtag>.nip44`, 0600).
  Plaintext exists only in memory (zeroized after use) — never on disk.
- **Per-entry sync** via NIP-78 `kind 30078` parameterized replaceable
  events. The `d` tag is `HMAC-SHA256(tag_key, path)`, so relays never see
  your tree structure or entry names. Deletes propagate as encrypted
  tombstones; conflicts resolve last-write-wins on the encrypted
  `updated_at`.
- **Key backends**:
  - `software` — nsec in the OS keychain (macOS Keychain / Windows
    Credential Manager / Secret Service), loaded per-operation into
    zeroizing memory.
  - `nsd` — [Nostr Signing Device](https://github.com/lnbits/nostr-signing-device)
    over USB serial. The nsec **never touches the host**: BIP-340 signing
    and ECDH run on the device; the host builds the NIP-44 conversation key
    from the device-returned shared secret (verified byte-identical to the
    standard derivation).
- **Tor**: `clearnet`, `socks5` (external Tor, default `127.0.0.1:9050`), or
  embedded Tor via `cargo build --features tor` (arti).
- **NIP-49** `ncryptsec` export/import for cold backups of the software key.

## Usage

```sh
shuki init                     # generate a key into the OS keychain
shuki init --nsd               # or use a Nostr Signing Device
shuki init --import-ncryptsec  # or restore a NIP-49 backup
shuki relay add wss://your.relay
shuki generate web/example.com --username alice   # copies to clipboard
shuki show web/example.com     # prints the password (pass contract)
shuki show -c web/example.com  # copies instead (auto-clears after 45 s)
shuki insert web/other.com     # prompted, never echoed
shuki ls / find / mv / rm / edit
shuki sync                     # push + pull
shuki restore                  # disaster recovery: rebuild from relays
shuki key export               # NIP-49 ncryptsec cold backup
shuki                          # no args → TUI
```

TUI keys: `j/k` navigate, `h/l` fold, `Enter` detail, `r` reveal, `y` copy,
`/` search, `a` add, `e` edit, `d` delete, `s` sync, `q` quit.

Config lives at `~/.config/shuki/config.json` (`SHUKI_CONFIG` overrides),
data under the platform data dir (`SHUKI_DATA_DIR` overrides).

## Threat model (what relays & attackers see)

Hidden from relays: entry names, tree structure, usernames, passwords, notes
(all inside NIP-44 ciphertext; paths are HMAC-blinded d-tags).

**Visible to relays** (accepted metadata leakage): your pubkey, the number of
entries, per-entry update timing, and the stable d-tag of each entry. Use a
dedicated key for shuki (recommended — `shuki init` generates one) and Tor
mode if network-level privacy matters.

Clipboard: auto-clear only writes an empty string after the TTL; clipboard
managers (and macOS pasteboard history tools) may retain copies — shuki
cannot use the concealed-pasteboard type through `arboard`.

The NSD auto-confirms nothing: every signature requires a physical button
press. PIN-locked or unplugged devices surface as explicit errors.

## Development

```sh
cargo test                                   # unit + integration (no network/HW)
cargo clippy --all-targets -- -D warnings
scripts/nsd_e2e.sh                           # full-stack E2E vs a fake NSD (socat)
docker run --rm -d -p 7777:8080 scsibug/nostr-rs-relay
SHUKI_TEST_RELAY=ws://127.0.0.1:7777 \
  cargo test --features relay-tests -- --ignored   # relay E2E
```

`examples/fake_nsd.rs` speaks the NSD serial protocol with real secp256k1
over a PTY — no hardware needed. See `CLAUDE.md` for architecture and
contribution rules (Leaf Node development).

## License

MIT
