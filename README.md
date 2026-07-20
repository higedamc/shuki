# shuki

A `pass`-like, tree-structured password manager with **Nostr backup/sync** and
**hardware signer support** (NSD — Nostr Signing Device). CLI + TUI, written
in Rust. Simple, lightweight, robust.

```
shuki
├── bank
│   └── main
└── web
    ├── example.com
    └── github.com
```

## Feature summary

| | |
|---|---|
| Storage | tree of entries (password / username / url / notes / custom fields), **ciphertext-only on disk** |
| Encryption | NIP-44 v2 self-encryption (audited construction: secp256k1 ECDH → HKDF → ChaCha20 + HMAC-SHA256) |
| Backup / sync | per-entry Nostr events (NIP-78 `kind 30078`), multi-device, offline-first, last-write-wins |
| Key backends | OS keychain (macOS Keychain / Windows Credential Manager / Secret Service) **or NSD hardware signer** |
| Cold backup | NIP-49 `ncryptsec` export/import |
| Network | clearnet, SOCKS5 (external Tor), or embedded Tor (arti) via `--features tor` |
| Interfaces | pass-style CLI **and** full-featured TUI (ratatui) — feature parity between both |

## Install

```sh
cargo install --path .        # → ~/.cargo/bin/shuki
```

## Quick start

```sh
shuki init                     # generate a key into the OS keychain
shuki init --nsd               # …or use a Nostr Signing Device (autodetected)
shuki init --import-ncryptsec  # …or restore a NIP-49 cold backup
shuki relay add wss://your.relay

shuki generate web/example.com --username alice   # 24-char CSPRNG pw → clipboard
shuki show web/example.com     # prints the password (pass contract)
shuki show -c web/example.com  # copies instead; auto-clears after 45 s
shuki insert web/other.com     # prompted twice, never echoed
shuki ls                       # render the tree
shuki find bank                # substring search
shuki mv old/path new/path     # rename (tombstones the old path)
shuki rm web/other.com         # delete (deletion syncs to other devices)
shuki edit web/example.com     # field-by-field re-prompt (no $EDITOR tempfiles)

shuki sync                     # push dirty entries + pull remote changes
shuki restore                  # disaster recovery: rebuild vault from relays
shuki key export               # print NIP-49 ncryptsec cold backup
shuki whoami                   # identity, signer backend, config/data paths
shuki                          # no args → TUI
```

### TUI

The identity you are logged in with (npub + signer backend) is always shown
in the header. Press `?` for the full key reference.

| Key | Action |
|---|---|
| `j/k` `↑/↓` | navigate |
| `h/l` `←/→` | collapse / expand directory |
| `Enter` | open entry detail |
| `r` | reveal / hide password (masked by default) |
| `y` | copy password (auto-clears after TTL) |
| `/` | live search filter |
| `a` / `e` / `d` | add / edit / delete (with confirmation) |
| `m` | move / rename the selected entry |
| `Ctrl-g` | generate a password into the form's password field |
| `s` | sync with relays (report in the status bar) |
| `?` | help overlay |
| `q` | quit |

Config: `~/.config/shuki/config.json` (override: `SHUKI_CONFIG`).
Data: platform data dir + `/shuki` (override: `SHUKI_DATA_DIR`, or
`data_dir` in the config).

## How it works

### One key is the root of everything

Your Nostr identity (nsec) is the single root secret. From it:

- **Entry encryption** — the NIP-44 v2 *self* conversation key (ECDH with
  your own pubkey → HKDF-extract with salt `nip44-v2`). It is constant for
  an identity, so it is fetched **once** per session — important for the
  hardware backend, where it costs a device round-trip.
- **Event signing** — sync events are BIP-340-signed by the same key.
- **d-tag blinding** — a tag key is domain-separated from the conversation
  key (`HMAC-SHA256(ck, "shuki-tag-key-v1")`); each entry's public event
  identifier is `HMAC-SHA256(tag_key, path)`, so relays never learn your
  tree structure or entry names.

Restoring on a new machine therefore needs only the nsec (or plugging in
the NSD): fetch → try-decrypt → done.

### Signer backends

```
             ┌────────────────────────── Signer trait ─────────────────────────┐
             │  public_key · sign_event · self_conversation_key · nip44_* │
             └──────────────┬───────────────────────────┬──────────────────────┘
                SoftwareSigner                       NsdSigner
        nsec in the OS keychain            USB serial (9600 baud, line protocol)
        loaded per-op, zeroized            nsec NEVER touches the host:
        after use                          BIP-340 signing + ECDH on-device
```

**NSD** ([lnbits/nostr-signing-device](https://github.com/lnbits/nostr-signing-device)):
shuki speaks the device's serial protocol (`/public-key`, `/sign-message`,
`/shared-secret`, `/ping`). The firmware returns the **raw ECDH
x-coordinate**, which is exactly the NIP-44 HKDF input — the host-side
bridge is verified byte-identical to the standard `ConversationKey::derive`
by a test, so NSD mode is fully NIP-44 interoperable. Every signature
requires a physical button press; rejection and PIN-lock surface as
explicit errors.

**Login confirmation**: before opening the vault, shuki sends the NSD a
throwaway signature challenge (a never-published NIP-42-style event), so a
session requires an explicit button press on the device — a plugged-in NSD
cannot be used to decrypt the vault silently. On by default in NSD mode;
disable with `"device_auth_on_open": false` in the config (e.g. for
scripting).

### Sync protocol

Each entry is one **parameterized replaceable event**:

```
kind:    30078 (NIP-78 application data)
d tag:   hex(HMAC-SHA256(tag_key, path))          ← blinds the path
content: NIP-44( {"app":"shuki","v":1,"path":…,"fields":{…},
                  "updated_at":…,"deleted":…} )
```

- The local store keeps **exactly these ciphertext strings**
  (`store/<dtag>.nip44`, mode 0600, atomic writes) plus a non-secret
  `sync_state.json` — what is on disk is what is on the relay.
- **Deletes** publish an encrypted tombstone (`deleted:true`) under the same
  d-tag, replacing the live event — so deletions propagate and never
  resurrect.
- **Conflicts** resolve last-write-wins on the *encrypted* `updated_at`
  (never the spoofable event `created_at`), with a deterministic event-id
  tie-break. When the local side wins, it republishes with
  `created_at > remote's`, so relays actually replace.
- **Restore** needs no manifest: fetch all kind-30078 by author,
  try-decrypt, keep payloads with `app == "shuki"`. No single point of
  sync failure.
- Relay list: config + NIP-65 (`kind 10002`) publish/fetch.

### Tor

`config.net` selects `clearnet`, `socks5` (default `127.0.0.1:9050`,
works with a system Tor/Start9/Whonix-style setup), or `tor` — an
embedded [arti](https://gitlab.torproject.org/tpo/core/arti) client when
built with `cargo build --features tor`.

## Threat model

Hidden from relays and network observers: entry names, tree structure,
usernames, passwords, notes, custom fields (NIP-44 ciphertext; paths are
HMAC-blinded).

**Visible to relays** (accepted): your pubkey, entry count, per-entry
update timing, stable per-entry d-tags. Recommendation: use a dedicated
key for shuki (`shuki init` generates one) and Tor mode if network-level
privacy matters.

Local machine: plaintext exists only in process memory and is zeroized
after use (`zeroize`); nothing unencrypted is ever written to disk; files
are 0600 in 0700 dirs. The clipboard auto-clear writes an empty string
after the TTL and never clobbers newer copies, but clipboard-manager
history is out of shuki's control (`arboard` has no concealed-pasteboard
support).

Trezor was evaluated and **dropped for v1**: production firmware ships
Nostr signing (`NostrSignEvent`) in debug builds only, pending a new
derivation-path NIP. The `Signer` trait is ready for it the day it lands.

## Architecture

```
src/
├── domain/     VaultPath (validated), Entry/SecretField (zeroizing,
│               redacted Debug, const-time eq), VaultTree (pure)
├── crypto/     raw-ECDH→NIP-44 bridge · d-tag HMAC · CSPRNG passgen
├── signer/     Signer trait · software (keyring) · nsd (serial worker
│               thread + pure protocol codec + mock transport)
├── store/      VaultStore trait · fs impl (atomic, 0600, traversal guard)
├── vault/      VaultService: decrypt-on-open index, tombstones,
│               dirty tracking, monotonic updated_at
├── sync/       frozen wire schema · relay client (Tor/SOCKS5) ·
│               pure LWW reconcile · push/pull/restore · NIP-65
├── cli/        clap commands, config IO, prompts (rpassword)
└── tui/        ratatui, elm-style tested reducer, tree widget
```

Contract-first development: all traits and the wire schema were frozen
before implementation; each module was built and tested against them in
an isolated worktree (see `CLAUDE.md`).

## Testing

- **`cargo test`** — 170+ unit/integration tests, no network or hardware:
  crypto equivalence proofs (NSD bridge ≡ standard NIP-44), exhaustive
  LWW reconcile tables, NSD protocol against a scripted mock transport,
  store permission/traversal checks, CLI dispatch, TUI reducer + render.
- **`scripts/nsd_e2e.sh`** — full-stack E2E against a **fake NSD**
  (`examples/fake_nsd.rs`: real secp256k1 over a socat PTY): generate /
  show / ls / find / mv / rm through the device, plaintext-at-rest check.
- **Relay E2E** — `docker run --rm -d -p 7777:8080 scsibug/nostr-rs-relay`
  then `SHUKI_TEST_RELAY=ws://127.0.0.1:7777 cargo test --features
  relay-tests -- --ignored`: push→restore roundtrip, tombstone
  propagation. (Port 7000 is taken by AirPlay on macOS.)
- **Tor smoke** — `sync` verified through a local Tor SOCKS5 proxy against
  a public relay.

Gates on every change: `cargo build --all-targets && cargo test &&
cargo clippy --all-targets -- -D warnings && cargo fmt --check`,
`#![forbid(unsafe_code)]`.

## License

MIT
