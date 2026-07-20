# shuki — Nostr 同期型パスワードマネージャ

`pass` ライクなツリー構造のパスワードマネージャ (CLI + TUI)。Rust 製。
バックアップ/同期は Nostr リレー (kind 30078, NIP-44 自己暗号化, Tor 対応)。
秘密鍵は native keychain (SoftwareSigner) または NSD = Nostr Signing Device (NsdSigner) に隔離。

## 絶対原則

- **平文シークレットをディスクに書かない**。ローカルストアは NIP-44 暗号文のみ (`store/<dtag>.nip44`)
- 秘密を扱うバッファは `Zeroizing` / `SecretField`。`Debug` 出力・`tracing` ログに秘密を流さない
- `#![forbid(unsafe_code)]`
- nostr-sdk は `=0.44.1` に pin。API 名の検証は `tests/contracts_compile.rs` が担う

## アーキテクチャ

```
CLI (clap) ─┐
            ├─→ Vault trait ─→ Signer trait ─→ SoftwareSigner (keyring) / NsdSigner (serial 9600baud)
TUI (ratatui)┘       │
                     ├─→ VaultStore trait ─→ FsVaultStore (暗号文のみ, 0700/0600, atomic write)
                     └─→ SyncApi trait ──→ SyncEngine (nostr-sdk, LWW reconcile, NIP-65, Tor)
```

- 契約 (trait / 型 / wire スキーマ) は Phase 0 で凍結済み。変更には契約 PR が必要
- 自己暗号化 conversation key は起動時 1 回取得しキャッシュ (NSD 往復を最小化)
- wire スキーマ: `src/sync/payload.rs` の `SyncPayload` (`app:"shuki"`, `v:1`)。restore は author の kind 30078 全取得 → try-decrypt → app マジックでフィルタ
- 削除 = tombstone イベントで同一 d タグを置換。競合 = payload `updated_at` の LWW
- d タグ = hex(HMAC-SHA256(tag_key, path))。tag_key は conversation key から派生

## 開発ルール (Leaf Node 戦略)

- ブランチ: `leaf/<feature>-<layer>-<task>`、1 leaf = 1 worktree、担当ファイル以外に触らない
- leaf は Phase 0 契約 + `tests/common/MockSigner` のみに依存。他 leaf のモジュールを import しない
- CLI/TUI は `Arc<dyn Vault>` / `Arc<dyn SyncApi>` を引数で受ける。構築 (DI) は `main.rs` のみ
- 統合マージ順: crypto → store → signer → vault → sync → cli/tui
- コミット: higedamc 名義 (repo-local 設定済み)、GPG 署名は global 設定で有効

## ゲート (全 PR / コミット前)

```
cargo build --all-targets && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## テスト

- `cargo test` — 単体 + MockSigner/tempdir 統合テスト (ネットワーク・HW 不要)
- `cargo test --features relay-tests -- --ignored` — 要 docker ローカルリレー (`scsibug/nostr-rs-relay`)
- NSD 実機なし検証: NIP-44 等価性テスト (crypto) + `socat` PTY フェイクデバイス

## NSD プロトコル早見

USB シリアル 9600 baud、改行区切り ASCII、レスポンスはコマンド名エコー付き `"<cmd> <payload>\n"`:
- `/public-key` → x-only 64hex
- `/sign-message <32byte-hex>` → BIP-340 署名 (物理ボタン確認必須、拒否時 `Rejected`)
- `/shared-secret <pubkey-hex>` → **生の ECDH x 座標** (NIP-44 conversation key は host 側で HKDF-extract "nip44-v2")
- `/ping <tok>` → `/ping 0 <deviceId>`
- ログ行 (`/log ...` 等) が混在するためパーサは期待コマンド以外をスキップ
