//! CLI unit tests: mock vault/sync, stub prompter, captured output.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use clap::CommandFactory as _;

use super::*;
use crate::domain::{Entry, EntryFields, VaultPath};
use crate::sync::SyncReport;

// ---------------------------------------------------------------- mocks

#[derive(Default)]
struct MockVault {
    entries: Mutex<HashMap<VaultPath, Entry>>,
}

impl MockVault {
    /// Entry at `p` with password `pw:<p>` and username `user`.
    fn with(paths: &[&str]) -> Self {
        let v = Self::default();
        for p in paths {
            let path = VaultPath::parse(p).unwrap();
            v.entries.lock().unwrap().insert(
                path.clone(),
                Entry {
                    path,
                    fields: EntryFields {
                        password: Some(SecretField::new(format!("pw:{p}"))),
                        username: Some("user".into()),
                        ..Default::default()
                    },
                    updated_at: 1,
                },
            );
        }
        v
    }
}

#[async_trait]
impl Vault for MockVault {
    async fn open(&self) -> Result<()> {
        Ok(())
    }

    async fn list_paths(&self) -> Result<Vec<VaultPath>> {
        let mut v: Vec<_> = self.entries.lock().unwrap().keys().cloned().collect();
        v.sort();
        Ok(v)
    }

    async fn get(&self, path: &VaultPath) -> Result<Entry> {
        self.entries
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| ShukiError::NotFound(path.to_string()))
    }

    async fn put(&self, entry: Entry) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(entry.path.clone(), entry);
        Ok(())
    }

    async fn remove(&self, path: &VaultPath) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| ShukiError::NotFound(path.to_string()))
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<()> {
        let mut m = self.entries.lock().unwrap();
        let mut e = m
            .remove(from)
            .ok_or_else(|| ShukiError::NotFound(from.to_string()))?;
        e.path = to.clone();
        m.insert(to.clone(), e);
        Ok(())
    }

    async fn find(&self, query: &str) -> Result<Vec<VaultPath>> {
        let q = query.to_lowercase();
        let mut v: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .keys()
            .filter(|p| p.as_str().to_lowercase().contains(&q))
            .cloned()
            .collect();
        v.sort();
        Ok(v)
    }
}

#[derive(Default)]
struct MockSyncApi {
    sync_calls: Mutex<u32>,
    restore_calls: Mutex<u32>,
}

#[async_trait]
impl SyncApi for MockSyncApi {
    async fn sync(&self) -> Result<SyncReport> {
        *self.sync_calls.lock().unwrap() += 1;
        Ok(SyncReport {
            pushed: 2,
            pulled: 1,
            tombstones_applied: 1,
            conflicts_lww: 0,
            errors: vec![("wss://r.example".into(), "timeout".into())],
        })
    }

    async fn restore_all(&self) -> Result<SyncReport> {
        *self.restore_calls.lock().unwrap() += 1;
        Ok(SyncReport {
            pulled: 5,
            ..Default::default()
        })
    }

    async fn publish_relay_list(&self) -> Result<()> {
        Ok(())
    }

    async fn fetch_relay_list(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

// ------------------------------------------------------------- prompter

#[derive(Default)]
struct StubPrompter {
    secrets: VecDeque<&'static str>,
    lines: VecDeque<&'static str>,
    confirms: VecDeque<bool>,
    multiline: VecDeque<&'static str>,
    interactive: bool,
}

impl Prompter for StubPrompter {
    fn prompt_secret(&mut self, _prompt: &str) -> Result<SecretField> {
        self.secrets
            .pop_front()
            .map(SecretField::from)
            .ok_or(ShukiError::Cancelled)
    }

    fn prompt_line(&mut self, _prompt: &str) -> Result<String> {
        self.lines
            .pop_front()
            .map(str::to_owned)
            .ok_or(ShukiError::Cancelled)
    }

    fn confirm(&mut self, _prompt: &str) -> Result<bool> {
        self.confirms.pop_front().ok_or(ShukiError::Cancelled)
    }

    fn read_multiline_secret(&mut self, _banner: &str) -> Result<SecretField> {
        self.multiline
            .pop_front()
            .map(SecretField::from)
            .ok_or(ShukiError::Cancelled)
    }

    fn is_interactive(&self) -> bool {
        self.interactive
    }
}

// -------------------------------------------------------------- helpers

fn ctx_with(vault: MockVault) -> AppContext {
    AppContext {
        vault: Arc::new(vault),
        sync: Arc::new(MockSyncApi::default()),
        clipboard: None,
        config: Config::default(),
    }
}

async fn run_capture(
    cmd: Command,
    ctx: &mut AppContext,
    prompter: &mut StubPrompter,
) -> (Result<()>, String) {
    let mut out: Vec<u8> = Vec::new();
    let res = {
        let mut ui = Ui {
            prompter,
            out: &mut out,
        };
        dispatch_with(cmd, ctx, &mut ui).await
    };
    (res, String::from_utf8(out).unwrap())
}

async fn run_standalone_capture(
    cmd: Command,
    config: &mut Config,
    prompter: &mut StubPrompter,
) -> (Result<()>, String) {
    let mut out: Vec<u8> = Vec::new();
    let res = {
        let mut ui = Ui {
            prompter,
            out: &mut out,
        };
        dispatch_standalone_with(cmd, config, &mut ui).await
    };
    (res, String::from_utf8(out).unwrap())
}

async fn get(ctx: &AppContext, path: &str) -> Result<Entry> {
    ctx.vault.get(&VaultPath::parse(path).unwrap()).await
}

// ------------------------------------------------------- parser surface

#[test]
fn cli_debug_assert() {
    Cli::command().debug_assert();
}

#[test]
fn needs_vault_matrix() {
    assert!(!needs_vault(&Command::Init {
        nsd: false,
        import_nsec: false,
        import_ncryptsec: false,
        relay: Vec::new(),
    }));
    assert!(!needs_vault(&Command::Key {
        cmd: KeyCmd::Export
    }));
    assert!(!needs_vault(&Command::Relay { cmd: RelayCmd::Ls }));
    assert!(needs_vault(&Command::Sync));
    assert!(needs_vault(&Command::Restore { yes: true }));
    assert!(needs_vault(&Command::Ls { path: None }));
    assert!(needs_vault(&Command::Show {
        path: "a".into(),
        clip: false
    }));
}

#[test]
fn parses_pass_like_invocations() {
    let cli = Cli::try_parse_from(["shuki", "show", "-c", "web/site"]).unwrap();
    match cli.command {
        Some(Command::Show { path, clip }) => {
            assert_eq!(path, "web/site");
            assert!(clip);
        }
        _ => panic!("wrong parse"),
    }
    let cli = Cli::try_parse_from(["shuki", "generate", "web/site"]).unwrap();
    match cli.command {
        Some(Command::Generate { length, .. }) => assert_eq!(length, 24),
        _ => panic!("wrong parse"),
    }
    let cli = Cli::try_parse_from(["shuki"]).unwrap();
    assert!(cli.command.is_none());
    assert!(Cli::try_parse_from(["shuki", "init", "--nsd", "--import-nsec"]).is_err());
}

// ------------------------------------------------------------ ls / find

#[tokio::test]
async fn ls_renders_full_tree() {
    let mut ctx = ctx_with(MockVault::with(&["web/github.com/alice", "bank/main"]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(Command::Ls { path: None }, &mut ctx, &mut p).await;
    res.unwrap();
    assert!(out.starts_with("shuki\n"), "got: {out}");
    assert!(out.contains("github.com"));
    assert!(out.contains("bank"));
}

#[tokio::test]
async fn ls_subtree_and_missing() {
    let mut ctx = ctx_with(MockVault::with(&["web/github.com/alice", "bank/main"]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Ls {
            path: Some("web".into()),
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.starts_with("web\n"));
    assert!(!out.contains("bank"));

    let (res, _) = run_capture(
        Command::Ls {
            path: Some("nope".into()),
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::NotFound(_))));
}

#[tokio::test]
async fn find_prints_matches_one_per_line() {
    let mut ctx = ctx_with(MockVault::with(&[
        "web/GitHub.com/alice",
        "web/example.com",
        "bank/main",
    ]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Find {
            query: "github".into(),
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert_eq!(out, "web/GitHub.com/alice\n");
}

// ----------------------------------------------------------------- show

#[tokio::test]
async fn show_prints_password_first_then_metadata() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Show {
            path: "bank/main".into(),
            clip: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.starts_with("pw:bank/main\n"), "got: {out}");
    assert!(out.contains("username: user"));
}

#[tokio::test]
async fn show_clip_without_clipboard_errors() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Show {
            path: "bank/main".into(),
            clip: true,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Clipboard(_))));
    assert!(!out.contains("pw:"), "password must not leak on error");
}

#[test]
fn format_entry_hides_password_when_copying() {
    let entry = Entry {
        path: VaultPath::parse("a").unwrap(),
        fields: EntryFields {
            password: Some(SecretField::from("s3cret")),
            username: Some("bob".into()),
            url: Some("https://example.com".into()),
            notes: Some(SecretField::from("line1\nline2")),
            ..Default::default()
        },
        updated_at: 1,
    };
    let with_pw = commands::entry_ops::format_entry(&entry, true);
    assert!(with_pw.starts_with("s3cret\n"));
    let without = commands::entry_ops::format_entry(&entry, false);
    assert!(!without.contains("s3cret"));
    for s in [
        "username: bob",
        "url: https://example.com",
        "notes:\nline1\nline2\n",
    ] {
        assert!(with_pw.contains(s));
        assert!(without.contains(s));
    }
}

// ------------------------------------------------------- insert / edit

#[tokio::test]
async fn insert_prompts_twice_and_stores() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter {
        secrets: VecDeque::from(["hunter2", "hunter2"]),
        ..Default::default()
    };
    let (res, out) = run_capture(
        Command::Insert {
            path: "new/one".into(),
            username: Some("bob".into()),
            url: None,
            multiline_notes: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.contains("Inserted new/one."));
    let e = get(&ctx, "new/one").await.unwrap();
    assert_eq!(e.fields.password.unwrap().expose(), "hunter2");
    assert_eq!(e.fields.username.as_deref(), Some("bob"));
    assert!(e.fields.notes.is_none());
}

#[tokio::test]
async fn insert_mismatch_gets_one_retry() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter {
        secrets: VecDeque::from(["a", "b", "c", "c"]),
        ..Default::default()
    };
    let (res, _) = run_capture(
        Command::Insert {
            path: "new/one".into(),
            username: None,
            url: None,
            multiline_notes: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    let e = get(&ctx, "new/one").await.unwrap();
    assert_eq!(e.fields.password.unwrap().expose(), "c");
}

#[tokio::test]
async fn insert_double_mismatch_cancels() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter {
        secrets: VecDeque::from(["a", "b", "c", "d"]),
        ..Default::default()
    };
    let (res, _) = run_capture(
        Command::Insert {
            path: "new/one".into(),
            username: None,
            url: None,
            multiline_notes: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Cancelled)));
    assert!(get(&ctx, "new/one").await.is_err());
}

#[tokio::test]
async fn insert_multiline_notes_reads_stdin() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter {
        secrets: VecDeque::from(["pw", "pw"]),
        multiline: VecDeque::from(["note line 1\nnote line 2\n"]),
        ..Default::default()
    };
    let (res, _) = run_capture(
        Command::Insert {
            path: "new/notes".into(),
            username: None,
            url: None,
            multiline_notes: true,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    let e = get(&ctx, "new/notes").await.unwrap();
    assert_eq!(
        e.fields.notes.unwrap().expose(),
        "note line 1\nnote line 2\n"
    );
}

#[tokio::test]
async fn edit_empty_keeps_nonempty_updates() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter {
        // username → "newuser", url → keep; password → keep, notes → keep.
        lines: VecDeque::from(["newuser", ""]),
        secrets: VecDeque::from(["", ""]),
        ..Default::default()
    };
    let (res, out) = run_capture(
        Command::Edit {
            path: "bank/main".into(),
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.contains("Updated bank/main."));
    let e = get(&ctx, "bank/main").await.unwrap();
    assert_eq!(e.fields.username.as_deref(), Some("newuser"));
    assert_eq!(e.fields.password.unwrap().expose(), "pw:bank/main");
    assert!(e.fields.url.is_none());
}

// -------------------------------------------------------------- rm / mv

#[tokio::test]
async fn rm_force_bypasses_confirmation_without_tty() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter::default(); // non-interactive, no scripted confirms
    let (res, out) = run_capture(
        Command::Rm {
            path: "bank/main".into(),
            force: true,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.contains("Removed bank/main."));
    assert!(get(&ctx, "bank/main").await.is_err());
}

#[tokio::test]
async fn rm_without_force_and_without_tty_cancels() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter::default();
    let (res, _) = run_capture(
        Command::Rm {
            path: "bank/main".into(),
            force: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Cancelled)));
    assert!(get(&ctx, "bank/main").await.is_ok());
}

#[tokio::test]
async fn rm_confirm_no_cancels_yes_deletes() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter {
        interactive: true,
        confirms: VecDeque::from([false, true]),
        ..Default::default()
    };
    let (res, _) = run_capture(
        Command::Rm {
            path: "bank/main".into(),
            force: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Cancelled)));
    let (res, _) = run_capture(
        Command::Rm {
            path: "bank/main".into(),
            force: false,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(get(&ctx, "bank/main").await.is_err());
}

#[tokio::test]
async fn mv_renames_entry() {
    let mut ctx = ctx_with(MockVault::with(&["bank/main"]));
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Mv {
            from: "bank/main".into(),
            to: "bank/primary".into(),
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(out.contains("Moved bank/main -> bank/primary."));
    assert!(get(&ctx, "bank/main").await.is_err());
    let e = get(&ctx, "bank/primary").await.unwrap();
    assert_eq!(e.fields.password.unwrap().expose(), "pw:bank/main");
}

// ------------------------------------------------------- sync / restore

#[tokio::test]
async fn sync_prints_report() {
    let sync_api = Arc::new(MockSyncApi::default());
    let mut ctx = AppContext {
        vault: Arc::new(MockVault::default()),
        sync: sync_api.clone(),
        clipboard: None,
        config: Config::default(),
    };
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(Command::Sync, &mut ctx, &mut p).await;
    res.unwrap();
    assert_eq!(*sync_api.sync_calls.lock().unwrap(), 1);
    assert!(out.contains("pushed: 2"));
    assert!(out.contains("pulled: 1"));
    assert!(out.contains("tombstones applied: 1"));
    assert!(out.contains("wss://r.example: timeout"));
}

#[tokio::test]
async fn restore_needs_yes_without_tty() {
    let sync_api = Arc::new(MockSyncApi::default());
    let mut ctx = AppContext {
        vault: Arc::new(MockVault::default()),
        sync: sync_api.clone(),
        clipboard: None,
        config: Config::default(),
    };
    let mut p = StubPrompter::default();
    let (res, _) = run_capture(Command::Restore { yes: false }, &mut ctx, &mut p).await;
    assert!(matches!(res, Err(ShukiError::Cancelled)));
    assert_eq!(*sync_api.restore_calls.lock().unwrap(), 0);

    let (res, out) = run_capture(Command::Restore { yes: true }, &mut ctx, &mut p).await;
    res.unwrap();
    assert_eq!(*sync_api.restore_calls.lock().unwrap(), 1);
    assert!(out.contains("pulled: 5"));
}

// ---------------------------------------------------------------- relay

#[tokio::test]
// Intentional: the std-mutex env lock serializes env-mutating tests; the
// mocked futures never actually suspend.
#[allow(clippy::await_holding_lock)]
async fn relay_add_ls_rm_roundtrip_persists() {
    let _g = crate::config::test_env_lock();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SHUKI_CONFIG", dir.path().join("config.json"));
    let mut config = Config::default();
    let mut p = StubPrompter::default();

    let add = |url: &str| Command::Relay {
        cmd: RelayCmd::Add { url: url.into() },
    };
    let (res, out) = run_standalone_capture(add("wss://relay.example"), &mut config, &mut p).await;
    res.unwrap();
    assert!(out.contains("Added relay wss://relay.example."));
    assert_eq!(Config::load().unwrap().relays, ["wss://relay.example"]);

    // Duplicate add is a no-op.
    let (res, out) = run_standalone_capture(add("wss://relay.example"), &mut config, &mut p).await;
    res.unwrap();
    assert!(out.contains("already configured"));
    assert_eq!(config.relays.len(), 1);

    let (res, out) =
        run_standalone_capture(Command::Relay { cmd: RelayCmd::Ls }, &mut config, &mut p).await;
    res.unwrap();
    assert_eq!(out, "wss://relay.example\n");

    let (res, _) = run_standalone_capture(
        Command::Relay {
            cmd: RelayCmd::Rm {
                url: "wss://relay.example".into(),
            },
        },
        &mut config,
        &mut p,
    )
    .await;
    res.unwrap();
    assert!(Config::load().unwrap().relays.is_empty());

    // Removing an unknown relay errors.
    let (res, _) = run_standalone_capture(
        Command::Relay {
            cmd: RelayCmd::Rm {
                url: "wss://nope.example".into(),
            },
        },
        &mut config,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::NotFound(_))));

    std::env::remove_var("SHUKI_CONFIG");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn relay_add_rejects_non_websocket_url() {
    let _g = crate::config::test_env_lock();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SHUKI_CONFIG", dir.path().join("config.json"));
    let mut config = Config::default();
    let mut p = StubPrompter::default();
    let (res, _) = run_standalone_capture(
        Command::Relay {
            cmd: RelayCmd::Add {
                url: "https://relay.example".into(),
            },
        },
        &mut config,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Config(_))));
    assert!(config.relays.is_empty());
    std::env::remove_var("SHUKI_CONFIG");
}

// ----------------------------------------------------- report formatting

#[test]
fn format_report_lists_errors_only_when_present() {
    let clean = SyncReport::default();
    let s = commands::sync_cmd::format_report(&clean);
    assert!(s.contains("pushed: 0"));
    assert!(!s.contains("error"));

    let with_errors = SyncReport {
        errors: vec![("d".into(), "boom".into())],
        ..Default::default()
    };
    let s = commands::sync_cmd::format_report(&with_errors);
    assert!(s.contains("1 error(s):"));
    assert!(s.contains("  d: boom"));
}

// ------------------------------------------------------------- generate

#[tokio::test]
#[ignore = "needs crypto leaf"]
async fn generate_no_clip_prints_password_and_stores() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter::default();
    let (res, out) = run_capture(
        Command::Generate {
            path: "gen/one".into(),
            length: 24,
            no_symbols: false,
            no_clip: true,
            username: None,
            url: None,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    res.unwrap();
    let printed = out.lines().next().unwrap().to_owned();
    assert_eq!(printed.chars().count(), 24);
    let e = get(&ctx, "gen/one").await.unwrap();
    assert_eq!(e.fields.password.unwrap().expose(), printed);
}

#[tokio::test]
async fn generate_without_clipboard_and_without_no_clip_errors() {
    let mut ctx = ctx_with(MockVault::default());
    let mut p = StubPrompter::default();
    let (res, _) = run_capture(
        Command::Generate {
            path: "gen/one".into(),
            length: 24,
            no_symbols: false,
            no_clip: false,
            username: None,
            url: None,
        },
        &mut ctx,
        &mut p,
    )
    .await;
    assert!(matches!(res, Err(ShukiError::Clipboard(_))));
    // Nothing stored: the command failed before generating.
    assert!(get(&ctx, "gen/one").await.is_err());
}
