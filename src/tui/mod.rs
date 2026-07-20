//! Ratatui TUI (owned by `leaf/tui-ratatui-app`).
//!
//! Elm-style architecture: a std input thread and spawned tokio tasks post
//! [`AppMsg`]s into one mpsc channel; the pure-ish [`update`] reducer mutates
//! [`AppState`] and returns [`Effect`]s; the main loop executes effects by
//! spawning tasks (never blocking the draw loop). Left tree pane
//! (tui-tree-widget, identifiers = full path strings) + right detail pane.
//! Keys: `/` search, `y` copy (auto-clear), `a` add, `e` edit, `d` delete
//! (confirm), `s` sync, `t` network mode, `q` quit. Secrets render only after
//! explicit reveal. Panic hook AND a Drop guard restore the terminal.

pub mod actions;
pub mod event;
pub mod ui;
pub mod widgets;

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::KeyEvent;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::Terminal;
use tokio::sync::mpsc;
use tui_tree_widget::{TreeItem, TreeState};

use crate::clipboard::Clipboard;
use crate::config::{Config, NetMode};
use crate::domain::{Entry, VaultPath, VaultTree};
use crate::error::ShukiError;
use crate::sync::{SyncApi, SyncReport};
use crate::vault::Vault;
use crate::Result;

use actions::Action;
pub use widgets::{FormState, NetChoice, NetworkState, RenameState};

/// The logged-in identity, shown in the header (shortened) and in the help
/// overlay (full). Built by `main.rs` from the signer.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Full bech32 npub.
    pub npub: String,
    /// Short signer backend label, e.g. "software" or "nsd".
    pub signer_label: String,
}

/// UI mode (drives the keymap and the right pane).
#[derive(Debug)]
pub enum Mode {
    Browse,
    /// Live search; the string is the current query.
    Search(String),
    /// Entry detail view; `reveal` is per-view and resets on leave.
    Detail {
        reveal: bool,
    },
    /// Add/edit form.
    Form(FormState),
    /// Waiting for `y`/`n` on deleting this path.
    ConfirmDelete(VaultPath),
    /// Move/rename input overlay.
    Rename(RenameState),
    /// Network-mode overlay (`t`): pick clearnet / socks5 / embedded tor,
    /// check relay connectivity.
    Network(NetworkState),
    /// Full-screen help overlay; closing restores the boxed previous mode.
    Help(Box<Mode>),
    /// A background task is running; the label is shown with a spinner.
    Busy(String),
    Error(String),
}

/// Messages consumed by [`update`].
#[derive(Debug)]
pub enum AppMsg {
    Key(KeyEvent),
    Resize,
    /// Spinner tick from the input thread's poll timeout.
    Tick,
    TaskDone(TaskResult),
}

/// Result of a completed background task.
#[derive(Debug)]
pub enum TaskResult {
    Entries(Result<Vec<VaultPath>>),
    Entry(Result<Entry>),
    Saved(Result<()>, VaultPath),
    Deleted(Result<()>, VaultPath),
    Renamed(Result<()>, VaultPath, VaultPath),
    Synced(Result<SyncReport>),
    Copied(Result<()>),
    /// Network mode applied (config saved + engine switched).
    NetModeSet(Result<()>, NetMode),
    /// Relay connectivity report: (relay url, error-or-None) per relay.
    NetChecked(Result<Vec<(String, Option<String>)>>),
    /// Device login-session marker cleared (Ctrl-l).
    SessionLocked(Result<()>),
}

/// Side effects requested by [`update`]; executed by [`Executor::spawn`].
#[derive(Debug, PartialEq)]
pub enum Effect {
    LoadEntries,
    LoadEntry(VaultPath),
    SaveEntry(Entry),
    DeleteEntry(VaultPath),
    RenameEntry(VaultPath, VaultPath),
    RunSync,
    CopyPassword(VaultPath),
    /// Persist `net` to the config file (spawn_blocking) and switch the
    /// running sync engine via [`SyncApi::set_net_mode`].
    SetNetMode(NetMode),
    /// Probe every configured relay via [`SyncApi::net_check`].
    NetCheck,
    /// Clear the device login-session marker in this data dir
    /// (spawn_blocking). The running process keeps its in-memory
    /// conversation key — locking affects the next process start.
    LockSession(PathBuf),
    Quit,
}

/// What to do with the entry currently being loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Detail,
    Edit,
}

/// All UI state. No IO happens here.
pub struct AppState {
    /// Full unfiltered tree.
    pub tree: VaultTree,
    /// Currently displayed (possibly filtered) tree.
    pub visible: VaultTree,
    /// Accepted search filter (survives leaving search mode).
    pub filter: Option<String>,
    /// Tree items built from `visible`; identifiers are full path strings.
    pub items: Vec<TreeItem<'static, String>>,
    pub tree_state: TreeState<String>,
    pub mode: Mode,
    pending: Option<Pending>,
    /// Entry shown in Detail (also kept while editing).
    pub current: Option<Entry>,
    /// Last status-bar message.
    pub status: String,
    pub spinner_frame: usize,
    /// Logged-in identity (header + help overlay).
    pub identity: Identity,
    /// App config (net mode shown in the header; the saved file stays
    /// authoritative — [`Effect::SetNetMode`] re-loads + saves it).
    pub config: Config,
    /// Number of configured relays (sync guard + help overlay).
    pub relay_count: usize,
    pub clipboard_available: bool,
    pub clipboard_clear_secs: u64,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(identity: Identity, config: Config, clipboard_available: bool) -> Self {
        Self {
            tree: VaultTree::default(),
            visible: VaultTree::default(),
            filter: None,
            items: Vec::new(),
            tree_state: TreeState::default(),
            mode: Mode::Busy("loading vault".into()),
            pending: None,
            current: None,
            status: String::new(),
            spinner_frame: 0,
            identity,
            relay_count: config.relays.len(),
            clipboard_available,
            clipboard_clear_secs: config.clipboard_clear_secs,
            config,
            should_quit: false,
        }
    }

    /// Path of the selected tree node (entry or directory).
    fn selected_path(&self) -> Option<VaultPath> {
        self.tree_state
            .selected()
            .last()
            .and_then(|s| VaultPath::parse(s).ok())
    }

    /// Selected node's path, only if it is an actual entry.
    pub fn selected_entry(&self) -> Option<VaultPath> {
        self.selected_path()
            .filter(|p| self.visible.paths().binary_search(p).is_ok())
    }

    /// The query currently narrowing the tree (live search wins over an
    /// accepted filter).
    fn active_query(&self) -> Option<String> {
        match &self.mode {
            Mode::Search(q) => (!q.is_empty()).then(|| q.clone()),
            _ => self.filter.clone(),
        }
    }

    /// Rebuild `visible` + `items` from `tree` and `query`; keep the
    /// selection valid. Filtering auto-expands all matched directories.
    fn apply_filter(&mut self, query: Option<&str>) {
        self.visible = match query {
            Some(q) if !q.is_empty() => self.tree.filter(q),
            _ => self.tree.clone(),
        };
        self.items = build_items(&self.visible);
        if query.is_some_and(|q| !q.is_empty()) {
            for path in self.visible.paths() {
                let chain = id_chain(path);
                for depth in 1..chain.len() {
                    self.tree_state.open(chain[..depth].to_vec());
                }
            }
        }
        let ids: Vec<Vec<String>> = self
            .tree_state
            .flatten(&self.items)
            .into_iter()
            .map(|f| f.identifier)
            .collect();
        if !ids
            .iter()
            .any(|id| id.as_slice() == self.tree_state.selected())
        {
            self.tree_state
                .select(ids.first().cloned().unwrap_or_default());
        }
    }
}

/// Short header/status tag for a [`NetMode`]: `clearnet` / `socks5:9050` /
/// `tor(embedded)`.
pub(crate) fn net_tag(net: &NetMode) -> String {
    match net {
        NetMode::Clearnet => "clearnet".to_owned(),
        NetMode::Socks5 { addr } => {
            let port = addr.rsplit(':').next().unwrap_or(addr.as_str());
            format!("socks5:{port}")
        }
        NetMode::Tor => "tor(embedded)".to_owned(),
    }
}

/// Identifier chain from the root to `path` (each element a full path prefix).
fn id_chain(path: &VaultPath) -> Vec<String> {
    let mut chain = Vec::new();
    let mut acc = String::new();
    for seg in path.segments() {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        chain.push(acc.clone());
    }
    chain
}

/// Build tree-widget items from a [`VaultTree`]; identifiers are full paths.
fn build_items(tree: &VaultTree) -> Vec<TreeItem<'static, String>> {
    #[derive(Default)]
    struct Node {
        children: BTreeMap<String, Node>,
    }
    let mut root = Node::default();
    for path in tree.paths() {
        let mut node = &mut root;
        for seg in path.segments() {
            node = node.children.entry(seg.to_owned()).or_default();
        }
    }
    fn to_items(node: &Node, prefix: &str) -> Vec<TreeItem<'static, String>> {
        node.children
            .iter()
            .map(|(name, child)| {
                let full = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let kids = to_items(child, &full);
                if kids.is_empty() {
                    TreeItem::new_leaf(full, name.clone())
                } else {
                    TreeItem::new(full, name.clone(), kids)
                        .expect("BTreeMap keys yield unique identifiers")
                }
            })
            .collect()
    }
    to_items(&root, "")
}

/// Move the tree selection by `delta` over the currently visible rows.
/// Render-independent (uses `TreeState::flatten`, not the last render).
fn move_selection(state: &mut AppState, delta: isize) {
    let ids: Vec<Vec<String>> = state
        .tree_state
        .flatten(&state.items)
        .into_iter()
        .map(|f| f.identifier)
        .collect();
    if ids.is_empty() {
        return;
    }
    let current = ids
        .iter()
        .position(|id| id.as_slice() == state.tree_state.selected());
    let next = match (current, delta >= 0) {
        (None, true) => 0,
        (None, false) => ids.len() - 1,
        (Some(i), true) => (i + delta.unsigned_abs()).min(ids.len() - 1),
        (Some(i), false) => i.saturating_sub(delta.unsigned_abs()),
    };
    state.tree_state.select(ids[next].clone());
}

/// The reducer: applies one message and returns the effects to run.
/// Pure-ish (no IO) — this is what unit tests drive.
pub fn update(state: &mut AppState, msg: AppMsg) -> Vec<Effect> {
    match msg {
        AppMsg::Tick => {
            if matches!(state.mode, Mode::Busy(_)) {
                state.spinner_frame = state.spinner_frame.wrapping_add(1);
            }
            Vec::new()
        }
        AppMsg::Resize => Vec::new(),
        AppMsg::Key(key) => match actions::action_for(&state.mode, key) {
            Some(action) => apply_action(state, action),
            None => Vec::new(),
        },
        AppMsg::TaskDone(result) => apply_task(state, result),
    }
}

fn apply_action(state: &mut AppState, action: Action) -> Vec<Effect> {
    match action {
        Action::Quit => {
            state.should_quit = true;
            vec![Effect::Quit]
        }
        Action::NavDown => {
            move_selection(state, 1);
            Vec::new()
        }
        Action::NavUp => {
            move_selection(state, -1);
            Vec::new()
        }
        Action::Collapse => {
            state.tree_state.key_left();
            Vec::new()
        }
        Action::Expand => {
            state.tree_state.key_right();
            Vec::new()
        }
        Action::OpenDetail => match state.selected_entry() {
            Some(path) => {
                state.pending = Some(Pending::Detail);
                state.mode = Mode::Busy("loading entry".into());
                vec![Effect::LoadEntry(path)]
            }
            None => {
                state.tree_state.toggle_selected();
                Vec::new()
            }
        },
        Action::StartSearch => {
            state.mode = Mode::Search(String::new());
            state.apply_filter(None);
            Vec::new()
        }
        Action::SearchInput(c) => {
            if let Mode::Search(q) = &mut state.mode {
                q.push(c);
                let q = q.clone();
                state.apply_filter(Some(&q));
            }
            Vec::new()
        }
        Action::SearchBackspace => {
            if let Mode::Search(q) = &mut state.mode {
                q.pop();
                let q = q.clone();
                state.apply_filter(Some(&q));
            }
            Vec::new()
        }
        Action::SearchAccept => {
            if let Mode::Search(q) = &state.mode {
                state.filter = (!q.is_empty()).then(|| q.clone());
            }
            state.mode = Mode::Browse;
            Vec::new()
        }
        Action::SearchCancel => {
            state.filter = None;
            state.mode = Mode::Browse;
            state.apply_filter(None);
            Vec::new()
        }
        Action::CopyPassword => {
            let path = match &state.mode {
                Mode::Detail { .. } => state.current.as_ref().map(|e| e.path.clone()),
                _ => state.selected_entry(),
            };
            match path {
                None => {
                    state.status = "no entry selected".into();
                    Vec::new()
                }
                Some(_) if !state.clipboard_available => {
                    state.status = "clipboard unavailable".into();
                    Vec::new()
                }
                Some(path) => vec![Effect::CopyPassword(path)],
            }
        }
        Action::StartAdd => {
            state.mode = Mode::Form(FormState::new_add());
            Vec::new()
        }
        Action::StartEdit => match state.selected_entry() {
            Some(path) => {
                state.pending = Some(Pending::Edit);
                state.mode = Mode::Busy("loading entry".into());
                vec![Effect::LoadEntry(path)]
            }
            None => {
                state.status = "no entry selected".into();
                Vec::new()
            }
        },
        Action::StartDelete => {
            match state.selected_entry() {
                Some(path) => state.mode = Mode::ConfirmDelete(path),
                None => state.status = "no entry selected".into(),
            }
            Vec::new()
        }
        Action::StartSync => {
            if state.relay_count == 0 {
                state.mode = Mode::Error(
                    "no relays configured — add one with: shuki relay add wss://…".into(),
                );
                return Vec::new();
            }
            state.mode = Mode::Busy("syncing".into());
            vec![Effect::RunSync]
        }
        Action::LockSession => {
            vec![Effect::LockSession(state.config.resolve_data_dir())]
        }
        Action::ToggleReveal => {
            if let Mode::Detail { reveal } = &mut state.mode {
                *reveal = !*reveal;
            }
            Vec::new()
        }
        Action::ConfirmYes => match std::mem::replace(&mut state.mode, Mode::Browse) {
            Mode::ConfirmDelete(path) => {
                state.mode = Mode::Busy("deleting".into());
                vec![Effect::DeleteEntry(path)]
            }
            other => {
                state.mode = other;
                Vec::new()
            }
        },
        Action::ConfirmNo => {
            state.mode = Mode::Browse;
            Vec::new()
        }
        Action::FormInput(c) => {
            if let Mode::Form(form) = &mut state.mode {
                form.input(c);
            }
            Vec::new()
        }
        Action::FormBackspace => {
            if let Mode::Form(form) = &mut state.mode {
                form.backspace();
            }
            Vec::new()
        }
        Action::FormNext => {
            if let Mode::Form(form) = &mut state.mode {
                form.next();
            }
            Vec::new()
        }
        Action::FormPrev => {
            if let Mode::Form(form) = &mut state.mode {
                form.prev();
            }
            Vec::new()
        }
        Action::FormSubmit => {
            if let Mode::Form(form) = &state.mode {
                match form.build_entry() {
                    Ok(entry) => {
                        state.mode = Mode::Busy("saving".into());
                        return vec![Effect::SaveEntry(entry)];
                    }
                    Err(msg) => state.status = format!("invalid: {msg}"),
                }
            }
            Vec::new()
        }
        Action::FormGeneratePassword => {
            if let Mode::Form(form) = &mut state.mode {
                if form.focus == widgets::FormFocus::Password {
                    match crate::crypto::passgen::generate(
                        &crate::crypto::passgen::PassSpec::default(),
                    ) {
                        Ok(password) => {
                            form.set_password(password.expose());
                            state.status = "generated 24-char password — Ctrl-g regenerates".into();
                        }
                        Err(e) => state.status = format!("generate failed: {e}"),
                    }
                }
            }
            Vec::new()
        }
        Action::OpenHelp => {
            let prev = std::mem::replace(&mut state.mode, Mode::Browse);
            state.mode = Mode::Help(Box::new(prev));
            Vec::new()
        }
        Action::CloseHelp => {
            if let Mode::Help(prev) = std::mem::replace(&mut state.mode, Mode::Browse) {
                state.mode = *prev;
            }
            Vec::new()
        }
        Action::StartRename => {
            let path = match &state.mode {
                Mode::Detail { .. } => state.current.as_ref().map(|e| e.path.clone()),
                _ => state.selected_entry(),
            };
            match path {
                Some(from) => state.mode = Mode::Rename(RenameState::new(from)),
                None => state.status = "no entry selected".into(),
            }
            Vec::new()
        }
        Action::RenameInput(c) => {
            if let Mode::Rename(rename) = &mut state.mode {
                rename.input(c);
            }
            Vec::new()
        }
        Action::RenameBackspace => {
            if let Mode::Rename(rename) = &mut state.mode {
                rename.backspace();
            }
            Vec::new()
        }
        Action::RenameSubmit => {
            if let Mode::Rename(rename) = &state.mode {
                match VaultPath::parse(rename.to.trim()) {
                    Ok(to) => {
                        let from = rename.from.clone();
                        state.mode = Mode::Busy("renaming".into());
                        return vec![Effect::RenameEntry(from, to)];
                    }
                    Err(e) => state.mode = Mode::Error(format!("invalid path: {e}")),
                }
            }
            Vec::new()
        }
        Action::RenameCancel => {
            state.current = None;
            state.mode = Mode::Browse;
            Vec::new()
        }
        Action::OpenNetwork => {
            state.mode = Mode::Network(NetworkState::new(&state.config.net));
            Vec::new()
        }
        Action::NetSelectDown => {
            if let Mode::Network(net) = &mut state.mode {
                net.select_next();
            }
            Vec::new()
        }
        Action::NetSelectUp => {
            if let Mode::Network(net) = &mut state.mode {
                net.select_prev();
            }
            Vec::new()
        }
        Action::NetInput(c) => {
            if let Mode::Network(net) = &mut state.mode {
                net.input(c);
            }
            Vec::new()
        }
        Action::NetBackspace => {
            if let Mode::Network(net) = &mut state.mode {
                net.backspace();
            }
            Vec::new()
        }
        Action::NetApply => {
            if let Mode::Network(net) = &state.mode {
                match net.build_mode() {
                    Ok(mode) => {
                        state.mode = Mode::Busy("applying network mode".into());
                        return vec![Effect::SetNetMode(mode)];
                    }
                    Err(msg) => state.status = format!("invalid: {msg}"),
                }
            }
            Vec::new()
        }
        Action::NetCheck => {
            if state.relay_count == 0 {
                state.status =
                    "no relays configured — add one with: shuki relay add wss://…".into();
                return Vec::new();
            }
            if let Mode::Network(net) = &mut state.mode {
                if !net.checking {
                    net.checking = true;
                    net.results = None;
                    return vec![Effect::NetCheck];
                }
            }
            Vec::new()
        }
        Action::NetClose => {
            state.mode = Mode::Browse;
            Vec::new()
        }
        Action::FormCancel | Action::DismissError => {
            state.mode = Mode::Browse;
            Vec::new()
        }
        Action::Back => {
            match &state.mode {
                Mode::Detail { .. } => {
                    state.current = None;
                    state.mode = Mode::Browse;
                }
                Mode::Browse => {
                    if state.filter.take().is_some() {
                        state.apply_filter(None);
                        state.status = "filter cleared".into();
                    }
                }
                _ => state.mode = Mode::Browse,
            }
            Vec::new()
        }
    }
}

fn apply_task(state: &mut AppState, result: TaskResult) -> Vec<Effect> {
    match result {
        TaskResult::Entries(Ok(paths)) => {
            state.tree = VaultTree::build(&paths);
            let query = state.active_query();
            state.apply_filter(query.as_deref());
            if matches!(state.mode, Mode::Busy(_)) {
                state.mode = Mode::Browse;
            }
            Vec::new()
        }
        TaskResult::Entries(Err(e)) => {
            state.mode = Mode::Error(e.to_string());
            Vec::new()
        }
        TaskResult::Entry(Ok(entry)) => {
            match state.pending.take() {
                Some(Pending::Detail) => {
                    state.current = Some(entry);
                    state.mode = Mode::Detail { reveal: false };
                }
                Some(Pending::Edit) => {
                    state.mode = Mode::Form(FormState::edit(&entry));
                    state.current = Some(entry);
                }
                None => {}
            }
            Vec::new()
        }
        TaskResult::Entry(Err(e)) => {
            state.pending = None;
            state.mode = Mode::Error(e.to_string());
            Vec::new()
        }
        TaskResult::Saved(Ok(()), path) => {
            state.status = format!("saved {path}");
            state.current = None;
            state.mode = Mode::Browse;
            vec![Effect::LoadEntries]
        }
        TaskResult::Saved(Err(e), path) => {
            state.mode = Mode::Error(format!("save {path}: {e}"));
            Vec::new()
        }
        TaskResult::Deleted(Ok(()), path) => {
            state.status = format!("deleted {path}");
            state.mode = Mode::Browse;
            vec![Effect::LoadEntries]
        }
        TaskResult::Deleted(Err(e), path) => {
            state.mode = Mode::Error(format!("delete {path}: {e}"));
            Vec::new()
        }
        TaskResult::Renamed(Ok(()), from, to) => {
            state.status = format!("moved {from} -> {to}");
            state.current = None;
            state.mode = Mode::Browse;
            vec![Effect::LoadEntries]
        }
        TaskResult::Renamed(Err(e), from, to) => {
            state.mode = Mode::Error(format!("rename {from} -> {to}: {e}"));
            Vec::new()
        }
        TaskResult::Synced(Ok(report)) => {
            state.status = format!(
                "sync: pushed {}, pulled {}, tombstones {}, lww {}, errors {}",
                report.pushed,
                report.pulled,
                report.tombstones_applied,
                report.conflicts_lww,
                report.errors.len()
            );
            state.mode = Mode::Browse;
            vec![Effect::LoadEntries]
        }
        TaskResult::Synced(Err(e)) => {
            state.mode = Mode::Error(e.to_string());
            Vec::new()
        }
        TaskResult::Copied(Ok(())) => {
            state.status = format!("copied — clears in {}s", state.clipboard_clear_secs);
            Vec::new()
        }
        TaskResult::Copied(Err(e)) => {
            state.status = match e {
                ShukiError::Clipboard(_) => "clipboard unavailable".into(),
                e => format!("copy failed: {e}"),
            };
            Vec::new()
        }
        TaskResult::NetModeSet(Ok(()), net) => {
            let mut status = format!("network: {}", net_tag(&net));
            if matches!(net, NetMode::Tor) && !cfg!(feature = "tor") {
                status.push_str(" — built without the tor feature; sync will error until rebuilt with --features tor");
            }
            state.config.net = net;
            state.status = status;
            state.mode = Mode::Browse;
            Vec::new()
        }
        TaskResult::NetModeSet(Err(e), _) => {
            state.mode = Mode::Error(format!("set network mode: {e}"));
            Vec::new()
        }
        TaskResult::NetChecked(Ok(results)) => {
            let ok = results.iter().filter(|(_, err)| err.is_none()).count();
            let summary = format!("net check: {ok}/{} relay(s) reachable", results.len());
            if let Mode::Network(net) = &mut state.mode {
                net.checking = false;
                net.results = Some(results);
            }
            state.status = summary;
            Vec::new()
        }
        TaskResult::NetChecked(Err(e)) => {
            state.mode = Mode::Error(format!("net check: {e}"));
            Vec::new()
        }
        TaskResult::SessionLocked(Ok(())) => {
            state.status = "device session cleared (applies to next start)".into();
            Vec::new()
        }
        TaskResult::SessionLocked(Err(e)) => {
            state.mode = Mode::Error(format!("lock session: {e}"));
            Vec::new()
        }
    }
}

/// Executes [`Effect`]s by spawning tokio tasks that post
/// [`AppMsg::TaskDone`] back into the channel.
struct Executor {
    vault: Arc<dyn Vault>,
    sync: Arc<dyn SyncApi>,
    clipboard: Option<Arc<Clipboard>>,
    tx: mpsc::Sender<AppMsg>,
    /// `Vault::open` has succeeded (decrypt-once happens on first load).
    vault_opened: Arc<AtomicBool>,
}

impl Executor {
    fn new(
        vault: Arc<dyn Vault>,
        sync: Arc<dyn SyncApi>,
        clipboard: Option<Arc<Clipboard>>,
        tx: mpsc::Sender<AppMsg>,
    ) -> Self {
        Self {
            vault,
            sync,
            clipboard,
            tx,
            vault_opened: Arc::new(AtomicBool::new(false)),
        }
    }

    fn spawn(&self, effect: Effect) {
        if matches!(effect, Effect::Quit) {
            return; // handled by the main loop via `should_quit`
        }
        let vault = Arc::clone(&self.vault);
        let sync = Arc::clone(&self.sync);
        let clipboard = self.clipboard.clone();
        let tx = self.tx.clone();
        let opened = Arc::clone(&self.vault_opened);
        tokio::spawn(async move {
            let result = run_effect(effect, &*vault, &*sync, clipboard.as_deref(), &opened).await;
            if tx.send(AppMsg::TaskDone(result)).await.is_err() {
                tracing::debug!("tui channel closed; dropping task result");
            }
        });
    }
}

async fn run_effect(
    effect: Effect,
    vault: &dyn Vault,
    sync: &dyn SyncApi,
    clipboard: Option<&Clipboard>,
    opened: &AtomicBool,
) -> TaskResult {
    match effect {
        Effect::Quit => unreachable!("Quit is handled by the main loop"),
        Effect::LoadEntries => TaskResult::Entries(load_entries(vault, opened).await),
        Effect::LoadEntry(path) => TaskResult::Entry(vault.get(&path).await),
        Effect::SaveEntry(entry) => {
            let path = entry.path.clone();
            TaskResult::Saved(vault.put(entry).await, path)
        }
        Effect::DeleteEntry(path) => {
            let result = vault.remove(&path).await;
            TaskResult::Deleted(result, path)
        }
        Effect::RenameEntry(from, to) => {
            let result = vault.rename(&from, &to).await;
            TaskResult::Renamed(result, from, to)
        }
        Effect::RunSync => TaskResult::Synced(sync.sync().await),
        Effect::CopyPassword(path) => {
            TaskResult::Copied(copy_password(vault, clipboard, &path).await)
        }
        Effect::SetNetMode(net) => {
            let result = set_net_mode(sync, net.clone()).await;
            TaskResult::NetModeSet(result, net)
        }
        Effect::NetCheck => TaskResult::NetChecked(sync.net_check().await),
        Effect::LockSession(data_dir) => TaskResult::SessionLocked(
            tokio::task::spawn_blocking(move || crate::signer::session::clear(&data_dir))
                .await
                .map_err(|e| ShukiError::Other(format!("lock session task: {e}")))
                .and_then(|r| r),
        ),
    }
}

/// Persist `net` into the config file (re-load + save on the blocking pool,
/// so the on-disk config stays authoritative) and switch the sync engine.
async fn set_net_mode(sync: &dyn SyncApi, net: NetMode) -> Result<()> {
    let to_save = net.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut config = Config::load()?;
        config.net = to_save;
        config.save()
    })
    .await
    .map_err(|e| ShukiError::Other(format!("config save task: {e}")))??;
    sync.set_net_mode(net).await
}

async fn load_entries(vault: &dyn Vault, opened: &AtomicBool) -> Result<Vec<VaultPath>> {
    if !opened.load(Ordering::Acquire) {
        vault.open().await?;
        opened.store(true, Ordering::Release);
    }
    vault.list_paths().await
}

async fn copy_password(
    vault: &dyn Vault,
    clipboard: Option<&Clipboard>,
    path: &VaultPath,
) -> Result<()> {
    let Some(clipboard) = clipboard else {
        return Err(ShukiError::Clipboard("clipboard unavailable".into()));
    };
    let entry = vault.get(path).await?;
    let Some(password) = entry.fields.password.as_ref() else {
        return Err(ShukiError::Other(format!("{path}: entry has no password")));
    };
    clipboard.copy_secret(password)
}

/// Full-length npub used by the TUI unit tests.
#[cfg(test)]
pub(crate) const TEST_NPUB: &str =
    "npub1zvxkq3jwv2yfxwv7t2z0tuuq6a0kdyv2mfmev6t9zjmalphzu6dq7q35xk";

/// Identity fixture for the TUI unit tests.
#[cfg(test)]
pub(crate) fn test_identity() -> Identity {
    Identity {
        npub: TEST_NPUB.into(),
        signer_label: "software".into(),
    }
}

/// Config fixture for the TUI unit tests: `relays` fake relay urls,
/// clipboard clear TTL 45s, clearnet.
#[cfg(test)]
pub(crate) fn test_config(relays: usize) -> Config {
    Config {
        relays: (0..relays).map(|i| format!("wss://r{i}.example")).collect(),
        clipboard_clear_secs: 45,
        ..Config::default()
    }
}

/// Restore the terminal (idempotent; used by the panic hook and Drop guard).
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Restores the terminal on every exit path (including `?` early returns).
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Run the TUI until the user quits. Entry point wired from `main.rs`.
/// `identity` is the logged-in identity (npub + signer backend label), shown
/// in the header and the help overlay.
pub async fn run(
    vault: Arc<dyn Vault>,
    sync: Arc<dyn SyncApi>,
    clipboard: Option<Arc<crate::clipboard::Clipboard>>,
    config: crate::config::Config,
    identity: Identity,
) -> crate::Result<()> {
    let (tx, mut rx) = mpsc::channel::<AppMsg>(256);
    let clipboard_available = clipboard.is_some();
    let executor = Executor::new(vault, sync, clipboard, tx.clone());
    let mut state = AppState::new(identity, config, clipboard_available);

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous_hook(info);
    }));

    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // Input thread; exits by itself once the channel closes.
    let _input = event::spawn_input_thread(tx.clone());

    executor.spawn(Effect::LoadEntries);

    loop {
        terminal.draw(|frame| ui::draw(frame, &mut state))?;
        let Some(msg) = rx.recv().await else { break };
        let mut effects = update(&mut state, msg);
        // Coalesce whatever else is already queued before redrawing.
        while let Ok(msg) = rx.try_recv() {
            effects.extend(update(&mut state, msg));
        }
        for effect in effects {
            executor.spawn(effect);
        }
        if state.should_quit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ratatui::crossterm::event::{KeyCode, KeyModifiers};

    use super::*;
    use crate::domain::{EntryFields, SecretField};

    // ---- mocks ----------------------------------------------------------

    #[derive(Default)]
    struct MockVault {
        entries: Mutex<HashMap<VaultPath, Entry>>,
        opens: AtomicUsize,
    }

    impl MockVault {
        fn with(paths: &[&str]) -> Self {
            let vault = Self::default();
            {
                let mut map = vault.entries.lock().unwrap();
                for p in paths {
                    let path = VaultPath::parse(p).unwrap();
                    map.insert(path.clone(), entry(p, "pw"));
                }
            }
            vault
        }
    }

    fn entry(path: &str, password: &str) -> Entry {
        Entry {
            path: VaultPath::parse(path).unwrap(),
            fields: EntryFields {
                password: Some(SecretField::from(password)),
                username: Some("alice".into()),
                ..Default::default()
            },
            updated_at: 1,
        }
    }

    #[async_trait]
    impl Vault for MockVault {
        async fn open(&self) -> Result<()> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn list_paths(&self) -> Result<Vec<VaultPath>> {
            let mut paths: Vec<VaultPath> = self.entries.lock().unwrap().keys().cloned().collect();
            paths.sort();
            Ok(paths)
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
            let mut map = self.entries.lock().unwrap();
            let mut entry = map
                .remove(from)
                .ok_or_else(|| ShukiError::NotFound(from.to_string()))?;
            entry.path = to.clone();
            map.insert(to.clone(), entry);
            Ok(())
        }
        async fn find(&self, query: &str) -> Result<Vec<VaultPath>> {
            let needle = query.to_lowercase();
            let mut paths: Vec<VaultPath> = self
                .entries
                .lock()
                .unwrap()
                .keys()
                .filter(|p| p.as_str().to_lowercase().contains(&needle))
                .cloned()
                .collect();
            paths.sort();
            Ok(paths)
        }
    }

    #[derive(Default)]
    struct MockSyncApi {
        calls: AtomicUsize,
        /// Every `set_net_mode` call, in order.
        net_modes: Mutex<Vec<NetMode>>,
    }

    #[async_trait]
    impl SyncApi for MockSyncApi {
        async fn sync(&self) -> Result<SyncReport> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SyncReport {
                pushed: 2,
                pulled: 1,
                ..Default::default()
            })
        }
        async fn restore_all(&self) -> Result<SyncReport> {
            Ok(SyncReport::default())
        }
        async fn publish_relay_list(&self) -> Result<()> {
            Ok(())
        }
        async fn fetch_relay_list(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn set_net_mode(&self, net: NetMode) -> Result<()> {
            self.net_modes.lock().unwrap().push(net);
            Ok(())
        }
        async fn net_check(&self) -> Result<Vec<(String, Option<String>)>> {
            Ok(vec![
                ("wss://r0.example".into(), None),
                ("wss://r1.example".into(), Some("Disconnected".into())),
            ])
        }
    }

    // ---- helpers --------------------------------------------------------

    fn state_with(paths: &[&str]) -> AppState {
        let mut state = AppState::new(test_identity(), test_config(1), true);
        let paths: Vec<VaultPath> = paths.iter().map(|p| VaultPath::parse(p).unwrap()).collect();
        let effects = update(&mut state, AppMsg::TaskDone(TaskResult::Entries(Ok(paths))));
        assert!(effects.is_empty());
        assert!(matches!(state.mode, Mode::Browse));
        state
    }

    fn press(state: &mut AppState, code: KeyCode) -> Vec<Effect> {
        update(state, AppMsg::Key(KeyEvent::new(code, KeyModifiers::NONE)))
    }

    fn press_char(state: &mut AppState, c: char) -> Vec<Effect> {
        press(state, KeyCode::Char(c))
    }

    fn type_str(state: &mut AppState, s: &str) {
        for c in s.chars() {
            press_char(state, c);
        }
    }

    fn selected(state: &AppState) -> Option<String> {
        state.tree_state.selected().last().cloned()
    }

    // ---- reducer: navigation -------------------------------------------

    #[test]
    fn navigation_moves_over_visible_rows_and_expands() {
        let mut state = state_with(&["a/x", "a/y", "b"]);
        // Initial selection is the first visible row.
        assert_eq!(selected(&state).as_deref(), Some("a"));
        press_char(&mut state, 'j');
        assert_eq!(selected(&state).as_deref(), Some("b"));
        press_char(&mut state, 'j'); // clamped at bottom
        assert_eq!(selected(&state).as_deref(), Some("b"));
        press_char(&mut state, 'k');
        assert_eq!(selected(&state).as_deref(), Some("a"));
        // Expand "a", then walk into its children.
        press_char(&mut state, 'l');
        press_char(&mut state, 'j');
        assert_eq!(selected(&state).as_deref(), Some("a/x"));
        press_char(&mut state, 'j');
        assert_eq!(selected(&state).as_deref(), Some("a/y"));
        // Collapse from within jumps to parent, second collapse closes it.
        press_char(&mut state, 'h');
        press_char(&mut state, 'h');
        press_char(&mut state, 'j');
        assert_eq!(selected(&state).as_deref(), Some("b"));
        // Directories are not entries.
        press_char(&mut state, 'k');
        assert_eq!(state.selected_entry(), None);
        press_char(&mut state, 'j');
        assert_eq!(state.selected_entry(), Some(VaultPath::parse("b").unwrap()));
    }

    // ---- reducer: search ------------------------------------------------

    #[test]
    fn search_filters_tree_live_and_accept_keeps_filter() {
        let mut state = state_with(&["web/github.com/alice", "web/example.com", "bank/main"]);
        assert_eq!(state.visible.paths().len(), 3);
        press_char(&mut state, '/');
        assert!(matches!(state.mode, Mode::Search(_)));
        type_str(&mut state, "git");
        assert_eq!(state.visible.paths().len(), 1);
        assert_eq!(state.visible.paths()[0].as_str(), "web/github.com/alice");
        // Backspace widens again.
        press(&mut state, KeyCode::Backspace);
        press(&mut state, KeyCode::Backspace);
        press(&mut state, KeyCode::Backspace);
        assert_eq!(state.visible.paths().len(), 3);
        type_str(&mut state, "bank");
        press(&mut state, KeyCode::Enter);
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.filter.as_deref(), Some("bank"));
        assert_eq!(state.visible.paths().len(), 1);
        // Esc in Browse clears the accepted filter.
        press(&mut state, KeyCode::Esc);
        assert_eq!(state.filter, None);
        assert_eq!(state.visible.paths().len(), 3);
    }

    #[test]
    fn search_cancel_restores_full_tree() {
        let mut state = state_with(&["a/x", "b"]);
        press_char(&mut state, '/');
        type_str(&mut state, "zzz");
        assert!(state.visible.is_empty());
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.visible.paths().len(), 2);
    }

    // ---- reducer: detail / reveal / copy -------------------------------

    #[test]
    fn detail_flow_loads_reveals_and_backs_out() {
        let mut state = state_with(&["b"]);
        assert_eq!(selected(&state).as_deref(), Some("b"));
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(
            effects,
            vec![Effect::LoadEntry(VaultPath::parse("b").unwrap())]
        );
        assert!(matches!(state.mode, Mode::Busy(_)));
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Entry(Ok(entry("b", "pw")))),
        );
        assert!(matches!(state.mode, Mode::Detail { reveal: false }));
        press_char(&mut state, 'r');
        assert!(matches!(state.mode, Mode::Detail { reveal: true }));
        // Copy from detail targets the loaded entry.
        let effects = press_char(&mut state, 'y');
        assert_eq!(
            effects,
            vec![Effect::CopyPassword(VaultPath::parse("b").unwrap())]
        );
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
        assert!(state.current.is_none());
    }

    #[test]
    fn copy_without_clipboard_reports_unavailable() {
        let mut state = AppState::new(test_identity(), test_config(1), false);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Entries(Ok(
                vec![VaultPath::parse("b").unwrap()],
            ))),
        );
        let effects = press_char(&mut state, 'y');
        assert!(effects.is_empty());
        assert_eq!(state.status, "clipboard unavailable");
    }

    #[test]
    fn copy_result_messages() {
        let mut state = state_with(&["b"]);
        update(&mut state, AppMsg::TaskDone(TaskResult::Copied(Ok(()))));
        assert_eq!(state.status, "copied — clears in 45s");
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Copied(Err(ShukiError::Clipboard("x".into())))),
        );
        assert_eq!(state.status, "clipboard unavailable");
    }

    // ---- reducer: add / edit form --------------------------------------

    #[test]
    fn add_form_submit_produces_save_entry_effect() {
        let mut state = state_with(&[]);
        press_char(&mut state, 'a');
        assert!(matches!(state.mode, Mode::Form(_)));
        type_str(&mut state, "web/x"); // path field
        press(&mut state, KeyCode::Tab);
        type_str(&mut state, "alice"); // username
        press(&mut state, KeyCode::Tab);
        type_str(&mut state, "s3cret"); // password
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(effects.len(), 1);
        let Effect::SaveEntry(saved) = &effects[0] else {
            panic!("expected SaveEntry, got {effects:?}");
        };
        assert_eq!(saved.path.as_str(), "web/x");
        assert_eq!(saved.fields.username.as_deref(), Some("alice"));
        assert_eq!(
            saved.fields.password.as_ref().map(|p| p.expose()),
            Some("s3cret")
        );
        assert!(matches!(state.mode, Mode::Busy(_)));
    }

    #[test]
    fn add_form_rejects_invalid_path() {
        let mut state = state_with(&[]);
        press_char(&mut state, 'a');
        type_str(&mut state, "/bad/");
        let effects = press(&mut state, KeyCode::Enter);
        assert!(effects.is_empty());
        assert!(matches!(state.mode, Mode::Form(_)));
        assert!(state.status.starts_with("invalid:"));
    }

    #[test]
    fn edit_flow_prefills_form_from_loaded_entry() {
        let mut state = state_with(&["b"]);
        let effects = press_char(&mut state, 'e');
        assert_eq!(
            effects,
            vec![Effect::LoadEntry(VaultPath::parse("b").unwrap())]
        );
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Entry(Ok(entry("b", "pw")))),
        );
        let Mode::Form(form) = &state.mode else {
            panic!("expected form mode");
        };
        assert!(form.editing);
        assert_eq!(form.path, "b");
        assert_eq!(form.username, "alice");
        assert_eq!(&*form.password, "pw");
    }

    #[test]
    fn saved_returns_to_browse_and_reloads() {
        let mut state = state_with(&[]);
        state.mode = Mode::Busy("saving".into());
        let effects = update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Saved(
                Ok(()),
                VaultPath::parse("web/x").unwrap(),
            )),
        );
        assert_eq!(effects, vec![Effect::LoadEntries]);
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.status, "saved web/x");
    }

    // ---- reducer: delete confirm flow ----------------------------------

    #[test]
    fn delete_confirm_flow() {
        let mut state = state_with(&["b"]);
        press_char(&mut state, 'd');
        assert!(matches!(state.mode, Mode::ConfirmDelete(_)));
        // 'n' cancels.
        press_char(&mut state, 'n');
        assert!(matches!(state.mode, Mode::Browse));
        // Esc cancels too.
        press_char(&mut state, 'd');
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
        // 'y' confirms.
        press_char(&mut state, 'd');
        let effects = press_char(&mut state, 'y');
        assert_eq!(
            effects,
            vec![Effect::DeleteEntry(VaultPath::parse("b").unwrap())]
        );
        assert!(matches!(state.mode, Mode::Busy(_)));
        let effects = update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Deleted(Ok(()), VaultPath::parse("b").unwrap())),
        );
        assert_eq!(effects, vec![Effect::LoadEntries]);
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.status, "deleted b");
    }

    // ---- reducer: rename ------------------------------------------------

    #[test]
    fn rename_flow_from_browse_prefills_and_emits_effect() {
        let mut state = state_with(&["a/b"]);
        press_char(&mut state, 'l'); // expand "a"
        press_char(&mut state, 'j'); // select "a/b"
        assert_eq!(
            state.selected_entry(),
            Some(VaultPath::parse("a/b").unwrap())
        );
        press_char(&mut state, 'm');
        let Mode::Rename(rename) = &state.mode else {
            panic!("expected rename mode, got {:?}", state.mode);
        };
        assert_eq!(rename.to, "a/b"); // prefilled with the current path
                                      // Edit the target: "a/b" → "a/c".
        press(&mut state, KeyCode::Backspace);
        press_char(&mut state, 'c');
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(
            effects,
            vec![Effect::RenameEntry(
                VaultPath::parse("a/b").unwrap(),
                VaultPath::parse("a/c").unwrap()
            )]
        );
        assert!(matches!(state.mode, Mode::Busy(_)));
        let effects = update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Renamed(
                Ok(()),
                VaultPath::parse("a/b").unwrap(),
                VaultPath::parse("a/c").unwrap(),
            )),
        );
        assert_eq!(effects, vec![Effect::LoadEntries]);
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.status, "moved a/b -> a/c");
    }

    #[test]
    fn rename_from_detail_targets_loaded_entry() {
        let mut state = state_with(&["b"]);
        press(&mut state, KeyCode::Enter);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Entry(Ok(entry("b", "pw")))),
        );
        assert!(matches!(state.mode, Mode::Detail { .. }));
        press_char(&mut state, 'm');
        let Mode::Rename(rename) = &state.mode else {
            panic!("expected rename mode");
        };
        assert_eq!(rename.from.as_str(), "b");
        assert_eq!(rename.to, "b");
        // Esc cancels back to browse.
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
        assert!(state.current.is_none());
    }

    #[test]
    fn rename_invalid_path_enters_error_mode() {
        let mut state = state_with(&["b"]);
        press_char(&mut state, 'm');
        // "b" → "/bad/" (invalid path).
        press(&mut state, KeyCode::Backspace);
        type_str(&mut state, "/bad/");
        let effects = press(&mut state, KeyCode::Enter);
        assert!(effects.is_empty());
        assert!(matches!(state.mode, Mode::Error(_)));
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
    }

    #[test]
    fn rename_without_selection_sets_status() {
        let mut state = state_with(&[]);
        press_char(&mut state, 'm');
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.status, "no entry selected");
    }

    #[test]
    fn rename_task_error_enters_error_mode() {
        let mut state = state_with(&["b"]);
        state.mode = Mode::Busy("renaming".into());
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Renamed(
                Err(ShukiError::NotFound("b".into())),
                VaultPath::parse("b").unwrap(),
                VaultPath::parse("c").unwrap(),
            )),
        );
        let Mode::Error(msg) = &state.mode else {
            panic!("expected error mode");
        };
        assert!(msg.contains("rename b -> c"));
    }

    // ---- reducer: help overlay -----------------------------------------

    #[test]
    fn help_opens_from_browse_and_any_key_closes() {
        let mut state = state_with(&["b"]);
        press_char(&mut state, '?');
        assert!(matches!(state.mode, Mode::Help(_)));
        press_char(&mut state, 'x'); // any key closes
        assert!(matches!(state.mode, Mode::Browse));
    }

    #[test]
    fn help_from_detail_restores_detail_with_reveal() {
        let mut state = state_with(&["b"]);
        press(&mut state, KeyCode::Enter);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Entry(Ok(entry("b", "pw")))),
        );
        press_char(&mut state, 'r'); // reveal
        press_char(&mut state, '?');
        assert!(matches!(state.mode, Mode::Help(_)));
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Detail { reveal: true }));
    }

    // ---- reducer: form password generation ------------------------------

    #[test]
    fn ctrl_g_fills_password_only_when_password_focused() {
        let mut state = state_with(&[]);
        press_char(&mut state, 'a');
        let gen = AppMsg::Key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
        // Path field focused: no generation.
        update(&mut state, gen);
        let Mode::Form(form) = &state.mode else {
            panic!("expected form");
        };
        assert!(form.password.is_empty());
        // Focus the password field (path → username → password).
        press(&mut state, KeyCode::Tab);
        press(&mut state, KeyCode::Tab);
        let gen = AppMsg::Key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
        update(&mut state, gen);
        let Mode::Form(form) = &state.mode else {
            panic!("expected form");
        };
        assert_eq!(form.password.chars().count(), 24);
        assert_eq!(
            state.status,
            "generated 24-char password — Ctrl-g regenerates"
        );
        // Regenerate: a fresh password each press.
        let first = form.password.clone();
        let gen = AppMsg::Key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
        update(&mut state, gen);
        let Mode::Form(form) = &state.mode else {
            panic!("expected form");
        };
        assert_ne!(*form.password, *first);
    }

    // ---- reducer: sync / quit / error ----------------------------------

    #[test]
    fn sync_without_relays_errors_with_hint() {
        let mut state = state_with(&[]);
        state.relay_count = 0;
        let effects = press_char(&mut state, 's');
        assert!(effects.is_empty());
        let Mode::Error(msg) = &state.mode else {
            panic!("expected error mode, got {:?}", state.mode);
        };
        assert!(msg.contains("no relays configured"));
        assert!(msg.contains("shuki relay add"));
    }

    #[test]
    fn sync_flow_busy_then_report_in_status() {
        let mut state = state_with(&[]);
        let effects = press_char(&mut state, 's');
        assert_eq!(effects, vec![Effect::RunSync]);
        assert!(matches!(state.mode, Mode::Busy(_)));
        let report = SyncReport {
            pushed: 2,
            pulled: 1,
            ..Default::default()
        };
        let effects = update(&mut state, AppMsg::TaskDone(TaskResult::Synced(Ok(report))));
        assert_eq!(effects, vec![Effect::LoadEntries]);
        assert!(matches!(state.mode, Mode::Browse));
        assert!(state.status.contains("pushed 2"));
        assert!(state.status.contains("pulled 1"));
    }

    #[test]
    fn quit_sets_flag_and_emits_quit_effect() {
        let mut state = state_with(&[]);
        let effects = press_char(&mut state, 'q');
        assert_eq!(effects, vec![Effect::Quit]);
        assert!(state.should_quit);
    }

    #[test]
    fn errors_enter_error_mode_and_dismiss() {
        let mut state = state_with(&[]);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::Synced(Err(ShukiError::Relay("down".into())))),
        );
        assert!(matches!(state.mode, Mode::Error(_)));
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
    }

    // ---- reducer: lock session ------------------------------------------

    #[test]
    fn ctrl_l_emits_lock_session_effect_and_reports_status() {
        let mut state = state_with(&["b"]);
        let effects = update(
            &mut state,
            AppMsg::Key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL)),
        );
        assert_eq!(
            effects,
            vec![Effect::LockSession(state.config.resolve_data_dir())]
        );
        // Browse keeps working while the (fast) task runs.
        assert!(matches!(state.mode, Mode::Browse));
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::SessionLocked(Ok(()))),
        );
        assert_eq!(
            state.status,
            "device session cleared (applies to next start)"
        );
        assert!(matches!(state.mode, Mode::Browse));
    }

    #[test]
    fn lock_session_error_enters_error_mode() {
        let mut state = state_with(&[]);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::SessionLocked(Err(ShukiError::Other(
                "disk".into(),
            )))),
        );
        let Mode::Error(msg) = &state.mode else {
            panic!("expected error mode, got {:?}", state.mode);
        };
        assert!(msg.contains("lock session"));
    }

    #[test]
    fn plain_l_still_expands_not_locks() {
        let mut state = state_with(&["a/x"]);
        let effects = press_char(&mut state, 'l');
        assert!(effects.is_empty(), "plain l must not emit LockSession");
    }

    #[test]
    fn tick_advances_spinner_only_while_busy() {
        let mut state = state_with(&[]);
        update(&mut state, AppMsg::Tick);
        assert_eq!(state.spinner_frame, 0);
        state.mode = Mode::Busy("x".into());
        update(&mut state, AppMsg::Tick);
        assert_eq!(state.spinner_frame, 1);
    }

    // ---- reducer: network overlay ---------------------------------------

    #[test]
    fn network_overlay_opens_prefilled_and_closes() {
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        let Mode::Network(net) = &state.mode else {
            panic!("expected network mode, got {:?}", state.mode);
        };
        assert_eq!(net.choice, NetChoice::Clearnet);
        assert_eq!(net.addr, crate::config::DEFAULT_SOCKS5_ADDR);
        press(&mut state, KeyCode::Esc);
        assert!(matches!(state.mode, Mode::Browse));
    }

    #[test]
    fn network_overlay_prefills_from_socks5_config() {
        let mut state = state_with(&[]);
        state.config.net = NetMode::Socks5 {
            addr: "10.0.0.1:9150".into(),
        };
        press_char(&mut state, 't');
        let Mode::Network(net) = &state.mode else {
            panic!("expected network mode");
        };
        assert_eq!(net.choice, NetChoice::Socks5);
        assert_eq!(net.addr, "10.0.0.1:9150");
    }

    #[test]
    fn network_apply_clearnet_emits_effect_and_updates_state_on_done() {
        let mut state = state_with(&[]);
        state.config.net = NetMode::Socks5 {
            addr: "127.0.0.1:9050".into(),
        };
        press_char(&mut state, 't');
        press_char(&mut state, 'k'); // socks5 → clearnet (clamped at top)
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(effects, vec![Effect::SetNetMode(NetMode::Clearnet)]);
        assert!(matches!(state.mode, Mode::Busy(_)));
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::NetModeSet(Ok(()), NetMode::Clearnet)),
        );
        assert!(matches!(state.mode, Mode::Browse));
        assert_eq!(state.config.net, NetMode::Clearnet);
        assert_eq!(state.status, "network: clearnet");
    }

    #[test]
    fn network_apply_socks5_edits_addr_and_validates() {
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        press_char(&mut state, 'j'); // clearnet → socks5
                                     // Rewrite the port: 127.0.0.1:9050 → 127.0.0.1:9150.
        for _ in 0..4 {
            press(&mut state, KeyCode::Backspace);
        }
        type_str(&mut state, "9150");
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(
            effects,
            vec![Effect::SetNetMode(NetMode::Socks5 {
                addr: "127.0.0.1:9150".into()
            })]
        );

        // Invalid address: stays in the overlay with a status hint.
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        press_char(&mut state, 'j');
        for _ in 0.."127.0.0.1:9050".len() {
            press(&mut state, KeyCode::Backspace);
        }
        type_str(&mut state, "not an addr");
        let effects = press(&mut state, KeyCode::Enter);
        assert!(effects.is_empty());
        assert!(matches!(state.mode, Mode::Network(_)));
        assert!(state.status.starts_with("invalid:"), "{}", state.status);
    }

    #[test]
    fn network_apply_embedded_warns_without_tor_feature() {
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        press_char(&mut state, 'j');
        press_char(&mut state, 'j'); // clearnet → socks5 → embedded
        let effects = press(&mut state, KeyCode::Enter);
        assert_eq!(effects, vec![Effect::SetNetMode(NetMode::Tor)]);
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::NetModeSet(Ok(()), NetMode::Tor)),
        );
        assert_eq!(state.config.net, NetMode::Tor);
        assert!(state.status.starts_with("network: tor(embedded)"));
        if !cfg!(feature = "tor") {
            assert!(state.status.contains("--features tor"), "{}", state.status);
        }
    }

    #[test]
    fn network_check_flow_shows_results_in_overlay() {
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        let effects = press_char(&mut state, 'c');
        assert_eq!(effects, vec![Effect::NetCheck]);
        let Mode::Network(net) = &state.mode else {
            panic!("expected network mode");
        };
        assert!(net.checking);
        // A second `c` while checking is a no-op.
        assert!(press_char(&mut state, 'c').is_empty());
        let results = vec![
            ("wss://r0.example".to_owned(), None),
            (
                "wss://r1.example".to_owned(),
                Some("Disconnected".to_owned()),
            ),
        ];
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::NetChecked(Ok(results.clone()))),
        );
        let Mode::Network(net) = &state.mode else {
            panic!("expected network mode");
        };
        assert!(!net.checking);
        assert_eq!(net.results, Some(results));
        assert_eq!(state.status, "net check: 1/2 relay(s) reachable");
    }

    #[test]
    fn network_check_without_relays_sets_status() {
        let mut state = state_with(&[]);
        state.relay_count = 0;
        press_char(&mut state, 't');
        let effects = press_char(&mut state, 'c');
        assert!(effects.is_empty());
        assert!(state.status.contains("no relays configured"));
    }

    #[test]
    fn network_check_error_enters_error_mode() {
        let mut state = state_with(&[]);
        press_char(&mut state, 't');
        press_char(&mut state, 'c');
        update(
            &mut state,
            AppMsg::TaskDone(TaskResult::NetChecked(Err(ShukiError::Relay(
                "down".into(),
            )))),
        );
        let Mode::Error(msg) = &state.mode else {
            panic!("expected error mode, got {:?}", state.mode);
        };
        assert!(msg.contains("net check"));
    }

    #[test]
    fn net_tag_labels() {
        assert_eq!(net_tag(&NetMode::Clearnet), "clearnet");
        assert_eq!(
            net_tag(&NetMode::Socks5 {
                addr: "127.0.0.1:9050".into()
            }),
            "socks5:9050"
        );
        assert_eq!(net_tag(&NetMode::Tor), "tor(embedded)");
    }

    // ---- effect execution (executor + mocks) ----------------------------

    async fn executor_with(
        vault: Arc<MockVault>,
        sync: Arc<MockSyncApi>,
    ) -> (Executor, mpsc::Receiver<AppMsg>) {
        let (tx, rx) = mpsc::channel(16);
        (Executor::new(vault, sync, None, tx), rx)
    }

    async fn run_one(
        executor: &Executor,
        rx: &mut mpsc::Receiver<AppMsg>,
        effect: Effect,
    ) -> TaskResult {
        executor.spawn(effect);
        match rx.recv().await.expect("task result") {
            AppMsg::TaskDone(result) => result,
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn save_entry_effect_writes_to_vault() {
        let vault = Arc::new(MockVault::default());
        let (executor, mut rx) = executor_with(Arc::clone(&vault), Arc::default()).await;

        let mut state = state_with(&[]);
        press_char(&mut state, 'a');
        type_str(&mut state, "web/x");
        press(&mut state, KeyCode::Tab);
        type_str(&mut state, "alice");
        let mut effects = press(&mut state, KeyCode::Enter);
        let effect = effects.pop().expect("SaveEntry effect");

        let result = run_one(&executor, &mut rx, effect).await;
        let followups = update(&mut state, AppMsg::TaskDone(result));
        assert_eq!(followups, vec![Effect::LoadEntries]);
        assert!(matches!(state.mode, Mode::Browse));

        let stored = vault
            .get(&VaultPath::parse("web/x").unwrap())
            .await
            .expect("entry written");
        assert_eq!(stored.fields.username.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn delete_entry_effect_removes_from_vault() {
        let vault = Arc::new(MockVault::with(&["b"]));
        let (executor, mut rx) = executor_with(Arc::clone(&vault), Arc::default()).await;
        let result = run_one(
            &executor,
            &mut rx,
            Effect::DeleteEntry(VaultPath::parse("b").unwrap()),
        )
        .await;
        assert!(matches!(result, TaskResult::Deleted(Ok(()), _)));
        assert!(vault.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rename_entry_effect_moves_in_vault() {
        let vault = Arc::new(MockVault::with(&["a/b"]));
        let (executor, mut rx) = executor_with(Arc::clone(&vault), Arc::default()).await;
        let result = run_one(
            &executor,
            &mut rx,
            Effect::RenameEntry(
                VaultPath::parse("a/b").unwrap(),
                VaultPath::parse("a/c").unwrap(),
            ),
        )
        .await;
        assert!(matches!(result, TaskResult::Renamed(Ok(()), _, _)));
        assert!(vault.get(&VaultPath::parse("a/c").unwrap()).await.is_ok());
        assert!(vault.get(&VaultPath::parse("a/b").unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn load_entries_opens_vault_exactly_once() {
        let vault = Arc::new(MockVault::with(&["a/x", "b"]));
        let (executor, mut rx) = executor_with(Arc::clone(&vault), Arc::default()).await;
        let first = run_one(&executor, &mut rx, Effect::LoadEntries).await;
        let TaskResult::Entries(Ok(paths)) = first else {
            panic!("expected entries");
        };
        assert_eq!(paths.len(), 2);
        run_one(&executor, &mut rx, Effect::LoadEntries).await;
        assert_eq!(vault.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn run_sync_effect_calls_sync_api() {
        let sync = Arc::new(MockSyncApi::default());
        let (executor, mut rx) =
            executor_with(Arc::new(MockVault::default()), Arc::clone(&sync)).await;
        let result = run_one(&executor, &mut rx, Effect::RunSync).await;
        let TaskResult::Synced(Ok(report)) = result else {
            panic!("expected sync report");
        };
        assert_eq!(report.pushed, 2);
        assert_eq!(sync.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    // The std-mutex env lock serializes env-mutating tests; held across
    // mocked awaits on purpose.
    #[allow(clippy::await_holding_lock)]
    async fn set_net_mode_effect_saves_config_and_switches_engine() {
        let _g = crate::config::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("SHUKI_CONFIG", dir.path().join("config.json"));
        Config::default().save().unwrap();

        let sync = Arc::new(MockSyncApi::default());
        let (executor, mut rx) =
            executor_with(Arc::new(MockVault::default()), Arc::clone(&sync)).await;
        let net = NetMode::Socks5 {
            addr: "127.0.0.1:9150".into(),
        };
        let result = run_one(&executor, &mut rx, Effect::SetNetMode(net.clone())).await;
        assert!(matches!(result, TaskResult::NetModeSet(Ok(()), ref n) if *n == net));
        // Saved file is authoritative…
        assert_eq!(Config::load().unwrap().net, net);
        // …and the running engine was switched too.
        assert_eq!(sync.net_modes.lock().unwrap().as_slice(), &[net]);

        std::env::remove_var("SHUKI_CONFIG");
    }

    #[tokio::test]
    async fn net_check_effect_returns_canned_results() {
        let (executor, mut rx) =
            executor_with(Arc::new(MockVault::default()), Arc::default()).await;
        let result = run_one(&executor, &mut rx, Effect::NetCheck).await;
        let TaskResult::NetChecked(Ok(results)) = result else {
            panic!("expected net check results");
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], ("wss://r0.example".to_owned(), None));
    }

    #[tokio::test]
    async fn lock_session_effect_removes_marker_file() {
        let dir = tempfile::tempdir().unwrap();
        crate::signer::session::record(dir.path(), TEST_NPUB).unwrap();
        assert!(crate::signer::session::is_valid(dir.path(), TEST_NPUB, 900));
        let (executor, mut rx) =
            executor_with(Arc::new(MockVault::default()), Arc::default()).await;
        let result = run_one(
            &executor,
            &mut rx,
            Effect::LockSession(dir.path().to_path_buf()),
        )
        .await;
        assert!(matches!(result, TaskResult::SessionLocked(Ok(()))));
        assert!(!crate::signer::session::is_valid(
            dir.path(),
            TEST_NPUB,
            900
        ));
        // Idempotent: locking again without a marker still succeeds.
        let result = run_one(
            &executor,
            &mut rx,
            Effect::LockSession(dir.path().to_path_buf()),
        )
        .await;
        assert!(matches!(result, TaskResult::SessionLocked(Ok(()))));
    }

    #[tokio::test]
    async fn copy_password_without_clipboard_errors() {
        let (executor, mut rx) =
            executor_with(Arc::new(MockVault::with(&["b"])), Arc::default()).await;
        let result = run_one(
            &executor,
            &mut rx,
            Effect::CopyPassword(VaultPath::parse("b").unwrap()),
        )
        .await;
        assert!(matches!(
            result,
            TaskResult::Copied(Err(ShukiError::Clipboard(_)))
        ));
    }
}
