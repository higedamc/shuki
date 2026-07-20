//! Rendering: header (identity), tree pane (left), detail/form/confirm pane
//! (right), status bar, plus full-screen overlays (help, rename).
//!
//! Secrets: the detail pane renders the password as a fixed-length mask
//! (never the real length) unless the user explicitly revealed it.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;
use tui_tree_widget::Tree;

use crate::domain::Entry;

use super::{widgets, AppState, Mode};

/// Busy spinner frames, advanced on [`super::AppMsg::Tick`].
pub const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Fixed-length password mask (does not leak the real length).
pub const PASSWORD_MASK: &str = "••••••••";

/// Draw the whole app.
pub fn draw(frame: &mut Frame, state: &mut AppState) {
    let [header, main, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(main);

    draw_header(frame, header, state);

    let tree = Tree::new(&state.items)
        .expect("tree identifiers are unique full paths")
        .block(Block::bordered().title("vault"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▸");
    frame.render_stateful_widget(tree, left, &mut state.tree_state);

    match &state.mode {
        Mode::Detail { reveal } => draw_detail(frame, right, state.current.as_ref(), *reveal),
        Mode::Form(form) => widgets::render_form(frame, right, form),
        Mode::ConfirmDelete(path) => {
            let lines = vec![
                Line::raw(format!("delete {path} ?")),
                Line::raw(""),
                Line::raw("y: delete    n/Esc: cancel"),
            ];
            frame.render_widget(
                Paragraph::new(lines).block(Block::bordered().title("confirm delete")),
                right,
            );
        }
        Mode::Error(err) => {
            frame.render_widget(
                Paragraph::new(err.as_str())
                    .wrap(Wrap { trim: false })
                    .block(Block::bordered().title("error (Esc to dismiss)")),
                right,
            );
        }
        _ => draw_help(frame, right),
    }

    draw_status(frame, status, state);

    // Full-screen overlays render on top of everything but the status bar.
    match &state.mode {
        Mode::Help(_) => draw_help_overlay(frame, main, state),
        Mode::Rename(rename) => widgets::render_rename(frame, main, rename),
        Mode::Network(net) => widgets::render_network(frame, main, net),
        _ => {}
    }
}

/// Header line: app name left; shortened npub + signer backend + network
/// mode tag right. Visible in every mode.
fn draw_header(frame: &mut Frame, area: Rect, state: &AppState) {
    frame.render_widget(
        Paragraph::new("shuki").style(Style::default().add_modifier(Modifier::BOLD)),
        area,
    );
    let id = format!(
        "{} ({}) [{}]",
        shorten_npub(&state.identity.npub),
        state.identity.signer_label,
        super::net_tag(&state.config.net)
    );
    frame.render_widget(Paragraph::new(id).alignment(Alignment::Right), area);
}

/// Shorten a bech32 npub for the header: `npub1abcd…wxyz`. The full npub is
/// shown in the help overlay. Bech32 is ASCII, so byte slicing is safe.
fn shorten_npub(npub: &str) -> String {
    if npub.len() > 15 && npub.is_ascii() {
        format!("{}…{}", &npub[..10], &npub[npub.len() - 4..])
    } else {
        npub.to_owned()
    }
}

/// Full-screen help overlay: all keybindings per mode + identity details.
fn draw_help_overlay(frame: &mut Frame, area: Rect, state: &AppState) {
    let lines = vec![
        Line::raw("browse"),
        Line::raw("  j/k ↑/↓  move        h/l ←/→  collapse / expand"),
        Line::raw("  Enter    open entry  /        search"),
        Line::raw("  y        copy        a        add entry"),
        Line::raw("  e        edit entry  m        rename / move entry"),
        Line::raw("  d        delete      s        sync"),
        Line::raw("  t        network mode   Ctrl-l  lock device session   ?  help   q  quit"),
        Line::raw("detail"),
        Line::raw("  r reveal/hide   y copy   m rename   ?  help   Esc back"),
        Line::raw("search"),
        Line::raw("  type to filter   Enter accept   Esc cancel"),
        Line::raw("add / edit form"),
        Line::raw("  Tab/Shift-Tab field   Ctrl-g generate password   Enter save   Esc cancel"),
        Line::raw("rename"),
        Line::raw("  Enter rename   Esc cancel"),
        Line::raw("network mode"),
        Line::raw("  j/k select   Enter apply   c check relays   Esc close"),
        Line::raw("confirm delete"),
        Line::raw("  y delete   n/Esc cancel"),
        Line::raw(""),
        Line::raw(format!("identity: {}", state.identity.npub)),
        Line::raw(format!("signer:   {}", state.identity.signer_label)),
        Line::raw(format!("network:  {}", super::net_tag(&state.config.net))),
        Line::raw(format!("relays:   {} configured", state.relay_count)),
        Line::raw(""),
        Line::raw("press any key to close"),
    ];
    let height = (lines.len() as u16).saturating_add(2);
    let rect = widgets::centered_rect(area, 80, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("help")),
        rect,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::raw("j/k ↑/↓  move"),
        Line::raw("h/l ←/→  collapse / expand"),
        Line::raw("Enter    open entry"),
        Line::raw("/        search"),
        Line::raw("y        copy password"),
        Line::raw("a        add entry"),
        Line::raw("e        edit entry"),
        Line::raw("m        rename entry"),
        Line::raw("d        delete entry"),
        Line::raw("s        sync"),
        Line::raw("t        network mode"),
        Line::raw("Ctrl-l   lock session"),
        Line::raw("?        help"),
        Line::raw("q        quit"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("shuki")),
        area,
    );
}

fn draw_detail(frame: &mut Frame, area: Rect, entry: Option<&Entry>, reveal: bool) {
    let Some(entry) = entry else {
        frame.render_widget(Paragraph::new("loading…").block(Block::bordered()), area);
        return;
    };
    let f = &entry.fields;
    let password = match (&f.password, reveal) {
        (None, _) => String::new(),
        (Some(p), true) => p.expose().to_owned(),
        (Some(_), false) => PASSWORD_MASK.to_owned(),
    };
    let reveal_hint = if reveal { "(r: hide)" } else { "(r: reveal)" };
    let lines = vec![
        Line::raw(format!("username: {}", f.username.as_deref().unwrap_or(""))),
        Line::raw(format!("password: {password}  {reveal_hint}")),
        Line::raw(format!("url:      {}", f.url.as_deref().unwrap_or(""))),
        Line::raw(format!(
            "notes:    {}",
            f.notes.as_ref().map_or("", |n| n.expose())
        )),
        Line::raw(""),
        Line::raw("y: copy password   Esc: back"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(entry.path.as_str().to_owned())),
        area,
    );
}

fn draw_status(frame: &mut Frame, area: Rect, state: &AppState) {
    let mode_label = match &state.mode {
        Mode::Browse => match &state.filter {
            Some(f) => format!("[browse] filter: {f} (Esc clears)"),
            None => "[browse]".to_owned(),
        },
        Mode::Search(q) => format!("[search] /{q}▏"),
        Mode::Detail { .. } => "[detail]".to_owned(),
        Mode::Form(form) => {
            if form.editing {
                "[edit]".to_owned()
            } else {
                "[add]".to_owned()
            }
        }
        Mode::ConfirmDelete(_) => "[delete?]".to_owned(),
        Mode::Rename(_) => "[rename]".to_owned(),
        Mode::Network(_) => "[network]".to_owned(),
        Mode::Help(_) => "[help]".to_owned(),
        Mode::Busy(label) => {
            let spin = SPINNER[state.spinner_frame % SPINNER.len()];
            format!("[busy] {spin} {label}…")
        }
        Mode::Error(_) => "[error]".to_owned(),
    };
    let line = format!("{mode_label}  {}", state.status);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::domain::{EntryFields, SecretField, VaultPath};
    use crate::tui::widgets::FormState;
    use crate::tui::{update, AppMsg, TaskResult};

    fn render(state: &mut AppState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| draw(f, state)).unwrap();
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn state_with(paths: &[&str]) -> AppState {
        let mut state = AppState::new(
            crate::tui::test_identity(),
            crate::tui::test_config(2),
            true,
        );
        let paths: Vec<VaultPath> = paths.iter().map(|p| VaultPath::parse(p).unwrap()).collect();
        update(&mut state, AppMsg::TaskDone(TaskResult::Entries(Ok(paths))));
        state
    }

    fn secret_entry(path: &str, password: &str) -> Entry {
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

    #[test]
    fn tree_shows_entry_names() {
        let mut state = state_with(&["web/github.com/alice", "bank/main"]);
        let text = render(&mut state);
        assert!(text.contains("bank"), "top-level dirs visible:\n{text}");
        assert!(text.contains("web"));
        // Children hidden until expanded.
        assert!(!text.contains("github.com"));
        // Expand "web": open its identifier chain.
        state.tree_state.open(vec!["web".to_owned()]);
        let text = render(&mut state);
        assert!(
            text.contains("github.com"),
            "expanded child visible:\n{text}"
        );
    }

    #[test]
    fn detail_masks_password_until_revealed() {
        let mut state = state_with(&["web/x"]);
        state.current = Some(secret_entry("web/x", "hunter2-plaintext"));
        state.mode = Mode::Detail { reveal: false };
        let text = render(&mut state);
        assert!(!text.contains("hunter2-plaintext"), "masked:\n{text}");
        assert!(text.contains(PASSWORD_MASK));
        assert!(text.contains("alice"));

        state.mode = Mode::Detail { reveal: true };
        let text = render(&mut state);
        assert!(text.contains("hunter2-plaintext"), "revealed:\n{text}");
    }

    #[test]
    fn form_renders_field_labels_and_masks_password() {
        let mut state = state_with(&[]);
        let mut form = FormState::new_add();
        // Type a password into the password field.
        form.focus = crate::tui::widgets::FormFocus::Password;
        for c in "s3cr3t".chars() {
            form.input(c);
        }
        state.mode = Mode::Form(form);
        let text = render(&mut state);
        for label in ["path", "username", "password", "url", "notes"] {
            assert!(text.contains(label), "label {label} missing:\n{text}");
        }
        assert!(
            !text.contains("s3cr3t"),
            "typed password not shown:\n{text}"
        );
        assert!(text.contains("••••••"));
    }

    #[test]
    fn status_bar_shows_busy_spinner_and_message() {
        let mut state = state_with(&[]);
        state.mode = Mode::Busy("syncing".into());
        state.status = "hello".into();
        let text = render(&mut state);
        assert!(text.contains("syncing"));
        assert!(text.contains("hello"));
    }

    #[test]
    fn header_shows_shortened_npub_in_every_mode() {
        let mut state = state_with(&["web/x"]);
        // Shortened form: first 10 chars + ellipsis + last 4.
        let short = format!(
            "{}…{}",
            &crate::tui::TEST_NPUB[..10],
            &crate::tui::TEST_NPUB[crate::tui::TEST_NPUB.len() - 4..]
        );
        for mode in [
            Mode::Browse,
            Mode::Detail { reveal: false },
            Mode::Form(FormState::new_add()),
            Mode::Busy("x".into()),
            Mode::Error("boom".into()),
        ] {
            state.mode = mode;
            let text = render(&mut state);
            assert!(text.contains(&short), "npub missing in header:\n{text}");
            assert!(text.contains("(software)"), "signer label missing:\n{text}");
            assert!(text.contains("[clearnet]"), "net tag missing:\n{text}");
        }
    }

    #[test]
    fn header_net_tag_tracks_config() {
        let mut state = state_with(&[]);
        state.config.net = crate::config::NetMode::Socks5 {
            addr: "127.0.0.1:9050".into(),
        };
        let text = render(&mut state);
        assert!(
            text.contains("[socks5:9050]"),
            "socks5 tag missing:\n{text}"
        );
        state.config.net = crate::config::NetMode::Tor;
        let text = render(&mut state);
        assert!(text.contains("[tor(embedded)]"), "tor tag missing:\n{text}");
    }

    #[test]
    fn network_overlay_lists_modes_addr_and_results() {
        let mut state = state_with(&[]);
        let mut net = crate::tui::NetworkState::new(&crate::config::NetMode::Clearnet);
        state.mode = Mode::Network(net);
        let text = render(&mut state);
        assert!(text.contains("network mode"), "title missing:\n{text}");
        assert!(text.contains("clearnet"), "clearnet row missing:\n{text}");
        assert!(
            text.contains("socks5 proxy: 127.0.0.1:9050"),
            "socks5 row (default addr) missing:\n{text}"
        );
        assert!(
            text.contains("embedded tor"),
            "embedded row missing:\n{text}"
        );
        if !cfg!(feature = "tor") {
            assert!(
                text.contains("requires --features tor build"),
                "feature hint missing:\n{text}"
            );
        }
        assert!(
            text.contains("c: check relays"),
            "key hint missing:\n{text}"
        );

        // Results render inside the overlay.
        net = crate::tui::NetworkState::new(&crate::config::NetMode::Clearnet);
        net.results = Some(vec![
            ("wss://r0.example".into(), None),
            ("wss://r1.example".into(), Some("Disconnected".into())),
        ]);
        state.mode = Mode::Network(net);
        let text = render(&mut state);
        assert!(
            text.contains("✓ wss://r0.example"),
            "ok relay missing:\n{text}"
        );
        assert!(
            text.contains("✗ wss://r1.example: Disconnected"),
            "failed relay missing:\n{text}"
        );

        // While checking, a progress note is shown.
        let mut net = crate::tui::NetworkState::new(&crate::config::NetMode::Clearnet);
        net.checking = true;
        state.mode = Mode::Network(net);
        let text = render(&mut state);
        assert!(
            text.contains("checking relays…"),
            "progress missing:\n{text}"
        );
    }

    #[test]
    fn shorten_npub_keeps_short_strings() {
        assert_eq!(shorten_npub("npub1short"), "npub1short");
        let s = shorten_npub(crate::tui::TEST_NPUB);
        assert!(s.starts_with("npub1"));
        assert!(s.contains('…'));
        assert!(s.len() < crate::tui::TEST_NPUB.len());
    }

    #[test]
    fn help_overlay_lists_keys_and_full_identity() {
        let mut state = state_with(&["web/x"]);
        state.mode = Mode::Help(Box::new(Mode::Browse));
        let text = render(&mut state);
        for needle in [
            "help",
            "rename / move entry",
            "Ctrl-g generate password",
            "t        network mode",
            "Ctrl-l  lock device session",
            "c check relays",
            "press any key to close",
            crate::tui::TEST_NPUB, // full npub, not shortened
            "signer:   software",
            "network:  clearnet",
            "relays:   2 configured",
        ] {
            assert!(text.contains(needle), "missing {needle:?}:\n{text}");
        }
    }

    #[test]
    fn rename_overlay_renders_prefilled_path() {
        let mut state = state_with(&["web/x"]);
        state.mode = Mode::Rename(crate::tui::RenameState::new(
            VaultPath::parse("web/x").unwrap(),
        ));
        let text = render(&mut state);
        assert!(text.contains("rename web/x"), "title missing:\n{text}");
        assert!(text.contains("new path: web/x"), "prefill missing:\n{text}");
        assert!(text.contains("Enter: rename"), "hint missing:\n{text}");
    }

    #[test]
    fn ctrl_g_generated_password_stays_masked_in_form() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};

        let mut state = state_with(&[]);
        let mut form = FormState::new_add();
        form.focus = crate::tui::widgets::FormFocus::Password;
        state.mode = Mode::Form(form);
        update(
            &mut state,
            AppMsg::Key(KeyEvent::new(
                ratatui::crossterm::event::KeyCode::Char('g'),
                KeyModifiers::CONTROL,
            )),
        );
        let generated = match &state.mode {
            Mode::Form(form) => form.password.clone(),
            other => panic!("expected form, got {other:?}"),
        };
        assert_eq!(generated.chars().count(), 24);
        let text = render(&mut state);
        assert!(
            !text.contains(&*generated),
            "generated password must stay masked:\n{text}"
        );
        assert!(text.contains("••••••"), "mask missing:\n{text}");
        assert!(
            text.contains("generated 24-char password"),
            "status hint missing:\n{text}"
        );
    }
}
