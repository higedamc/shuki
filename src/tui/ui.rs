//! Rendering: tree pane (left), detail/form/confirm pane (right), status bar.
//!
//! Secrets: the detail pane renders the password as a fixed-length mask
//! (never the real length) unless the user explicitly revealed it.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
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
    let [main, status] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(frame.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(main);

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
        Line::raw("d        delete entry"),
        Line::raw("s        sync"),
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
        let mut state = AppState::new(true, 45);
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
}
