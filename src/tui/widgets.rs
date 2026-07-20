//! Form widget state + rendering (add / edit entry).
//!
//! The password field is kept in a [`Zeroizing`] buffer and rendered masked;
//! `FormState` deliberately implements a redacting `Debug`.

use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::Frame;
use zeroize::Zeroizing;

use crate::domain::{Entry, EntryFields, SecretField, VaultPath};

/// Which form field currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFocus {
    Path,
    Username,
    Password,
    Url,
    Notes,
}

const FOCUS_ORDER: [FormFocus; 5] = [
    FormFocus::Path,
    FormFocus::Username,
    FormFocus::Password,
    FormFocus::Url,
    FormFocus::Notes,
];

/// State of the add/edit entry form.
///
/// In edit mode the path is fixed (rename is not supported from the form);
/// focus cycling skips the path field. `custom` fields of an edited entry are
/// carried through unchanged.
pub struct FormState {
    pub editing: bool,
    pub path: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: Zeroizing<String>,
    pub focus: FormFocus,
    custom: BTreeMap<String, SecretField>,
}

impl std::fmt::Debug for FormState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormState")
            .field("editing", &self.editing)
            .field("path", &self.path)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .field("focus", &self.focus)
            .finish()
    }
}

impl FormState {
    /// Empty form for a new entry.
    pub fn new_add() -> Self {
        Self {
            editing: false,
            path: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            url: String::new(),
            notes: Zeroizing::new(String::new()),
            focus: FormFocus::Path,
            custom: BTreeMap::new(),
        }
    }

    /// Form prefilled from an existing entry (path fixed).
    pub fn edit(entry: &Entry) -> Self {
        let f = &entry.fields;
        Self {
            editing: true,
            path: entry.path.to_string(),
            username: f.username.clone().unwrap_or_default(),
            password: Zeroizing::new(
                f.password
                    .as_ref()
                    .map_or_else(String::new, |p| p.expose().to_owned()),
            ),
            url: f.url.clone().unwrap_or_default(),
            notes: Zeroizing::new(
                f.notes
                    .as_ref()
                    .map_or_else(String::new, |n| n.expose().to_owned()),
            ),
            focus: FormFocus::Username,
            custom: f.custom.clone(),
        }
    }

    fn focus_index(&self) -> usize {
        FOCUS_ORDER
            .iter()
            .position(|f| *f == self.focus)
            .unwrap_or(0)
    }

    /// Tab: focus the next field (skipping the fixed path in edit mode).
    pub fn next(&mut self) {
        let mut i = (self.focus_index() + 1) % FOCUS_ORDER.len();
        if self.editing && FOCUS_ORDER[i] == FormFocus::Path {
            i = (i + 1) % FOCUS_ORDER.len();
        }
        self.focus = FOCUS_ORDER[i];
    }

    /// Shift-Tab: focus the previous field (skipping the fixed path in edit mode).
    pub fn prev(&mut self) {
        let mut i = (self.focus_index() + FOCUS_ORDER.len() - 1) % FOCUS_ORDER.len();
        if self.editing && FOCUS_ORDER[i] == FormFocus::Path {
            i = (i + FOCUS_ORDER.len() - 1) % FOCUS_ORDER.len();
        }
        self.focus = FOCUS_ORDER[i];
    }

    fn active_mut(&mut self) -> &mut String {
        match self.focus {
            FormFocus::Path => &mut self.path,
            FormFocus::Username => &mut self.username,
            FormFocus::Password => &mut self.password,
            FormFocus::Url => &mut self.url,
            FormFocus::Notes => &mut self.notes,
        }
    }

    /// Append a typed character to the focused field.
    pub fn input(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        self.active_mut().push(c);
    }

    /// Remove the last character of the focused field.
    pub fn backspace(&mut self) {
        self.active_mut().pop();
    }

    /// Replace the password field (the previous buffer is dropped zeroized).
    pub fn set_password(&mut self, password: &str) {
        self.password = Zeroizing::new(password.to_owned());
    }

    /// Validate and build the [`Entry`] to save. `updated_at` is left at 0:
    /// the vault stamps it on `put`.
    pub fn build_entry(&self) -> std::result::Result<Entry, String> {
        let path = VaultPath::parse(self.path.trim()).map_err(|e| e.to_string())?;
        let non_empty = |s: &str| {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_owned())
        };
        let fields = EntryFields {
            password: (!self.password.is_empty())
                .then(|| SecretField::new(self.password.as_str().to_owned())),
            username: non_empty(&self.username),
            url: non_empty(&self.url),
            notes: (!self.notes.is_empty())
                .then(|| SecretField::new(self.notes.as_str().to_owned())),
            custom: self.custom.clone(),
        };
        Ok(Entry {
            path,
            fields,
            updated_at: 0,
        })
    }
}

/// Render the add/edit form into `area`.
pub fn render_form(frame: &mut Frame, area: Rect, form: &FormState) {
    let title = if form.editing {
        "edit entry"
    } else {
        "add entry"
    };
    let masked: String = "•".repeat(form.password.chars().count());
    let rows: [(FormFocus, &str, &str); 5] = [
        (FormFocus::Path, "path", form.path.as_str()),
        (FormFocus::Username, "username", form.username.as_str()),
        (FormFocus::Password, "password", masked.as_str()),
        (FormFocus::Url, "url", form.url.as_str()),
        (FormFocus::Notes, "notes", form.notes.as_str()),
    ];
    let mut lines: Vec<Line> = Vec::with_capacity(7);
    for (focus, label, value) in rows {
        let fixed = form.editing && focus == FormFocus::Path;
        let marker = if focus == form.focus { "▸ " } else { "  " };
        let suffix = if fixed { " (fixed)" } else { "" };
        let line = Line::raw(format!("{marker}{label}{suffix}: {value}"));
        if focus == form.focus {
            lines.push(line.style(Style::default().add_modifier(Modifier::REVERSED)));
        } else {
            lines.push(line);
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(
        "Tab/Shift-Tab: field   Ctrl-g: generate password   Enter: save   Esc: cancel",
    ));
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)),
        area,
    );
}

/// State of the move/rename input overlay: `to` starts prefilled with the
/// current path.
#[derive(Debug)]
pub struct RenameState {
    /// Path being renamed (fixed).
    pub from: VaultPath,
    /// Editable target path.
    pub to: String,
}

impl RenameState {
    /// Overlay prefilled with the current path.
    pub fn new(from: VaultPath) -> Self {
        let to = from.to_string();
        Self { from, to }
    }

    /// Append a typed character.
    pub fn input(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        self.to.push(c);
    }

    /// Remove the last character.
    pub fn backspace(&mut self) {
        self.to.pop();
    }
}

/// Centered sub-rectangle: `percent_x` of the width, fixed `height` rows.
pub fn centered_rect(area: Rect, percent_x: u16, height: u16) -> Rect {
    let [h] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [rect] = Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .areas(h);
    rect
}

/// Render the one-line rename/move overlay centered over `full`.
pub fn render_rename(frame: &mut Frame, full: Rect, rename: &RenameState) {
    let area = centered_rect(full, 70, 5);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::raw(format!("new path: {}▏", rename.to)),
        Line::raw(""),
        Line::raw("Enter: rename   Esc: cancel"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(format!("rename {}", rename.from))),
        area,
    );
}
