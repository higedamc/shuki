//! Pure keymap: [`action_for`] maps a key event in a [`Mode`] to an [`Action`].
//!
//! No IO, no state mutation — fully table-testable.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::Mode;

/// Semantic input action, decoupled from concrete keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    NavUp,
    NavDown,
    Collapse,
    Expand,
    OpenDetail,
    StartSearch,
    SearchInput(char),
    SearchBackspace,
    SearchAccept,
    SearchCancel,
    CopyPassword,
    StartAdd,
    StartEdit,
    StartDelete,
    StartSync,
    ToggleReveal,
    ConfirmYes,
    ConfirmNo,
    FormInput(char),
    FormBackspace,
    FormNext,
    FormPrev,
    FormSubmit,
    FormCancel,
    /// Ctrl-g in the form: fill the focused password field with a generated
    /// password.
    FormGeneratePassword,
    OpenHelp,
    CloseHelp,
    /// `t` in browse: open the network-mode overlay.
    OpenNetwork,
    NetSelectUp,
    NetSelectDown,
    /// Typed character for the socks5 address field (socks5 row selected).
    NetInput(char),
    NetBackspace,
    /// Enter in the overlay: apply the selected mode.
    NetApply,
    /// `c` in the overlay: check relay connectivity through the current mode.
    NetCheck,
    NetClose,
    StartRename,
    RenameInput(char),
    RenameBackspace,
    RenameSubmit,
    RenameCancel,
    DismissError,
    Back,
    Quit,
}

/// A printable character typed without control-ish modifiers (Shift is fine).
fn text_char(key: KeyEvent) -> Option<char> {
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
    {
        return None;
    }
    match key.code {
        KeyCode::Char(c) => Some(c),
        _ => None,
    }
}

/// Map `key` to an action for the current `mode`. `None` = ignored key.
pub fn action_for(mode: &Mode, key: KeyEvent) -> Option<Action> {
    // Ctrl-C quits from every mode.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match mode {
        Mode::Browse => match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Action::NavDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::NavUp),
            KeyCode::Char('h') | KeyCode::Left => Some(Action::Collapse),
            KeyCode::Char('l') | KeyCode::Right => Some(Action::Expand),
            KeyCode::Enter => Some(Action::OpenDetail),
            KeyCode::Char('/') => Some(Action::StartSearch),
            KeyCode::Char('y') => Some(Action::CopyPassword),
            KeyCode::Char('a') => Some(Action::StartAdd),
            KeyCode::Char('e') => Some(Action::StartEdit),
            KeyCode::Char('d') => Some(Action::StartDelete),
            KeyCode::Char('s') => Some(Action::StartSync),
            KeyCode::Char('t') => Some(Action::OpenNetwork),
            KeyCode::Char('m') => Some(Action::StartRename),
            KeyCode::Char('?') => Some(Action::OpenHelp),
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        },
        Mode::Search(_) => match key.code {
            KeyCode::Enter => Some(Action::SearchAccept),
            KeyCode::Esc => Some(Action::SearchCancel),
            KeyCode::Backspace => Some(Action::SearchBackspace),
            _ => text_char(key).map(Action::SearchInput),
        },
        Mode::Detail { .. } => match key.code {
            KeyCode::Char('r') => Some(Action::ToggleReveal),
            KeyCode::Char('y') => Some(Action::CopyPassword),
            KeyCode::Char('m') => Some(Action::StartRename),
            KeyCode::Char('?') => Some(Action::OpenHelp),
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        },
        Mode::Form(_) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
                return Some(Action::FormGeneratePassword);
            }
            match key.code {
                KeyCode::Tab => Some(Action::FormNext),
                KeyCode::BackTab => Some(Action::FormPrev),
                KeyCode::Enter => Some(Action::FormSubmit),
                KeyCode::Esc => Some(Action::FormCancel),
                KeyCode::Backspace => Some(Action::FormBackspace),
                _ => text_char(key).map(Action::FormInput),
            }
        }
        Mode::Network(net) => {
            // On the socks5 row printable characters edit the proxy address
            // (so `c` types into it); elsewhere `c` runs the relay check.
            let editing = net.choice == crate::tui::widgets::NetChoice::Socks5;
            match key.code {
                KeyCode::Char('j') | KeyCode::Down => Some(Action::NetSelectDown),
                KeyCode::Char('k') | KeyCode::Up => Some(Action::NetSelectUp),
                KeyCode::Enter => Some(Action::NetApply),
                KeyCode::Esc => Some(Action::NetClose),
                KeyCode::Backspace if editing => Some(Action::NetBackspace),
                KeyCode::Char('c') if !editing => Some(Action::NetCheck),
                _ if editing => text_char(key).map(Action::NetInput),
                _ => None,
            }
        }
        Mode::Rename(_) => match key.code {
            KeyCode::Enter => Some(Action::RenameSubmit),
            KeyCode::Esc => Some(Action::RenameCancel),
            KeyCode::Backspace => Some(Action::RenameBackspace),
            _ => text_char(key).map(Action::RenameInput),
        },
        // Any key closes the help overlay (Ctrl-C already quit above).
        Mode::Help(_) => Some(Action::CloseHelp),
        Mode::ConfirmDelete(_) => match key.code {
            KeyCode::Char('y') => Some(Action::ConfirmYes),
            KeyCode::Char('n') | KeyCode::Esc => Some(Action::ConfirmNo),
            _ => None,
        },
        Mode::Busy(_) => None,
        Mode::Error(_) => match key.code {
            KeyCode::Esc | KeyCode::Enter => Some(Action::DismissError),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VaultPath;
    use crate::tui::widgets::FormState;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn shift(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::SHIFT)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn check(mode: &Mode, cases: &[(KeyEvent, Option<Action>)]) {
        for (k, expected) in cases {
            assert_eq!(&action_for(mode, *k), expected, "key {k:?} in {mode:?}");
        }
    }

    #[test]
    fn browse_keymap() {
        check(
            &Mode::Browse,
            &[
                (key(KeyCode::Char('j')), Some(Action::NavDown)),
                (key(KeyCode::Down), Some(Action::NavDown)),
                (key(KeyCode::Char('k')), Some(Action::NavUp)),
                (key(KeyCode::Up), Some(Action::NavUp)),
                (key(KeyCode::Char('h')), Some(Action::Collapse)),
                (key(KeyCode::Left), Some(Action::Collapse)),
                (key(KeyCode::Char('l')), Some(Action::Expand)),
                (key(KeyCode::Right), Some(Action::Expand)),
                (key(KeyCode::Enter), Some(Action::OpenDetail)),
                (key(KeyCode::Char('/')), Some(Action::StartSearch)),
                (key(KeyCode::Char('y')), Some(Action::CopyPassword)),
                (key(KeyCode::Char('a')), Some(Action::StartAdd)),
                (key(KeyCode::Char('e')), Some(Action::StartEdit)),
                (key(KeyCode::Char('d')), Some(Action::StartDelete)),
                (key(KeyCode::Char('s')), Some(Action::StartSync)),
                (key(KeyCode::Char('t')), Some(Action::OpenNetwork)),
                (key(KeyCode::Char('m')), Some(Action::StartRename)),
                (key(KeyCode::Char('?')), Some(Action::OpenHelp)),
                (key(KeyCode::Char('q')), Some(Action::Quit)),
                (key(KeyCode::Esc), Some(Action::Back)),
                (key(KeyCode::Char('x')), None),
                (key(KeyCode::Tab), None),
                (key(KeyCode::Backspace), None),
            ],
        );
    }

    #[test]
    fn search_keymap() {
        check(
            &Mode::Search("gi".into()),
            &[
                (key(KeyCode::Enter), Some(Action::SearchAccept)),
                (key(KeyCode::Esc), Some(Action::SearchCancel)),
                (key(KeyCode::Backspace), Some(Action::SearchBackspace)),
                (key(KeyCode::Char('t')), Some(Action::SearchInput('t'))),
                // Browse keys become plain input while searching.
                (key(KeyCode::Char('q')), Some(Action::SearchInput('q'))),
                (key(KeyCode::Char('/')), Some(Action::SearchInput('/'))),
                (shift(KeyCode::Char('G')), Some(Action::SearchInput('G'))),
                (ctrl('x'), None),
                (key(KeyCode::Tab), None),
                (key(KeyCode::Down), None),
            ],
        );
    }

    #[test]
    fn detail_keymap() {
        for reveal in [false, true] {
            check(
                &Mode::Detail { reveal },
                &[
                    (key(KeyCode::Char('r')), Some(Action::ToggleReveal)),
                    (key(KeyCode::Char('y')), Some(Action::CopyPassword)),
                    (key(KeyCode::Char('m')), Some(Action::StartRename)),
                    (key(KeyCode::Char('?')), Some(Action::OpenHelp)),
                    (key(KeyCode::Esc), Some(Action::Back)),
                    (key(KeyCode::Char('j')), None),
                    (key(KeyCode::Enter), None),
                    (key(KeyCode::Char('d')), None),
                ],
            );
        }
    }

    #[test]
    fn form_keymap() {
        check(
            &Mode::Form(FormState::new_add()),
            &[
                (key(KeyCode::Tab), Some(Action::FormNext)),
                (key(KeyCode::BackTab), Some(Action::FormPrev)),
                (key(KeyCode::Enter), Some(Action::FormSubmit)),
                (key(KeyCode::Esc), Some(Action::FormCancel)),
                (key(KeyCode::Backspace), Some(Action::FormBackspace)),
                (key(KeyCode::Char('a')), Some(Action::FormInput('a'))),
                (key(KeyCode::Char('/')), Some(Action::FormInput('/'))),
                (shift(KeyCode::Char('P')), Some(Action::FormInput('P'))),
                (ctrl('g'), Some(Action::FormGeneratePassword)),
                (ctrl('x'), None),
                (key(KeyCode::Down), None),
            ],
        );
    }

    #[test]
    fn rename_keymap() {
        check(
            &Mode::Rename(crate::tui::widgets::RenameState::new(
                VaultPath::parse("a/b").unwrap(),
            )),
            &[
                (key(KeyCode::Enter), Some(Action::RenameSubmit)),
                (key(KeyCode::Esc), Some(Action::RenameCancel)),
                (key(KeyCode::Backspace), Some(Action::RenameBackspace)),
                (key(KeyCode::Char('x')), Some(Action::RenameInput('x'))),
                (key(KeyCode::Char('/')), Some(Action::RenameInput('/'))),
                (ctrl('x'), None),
                (key(KeyCode::Tab), None),
            ],
        );
    }

    #[test]
    fn network_keymap_non_socks5_row_runs_check() {
        use crate::config::NetMode;
        use crate::tui::widgets::NetworkState;

        let mode = Mode::Network(NetworkState::new(&NetMode::Clearnet));
        check(
            &mode,
            &[
                (key(KeyCode::Char('j')), Some(Action::NetSelectDown)),
                (key(KeyCode::Down), Some(Action::NetSelectDown)),
                (key(KeyCode::Char('k')), Some(Action::NetSelectUp)),
                (key(KeyCode::Up), Some(Action::NetSelectUp)),
                (key(KeyCode::Enter), Some(Action::NetApply)),
                (key(KeyCode::Esc), Some(Action::NetClose)),
                (key(KeyCode::Char('c')), Some(Action::NetCheck)),
                // Not editing → plain characters and backspace are ignored.
                (key(KeyCode::Char('x')), None),
                (key(KeyCode::Backspace), None),
                (key(KeyCode::Tab), None),
            ],
        );
    }

    #[test]
    fn network_keymap_socks5_row_edits_addr() {
        use crate::config::NetMode;
        use crate::tui::widgets::NetworkState;

        let mode = Mode::Network(NetworkState::new(&NetMode::Socks5 {
            addr: "127.0.0.1:9050".into(),
        }));
        check(
            &mode,
            &[
                (key(KeyCode::Char('1')), Some(Action::NetInput('1'))),
                (key(KeyCode::Char(':')), Some(Action::NetInput(':'))),
                // `c` types into the address instead of running the check.
                (key(KeyCode::Char('c')), Some(Action::NetInput('c'))),
                (key(KeyCode::Backspace), Some(Action::NetBackspace)),
                // Navigation and apply/close still work.
                (key(KeyCode::Char('j')), Some(Action::NetSelectDown)),
                (key(KeyCode::Char('k')), Some(Action::NetSelectUp)),
                (key(KeyCode::Enter), Some(Action::NetApply)),
                (key(KeyCode::Esc), Some(Action::NetClose)),
                (ctrl('x'), None),
            ],
        );
    }

    #[test]
    fn help_keymap_any_key_closes() {
        let mode = Mode::Help(Box::new(Mode::Browse));
        for k in [
            key(KeyCode::Esc),
            key(KeyCode::Enter),
            key(KeyCode::Char('?')),
            key(KeyCode::Char('q')),
            key(KeyCode::Char('j')),
            key(KeyCode::Tab),
        ] {
            assert_eq!(action_for(&mode, k), Some(Action::CloseHelp), "key {k:?}");
        }
        // Ctrl-C still quits from the help overlay.
        assert_eq!(action_for(&mode, ctrl('c')), Some(Action::Quit));
    }

    #[test]
    fn confirm_delete_keymap() {
        check(
            &Mode::ConfirmDelete(VaultPath::parse("a/b").unwrap()),
            &[
                (key(KeyCode::Char('y')), Some(Action::ConfirmYes)),
                (key(KeyCode::Char('n')), Some(Action::ConfirmNo)),
                (key(KeyCode::Esc), Some(Action::ConfirmNo)),
                (key(KeyCode::Enter), None),
                (key(KeyCode::Char('d')), None),
                (key(KeyCode::Char('q')), None),
            ],
        );
    }

    #[test]
    fn busy_keymap_ignores_everything_but_ctrl_c() {
        check(
            &Mode::Busy("syncing".into()),
            &[
                (key(KeyCode::Char('q')), None),
                (key(KeyCode::Esc), None),
                (key(KeyCode::Enter), None),
                (key(KeyCode::Char('j')), None),
            ],
        );
    }

    #[test]
    fn error_keymap() {
        check(
            &Mode::Error("boom".into()),
            &[
                (key(KeyCode::Esc), Some(Action::DismissError)),
                (key(KeyCode::Enter), Some(Action::DismissError)),
                (key(KeyCode::Char('q')), Some(Action::Quit)),
                (key(KeyCode::Char('j')), None),
            ],
        );
    }

    #[test]
    fn ctrl_c_quits_in_every_mode() {
        let modes = [
            Mode::Browse,
            Mode::Search("x".into()),
            Mode::Detail { reveal: false },
            Mode::Form(FormState::new_add()),
            Mode::ConfirmDelete(VaultPath::parse("a").unwrap()),
            Mode::Rename(crate::tui::widgets::RenameState::new(
                VaultPath::parse("a").unwrap(),
            )),
            Mode::Help(Box::new(Mode::Browse)),
            Mode::Network(crate::tui::widgets::NetworkState::new(
                &crate::config::NetMode::Clearnet,
            )),
            Mode::Busy("b".into()),
            Mode::Error("e".into()),
        ];
        for mode in &modes {
            assert_eq!(action_for(mode, ctrl('c')), Some(Action::Quit), "{mode:?}");
        }
    }
}
