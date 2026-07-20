//! Input thread: polls crossterm events on a dedicated std thread and
//! forwards them into the app's tokio mpsc channel. Poll timeouts become
//! [`AppMsg::Tick`] (drives the busy spinner). The thread exits when the
//! receiving side of the channel is gone.

use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tokio::sync::mpsc::Sender;

use super::AppMsg;

/// Poll timeout; also the spinner tick interval.
pub const TICK: Duration = Duration::from_millis(150);

/// Spawn the input-forwarding thread.
pub fn spawn_input_thread(tx: Sender<AppMsg>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        match event::poll(TICK) {
            Ok(true) => {
                let msg = match event::read() {
                    Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        Some(AppMsg::Key(key))
                    }
                    Ok(Event::Resize(..)) => Some(AppMsg::Resize),
                    Ok(_) => None,
                    Err(_) => return,
                };
                if let Some(msg) = msg {
                    if tx.blocking_send(msg).is_err() {
                        return;
                    }
                }
            }
            Ok(false) => {
                if tx.blocking_send(AppMsg::Tick).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    })
}
