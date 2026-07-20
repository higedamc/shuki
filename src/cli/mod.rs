//! CLI surface (owned by `leaf/cli-commands-all`).
//!
//! Commands: init, ls, show [-c], insert, generate, edit, rm, mv, find,
//! sync, relay add/rm/ls, key export/import. No args → TUI (dispatched by
//! `main.rs` in the integration phase).

pub mod commands;
