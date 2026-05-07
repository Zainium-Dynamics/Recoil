/*
Copyright! (C) 2026 Ali Zain <alizain.arch@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://gnu.org>.
*/

//! # Recoil
//!
//! Immutable system safety net, chronology engine, and integrated vault
//! for Linux.
//!
//! ## Module layout
//!
//! - `cli`       — Clap derive CLI (all nine subcommands)
//! - `config`    — Encrypted JSON configuration persistence
//! - `security`  — PBKDF2-HMAC-SHA512 key derivation, AES-256-GCM vault, rate limiter
//! - `utils`     — OS detection, filesystem detection, logging, constants
//!
//! Phases 2–7 will add:
//! - `shadow`    — Root filesystem mirror (Phase 2)
//! - `vault`     — Encrypted deleted-file storage (Phase 3)
//! - `intercept` — LD_PRELOAD + eBPF interception (Phase 4)
//! - `chronology`— SQLite provenance database (Phase 4)
//! - `integration`— Vaultion bridge (Phase 5)
//! - `daemon`    — Tokio background service (Phase 5)
//! - `tui`       — ratatui interactive interface (Phase 5)

pub mod cli;
pub mod config;
pub mod error;
pub mod security;
pub mod utils;
