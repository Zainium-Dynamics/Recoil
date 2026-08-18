/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! Recoil — Immutable Root Filesystem Mirror, Atomic Rollback Engine,
//! Hybrid Kernel Interception and Cryptographic Provenance Tracking
//! for Linux and Redox OS.
//!
//! Module layout:
//!   cli      — Clap command-line interface and all command handlers
//!   config   — RecoilConfig schema and AES-256-GCM encrypted persistence
//!   error    — Unified RecoilError type covering all five milestones
//!   security — PBKDF2 key derivation, AES-256-GCM, LockState rate limiter
//!   shadow   — Shadow layer engine (immutability, linking, scanning)
//!   utils    — OS detection, filesystem detection, constants, logging

pub mod cli;
pub mod config;
pub mod error;
pub mod security;
pub mod shadow;
pub mod utils;
