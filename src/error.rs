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

use thiserror::Error;

/// Unified error type for the entire Recoil codebase.
///
/// All 19 variants are defined from the start so that function signatures
/// never change as new milestones are implemented. New milestones only
/// add implementations — they never change module boundaries.
///
/// `AuthFailed` intentionally carries no diagnostic detail. Distinguishing
/// between a wrong password, tampered ciphertext, and a truncated file
/// would help an attacker narrow their approach. All three return the
/// same variant with the same message.
#[derive(Debug, Error)]
pub enum RecoilError {
    // ── I/O and system ─────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("This command requires root — run with sudo")]
    PermissionDenied,

    #[error("Recoil is not initialised on this system — run 'sudo recoil setup' first")]
    NotInitialised,

    // ── Authentication ──────────────────────────────────────────────────
    #[error("Incorrect password")]
    AuthFailed,

    #[error("Vault locked — too many failed attempts. Try again in {minutes} minute(s)")]
    RateLimited { minutes: u64 },

    #[error("Vault permanently locked due to repeated failed attempts. Manual reset required")]
    HardLocked,

    // ── Configuration ───────────────────────────────────────────────────
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    // ── Cryptography ────────────────────────────────────────────────────
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    // ── OS and filesystem detection ─────────────────────────────────────
    #[error("OS detection failed: {0}")]
    OsDetection(String),

    #[error("Filesystem detection failed: {0}")]
    FsDetection(String),

    // ── Shadow layer (Milestone 2) ──────────────────────────────────────
    #[error("Shadow layer error: {0}")]
    Shadow(String),

    #[error("Shadow layer not initialised — run 'sudo recoil setup' first")]
    ShadowNotInitialised,

    // ── Vault (Milestone 3) ─────────────────────────────────────────────
    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Path not found in vault: {path}")]
    NotInVault { path: String },

    // ── Chronology engine (Milestone 4) ────────────────────────────────
    #[error("Chronology database error: {0}")]
    Chronology(String),

    // ── Interception layer (Milestone 4) ───────────────────────────────
    #[error("Interceptor error: {0}")]
    Interceptor(String),

    // ── Daemon (Milestone 5) ────────────────────────────────────────────
    #[error("Daemon error: {0}")]
    Daemon(String),

    // ── General ─────────────────────────────────────────────────────────
    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for RecoilError {
    fn from(e: serde_json::Error) -> Self {
        RecoilError::Serialisation(e.to_string())
    }
}

/// Project-wide result alias. Every public function returns this type.
pub type Result<T> = std::result::Result<T, RecoilError>;
