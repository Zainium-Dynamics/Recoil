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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoilError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Recoil is not initialised — run 'sudo recoil setup' first")]
    NotInitialised,

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    // Intentionally vague — never tell an attacker why auth failed
    #[error("Authentication failed")]
    AuthFailed,

    #[error("Vault locked — too many failed attempts. Try again in {minutes} minute(s)")]
    RateLimited { minutes: u64 },

    #[error("Vault permanently locked due to sustained attack. Manual reset required")]
    HardLocked,

    #[error("OS detection failed: {0}")]
    OsDetection(String),

    #[error("Filesystem detection failed: {0}")]
    FsDetection(String),

    #[error("Shadow layer error: {0}")]
    Shadow(String),

    #[error("Shadow layer not initialised — complete 'sudo recoil setup' first")]
    ShadowNotInitialised,

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Path not found in vault: {path}")]
    NotInVault { path: String },

    #[error("Chronology database error: {0}")]
    Chronology(String),

    #[error("Interceptor error: {0}")]
    Interceptor(String),

    #[error("Daemon error: {0}")]
    Daemon(String),

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("This command requires root — run with sudo")]
    PermissionDenied,

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for RecoilError {
    fn from(e: serde_json::Error) -> Self {
        RecoilError::Serialisation(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RecoilError>;
