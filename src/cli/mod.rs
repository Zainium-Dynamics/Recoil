/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

pub mod auth;
pub mod commands;
pub mod display;

use crate::error::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "recoil",
    version = "1.0.0",
    about = "Immutable System Safety Net for Linux"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// First-time initialisation — creates shadow layer and root mirror
    Setup(commands::setup::SetupArgs),
    /// Show system protection status
    Status(commands::status::StatusArgs),
    /// View and search the complete system chronology
    History(commands::history::HistoryArgs),
    /// Restore files or directories from vault or root mirror
    Restore(commands::restore::RestoreArgs),
    /// Shadow layer structural integrity verification
    Verify(commands::verify::VerifyArgs),
    /// Authenticated shadow layer unlock (chattr -i)
    Unlock(commands::unlock::UnlockArgs),
    /// Show the complete lifecycle record for any file or binary
    Provenance(commands::provenance::ProvenanceArgs),
    /// Per-file AES-256-GCM vault operations
    Vault(commands::vault::VaultArgs),
    /// Background daemon management
    Daemon(commands::daemon::DaemonArgs),
    /// Interactive terminal user interface
    Tui(commands::tui::TuiArgs),
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Setup(a) => commands::setup::run(a).await,
        Command::Status(a) => commands::status::run(a).await,
        Command::History(a) => commands::history::run(a).await,
        Command::Restore(a) => commands::restore::run(a).await,
        Command::Verify(a) => commands::verify::run(a).await,
        Command::Unlock(a) => commands::unlock::run(a).await,
        Command::Provenance(a) => commands::provenance::run(a).await,
        Command::Vault(a) => commands::vault::run(a).await,
        Command::Daemon(a) => commands::daemon::run(a).await,
        Command::Tui(a) => commands::tui::run(a).await,
    }
}
