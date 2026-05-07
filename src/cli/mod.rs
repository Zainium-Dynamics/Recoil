/*
Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>

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

pub mod commands;

use clap::{Parser, Subcommand};

use commands::{
    setup::SetupArgs, ConfigArgs, DaemonArgs, HistoryArgs,
    ProvenanceArgs, RestoreArgs, StatusArgs, TuiArgs, VaultArgs,
};
use crate::error::Result;

// ---------------------------------------------------------------------------
// Top-level CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name    = "recoil",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Immutable system safety net and chronology engine for Linux",
    long_about = "\
Recoil protects Linux systems from permanent data loss caused by accidental\n\
or destructive terminal commands.  It mirrors the entire root filesystem\n\
into a cryptographically sealed, kernel-immutable shadow layer and maintains\n\
a forensic-quality record of every significant system change.\n\n\
First run:   sudo recoil setup\n\
Check status: recoil status",
    arg_required_else_help = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialise Recoil on this system (requires root).
    Setup(SetupArgs),

    /// Show protection status and phase completion.
    Status(StatusArgs),

    /// Restore a file, directory, or the full system from the vault.
    Restore(RestoreArgs),

    /// Browse and search the system chronology.
    History(HistoryArgs),

    /// Manage the integrated Vaultion encrypted vault.
    Vault(VaultArgs),

    /// Control the Recoil background daemon.
    Daemon(DaemonArgs),

    /// View or change Recoil configuration.
    Config(ConfigArgs),

    /// Show the complete lifecycle provenance of a file or binary.
    Provenance(ProvenanceArgs),

    /// Open the interactive terminal UI.
    Tui(TuiArgs),
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Setup(a)      => commands::setup::run(a).await,
        Command::Status(a)     => commands::status(a).await,
        Command::Restore(a)    => commands::restore(a).await,
        Command::History(a)    => commands::history(a).await,
        Command::Vault(a)      => commands::vault(a).await,
        Command::Daemon(a)     => commands::daemon(a).await,
        Command::Config(a)     => commands::config_cmd(a).await,
        Command::Provenance(a) => commands::provenance(a).await,
        Command::Tui(a)        => commands::tui(a).await,
    }
}
