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

pub mod setup;

use clap::Args;
use console::style;
use rpassword::prompt_password;

use crate::config::ConfigManager;
use crate::error::{RecoilError, Result};
use crate::utils::constants::RECOIL_VERSION;

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub async fn status(args: StatusArgs) -> Result<()> {
    let mgr = ConfigManager::bootstrap();

    if !mgr.exists() {
        println!(
            "\n  {} Recoil is not initialised on this system.\n  Run {} to begin.\n",
            style("○").dim(),
            style("sudo recoil setup").cyan(),
        );
        return Ok(());
    }

    let pw  = get_password(args.password)?;
    let cfg = mgr.load(&pw)?;

    println!(
        "\n  {} v{}  —  {}\n  {}\n",
        style("Recoil").bold().cyan(),
        RECOIL_VERSION,
        style(&cfg.distro.display_name()).cyan(),
        style("─".repeat(50)).dim(),
    );

    info_row("Distribution", &cfg.distro.display_name());
    info_row("Filesystem",   cfg.filesystem.display_name());
    info_row("Shadow dir",   &cfg.shadow_dir.display().to_string());
    info_row("Link strategy",&cfg.link_strategy.to_string());
    info_row("Created",      &cfg.created_at.format("%Y-%m-%d %H:%M UTC").to_string());

    println!("\n  Phase completion:");
    phase_row("Phase 1 — Foundation",          cfg.phase1_complete);
    phase_row("Phase 2 — Shadow layer",         cfg.phase2_complete);
    phase_row("Phase 3 — Vault + audit log",    cfg.phase3_complete);
    phase_row("Phase 4 — Interceptor",          cfg.phase4_complete);
    phase_row("Phase 5 — Vaultion + daemon",    cfg.phase5_complete);
    phase_row("Phase 6 — eBPF + packaging",     cfg.phase6_complete);
    phase_row("Phase 7 — Validation + release", cfg.phase7_complete);
    println!();

    Ok(())
}

fn info_row(label: &str, value: &str) {
    println!("  {:<14}  {}", style(label).dim(), style(value).cyan());
}

fn phase_row(label: &str, done: bool) {
    if done {
        println!("    {}  {}", style("✓").green(), label);
    } else {
        println!("    {}  {}", style("○").dim(), style(label).dim());
    }
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Path to restore (file, directory, or omit for interactive picker).
    pub path: Option<String>,

    /// Restore as it existed at this timestamp  ("2026-05-04 14:00:00").
    #[arg(long)]
    pub date: Option<String>,

    /// Restore the complete root filesystem from the shadow mirror.
    #[arg(long, default_value_t = false)]
    pub system: bool,

    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub async fn restore(_args: RestoreArgs) -> Result<()> {
    not_implemented("restore", 5,
        "Recovery engine — vault decryption and root-mirror restoration")
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// Full-text search across commands, paths, and provenance metadata.
    #[arg(long)]
    pub search: Option<String>,

    /// Show events since this duration ago  (e.g. "24h", "7d").
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by event type: delete | modify | download | build | vault.
    #[arg(long)]
    pub event: Option<String>,

    /// Maximum number of results to display.
    #[arg(short, long, default_value_t = 50)]
    pub limit: usize,

    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub async fn history(_args: HistoryArgs) -> Result<()> {
    not_implemented("history", 4,
        "SQLite chronology database — implemented in Phase 4")
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub subcommand: VaultSubcmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum VaultSubcmd {
    /// Encrypt a file into the Vaultion vault.
    Encrypt { file: String },
    /// Decrypt and restore a .rvb file.
    Decrypt { file: String, #[arg(long)] output: Option<String> },
    /// Decrypt to RAM and open — temp file wiped after viewing.
    View { file: String },
    /// Securely delete a .rvb file (3-pass overwrite).
    Delete { file: String },
    /// List all encrypted files in the vault.
    List,
    /// Export entire vault as an encrypted .vbk archive.
    Backup { #[arg(long)] output: Option<String> },
    /// Restore from a .vbk backup archive.
    Restore { file: String },
    /// Verify AES-GCM authentication tag on every .rvb file.
    Integrity,
    /// Show vault statistics and health.
    Status,
    /// Lock the vault (indefinite or timed).
    Lock { #[arg(long)] minutes: Option<u64> },
    /// Unlock the vault.
    Unlock,
    /// Change the vault master password.
    ChangePassword,
    /// Permanently destroy all vault contents.
    Purge,
}

pub async fn vault(_args: VaultArgs) -> Result<()> {
    not_implemented("vault", 5,
        "Vaultion integration bridge — implemented in Phase 5")
}

// ---------------------------------------------------------------------------
// daemon
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub subcommand: DaemonSubcmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum DaemonSubcmd {
    /// Start the Recoil daemon.
    Start,
    /// Stop the Recoil daemon.
    Stop,
    /// Show daemon status.
    Status,
    /// Install the systemd service unit.
    Install,
    /// Remove the systemd service unit.
    Uninstall,
}

pub async fn daemon(_args: DaemonArgs) -> Result<()> {
    not_implemented("daemon", 5,
        "Tokio async daemon with systemd integration — implemented in Phase 5")
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub subcommand: ConfigSubcmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum ConfigSubcmd {
    /// Display current configuration.
    Show,
    /// Change the master password.
    ChangePassword,
    /// Export configuration as JSON.
    Export,
}

pub async fn config_cmd(_args: ConfigArgs) -> Result<()> {
    not_implemented("config", 1,
        "Use 'recoil status' to view the current configuration")
}

// ---------------------------------------------------------------------------
// provenance
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct ProvenanceArgs {
    /// File or binary to inspect.
    pub path: String,

    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub async fn provenance(_args: ProvenanceArgs) -> Result<()> {
    not_implemented("provenance", 4,
        "Chronology engine — Git SHA, download source, build command tracking")
}

// ---------------------------------------------------------------------------
// tui
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct TuiArgs {
    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub async fn tui(_args: TuiArgs) -> Result<()> {
    not_implemented("tui", 5,
        "Interactive ratatui terminal UI — implemented in Phase 5")
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Ask for the master password — either from the provided value or by
/// prompting interactively.
pub fn get_password(provided: Option<String>) -> Result<String> {
    match provided {
        Some(p) => Ok(p),
        None => prompt_password("  Master password: ")
            .map_err(|e| RecoilError::Config(format!("Password prompt: {e}"))),
    }
}

/// Printed when a command is not yet implemented in this phase.
fn not_implemented(cmd: &str, phase: u8, description: &str) -> Result<()> {
    println!(
        "\n  {} '{}' is scheduled for Phase {}.\n  {}\n",
        style("○").dim(),
        style(cmd).cyan(),
        style(phase).yellow(),
        style(description).dim(),
    );
    Ok(())
}
