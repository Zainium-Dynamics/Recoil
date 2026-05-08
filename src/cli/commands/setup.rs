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

use std::time::Duration;

use clap::Args;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use tracing::info;

use crate::config::{ConfigManager, RecoilConfig};
use crate::error::{RecoilError, Result};
use crate::security::{password_strength, Strength};
use crate::utils::{
    constants::{MIN_FREE_BYTES, MIN_PASSWORD_LEN, RECOIL_VERSION},
    fs_detect::{available_bytes, detect_filesystem},
    os_detect::{detect_distro, is_root, kernel_version},
};

#[derive(Args, Debug)]
pub struct SetupArgs {
    /// Skip the minimum-disk-space check.
    #[arg(long, default_value_t = false)]
    pub skip_space_check: bool,

    /// Read password from this env var instead of prompting.
    /// Only use this for automated provisioning — not interactive use.
    #[arg(long, env = "RECOIL_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub async fn run(args: SetupArgs) -> Result<()> {
    print_banner();

    // ── Step 1: must be root ────────────────────────────────────────────────
    if !is_root() {
        return Err(RecoilError::PermissionDenied);
    }

    // ── Step 2: already initialised? ───────────────────────────────────────
    if ConfigManager::bootstrap().exists() {
        println!(
            "\n  {} Recoil is already initialised on this system.\n  \
             Run {} to check the current status.\n",
            style("!").yellow().bold(),
            style("recoil status").cyan(),
        );
        return Ok(());
    }

    // ── Step 3: detect distro ──────────────────────────────────────────────
    let sp = spinner("Detecting Linux distribution ...");
    let distro = detect_distro()?;
    let kernel = kernel_version().unwrap_or_else(|_| "unknown".into());
    sp.finish_with_message(format!(
        "{} {}  (kernel {})",
        ok_tick(),
        style(distro.display_name()).cyan().bold(),
        style(&kernel).dim(),
    ));

    // ── Step 4: detect filesystem ──────────────────────────────────────────
    let sp = spinner("Detecting root filesystem ...");
    let fs = detect_filesystem(std::path::Path::new("/"))?;
    sp.finish_with_message(format!(
        "{} {}  →  link strategy: {}",
        ok_tick(),
        style(fs.display_name()).cyan(),
        style(fs.link_strategy().to_string()).dim(),
    ));

    // ── Step 5: disk space pre-flight ──────────────────────────────────────
    if !args.skip_space_check {
        let sp = spinner("Checking available disk space ...");
        let free = available_bytes(std::path::Path::new("/"))?;
        if free < MIN_FREE_BYTES {
            sp.finish_with_message(format!(
                "{} Only {} MiB free — at least {} MiB required",
                style("✗").red().bold(),
                free / 1024 / 1024,
                MIN_FREE_BYTES / 1024 / 1024,
            ));
            return Err(RecoilError::Config(format!(
                "Insufficient disk space ({} MiB free, {} MiB required)",
                free / 1024 / 1024,
                MIN_FREE_BYTES / 1024 / 1024,
            )));
        }
        sp.finish_with_message(format!(
            "{} {} MiB available",
            ok_tick(),
            free / 1024 / 1024,
        ));
    }

    // ── Step 6: shadow directory preview ───────────────────────────────────
    let shadow = distro.shadow_path();
    println!(
        "\n  {}  Shadow directory  →  {}\n",
        style("→").blue().bold(),
        style(shadow.display()).yellow(),
    );

    // ── Step 7: master password ────────────────────────────────────────────
    let password = match args.password {
        Some(p) => {
            println!(
                "  {} Using password from environment variable.\n",
                style("⚠").yellow(),
            );
            p
        }
        None => prompt_new_password()?,
    };

    // ── Step 8: derive key + write config ──────────────────────────────────
    let sp = spinner("Deriving master key with Argon2id  (this takes ~3 s) ...");

    let mut config = RecoilConfig::new(distro.clone(), fs.clone());
    config.phase1_complete = true;

    let mgr = ConfigManager::bootstrap();
    mgr.save(&config, &password)?;

    sp.finish_with_message(format!(
        "{} Master key derived — config encrypted and saved",
        ok_tick(),
    ));

    println!();
    phase_line("Phase 2  —  Root filesystem mirror + chattr +i", false);
    phase_line("Phase 3  —  AES-256-GCM vault + audit log", false);
    phase_line("Phase 4  —  LD_PRELOAD interceptor + chronology", false);
    phase_line("Phase 5  —  Vaultion integration + daemon", false);
    phase_line("Phase 6  —  eBPF + multi-distro packaging", false);
    phase_line("Phase 7  —  Validation report + v1.0.0 release", false);

    println!(
        "\n  {} Recoil Phase 1 setup complete.\n",
        style("✓").green().bold(),
    );
    println!(
        "  {}  Distribution  {}",
        style("→").blue(),
        style(distro.display_name()).cyan(),
    );
    println!(
        "  {}  Filesystem     {}",
        style("→").blue(),
        style(fs.display_name()).cyan(),
    );
    println!(
        "  {}  Shadow dir     {}",
        style("→").blue(),
        style(shadow.display()).yellow(),
    );
    println!(
        "  {}  Config         {}\n",
        style("→").blue(),
        style(mgr.path().display()).dim(),
    );

    info!(distro = ?config.distro, shadow = %shadow.display(), "Phase 1 setup complete");
    Ok(())
}

// Password prompt

fn prompt_new_password() -> Result<String> {
    println!(
        "  {}  Create the Recoil master password.\n\n  {}  This password is the only key to your vault. If you lose it, your recovery data is permanently inaccessible. Write it down and store it physically.\n",
        style("→").blue().bold(),
        style("⚠").yellow().bold(),
    );

    loop {
        let pw1 = prompt_password("  Master password: ")
            .map_err(|e| RecoilError::Config(format!("Password prompt: {e}")))?;

        if pw1.len() < MIN_PASSWORD_LEN {
            eprintln!(
                "\n  {} Password must be at least {} characters.\n",
                style("✗").red(),
                MIN_PASSWORD_LEN,
            );
            continue;
        }

        match password_strength(&pw1) {
            Strength::Weak => eprintln!(
                "  {} Weak password — consider adding uppercase, digits and symbols.",
                style("⚠").yellow(),
            ),
            Strength::Moderate => {
                println!("  {} Password strength: moderate.", style("~").yellow(),)
            }
            Strength::Strong => println!("  {} Password strength: strong.", style("✓").green(),),
        }

        let pw2 = prompt_password("  Confirm password: ")
            .map_err(|e| RecoilError::Config(format!("Confirm prompt: {e}")))?;

        if pw1 != pw2 {
            eprintln!(
                "\n  {} Passwords do not match — try again.\n",
                style("✗").red()
            );
            continue;
        }

        return Ok(pw1);
    }
}

// UI helpers

fn print_banner() {
    println!(
        "\n  {} v{}  —  Immutable System Safety Net for Linux\n",
        style("Recoil").bold().cyan(),
        style(RECOIL_VERSION).dim(),
    );
}

fn spinner(msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg);
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn ok_tick() -> console::StyledObject<&'static str> {
    style("✓").green().bold()
}

fn phase_line(label: &str, done: bool) {
    if done {
        println!("  {}  {}", style("✓").green(), label);
    } else {
        println!("  {}  {}", style("○").dim(), style(label).dim());
    }
}
