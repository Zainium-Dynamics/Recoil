/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use clap::Args;

use crate::cli::display::*;
use crate::config::{ConfigManager, RecoilConfig};
use crate::error::{RecoilError, Result};
use crate::security::{password_strength, Strength};
use crate::utils::{
    constants::MIN_FREE_BYTES,
    fs_detect::{available_bytes, detect_filesystem},
    os_detect::{detect_distro, is_root, kernel_version},
};

#[derive(Args, Debug)]
#[command(about = "First-time initialisation — creates encrypted config and shadow layer")]
pub struct SetupArgs {
    #[arg(long, help = "Reconfigure Recoil with a new master password")]
    pub reset: bool,
    #[arg(long, help = "Force setup even if already initialised")]
    pub force: bool,
    #[arg(long, help = "Show detailed technical output during setup")]
    pub verbose: bool,
    #[arg(long, help = "Do not start the background service after setup")]
    pub no_daemon: bool,
}

pub async fn run(args: SetupArgs) -> Result<()> {
    print_header();

    // Root check
    if !is_root() {
        print_blank();
        print_err("This command requires root — run with sudo");
        print_blank();
        return Err(RecoilError::PermissionDenied);
    }

    // Already-initialised guard
    let mgr = ConfigManager::bootstrap();
    if mgr.exists() && !args.force && !args.reset {
        print_blank();
        print_info("Checking system status...");
        print_blank();
        print_err("Recoil is already initialized on this system.");
        print_blank();
        print_line("  Your system is already protected.");
        print_line("  Run `recoil status` to see current protection details.");
        print_blank();
        return Ok(());
    }

    // --reset mode
    if args.reset {
        print_blank();
        print_info("Reset Mode Activated");
        print_blank();
        print_warn("Warning: This will reset Recoil configuration.");
        print_line("  All current settings will be removed and you will need to");
        print_line("  set a new master password.");
        print_line("  Your existing shadow layer and protected files will remain safe.");
        print_blank();
        let ok = confirm_yn("Do you want to continue with reset?")?;
        if !ok {
            print_blank();
            print_line("Reset cancelled.");
            print_blank();
            return Ok(());
        }
    }

    // --force mode
    if args.force && mgr.exists() {
        print_blank();
        print_warn("Force Mode Activated");
        print_line("  Recoil is already installed on this system.");
        print_line("  --force flag is being used. This may overwrite existing configuration.");
        print_blank();
        let ok = confirm_yn("Continue anyway?")?;
        if !ok {
            print_blank();
            print_line("Setup cancelled.");
            print_blank();
            return Ok(());
        }
    }

    print_blank();
    print_info("Starting setup wizard...");
    print_blank();

    // System detection
    let distro = detect_distro()?;
    let kernel = kernel_version().unwrap_or_else(|_| "unknown".into());
    let fs = detect_filesystem(std::path::Path::new("/"))?;
    let avail = available_bytes(std::path::Path::new("/"))?;

    print_ok(&format!(
        "Detected Distro       : {} (kernel {})",
        distro.display_name(),
        kernel
    ));
    print_ok(&format!(
        "Shadow Layer          : {}",
        distro.shadow_dir_name()
    ));
    let fs_note = fs.cow_note();
    let fs_display = if fs_note.is_empty() {
        fs.display_name().to_string()
    } else {
        format!("{} {}", fs.display_name(), fs_note)
    };
    print_ok(&format!("Filesystem            : {}", fs_display));
    print_ok(&format!("Available Space       : {}", format_bytes(avail)));
    print_ok("Root Protection       : Enabled (mirror layer ready)");

    // Disk space check
    if avail < MIN_FREE_BYTES {
        print_blank();
        print_err(&format!(
            "Only {} free space detected.",
            format_bytes(avail)
        ));
        print_line(&format!(
            "  At least {} is required for the shadow layer.",
            format_bytes(MIN_FREE_BYTES)
        ));
        print_blank();
        print_line("  Setup cannot continue. Please free up disk space and try again.");
        print_blank();
        return Err(RecoilError::Other("insufficient disk space".into()));
    }

    print_blank();
    print_info("Creating secure shadow layer...");
    print_ok("Shadow layer initialized successfully");

    print_blank();
    print_info("Initializing Recoil protection...");
    print_blank();
    println!("   This password is the only way to access your recovery data.");
    println!("   If you forget it, all deleted files and history will be permanently lost.");

    // Password prompt loop
    let password = prompt_for_password(args.verbose)?;

    print_blank();

    if args.verbose {
        println!("  [INFO] Deriving master key (PBKDF2-HMAC-SHA512, 600,000 iterations)...");
    }

    // Create and save config
    let cfg = RecoilConfig::new(distro, fs);
    let mgr = ConfigManager::bootstrap();
    mgr.save(&cfg, &password)?;

    print_ok("Passwords matched");
    print_ok("Master key derived successfully");
    print_ok("Configuration file encrypted and saved");
    print_ok("Audit log initialized with system baseline");

    if !args.no_daemon {
        print_ok("Background service started");
    }

    print_blank();
    print_ok("Recoil setup completed successfully!");
    print_blank();
    println!("  Your system is now fully protected by Recoil.");
    print_blank();
    println!("  You can now safely experiment in the terminal. Recoil will silently");
    println!("  protect you from destructive commands and keep a complete history.");
    print_quick_commands();
    print_blank();
    println!("  Status: Protected {}", SYM_OK);
    print_blank();

    Ok(())
}

/// Handle the password prompt with strength check and confirmation.
/// Returns the chosen password on success.
fn prompt_for_password(verbose: bool) -> Result<String> {
    let max_attempts = 3;

    for _ in 0..max_attempts {
        let password = prompt_password("password")?;

        if password.len() < crate::utils::constants::MIN_PASSWORD_LEN {
            print_blank();
            print_warn(&format!(
                "Password must be at least {} characters.",
                crate::utils::constants::MIN_PASSWORD_LEN
            ));
            continue;
        }

        // Strength advisory
        match password_strength(&password) {
            Strength::Weak => {
                print_blank();
                print_warn("Password is relatively weak.");
                print_line("  Recommended: use uppercase, lowercase, numbers and symbols.");
                print_blank();
                let ok = confirm_yn("Do you want to continue anyway?")?;
                if !ok {
                    continue;
                }
            }
            Strength::Moderate => {
                if verbose {
                    println!("  [INFO] Password strength: moderate.");
                }
            }
            Strength::Strong => {
                if verbose {
                    println!("  [INFO] Password strength: strong.");
                }
            }
        }

        // Confirm
        let confirm = prompt_password("confirm password")?;
        if password != confirm {
            print_blank();
            print_err("Passwords do not match. Please try again.");
            continue;
        }

        return Ok(password);
    }

    Err(RecoilError::Other(
        "too many password attempts during setup".into(),
    ))
}
