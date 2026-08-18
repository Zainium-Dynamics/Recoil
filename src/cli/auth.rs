/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Centralised password verification with rate-limiter integration.
//!
//! Every authenticated command calls `verify_master_password()` rather
//! than implementing its own password loop. This guarantees that the
//! rate limiter is applied consistently across all commands.

use std::path::Path;

use crate::cli::display::{
    print_blank, print_err, print_ok, print_password_notice, print_warn, prompt_password, SYM_INFO,
};
use crate::config::{load_lock_state, save_lock_state, ConfigManager, RecoilConfig};
use crate::error::{RecoilError, Result};

/// Resolve the config manager — tries shadow first, falls back to bootstrap.
pub fn resolve_config_manager() -> Result<ConfigManager> {
    // After Milestone 2, the config lives inside the shadow layer.
    // For Milestone 1, it lives at the bootstrap path /etc/recoil/.config.
    // We check the most common paths for any known distro.
    let shadow_names = [
        ".recoil-debian",
        ".recoil-ubuntu",
        ".recoil-arch",
        ".recoil-fedora",
        ".recoil-kali",
        ".recoil-mint",
        ".recoil-pop",
        ".recoil-parrot",
        ".recoil-rocky",
        ".recoil-alma",
        ".recoil-void",
        ".recoil-alpine",
        ".recoil-linux",
    ];
    for name in &shadow_names {
        let shadow = Path::new("/").join(name);
        let mgr = ConfigManager::from_shadow(&shadow);
        if mgr.exists() {
            return Ok(mgr);
        }
    }
    // Fall back to bootstrap path
    let bootstrap = ConfigManager::bootstrap();
    if bootstrap.exists() {
        Ok(bootstrap)
    } else {
        Err(RecoilError::NotInitialised)
    }
}

/// Rate-limiter state directory — same directory as the config file.
fn lock_state_dir(mgr: &ConfigManager) -> std::path::PathBuf {
    mgr.path()
        .parent()
        .unwrap_or_else(|| Path::new("/etc/recoil"))
        .to_path_buf()
}

/// Prompt for the master password and verify it against the stored config.
///
/// Displays the standard "This command requires master password verification"
/// header, prompts up to three times, applies the rate limiter on every
/// failure, and returns the decrypted `RecoilConfig` on success.
pub fn verify_master_password(context: &str) -> Result<RecoilConfig> {
    let mgr = resolve_config_manager()?;
    let lock_dir = lock_state_dir(&mgr);
    let mut lock = load_lock_state(&lock_dir);

    // Check whether already locked before prompting.
    lock.check().inspect_err(|e| match e {
        RecoilError::RateLimited { minutes } => {
            print_blank();
            print_err(&format!(
                "Vault is locked. Try again in {} minute(s).",
                minutes
            ));
        }
        RecoilError::HardLocked => {
            print_blank();
            print_err("Vault is permanently locked due to too many failed attempts.");
            print_blank();
            println!(
                "  {}  Contact your administrator or set RECOIL_RECOVERY=1 \
                    to reset.",
                SYM_INFO
            );
        }
        _ => {}
    })?;

    // Check for offline administrator recovery bypass.
    if std::env::var("RECOIL_RECOVERY").as_deref() == Ok("1") {
        print_blank();
        print_warn("RECOIL_RECOVERY mode active — rate limiter bypassed.");
        print_blank();
        let password = prompt_password("password")?;
        return mgr.load(&password);
    }

    print_password_notice(context);

    // Up to 3 attempts.
    let max_attempts = 3usize;
    for attempt in 0..max_attempts {
        let password = prompt_password("password")?;
        match mgr.load(&password) {
            Ok(cfg) => {
                lock.on_success();
                let _ = save_lock_state(&lock_dir, &lock);
                print_blank();
                print_ok("Password verified successfully");
                return Ok(cfg);
            }
            Err(RecoilError::AuthFailed) => {
                lock.on_failure();
                let _ = save_lock_state(&lock_dir, &lock);

                let remaining = max_attempts - attempt - 1;
                print_blank();
                print_err("Incorrect password");
                print_blank();

                match lock.check() {
                    Err(RecoilError::RateLimited { minutes }) => {
                        print_warn(&format!(
                            "Too many failed attempts. Vault locked for {} minute(s).",
                            minutes
                        ));
                        return Err(RecoilError::RateLimited { minutes });
                    }
                    Err(RecoilError::HardLocked) => {
                        print_err("Vault permanently locked.");
                        return Err(RecoilError::HardLocked);
                    }
                    _ => {}
                }

                if remaining > 0 {
                    println!("  Attempts remaining: {}", remaining);
                    println!("  After 3 failed attempts, Recoil will lock for 20 minutes.");
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Err(RecoilError::AuthFailed)
}
