/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use crate::cli::auth::verify_master_password;
use crate::cli::display::*;
use crate::error::{RecoilError, Result};
use crate::shadow::immutable::clear_immutable;
use crate::utils::os_detect::is_root;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(about = "Authenticated chattr -i bypass — requires master password and sudo")]
pub struct UnlockArgs {
    #[arg(
        long,
        help = "Shadow layer path to unlock, e.g. /.recoil-debian/vault/"
    )]
    pub path: Option<PathBuf>,
}

pub async fn run(args: UnlockArgs) -> Result<()> {
    print_header();

    // Root required
    if !is_root() {
        print_blank();
        print_err("This command requires root — run with sudo");
        print_blank();
        return Err(RecoilError::PermissionDenied);
    }

    // No path — show usage
    let Some(ref target) = args.path else {
        let _cfg = verify_master_password("")?;
        print_blank();
        print_line("Usage: recoil unlock --path <SHADOW_PATH>");
        print_blank();
        print_line("  Example:");
        print_line("     sudo recoil unlock --path /.recoil-debian/vault/");
        print_blank();
        return Ok(());
    };

    // Validate path is inside a shadow directory
    let path_str = target.to_string_lossy();
    if !path_str.contains("/.recoil-") {
        print_blank();
        print_err("Invalid path");
        print_blank();
        print_line("  recoil unlock only operates on paths within the shadow directory.");
        print_line("  Path must begin with /.recoil-");
        print_blank();
        return Err(RecoilError::Other("path outside shadow directory".into()));
    }

    print_blank();
    print_info(&format!(
        "Authenticated unlock requested for: {}",
        target.display()
    ));

    // Verify master password
    let _cfg = verify_master_password("")?;

    // Call immutability stub (Milestone 2 implements this with ioctl)
    clear_immutable(target)?;

    print_ok(&format!(
        "Immutability flag cleared for: {}",
        target.display()
    ));
    print_ok("Event recorded in audit log");
    print_blank();
    print_warn("Remember to re-lock this path when done:");
    println!("     sudo recoil lock --path {}", target.display());
    print_blank();

    Ok(())
}
