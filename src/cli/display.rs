/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Shared terminal output utilities.
//!
//! Every command imports from this module. All formatting decisions live
//! here — no string literals for symbols or colours appear in command code.

use crate::error::{RecoilError, Result};

// ── Symbols — never appear as literals in command files ───────────────────────

pub const SYM_OK: &str = "✓";
pub const SYM_ERR: &str = "✗";
pub const SYM_WARN: &str = "⚠";
pub const SYM_INFO: &str = "→";
pub const SYM_PASS: &str = "••••••••••••••••••••";
pub const SEP_LINE: &str = "────────────────────────────────────────────────────────────";

// ── Core print functions ──────────────────────────────────────────────────────

pub fn print_header() {
    println!("\n  {}", crate::utils::constants::RECOIL_HEADER);
}

pub fn print_blank() {
    println!();
}

pub fn print_ok(msg: &str) {
    println!("  {}  {}", SYM_OK, msg);
}

pub fn print_err(msg: &str) {
    println!("  {}  {}", SYM_ERR, msg);
}

pub fn print_warn(msg: &str) {
    println!("  {}  {}", SYM_WARN, msg);
}

pub fn print_info(msg: &str) {
    println!("  {}  {}", SYM_INFO, msg);
}

pub fn print_sep() {
    println!("  {}", SEP_LINE);
}

pub fn print_line(msg: &str) {
    println!("  {}", msg);
}

/// Print the standard password-required notice before prompting.
pub fn print_password_notice(context: &str) {
    print_blank();
    print_info("This command requires master password verification");
    print_blank();
    println!("   Enter master password{}:", context);
}

// ── Password prompt ───────────────────────────────────────────────────────────

/// Prompt for a password using rpassword (input is not echoed).
/// Format: ` Master password: ` with a leading space.
pub fn prompt_password(label: &str) -> Result<String> {
    rpassword::prompt_password(format!("\n Master {}: ", label)).map_err(RecoilError::Io)
}

/// Ask a yes/no question. Returns true only for 'y' or 'Y'.
pub fn confirm_yn(prompt: &str) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    print!("\n  {} (y/N): ", prompt);
    io::stdout().flush().map_err(RecoilError::Io)?;
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .unwrap_or(Ok(String::new()))
        .map_err(RecoilError::Io)?;
    Ok(matches!(line.trim(), "y" | "Y"))
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/// Format a byte count as a human-readable string.
/// Examples: `284.7 GiB`, `2.4 GB`, `2.8 MB`, `45.2 KB`
pub fn format_bytes(n: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KB", n as f64 / KIB as f64)
    } else {
        format!("{} B", n)
    }
}

/// Format a duration in seconds as a human-readable "ago" string.
pub fn format_ago(secs: u64) -> String {
    if secs < 60 {
        "just now".into()
    } else if secs < 3600 {
        let m = secs / 60;
        format!("{} minute{} ago", m, if m == 1 { "" } else { "s" })
    } else if secs < 86400 {
        let h = secs / 3600;
        format!("{} hour{} ago", h, if h == 1 { "" } else { "s" })
    } else {
        let d = secs / 86400;
        format!("{} day{} ago", d, if d == 1 { "" } else { "s" })
    }
}

// ── History table ─────────────────────────────────────────────────────────────

pub fn print_table_header() {
    println!();
    println!(
        "  {:<7} {:<24} {:<10} Action / Command",
        "ID", "Date & Time", "Type"
    );
    println!("  {}", SEP_LINE);
}

/// Print one history table row.
/// `tag` is optional: `→ Protected`, `→ Recovered`, `→ In Recoil`, or `""`.
pub fn print_table_row(id: u32, datetime: &str, event_type: &str, action: &str, tag: &str) {
    let tag_part = if tag.is_empty() {
        String::new()
    } else {
        format!("   {}", tag)
    };
    println!(
        "  #{:<6} {:<24} {:<10} {}{}",
        id, datetime, event_type, action, tag_part
    );
}

// ── Quick-command block ───────────────────────────────────────────────────────

pub fn print_quick_commands() {
    print_blank();
    println!("  Quick commands:");
    println!(
        "     recoil status     {} Check protection status",
        SYM_INFO
    );
    println!(
        "     recoil history    {} View full system chronology",
        SYM_INFO
    );
    println!(
        "     recoil restore    {} Recover files or directories",
        SYM_INFO
    );
}
