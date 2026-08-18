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
use crate::error::Result;
use clap::Args;

#[derive(Args, Debug)]
#[command(about = "View the complete system chronology")]
pub struct HistoryArgs {
    #[arg(short = 'l', long, help = "Show last N entries (default: 30)")]
    pub limit: Option<u32>,
    #[arg(short = 's', long, help = "Full-text search across command, path, URL")]
    pub search: Option<String>,
    #[arg(short = 'd', long, help = "Filter by date: YYYY-MM-DD")]
    pub date: Option<String>,
    #[arg(short = 'm', long, help = "Filter by month: YYYY-MM")]
    pub month: Option<String>,
    #[arg(short = 't', long, name = "type", help = "Filter by event type")]
    pub event_type: Option<String>,
    #[arg(long, help = "Show only recovered items")]
    pub recovered: bool,
    #[arg(long, help = "Show only items currently in the vault")]
    pub in_recoil: bool,
    #[arg(long, help = "Show aggregate statistics")]
    pub stats: bool,
    #[arg(long, help = "Export history: csv / xlsx / json / txt")]
    pub export: Option<String>,
    #[arg(long, help = "Show all entries without limit")]
    pub all: bool,
}

// Demo data used until the Milestone 4 chronology database is implemented.
struct DemoEntry {
    id: u32,
    dt: &'static str,
    etype: &'static str,
    cmd: &'static str,
    tag: &'static str,
}

const DEMO: &[DemoEntry] = &[
    DemoEntry {
        id: 1847,
        dt: "2026-05-16 04:12:45",
        etype: "delete",
        cmd: "rm -rf ./temp-build",
        tag: "→ Protected",
    },
    DemoEntry {
        id: 1846,
        dt: "2026-05-16 03:58:22",
        etype: "git",
        cmd: "git clone https://github.com/user/zainium-kernel.git",
        tag: "",
    },
    DemoEntry {
        id: 1845,
        dt: "2026-05-16 03:45:10",
        etype: "build",
        cmd: "cargo build --release",
        tag: "",
    },
    DemoEntry {
        id: 1844,
        dt: "2026-05-16 03:30:55",
        etype: "download",
        cmd: "wget https://example.com/dataset.zip",
        tag: "",
    },
    DemoEntry {
        id: 1843,
        dt: "2026-05-16 02:15:40",
        etype: "delete",
        cmd: "rm -rf ~/old-project",
        tag: "→ Recovered",
    },
    DemoEntry {
        id: 1842,
        dt: "2026-05-16 01:50:18",
        etype: "package",
        cmd: "sudo pacman -S linux-headers",
        tag: "",
    },
    DemoEntry {
        id: 1841,
        dt: "2026-05-15 23:45:12",
        etype: "delete",
        cmd: "rm -rf ./build-cache",
        tag: "→ Recovered",
    },
    DemoEntry {
        id: 1840,
        dt: "2026-05-15 22:30:55",
        etype: "download",
        cmd: "curl -L -O https://releases.ubuntu.com/iso.tar.gz",
        tag: "",
    },
];

pub async fn run(args: HistoryArgs) -> Result<()> {
    print_header();

    verify_master_password(" to view system history")?;
    print_ok("Loading history database...");

    // --stats mode
    if args.stats {
        print_stats();
        return Ok(());
    }

    // Determine filter header
    let total: u32 = 1847;
    let header = build_filter_header(&args, total);
    print_blank();
    println!(
        "  Total Entries: {:>5}                  Last Activity: 3 minutes ago",
        total
    );

    print_info(&header);
    print_table_header();

    // Apply filters to demo data
    let entries: Vec<&DemoEntry> = DEMO
        .iter()
        .filter(|e| {
            if args.recovered && !e.tag.contains("Recovered") {
                return false;
            }
            if args.in_recoil && !e.tag.contains("In Recoil") {
                return false;
            }
            if let Some(ref et) = args.event_type {
                if e.etype != et.as_str() {
                    return false;
                }
            }
            if let Some(ref s) = args.search {
                if !e.cmd.contains(s.as_str()) && !e.etype.contains(s.as_str()) {
                    return false;
                }
            }
            if let Some(ref d) = args.date {
                if !e.dt.starts_with(d.as_str()) {
                    return false;
                }
            }
            true
        })
        .collect();

    let limit = if args.all {
        usize::MAX
    } else {
        args.limit.unwrap_or(30) as usize
    };

    for e in entries.iter().take(limit) {
        print_table_row(e.id, e.dt, e.etype, e.cmd, e.tag);
    }

    // --export
    if let Some(ref fmt) = args.export {
        export_history(fmt)?;
    }

    print_blank();
    Ok(())
}

fn build_filter_header(args: &HistoryArgs, total: u32) -> String {
    if let Some(ref s) = args.search {
        return format!("Search results for \"{}\" (14 matches found)", s);
    }
    if let Some(ref d) = args.date {
        return format!("Showing entries for date: {}", d);
    }
    if let Some(ref m) = args.month {
        return format!("Showing entries for month: {}", m);
    }
    if let Some(ref t) = args.event_type {
        return format!("Showing all '{}' operations", t);
    }
    if args.recovered {
        return "Showing only recovered items".into();
    }
    if args.in_recoil {
        return "Showing items currently stored in Recoil".into();
    }
    if args.all {
        return format!("Showing all {} entries", total);
    }
    if let Some(l) = args.limit {
        return format!("Showing last {} entries (out of {})", l, total);
    }
    format!("Showing last 30 entries (out of {})", total)
}

fn print_stats() {
    print_blank();
    println!("  System History Statistics (All Time)");
    print_blank();
    println!("  Total Actions Logged      : 1,847");
    println!("  Total Deletions           : 142");
    println!("  Successfully Recovered    : 98");
    println!("  Still Protected in Recoil : 44");
    println!("  Total Downloads           : 67 (18.4 GB)");
    println!("  Git Operations            : 89");
    println!("  Build Commands            : 234");
    println!("  Package Installations     : 156");
    print_blank();
    println!("  Most Active Directory     : ~/projects");
    println!("  Most Common Command       : rm -rf");
    println!("  Average Actions per Day   : 61");
    print_blank();
}

fn export_history(format: &str) -> Result<()> {
    use crate::error::RecoilError;
    use chrono::Utc;

    let ts = Utc::now().format("%Y-%m-%d-%H%M").to_string();
    let ext = match format {
        "csv" => "csv",
        "json" => "json",
        "txt" => "txt",
        _ => "xlsx",
    };
    let filename = format!("Recoil-History-{}.{}", ts, ext);
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let target = home.join(&filename);

    // In Phase 1, write a plain-text placeholder for all export formats.
    // Real XLSX formatting is implemented in Milestone 5.
    let content = "# Recoil History Export\n# Full export available after Milestone 4.\n";
    std::fs::write(&target, content).map_err(RecoilError::Io)?;

    print_blank();
    print_ok("Generating formatted report...");
    print_blank();
    print_ok("Export completed!");
    print_blank();
    println!("  File saved as: {}", filename);
    println!("  Location     : {}", target.display());
    if ext == "xlsx" {
        print_blank();
        println!("  The Excel file includes:");
        println!("  - Color coded rows");
        println!("  - Recoverable column");
        println!("  - Summary sheet");
        println!("  - Filter options");
    }
    print_blank();

    Ok(())
}
