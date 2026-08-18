/*
 * Copyright (C) 2026 Ali Zain <alizain.arch@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/// The universal header printed at the top of every command output.
/// Defined once here — never appears as a string literal in command code.
pub const RECOIL_HEADER: &str = "Recoil v1.0.0 — Immutable System Safety Net for Linux";

/// Application version — must match Cargo.toml.
pub const RECOIL_VERSION: &str = "1.0.0";

/// Config schema version. Increment on breaking schema changes.
pub const CONFIG_VERSION: &str = "1";

// ── Bootstrap and shadow paths ──────────────────────────────────────────────

/// Encrypted config location before the shadow layer exists.
/// After Milestone 2 setup, config migrates into the shadow layer.
pub const BOOTSTRAP_CONFIG_DIR: &str = "/etc/recoil";

// ── Shadow layer subdirectory names ─────────────────────────────────────────

pub const DIR_ROOT_MIRROR: &str = "root-mirror";
pub const DIR_VERSIONS: &str = "versions";
pub const DIR_VAULT: &str = "vault";
pub const DIR_LOGS: &str = "logs";
pub const DIR_DB: &str = "db";
pub const DIR_RECOIL_B: &str = "recoil-b";
pub const DIR_RECOIL_ETC: &str = "recoil-etc";

pub const FILE_CONFIG: &str = ".config";
pub const FILE_LOCK_STATE: &str = ".lock_state";
pub const FILE_RECOIL_CTL: &str = "recoil-ctl";

// ── Root filesystem paths mirrored in Milestone 2 ───────────────────────────
//
// bin, sbin, lib, lib64 are listed explicitly. On merged-/usr systems these
// are symlinks on the live filesystem. In the mirror they are always created
// as independent physical directories — never as symlinks. This ensures the
// mirror is recoverable regardless of the state of /usr.
pub const MIRROR_PATHS: &[&str] = &[
    "usr", "boot", "etc", "root", "home", "var", "opt", "srv", "bin", "sbin", "lib", "lib64",
];

/// Paths excluded from the mirror — runtime virtual filesystems only.
pub const VIRTUAL_PATHS: &[&str] = &["dev", "proc", "sys", "run", "tmp", "mnt", "media"];

// ── Safety thresholds ────────────────────────────────────────────────────────

/// Minimum free disk space required before setup proceeds.
/// setup aborts with ✗ if available_bytes < MIN_FREE_BYTES.
pub const MIN_FREE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Minimum master password length enforced at setup and password change.
pub const MIN_PASSWORD_LEN: usize = 8;

// ── Rate-limiter tiers ───────────────────────────────────────────────────────

/// Tier 1 — 3 consecutive failures → 20-minute lockout.
pub const TIER1_ATTEMPTS: u32 = 3;
pub const TIER1_LOCK_SEC: u64 = 20 * 60; // 20 minutes

/// Tier 2 — 15 failures within any rolling 1-hour window → 3-hour lockout.
pub const TIER2_ATTEMPTS: u32 = 15;
pub const TIER2_WINDOW: u64 = 3_600; // 1-hour rolling window
pub const TIER2_LOCK_SEC: u64 = 3 * 3_600; // 3-hour lockout

/// Tier 3 — 50 failures within any rolling 24-hour window → permanent lock.
pub const TIER3_ATTEMPTS: u32 = 50;
pub const TIER3_WINDOW: u64 = 86_400; // 24-hour rolling window
