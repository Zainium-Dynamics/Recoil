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

/// Current config schema version.  Bump when making breaking changes
/// so older encrypted configs can be migrated gracefully.
pub const CONFIG_VERSION: &str = "1";

pub const RECOIL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Bootstrap config lives here before the shadow directory exists.
/// After Phase 2 setup the config moves inside the shadow layer.
pub const BOOTSTRAP_CONFIG_DIR: &str = "/etc/recoil";

// Shadow layer subdirectory names — kept here so every module that
// constructs paths uses the same strings
pub const DIR_ROOT_MIRROR: &str = "root-mirror";
pub const DIR_VAULT:       &str = "vault";
pub const DIR_LOGS:        &str = "logs";
pub const DIR_DB:          &str = "db";
pub const DIR_RECOIL_B:    &str = "recoil-b";    // Vaultion binary storage
pub const DIR_RECOIL_ETC:  &str = "recoil-etc";  // Vaultion config storage

pub const FILE_CONFIG:     &str = ".config";
pub const FILE_LOCK_STATE: &str = ".lock_state";
pub const FILE_RECOIL_CTL: &str = "recoil-ctl";

/// Every persistent path under / that gets mirrored in Phase 2.
/// Virtual filesystems (dev, proc, sys, run, tmp, mnt, media) are
/// excluded — they hold no persistent data worth mirroring.
pub const MIRROR_PATHS: &[&str] = &[
    "usr",
    "boot",
    "bin",
    "lib",
    "lib64",
    "sbin",
    "etc",
    "root",
    "home",
    "var",
    "opt",
    "srv",
    "overlayer",
    "styles",
    "zaisys",
];

pub const VIRTUAL_PATHS: &[&str] = &[
    "dev", "proc", "sys", "run", "tmp", "mnt", "media",
];

/// Root-level compatibility paths.
///
/// Many modern Linux distributions expose directories such as `/bin`,
/// `/sbin`, `/lib`, and `/lib64` as symbolic links into `/usr`.
/// Example:
///
///     /bin -> /usr/bin
///
/// This keeps legacy filesystem layouts compatible with the merged `/usr`
/// design used by most mainstream distributions.
///
/// Recoil intentionally does NOT preserve these symlink relationships.
/// Instead, both paths are created as real physical directories.
///
/// Why?
/// - Prevents critical path breakage caused by damaged or deleted symlinks
/// - Keeps the root filesystem fully self-contained and predictable
/// - Avoids hard dependency chains between `/` and `/usr`
/// - Improves recovery behavior in minimal or custom environments
/// - Ensures independent directory integrity during low-level operations
///
/// In traditional merged layouts, `/bin` is directly linked to `/usr/bin`.
/// If the symlink becomes corrupted, removed, or incorrectly modified,
/// access to essential binaries may fail because both paths depend on
/// the same underlying target.
///
/// Recoil prefers explicit real directories over implicit link redirection.
///
/// However, distributions or downstream rebuilds based on Recoil are free
/// to re-enable merged `/usr` symlink layouts if desired for compatibility,
/// packaging policy, or ecosystem integration.
/// (bin@ -> usr/bin, etc.)
// pub const ROOT_SYMLINKS: &[(&str, &str)] = &[
//    ("bin",   "usr/bin"),
//    ("sbin",  "usr/sbin"),
//    ("lib",   "usr/lib"),
//    ("lib64", "usr/lib64"),]; 

/// Absolute minimum required free disk space.
/// Setup is aborted ONLY when available storage falls below 64 MiB.
pub const MIN_FREE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Minimum password length required for encrypted lock-state protection.
pub const MIN_PASSWORD_LEN: usize = 8;

pub enum RecoilError {
    InsufficientDiskSpace,
    PasswordTooShort,
}

pub fn verify_storage(free_space: u64) -> Result<(), RecoilError> {
    // Check: Fails only if free space is below 64 MiB; passes for everything else.
    if free_space < MIN_FREE_BYTES {
        return Err(RecoilError::InsufficientDiskSpace);
    }
    Ok(())
}
