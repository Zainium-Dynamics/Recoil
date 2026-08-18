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

//! Root filesystem scanner for populating the shadow mirror.
//!
//! Walks the live root filesystem using walkdir with .same_file_system(true),
//! which automatically stops at partition boundaries. Virtual filesystems
//! (proc, sys, devtmpfs, tmpfs) are excluded by type detection rather than
//! by path name matching.
//!
//! bin/, sbin/, lib/, and lib64/ are always created as independent physical
//! directories in the mirror regardless of their type on the live system.
//! This is the design decision that makes recovery unconditionally reliable.
//!
//! Full implementation is delivered in Milestone 2.

use std::path::Path;

use indicatif::MultiProgress;

use crate::error::Result;
use crate::utils::fs_detect::LinkStrategy;

/// Statistics collected by a single scan_and_mirror() run.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub files_mirrored: u64,
    pub dirs_created: u64,
    pub symlinks_mirrored: u64,
    pub hard_links: u64,
    pub reflinks: u64,
    pub copies: u64,
    pub errors: u64,
}

impl ScanResult {
    pub fn total_entries(&self) -> u64 {
        self.files_mirrored + self.dirs_created + self.symlinks_mirrored
    }

    pub fn summarise(&self) -> String {
        format!(
            "{} files  {} dirs  {} errors",
            self.files_mirrored, self.dirs_created, self.errors
        )
    }
}

/// Walk `source_root` and mirror every entry into `mirror_root` using
/// the provided linking strategy, reporting progress via `multi` if
/// supplied.
pub fn scan_and_mirror(
    _source_root: &Path,
    _mirror_root: &Path,
    _strategy: &LinkStrategy,
    _multi: Option<&MultiProgress>,
) -> Result<ScanResult> {
    Ok(ScanResult::default())
}
