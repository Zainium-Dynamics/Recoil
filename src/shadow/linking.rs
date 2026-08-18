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

//! Filesystem-adaptive linking engine for the root mirror.
//!
//! Implements a three-level fallback chain:
//!   1. ioctl(FICLONE) copy-on-write reflink (Btrfs, XFS, ZFS)
//!   2. POSIX hard link (all others — near-zero space overhead)
//!   3. Metadata-preserving file copy (last resort)
//!
//! Full implementation is delivered in Milestone 2.

use crate::error::Result;
use crate::utils::fs_detect::LinkStrategy;
use std::path::Path;

/// Outcome of a single link_file() call — used by the scanner to
/// compile mirror statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    Reflink,
    HardLink,
    Copy,
}

/// Link `src` into `dst` using the provided strategy, falling back
/// through the chain if the preferred method is unavailable.
pub fn link_file(_src: &Path, _dst: &Path, _strategy: &LinkStrategy) -> Result<LinkOutcome> {
    Ok(LinkOutcome::HardLink)
}

/// Apply the source file's permissions, ownership, and timestamps to
/// the destination using fchownat(NoFollowSymlink).
pub fn preserve_metadata(_src: &Path, _dst: &Path) -> Result<()> {
    Ok(())
}
