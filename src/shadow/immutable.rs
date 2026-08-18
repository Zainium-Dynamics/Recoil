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

//! Kernel-level filesystem immutability management via ioctl(FS_IOC_SETFLAGS).
//!
//! Full implementation is delivered in Milestone 2. The signatures defined
//! here are final — Milestone 2 replaces the bodies only.

use crate::error::Result;
use std::path::Path;

/// Apply the FS_IMMUTABLE_FL flag to a single path.
pub fn set_immutable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Clear the FS_IMMUTABLE_FL flag from a single path.
/// Requires master password authentication via the eBPF daemon (Milestone 4).
pub fn clear_immutable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Return true if FS_IMMUTABLE_FL is currently set on the path.
pub fn is_immutable(_path: &Path) -> Result<bool> {
    Ok(false)
}

/// Apply FS_APPEND_FL to the audit log file (Milestone 3).
pub fn set_append_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Apply FS_IMMUTABLE_FL recursively to all entries under `root`.
/// Uses contents-first traversal order: files are locked before their
/// containing directories to avoid ordering errors.
pub fn set_immutable_recursive(_root: &Path) -> Result<()> {
    Ok(())
}
