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

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{RecoilError, Result};

// ── FilesystemType ────────────────────────────────────────────────────────────

/// All filesystem types Recoil recognises via statfs(2) magic numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesystemType {
    Ext4,
    Btrfs,
    Xfs,
    Zfs,
    F2fs,
    Tmpfs,
    Proc,
    Sysfs,
    Devtmpfs,
    Unknown(i64),
}

impl FilesystemType {
    /// Linking strategy the Milestone 2 scanner uses for this filesystem.
    /// Btrfs, XFS, and ZFS support ioctl(FICLONE) copy-on-write reflinks.
    /// All others fall back to POSIX hard links.
    pub fn link_strategy(&self) -> LinkStrategy {
        match self {
            FilesystemType::Btrfs | FilesystemType::Xfs | FilesystemType::Zfs => {
                LinkStrategy::Reflink
            }
            _ => LinkStrategy::HardLink,
        }
    }

    /// Returns true for runtime-only virtual filesystems that hold no
    /// persistent data worth mirroring.
    pub fn is_virtual(&self) -> bool {
        matches!(
            self,
            FilesystemType::Tmpfs
                | FilesystemType::Proc
                | FilesystemType::Sysfs
                | FilesystemType::Devtmpfs
        )
    }

    /// Short display name used in setup output.
    pub fn display_name(&self) -> &'static str {
        match self {
            FilesystemType::Ext4 => "ext4",
            FilesystemType::Btrfs => "btrfs",
            FilesystemType::Xfs => "xfs",
            FilesystemType::Zfs => "zfs",
            FilesystemType::F2fs => "f2fs",
            FilesystemType::Tmpfs => "tmpfs",
            FilesystemType::Proc => "proc",
            FilesystemType::Sysfs => "sysfs",
            FilesystemType::Devtmpfs => "devtmpfs",
            FilesystemType::Unknown(_) => "unknown",
        }
    }

    /// Parenthetical CoW note shown in `recoil setup` output, e.g.
    /// `btrfs (CoW supported)`. Returns an empty string for non-CoW types.
    pub fn cow_note(&self) -> &'static str {
        match self {
            FilesystemType::Btrfs | FilesystemType::Xfs | FilesystemType::Zfs => "(CoW supported)",
            _ => "",
        }
    }
}

// ── LinkStrategy ─────────────────────────────────────────────────────────────

/// The mechanism the Milestone 2 scanner uses to populate the root mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkStrategy {
    /// POSIX hard link — near-zero space overhead, same filesystem required.
    HardLink,
    /// ioctl(FICLONE) copy-on-write reflink — zero space until modified.
    Reflink,
}

impl std::fmt::Display for LinkStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkStrategy::HardLink => write!(f, "hard link strategy"),
            LinkStrategy::Reflink => write!(f, "reflink strategy (CoW)"),
        }
    }
}

// ── Magic number constants ────────────────────────────────────────────────────
// Source: Linux <linux/magic.h>

const EXT4_MAGIC: i64 = 0x0000_EF53;
const BTRFS_MAGIC: i64 = 0x9123_683E_u32 as i32 as i64;
const XFS_MAGIC: i64 = 0x5846_5342;
const ZFS_MAGIC: i64 = 0x2FC1_2FC1;
const F2FS_MAGIC: i64 = 0xF2F5_2010_u32 as i32 as i64;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const PROC_MAGIC: i64 = 0x9FA0;
const SYSFS_MAGIC: i64 = 0x6265_6572;
const DEVTMPFS_MAGIC: i64 = 0x1373;

// ── Public API ────────────────────────────────────────────────────────────────

/// Detect the filesystem type at `path` using `statfs(2)`.
pub fn detect_filesystem(path: &Path) -> Result<FilesystemType> {
    use nix::sys::statfs::statfs;
    let stat =
        statfs(path).map_err(|e| RecoilError::FsDetection(format!("statfs({path:?}): {e}")))?;
    let magic = stat.filesystem_type().0 as i64;
    Ok(match magic {
        EXT4_MAGIC => FilesystemType::Ext4,
        BTRFS_MAGIC => FilesystemType::Btrfs,
        XFS_MAGIC => FilesystemType::Xfs,
        ZFS_MAGIC => FilesystemType::Zfs,
        F2FS_MAGIC => FilesystemType::F2fs,
        TMPFS_MAGIC => FilesystemType::Tmpfs,
        PROC_MAGIC => FilesystemType::Proc,
        SYSFS_MAGIC => FilesystemType::Sysfs,
        DEVTMPFS_MAGIC => FilesystemType::Devtmpfs,
        other => FilesystemType::Unknown(other),
    })
}

/// Returns `true` when `a` and `b` reside on the same filesystem.
/// Used by the Milestone 2 scanner to detect partition boundaries before
/// attempting hard link creation (hard links require the same filesystem).
pub fn same_filesystem(a: &Path, b: &Path) -> Result<bool> {
    use nix::sys::statfs::statfs;
    let fa = statfs(a).map_err(|e| RecoilError::FsDetection(format!("statfs({a:?}): {e}")))?;
    let fb = statfs(b).map_err(|e| RecoilError::FsDetection(format!("statfs({b:?}): {e}")))?;
    Ok(fa.filesystem_type().0 == fb.filesystem_type().0)
}

/// Returns the number of bytes available to unprivileged processes at `path`.
/// Used by the disk-space preflight check in `recoil setup`.
pub fn available_bytes(path: &Path) -> Result<u64> {
    use nix::sys::statfs::statfs;
    let stat =
        statfs(path).map_err(|e| RecoilError::FsDetection(format!("statfs({path:?}): {e}")))?;
    Ok(stat.blocks_available() * stat.block_size().unsigned_abs())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_filesystem_is_not_virtual() {
        let fs = detect_filesystem(Path::new("/")).unwrap();
        assert!(!fs.is_virtual());
    }

    #[test]
    fn tmpfs_is_virtual() {
        assert!(FilesystemType::Tmpfs.is_virtual());
        assert!(FilesystemType::Proc.is_virtual());
        assert!(FilesystemType::Sysfs.is_virtual());
        assert!(FilesystemType::Devtmpfs.is_virtual());
    }

    #[test]
    fn ext4_uses_hardlink() {
        assert_eq!(FilesystemType::Ext4.link_strategy(), LinkStrategy::HardLink);
    }

    #[test]
    fn btrfs_uses_reflink() {
        assert_eq!(FilesystemType::Btrfs.link_strategy(), LinkStrategy::Reflink);
    }

    #[test]
    fn xfs_uses_reflink() {
        assert_eq!(FilesystemType::Xfs.link_strategy(), LinkStrategy::Reflink);
    }

    #[test]
    fn available_bytes_nonzero_on_root() {
        let b = available_bytes(Path::new("/")).unwrap();
        assert!(b > 0, "available bytes on / must be > 0");
    }
}
