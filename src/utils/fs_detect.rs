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

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::{RecoilError, Result};

// Magic numbers  (<linux/magic.h>)


mod magic {
    pub const EXT4:      i64 = 0x0000_EF53;
    pub const BTRFS:     i64 = 0x9123_683E;
    pub const XFS:       i64 = 0x5846_5342;
    pub const ZFS:       i64 = 0x2FC1_2FC1;
    pub const F2FS:      i64 = 0xF2F5_2010u64 as i64;
    pub const TMPFS:     i64 = 0x0102_1994;
    pub const PROC:      i64 = 0x9fa0;
    pub const SYSFS:     i64 = 0x6265_6572;
    pub const DEVTMPFS:  i64 = 0x1373;
}


// Types

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    Unknown(String),
}

impl FilesystemType {
    /// Btrfs, XFS, and ZFS support ioctl(FICLONE) copy-on-write reflinks.
    /// Reflinks are strictly better than hard links for large files because
    /// they consume zero extra space until the source is modified.
    pub fn supports_reflinks(&self) -> bool {
        matches!(self, Self::Btrfs | Self::Xfs | Self::Zfs)
    }

    /// Virtual/runtime filesystems have no persistent data worth mirroring.
    pub fn is_virtual(&self) -> bool {
        matches!(self, Self::Tmpfs | Self::Proc | Self::Sysfs | Self::Devtmpfs)
    }

    /// The backup strategy the Phase 2 shadow layer will use.
    pub fn link_strategy(&self) -> LinkStrategy {
        if self.supports_reflinks() {
            LinkStrategy::Reflink
        } else {
            LinkStrategy::HardLink
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::Ext4            => "ext4",
            Self::Btrfs           => "btrfs",
            Self::Xfs             => "xfs",
            Self::Zfs             => "zfs",
            Self::F2fs            => "f2fs",
            Self::Tmpfs           => "tmpfs (virtual)",
            Self::Proc            => "proc (virtual)",
            Self::Sysfs           => "sysfs (virtual)",
            Self::Devtmpfs        => "devtmpfs (virtual)",
            Self::Unknown(s)      => s.as_str(),
        }
    }
}

/// Phase 2 will use this to decide how to populate the shadow layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStrategy {
    /// `std::os::unix::fs::hard_link` — works on ext4, f2fs.
    /// Requires source and destination on the same filesystem.
    HardLink,
    /// `ioctl(FICLONE)` — copy-on-write, works on btrfs/xfs/zfs.
    /// Zero space cost until the source file is modified.
    Reflink,
}

impl std::fmt::Display for LinkStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardLink => write!(f, "hard link"),
            Self::Reflink  => write!(f, "reflink (copy-on-write)"),
        }
    }
}

// Detection


/// Identify the filesystem that `path` lives on using `statfs(2)`.
pub fn detect_filesystem(path: &Path) -> Result<FilesystemType> {
    use nix::sys::statfs::statfs;

    let stat = statfs(path).map_err(|e| {
        RecoilError::FsDetection(format!("statfs({path:?}) failed: {e}"))
    })?;

    // The nix crate wraps f_type in a newtype; pull the i64 out.
    let magic = stat.filesystem_type().0 as i64;
    debug!(path = %path.display(), magic = format!("0x{:X}", magic as u64), "statfs");

    let fs = match magic {
        magic::EXT4     => FilesystemType::Ext4,
        magic::BTRFS    => FilesystemType::Btrfs,
        magic::XFS      => FilesystemType::Xfs,
        magic::ZFS      => FilesystemType::Zfs,
        magic::F2FS     => FilesystemType::F2fs,
        magic::TMPFS    => FilesystemType::Tmpfs,
        magic::PROC     => FilesystemType::Proc,
        magic::SYSFS    => FilesystemType::Sysfs,
        magic::DEVTMPFS => FilesystemType::Devtmpfs,
        other => {
            warn!(magic = format!("0x{:X}", other as u64), "Unrecognised filesystem");
            FilesystemType::Unknown(format!("0x{:X}", other as u64))
        }
    };

    Ok(fs)
}

/// Check that `a` and `b` live on the same filesystem.
///
/// Hard links only work within a single filesystem — if the shadow directory
/// and the source paths are on different partitions the Phase 2 scanner must
/// create separate link groups for each partition.
pub fn same_filesystem(a: &Path, b: &Path) -> Result<bool> {
    use nix::sys::statfs::statfs;

    let sa = statfs(a).map_err(|e| RecoilError::FsDetection(format!("statfs({a:?}): {e}")))?;
    let sb = statfs(b).map_err(|e| RecoilError::FsDetection(format!("statfs({b:?}): {e}")))?;

    // Two paths are on the same device when both the filesystem type and the
    // total block count match.  Using block count is a reasonable heuristic
    // because the filesystem type alone is not unique (two ext4 volumes).
    Ok(sa.filesystem_type() == sb.filesystem_type() && sa.blocks() == sb.blocks())
}

/// Available free bytes on the filesystem containing `path`.
pub fn available_bytes(path: &Path) -> Result<u64> {
    use nix::sys::statfs::statfs;

    let stat = statfs(path).map_err(|e| {
        RecoilError::FsDetection(format!("statfs({path:?}): {e}"))
    })?;

    Ok(stat.blocks_available() * stat.block_size() as u64)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_not_virtual() {
        let fs = detect_filesystem(Path::new("/")).expect("statfs / should succeed");
        assert!(!fs.is_virtual(), "/ must not be a virtual filesystem");
    }

    #[test]
    fn virtual_types_identified() {
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
    fn free_bytes_positive() {
        let b = available_bytes(Path::new("/")).expect("available_bytes /");
        assert!(b > 0);
    }
}
