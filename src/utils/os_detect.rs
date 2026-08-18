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

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::{RecoilError, Result};

// ── Distro enum ──────────────────────────────────────────────────────────────

/// All recognised Linux distributions plus a generic fallback.
/// The shadow directory name is derived from this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Distro {
    Debian,
    Ubuntu,
    Arch,
    Manjaro,
    Fedora,
    CentOs,
    Rhel,
    AlmaLinux,
    RockyLinux,
    OpenSuse,
    Gentoo,
    Void,
    Alpine,
    Mint,
    PopOs,
    ElementaryOs,
    Kali,
    Parrot,
    /// Generic fallback carrying the PRETTY_NAME value.
    Unknown(String),
}

impl Distro {
    /// Dot-prefixed hidden shadow directory name.
    /// The leading dot makes the directory invisible to standard `ls`.
    pub fn shadow_dir_name(&self) -> String {
        match self {
            Distro::Debian => ".recoil-debian",
            Distro::Ubuntu => ".recoil-ubuntu",
            Distro::Arch => ".recoil-arch",
            Distro::Manjaro => ".recoil-manjaro",
            Distro::Fedora => ".recoil-fedora",
            Distro::CentOs => ".recoil-centos",
            Distro::Rhel => ".recoil-rhel",
            Distro::AlmaLinux => ".recoil-alma",
            Distro::RockyLinux => ".recoil-rocky",
            Distro::OpenSuse => ".recoil-opensuse",
            Distro::Gentoo => ".recoil-gentoo",
            Distro::Void => ".recoil-void",
            Distro::Alpine => ".recoil-alpine",
            Distro::Mint => ".recoil-mint",
            Distro::PopOs => ".recoil-pop",
            Distro::ElementaryOs => ".recoil-elementary",
            Distro::Kali => ".recoil-kali",
            Distro::Parrot => ".recoil-parrot",
            Distro::Unknown(_) => ".recoil-linux",
        }
        .to_string()
    }

    /// Absolute path of the shadow directory root, e.g. `/.recoil-debian`.
    pub fn shadow_path(&self) -> PathBuf {
        PathBuf::from("/").join(self.shadow_dir_name())
    }

    /// Human-readable display name for terminal output.
    pub fn display_name(&self) -> String {
        match self {
            Distro::Debian => "Debian GNU/Linux".into(),
            Distro::Ubuntu => "Ubuntu".into(),
            Distro::Arch => "Arch Linux".into(),
            Distro::Manjaro => "Manjaro Linux".into(),
            Distro::Fedora => "Fedora Linux".into(),
            Distro::CentOs => "CentOS Linux".into(),
            Distro::Rhel => "Red Hat Enterprise Linux".into(),
            Distro::AlmaLinux => "AlmaLinux".into(),
            Distro::RockyLinux => "Rocky Linux".into(),
            Distro::OpenSuse => "openSUSE".into(),
            Distro::Gentoo => "Gentoo Linux".into(),
            Distro::Void => "Void Linux".into(),
            Distro::Alpine => "Alpine Linux".into(),
            Distro::Mint => "Linux Mint".into(),
            Distro::PopOs => "Pop!_OS".into(),
            Distro::ElementaryOs => "elementary OS".into(),
            Distro::Kali => "Kali Linux".into(),
            Distro::Parrot => "Parrot OS".into(),
            Distro::Unknown(n) => n.clone(),
        }
    }
}

// ── /etc/os-release parser ───────────────────────────────────────────────────

struct OsRelease {
    id: String,
    id_like: Vec<String>,
    pretty_name: String,
}

impl OsRelease {
    fn parse(src: &str) -> Self {
        let mut map: HashMap<&str, String> = HashMap::new();
        for line in src.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim_matches('"').trim_matches('\'').to_string();
                map.insert(k, v);
            }
        }
        let id = map.get("ID").cloned().unwrap_or_default().to_lowercase();
        let id_like = map
            .get("ID_LIKE")
            .map(|s| s.split_whitespace().map(|w| w.to_lowercase()).collect())
            .unwrap_or_default();
        let pretty_name = map
            .get("PRETTY_NAME")
            .cloned()
            .unwrap_or_else(|| "Linux".to_string());
        OsRelease {
            id,
            id_like,
            pretty_name,
        }
    }

    fn matches_id(&self, candidate: &str) -> bool {
        self.id == candidate || self.id_like.iter().any(|s| s == candidate)
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Detect the running Linux distribution from `/etc/os-release`.
pub fn detect_distro() -> Result<Distro> {
    let src = std::fs::read_to_string("/etc/os-release")
        .map_err(|e| RecoilError::OsDetection(format!("cannot read /etc/os-release: {e}")))?;
    let rel = OsRelease::parse(&src);
    debug!(
        id = %rel.id,
        id_like = ?rel.id_like,
        pretty = %rel.pretty_name,
        "os-release parsed"
    );
    Ok(map_to_distro(&rel))
}

fn map_to_distro(rel: &OsRelease) -> Distro {
    match rel.id.as_str() {
        "debian" => Distro::Debian,
        "ubuntu" => Distro::Ubuntu,
        "linuxmint" => Distro::Mint,
        "pop" => Distro::PopOs,
        "elementary" => Distro::ElementaryOs,
        "kali" => Distro::Kali,
        "parrot" => Distro::Parrot,
        "arch" => Distro::Arch,
        "manjaro" => Distro::Manjaro,
        "fedora" => Distro::Fedora,
        "centos" => Distro::CentOs,
        "rhel" => Distro::Rhel,
        "almalinux" => Distro::AlmaLinux,
        "rocky" => Distro::RockyLinux,
        "gentoo" => Distro::Gentoo,
        "void" => Distro::Void,
        "alpine" => Distro::Alpine,
        id if id.starts_with("opensuse") => Distro::OpenSuse,
        _ => {
            // ID_LIKE fallback chain
            if rel.matches_id("debian") {
                warn!(id = %rel.id, "unknown distro matched via ID_LIKE=debian");
                Distro::Debian
            } else if rel.matches_id("ubuntu") {
                warn!(id = %rel.id, "unknown distro matched via ID_LIKE=ubuntu");
                Distro::Ubuntu
            } else if rel.matches_id("arch") {
                Distro::Arch
            } else if rel.matches_id("fedora") || rel.matches_id("rhel") {
                Distro::Fedora
            } else {
                warn!(id = %rel.id, "unrecognised distribution — using generic shadow path");
                Distro::Unknown(rel.pretty_name.clone())
            }
        }
    }
}

/// Returns the running kernel version string via `uname -r`.
pub fn kernel_version() -> Result<String> {
    let out = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|e| RecoilError::OsDetection(format!("uname failed: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Returns `true` when the effective UID is 0 (root).
pub fn is_root() -> bool {
    // SAFETY: geteuid() is always safe on POSIX systems.
    unsafe { libc::geteuid() == 0 }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_12: &str = r#"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
"#;

    const UBUNTU_24: &str = r#"
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="24.04"
ID_LIKE=debian
"#;

    const ARCH: &str = r#"
PRETTY_NAME="Arch Linux"
NAME="Arch Linux"
ID=arch
"#;

    const FEDORA_40: &str = r#"
PRETTY_NAME="Fedora Linux 40 (Workstation Edition)"
NAME="Fedora Linux"
ID=fedora
VERSION_ID=40
"#;

    const MX_LINUX: &str = r#"
PRETTY_NAME="MX Linux 23"
NAME="MX Linux"
ID=mxlinux
ID_LIKE=debian
"#;

    const UNKNOWN: &str = r#"
PRETTY_NAME="CustomOS 1.0"
NAME="CustomOS"
ID=customos
"#;

    #[test]
    fn detects_debian() {
        assert_eq!(map_to_distro(&OsRelease::parse(DEBIAN_12)), Distro::Debian);
    }

    #[test]
    fn detects_ubuntu() {
        assert_eq!(map_to_distro(&OsRelease::parse(UBUNTU_24)), Distro::Ubuntu);
    }

    #[test]
    fn detects_arch() {
        assert_eq!(map_to_distro(&OsRelease::parse(ARCH)), Distro::Arch);
    }

    #[test]
    fn detects_fedora() {
        assert_eq!(map_to_distro(&OsRelease::parse(FEDORA_40)), Distro::Fedora);
    }

    #[test]
    fn id_like_fallback_debian() {
        // MX Linux has ID=mxlinux but ID_LIKE=debian — should fall back.
        assert_eq!(map_to_distro(&OsRelease::parse(MX_LINUX)), Distro::Debian);
    }

    #[test]
    fn unknown_distro_uses_generic_path() {
        let d = map_to_distro(&OsRelease::parse(UNKNOWN));
        assert!(matches!(d, Distro::Unknown(_)));
        assert_eq!(d.shadow_path(), std::path::PathBuf::from("/.recoil-linux"));
    }

    #[test]
    fn all_known_shadow_paths_are_dot_prefixed() {
        let distros = [
            Distro::Debian,
            Distro::Ubuntu,
            Distro::Arch,
            Distro::Fedora,
            Distro::Kali,
            Distro::Mint,
            Distro::Unknown("TestOS".into()),
        ];
        for d in &distros {
            let p = d.shadow_path();
            assert!(p.is_absolute(), "{p:?} must be absolute");
            assert!(
                p.to_string_lossy().starts_with("/.recoil-"),
                "{p:?} must start with /.recoil-"
            );
        }
    }
}
