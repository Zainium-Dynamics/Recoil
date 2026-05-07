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

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::{RecoilError, Result};

// Distro enum

/// Every distribution Recoil knows about.  The `Unknown` variant catches
/// anything not in this list — we still protect those systems, they just
/// get the generic shadow directory name.
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
    Zainium,
    Unknown(String),
}

impl Distro {
    /// Returns the name of the hidden shadow directory used for Recoil
    /// on the root filesystem.
    ///
    /// Each distribution gets its own unique namespace (e.g. `.recoil-ubuntu`,
    /// `.recoil-arch`) so that:
    ///
    /// - Multi-boot systems do not collide between installations
    /// - Each OS instance can isolate its own Recoil metadata
    /// - Forensic and recovery tools can clearly identify origin system
    /// - Shadow state remains distro-specific and traceable
    ///
    /// This is not intended to be user-facing or manually edited.
    pub fn shadow_dir_name(&self) -> String {
        match self {
            Distro::Debian       => ".recoil-debian",
            Distro::Ubuntu       => ".recoil-ubuntu",
            Distro::Arch         => ".recoil-arch",
            Distro::Manjaro      => ".recoil-manjaro",
            Distro::Fedora       => ".recoil-fedora",
            Distro::CentOs       => ".recoil-centos",
            Distro::Rhel         => ".recoil-rhel",
            Distro::AlmaLinux    => ".recoil-alma",
            Distro::RockyLinux   => ".recoil-rocky",
            Distro::OpenSuse     => ".recoil-opensuse",
            Distro::Gentoo       => ".recoil-gentoo",
            Distro::Void         => ".recoil-void",
            Distro::Alpine       => ".recoil-alpine",
            Distro::Mint         => ".recoil-mint",
            Distro::PopOs        => ".recoil-pop",
            Distro::ElementaryOs => ".recoil-elementary",
            Distro::Kali         => ".recoil-kali",
            Distro::Parrot       => ".recoil-parrot",
            Distro::Zainium      => ".recoil-zainium",
            Distro::Unknown(_)   => ".recoil-linux",
        }
        .to_string()
    }

    /// Absolute path of the shadow directory root (e.g. `/.recoil-debian`).
    pub fn shadow_path(&self) -> PathBuf {
        PathBuf::from("/").join(self.shadow_dir_name())
    }

    pub fn display_name(&self) -> String {
        match self {
            Distro::Debian       => "Debian GNU/Linux",
            Distro::Ubuntu       => "Ubuntu",
            Distro::Arch         => "Arch Linux",
            Distro::Manjaro      => "Manjaro Linux",
            Distro::Fedora       => "Fedora Linux",
            Distro::CentOs       => "CentOS Linux",
            Distro::Rhel         => "Red Hat Enterprise Linux",
            Distro::AlmaLinux    => "AlmaLinux",
            Distro::RockyLinux   => "Rocky Linux",
            Distro::OpenSuse     => "openSUSE",
            Distro::Gentoo       => "Gentoo Linux",
            Distro::Void         => "Void Linux",
            Distro::Alpine       => "Alpine Linux",
            Distro::Mint         => "Linux Mint",
            Distro::PopOs        => "Pop!_OS",
            Distro::ElementaryOs => "elementary OS",
            Distro::Kali         => "Kali Linux",
            Distro::Parrot       => "Parrot OS",
            Distro::Zainium      => "Zainium OS",
            Distro::Unknown(n)   => return n.clone(),
        }
        .to_string()
    }
}

// /etc/os-release parser

#[derive(Debug)]
struct OsRelease {
    id:          String,
    id_like:     Vec<String>,
    pretty_name: String,
    version_id:  Option<String>,
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
                // Strip surrounding quotes if present
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

        let version_id = map.get("VERSION_ID").cloned();

        OsRelease { id, id_like, pretty_name, version_id }
    }

    /// Returns true if `candidate` appears in ID or any ID_LIKE token.
    fn matches(&self, candidate: &str) -> bool {
        self.id == candidate || self.id_like.iter().any(|s| s == candidate)
    }
}

// Public API

/// Read /etc/os-release and classify the running distribution.
pub fn detect_distro() -> Result<Distro> {
    let content = std::fs::read_to_string("/etc/os-release").map_err(|e| {
        RecoilError::OsDetection(format!("Cannot read /etc/os-release: {e}"))
    })?;

    let rel = OsRelease::parse(&content);
    debug!(id = %rel.id, id_like = ?rel.id_like, version = ?rel.version_id, pretty = %rel.pretty_name, "os-release parsed");

    let distro = map_to_distro(&rel);
    Ok(distro)
}

fn map_to_distro(rel: &OsRelease) -> Distro {
    match rel.id.as_str() {
        "zainium"          => Distro::Zainium,
        "debian"           => Distro::Debian,
        "ubuntu"           => Distro::Ubuntu,
        "linuxmint"        => Distro::Mint,
        "pop"              => Distro::PopOs,
        "elementary"       => Distro::ElementaryOs,
        "kali"             => Distro::Kali,
        "parrot"           => Distro::Parrot,
        "arch"             => Distro::Arch,
        "manjaro"          => Distro::Manjaro,
        "fedora"           => Distro::Fedora,
        "centos"           => Distro::CentOs,
        "rhel"             => Distro::Rhel,
        "almalinux"        => Distro::AlmaLinux,
        "rocky"            => Distro::RockyLinux,
        "gentoo"           => Distro::Gentoo,
        "void"             => Distro::Void,
        "alpine"           => Distro::Alpine,
        id if id.starts_with("opensuse") => Distro::OpenSuse,
        _ => {
            // Fall back through ID_LIKE before giving up
            if rel.matches("debian") {
                warn!(id = %rel.id, "Unknown distro; ID_LIKE matched debian");
                Distro::Debian
            } else if rel.matches("ubuntu") {
                warn!(id = %rel.id, "Unknown distro; ID_LIKE matched ubuntu");
                Distro::Ubuntu
            } else if rel.matches("arch") {
                Distro::Arch
            } else if rel.matches("fedora") || rel.matches("rhel") {
                Distro::Fedora
            } else {
                warn!(id = %rel.id, "Unrecognised distribution — using generic shadow path");
                Distro::Unknown(rel.pretty_name.clone())
            }
        }
    }
}

/// Returns the running kernel version string from `uname -r`.
pub fn kernel_version() -> Result<String> {
    let out = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|e| RecoilError::OsDetection(format!("uname failed: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Returns true when the effective user ID is 0 (root).
pub fn is_root() -> bool {
    // SAFETY: getuid() is always safe to call
    unsafe { libc::geteuid() == 0 }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_12: &str = r#"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
HOME_URL="https://www.debian.org/"
"#;

    const UBUNTU_24: &str = r#"
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;

    const ZAINIUM: &str = r#"
PRETTY_NAME="Zainium OS 1.0"
NAME="Zainium OS"
ID=zainium
ID_LIKE=debian
"#;

    const UNKNOWN_DEBIAN_LIKE: &str = r#"
PRETTY_NAME="MXLinux 23"
NAME="MXLinux"
ID=mxlinux
ID_LIKE=debian
"#;

    #[test]
    fn detects_debian_12() {
        let rel = OsRelease::parse(DEBIAN_12);
        assert_eq!(rel.id, "debian");
        assert_eq!(rel.version_id.as_deref(), Some("12"));
    }

    #[test]
    fn detects_ubuntu_24() {
        let rel = OsRelease::parse(UBUNTU_24);
        assert_eq!(rel.id, "ubuntu");
        assert!(rel.id_like.contains(&"debian".to_string()));
    }

    #[test]
    fn zainium_gets_correct_shadow_path() {
        let d = map_to_distro(&OsRelease::parse(ZAINIUM));
        assert_eq!(d, Distro::Zainium);
        assert_eq!(d.shadow_path(), std::path::PathBuf::from("/.recoil-zainium"));
    }

    #[test]
    fn unknown_falls_back_via_id_like() {
        let d = map_to_distro(&OsRelease::parse(UNKNOWN_DEBIAN_LIKE));
        assert_eq!(d, Distro::Debian);
    }

    #[test]
    fn all_shadow_paths_are_absolute_and_prefixed() {
        let distros = [
            Distro::Debian, Distro::Ubuntu, Distro::Arch,
            Distro::Fedora, Distro::Zainium,
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
