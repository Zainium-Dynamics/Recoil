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

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{RecoilError, Result};
use crate::security::{decrypt, derive_key, encrypt, generate_salt, LockState, SALT_LEN};
use crate::utils::{
    constants::*,
    fs_detect::{FilesystemType, LinkStrategy},
    os_detect::Distro,
};

// ── RecoilConfig ──────────────────────────────────────────────────────────────

/// Top-level configuration schema stored AES-256-GCM encrypted on disk.
///
/// On-disk layout: salt (32 B) || nonce (12 B) || ciphertext+tag.
/// All fields are serialised to JSON before encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoilConfig {
    /// Schema version — increment on breaking changes.
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Detected Linux distribution.
    pub distro: Distro,
    /// Detected root filesystem type.
    pub filesystem: FilesystemType,
    /// Absolute path of the shadow directory root.
    pub shadow_dir: PathBuf,
    /// Mirror linking strategy derived from the filesystem type.
    pub link_strategy: LinkStrategy,
    /// Milestone completion flags — updated as each milestone ships.
    pub milestone1_complete: bool,
    pub milestone2_complete: bool,
    pub milestone3_complete: bool,
    pub milestone4_complete: bool,
    pub milestone5_complete: bool,
}

impl RecoilConfig {
    /// Construct a new config from detected system properties.
    pub fn new(distro: Distro, filesystem: FilesystemType) -> Self {
        let link_strategy = filesystem.link_strategy();
        let shadow_dir = distro.shadow_path();
        let now = Utc::now();
        Self {
            version: CONFIG_VERSION.to_string(),
            created_at: now,
            updated_at: now,
            distro,
            filesystem,
            shadow_dir,
            link_strategy,
            milestone1_complete: false,
            milestone2_complete: false,
            milestone3_complete: false,
            milestone4_complete: false,
            milestone5_complete: false,
        }
    }

    // ── Convenience path helpers ─────────────────────────────────────────────

    pub fn root_mirror(&self) -> PathBuf {
        self.shadow_dir.join(DIR_ROOT_MIRROR)
    }

    pub fn versions_dir(&self) -> PathBuf {
        self.shadow_dir.join(DIR_VERSIONS)
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.shadow_dir.join(DIR_VAULT)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.shadow_dir.join(DIR_LOGS)
    }

    pub fn db_dir(&self) -> PathBuf {
        self.shadow_dir.join(DIR_DB)
    }

    pub fn recoil_b(&self) -> PathBuf {
        self.shadow_dir.join(DIR_RECOIL_B)
    }

    pub fn recoil_etc(&self) -> PathBuf {
        self.shadow_dir.join(DIR_RECOIL_ETC)
    }

    pub fn config_path(&self) -> PathBuf {
        self.shadow_dir.join(FILE_CONFIG)
    }

    pub fn lock_state_path(&self) -> PathBuf {
        self.shadow_dir.join(FILE_LOCK_STATE)
    }
}

// ── ConfigManager ─────────────────────────────────────────────────────────────

/// Manages encrypted configuration persistence.
///
/// Two constructors handle the two stages of Recoil's lifecycle:
/// - `bootstrap()` — used during first-time setup before the shadow layer
///   exists, storing config at `/etc/recoil/.config`.
/// - `from_shadow()` — used after Milestone 2 setup, storing config inside
///   the immutable shadow layer at `/.recoil-<distro>/.config`.
pub struct ConfigManager {
    path: PathBuf,
}

impl ConfigManager {
    /// Pre-shadow bootstrap path — `/etc/recoil/.config`.
    pub fn bootstrap() -> Self {
        Self {
            path: PathBuf::from(BOOTSTRAP_CONFIG_DIR).join(FILE_CONFIG),
        }
    }

    /// Shadow layer path — `<shadow_dir>/.config`.
    pub fn from_shadow(shadow_dir: &Path) -> Self {
        Self {
            path: shadow_dir.join(FILE_CONFIG),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Encrypt `cfg` with `password` and write to disk.
    ///
    /// A fresh random salt is generated on every save. This means each write
    /// re-derives the key, and a password change transparently re-keys the
    /// ciphertext at no extra cost.
    pub fn save(&self, cfg: &RecoilConfig, password: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(RecoilError::Io)?;
        }
        let salt = generate_salt();
        let key = derive_key(password, &salt)?;
        let json = serde_json::to_vec(cfg)?;
        let encrypted = encrypt(&json, &key)?;
        let mut blob = Vec::with_capacity(SALT_LEN + encrypted.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&encrypted);
        std::fs::write(&self.path, &blob).map_err(RecoilError::Io)
    }

    /// Decrypt and deserialise the stored configuration.
    pub fn load(&self, password: &str) -> Result<RecoilConfig> {
        if !self.path.exists() {
            return Err(RecoilError::NotInitialised);
        }
        let blob = std::fs::read(&self.path).map_err(RecoilError::Io)?;
        if blob.len() < SALT_LEN + 1 {
            return Err(RecoilError::Config(
                "configuration file is corrupt or truncated".into(),
            ));
        }
        let salt: [u8; SALT_LEN] = blob[..SALT_LEN]
            .try_into()
            .map_err(|_| RecoilError::Config("salt extraction failed".into()))?;
        let key = derive_key(password, &salt)?;
        let plaintext = decrypt(&blob[SALT_LEN..], &key)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

// ── LockState persistence ─────────────────────────────────────────────────────

/// Load the rate-limiter state from `base/.lock_state`.
/// Returns `LockState::default()` when the file does not exist yet.
pub fn load_lock_state(base: &Path) -> LockState {
    let path = base.join(FILE_LOCK_STATE);
    if !path.exists() {
        return LockState::default();
    }
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Persist the rate-limiter state to `base/.lock_state`.
pub fn save_lock_state(base: &Path, state: &LockState) -> Result<()> {
    let path = base.join(FILE_LOCK_STATE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(RecoilError::Io)?;
    }
    let bytes = serde_json::to_vec(state)?;
    std::fs::write(&path, bytes).map_err(RecoilError::Io)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_config() -> RecoilConfig {
        RecoilConfig::new(Distro::Debian, FilesystemType::Ext4)
    }

    #[test]
    fn roundtrip_save_and_load() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager {
            path: dir.path().join(FILE_CONFIG),
        };
        mgr.save(&sample_config(), "correct-pass-42!").unwrap();
        let cfg = mgr.load("correct-pass-42!").unwrap();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(!cfg.milestone2_complete);
    }

    #[test]
    fn wrong_password_returns_auth_failed() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager {
            path: dir.path().join(FILE_CONFIG),
        };
        mgr.save(&sample_config(), "correct!42").unwrap();
        assert!(matches!(
            mgr.load("wrong-password"),
            Err(RecoilError::AuthFailed)
        ));
    }

    #[test]
    fn missing_file_returns_not_initialised() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager {
            path: dir.path().join(FILE_CONFIG),
        };
        assert!(matches!(
            mgr.load("anything"),
            Err(RecoilError::NotInitialised)
        ));
    }

    #[test]
    fn shadow_path_is_dot_prefixed() {
        let cfg = sample_config();
        assert!(
            cfg.shadow_dir.to_string_lossy().contains(".recoil-"),
            "shadow_dir must contain .recoil-"
        );
    }

    #[test]
    fn lock_state_roundtrip() {
        let dir = tempdir().unwrap();
        let mut s = LockState::default();
        s.on_failure();
        s.on_failure();
        save_lock_state(dir.path(), &s).unwrap();
        let loaded = load_lock_state(dir.path());
        assert_eq!(loaded.consecutive, 2);
    }

    #[test]
    fn missing_lock_state_file_returns_default() {
        let dir = tempdir().unwrap();
        let loaded = load_lock_state(dir.path());
        assert_eq!(loaded.consecutive, 0);
        assert_eq!(loaded.locked_until, 0);
    }

    #[test]
    fn truncated_config_file_returns_config_error() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager {
            path: dir.path().join(FILE_CONFIG),
        };
        std::fs::write(mgr.path(), [0u8; 4]).unwrap();
        assert!(matches!(mgr.load("anything"), Err(RecoilError::Config(_))));
    }

    #[test]
    fn config_path_helpers_join_under_shadow_dir() {
        let cfg = sample_config();
        for path in [
            cfg.root_mirror(),
            cfg.versions_dir(),
            cfg.vault_dir(),
            cfg.logs_dir(),
            cfg.db_dir(),
            cfg.recoil_b(),
            cfg.recoil_etc(),
            cfg.config_path(),
            cfg.lock_state_path(),
        ] {
            assert!(
                path.starts_with(&cfg.shadow_dir),
                "{path:?} must live under {:?}",
                cfg.shadow_dir
            );
        }
    }

    #[test]
    fn save_regenerates_salt_on_every_write() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager {
            path: dir.path().join(FILE_CONFIG),
        };
        mgr.save(&sample_config(), "pass-1-42!").unwrap();
        let first = std::fs::read(mgr.path()).unwrap();
        mgr.save(&sample_config(), "pass-1-42!").unwrap();
        let second = std::fs::read(mgr.path()).unwrap();
        assert_ne!(
            first[..SALT_LEN],
            second[..SALT_LEN],
            "salt must be fresh on every save"
        );
    }
}
