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

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::{RecoilError, Result};
use crate::security::{
    decrypt, derive_key, encrypt, generate_salt, LockState, MasterKey, SALT_LEN,
};
use crate::utils::{
    constants::{
        CONFIG_VERSION, DIR_DB, DIR_LOGS, DIR_RECOIL_B, DIR_RECOIL_ETC,
        DIR_ROOT_MIRROR, DIR_VAULT, FILE_CONFIG, FILE_LOCK_STATE,
    },
    fs_detect::{FilesystemType, LinkStrategy},
    os_detect::Distro,
};

// ── RecoilConfig ─────────────────────────────────────────────────────────────
//
// Everything Recoil needs to know about the system it is protecting.
// Serialised to JSON, then AES-256-GCM encrypted before touching disk.
// The format is invisible to users — encryption makes human-readability
// irrelevant — so JSON is the right choice: smaller, faster, no dep issues.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoilConfig {
    pub version:    String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub distro:        Distro,
    pub filesystem:    FilesystemType,
    pub shadow_dir:    PathBuf,
    pub link_strategy: LinkStrategy,

    // Phase completion flags — set true at the end of each phase
    pub phase1_complete: bool,
    pub phase2_complete: bool,
    pub phase3_complete: bool,
    pub phase4_complete: bool,
    pub phase5_complete: bool,
    pub phase6_complete: bool,
    pub phase7_complete: bool,

    #[serde(default)]
    pub display_name: Option<String>,
}

impl RecoilConfig {
    pub fn new(distro: Distro, filesystem: FilesystemType) -> Self {
        let shadow_dir    = distro.shadow_path();
        let link_strategy = filesystem.link_strategy();
        let now           = Utc::now();
        Self {
            version:         CONFIG_VERSION.to_string(),
            created_at:      now,
            updated_at:      now,
            distro,
            filesystem,
            shadow_dir,
            link_strategy,
            phase1_complete: false,
            phase2_complete: false,
            phase3_complete: false,
            phase4_complete: false,
            phase5_complete: false,
            phase6_complete: false,
            phase7_complete: false,
            display_name:    None,
        }
    }

    // Convenience accessors for shadow subdirectory paths
    pub fn root_mirror(&self) -> PathBuf { self.shadow_dir.join(DIR_ROOT_MIRROR) }
    pub fn vault_dir(&self)   -> PathBuf { self.shadow_dir.join(DIR_VAULT) }
    pub fn logs_dir(&self)    -> PathBuf { self.shadow_dir.join(DIR_LOGS) }
    pub fn db_dir(&self)      -> PathBuf { self.shadow_dir.join(DIR_DB) }
    pub fn recoil_b(&self)    -> PathBuf { self.shadow_dir.join(DIR_RECOIL_B) }
    pub fn recoil_etc(&self)  -> PathBuf { self.shadow_dir.join(DIR_RECOIL_ETC) }
}

// ── On-disk layout ────────────────────────────────────────────────────────────
//
//  [0 .. SALT_LEN)   Argon2id salt  (32 bytes, plaintext — not secret)
//  [SALT_LEN ..)     AES-256-GCM encrypted JSON  (nonce prepended inside)
//
// A fresh salt is generated on every save so password rotation
// automatically re-keys the ciphertext with no extra steps.

// ── ConfigManager ─────────────────────────────────────────────────────────────

pub struct ConfigManager {
    path: PathBuf,
}

impl ConfigManager {
    /// Bootstrap path: used before the shadow directory exists (Phase 1).
    /// After Phase 2 the config migrates inside the shadow layer.
    pub fn bootstrap() -> Self {
        Self {
            path: PathBuf::from(crate::utils::constants::BOOTSTRAP_CONFIG_DIR)
                .join(FILE_CONFIG),
        }
    }

    pub fn from_shadow(shadow_dir: &Path) -> Self {
        Self { path: shadow_dir.join(FILE_CONFIG) }
    }

    pub fn path(&self) -> &Path   { &self.path }
    pub fn exists(&self) -> bool  { self.path.exists() }

    pub fn save(&self, config: &RecoilConfig, password: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RecoilError::Config(format!("Cannot create {:?}: {e}", parent))
            })?;
        }

        let salt      = generate_salt();
        let key       = derive_key(password, &salt)?;
        let json      = serde_json::to_vec(config)?;
        let encrypted = encrypt(&json, &key)?;

        let mut blob = Vec::with_capacity(SALT_LEN + encrypted.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&encrypted);

        std::fs::write(&self.path, &blob).map_err(|e| {
            RecoilError::Config(format!("Cannot write {:?}: {e}", self.path))
        })?;

        info!(path = %self.path.display(), "Config saved (AES-256-GCM encrypted)");
        Ok(())
    }

    pub fn load(&self, password: &str) -> Result<RecoilConfig> {
        if !self.path.exists() {
            return Err(RecoilError::NotInitialised);
        }

        let blob = std::fs::read(&self.path).map_err(|e| {
            RecoilError::Config(format!("Cannot read {:?}: {e}", self.path))
        })?;

        if blob.len() < SALT_LEN + 1 {
            return Err(RecoilError::Config(
                "Config file is corrupt or truncated".into(),
            ));
        }

        let salt: [u8; SALT_LEN] = blob[..SALT_LEN]
            .try_into()
            .map_err(|_| RecoilError::Config("Salt extraction failed".into()))?;

        let key       = derive_key(password, &salt)?;
        let plaintext = decrypt(&blob[SALT_LEN..], &key)?;
        let config: RecoilConfig = serde_json::from_slice(&plaintext)?;

        debug!(distro = ?config.distro, shadow = %config.shadow_dir.display(),
               "Config loaded");
        Ok(config)
    }

    /// Derive the master key from the salt stored in the config file.
    /// Used by vault operations that need the key without loading the full config.
    pub fn derive_key_only(&self, password: &str) -> Result<MasterKey> {
        if !self.path.exists() {
            return Err(RecoilError::NotInitialised);
        }
        let blob = std::fs::read(&self.path).map_err(|e| {
            RecoilError::Config(format!("Cannot read config: {e}"))
        })?;
        if blob.len() < SALT_LEN {
            return Err(RecoilError::Config("Config file truncated".into()));
        }
        let salt: [u8; SALT_LEN] = blob[..SALT_LEN]
            .try_into()
            .map_err(|_| RecoilError::Config("Salt extraction failed".into()))?;
        derive_key(password, &salt)
    }
}

// ── LockState persistence ─────────────────────────────────────────────────────

pub fn lock_state_path(base: &Path) -> PathBuf {
    base.join(FILE_LOCK_STATE)
}

pub fn load_lock_state(base: &Path) -> LockState {
    let path = lock_state_path(base);
    if !path.exists() { return LockState::default(); }
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_lock_state(base: &Path, state: &LockState) -> Result<()> {
    let path = lock_state_path(base);
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
        let mgr = ConfigManager { path: dir.path().join(".config") };

        mgr.save(&sample_config(), "correct_password_1!").unwrap();
        let loaded = mgr.load("correct_password_1!").unwrap();

        assert_eq!(loaded.version, CONFIG_VERSION);
        assert_eq!(loaded.distro, Distro::Debian);
        assert!(!loaded.phase2_complete);
    }

    #[test]
    fn wrong_password_gives_auth_failed() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager { path: dir.path().join(".config") };
        mgr.save(&sample_config(), "correct!1").unwrap();
        assert!(matches!(
            mgr.load("totally_wrong"),
            Err(RecoilError::AuthFailed)
        ));
    }

    #[test]
    fn missing_file_gives_not_initialised() {
        let dir = tempdir().unwrap();
        let mgr = ConfigManager { path: dir.path().join(".config") };
        assert!(matches!(
            mgr.load("anything"),
            Err(RecoilError::NotInitialised)
        ));
    }

    #[test]
    fn shadow_path_derived_from_distro() {
        let cfg = sample_config();
        assert_eq!(cfg.shadow_dir, PathBuf::from("/.recoil-debian"));
    }

    #[test]
    fn subdirectory_accessors_are_under_shadow() {
        let cfg = sample_config();
        assert!(cfg.vault_dir().starts_with(&cfg.shadow_dir));
        assert!(cfg.recoil_b().starts_with(&cfg.shadow_dir));
        assert!(cfg.recoil_etc().starts_with(&cfg.shadow_dir));
    }

    #[test]
    fn lock_state_survives_persist_and_reload() {
        let dir = tempdir().unwrap();
        let mut s = LockState::default();
        s.on_failure();
        s.on_failure();
        save_lock_state(dir.path(), &s).unwrap();
        let loaded = load_lock_state(dir.path());
        assert_eq!(loaded.consecutive, 2);
    }
}
