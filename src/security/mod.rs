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

//! Cryptographic core for Recoil.
//!
//! Key derivation: PBKDF2-HMAC-SHA512 at 600,000 iterations (OWASP 2024).
//! Milestone 3 upgrades this to Argon2id (64 MiB, 3 iterations, 4-way
//! parallelism) once toolchain compatibility is confirmed.
//!
//! Encryption: AES-256-GCM with fresh OsRng 96-bit nonce per operation.
//! On-disk format: nonce (12 bytes) || ciphertext+GCM_tag.
//!
//! Rate limiting: three-tier wall-clock exponential back-off.
//! All state is stored on disk as Unix seconds — survives reboots.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{RecoilError, Result};
use crate::utils::constants::{
    TIER1_ATTEMPTS, TIER1_LOCK_SEC, TIER2_ATTEMPTS, TIER2_LOCK_SEC, TIER2_WINDOW, TIER3_ATTEMPTS,
    TIER3_WINDOW,
};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const KDF_ITERS: u32 = 600_000;
pub const KEY_LEN: usize = 32; // 256-bit AES key
pub const NONCE_LEN: usize = 12; // 96-bit GCM nonce
pub const SALT_LEN: usize = 32; // 256-bit random salt

// ── MasterKey ─────────────────────────────────────────────────────────────────

/// The 256-bit AES key derived from the master password.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` — the key bytes are cleared
/// from memory when the value is dropped, preventing recovery from heap
/// dumps, swap, or core files.
///
/// The `Debug` implementation always prints `[REDACTED]` to prevent
/// accidental exposure through log output or panic messages.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Generate a fresh 32-byte cryptographically random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut buf = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Derive a 256-bit AES key from `password` and `salt` using
/// PBKDF2-HMAC-SHA512 at 600,000 iterations.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<MasterKey> {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, KDF_ITERS, &mut key)
        .map_err(|e| RecoilError::Crypto(format!("PBKDF2 failed: {e}")))?;
    Ok(MasterKey(key))
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` and return `nonce (12 B) || ciphertext+tag`.
///
/// A fresh OsRng nonce is generated for every call — nonce reuse is
/// structurally impossible in this design.
pub fn encrypt(plaintext: &[u8], key: &MasterKey) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| RecoilError::Crypto(format!("AES init: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| RecoilError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by `encrypt()`.
///
/// Returns `Err(AuthFailed)` on any failure — wrong key, tampered
/// ciphertext, truncated data, and nonce-length violations all return
/// the same error with no diagnostic detail.
pub fn decrypt(data: &[u8], key: &MasterKey) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + 16 {
        return Err(RecoilError::AuthFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| RecoilError::Crypto(format!("AES init: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| RecoilError::AuthFailed)
}

// ── LockState — persistent rate limiter ──────────────────────────────────────

/// Serialisable rate-limiter state stored at `<shadow>/.lock_state`.
///
/// All timestamps are wall-clock Unix seconds — the state survives reboots
/// without resetting. An attacker cannot clear the lockout by power-cycling
/// the device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockState {
    /// Consecutive failures in the current streak.
    pub consecutive: u32,
    /// Unix timestamp of the first attempt in the current rolling window.
    pub window_start: u64,
    /// Attempt count within the current rolling window.
    pub window_count: u32,
    /// Unix timestamp after which the vault is unlocked again. 0 = unlocked.
    pub locked_until: u64,
    /// Permanent hard lock — requires manual administrator reset.
    pub hard_locked: bool,
    /// All-time failed attempt counter for audit purposes.
    pub total_attempts: u32,
}

impl LockState {
    /// Check whether the vault is currently locked.
    /// Returns `Err` when locked, `Ok(())` when access should be permitted.
    pub fn check(&self) -> Result<()> {
        if self.hard_locked {
            return Err(RecoilError::HardLocked);
        }
        let now = unix_now();
        if now < self.locked_until {
            let mins = (self.locked_until - now).div_ceil(60);
            return Err(RecoilError::RateLimited { minutes: mins });
        }
        Ok(())
    }

    /// Number of attempts remaining before the next lockout tier activates.
    pub fn attempts_remaining(&self) -> u32 {
        if self.consecutive < TIER1_ATTEMPTS {
            TIER1_ATTEMPTS - self.consecutive
        } else {
            1
        }
    }

    /// Record a successful authentication and reset all counters.
    pub fn on_success(&mut self) {
        *self = LockState::default();
    }

    /// Record a failed authentication attempt and apply the appropriate tier.
    pub fn on_failure(&mut self) {
        let now = unix_now();
        self.consecutive += 1;
        self.total_attempts += 1;

        // Refresh rolling window counter.
        if now.saturating_sub(self.window_start) > TIER3_WINDOW {
            self.window_start = now;
            self.window_count = 1;
        } else {
            self.window_count += 1;
        }

        warn!(
            consecutive = self.consecutive,
            window = self.window_count,
            "failed authentication attempt"
        );

        // Evaluate tiers from highest severity downward.
        if self.window_count >= TIER3_ATTEMPTS
            && now.saturating_sub(self.window_start) <= TIER3_WINDOW
        {
            warn!("tier-3 hard lock activated");
            self.hard_locked = true;
            return;
        }
        if self.window_count >= TIER2_ATTEMPTS
            && now.saturating_sub(self.window_start) <= TIER2_WINDOW
        {
            self.locked_until = now + TIER2_LOCK_SEC;
            warn!("tier-2 lock: {} min", TIER2_LOCK_SEC / 60);
            return;
        }
        if self.consecutive >= TIER1_ATTEMPTS {
            self.locked_until = now + TIER1_LOCK_SEC;
            warn!("tier-1 lock: {} min", TIER1_LOCK_SEC / 60);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Password strength ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Strength {
    Weak,
    Moderate,
    Strong,
}

/// Advisory password strength classification used by `recoil setup` to
/// display the `⚠ Password is relatively weak` warning. Does not block.
pub fn password_strength(pw: &str) -> Strength {
    let has_upper = pw.chars().any(|c| c.is_uppercase());
    let has_lower = pw.chars().any(|c| c.is_lowercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_alphanumeric());
    let score = [has_upper, has_lower, has_digit, has_symbol]
        .iter()
        .filter(|&&b| b)
        .count();

    match (pw.len(), score) {
        (l, s) if l >= 16 && s >= 3 => Strength::Strong,
        (l, s) if l >= 8 && s >= 2 => Strength::Moderate,
        _ => Strength::Weak,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic() {
        let salt = generate_salt();
        let k1 = derive_key("correct-horse-battery-42!", &salt).unwrap();
        let k2 = derive_key("correct-horse-battery-42!", &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let k1 = derive_key("same-password", &generate_salt()).unwrap();
        let k2 = derive_key("same-password", &generate_salt()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("roundtrip-test-42!", &generate_salt()).unwrap();
        let msg = b"sensitive system data - recoil test";
        let ct = encrypt(msg, &key).unwrap();
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_key_returns_auth_failed() {
        let k1 = derive_key("correct", &generate_salt()).unwrap();
        let k2 = derive_key("wrong", &generate_salt()).unwrap();
        let ct = encrypt(b"secret", &k1).unwrap();
        assert!(matches!(decrypt(&ct, &k2), Err(RecoilError::AuthFailed)));
    }

    #[test]
    fn tampered_ciphertext_returns_auth_failed() {
        let key = derive_key("tamper-test", &generate_salt()).unwrap();
        let mut ct = encrypt(b"real data", &key).unwrap();
        ct[NONCE_LEN + 2] ^= 0xFF; // flip a bit inside the ciphertext
        assert!(matches!(decrypt(&ct, &key), Err(RecoilError::AuthFailed)));
    }

    #[test]
    fn tier1_lock_activates_after_3_failures() {
        let mut s = LockState::default();
        for _ in 0..3 {
            s.on_failure();
        }
        assert!(matches!(s.check(), Err(RecoilError::RateLimited { .. })));
    }

    #[test]
    fn success_resets_all_state() {
        let mut s = LockState::default();
        s.on_failure();
        s.on_failure();
        s.on_success();
        assert_eq!(s.consecutive, 0);
        assert!(s.check().is_ok());
    }

    #[test]
    fn password_strength_classification() {
        assert_eq!(password_strength("abc"), Strength::Weak);
        assert_eq!(password_strength("Password1"), Strength::Moderate);
        assert_eq!(password_strength("V@ult_Key!2026#Sec"), Strength::Strong);
    }
}
