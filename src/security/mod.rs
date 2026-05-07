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

//! Cryptographic primitives for Recoil.
//!
//! Key derivation: PBKDF2-HMAC-SHA512 at 600,000 iterations (current OWASP
//! recommendation for PBKDF2-SHA512).  The salt is 32 random bytes generated
//! per-setup via OsRng.  The output is a 256-bit AES key.
//!
//! Encryption: AES-256-GCM with a fresh 96-bit OsRng nonce per call.
//! Ciphertext format on disk: nonce (12 B) || ciphertext+tag.
//!
//! Rate limiting: three-tier wall-clock exponential backoff persisted to disk,
//! reboot-proof (all timestamps are Unix seconds not process uptime).

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

// ── Constants ─────────────────────────────────────────────────────────────────

/// 600,000 iterations — OWASP recommendation for PBKDF2-HMAC-SHA512 (2024).
pub const KDF_ITERS: u32 = 600_000;
pub const KEY_LEN: usize = 32; // 256-bit AES key
pub const NONCE_LEN: usize = 12; // 96-bit GCM nonce per NIST SP 800-38D
pub const SALT_LEN: usize = 32; // 256-bit random salt

// Lockout thresholds and durations (all in seconds)
const T1_ATTEMPTS: u32 = 3;
const T1_SECS: u64 = 20 * 60;
const T2_ATTEMPTS: u32 = 15;
const T2_WINDOW: u64 = 3_600;
const T2_SECS: u64 = 3 * 3_600;
const T3_ATTEMPTS: u32 = 50;
const T3_WINDOW: u64 = 86_400;

// ── MasterKey ─────────────────────────────────────────────────────────────────

/// The derived 256-bit AES key.  Memory is zeroed on drop — the key
/// must never be written to disk or included in log output.
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

// ── Key derivation ─────────────────────────────────────────────────────────────

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut buf = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Derive a 256-bit encryption key from `password` using PBKDF2-HMAC-SHA512.
///
/// `salt` must be unique per vault (generated once at setup and stored in
/// plaintext alongside the ciphertext — the salt is not secret).
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<MasterKey> {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, KDF_ITERS, &mut key)
        .map_err(|e| RecoilError::Crypto(format!("PBKDF2 failed: {e}")))?;
    Ok(MasterKey(key))
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext`.  Returns `nonce (12 B) || ciphertext+tag`.
/// A fresh nonce is generated from OsRng for every single call.
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

// Decrypt data produced by `encrypt()`.
//
// Returns `AuthFailed` regardless of whether the cause was a wrong key,
// a tampered ciphertext, or a truncated blob — leaking that distinction
// would help an attacker narrow down the failure mode.
pub fn decrypt(data: &[u8], key: &MasterKey) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + 16 {
        // Minimum: 12-byte nonce + 16-byte GCM auth tag
        return Err(RecoilError::AuthFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| RecoilError::Crypto(format!("AES init: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| RecoilError::AuthFailed)
}

// ── Rate limiter ───────────────────────────────────────────────────────────────

// Persisted lock state.  All timestamps are Unix seconds so the timers
// survive process restarts and reboots — an attacker cannot reset a lockout
// by rebooting the machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockState {
    pub consecutive: u32,
    pub window_start: u64, // Unix ts of first attempt in the current window
    pub window_count: u32, // Attempts seen in the current sliding window
    pub locked_until: u64, // Unix ts; 0 = not locked
    pub hard_locked: bool,
}

impl LockState {
    /// Returns `Err` if the vault is currently locked.
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

    pub fn on_success(&mut self) {
        *self = LockState::default();
    }

    pub fn on_failure(&mut self) {
        let now = unix_now();
        self.consecutive += 1;

        // Maintain the sliding window
        if now.saturating_sub(self.window_start) > T3_WINDOW {
            self.window_start = now;
            self.window_count = 1;
        } else {
            self.window_count += 1;
        }

        warn!(
            consecutive = self.consecutive,
            window = self.window_count,
            "Failed authentication attempt"
        );

        // Evaluate tiers highest → lowest so we apply the most severe that applies
        if self.window_count >= T3_ATTEMPTS && now.saturating_sub(self.window_start) <= T3_WINDOW {
            warn!(
                "Hard lock activated ({} attempts in 24h)",
                self.window_count
            );
            self.hard_locked = true;
            return;
        }
        if self.window_count >= T2_ATTEMPTS && now.saturating_sub(self.window_start) <= T2_WINDOW {
            self.locked_until = now + T2_SECS;
            warn!("Tier-2 lock: {} min", T2_SECS / 60);
            return;
        }
        if self.consecutive >= T1_ATTEMPTS {
            self.locked_until = now + T1_SECS;
            warn!("Tier-1 lock: {} min", T1_SECS / 60);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Password strength hint

#[derive(Debug, PartialEq, Eq)]
pub enum Strength {
    Weak,
    Moderate,
    Strong,
}

pub fn password_strength(pw: &str) -> Strength {
    let score: u8 = [
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .map(|&b| b as u8)
    .sum();

    match (pw.len(), score) {
        (l, s) if l >= 16 && s >= 3 => Strength::Strong,
        (l, s) if l >= 8 && s >= 2 => Strength::Moderate,
        _ => Strength::Weak,
    }
}

// ── Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic() {
        let salt = generate_salt();
        let k1 = derive_key("same_pass_42!", &salt).unwrap();
        let k2 = derive_key("same_pass_42!", &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salts_give_different_keys() {
        let k1 = derive_key("same", &generate_salt()).unwrap();
        let k2 = derive_key("same", &generate_salt()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("roundtrip_test!", &generate_salt()).unwrap();
        let msg = b"sensitive system data \xFF\x00\x42";
        let ct = encrypt(msg, &key).unwrap();
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_key_gives_auth_failed() {
        let k1 = derive_key("correct", &generate_salt()).unwrap();
        let k2 = derive_key("wrong", &generate_salt()).unwrap();
        let ct = encrypt(b"secret", &k1).unwrap();
        assert!(matches!(decrypt(&ct, &k2), Err(RecoilError::AuthFailed)));
    }

    #[test]
    fn tampered_ciphertext_gives_auth_failed() {
        let key = derive_key("tamper", &generate_salt()).unwrap();
        let mut ct = encrypt(b"real data", &key).unwrap();
        ct[NONCE_LEN + 2] ^= 0xFF; // flip a byte past the nonce
        assert!(matches!(decrypt(&ct, &key), Err(RecoilError::AuthFailed)));
    }

    #[test]
    fn tier1_lock_after_3_failures() {
        let mut s = LockState::default();
        for _ in 0..3 {
            s.on_failure();
        }
        assert!(matches!(s.check(), Err(RecoilError::RateLimited { .. })));
    }

    #[test]
    fn success_resets_state() {
        let mut s = LockState::default();
        s.on_failure();
        s.on_success();
        assert_eq!(s.consecutive, 0);
        assert!(s.check().is_ok());
    }

    #[test]
    fn password_strength_classification() {
        assert_eq!(password_strength("abc"), Strength::Weak);
        assert_eq!(password_strength("Password1"), Strength::Moderate);
        assert_eq!(password_strength("V@ult_K3y!2026#Sec"), Strength::Strong);
    }
}
