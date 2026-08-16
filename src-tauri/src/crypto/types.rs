//! Core types for vault cryptography: the derived key and KDF parameters.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

use super::CryptoError;

/// Length of the derived vault key in bytes (Argon2id output).
pub const KEY_LEN: usize = 32;

/// Length of the per-vault salt in bytes.
pub const SALT_LEN: usize = 16;

/// OWASP-recommended Argon2id memory cost: 64 MiB (in KiB).
pub const OWASP_ARGON2_M_KIB: u32 = 65_536;

/// OWASP-recommended Argon2id iteration count.
pub const OWASP_ARGON2_T: u32 = 3;

/// OWASP-recommended Argon2id parallelism.
pub const OWASP_ARGON2_P: u32 = 4;

/// Upper bound for Argon2id memory cost: 1 GiB (in KiB). Prevents corrupt or
/// malicious `vault.meta` params from forcing multi-GiB allocations at unlock.
pub const MAX_M_KIB: u32 = 1_048_576;

/// Upper bound for Argon2id iteration count.
pub const MAX_T: u32 = 10;

/// Upper bound for Argon2id parallelism.
pub const MAX_P: u32 = 16;

/// Fast Argon2id memory cost for tests only: the minimum Argon2 accepts.
pub const FAST_TEST_M_KIB: u32 = 8;

/// Fast Argon2id iteration count for tests only.
pub const FAST_TEST_T: u32 = 1;

/// Fast Argon2id parallelism for tests only.
pub const FAST_TEST_P: u32 = 1;

/// Argon2id derivation parameters.
///
/// The per-vault salt is deliberately NOT part of these params: it is
/// generated once at vault creation and persisted next to the params in
/// `vault.meta` (store layer). Keeping derivation params salt-free makes
/// `Default` meaningful (production OWASP params) and keeps the crypto
/// layer free of per-vault state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism factor.
    pub p_cost: u32,
}

impl KdfParams {
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Validates the params against Argon2's hard limits.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost < 8 {
            return Err(CryptoError::InvalidParams(format!(
                "m_cost must be at least 8 KiB, got {}",
                self.m_cost
            )));
        }
        if self.t_cost < 1 {
            return Err(CryptoError::InvalidParams(format!(
                "t_cost must be at least 1, got {}",
                self.t_cost
            )));
        }
        if self.p_cost < 1 {
            return Err(CryptoError::InvalidParams(format!(
                "p_cost must be at least 1, got {}",
                self.p_cost
            )));
        }
        if self.m_cost > MAX_M_KIB {
            return Err(CryptoError::InvalidParams(format!(
                "m_cost must be at most {} KiB (1 GiB), got {}",
                MAX_M_KIB, self.m_cost
            )));
        }
        if self.t_cost > MAX_T {
            return Err(CryptoError::InvalidParams(format!(
                "t_cost must be at most {}, got {}",
                MAX_T, self.t_cost
            )));
        }
        if self.p_cost > MAX_P {
            return Err(CryptoError::InvalidParams(format!(
                "p_cost must be at most {}, got {}",
                MAX_P, self.p_cost
            )));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    /// OWASP-recommended production parameters (m=64 MiB, t=3, p=4).
    fn default() -> Self {
        Self::new(OWASP_ARGON2_M_KIB, OWASP_ARGON2_T, OWASP_ARGON2_P)
    }
}

/// The derived vault key (32 bytes).
///
/// Deliberately NOT `Serialize`/`Clone`/`Copy`/`PartialEq`: key material
/// must never be serialized or leaked through timing side channels
/// (CRY-03). The inner buffer is `Zeroizing`, so the key is wiped on drop
/// (CRY-02).
pub struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl VaultKey {
    /// Wraps a freshly derived key buffer into a zeroizing key, taking
    /// ownership without copying the secret.
    pub(crate) fn from_zeroizing(inner: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(inner)
    }

    /// Test-only constructor for arbitrary key bytes.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Accessor for the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for VaultKey {
    /// Redacted `Debug` impl: never leaks key material into logs (CRY-03).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_match_owasp_recommendations() {
        let params = KdfParams::default();
        assert_eq!(params.m_cost, 65_536);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
        assert_eq!(params.m_cost, OWASP_ARGON2_M_KIB);
        assert_eq!(params.t_cost, OWASP_ARGON2_T);
        assert_eq!(params.p_cost, OWASP_ARGON2_P);
    }

    #[test]
    fn fast_test_params_are_minimum_valid() {
        assert_eq!(FAST_TEST_M_KIB, 8);
        assert_eq!(FAST_TEST_T, 1);
        assert_eq!(FAST_TEST_P, 1);
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_rejects_below_minimum_params() {
        assert!(KdfParams::new(7, 1, 1).validate().is_err());
        assert!(KdfParams::new(8, 0, 1).validate().is_err());
        assert!(KdfParams::new(8, 1, 0).validate().is_err());
        assert!(KdfParams::new(8, 1, 1).validate().is_ok());
    }

    #[test]
    fn validate_rejects_above_maximum_params() {
        // m_cost capped at 1 GiB (in KiB): 2^20.
        assert!(KdfParams::new(1_048_577, 1, 1).validate().is_err());
        assert!(KdfParams::new(1_048_576, 1, 1).validate().is_ok());
        // t_cost capped at 10.
        assert!(KdfParams::new(8, 11, 1).validate().is_err());
        assert!(KdfParams::new(8, 10, 1).validate().is_ok());
        // p_cost capped at 16 (m=128 keeps m >= 8*p for the boundary case).
        assert!(KdfParams::new(8, 1, 17).validate().is_err());
        assert!(KdfParams::new(128, 1, 16).validate().is_ok());
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let key = VaultKey::from_bytes([0xAB; KEY_LEN]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "VaultKey([REDACTED])");
        assert!(!debug.contains("AB"));
    }

    #[test]
    fn key_bytes_are_zeroized_on_drop() {
        // Mirrors the `zeroize` crate's own test: read the buffer through a
        // pointer after `drop` — `Zeroizing` wipes it (CRY-02).
        let ptr = {
            let key = VaultKey::from_bytes([0xAA; KEY_LEN]);
            key.as_bytes().as_ptr()
        };
        let leaked = unsafe { core::slice::from_raw_parts(ptr, KEY_LEN) };
        assert!(leaked.iter().all(|&b| b == 0));
    }
}
