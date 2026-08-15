//! Argon2id key derivation with injectable parameters.

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use super::types::{KdfParams, VaultKey, KEY_LEN, SALT_LEN};
use super::CryptoError;

/// Generates a fresh 16-byte salt for vault creation.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives the 32-byte vault key from the master password using Argon2id.
///
/// Parameters are injectable: tests use fast params (m=8 KiB, t=1, p=1);
/// production uses `KdfParams::default()` (OWASP m=64 MiB, t=3, p=4). The
/// password is borrowed and never copied here; the output key buffer is
/// `Zeroizing`, so it is wiped on drop (CRY-02).
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<VaultKey, CryptoError> {
    params.validate()?;
    let argon2_params =
        Argon2Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;
    Ok(VaultKey::from_zeroizing(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::types::{FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    #[test]
    fn derive_key_returns_32_byte_key() {
        let salt = [7u8; SALT_LEN];
        let key = derive_key(b"correct horse battery staple", &salt, &fast_params()).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"same password", &salt, &fast_params()).unwrap();
        let b = derive_key(b"same password", &salt, &fast_params()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_produces_different_key() {
        let k1 = derive_key(b"pw", &[1u8; SALT_LEN], &fast_params()).unwrap();
        let k2 = derive_key(b"pw", &[2u8; SALT_LEN], &fast_params()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_password_produces_different_key() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_key(b"password-a", &salt, &fast_params()).unwrap();
        let k2 = derive_key(b"password-b", &salt, &fast_params()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn invalid_params_are_rejected() {
        let err = derive_key(b"pw", &[0u8; SALT_LEN], &KdfParams::new(4, 1, 1)).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidParams(_)));
    }

    #[test]
    fn generate_salt_returns_unique_16_bytes() {
        let a = generate_salt();
        let b = generate_salt();
        assert_eq!(a.len(), SALT_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_key_accepts_empty_password() {
        // Master passwords are policy-checked at create time (SES-01); the
        // KDF itself must accept any byte input, including empty.
        let salt = [7u8; SALT_LEN];
        let key = derive_key(b"", &salt, &fast_params()).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }
}
