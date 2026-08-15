//! Cryptographic primitives: Argon2id KDF, vault key type, and the
//! `vault.meta` verifier.
//!
//! Verifier + SQLCipher per-page HMAC role split (design): the `vault.meta`
//! verifier authenticates the *key* (wrong password, tampered salt/params);
//! SQLCipher's per-page HMAC guards the *body* (task 2.1). Both failures
//! surface the same opaque `unlock_failed` error at the command layer
//! (CRY-04).

mod kdf;
mod types;
mod verifier;

pub use kdf::{derive_key, generate_salt};
pub use types::{
    KdfParams, VaultKey, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T, KEY_LEN, OWASP_ARGON2_M_KIB,
    OWASP_ARGON2_P, OWASP_ARGON2_T, SALT_LEN,
};
pub use verifier::{
    compute_verifier, verify_slice, verify_verifier, VERIFIER_CONTEXT, VERIFIER_LEN,
};

/// Errors produced by the crypto layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Argon2 parameters outside the valid range.
    InvalidParams(String),
    /// Argon2 derivation failed.
    DerivationFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidParams(msg) => write!(f, "invalid KDF params: {msg}"),
            CryptoError::DerivationFailed(msg) => write!(f, "key derivation failed: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use kdf::{derive_key, generate_salt};
    use types::{KdfParams, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T, SALT_LEN};

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    #[test]
    fn unlock_roundtrip_with_correct_password() {
        let salt = generate_salt();
        let params = fast_params();
        let key = derive_key(b"correct master password", &salt, &params).unwrap();
        let verifier = compute_verifier(&key);
        let rederived = derive_key(b"correct master password", &salt, &params).unwrap();
        assert!(verify_verifier(&rederived, &verifier));
    }

    #[test]
    fn wrong_password_fails_the_verifier() {
        let salt = generate_salt();
        let params = fast_params();
        let key = derive_key(b"correct master password", &salt, &params).unwrap();
        let verifier = compute_verifier(&key);
        let wrong = derive_key(b"wrong master password", &salt, &params).unwrap();
        assert!(!verify_verifier(&wrong, &verifier));
    }

    #[test]
    fn tampered_salt_fails_the_verifier() {
        let params = fast_params();
        let key = derive_key(b"master password", &[1u8; SALT_LEN], &params).unwrap();
        let verifier = compute_verifier(&key);
        let tampered = derive_key(b"master password", &[2u8; SALT_LEN], &params).unwrap();
        assert!(!verify_verifier(&tampered, &verifier));
    }
}
