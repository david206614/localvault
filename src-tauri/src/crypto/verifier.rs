//! `vault.meta` verifier: constant-time HMAC-SHA256 authentication of the
//! derived key.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::types::VaultKey;

/// Context string HMAC'd with the derived key to produce the verifier.
pub const VERIFIER_CONTEXT: &[u8] = b"localvault-verifier-v1";

/// Verifier output length (HMAC-SHA256 = 32 bytes).
pub const VERIFIER_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Computes the vault verifier: HMAC-SHA256(key, `VERIFIER_CONTEXT`).
///
/// Stored in `vault.meta` at creation and re-derived at unlock. The verifier
/// itself is public (it lives on disk); it only ever authenticates the key.
pub fn compute_verifier(key: &VaultKey) -> [u8; VERIFIER_LEN] {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(VERIFIER_CONTEXT);
    mac.finalize().into_bytes().into()
}

/// Constant-time verification of a stored verifier against a derived key.
pub fn verify_verifier(key: &VaultKey, expected: &[u8; VERIFIER_LEN]) -> bool {
    verify_slice(&compute_verifier(key), expected)
}

/// Constant-time byte-slice comparison (subtle).
///
/// Length mismatch and byte comparison both run without data-dependent
/// branches, so attacker-controlled inputs cannot be probed byte-by-byte.
pub fn verify_slice(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_key;
    use crate::crypto::types::{KdfParams, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T, SALT_LEN};

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    fn key_from(bytes: [u8; 32]) -> VaultKey {
        VaultKey::from_bytes(bytes)
    }

    #[test]
    fn compute_verifier_is_deterministic() {
        let key = key_from([1u8; 32]);
        assert_eq!(compute_verifier(&key), compute_verifier(&key));
    }

    #[test]
    fn verifier_is_32_bytes() {
        let key = key_from([1u8; 32]);
        assert_eq!(compute_verifier(&key).len(), VERIFIER_LEN);
    }

    #[test]
    fn verify_accepts_the_correct_key() {
        let key = key_from([42u8; 32]);
        let verifier = compute_verifier(&key);
        assert!(verify_verifier(&key, &verifier));
    }

    #[test]
    fn verify_rejects_a_different_key() {
        let key = key_from([42u8; 32]);
        let other = key_from([43u8; 32]);
        let verifier = compute_verifier(&key);
        assert!(!verify_verifier(&other, &verifier));
    }

    #[test]
    fn verify_rejects_tampered_verifier() {
        let key = key_from([42u8; 32]);
        let mut verifier = compute_verifier(&key);
        verifier[0] ^= 0x01; // tamper a single byte
        assert!(!verify_verifier(&key, &verifier));
    }

    #[test]
    fn verify_slice_handles_equal_and_unequal_inputs() {
        assert!(verify_slice(b"abc", b"abc"));
        assert!(!verify_slice(b"abc", b"abd"));
        assert!(!verify_slice(b"abc", b"ab"));
        assert!(!verify_slice(b"", b"abc"));
        assert!(verify_slice(b"", b""));
    }

    #[test]
    fn derived_key_and_verifier_integrate() {
        // Full KDF -> verifier -> unlock path with fast params.
        let salt = [3u8; SALT_LEN];
        let params = fast_params();
        let key = derive_key(b"master password", &salt, &params).unwrap();
        let verifier = compute_verifier(&key);
        assert!(verify_verifier(&key, &verifier));
    }
}
