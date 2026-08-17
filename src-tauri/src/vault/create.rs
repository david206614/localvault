//! Vault creation (SES-01..SES-03): policy check, password-twice, key
//! derivation, meta + DB write, and the atomicity cleanup on failure.

use crate::crypto::{compute_verifier, derive_key, generate_salt, KdfParams};
use crate::store::{self, db_path, write_meta, Store, VaultMeta, SCHEMA_VERSION};

use super::session::{PolicyError, SessionState, VaultError};

/// Master-password policy (SES-01): ≥12 chars and one of each class.
pub(crate) const POLICY_MIN_LEN: usize = 12;

impl crate::vault::VaultSession {
    /// Creates a vault at the session directory (SES-01..SES-03).
    pub fn create(
        &mut self,
        password: &[u8],
        confirm: &[u8],
        params: &KdfParams,
    ) -> Result<(), VaultError> {
        // Guard: never create over an existing vault (SES-03). The disk check
        // catches stale states; the state check catches a session that
        // already saw a vault.
        if self.state != SessionState::NoVault || store::vault_exists(&self.dir) {
            return Err(VaultError::AlreadyExists);
        }
        // SES-01: policy first, so a mismatch is only reported once the
        // password itself is acceptable.
        validate_password_policy(password).map_err(VaultError::Policy)?;
        // SES-02: password-twice.
        if password != confirm {
            return Err(VaultError::Mismatch);
        }
        let salt = generate_salt();
        let key = derive_key(password, &salt, params).map_err(VaultError::Crypto)?;
        let verifier = compute_verifier(&key);
        let meta = VaultMeta::new(*params, salt, verifier, SCHEMA_VERSION);
        let store = match Store::create(&self.dir, &key) {
            Ok(s) => s,
            Err(e) => {
                // Best-effort rollback so a retry isn't blocked by a
                // half-created file.
                let _ = std::fs::remove_file(db_path(&self.dir));
                return Err(VaultError::Store(e));
            }
        };
        // Meta write failure must not leave a keyed DB with no header — the
        // vault would be unrecoverable (no salt/verifier on disk). Remove the
        // DB and fail cleanly.
        if let Err(e) = write_meta(&self.dir, &meta) {
            let _ = std::fs::remove_file(db_path(&self.dir));
            return Err(VaultError::Store(e));
        }
        self.state = SessionState::Unlocked;
        self.store = Some(store);
        self.key = Some(key);
        Ok(())
    }
}

/// Validates `password` against the master-password policy (SES-01). The
/// error NAMES the first failing rule.
///
/// Class checks are ASCII-based: a non-ASCII letter counts as a "symbol",
/// which is fine for a policy meant to force class variety, not to measure
/// entropy.
pub(crate) fn validate_password_policy(password: &[u8]) -> Result<(), PolicyError> {
    if password.len() < POLICY_MIN_LEN {
        return Err(PolicyError::TooShort {
            min: POLICY_MIN_LEN,
            actual: password.len(),
        });
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for &b in password {
        has_upper |= b.is_ascii_uppercase();
        has_lower |= b.is_ascii_lowercase();
        has_digit |= b.is_ascii_digit();
        has_symbol |= !b.is_ascii_alphanumeric() && !b.is_ascii_whitespace();
    }
    if !has_upper {
        return Err(PolicyError::MissingUppercase);
    }
    if !has_lower {
        return Err(PolicyError::MissingLowercase);
    }
    if !has_digit {
        return Err(PolicyError::MissingDigit);
    }
    if !has_symbol {
        return Err(PolicyError::MissingSymbol);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};
    use crate::store::meta_path;

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    fn session_dir() -> std::path::PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    fn policy_password() -> &'static [u8] {
        b"CorrectHorseBatteryStaple!1"
    }

    // ---- policy (SES-01) ----

    #[test]
    fn policy_accepts_valid_password() {
        assert!(validate_password_policy(policy_password()).is_ok());
    }

    #[test]
    fn policy_rejects_short_password_naming_rule() {
        let err = validate_password_policy(b"Ab1!").unwrap_err();
        assert_eq!(
            err,
            PolicyError::TooShort {
                min: POLICY_MIN_LEN,
                actual: 4
            }
        );
    }

    #[test]
    fn policy_rejects_missing_uppercase() {
        assert_eq!(
            validate_password_policy(b"abcdefghijkl!1").unwrap_err(),
            PolicyError::MissingUppercase
        );
    }

    #[test]
    fn policy_rejects_missing_lowercase() {
        assert_eq!(
            validate_password_policy(b"ABCDEFGHIJKL!1").unwrap_err(),
            PolicyError::MissingLowercase
        );
    }

    #[test]
    fn policy_rejects_missing_digit() {
        assert_eq!(
            validate_password_policy(b"Abcdefghijkl!").unwrap_err(),
            PolicyError::MissingDigit
        );
    }

    #[test]
    fn policy_rejects_missing_symbol() {
        assert_eq!(
            validate_password_policy(b"Abcdefghijkl1").unwrap_err(),
            PolicyError::MissingSymbol
        );
    }

    // ---- create (SES-01..SES-03) ----

    #[test]
    fn create_creates_vault_files_and_unlocks() {
        let mut session = crate::vault::VaultSession::new(session_dir());
        session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        assert_eq!(session.state(), crate::vault::SessionState::Unlocked);
        assert!(session.store().is_ok());
        let dir = session.dir().to_path_buf();
        assert!(db_path(&dir).exists());
        assert!(meta_path(&dir).exists());
    }

    #[test]
    fn create_refused_when_vault_exists() {
        let dir = session_dir();
        let mut session = crate::vault::VaultSession::new(dir.clone());
        session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        let mut second = crate::vault::VaultSession::new(dir);
        let err = second
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists));
    }

    #[test]
    fn create_refused_from_locked_state() {
        let dir = session_dir();
        let mut session = crate::vault::VaultSession::new(dir.clone());
        session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        session.lock();
        assert_eq!(session.state(), crate::vault::SessionState::Locked);
        let err = session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists));
    }

    #[test]
    fn create_rejects_confirmation_mismatch_and_writes_nothing() {
        let dir = session_dir();
        let mut session = crate::vault::VaultSession::new(dir.clone());
        let err = session
            .create(
                policy_password(),
                b"DifferentBatteryStaple!2",
                &fast_params(),
            )
            .unwrap_err();
        assert!(matches!(err, VaultError::Mismatch));
        assert_eq!(session.state(), crate::vault::SessionState::NoVault);
        assert!(!db_path(&dir).exists());
        assert!(!meta_path(&dir).exists());
    }

    #[test]
    fn create_rejects_weak_password_and_writes_nothing() {
        let dir = session_dir();
        let mut session = crate::vault::VaultSession::new(dir.clone());
        let err = session
            .create(b"Ab1!", b"Ab1!", &fast_params())
            .unwrap_err();
        assert!(matches!(
            err,
            VaultError::Policy(PolicyError::TooShort { .. })
        ));
        assert_eq!(session.state(), crate::vault::SessionState::NoVault);
        assert!(!db_path(&dir).exists());
        assert!(!meta_path(&dir).exists());
    }

    #[test]
    fn created_vault_reopens_with_same_password_after_relock() {
        let dir = session_dir();
        let mut session = crate::vault::VaultSession::new(dir.clone());
        session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        session.lock();
        session.unlock(policy_password()).unwrap();
        assert_eq!(session.state(), crate::vault::SessionState::Unlocked);
        assert!(session.store().is_ok());
    }
}
