//! Vault unlock (SES-03, CRY-04): read meta, re-derive the key, verifier
//! check, open the store — with a single opaque error for every failure.

use crate::crypto::{derive_key, verify_verifier};
use crate::store::{read_meta, Store};

use super::session::{SessionState, VaultError};

impl crate::vault::VaultSession {
    /// Unlocks the session (SES-03): re-derive from meta, verifier-check
    /// (CRY-04), open the store. Blocking KDF — the command layer MUST run
    /// this on a blocking thread (`spawn_blocking`, task 3.2).
    pub fn unlock(&mut self, password: &[u8]) -> Result<(), VaultError> {
        match self.state {
            // Idempotent: already open.
            SessionState::Unlocked => return Ok(()),
            SessionState::NoVault => return Err(VaultError::NoVault),
            SessionState::Locked => {}
        }
        // CRY-04: EVERY failure collapses to the same opaque error. Wrong
        // password, tampered meta, and corrupt DB are byte-identical to
        // callers — no oracle to probe which layer failed.
        let meta = read_meta(&self.dir).map_err(|_| VaultError::UnlockFailed)?;
        let salt = meta.salt().map_err(|_| VaultError::UnlockFailed)?;
        let key = derive_key(password, &salt, &meta.kdf).map_err(|_| VaultError::UnlockFailed)?;
        let verifier = meta.verifier().map_err(|_| VaultError::UnlockFailed)?;
        if !verify_verifier(&key, &verifier) {
            // `key` drops here → zeroized (CRY-02).
            return Err(VaultError::UnlockFailed);
        }
        let store = Store::open(&self.dir, &key).map_err(|_| VaultError::UnlockFailed)?;
        self.state = SessionState::Unlocked;
        self.store = Some(store);
        self.key = Some(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{KdfParams, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};
    use crate::store::meta_path;
    use crate::vault::{SessionState, VaultError, VaultSession};
    use std::io::{Seek, Write};

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    fn session_dir() -> std::path::PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    fn policy_password() -> &'static [u8] {
        b"CorrectHorseBatteryStaple!1"
    }

    /// Creates + locks a vault at `dir`, returning the locked session.
    fn locked_session(dir: std::path::PathBuf) -> VaultSession {
        let mut session = VaultSession::new(dir);
        session
            .create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        session.lock();
        assert_eq!(session.state(), SessionState::Locked);
        session
    }

    /// Flips one byte in a file at an offset deep enough to not hit the
    /// header region the verifier/meta checks read.
    fn corrupt_file_bytes(path: &std::path::Path, offset: u64, byte: u8) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(std::io::SeekFrom::Start(offset)).unwrap();
        f.write_all(&[byte]).unwrap();
    }

    // ---- happy path ----

    #[test]
    fn unlock_with_correct_password_succeeds() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        session.unlock(policy_password()).unwrap();
        assert_eq!(session.state(), SessionState::Unlocked);
        assert!(session.store().is_ok());
    }

    #[test]
    fn unlock_restores_data_across_relock() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        session.unlock(policy_password()).unwrap();
        session
            .store()
            .unwrap()
            .with_transaction(|conn| -> Result<(), crate::store::StoreError> {
                conn.execute(
                    "INSERT INTO credentials
                     (service_name, username, password, created_at, updated_at)
                     VALUES (?1, ?1, '', '2026-08-16T00:00:00Z',
                             '2026-08-16T00:00:00Z')",
                    ["github"],
                )
                .map_err(crate::store::StoreError::Sqlite)?;
                Ok(())
            })
            .unwrap();
        session.lock();
        session.unlock(policy_password()).unwrap();
        let count: i64 = session
            .store()
            .unwrap()
            .with_transaction(|conn| {
                conn.query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
                    .map_err(crate::store::StoreError::Sqlite)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    // ---- failure paths: all opaque (CRY-04) ----

    #[test]
    fn unlock_with_wrong_password_fails_opaque() {
        let dir = session_dir();
        let mut session = locked_session(dir);
        let err = session.unlock(b"WrongHorseBatteryStaple!2").unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
        assert_eq!(session.state(), SessionState::Locked);
    }

    #[test]
    fn unlock_with_tampered_meta_fails_opaque() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        // Corrupt the format byte → read_meta fails.
        corrupt_file_bytes(&meta_path(&dir), 0, 0xFF);
        let err = session.unlock(policy_password()).unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
        assert_eq!(session.state(), SessionState::Locked);
    }

    #[test]
    fn unlock_with_tampered_salt_fails_opaque() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        // Tamper the ACTUAL salt_hex value: parse the header JSON, flip the
        // first hex digit of the salt, write it back. (The old offset-8
        // write hit the "format" field name in the pretty JSON instead —
        // review fix R1.) The header still validates (valid hex, right
        // length), so this genuinely exercises "different salt → different
        // derived key → verifier rejects" (CRY-04).
        let path = meta_path(&dir);
        let mut meta: crate::store::VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // Flip one byte of the decoded salt, then re-encode: guaranteed to
        // change the value regardless of what the first hex digit was.
        let mut salt = meta.salt().unwrap();
        salt[0] ^= 0xFF;
        meta.salt_hex = hex::encode(salt);
        std::fs::write(&path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        let err = session.unlock(policy_password()).unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
        assert_eq!(session.state(), SessionState::Locked);
    }

    #[test]
    fn unlock_with_corrupt_database_fails_opaque() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        // Flip a byte mid-file → cipher_integrity_check / HMAC failure.
        corrupt_file_bytes(&crate::store::db_path(&dir), 4096 * 2 + 200, 0x00);
        let err = session.unlock(policy_password()).unwrap_err();
        assert!(matches!(err, VaultError::UnlockFailed));
    }

    #[test]
    fn unlock_failures_are_byte_identical_no_oracle() {
        // Wrong password, tampered meta, and corrupt DB must surface the
        // EXACT same error — an attacker probing the API can learn nothing
        // about which layer failed (CRY-04).
        let wrong_pw = {
            let dir = session_dir();
            let mut s = locked_session(dir);
            s.unlock(b"WrongHorseBatteryStaple!2").unwrap_err()
        };
        let tampered_meta = {
            let dir = session_dir();
            let mut s = locked_session(dir.clone());
            corrupt_file_bytes(&meta_path(&dir), 0, 0xFF);
            s.unlock(policy_password()).unwrap_err()
        };
        let corrupt_db = {
            let dir = session_dir();
            let mut s = locked_session(dir.clone());
            corrupt_file_bytes(&crate::store::db_path(&dir), 4096 * 2 + 200, 0x00);
            s.unlock(policy_password()).unwrap_err()
        };
        assert_eq!(
            format!("{wrong_pw:?}"),
            format!("{tampered_meta:?}"),
            "wrong-password vs tampered-meta must be byte-identical"
        );
        assert_eq!(
            format!("{wrong_pw:?}"),
            format!("{corrupt_db:?}"),
            "wrong-password vs corrupt-db must be byte-identical"
        );
    }

    // ---- state machine ----

    #[test]
    fn unlock_in_no_vault_state_errors() {
        let mut session = VaultSession::new(session_dir());
        assert_eq!(session.state(), SessionState::NoVault);
        let err = session.unlock(policy_password()).unwrap_err();
        assert!(matches!(err, VaultError::NoVault));
    }

    #[test]
    fn unlock_when_already_unlocked_is_noop() {
        let dir = session_dir();
        let mut session = locked_session(dir.clone());
        session.unlock(policy_password()).unwrap();
        // Idempotent: unlocking again keeps Unlocked and the same store.
        session.unlock(policy_password()).unwrap();
        assert_eq!(session.state(), SessionState::Unlocked);
        assert!(session.store().is_ok());
    }
}
