//! SQLCipher-backed encrypted database (STO-01..STO-07).
//!
//! - Raw-key mode: `PRAGMA key = "x'<hex>'"` consumes the derived 32-byte key
//!   directly (Argon2id pre-derivation bypasses SQLCipher's PBKDF2).
//! - Cipher config: `cipher_hmac_algorithm = HMAC_SHA512`, `secure_delete =
//!   ON` (design cipher settings).
//! - Journal mode: DELETE (never WAL) so no plaintext sidecar files exist
//!   (STO-06); the whole vault is one encrypted file.
//! - Schema versioning: `PRAGMA user_version` (STO-04); newer schemas are
//!   refused.
//! - Corruption detection: wrong key / tampered pages / truncation all refuse
//!   to open (STO-05). Key authentication itself is the vault layer's job
//!   (verifier); here we only enforce that the file decrypts coherently.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::crypto::VaultKey;

use super::{db_path, schema, StoreError};

/// Open encrypted connection factory: raw-key pragma, cipher settings, DELETE
/// journal, and a read probe that forces SQLCipher to decrypt page 1.
///
/// The probe is the cheap wrong-key / not-a-database detector: with a wrong
/// key (or a plain/non-SQLCipher file) the first read fails with
/// `file is not a database`, mapped to `StoreError::Corrupt` (STO-05). The
/// probe runs BEFORE `journal_mode` so key failures surface as corruption
/// rather than as a misleading journal-mode error.
fn open_encrypted(path: &Path, key: &VaultKey) -> Result<Connection, StoreError> {
    let conn = Connection::open(path).map_err(StoreError::Sqlite)?;
    // Raw-key mode: SQLCipher consumes the derived 32-byte key directly,
    // bypassing its PBKDF2 (the Argon2id derivation already happened above).
    let raw_key = format!("x'{}'", hex::encode(key.as_bytes()));
    conn.pragma_update(None, "key", raw_key)
        .map_err(StoreError::Sqlite)?;
    // Cipher config (design): SHA-512 per-page HMAC + secure delete.
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")
        .map_err(StoreError::Sqlite)?;
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(StoreError::Sqlite)?;
    // Probe: forces decryption of page 1; wrong key / non-SQLCipher file
    // fails here with "file is not a database".
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|e| StoreError::Corrupt(format!("database refuses to open: {e}")))?;
    // STO-06: DELETE journal (default), never WAL — no plaintext sidecars.
    conn.pragma_update(None, "journal_mode", "DELETE")
        .map_err(StoreError::Sqlite)?;
    Ok(conn)
}

/// Runs `PRAGMA cipher_integrity_check` over the connection: SQLCipher 4.x
/// emits one row PER FAILING page (HMAC mismatch, read error, invalid size)
/// and zero rows on success — so any row means corrupt (STO-05).
fn integrity_faults(conn: &Connection) -> Result<Vec<String>, StoreError> {
    let mut stmt = conn
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(StoreError::Sqlite)?;
    let mut rows = stmt.query([]).map_err(StoreError::Sqlite)?;
    let mut faults = Vec::new();
    while let Some(row) = rows.next().map_err(StoreError::Sqlite)? {
        faults.push(row.get(0).map_err(StoreError::Sqlite)?);
    }
    Ok(faults)
}

/// The encrypted vault database handle.
///
/// `Connection` is `Send` (it may move into a `Mutex`-held session); it is
/// dropped on `VaultSession::lock`, releasing the SQLCipher key material.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    dir: PathBuf,
}

impl Store {
    /// Creates a new encrypted vault database at `dir` (directory created if
    /// absent) with the credentials schema and `user_version = 1`. Refuses if
    /// a database already exists.
    pub fn create(dir: &Path, key: &VaultKey) -> Result<Store, StoreError> {
        let path = db_path(dir);
        if path.exists() {
            return Err(StoreError::AlreadyExists);
        }
        std::fs::create_dir_all(dir).map_err(StoreError::Io)?;
        let conn = open_encrypted(&path, key)?;
        // Schema init is transactional (STO-07): DDL + user_version commit
        // atomically, so a crash mid-init never leaves a version-0 database
        // that would look like an empty-but-valid vault.
        // `new_unchecked` keeps the API `&self`-friendly (unlike
        // `transaction_with_behavior`, which needs `&mut`); nesting is caught
        // at runtime by SQLite.
        let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)
            .map_err(StoreError::Sqlite)?;
        tx.execute_batch(schema::CREDENTIALS_DDL)
            .map_err(StoreError::Sqlite)?;
        tx.pragma_update(None, "user_version", schema::SCHEMA_VERSION as i64)
            .map_err(StoreError::Sqlite)?;
        tx.commit().map_err(StoreError::Sqlite)?;
        Ok(Store {
            conn,
            dir: dir.to_path_buf(),
        })
    }

    /// Opens an existing encrypted vault at `dir`.
    ///
    /// Refuses (STO-05) on: missing database, wrong key / not a SQLCipher
    /// file, schema newer than supported (STO-04), zero schema version
    /// (half-created vault), or any page failing `cipher_integrity_check`
    /// (tampered/truncated file).
    pub fn open(dir: &Path, key: &VaultKey) -> Result<Store, StoreError> {
        let path = db_path(dir);
        if !path.exists() {
            return Err(StoreError::NotFound);
        }
        let conn = open_encrypted(&path, key)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(StoreError::Sqlite)?;
        if version as u32 > schema::SCHEMA_VERSION {
            return Err(StoreError::NewerSchema(version as u32));
        }
        if version == 0 {
            return Err(StoreError::Corrupt(
                "database has no schema (user_version 0): half-created vault".into(),
            ));
        }
        // Full-body integrity: every page's HMAC (STO-05). Tampered pages and
        // truncated tails are detected here, not lazily on first read.
        let faults = integrity_faults(&conn)?;
        if let Some(first) = faults.first() {
            let mut msg = first.clone();
            for fault in faults.iter().skip(1) {
                msg.push_str("; ");
                msg.push_str(fault);
            }
            return Err(StoreError::Corrupt(format!(
                "integrity check failed: {msg}"
            )));
        }
        Ok(Store {
            conn,
            dir: dir.to_path_buf(),
        })
    }

    /// Full-database integrity verification (`cipher_integrity_check`).
    pub fn verify_integrity(&self) -> Result<(), StoreError> {
        let faults = integrity_faults(&self.conn)?;
        match faults.as_slice() {
            [] => Ok(()),
            [first, rest @ ..] => {
                let mut msg = first.clone();
                for fault in rest {
                    msg.push_str("; ");
                    msg.push_str(fault);
                }
                Err(StoreError::Corrupt(format!(
                    "integrity check failed: {msg}"
                )))
            }
        }
    }

    /// Runs `f` inside an `IMMEDIATE` transaction; rolls back on any error
    /// (STO-07) and commits only when `f` returns `Ok`.
    pub fn with_transaction<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .map_err(StoreError::Sqlite)?;
        let result = f(&tx);
        match result {
            Ok(value) => {
                tx.commit().map_err(StoreError::Sqlite)?;
                Ok(value)
            }
            // Err path: the tx is dropped without commit → rollback (STO-07).
            Err(e) => Err(e),
        }
    }

    /// Raw connection access for the credential layer (task 3.1).
    // Currently only reached from tests (and the vault session's persistence
    // test); the credential CRUD layer consumes it next batch. The allowance
    // disappears once 3.1 lands.
    #[allow(dead_code)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The vault directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Absolute path of the encrypted database file.
    pub fn db_path(&self) -> PathBuf {
        db_path(&self.dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{VaultKey, KEY_LEN};

    /// Arbitrary deterministic key for store tests: the store does not derive
    /// keys (that is the vault layer's job), so tests use fixed bytes instead
    /// of burning KDF time.
    fn test_key() -> VaultKey {
        VaultKey::from_bytes([7u8; KEY_LEN])
    }

    fn other_key() -> VaultKey {
        VaultKey::from_bytes([8u8; KEY_LEN])
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn insert_row(store: &Store, service: &str) {
        store
            .with_transaction(|conn| {
                conn.execute(
                    "INSERT INTO credentials
                     (service_name, username, password, url, category, notes,
                      created_at, updated_at)
                     VALUES (?1, ?1, '', '', '', '', '2026-08-16T00:00:00Z',
                             '2026-08-16T00:00:00Z')",
                    [service],
                )
                .map_err(StoreError::Sqlite)?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn create_makes_encrypted_db_with_schema_v1() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        assert_eq!(store.dir(), dir.path());
        assert!(store.db_path().exists());

        let version: i64 = store
            .connection()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION as i64);

        let tables: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'credentials'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
    }

    #[test]
    fn create_refuses_existing_database() {
        let dir = temp_dir();
        Store::create(dir.path(), &test_key()).unwrap();
        let err = Store::create(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyExists));
    }

    #[test]
    fn open_with_correct_key_roundtrips_persisted_rows() {
        let dir = temp_dir();
        {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            insert_row(&store, "github");
        } // store dropped → connection closed
        let store = Store::open(dir.path(), &test_key()).unwrap();
        let count: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn open_with_wrong_key_is_refused() {
        let dir = temp_dir();
        Store::create(dir.path(), &test_key()).unwrap();
        let err = Store::open(dir.path(), &other_key()).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[test]
    fn open_missing_database_errors() {
        let dir = temp_dir();
        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn open_refuses_plaintext_non_sqlcipher_file() {
        let dir = temp_dir();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(db_path(dir.path()), b"this is not an encrypted database").unwrap();
        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[test]
    fn open_refuses_newer_schema_version() {
        let dir = temp_dir();
        {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            store
                .connection()
                .pragma_update(None, "user_version", schema::SCHEMA_VERSION as i64 + 1)
                .unwrap();
        }
        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::NewerSchema(_)));
    }

    #[test]
    fn open_refuses_zero_schema_version() {
        // A database without schema (version 0) is a half-created vault:
        // refuse rather than report an empty-but-uninitialized store.
        let dir = temp_dir();
        let conn = Connection::open(db_path(dir.path())).unwrap();
        conn.pragma_update(
            None,
            "key",
            format!("x'{}'", hex::encode(test_key().as_bytes())),
        )
        .unwrap();
        // Force the file to exist and initialize with the key.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        drop(conn);
        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[test]
    fn tampered_page_is_refused_on_open() {
        let dir = temp_dir();
        {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            insert_row(&store, "github");
            insert_row(&store, "gitlab");
        }
        // Flip one byte inside page 2's payload area (page 1 = SQLite header
        // must stay intact so the file still opens with the right key; any
        // later page byte flip breaks that page's HMAC).
        let path = db_path(dir.path());
        let mut bytes = std::fs::read(&path).unwrap();
        let page_size = 4096usize; // SQLCipher default
        let target = page_size * 2 + 200;
        assert!(
            target < bytes.len(),
            "database too small to tamper a data page"
        );
        bytes[target] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();

        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[test]
    fn truncated_file_is_refused_on_open() {
        let dir = temp_dir();
        {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            insert_row(&store, "github");
        }
        let path = db_path(dir.path());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 2 * 4096, "database too small to truncate");
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        let err = Store::open(dir.path(), &test_key()).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[test]
    fn verify_integrity_ok_on_fresh_database() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        insert_row(&store, "github");
        store.verify_integrity().unwrap();
        // The tampered-page case is covered by `tampered_page_is_refused_on_open`
        // (open runs the same integrity detector before returning a store).
    }

    #[test]
    fn transaction_commits_on_success() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        insert_row(&store, "github");
        let count: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn transaction_rolls_back_on_failure() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        let err = store
            .with_transaction(|conn| -> Result<(), StoreError> {
                conn.execute(
                    "INSERT INTO credentials
                     (service_name, username, password, url, category, notes,
                      created_at, updated_at)
                     VALUES ('rolled-back', 'u', '', '', '', '', 't', 't')",
                    [],
                )
                .map_err(StoreError::Sqlite)?;
                // Simulated mid-commit failure: any error must roll back the
                // whole transaction (STO-07).
                Err(StoreError::Corrupt("simulated failure".into()))
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)));
        let count: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "failed transaction must not leave partial rows");
    }

    #[test]
    fn journal_mode_is_delete_with_no_sidecar_files() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        insert_row(&store, "github");
        let mode: String = store
            .connection()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
        drop(store);

        // STO-06: no WAL/shm/plain journal sidecars — only vault.db exists.
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["vault.db".to_string()]);
        assert!(entries
            .iter()
            .all(|n| !n.ends_with("-journal") && !n.ends_with("-wal") && !n.ends_with("-shm")));
    }

    #[test]
    fn no_plaintext_credentials_at_rest() {
        // STO-01/STO-05 scenario: credential values must never appear in
        // plaintext inside the vault file.
        let dir = temp_dir();
        let secrets = [
            "SuperSecretPassword123!",
            "octocat@example.com",
            "github.com/octocat",
        ];
        {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            store
                .with_transaction(|conn| {
                    conn.execute(
                        "INSERT INTO credentials
                         (service_name, username, password, url, category, notes,
                          created_at, updated_at)
                         VALUES ('github', 'octocat', ?1, ?2, 'dev', 'notes here',
                                 '2026-08-16T00:00:00Z', '2026-08-16T00:00:00Z')",
                        [secrets[0], secrets[1]],
                    )
                    .map_err(StoreError::Sqlite)?;
                    Ok(())
                })
                .unwrap();
        }
        let raw = std::fs::read(db_path(dir.path())).unwrap();
        for secret in secrets {
            assert!(
                !raw.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "credential value leaked in plaintext: {secret}"
            );
        }
    }

    #[test]
    fn secure_delete_and_hmac_settings_are_active() {
        let dir = temp_dir();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        let secure_delete: i64 = store
            .connection()
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(secure_delete, 1);
        // HMAC is what makes the tamper tests fail; prove the setting sticks
        // by reading it back (SQLCipher 4 returns the algorithm label).
        let hmac: String = store
            .connection()
            .query_row("PRAGMA cipher_hmac_algorithm", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hmac, "HMAC_SHA512");
    }

    #[test]
    fn rederived_key_from_meta_unlocks_the_same_database() {
        // Full create → meta → re-derive → open loop with fast params, the
        // same path the vault session (2.2) will take.
        use crate::crypto::{
            compute_verifier, derive_key, generate_salt, verify_verifier, KdfParams,
            FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T,
        };
        use crate::store::{read_meta, write_meta, VaultMeta};

        let dir = temp_dir();
        let params = KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P);
        let salt = generate_salt();
        let key = derive_key(b"master password", &salt, &params).unwrap();
        {
            let store = Store::create(dir.path(), &key).unwrap();
            insert_row(&store, "github");
            let verifier = compute_verifier(&key);
            write_meta(
                dir.path(),
                &VaultMeta::new(params, salt, verifier, schema::SCHEMA_VERSION),
            )
            .unwrap();
        }
        // Simulate unlock: read meta, re-derive, open.
        let meta = read_meta(dir.path()).unwrap();
        let salt = meta.salt().unwrap();
        let key = derive_key(b"master password", &salt, &meta.kdf).unwrap();
        assert!(verify_verifier(&key, &meta.verifier().unwrap()));
        let store = Store::open(dir.path(), &key).unwrap();
        let count: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
