//! Encrypted SQLCipher storage layer (task 2.1).
//!
//! The vault lives as two files inside a vault directory:
//!
//! - `vault.db`  — SQLCipher-encrypted SQLite database (raw-key mode via
//!   `PRAGMA key = "x'<hex>'"`), DELETE journal mode (STO-06), schema
//!   versioned via `PRAGMA user_version` (STO-04).
//! - `vault.meta` — plaintext JSON with the KDF salt/params and the verifier
//!   (CRY-05). It contains NO secrets and MUST be readable before the key
//!   exists, so it cannot live inside the encrypted DB (design decision).
//!
//! All entry points take an explicit vault directory: tests and the command
//! layer inject temp dirs / user-chosen paths, so integration tests never
//! touch the real `~/.local/share` (default resolution is opt-in via
//! `default_vault_dir`).

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

mod db;
mod meta;
mod schema;

pub use db::Store;
pub use meta::{read_meta, write_meta, VaultMeta};
pub use schema::{CREDENTIALS_DDL, META_FORMAT, SCHEMA_VERSION};

/// Errors produced by the storage layer.
///
/// `Debug`-only on purpose: `rusqlite::Error` is not `PartialEq`, and the
/// vault layer collapses every open/unlock failure into one opaque
/// `unlock_failed` (CRY-04) before anything surfaces to the UI.
#[derive(Debug)]
pub enum StoreError {
    /// `vault.db` does not exist (open attempted on a vault-less directory).
    NotFound,
    /// `vault.db` already exists (create attempted on an existing vault).
    AlreadyExists,
    /// `vault.meta` is missing.
    MetaNotFound,
    /// `vault.meta` exists but is unparsable, malformed, or from an unsupported format.
    MetaCorrupt(String),
    /// The database refuses to open or fails integrity: wrong key, tampered
    /// pages, truncated file, missing schema (STO-05: refuse, never partial).
    Corrupt(String),
    /// Database created by a newer app version (`user_version` too high).
    NewerSchema(u32),
    /// Filesystem error.
    Io(std::io::Error),
    /// SQLite/SQLCipher error.
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "vault database not found"),
            StoreError::AlreadyExists => write!(f, "vault database already exists"),
            StoreError::MetaNotFound => write!(f, "vault metadata file not found"),
            StoreError::MetaCorrupt(msg) => write!(f, "corrupt vault metadata: {msg}"),
            StoreError::Corrupt(msg) => write!(f, "corrupt vault database: {msg}"),
            StoreError::NewerSchema(v) => {
                write!(f, "vault schema version {v} is newer than supported")
            }
            StoreError::Io(e) => write!(f, "i/o error: {e}"),
            StoreError::Sqlite(e) => write!(f, "sqlite error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Absolute path of the encrypted database inside a vault directory.
pub fn db_path(dir: &Path) -> PathBuf {
    dir.join("vault.db")
}

/// Absolute path of the metadata file inside a vault directory.
pub fn meta_path(dir: &Path) -> PathBuf {
    dir.join("vault.meta")
}

/// Whether a vault already exists at `dir` (i.e. its database file is there).
pub fn vault_exists(dir: &Path) -> bool {
    db_path(dir).exists()
}

/// Removes an orphaned `vault.db` that has no `vault.meta` alongside it.
///
/// A keyed database whose header is gone is unrecoverable BY DESIGN: the KDF
/// salt, params, and verifier live only in `vault.meta`, so the key can never
/// be re-derived and the DB can never be opened again. This happens in the
/// crash window between `Store::create` (DB written) and `write_meta`
/// (header written) — or if the header is deleted manually. Removing the
/// orphan lets the next create start clean instead of surfacing a bricked
/// vault that blocks everything (review fix R1).
///
/// Only a MISSING meta file triggers removal: a corrupt-but-present header
/// still describes a real vault and must never be deleted on a read hiccup.
/// Returns `true` when an orphan was removed.
pub fn remove_orphaned_vault(dir: &Path) -> Result<bool, StoreError> {
    let db = db_path(dir);
    if !db.exists() {
        return Ok(false);
    }
    if meta_path(dir).exists() {
        return Ok(false);
    }
    std::fs::remove_file(&db).map_err(StoreError::Io)?;
    Ok(true)
}

/// Restrictive permissions for the vault directory (Unix): `0700` — owner
/// only. The whole vault (encrypted DB + header) lives under it, so the
/// directory must not be traversable by other users. Set EXPLICITLY after
/// creation: we never rely on the ambient umask (review fix R1).
#[cfg(unix)]
pub(crate) fn restrict_dir(dir: &Path) -> Result<(), StoreError> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(StoreError::Io)
}

/// Restrictive permissions for a vault file (Unix): `0600` — owner read/write
/// only. Applied to `vault.db` and the `vault.meta` temp file (rename
/// preserves the inode permissions). Set EXPLICITLY after creation, never
/// relying on the ambient umask (review fix R1).
#[cfg(unix)]
pub(crate) fn restrict_file(path: &Path) -> Result<(), StoreError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(StoreError::Io)
}

/// Resolves the default vault directory.
///
/// 1. `LOCALVAULT_VAULT_DIR` environment override (used by CI and by tests
///    that exercise the default path without touching the real user data
///    dir).
/// 2. Platform data dir (`dirs::data_dir()`) + `localvault` — on Linux
///    `~/.local/share/localvault` (STO-01).
pub fn default_vault_dir() -> Result<PathBuf, StoreError> {
    if let Ok(dir) = std::env::var("LOCALVAULT_VAULT_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let base = dirs::data_dir().ok_or_else(|| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no platform data directory",
        ))
    })?;
    Ok(base.join("localvault"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate the process-global `LOCALVAULT_VAULT_DIR`
    /// env var so they cannot race with each other (parallel test harness).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn db_and_meta_paths_live_inside_the_vault_dir() {
        let dir = Path::new("/tmp/some/vault");
        assert_eq!(db_path(dir), Path::new("/tmp/some/vault/vault.db"));
        assert_eq!(meta_path(dir), Path::new("/tmp/some/vault/vault.meta"));
    }

    #[test]
    fn vault_exists_reflects_database_file_presence() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!vault_exists(tmp.path()));
        std::fs::write(db_path(tmp.path()), b"x").unwrap();
        assert!(vault_exists(tmp.path()));
    }

    #[test]
    fn default_vault_dir_honors_env_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("LOCALVAULT_VAULT_DIR", tmp.path());
        let resolved = default_vault_dir().unwrap();
        assert_eq!(resolved, tmp.path());
        std::env::remove_var("LOCALVAULT_VAULT_DIR");
    }

    #[test]
    fn default_vault_dir_falls_back_to_platform_data_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("LOCALVAULT_VAULT_DIR");
        let resolved = default_vault_dir().unwrap();
        // Linux: ~/.local/share/localvault; the invariant is the leaf segment.
        // The default resolution is pure (creates nothing), but we do NOT
        // assert non-existence: a real app run on the dev machine legitimately
        // creates the directory, which would flake this test (review fix R1).
        assert_eq!(resolved.file_name().unwrap().to_str(), Some("localvault"));
    }

    #[test]
    fn empty_env_override_falls_back_to_default() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("LOCALVAULT_VAULT_DIR", "   ");
        let resolved = default_vault_dir().unwrap();
        assert_eq!(resolved.file_name().unwrap().to_str(), Some("localvault"));
        std::env::remove_var("LOCALVAULT_VAULT_DIR");
    }
}
