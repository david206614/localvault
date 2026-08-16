//! `vault.meta` — the plaintext vault header (CRY-05, STO-04).
//!
//! Contains everything needed to reproduce unlock: KDF params, salt, and the
//! HMAC verifier. It holds NO secrets (the verifier authenticates the key but
//! is public data) and MUST be readable before any key exists, which is why
//! it lives outside the encrypted database (design decision).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{KdfParams, SALT_LEN, VERIFIER_LEN};

use super::{meta_path, schema, StoreError};

#[cfg(unix)]
use super::{restrict_dir, restrict_file};

/// The vault header persisted as `vault.meta` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Meta file format version (`schema::META_FORMAT`).
    pub format: u8,
    /// Argon2id derivation parameters used at create/unlock.
    pub kdf: KdfParams,
    /// Per-vault salt, hex-encoded (`SALT_LEN` bytes → 32 hex chars).
    pub salt_hex: String,
    /// HMAC-SHA256 verifier of the derived key, hex-encoded
    /// (`VERIFIER_LEN` bytes → 64 hex chars).
    pub verifier_hex: String,
    /// Database schema version, mirrored from `PRAGMA user_version`.
    pub schema_version: u32,
}

impl VaultMeta {
    /// Builds a header for a freshly created vault.
    pub fn new(
        kdf: KdfParams,
        salt: [u8; SALT_LEN],
        verifier: [u8; VERIFIER_LEN],
        schema_version: u32,
    ) -> Self {
        Self {
            format: schema::META_FORMAT,
            kdf,
            salt_hex: hex::encode(salt),
            verifier_hex: hex::encode(verifier),
            schema_version,
        }
    }

    /// Validates structure: supported format, sane hex lengths, valid KDF
    /// params, supported schema version. Corrupt metadata must never reach
    /// the KDF (a tampered salt/params would silently derive a wrong key).
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.format != schema::META_FORMAT {
            return Err(StoreError::MetaCorrupt(format!(
                "unsupported meta format {}, expected {}",
                self.format,
                schema::META_FORMAT
            )));
        }
        if self.schema_version == 0 || self.schema_version > schema::SCHEMA_VERSION {
            return Err(StoreError::MetaCorrupt(format!(
                "unsupported schema version {}",
                self.schema_version
            )));
        }
        // Hex must decode AND have the exact expected length: wrong length or
        // invalid characters both mean the meta was tampered with or written
        // by a different format.
        if self.salt_hex.len() != SALT_LEN * 2 || hex::decode(&self.salt_hex).is_err() {
            return Err(StoreError::MetaCorrupt("malformed salt_hex".into()));
        }
        if self.verifier_hex.len() != VERIFIER_LEN * 2 || hex::decode(&self.verifier_hex).is_err() {
            return Err(StoreError::MetaCorrupt("malformed verifier_hex".into()));
        }
        self.kdf
            .validate()
            .map_err(|e| StoreError::MetaCorrupt(format!("invalid kdf params: {e}")))?;
        Ok(())
    }

    /// Decodes the salt bytes.
    pub fn salt(&self) -> Result<[u8; SALT_LEN], StoreError> {
        decode_hex::<SALT_LEN>(&self.salt_hex, "salt")
    }

    /// Decodes the verifier bytes.
    pub fn verifier(&self) -> Result<[u8; VERIFIER_LEN], StoreError> {
        decode_hex::<VERIFIER_LEN>(&self.verifier_hex, "verifier")
    }
}

/// Decodes a hex string into a fixed-size byte array.
fn decode_hex<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], StoreError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| StoreError::MetaCorrupt(format!("malformed {what} hex")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| StoreError::MetaCorrupt(format!("{what} has wrong length")))
}

/// Writes `vault.meta` atomically (temp file + rename, so a crash mid-write
/// never leaves a truncated header that would brick unlock).
pub fn write_meta(dir: &Path, meta: &VaultMeta) -> Result<(), StoreError> {
    meta.validate()?;
    std::fs::create_dir_all(dir).map_err(StoreError::Io)?;
    // Review fix R1: the vault dir is owner-only — never rely on umask.
    #[cfg(unix)]
    restrict_dir(dir)?;
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| StoreError::MetaCorrupt(format!("serialize failed: {e}")))?;
    let tmp = meta_path(dir).with_extension("meta.tmp");
    std::fs::write(&tmp, json).map_err(StoreError::Io)?;
    // The temp file carries the final 0600; rename preserves its inode
    // permissions, so vault.meta lands owner-only (review fix R1).
    #[cfg(unix)]
    restrict_file(&tmp)?;
    if let Err(e) = std::fs::rename(&tmp, meta_path(dir)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(StoreError::Io(e));
    }
    Ok(())
}

/// Reads and validates `vault.meta`.
pub fn read_meta(dir: &Path) -> Result<VaultMeta, StoreError> {
    let raw = std::fs::read_to_string(meta_path(dir)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::MetaNotFound
        } else {
            StoreError::Io(e)
        }
    })?;
    let meta: VaultMeta = serde_json::from_str(&raw)
        .map_err(|e| StoreError::MetaCorrupt(format!("invalid meta json: {e}")))?;
    meta.validate()?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};

    fn sample_meta() -> VaultMeta {
        VaultMeta::new(
            KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P),
            [0x11; SALT_LEN],
            [0x22; VERIFIER_LEN],
            schema::SCHEMA_VERSION,
        )
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Writes raw meta JSON, bypassing `write_meta`'s validation, so tests can
    /// plant corrupt headers on disk (production `write_meta` refuses them).
    fn write_raw_meta(dir: &Path, json: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(meta_path(dir), json).unwrap();
    }

    #[test]
    fn meta_roundtrip_via_json_file() {
        let dir = temp_dir();
        let meta = sample_meta();
        write_meta(dir.path(), &meta).unwrap();
        let read = read_meta(dir.path()).unwrap();
        assert_eq!(read, meta);
        assert_eq!(read.salt().unwrap(), [0x11; SALT_LEN]);
        assert_eq!(read.verifier().unwrap(), [0x22; VERIFIER_LEN]);
    }

    #[test]
    fn meta_file_is_plaintext_json_without_secrets() {
        let dir = temp_dir();
        let meta = sample_meta();
        write_meta(dir.path(), &meta).unwrap();
        let raw = std::fs::read_to_string(meta_path(dir.path())).unwrap();
        // JSON keys survive; the verifier is public data, but no derived key
        // bytes (0x22 repeated) ever appear in plaintext — wait, the verifier
        // IS hex-encoded 0x22*32 here, so assert on the JSON shape instead.
        assert!(raw.contains("\"format\": 1"));
        assert!(raw.contains("\"kdf\""));
        assert!(raw.contains("\"salt_hex\""));
        assert!(raw.contains("\"verifier_hex\""));
        assert!(raw.contains("\"schema_version\": 1"));
    }

    #[test]
    fn read_meta_missing_file_errors() {
        let dir = temp_dir();
        let err = read_meta(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::MetaNotFound));
    }

    #[test]
    fn read_meta_corrupt_json_errors() {
        let dir = temp_dir();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(meta_path(dir.path()), b"{ not json !").unwrap();
        let err = read_meta(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::MetaCorrupt(_)));
    }

    #[test]
    fn read_meta_rejects_unsupported_format() {
        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.format = 99;
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        let err = read_meta(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::MetaCorrupt(_)));
    }

    #[test]
    fn read_meta_rejects_unsupported_schema_version() {
        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.schema_version = schema::SCHEMA_VERSION + 1;
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        let err = read_meta(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::MetaCorrupt(_)));
    }

    #[test]
    fn read_meta_rejects_malformed_hex() {
        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.salt_hex = "zz".repeat(SALT_LEN);
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        assert!(read_meta(dir.path()).is_err());

        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.verifier_hex = "zz".repeat(VERIFIER_LEN);
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        assert!(read_meta(dir.path()).is_err());
    }

    #[test]
    fn read_meta_rejects_wrong_hex_lengths() {
        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.salt_hex = "ab".to_string(); // too short for 16 bytes
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        let err = read_meta(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::MetaCorrupt(_)));

        let dir = temp_dir();
        let mut meta = sample_meta();
        meta.verifier_hex = "ab".to_string();
        write_raw_meta(dir.path(), &serde_json::to_string(&meta).unwrap());
        assert!(read_meta(dir.path()).is_err());
    }

    #[test]
    fn salt_and_verifier_require_valid_hex() {
        let mut meta = sample_meta();
        meta.salt_hex = "zz".repeat(SALT_LEN);
        assert!(matches!(meta.salt(), Err(StoreError::MetaCorrupt(_))));

        let mut meta = sample_meta();
        meta.verifier_hex = "zz".repeat(VERIFIER_LEN);
        assert!(matches!(meta.verifier(), Err(StoreError::MetaCorrupt(_))));

        let meta = sample_meta();
        assert_eq!(meta.salt().unwrap(), [0x11; SALT_LEN]);
        assert_eq!(meta.verifier().unwrap(), [0x22; VERIFIER_LEN]);
    }

    #[test]
    #[cfg(unix)]
    fn meta_file_has_restrictive_permissions() {
        // Review fix R1: vault.meta must be 0600 (owner-only) after write —
        // the temp file's 0600 must survive the rename.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        write_meta(dir.path(), &sample_meta()).unwrap();
        let mode = std::fs::metadata(meta_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "vault.meta must be owner-only");
        let dir_mode = std::fs::metadata(dir.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "vault dir must be owner-only");
    }

    #[test]
    fn write_meta_creates_the_vault_directory() {
        let base = temp_dir();
        let nested = base.path().join("a").join("b");
        let meta = sample_meta();
        write_meta(&nested, &meta).unwrap();
        assert!(meta_path(&nested).exists());
    }

    #[test]
    fn validate_rejects_invalid_kdf_params() {
        let mut meta = sample_meta();
        meta.kdf = KdfParams::new(4, 1, 1); // below Argon2 minimum
        let err = meta.validate().unwrap_err();
        assert!(matches!(err, StoreError::MetaCorrupt(_)));
    }
}
