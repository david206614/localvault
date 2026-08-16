//! Schema versioning constants and the credentials DDL (RF-03).
//!
//! Versioning: `vault.db` carries its schema in SQLite's `user_version`
//! pragma; `vault.meta` carries a matching `schema_version` field plus its
//! own `format` version. Both must agree with the constants here, so a vault
//! created by a newer app version is refused instead of half-read (STO-04).

/// Current on-disk format of the `vault.meta` JSON file. Bump on any breaking
/// meta change (field removal, semantics change). Unknown formats are refused
/// at read time.
pub const META_FORMAT: u8 = 1;

/// Current database schema version (SQLite `PRAGMA user_version`). Bump with
/// every schema migration; `Store::open` refuses databases newer than this.
pub const SCHEMA_VERSION: u32 = 1;

/// Credentials table DDL per RF-03 / design schema contract.
///
/// - `service_name` and `username` are mandatory (CRU-06).
/// - `password` MAY be empty (CRU-06); the `CHECK` only enforces presence of
///   the field, not its length.
/// - `created_at`/`updated_at` are UTC RFC3339 strings, set by the credential
///   layer (task 3.1).
pub const CREDENTIALS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_name TEXT NOT NULL CHECK(length(service_name) > 0),
  username TEXT NOT NULL CHECK(length(username) > 0),
  password TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#;
