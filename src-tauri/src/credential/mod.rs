//! Credential CRUD over the encrypted store (task 3.1, CRU-01..CRU-07).
//!
//! All access goes through the session's single `Store` connection — the
//! command layer (3.2) serializes commands on one session, because a second
//! concurrent writer would hit SQLITE_BUSY (DELETE journal, no WAL — see the
//! store concurrency test).
//!
//! - Reads (`list`/`get`) run directly on the store connection.
//! - Writes (`create`/`update`/`delete`) run inside `IMMEDIATE`
//!   transactions via `Store::with_transaction` (STO-07): any error rolls
//!   back, so no partial records survive.
//! - All SQL is parameterized; input values never reach the query text
//!   (injection-proof, adversarial-tested at the store layer).
//! - Timestamps are UTC RFC3339 (chrono); `created_at` is set once,
//!   `updated_at` is refreshed on every update (CRU-03). `create_at` /
//!   `update_at` accept an injected timestamp so tests advance the clock
//!   deterministically (no wall-clock sleeps).
//! - `password` MAY be empty (CRU-06); `service_name` and `username` must be
//!   non-empty, and every field has an upper length cap (S8). Errors never
//!   echo credential values (CRU-07).

mod model;
mod validate;

use rusqlite::{params, Connection, Row};

use crate::store::{Store, StoreError};

pub use model::{CredentialInput, CredentialView};
pub use validate::{
    validate_input, ValidationError, MAX_CATEGORY_LEN, MAX_NOTES_LEN, MAX_PASSWORD_LEN,
    MAX_SERVICE_NAME_LEN, MAX_URL_LEN, MAX_USERNAME_LEN,
};

/// Errors produced by the credential layer.
///
/// `Debug`-only: the command layer maps these to `AppError` codes, and
/// credential VALUES never appear in any message (CRU-07).
#[derive(Debug)]
pub enum CredentialError {
    /// CRU-06 validation failure — names the failing rule.
    InvalidInput(ValidationError),
    /// The credential id does not exist.
    NotFound,
    /// Storage-layer error.
    Store(StoreError),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::InvalidInput(e) => write!(f, "invalid credential: {e:?}"),
            CredentialError::NotFound => write!(f, "credential not found"),
            CredentialError::Store(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<StoreError> for CredentialError {
    fn from(e: StoreError) -> Self {
        CredentialError::Store(e)
    }
}

impl From<ValidationError> for CredentialError {
    fn from(e: ValidationError) -> Self {
        CredentialError::InvalidInput(e)
    }
}

/// The columns every read query selects, in row order.
const COLUMNS: &str = "id, service_name, username, password, url, category, notes, \
                       created_at, updated_at";

/// Maps a result row to a `CredentialView`.
fn row_to_view(row: &Row) -> rusqlite::Result<CredentialView> {
    Ok(CredentialView {
        id: row.get(0)?,
        service_name: row.get(1)?,
        username: row.get(2)?,
        password: row.get(3)?,
        url: row.get(4)?,
        category: row.get(5)?,
        notes: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

/// Reads one credential by id, mapping a missing row to `NotFound`.
fn get_row(conn: &Connection, id: i64) -> Result<CredentialView, CredentialError> {
    let sql = format!("SELECT {COLUMNS} FROM credentials WHERE id = ?1");
    conn.query_row(&sql, [id], row_to_view)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CredentialError::NotFound,
            other => CredentialError::from(StoreError::Sqlite(other)),
        })
}

/// Formats a `DateTime<Utc>` as the RFC3339 millisecond string the design
/// specifies for `created_at`/`updated_at`. The timestamp SOURCE is injected
/// (S7): production calls pass `Utc::now`, tests pass explicit instants so
/// `updated_at > created_at` is guaranteed deterministically — no sleeps.
fn format_timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Lists all credentials in a stable order (service name, then id).
pub fn list(store: &Store) -> Result<Vec<CredentialView>, CredentialError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM credentials ORDER BY service_name COLLATE NOCASE ASC, id ASC"
    );
    let mut stmt = store
        .connection()
        .prepare(&sql)
        .map_err(|e| CredentialError::from(StoreError::Sqlite(e)))?;
    let rows = stmt
        .query_map([], row_to_view)
        .map_err(|e| CredentialError::from(StoreError::Sqlite(e)))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| CredentialError::from(StoreError::Sqlite(e)))?);
    }
    Ok(out)
}

/// Reads one credential by id (CRU-02).
pub fn get(store: &Store, id: i64) -> Result<CredentialView, CredentialError> {
    get_row(store.connection(), id)
}

/// Creates a credential (CRU-01): validates, sets both timestamps, and
/// commits transactionally (STO-07). Returns the persisted row.
pub fn create(store: &Store, input: CredentialInput) -> Result<CredentialView, CredentialError> {
    create_at(store, input, chrono::Utc::now())
}

/// Like `create`, but with an explicit timestamp (S7): tests advance the
/// clock deterministically instead of sleeping.
fn create_at(
    store: &Store,
    input: CredentialInput,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<CredentialView, CredentialError> {
    validate_input(&input)?;
    let now = format_timestamp(now);
    store.with_transaction(|conn| {
        conn.execute(
            "INSERT INTO credentials
             (service_name, username, password, url, category, notes,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                input.service_name,
                input.username,
                input.password,
                input.url,
                input.category,
                input.notes,
                &now,
                &now
            ],
        )
        .map_err(StoreError::Sqlite)?;
        let id = conn.last_insert_rowid();
        get_row(conn, id)
    })
}

/// Updates the editable fields of a credential (CRU-03): refreshes
/// `updated_at`, preserves `created_at`. Errors with `NotFound` when the id
/// does not exist. Commits transactionally.
///
/// Contract (W2): the update REPLACES all six editable fields — the
/// frontend must always send the complete object. There is no merge:
/// empty `url`/`notes` in the input WIPE the stored values.
pub fn update(
    store: &Store,
    id: i64,
    input: CredentialInput,
) -> Result<CredentialView, CredentialError> {
    update_at(store, id, input, chrono::Utc::now())
}

/// Like `update`, but with an explicit timestamp (S7): tests advance the
/// clock deterministically instead of sleeping.
fn update_at(
    store: &Store,
    id: i64,
    input: CredentialInput,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<CredentialView, CredentialError> {
    validate_input(&input)?;
    let now = format_timestamp(now);
    store.with_transaction(|conn| {
        let updated = conn
            .execute(
                "UPDATE credentials
                 SET service_name = ?1, username = ?2, password = ?3, url = ?4,
                     category = ?5, notes = ?6, updated_at = ?7
                 WHERE id = ?8",
                params![
                    input.service_name,
                    input.username,
                    input.password,
                    input.url,
                    input.category,
                    input.notes,
                    &now,
                    id
                ],
            )
            .map_err(StoreError::Sqlite)?;
        if updated == 0 {
            return Err(CredentialError::NotFound);
        }
        get_row(conn, id)
    })
}

/// Deletes a credential by id (CRU-04 core: the confirmation dialog is a UI
/// concern; this command removes the record when invoked). Errors with
/// `NotFound` when the id does not exist. Commits transactionally.
pub fn delete(store: &Store, id: i64) -> Result<(), CredentialError> {
    store.with_transaction(|conn| {
        let removed = conn
            .execute("DELETE FROM credentials WHERE id = ?1", [id])
            .map_err(StoreError::Sqlite)?;
        if removed == 0 {
            return Err(CredentialError::NotFound);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{VaultKey, KEY_LEN};
    use crate::store::Store;

    fn test_key() -> VaultKey {
        VaultKey::from_bytes([7u8; KEY_LEN])
    }

    /// Fresh encrypted store on a tempdir (never touches real data dirs).
    fn test_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(dir.path(), &test_key()).unwrap();
        (dir, store)
    }

    fn input() -> CredentialInput {
        CredentialInput {
            service_name: "github".into(),
            username: "octocat".into(),
            password: "s3cret!".into(),
            url: "https://github.com".into(),
            category: "dev".into(),
            notes: "work account".into(),
        }
    }

    fn assert_rfc3339_utc(s: &str) {
        assert!(
            s.len() >= 24 && s.ends_with('Z') && s.contains('T'),
            "timestamp must be UTC RFC3339, got {s:?}"
        );
        assert!(
            chrono::DateTime::parse_from_rfc3339(s).is_ok(),
            "timestamp must parse as RFC3339, got {s:?}"
        );
    }

    // ---- create (CRU-01) ----

    #[test]
    fn create_persists_all_fields_and_sets_timestamps() {
        let (_dir, store) = test_store();
        let view = create(&store, input()).unwrap();
        assert!(view.id > 0);
        assert_eq!(view.service_name, "github");
        assert_eq!(view.username, "octocat");
        assert_eq!(view.password, "s3cret!");
        assert_eq!(view.url, "https://github.com");
        assert_eq!(view.category, "dev");
        assert_eq!(view.notes, "work account");
        assert_eq!(
            view.created_at, view.updated_at,
            "fresh row: both timestamps equal"
        );
        assert_rfc3339_utc(&view.created_at);
        assert_rfc3339_utc(&view.updated_at);
    }

    #[test]
    fn create_with_empty_password_is_allowed() {
        // CRU-06: an empty password is a valid credential.
        let (_dir, store) = test_store();
        let mut i = input();
        i.password.clear();
        let view = create(&store, i).unwrap();
        assert_eq!(view.password, "");
        assert_eq!(list(&store).unwrap().len(), 1);
    }

    #[test]
    fn create_rejects_empty_service_name_and_writes_nothing() {
        let (_dir, store) = test_store();
        let mut i = input();
        i.service_name.clear();
        let err = create(&store, i).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::InvalidInput(ValidationError::EmptyServiceName)
        ));
        assert!(
            list(&store).unwrap().is_empty(),
            "no row on validation failure"
        );
    }

    #[test]
    fn create_rejects_empty_username_and_writes_nothing() {
        let (_dir, store) = test_store();
        let mut i = input();
        i.username.clear();
        let err = create(&store, i).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::InvalidInput(ValidationError::EmptyUsername)
        ));
        assert!(list(&store).unwrap().is_empty());
    }

    // ---- read (CRU-02) ----

    #[test]
    fn list_returns_all_rows_in_stable_order() {
        let (_dir, store) = test_store();
        let mut zebra = input();
        zebra.service_name = "zebra".into();
        let mut alpha = input();
        alpha.service_name = "alpha".into();
        let mut alpha2 = input();
        alpha2.service_name = "ALPHA2".into(); // NOCASE ordering puts it near alpha
        create(&store, alpha).unwrap();
        create(&store, zebra).unwrap();
        create(&store, alpha2).unwrap();

        let names: Vec<String> = list(&store)
            .unwrap()
            .into_iter()
            .map(|c| c.service_name)
            .collect();
        assert_eq!(names, vec!["alpha", "ALPHA2", "zebra"]);
    }

    #[test]
    fn get_returns_one_by_id() {
        let (_dir, store) = test_store();
        let created = create(&store, input()).unwrap();
        let fetched = get(&store, created.id).unwrap();
        assert_eq!(fetched, created);
    }

    #[test]
    fn get_missing_id_errors_not_found() {
        let (_dir, store) = test_store();
        assert!(matches!(get(&store, 999), Err(CredentialError::NotFound)));
    }

    #[test]
    fn list_is_empty_on_fresh_vault() {
        let (_dir, store) = test_store();
        assert!(list(&store).unwrap().is_empty());
    }

    // ---- update (CRU-03) ----

    #[test]
    fn update_changes_fields_and_advances_updated_at_preserving_created_at() {
        let (_dir, store) = test_store();
        // Deterministic clock (S7): no wall-clock sleep. Create at t0, update
        // at t0 + 1 ms — `updated_at > created_at` is guaranteed by the
        // injected timestamps, not by a sleep racing the clock.
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-08-16T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let created = create_at(&store, input(), t0).unwrap();
        let mut edited = input();
        edited.password = "new-password!".into();
        edited.notes = "edited notes".into();

        let updated = update_at(
            &store,
            created.id,
            edited,
            t0 + chrono::Duration::milliseconds(1),
        )
        .unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.password, "new-password!");
        assert_eq!(updated.notes, "edited notes");
        assert_eq!(
            updated.created_at, created.created_at,
            "created_at preserved"
        );
        assert_ne!(
            updated.updated_at, created.updated_at,
            "updated_at advanced"
        );
        assert!(updated.updated_at > created.updated_at);
        assert_rfc3339_utc(&updated.updated_at);
    }

    #[test]
    fn update_can_clear_the_password() {
        // CRU-06 applies to updates too: clearing a password is valid.
        let (_dir, store) = test_store();
        let created = create(&store, input()).unwrap();
        let mut cleared = input();
        cleared.password.clear();
        let updated = update(&store, created.id, cleared).unwrap();
        assert_eq!(updated.password, "");
    }

    #[test]
    fn update_missing_id_errors_not_found() {
        let (_dir, store) = test_store();
        let err = update(&store, 999, input()).unwrap_err();
        assert!(matches!(err, CredentialError::NotFound));
    }

    #[test]
    fn update_rejects_empty_required_fields_and_preserves_row() {
        let (_dir, store) = test_store();
        let created = create(&store, input()).unwrap();
        let mut bad = input();
        bad.username.clear();
        let err = update(&store, created.id, bad).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::InvalidInput(ValidationError::EmptyUsername)
        ));
        // The stored row is untouched.
        assert_eq!(get(&store, created.id).unwrap(), created);
    }

    // ---- delete (CRU-04 core) ----

    #[test]
    fn delete_removes_the_record_and_commits() {
        let (_dir, store) = test_store();
        let a = create(&store, input()).unwrap();
        let mut other = input();
        other.service_name = "gitlab".into();
        let b = create(&store, other).unwrap();

        delete(&store, a.id).unwrap();
        assert!(matches!(get(&store, a.id), Err(CredentialError::NotFound)));
        assert_eq!(get(&store, b.id).unwrap(), b, "unrelated row survives");
        assert_eq!(list(&store).unwrap().len(), 1);
    }

    #[test]
    fn delete_missing_id_errors_not_found() {
        let (_dir, store) = test_store();
        assert!(matches!(
            delete(&store, 999),
            Err(CredentialError::NotFound)
        ));
    }

    // ---- durability (CRU-05) ----

    #[test]
    fn credentials_survive_reopen_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let view = {
            let store = Store::create(dir.path(), &test_key()).unwrap();
            create(&store, input()).unwrap()
        }; // store dropped → connection closed
        let store = Store::open(dir.path(), &test_key()).unwrap();
        let rows = list(&store).unwrap();
        assert_eq!(rows, vec![view]);
    }

    // ---- adversarial values (CRU-07 / store hardening) ----

    #[test]
    fn hostile_inputs_roundtrip_byte_identical() {
        let (_dir, store) = test_store();
        // S8: field caps are enforced by `validate_input`, so the long value
        // rides in `notes` (cap 16 384) to stay UNDER the cap and round-trip
        // byte-identically. (The store-layer adversarial test still covers a
        // 10 000-char value at the raw-SQL level, where no validation runs.)
        let long = "x".repeat(4_000);
        let hostile = [
            "O'Reilly",
            "'); DROP TABLE credentials;--",
            "héllo wörld 世界 🚀",
            "line1\nline2\tend",
        ];
        for (i, value) in hostile.iter().enumerate() {
            let mut c = input();
            c.service_name = format!("svc-{i}");
            c.username = value.to_string();
            create(&store, c).unwrap();
        }
        let mut long_input = input();
        long_input.service_name = "svc-long".into();
        long_input.notes = long.clone();
        create(&store, long_input).unwrap();

        let rows = list(&store).unwrap();
        for (i, row) in rows.iter().take(hostile.len()).enumerate() {
            assert_eq!(row.username.as_bytes(), hostile[i].as_bytes());
        }
        let long_row = rows
            .iter()
            .find(|r| r.service_name == "svc-long")
            .expect("long-value row must exist");
        assert_eq!(long_row.notes.as_bytes(), long.as_bytes());
        // The injection attempt must not have altered the schema.
        let count: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, (hostile.len() + 1) as i64);
    }

    #[test]
    fn over_cap_values_are_rejected_and_write_nothing() {
        // S8: a value above the cap is rejected with FieldTooLong and the
        // transaction writes nothing.
        let (_dir, store) = test_store();
        let mut too_long_notes = input();
        too_long_notes.notes = "n".repeat(MAX_NOTES_LEN + 1);
        let err = create(&store, too_long_notes).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::InvalidInput(ValidationError::FieldTooLong { max: MAX_NOTES_LEN })
        ));
        assert!(
            list(&store).unwrap().is_empty(),
            "no row on over-cap validation failure"
        );

        // The cap applies to updates too, and the stored row survives.
        let created = create(&store, input()).unwrap();
        let mut too_long_url = input();
        too_long_url.url = "x".repeat(MAX_URL_LEN + 1);
        let err = update(&store, created.id, too_long_url).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::InvalidInput(ValidationError::FieldTooLong { max: MAX_URL_LEN })
        ));
        assert_eq!(get(&store, created.id).unwrap(), created, "row untouched");
    }
}
