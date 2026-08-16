//! Integration tests for the command layer (task 3.2).
//!
//! These exercise the PLAIN command functions in `localvault_lib::commands`
//! — the same functions the `#[tauri::command]` wrappers call (the wrappers
//! themselves are `app`-feature-only: thin mutex + spawn_blocking glue that
//! CI exercises with `--features app`).
//!
//! Isolation guarantees:
//! - Every test injects a tempdir vault path via `VaultSession::new` —
//!   NEVER the real `~/.local/share`.
//! - Every test uses FAST KDF params (8 KiB / t=1 / p=1), never the OWASP
//!   production defaults.
//! - Sessions are single-connection: all commands run through one
//!   `VaultSession` (SQLITE_BUSY is expected for concurrent writers and the
//!   command layer serializes by design).

use std::sync::{Arc, Mutex};

use localvault_lib::commands::{
    create_credential, create_vault, delete_credential, get_credential, list_credentials, lock,
    unlock, update_credential, vault_status,
};
use localvault_lib::credential::CredentialInput;
use localvault_lib::crypto::{KdfParams, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};
use localvault_lib::vault::{SessionState, VaultSession};

fn fast_params() -> KdfParams {
    KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
}

/// Fresh session on a tempdir; the `TempDir` is kept alive for the test's
/// lifetime so cleanup happens on drop.
fn make_session() -> (tempfile::TempDir, VaultSession) {
    let dir = tempfile::tempdir().unwrap();
    let session = VaultSession::new(dir.path().to_path_buf());
    (dir, session)
}

fn master_password() -> String {
    "CorrectHorseBatteryStaple!1".to_string()
}

fn sample_input() -> CredentialInput {
    CredentialInput {
        service_name: "github".into(),
        username: "octocat".into(),
        password: "s3cret!".into(),
        url: "https://github.com".into(),
        category: "dev".into(),
        notes: "work account".into(),
    }
}

/// Creates an unlocked session with one credential; returns it plus the row.
fn unlocked_with_credential() -> (
    tempfile::TempDir,
    VaultSession,
    localvault_lib::credential::CredentialView,
) {
    let (dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();
    let view = create_credential(&session, sample_input()).unwrap();
    (dir, session, view)
}

// ---- full lifecycle (create → CRUD → relock → persistence) ----

#[test]
fn full_lifecycle_create_crud_relock_and_delete() {
    let (_dir, mut session) = make_session();
    let pw = master_password();

    // create_vault (SES-01..03): starts NoVault, ends Unlocked.
    assert_eq!(vault_status(&session).unwrap(), SessionState::NoVault);
    create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
    assert_eq!(vault_status(&session).unwrap(), SessionState::Unlocked);

    // create_credential (CRU-01).
    let created = create_credential(&session, sample_input()).unwrap();
    assert!(created.id > 0);
    assert_eq!(created.created_at, created.updated_at);

    // list (CRU-02).
    assert_eq!(list_credentials(&session).unwrap(), vec![created.clone()]);

    // get by id (CRU-02).
    assert_eq!(get_credential(&session, created.id).unwrap(), created);

    // update (CRU-03): password + notes change, created_at preserved.
    let mut edited = sample_input();
    edited.password = "new-password!".into();
    edited.notes = "edited".into();
    let updated = update_credential(&session, created.id, edited).unwrap();
    assert_eq!(updated.password, "new-password!");
    assert_eq!(updated.notes, "edited");
    assert_eq!(updated.created_at, created.created_at);

    // lock (SES-04) → CRUD gated (SES-05).
    lock(&mut session).unwrap();
    assert_eq!(vault_status(&session).unwrap(), SessionState::Locked);

    // unlock (SES-03) → data persists across relock (CRU-05).
    unlock(&mut session, pw).unwrap();
    assert_eq!(vault_status(&session).unwrap(), SessionState::Unlocked);
    assert_eq!(list_credentials(&session).unwrap(), vec![updated.clone()]);

    // delete (CRU-04) + idempotent not_found on second attempt.
    delete_credential(&session, created.id).unwrap();
    assert!(list_credentials(&session).unwrap().is_empty());
    let err = delete_credential(&session, created.id).unwrap_err();
    assert_eq!(err.code, "not_found");
    assert_eq!(err.key, "errors.credential_not_found");
}

// ---- unlock failure is opaque and byte-identical (CRY-04) ----

#[test]
fn unlock_failures_are_opaque_and_byte_identical() {
    // CRY-04 no-oracle, at the COMMAND layer: wrong password, tampered meta,
    // and corrupt DB must collapse to the SAME AppError (byte-identical
    // code/key/message). Each leg uses an isolated vault so the failure mode
    // is genuinely exercised — in particular the corrupt-DB leg (W1): with
    // the meta INTACT, unlock reaches `Store::open`, whose failure must map
    // to `unlock_failed`. This is the leg that guards the `VaultError::Store`
    // arm in `map_vault_error` — if a future refactor routed corrupt-DB
    // through `Store`, the command layer would return `internal` here and
    // this test fails.
    let wrong_pw = {
        let (_dir, mut session) = make_session();
        let pw = master_password();
        create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
        lock(&mut session).unwrap();
        unlock(&mut session, "WrongHorseBatteryStaple!2".to_string()).unwrap_err()
    };
    let tampered_meta = {
        let (_dir, mut session) = make_session();
        let pw = master_password();
        create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
        lock(&mut session).unwrap();
        std::fs::write(session.dir().join("vault.meta"), b"{ not json !").unwrap();
        unlock(&mut session, pw).unwrap_err()
    };
    let corrupt_db = {
        let (_dir, mut session) = make_session();
        let pw = master_password();
        create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
        lock(&mut session).unwrap();
        // Corrupt the DB BODY (not meta): flip one byte in a data page so
        // the file still parses as SQLCipher but its page HMAC fails.
        let path = localvault_lib::store::db_path(session.dir());
        let mut bytes = std::fs::read(&path).unwrap();
        let target = 4096 * 2 + 200;
        assert!(target < bytes.len(), "database too small to tamper");
        bytes[target] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();
        let err = unlock(&mut session, pw).unwrap_err();
        assert_eq!(
            vault_status(&session).unwrap(),
            SessionState::Locked,
            "failed unlock must not open the session"
        );
        err
    };

    assert_eq!(wrong_pw.code, "unlock_failed");
    assert_eq!(wrong_pw.key, "errors.unlock_failed");
    assert_eq!(
        wrong_pw, tampered_meta,
        "no oracle: wrong password vs tampered meta must be byte-identical"
    );
    assert_eq!(
        wrong_pw, corrupt_db,
        "no oracle: wrong password vs corrupt DB must be byte-identical"
    );
    assert_eq!(
        tampered_meta, corrupt_db,
        "no oracle: tampered meta vs corrupt DB must be byte-identical"
    );
}

// ---- create_vault validation (SES-01, SES-02) ----

#[test]
fn create_vault_rejects_weak_password_naming_the_rule() {
    let (_dir, mut session) = make_session();
    let err = create_vault(
        &mut session,
        "Ab1!".to_string(),
        "Ab1!".to_string(),
        &fast_params(),
    )
    .unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.password_too_short");
    assert_eq!(vault_status(&session).unwrap(), SessionState::NoVault);
}

#[test]
fn create_vault_rejects_confirmation_mismatch() {
    let (_dir, mut session) = make_session();
    let err = create_vault(
        &mut session,
        master_password(),
        "DifferentBatteryStaple!2".to_string(),
        &fast_params(),
    )
    .unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.passwords_mismatch");
}

#[test]
fn create_vault_twice_fails_with_already_exists() {
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
    let err = create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap_err();
    assert_eq!(err.code, "already_exists");
}

#[test]
fn unlock_without_vault_fails_with_no_vault() {
    let (_dir, mut session) = make_session();
    let err = unlock(&mut session, master_password()).unwrap_err();
    assert_eq!(err.code, "no_vault");
}

// ---- credential validation (CRU-06) ----

#[test]
fn empty_password_is_allowed_end_to_end() {
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();
    let mut empty = sample_input();
    empty.password.clear();
    let view = create_credential(&session, empty).unwrap();
    assert_eq!(view.password, "");
    assert_eq!(list_credentials(&session).unwrap(), vec![view]);
}

#[test]
fn empty_required_fields_are_rejected_with_validation() {
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();

    let mut no_service = sample_input();
    no_service.service_name.clear();
    let err = create_credential(&session, no_service).unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.empty_service_name");

    let mut no_user = sample_input();
    no_user.username.clear();
    let err = create_credential(&session, no_user).unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.empty_username");

    assert!(list_credentials(&session).unwrap().is_empty());
}

#[test]
fn over_cap_fields_are_rejected_with_field_too_long() {
    // S8: the command layer surfaces over-cap values as the granular
    // `validation` / `errors.field_too_long` contract — and nothing is
    // written. The caps themselves are pinned at the unit level
    // (validate.rs); here we pin the code/key mapping end-to-end.
    let (_dir, session, created) = unlocked_with_credential();

    let mut over_notes = sample_input();
    over_notes.notes = "n".repeat(localvault_lib::credential::MAX_NOTES_LEN + 1);
    let err = create_credential(&session, over_notes).unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.field_too_long");
    assert!(
        !err.message.contains("nnnn"),
        "message must not echo the value (CRU-07)"
    );
    assert_eq!(
        list_credentials(&session).unwrap().len(),
        1,
        "no row written for the over-cap create"
    );

    // The same contract applies to update_credential, and the row survives.
    let mut over_url = sample_input();
    over_url.url = "x".repeat(localvault_lib::credential::MAX_URL_LEN + 1);
    let err = update_credential(&session, created.id, over_url).unwrap_err();
    assert_eq!(err.code, "validation");
    assert_eq!(err.key, "errors.field_too_long");
    assert_eq!(
        get_credential(&session, created.id).unwrap(),
        created,
        "over-cap update must leave the stored row untouched"
    );
}

#[test]
fn update_replaces_all_editable_fields_never_merges() {
    // W2 contract: `update` REPLACES all six editable fields. The frontend
    // must ALWAYS send the complete object — sending empty url/notes WIPES
    // them; there is no merge.
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();
    let created = create_credential(&session, sample_input()).unwrap();
    assert_eq!(created.url, "https://github.com");
    assert_eq!(created.notes, "work account");

    let mut cleared = sample_input();
    cleared.url.clear();
    cleared.notes.clear();
    cleared.password = "rotated!".into();
    let updated = update_credential(&session, created.id, cleared).unwrap();
    assert_eq!(
        updated.url, "",
        "empty url in the full object wipes the stored url"
    );
    assert_eq!(
        updated.notes, "",
        "empty notes in the full object wipe the stored notes"
    );
    assert_eq!(updated.password, "rotated!");
    assert_eq!(updated.service_name, "github");
    assert_eq!(updated.username, "octocat");
}

#[test]
fn error_messages_never_leak_credential_values() {
    // CRU-07: a distinctive secret must never appear in any error message.
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();

    let mut bad = sample_input();
    bad.service_name.clear();
    bad.username = "ULTRA-SECRET-USERNAME-42".into();
    bad.password = "ULTRA-SECRET-PASSWORD-42".into();
    let err = create_credential(&session, bad).unwrap_err();
    assert!(!err.message.contains("ULTRA-SECRET"));
    assert!(!err.message.contains("42"));

    // The opaque unlock error must not echo the attempted password either.
    lock(&mut session).unwrap();
    let err = unlock(&mut session, "ULTRA-SECRET-PASSWORD-42".to_string()).unwrap_err();
    assert!(!err.message.contains("ULTRA-SECRET"));
}

// ---- SES-05: session gating ----

#[test]
fn locked_session_gates_every_credential_command() {
    let (_dir, mut session, _view) = unlocked_with_credential();
    lock(&mut session).unwrap();

    assert_eq!(list_credentials(&session).unwrap_err().code, "locked");
    assert_eq!(get_credential(&session, 1).unwrap_err().code, "locked");
    assert_eq!(
        create_credential(&session, sample_input())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        update_credential(&session, 1, sample_input())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(delete_credential(&session, 1).unwrap_err().code, "locked");
}

#[test]
fn no_vault_session_gates_credential_commands_with_no_vault() {
    // S4: ALL FIVE credential commands from NoVault must answer `no_vault`
    // (never `locked` — the first-run gate would strand on the unlock view).
    let (_dir, session) = make_session();
    assert_eq!(list_credentials(&session).unwrap_err().code, "no_vault");
    assert_eq!(get_credential(&session, 1).unwrap_err().code, "no_vault");
    assert_eq!(
        create_credential(&session, sample_input())
            .unwrap_err()
            .code,
        "no_vault"
    );
    assert_eq!(
        update_credential(&session, 1, sample_input())
            .unwrap_err()
            .code,
        "no_vault"
    );
    assert_eq!(delete_credential(&session, 1).unwrap_err().code, "no_vault");
}

// ---- not_found contract (CRU-02/03/04) ----

#[test]
fn get_and_update_nonexistent_id_error_not_found() {
    // S6: `get` and `update` on a missing id must surface the SAME
    // code/key contract the delete path already asserts end-to-end.
    let (_dir, session, _view) = unlocked_with_credential();

    let err = get_credential(&session, 999).unwrap_err();
    assert_eq!(err.code, "not_found");
    assert_eq!(err.key, "errors.credential_not_found");

    let err = update_credential(&session, 999, sample_input()).unwrap_err();
    assert_eq!(err.code, "not_found");
    assert_eq!(err.key, "errors.credential_not_found");
}

// ---- full restart persistence (frontend-facing flow) ----

#[test]
fn full_restart_persists_data_across_sessions() {
    // S5: close the app (session dropped), start a FRESH session on the same
    // vault dir. The state is detected as Locked from disk (not NoVault),
    // unlock restores access, and data created in the prior session
    // survives — the frontend-facing restart flow.
    let dir = tempfile::tempdir().unwrap();
    let pw = master_password();
    {
        let mut session = VaultSession::new(dir.path().to_path_buf());
        create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
        create_credential(&session, sample_input()).unwrap();
        // session dropped here — simulates the app closing.
    }

    let mut fresh = VaultSession::new(dir.path().to_path_buf());
    assert_eq!(
        vault_status(&fresh).unwrap(),
        SessionState::Locked,
        "restart must detect the existing vault from disk"
    );
    unlock(&mut fresh, pw).unwrap();
    let rows = list_credentials(&fresh).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "data from the prior session must survive a full restart"
    );
    assert_eq!(rows[0].service_name, "github");
    assert_eq!(rows[0].username, "octocat");
}

// ---- lock semantics ----

#[test]
fn lock_is_safe_when_no_vault_is_open() {
    let (_dir, mut session) = make_session();
    // NoVault → lock is a no-op, state stays NoVault (never regresses to
    // Locked, which would strand the first-run gate on the unlock view).
    lock(&mut session).unwrap();
    assert_eq!(vault_status(&session).unwrap(), SessionState::NoVault);
}

// ---- serialization smoke test: one session, one connection ----

#[test]
fn rapid_sequential_writes_through_one_session_succeed() {
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw, &fast_params()).unwrap();
    // Burst of writes through the single session connection: each commits
    // before the next starts (serialized), so no SQLITE_BUSY surfaces.
    for i in 0..20 {
        let mut input = sample_input();
        input.service_name = format!("service-{i:02}");
        create_credential(&session, input).unwrap();
    }
    assert_eq!(list_credentials(&session).unwrap().len(), 20);
}

// ---- W3: serialization through ONE session, proven under real threads ----

#[test]
fn concurrent_crud_through_shared_session_is_serialized() {
    // The production serialization lives in the `app`-feature wrapper
    // (Mutex in `with_session`/`blocking`), which can't build locally (no
    // webkit, no ../dist). The serialization THROUGH ONE SESSION is
    // testable without the feature: guard `Arc<Mutex<VaultSession>>` exactly
    // like `with_session` does and hammer it from N threads. This proves
    // SQLITE_BUSY avoidance via single-session serialization — and that
    // `Connection: Send` (PR 2 claim) holds so the wrapper compiles.
    const THREADS: usize = 8;
    const PER_THREAD: usize = 5;
    let expected = THREADS * PER_THREAD;

    let dir = tempfile::tempdir().unwrap();
    let session = Arc::new(Mutex::new(VaultSession::new(dir.path().to_path_buf())));
    let pw = master_password();
    {
        let mut guard = session.lock().unwrap_or_else(|e| e.into_inner());
        create_vault(&mut guard, pw.clone(), pw.clone(), &fast_params()).unwrap();
    }

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let session = Arc::clone(&session);
            let pw = pw.clone();
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let mut guard = session.lock().unwrap_or_else(|e| e.into_inner());
                    // Idempotent when already Unlocked — exercises the same
                    // command path the wrappers run per request.
                    unlock(&mut guard, pw.clone()).unwrap();
                    let mut input = sample_input();
                    input.service_name = format!("svc-{t:02}-{i:02}");
                    create_credential(&guard, input).unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker thread panicked");
    }

    {
        let guard = session.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = list_credentials(&guard)
            .unwrap()
            .into_iter()
            .map(|c| c.service_name)
            .collect();
        assert_eq!(names.len(), expected, "no lost rows under concurrency");
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(
            unique.len(),
            expected,
            "no duplicate rows under concurrency"
        );
        // The file itself is uncorrupted after the burst.
        guard.store().unwrap().verify_integrity().unwrap();
    }

    // The store still opens cleanly from a fresh session (restart flow).
    {
        let mut guard = session.lock().unwrap_or_else(|e| e.into_inner());
        lock(&mut guard).unwrap();
    }
    let mut fresh = VaultSession::new(dir.path().to_path_buf());
    assert_eq!(fresh.state(), SessionState::Locked);
    unlock(&mut fresh, pw).unwrap();
    assert_eq!(list_credentials(&fresh).unwrap().len(), expected);
}
