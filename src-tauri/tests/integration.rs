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
    let (_dir, mut session) = make_session();
    let pw = master_password();
    create_vault(&mut session, pw.clone(), pw.clone(), &fast_params()).unwrap();
    lock(&mut session).unwrap();

    // Wrong password...
    let wrong_pw = unlock(&mut session, "WrongHorseBatteryStaple!2".to_string()).unwrap_err();

    // ...and tampered meta collapse to the SAME AppError (CRY-04 no-oracle:
    // byte-identical code, key, and message — the caller cannot distinguish).
    std::fs::write(session.dir().join("vault.meta"), b"{ not json !").unwrap();
    let tampered = unlock(&mut session, pw).unwrap_err();

    assert_eq!(wrong_pw.code, "unlock_failed");
    assert_eq!(wrong_pw.key, "errors.unlock_failed");
    assert_eq!(
        wrong_pw, tampered,
        "no oracle: errors must be byte-identical"
    );
    assert_eq!(vault_status(&session).unwrap(), SessionState::Locked);
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
    let (_dir, session) = make_session();
    assert_eq!(list_credentials(&session).unwrap_err().code, "no_vault");
    assert_eq!(
        create_credential(&session, sample_input())
            .unwrap_err()
            .code,
        "no_vault"
    );
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
