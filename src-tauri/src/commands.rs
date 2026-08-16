//! Command layer (task 3.2): the thin bridge between the Rust core and the
//! Tauri frontend.
//!
//! Two layers, so the whole command surface is testable WITHOUT the `app`
//! feature (no webview needed):
//!
//! - **Plain command functions** (this module's root) — synchronous, Tauri
//!   free. They take the `VaultSession` directly, so integration tests drive
//!   them with tempdir sessions and fast KDF params.
//! - **`tauri` wrapper module** (`#[cfg(feature = "app")]`) — `#[tauri::command]`
//!   functions that pull the shared session from Tauri state and run the
//!   KDF-heavy operations (`create_vault`, `unlock`) on a blocking thread via
//!   `tauri::async_runtime::spawn_blocking`, so the UI thread never blocks
//!   (design decision: async unlock; the core stays sync).
//!
//! Concurrency contract: ALL commands serialize through the single session
//! (`Mutex<VaultSession>` held by the Tauri shell). One session, one
//! connection — never open a second one, or concurrent writes hit
//! SQLITE_BUSY (DELETE journal, no WAL; documented by the store tests).
//!
//! Error contract: unlock failures ALWAYS map to the opaque `unlock_failed`
//! code + `errors.unlock_failed` key (CRY-04, no oracle — wrong password,
//! tampered meta, and corrupt DB are indistinguishable). Validation errors
//! carry a granular i18n `key` naming the failing rule (SES-01). Credential
//! values never appear in any message (CRU-07).

use zeroize::Zeroizing;

use crate::credential::{self, CredentialError, CredentialInput, CredentialView, ValidationError};
use crate::crypto::KdfParams;
use crate::error::AppError;
use crate::vault::{PolicyError, SessionState, VaultError, VaultSession};

/// Owns a master password String at the command boundary: the IPC `String`
/// is moved in, converted to bytes WITHOUT copying the heap buffer, and
/// zeroized on drop (CRY-03 — the framework-managed IPC copy is accepted and
/// documented in the design).
fn into_zeroizing(password: String) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.into_bytes())
}

/// Maps a session-layer error to an `AppError` with the design's code
/// contract. Unlock failures collapse to the single opaque `unlock_failed`.
fn map_vault_error(e: VaultError) -> AppError {
    match e {
        VaultError::NoVault => AppError::with_key(
            "no_vault",
            "errors.no_vault",
            "no vault exists; create one first",
        ),
        VaultError::AlreadyExists => AppError::with_key(
            "already_exists",
            "errors.already_exists",
            "a vault already exists",
        ),
        VaultError::NotUnlocked => {
            AppError::with_key("locked", "errors.vault_locked", "vault is locked")
        }
        VaultError::Policy(PolicyError::TooShort { min, actual }) => AppError::with_key(
            "validation",
            "errors.password_too_short",
            format!("password must be at least {min} characters (got {actual})"),
        ),
        VaultError::Policy(PolicyError::MissingUppercase) => AppError::with_key(
            "validation",
            "errors.password_missing_uppercase",
            "password must contain at least one uppercase letter",
        ),
        VaultError::Policy(PolicyError::MissingLowercase) => AppError::with_key(
            "validation",
            "errors.password_missing_lowercase",
            "password must contain at least one lowercase letter",
        ),
        VaultError::Policy(PolicyError::MissingDigit) => AppError::with_key(
            "validation",
            "errors.password_missing_digit",
            "password must contain at least one digit",
        ),
        VaultError::Policy(PolicyError::MissingSymbol) => AppError::with_key(
            "validation",
            "errors.password_missing_symbol",
            "password must contain at least one symbol",
        ),
        VaultError::Mismatch => AppError::with_key(
            "validation",
            "errors.passwords_mismatch",
            "passwords do not match",
        ),
        // CRY-04: one opaque error for every unlock failure. The message is
        // deliberately generic — wrong password, tampered meta, and corrupt
        // DB are byte-identical to the caller (no oracle).
        VaultError::UnlockFailed => AppError::with_key(
            "unlock_failed",
            "errors.unlock_failed",
            "unable to unlock the vault",
        ),
        // Create-path storage/crypto failures: never technical detail, never
        // credential values (CRU-07).
        VaultError::Store(_) => AppError::with_key("internal", "errors.internal", "storage error"),
        VaultError::Crypto(_) => AppError::with_key("internal", "errors.internal", "crypto error"),
    }
}

/// Maps a credential-layer error to an `AppError`. Never echoes values.
fn map_credential_error(e: CredentialError) -> AppError {
    match e {
        CredentialError::InvalidInput(ValidationError::EmptyServiceName) => AppError::with_key(
            "validation",
            "errors.empty_service_name",
            "service name must not be empty",
        ),
        CredentialError::InvalidInput(ValidationError::EmptyUsername) => AppError::with_key(
            "validation",
            "errors.empty_username",
            "username must not be empty",
        ),
        CredentialError::InvalidInput(ValidationError::FieldTooLong { max }) => AppError::with_key(
            "validation",
            "errors.field_too_long",
            format!("field must be at most {max} characters"),
        ),
        CredentialError::NotFound => AppError::with_key(
            "not_found",
            "errors.credential_not_found",
            "credential not found",
        ),
        CredentialError::Store(_) => {
            AppError::with_key("internal", "errors.internal", "storage error")
        }
    }
}

// ---- vault lifecycle commands ----

/// Creates a vault (SES-01..SES-03) and ends Unlocked. `params` is injected
/// so tests run with fast KDF parameters; the Tauri shell passes
/// `KdfParams::default()` (OWASP production values).
pub fn create_vault(
    session: &mut VaultSession,
    password: String,
    confirm: String,
    params: &KdfParams,
) -> Result<(), AppError> {
    let password = into_zeroizing(password);
    let confirm = into_zeroizing(confirm);
    session
        .create(&password, &confirm, params)
        .map_err(map_vault_error)
}

/// Unlocks the session (SES-03). EVERY failure maps to the opaque
/// `unlock_failed` (CRY-04) — no oracle.
pub fn unlock(session: &mut VaultSession, password: String) -> Result<(), AppError> {
    let password = into_zeroizing(password);
    session.unlock(&password).map_err(map_vault_error)
}

/// Locks the session (SES-04): drops the store and zeroizes the key. Safe on
/// any state (no-op when not Unlocked).
pub fn lock(session: &mut VaultSession) -> Result<(), AppError> {
    session.lock();
    Ok(())
}

/// Current session state — drives the first-run gate (SHE-01): the frontend
/// shows the create view on `NoVault`, the unlock view on `Locked`.
pub fn vault_status(session: &VaultSession) -> Result<SessionState, AppError> {
    Ok(session.state())
}

// ---- credential commands (all gated on Unlocked, SES-05) ----

/// Lists all credentials. Rejected unless the session is Unlocked (SES-05).
pub fn list_credentials(session: &VaultSession) -> Result<Vec<CredentialView>, AppError> {
    let store = session.store().map_err(map_vault_error)?;
    credential::list(store).map_err(map_credential_error)
}

/// Reads one credential by id (CRU-02). Gated on Unlocked (SES-05).
pub fn get_credential(session: &VaultSession, id: i64) -> Result<CredentialView, AppError> {
    let store = session.store().map_err(map_vault_error)?;
    credential::get(store, id).map_err(map_credential_error)
}

/// Creates a credential (CRU-01). Gated on Unlocked (SES-05).
pub fn create_credential(
    session: &VaultSession,
    input: CredentialInput,
) -> Result<CredentialView, AppError> {
    let store = session.store().map_err(map_vault_error)?;
    credential::create(store, input).map_err(map_credential_error)
}

/// Updates a credential (CRU-03). Gated on Unlocked (SES-05).
pub fn update_credential(
    session: &VaultSession,
    id: i64,
    input: CredentialInput,
) -> Result<CredentialView, AppError> {
    let store = session.store().map_err(map_vault_error)?;
    credential::update(store, id, input).map_err(map_credential_error)
}

/// Deletes a credential (CRU-04 core: confirmation is the UI's job). Gated on
/// Unlocked (SES-05).
pub fn delete_credential(session: &VaultSession, id: i64) -> Result<(), AppError> {
    let store = session.store().map_err(map_vault_error)?;
    credential::delete(store, id).map_err(map_credential_error)
}

// ========================================================================
// Tauri shell wiring (`app` feature only)
// ========================================================================
//
// The wrappers are intentionally thin: lock the session mutex, run the plain
// command function. KDF-heavy operations run inside `spawn_blocking` so the
// async UI thread never blocks; the mutex is only ever held on a blocking
// thread, never across an `.await`, so no deadlock is possible and every
// command is serialized through the single session connection.

#[cfg(feature = "app")]
pub mod tauri {
    use std::sync::{Arc, Mutex};

    use tauri::State;

    use crate::crypto::KdfParams;
    use crate::error::AppError;
    use crate::vault::VaultSession;

    use super::{
        create_credential, create_vault, delete_credential, get_credential, list_credentials, lock,
        unlock, update_credential, vault_status,
    };
    use crate::credential::{CredentialInput, CredentialView};
    use crate::vault::SessionState;

    /// Shared session handle managed by the Tauri shell: the single
    /// `Mutex<VaultSession>` every command serializes through.
    pub type SessionHandle = Arc<Mutex<VaultSession>>;

    /// Runs `f` on a blocking thread (KDF work must never run on the async
    /// UI runtime). A panicked or cancelled task surfaces as an internal
    /// error.
    async fn blocking<T: Send + 'static>(
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AppError> {
        tauri::async_runtime::spawn_blocking(f)
            .await
            .map_err(|e| AppError::new("internal", format!("background task failed: {e}")))
    }

    /// Locks the shared session and hands it to `f`.
    fn with_session<T>(handle: &SessionHandle, f: impl FnOnce(&mut VaultSession) -> T) -> T {
        let mut session = handle.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut session)
    }

    #[tauri::command]
    pub async fn create_vault(
        state: State<'_, SessionHandle>,
        password: String,
        confirm: String,
    ) -> Result<(), AppError> {
        let handle = state.inner().clone();
        blocking(move || {
            with_session(&handle, |session| {
                super::create_vault(session, password, confirm, &KdfParams::default())
            })
        })
        .await
    }

    #[tauri::command]
    pub async fn unlock(state: State<'_, SessionHandle>, password: String) -> Result<(), AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::unlock(session, password))).await
    }

    #[tauri::command]
    pub async fn lock(state: State<'_, SessionHandle>) -> Result<(), AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::lock(session))).await
    }

    #[tauri::command]
    pub async fn vault_status(state: State<'_, SessionHandle>) -> Result<SessionState, AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::vault_status(session))).await
    }

    #[tauri::command]
    pub async fn list_credentials(
        state: State<'_, SessionHandle>,
    ) -> Result<Vec<CredentialView>, AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::list_credentials(session))).await
    }

    #[tauri::command]
    pub async fn get_credential(
        state: State<'_, SessionHandle>,
        id: i64,
    ) -> Result<CredentialView, AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::get_credential(session, id))).await
    }

    #[tauri::command]
    pub async fn create_credential(
        state: State<'_, SessionHandle>,
        input: CredentialInput,
    ) -> Result<CredentialView, AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::create_credential(session, input)))
            .await
    }

    #[tauri::command]
    pub async fn update_credential(
        state: State<'_, SessionHandle>,
        id: i64,
        input: CredentialInput,
    ) -> Result<CredentialView, AppError> {
        let handle = state.inner().clone();
        blocking(move || {
            with_session(&handle, |session| {
                super::update_credential(session, id, input)
            })
        })
        .await
    }

    #[tauri::command]
    pub async fn delete_credential(
        state: State<'_, SessionHandle>,
        id: i64,
    ) -> Result<(), AppError> {
        let handle = state.inner().clone();
        blocking(move || with_session(&handle, |session| super::delete_credential(session, id)))
            .await
    }
}

// Re-export only the types the shell wiring needs.
#[cfg(feature = "app")]
pub use tauri::SessionHandle;
