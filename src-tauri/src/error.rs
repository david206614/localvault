//! Application-level error type used across the Tauri command layer.

use std::fmt;

/// Application error surfaced to the UI layer.
///
/// - `code` — coarse error bucket the frontend uses for flow decisions
///   (`unlock_failed | locked | no_vault | already_exists | validation |
///   not_found | internal`). Unlock failures ALWAYS use `unlock_failed`
///   (no-oracle policy, CRY-04).
/// - `key` — stable, granular i18n key (SHE-06): the frontend maps `key` to
///   a localized string (e.g. `errors.password_too_short`), with `code` as
///   fallback. This is what lets SES-01 name the exact failing policy rule.
/// - `message` — English fallback / log text. NEVER contains credential
///   values or technical internals (CRU-07, CRY-03).
///
/// `Serialize`: tauri 2 requires command `Result<T, E>` error types to be
/// serializable so failures can cross the IPC boundary to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppError {
    pub code: String,
    pub key: String,
    pub message: String,
}

impl AppError {
    /// Builds an error whose i18n key defaults to its code.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        let key = code.clone();
        Self { code, key, message }
    }

    /// Builds an error with an explicit granular i18n key.
    pub fn with_key(
        code: impl Into<String>,
        key: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            key: key.into(),
            message: message.into(),
        }
    }

    /// Internal failure: never surface secrets or technical detail.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}
