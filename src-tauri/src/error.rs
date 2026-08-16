//! Application-level error type used across the Tauri command layer.

use std::fmt;

/// Application error surfaced to the UI layer.
///
/// Error codes are stable strings the frontend maps to i18n keys.
/// Unlock failures ALWAYS use `unlock_failed` (no-oracle policy, CRY-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
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
