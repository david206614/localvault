//! Credential data types shared by the store layer and the command layer.

use serde::{Deserialize, Serialize};

/// Editable credential fields coming from the UI (CRU-01).
///
/// `password` MAY be empty (CRU-06) — it must never be rejected on its own.
/// `url`, `category`, and `notes` are optional and default to the empty
/// string at the schema level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialInput {
    pub service_name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub category: String,
    pub notes: String,
}

/// A persisted credential as returned to the frontend (serde Serialize).
///
/// `created_at`/`updated_at` are UTC RFC3339 strings set by the credential
/// layer; `updated_at` advances on every update while `created_at` is
/// preserved (CRU-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialView {
    pub id: i64,
    pub service_name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub category: String,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}
