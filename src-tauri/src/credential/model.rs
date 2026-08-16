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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_input_fails_serde_with_raw_deserialization_error() {
        // W2 contract: `CredentialInput` has NO `Option` fields — every field
        // is required. A partial JSON object therefore fails at serde BEFORE
        // any command body runs: at the Tauri IPC boundary the frontend gets
        // a raw serde deserialization error (missing field), NEVER an
        // `AppError` code/key. The UI must always send the complete object.
        let partial = r#"{"service_name":"github","username":"octocat"}"#;
        let err = serde_json::from_str::<CredentialInput>(partial).unwrap_err();
        assert!(err.is_data(), "must be a data-class deserialization error");
        let msg = err.to_string();
        assert!(
            msg.contains("missing field"),
            "serde must name the missing field, got: {msg}"
        );
        assert!(
            msg.contains("password"),
            "first missing field is `password` (struct order), got: {msg}"
        );
    }

    #[test]
    fn complete_json_input_deserializes() {
        let json = r#"{
            "service_name":"github",
            "username":"octocat",
            "password":"s3cret!",
            "url":"https://github.com",
            "category":"dev",
            "notes":"work account"
        }"#;
        let parsed: CredentialInput = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.service_name, "github");
        assert_eq!(parsed.notes, "work account");
    }
}
