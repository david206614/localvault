//! Credential input validation (CRU-06, field caps S8).

use super::model::CredentialInput;

/// Upper length caps (in chars) per editable field (review fix S8). Without
/// caps, a buggy or hostile frontend could persist multi-megabyte rows and
/// ship unbounded IPC payloads; these limits are generous for real
/// credentials while keeping storage bounded and the contract explicit.
/// Values exactly AT the cap are valid; only values ABOVE it are rejected.
pub const MAX_SERVICE_NAME_LEN: usize = 256;
pub const MAX_USERNAME_LEN: usize = 256;
pub const MAX_URL_LEN: usize = 2_048;
pub const MAX_CATEGORY_LEN: usize = 128;
pub const MAX_PASSWORD_LEN: usize = 4_096;
pub const MAX_NOTES_LEN: usize = 16_384;

/// Input-validation failures (CRU-06). Each variant names the failing rule so
/// the command layer can surface a stable, i18n-mappable error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// `service_name` must not be empty.
    EmptyServiceName,
    /// `username` must not be empty.
    EmptyUsername,
    /// A field exceeds its upper bound (S8). `max` is the cap in chars; the
    /// message never echoes the offending value (CRU-07).
    FieldTooLong { max: usize },
}

/// Validates credential input against CRU-06 and the S8 field caps:
///
/// - `service_name` and `username` MUST be non-empty.
/// - `password` MAY be empty — never reject an empty password (CRU-06).
/// - `url`, `category`, `notes` are optional.
/// - Every field has an upper bound (S8); values strictly above the cap are
///   rejected with `FieldTooLong { max }`.
///
/// Error messages NEVER echo field values (CRU-07): they name the rule, not
/// the offending input.
pub fn validate_input(input: &CredentialInput) -> Result<(), ValidationError> {
    if input.service_name.trim().is_empty() {
        return Err(ValidationError::EmptyServiceName);
    }
    if input.username.trim().is_empty() {
        return Err(ValidationError::EmptyUsername);
    }
    check_len(input.service_name.chars().count(), MAX_SERVICE_NAME_LEN)?;
    check_len(input.username.chars().count(), MAX_USERNAME_LEN)?;
    check_len(input.url.chars().count(), MAX_URL_LEN)?;
    check_len(input.category.chars().count(), MAX_CATEGORY_LEN)?;
    check_len(input.password.chars().count(), MAX_PASSWORD_LEN)?;
    check_len(input.notes.chars().count(), MAX_NOTES_LEN)?;
    Ok(())
}

/// Rejects a value strictly above `max`; a value exactly at the cap is valid.
fn check_len(len: usize, max: usize) -> Result<(), ValidationError> {
    if len > max {
        return Err(ValidationError::FieldTooLong { max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn accepts_valid_input() {
        assert_eq!(validate_input(&input()), Ok(()));
    }

    #[test]
    fn accepts_empty_password() {
        // CRU-06: an empty password is a legitimate entry.
        let mut i = input();
        i.password.clear();
        assert_eq!(validate_input(&i), Ok(()));
    }

    #[test]
    fn accepts_empty_optional_fields() {
        let mut i = input();
        i.url.clear();
        i.category.clear();
        i.notes.clear();
        assert_eq!(validate_input(&i), Ok(()));
    }

    #[test]
    fn rejects_empty_service_name() {
        let mut i = input();
        i.service_name.clear();
        assert_eq!(validate_input(&i), Err(ValidationError::EmptyServiceName));
    }

    #[test]
    fn rejects_whitespace_only_service_name() {
        let mut i = input();
        i.service_name = "   ".into();
        assert_eq!(validate_input(&i), Err(ValidationError::EmptyServiceName));
    }

    #[test]
    fn rejects_empty_username() {
        let mut i = input();
        i.username.clear();
        assert_eq!(validate_input(&i), Err(ValidationError::EmptyUsername));
    }

    // ---- S8 field caps ----

    #[test]
    fn accepts_values_exactly_at_each_cap() {
        // At-the-cap is valid; only strictly-above is rejected.
        let mut i = input();
        i.service_name = "s".repeat(MAX_SERVICE_NAME_LEN);
        i.username = "u".repeat(MAX_USERNAME_LEN);
        i.url = "x".repeat(MAX_URL_LEN);
        i.category = "c".repeat(MAX_CATEGORY_LEN);
        i.password = "p".repeat(MAX_PASSWORD_LEN);
        i.notes = "n".repeat(MAX_NOTES_LEN);
        assert_eq!(validate_input(&i), Ok(()));
    }

    #[test]
    fn rejects_over_cap_values_naming_the_max() {
        let mut i = input();
        i.service_name = "s".repeat(MAX_SERVICE_NAME_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong {
                max: MAX_SERVICE_NAME_LEN
            })
        );

        let mut i = input();
        i.username = "u".repeat(MAX_USERNAME_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong {
                max: MAX_USERNAME_LEN
            })
        );

        let mut i = input();
        i.url = "x".repeat(MAX_URL_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong { max: MAX_URL_LEN })
        );

        let mut i = input();
        i.category = "c".repeat(MAX_CATEGORY_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong {
                max: MAX_CATEGORY_LEN
            })
        );

        let mut i = input();
        i.password = "p".repeat(MAX_PASSWORD_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong {
                max: MAX_PASSWORD_LEN
            })
        );

        let mut i = input();
        i.notes = "n".repeat(MAX_NOTES_LEN + 1);
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong { max: MAX_NOTES_LEN })
        );
    }

    #[test]
    fn caps_count_chars_not_bytes() {
        // A multi-byte character counts once: 129 two-byte chars fit in the
        // 256-char service_name cap (the byte length is irrelevant).
        let mut i = input();
        i.service_name = "é".repeat(MAX_SERVICE_NAME_LEN + 1); // 2 bytes each
        assert_eq!(
            validate_input(&i),
            Err(ValidationError::FieldTooLong {
                max: MAX_SERVICE_NAME_LEN
            })
        );
        let mut i = input();
        i.service_name = "é".repeat(MAX_SERVICE_NAME_LEN);
        assert_eq!(validate_input(&i), Ok(()));
    }
}
