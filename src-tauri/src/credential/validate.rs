//! Credential input validation (CRU-06).

use super::model::CredentialInput;

/// Input-validation failures (CRU-06). Each variant names the failing rule so
/// the command layer can surface a stable, i18n-mappable error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// `service_name` must not be empty.
    EmptyServiceName,
    /// `username` must not be empty.
    EmptyUsername,
}

/// Validates credential input against CRU-06:
///
/// - `service_name` and `username` MUST be non-empty.
/// - `password` MAY be empty — never reject an empty password (CRU-06).
/// - `url`, `category`, `notes` are optional.
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
}
