//! Session types and the state machine core (SES-01..SES-05).

use std::fmt;
use std::path::{Path, PathBuf};

use crate::crypto::VaultKey;
use crate::store::{self, Store, StoreError};

/// Session state machine.
///
/// `Serialize`: the `vault_status` command returns this to the frontend to
/// drive the first-run gate (SHE-01) — variants serialize as
/// `"NoVault" | "Locked" | "Unlocked"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SessionState {
    /// No vault exists at the session directory yet — first-run create gate
    /// (SHE-01).
    NoVault,
    /// A vault exists but is locked (or the session was started locked).
    Locked,
    /// Vault open; derived key in memory; CRUD allowed (SES-05).
    Unlocked,
}

/// Master-password policy failures (SES-01). Each variant NAMES the failing
/// rule so the UI can point the user at it instead of a generic rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// Fewer than `min` characters.
    TooShort { min: usize, actual: usize },
    /// No ASCII uppercase letter.
    MissingUppercase,
    /// No ASCII lowercase letter.
    MissingLowercase,
    /// No ASCII digit.
    MissingDigit,
    /// No symbol (non-alphanumeric, non-whitespace byte; note Unicode letters
    /// count as symbols under this ASCII-class policy).
    MissingSymbol,
}

/// Errors produced by the session layer.
///
/// `UnlockFailed` is the ONLY error an unlock attempt can return (besides
/// state-machine errors like `NoVault`): wrong password, tampered meta, and
/// corrupt pages all collapse to it — byte-identical, no oracle (CRY-04).
#[derive(Debug)]
pub enum VaultError {
    /// No vault exists (create is required).
    NoVault,
    /// A vault already exists (create called again).
    AlreadyExists,
    /// Store/CRUD access attempted while not Unlocked (SES-05).
    NotUnlocked,
    /// Master password fails the policy — names the rule (SES-01).
    Policy(PolicyError),
    /// Password and confirmation differ (SES-02).
    Mismatch,
    /// Opaque unlock failure (wrong password / tampered meta / corrupt DB).
    UnlockFailed,
    /// Storage-layer error during create (never surfaced on the unlock path).
    Store(StoreError),
    /// Crypto-layer error (e.g. invalid KDF params).
    Crypto(crate::crypto::CryptoError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::TooShort { min, actual } => write!(
                f,
                "password must be at least {min} characters (got {actual})"
            ),
            PolicyError::MissingUppercase => {
                write!(f, "password must contain at least one uppercase letter")
            }
            PolicyError::MissingLowercase => {
                write!(f, "password must contain at least one lowercase letter")
            }
            PolicyError::MissingDigit => {
                write!(f, "password must contain at least one digit")
            }
            PolicyError::MissingSymbol => {
                write!(f, "password must contain at least one symbol")
            }
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NoVault => write!(f, "no vault exists"),
            VaultError::AlreadyExists => write!(f, "a vault already exists"),
            VaultError::NotUnlocked => write!(f, "vault is locked"),
            VaultError::Policy(e) => write!(f, "{e}"),
            VaultError::Mismatch => write!(f, "passwords do not match"),
            VaultError::UnlockFailed => write!(f, "unlock failed"),
            VaultError::Store(e) => write!(f, "storage error: {e}"),
            VaultError::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

/// The vault session: state + open store + in-memory key (CRY-02).
///
/// Fields are `pub(super)`: the session's siblings (`vault::create`,
/// `vault::unlock`) mutate them through the lifecycle operations, while the
/// rest of the crate only sees the public API (`state`/`store`/`dir`/`lock`).
pub struct VaultSession {
    pub(super) dir: PathBuf,
    pub(super) state: SessionState,
    pub(super) store: Option<Store>,
    pub(super) key: Option<VaultKey>,
}

impl VaultSession {
    /// Starts a session at `dir` (injected path — tests never touch the real
    /// user data dir). Initial state follows whether a vault file exists.
    ///
    /// Reconciles the crash window between DB create and meta write (review
    /// fix R1): a keyed `vault.db` without `vault.meta` is unrecoverable by
    /// design (salt/verifier live only in the header), so the orphaned DB is
    /// removed and the session starts as `NoVault`, letting the user create a
    /// clean vault. Best-effort: if the removal fails (pathological IO) the
    /// session stays `Locked` and unlock fails opaquely.
    pub fn new(dir: PathBuf) -> Self {
        let _ = store::remove_orphaned_vault(&dir);
        let state = if store::vault_exists(&dir) {
            SessionState::Locked
        } else {
            SessionState::NoVault
        };
        Self {
            dir,
            state,
            store: None,
            key: None,
        }
    }

    /// Current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The vault directory this session operates on.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Locks the session (SES-04): drops the SQLCipher connection (releasing
    /// its key material) and zeroizes the derived key on drop (CRY-02).
    /// No-op unless a vault is currently open, so NoVault never regresses to
    /// Locked.
    pub fn lock(&mut self) {
        if self.state != SessionState::Unlocked {
            return;
        }
        self.state = SessionState::Locked;
        self.store = None;
        self.key = None;
    }

    /// Access to the open store — the CRUD gate (SES-05): every credential
    /// command must go through this and is rejected while locked.
    pub fn store(&self) -> Result<&Store, VaultError> {
        if self.state != SessionState::Unlocked {
            return match self.state {
                SessionState::NoVault => Err(VaultError::NoVault),
                _ => Err(VaultError::NotUnlocked),
            };
        }
        self.store.as_ref().ok_or(VaultError::NotUnlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KdfParams, FAST_TEST_M_KIB, FAST_TEST_P, FAST_TEST_T};
    use crate::store::{db_path, meta_path};

    fn fast_params() -> KdfParams {
        KdfParams::new(FAST_TEST_M_KIB, FAST_TEST_T, FAST_TEST_P)
    }

    fn policy_password() -> &'static [u8] {
        b"CorrectHorseBatteryStaple!1"
    }

    fn session_dir() -> std::path::PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    #[test]
    fn orphaned_db_without_meta_is_removed_and_create_allowed() {
        // Review fix R1: crash window between DB create and meta write (or a
        // deleted header). The keyed DB without meta is unrecoverable, so the
        // next session removes it and treats the vault as absent.
        let dir = session_dir();
        let mut s1 = VaultSession::new(dir.clone());
        s1.create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        // Simulate the crash: only the encrypted DB survives.
        std::fs::remove_file(meta_path(&dir)).unwrap();
        assert!(db_path(&dir).exists());

        let mut s2 = VaultSession::new(dir.clone());
        assert_eq!(s2.state(), SessionState::NoVault);
        assert!(!db_path(&dir).exists(), "orphaned DB must be removed");
        // Re-create from scratch works cleanly.
        s2.create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        assert_eq!(s2.state(), SessionState::Unlocked);
        assert!(meta_path(&dir).exists());
    }

    #[test]
    fn intact_vault_is_not_touched_by_session_start() {
        let dir = session_dir();
        let mut s1 = VaultSession::new(dir.clone());
        s1.create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        s1.lock();

        let s2 = VaultSession::new(dir.clone());
        assert_eq!(s2.state(), SessionState::Locked);
        assert!(db_path(&dir).exists());
        assert!(meta_path(&dir).exists());
    }

    #[test]
    fn corrupt_meta_does_not_trigger_orphan_cleanup() {
        // A present-but-corrupt header still describes a real vault: never
        // delete the DB on a read hiccup — surface the corruption instead.
        let dir = session_dir();
        let mut s1 = VaultSession::new(dir.clone());
        s1.create(policy_password(), policy_password(), &fast_params())
            .unwrap();
        s1.lock();
        std::fs::write(meta_path(&dir), b"{ not json !").unwrap();

        let s2 = VaultSession::new(dir.clone());
        assert_eq!(s2.state(), SessionState::Locked, "corrupt meta ≠ orphan");
        assert!(db_path(&dir).exists(), "DB must survive corrupt meta");
    }
}
