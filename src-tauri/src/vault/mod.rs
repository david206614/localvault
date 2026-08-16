//! Vault session lifecycle (task 2.2): create, unlock, lock.
//!
//! The session owns the vault state machine `NoVault / Locked / Unlocked`
//! (SES-01..SES-05) plus the open store and the in-memory derived key:
//!
//! - `create` — policy-validated (≥12 chars + character classes, SES-01),
//!   password-twice (SES-02), derives the key, writes `vault.meta` + the
//!   encrypted DB, and ends Unlocked.
//! - `unlock` — reads meta, re-derives, verifier-check (CRY-04), opens the
//!   store; EVERY failure collapses to one opaque `UnlockFailed` (no oracle:
//!   wrong password, tampered meta, corrupt pages are indistinguishable).
//! - `lock` — drops the store (SQLCipher releases its key) and zeroizes the
//!   derived key (CRY-02, SES-04); CRUD is gated on Unlocked (SES-05).
//!
//! The KDF is the only blocking-heavy step, so `unlock`/`create` are
//! synchronous core functions that callers (the Tauri command layer, 3.2)
//! MUST run on a blocking thread (`tauri::async_runtime::spawn_blocking`).
//! The core itself stays Tauri-free so `cargo test`/`build` need no webview.

mod create;
mod session;
mod unlock;

pub use session::{PolicyError, SessionState, VaultError, VaultSession};
