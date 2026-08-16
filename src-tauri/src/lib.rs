//! LocalVault — local-first, offline password manager.
//!
//! Layered Rust core behind a thin Tauri shell:
//! `crypto -> store -> vault -> credential -> commands`.
//!
//! The `app` feature (off by default) enables the Tauri UI shell, which
//! requires the platform webview at build time. The core modules never
//! depend on Tauri, so `cargo test`, `cargo clippy` and `cargo build` run
//! without it — the command LOGIC lives in `commands` (Tauri-free, fully
//! tested), and only the `#[tauri::command]` wrappers inside it need the
//! feature.

pub mod commands;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod store;
pub mod vault;

/// Launches the desktop application (only when the `app` feature is on).
///
/// Manages the single shared session (`Arc<Mutex<VaultSession>>`) every
/// command serializes through — one session, one SQLCipher connection
/// (concurrent writers would hit SQLITE_BUSY by design).
#[cfg(feature = "app")]
pub fn run() {
    use std::sync::{Arc, Mutex};

    let session = Arc::new(Mutex::new(vault::VaultSession::new(
        store::default_vault_dir().expect("failed to resolve the vault directory"),
    )));
    tauri::Builder::default()
        .manage(session)
        .invoke_handler(tauri::generate_handler![
            commands::tauri::create_vault,
            commands::tauri::unlock,
            commands::tauri::lock,
            commands::tauri::vault_status,
            commands::tauri::list_credentials,
            commands::tauri::get_credential,
            commands::tauri::create_credential,
            commands::tauri::update_credential,
            commands::tauri::delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LocalVault");
}
