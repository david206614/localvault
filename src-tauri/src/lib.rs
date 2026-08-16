//! LocalVault — local-first, offline password manager.
//!
//! Layered Rust core behind a thin Tauri shell:
//! `crypto -> store -> vault -> credential`.
//!
//! The `app` feature (off by default) enables the Tauri UI shell, which
//! requires the platform webview at build time. The core modules never
//! depend on Tauri, so `cargo test`, `cargo clippy` and `cargo build` run
//! without it.

pub mod credential;
pub mod crypto;
pub mod error;
pub mod store;
pub mod vault;

#[cfg(feature = "app")]
pub mod commands;

/// Launches the desktop application (only when the `app` feature is on).
#[cfg(feature = "app")]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running LocalVault");
}
