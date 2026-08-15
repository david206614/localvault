//! LocalVault desktop binary entry point.
//!
//! This target is only built when the `app` feature is enabled (the Tauri
//! shell requires the platform webview). See `required-features` in
//! Cargo.toml.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    localvault_lib::run();
}
