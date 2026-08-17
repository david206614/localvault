// Build script for the Tauri application shell.
//
// `tauri_build::build()` validates `tauri.conf.json` and prepares the app
// context. It only runs when the `app` feature is enabled: the shell needs
// the system webview, while the core (crypto/store/vault/credential) is
// built and tested without it.
fn main() {
    #[cfg(feature = "app")]
    tauri_build::build();
}
