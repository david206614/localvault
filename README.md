# LocalVault

> Encrypted password manager for Linux — 100% local, zero cloud, zero tracking.

LocalVault stores your credentials in an encrypted vault protected by a master password. Built with **Rust + Tauri 2** for security and performance, using **SQLCipher** for at-rest encryption and **Argon2id** for key derivation.

## Features

- **Encrypted vault** — credentials stored with SQLCipher (AES-256), derived from Argon2id (m=64MiB, t=3, p=4)
- **Zero-knowledge design** — master password never stored; only the derived key lives in memory (zeroized on lock)
- **No oracle** — wrong password, tampered vault, and corrupt database all produce the same error (no information leakage)
- **Credential CRUD** — create, edit, delete, and list credentials with fields: service, username, password, URL, category, notes
- **Dark/Light theme** — follows system theme with live reactivity
- **i18n** — English and Spanish (neutral) with runtime language switching
- **Fast** — Rust backend with async KDF on blocking threads; UI never freezes

## Installation

### Quick install (Arch Linux)

```bash
curl -sSL https://raw.githubusercontent.com/david206614/localvault/main/scripts/install.sh | bash
```

Or clone and run locally:

```bash
git clone https://github.com/david206614/localvault.git
cd localvault
bash scripts/install.sh
```

The installer will:
1. Detect Arch Linux and install system dependencies (`webkit2gtk-4.1`, `gtk3`, `openssl`, etc.)
2. Build the frontend (React + Vite)
3. Build the Tauri release binary
4. Install to `~/.local/bin/localvault`
5. Create a desktop entry (find it in your application menu)

### Manual install

<details>
<summary>Step by step</summary>

**Prerequisites:**

```bash
# Arch Linux
sudo pacman -S base-devel rust nodejs npm webkit2gtk-4.1 gtk3 openssl libsoup3 librsvg hicolor-icon-theme pkg-config
```

**Build:**

```bash
git clone https://github.com/david206614/localvault.git
cd localvault

# Frontend
npm ci
npm run build

# Tauri binary
cd src-tauri
cargo build --release --features app
```

**Install:**

```bash
mkdir -p ~/.local/bin
cp src-tauri/target/release/localvault ~/.local/bin/
chmod +x ~/.local/bin/localvault
```

Make sure `~/.local/bin` is in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

</details>

### From AUR (Arch)

A `PKGBUILD` is included for building with `makepkg`:

```bash
git clone https://github.com/david206614/localvault.git
cd localvault/packaging
makepkg -si
```

## Usage

1. **First run** — LocalVault detects no vault and shows the "Create Vault" screen
2. **Create vault** — enter a master password (min 12 characters, must include uppercase, lowercase, numbers, and symbols)
3. **Unlock** — enter your master password to access the vault
4. **Manage credentials** — create, edit, or delete credentials. Password field is optional (CRU-06)
5. **Lock** — click "Lock" to close the vault and wipe the key from memory

### Keyboard shortcuts

- `Enter` — submit forms (create vault, unlock, save credential)
- `Escape` — close dialogs, cancel edits

## Architecture

```
Frontend (React 19 + TypeScript)
    ↓ Tauri IPC
Commands (Rust, spawn_blocking for KDF)
    ↓
Core: crypto → store → vault → credential
    ↓
SQLCipher (encrypted SQLite)
```

### Security layers

| Layer | Mechanism | Protects against |
|-------|-----------|-----------------|
| Key derivation | Argon2id (64 MiB, 3 iterations, 4 threads) | Brute-force attacks |
| Key verification | HMAC-SHA256 verifier in vault.meta | Wrong password detection |
| Storage encryption | SQLCipher (AES-256, HMAC-SHA512 per-page) | Data theft from disk |
| Memory hygiene | `cipher_memory_security = ON` + Zeroizing | Heap key recovery |
| No oracle | Single opaque error for all unlock failures | Password/tamper discrimination |
| File permissions | 0700 (dir), 0600 (files) | Local user access |

## Development

```bash
# Prerequisites (Arch)
sudo pacman -S base-devel rust nodejs npm webkit2gtk-4.1 gtk3 openssl

# Clone
git clone https://github.com/david206614/localvault.git
cd localvault

# Frontend
npm ci
npm run dev          # Vite dev server (for UI development)

# Rust backend
cd src-tauri
cargo test           # Run all tests (fast KDF params)
cargo clippy --all-targets -- -D warnings  # Lint

# Full build
cd ..
npm run build
cd src-tauri
cargo tauri build --features app
```

### Testing

| Layer | Command | Count |
|-------|---------|-------|
| Rust unit + integration | `cargo test` | 135 |
| Frontend (Vitest) | `npx vitest run` | 95 |
| **Total** | | **230** |

## Project structure

```
localvault/
├── .github/workflows/ci.yml    ← CI (ubuntu-22.04)
├── packaging/
│   ├── PKGBUILD                ← Arch Linux package
│   └── localvault.desktop      ← Desktop entry
├── scripts/
│   └── install.sh              ← One-line installer
├── src/                        ← Frontend (React + TS)
│   ├── views/                  ← 5 views
│   ├── stores/                 ← Zustand state
│   ├── lib/                    ← API layer, types
│   ├── i18n/                   ← English + Spanish
│   └── __tests__/              ← 95 Vitest tests
├── src-tauri/                  ← Rust backend
│   ├── src/crypto/             ← Argon2id, HMAC, VaultKey
│   ├── src/store/              ← SQLCipher encrypted store
│   ├── src/vault/              ← Session state machine
│   ├── src/credential/         ← CRUD + validation
│   ├── src/commands.rs         ← Tauri command layer
│   └── tests/integration.rs    ← 18 integration tests
└── README.md
```

## Roadmap

- [ ] Password generator (RF-04)
- [ ] Search and filter (RF-05)
- [ ] Clipboard integration with auto-clear (RF-07)
- [ ] Master password change with re-encryption (RF-08)
- [ ] Encrypted backup/restore (RF-09)
- [ ] Auto-lock on inactivity (RF-02)
- [ ] E2E tests with tauri-driver

## Tech stack

- **Backend:** Rust + Tauri 2
- **Cryptography:** RustCrypto (argon2, hmac, sha2, zeroize)
- **Storage:** SQLCipher via rusqlite (bundled-sqlcipher-vendored-openssl)
- **Frontend:** React 19 + TypeScript + Vite 6
- **State:** Zustand
- **i18n:** i18next (English + Spanish)
- **Testing:** cargo test + Vitest
- **CI:** GitHub Actions (ubuntu-22.04)

## License

This project is part of an academic thesis at UNIAJC (Institución Universitaria Antonio José Camacho), Cali, Colombia.

## Acknowledgments

- Director: Héctor Exequiel Rosero Montaño
- Institution: UNIAJC — Facultad de Ingeniería, Ingeniería de Sistemas
