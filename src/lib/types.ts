// API types — mirrors the Rust serde contract from:
//   src-tauri/src/error.rs       (AppError { code, key, message })
//   src-tauri/src/credential/model.rs  (CredentialInput, CredentialView)
//   src-tauri/src/vault/session.rs     (SessionState enum)

export interface AppError {
  code: string;
  key: string;
  message: string;
}

export interface CredentialInput {
  service_name: string;
  username: string;
  password: string;
  url: string;
  category: string;
  notes: string;
}

export interface CredentialView {
  id: number;
  service_name: string;
  username: string;
  password: string;
  url: string;
  category: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

export type SessionState = "NoVault" | "Locked" | "Unlocked";

// Field length caps from src-tauri/src/credential/validate.rs
export const FIELD_CAPS = {
  service_name: 256,
  username: 256,
  url: 2048,
  category: 128,
  password: 4096,
  notes: 16384,
} as const;
