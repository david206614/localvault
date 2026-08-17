import { invoke } from "@tauri-apps/api/core";
import type { AppError, CredentialInput, CredentialView, SessionState } from "./types";

// All invoke wrappers are typed to match the Rust command signatures exactly.
// Serde field names are lowercase_snake_case (Rust defaults).
// Errors are always AppError (code, key, message).

export async function vaultStatus(): Promise<SessionState> {
  return invoke<SessionState>("vault_status");
}

export async function createVault(password: string, confirm: string): Promise<void> {
  return invoke<void>("create_vault", { password, confirm });
}

export async function unlock(password: string): Promise<void> {
  return invoke<void>("unlock", { password });
}

export async function lockVault(): Promise<void> {
  return invoke<void>("lock");
}

export async function listCredentials(): Promise<CredentialView[]> {
  return invoke<CredentialView[]>("list_credentials");
}

export async function getCredential(id: number): Promise<CredentialView> {
  return invoke<CredentialView>("get_credential", { id });
}

export async function createCredential(input: CredentialInput): Promise<CredentialView> {
  return invoke<CredentialView>("create_credential", { input });
}

export async function updateCredential(
  id: number,
  input: CredentialInput,
): Promise<CredentialView> {
  return invoke<CredentialView>("update_credential", { id, input });
}

export async function deleteCredential(id: number): Promise<void> {
  return invoke<void>("delete_credential", { id });
}

// ---------- Error helpers ----------

export function isAppError(err: unknown): err is AppError {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    "key" in err &&
    "message" in err
  );
}

/** Extract an AppError from an unknown catch — returns generic internal if unrecognizable. */
export function toAppError(err: unknown): AppError {
  if (isAppError(err)) return err;
  return { code: "internal", key: "errors.internal", message: String(err) };
}
