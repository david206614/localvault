import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock @tauri-apps/api/core before importing api.ts
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import {
  vaultStatus,
  createVault,
  unlock,
  lockVault,
  listCredentials,
  getCredential,
  createCredential,
  updateCredential,
  deleteCredential,
  isAppError,
  toAppError,
} from "../lib/api";
import type { CredentialInput, CredentialView, AppError } from "../lib/types";

const mockInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("api — vault lifecycle", () => {
  it("vaultStatus returns SessionState", async () => {
    mockInvoke.mockResolvedValue("Locked");
    const result = await vaultStatus();
    expect(result).toBe("Locked");
    expect(mockInvoke).toHaveBeenCalledWith("vault_status");
  });

  it("createVault sends password + confirm", async () => {
    mockInvoke.mockResolvedValue(undefined);
    await createVault("s3cret!ABC123", "s3cret!ABC123");
    expect(mockInvoke).toHaveBeenCalledWith("create_vault", {
      password: "s3cret!ABC123",
      confirm: "s3cret!ABC123",
    });
  });

  it("unlock sends password", async () => {
    mockInvoke.mockResolvedValue(undefined);
    await unlock("mypass");
    expect(mockInvoke).toHaveBeenCalledWith("unlock", { password: "mypass" });
  });

  it("lockVault calls lock", async () => {
    mockInvoke.mockResolvedValue(undefined);
    await lockVault();
    expect(mockInvoke).toHaveBeenCalledWith("lock");
  });
});

describe("api — credential CRUD", () => {
  const input: CredentialInput = {
    service_name: "github",
    username: "octocat",
    password: "s3cret!",
    url: "https://github.com",
    category: "dev",
    notes: "work",
  };

  const view: CredentialView = {
    id: 1,
    ...input,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };

  it("listCredentials returns array", async () => {
    mockInvoke.mockResolvedValue([view]);
    const result = await listCredentials();
    expect(result).toEqual([view]);
    expect(mockInvoke).toHaveBeenCalledWith("list_credentials");
  });

  it("getCredential sends id", async () => {
    mockInvoke.mockResolvedValue(view);
    const result = await getCredential(1);
    expect(result).toEqual(view);
    expect(mockInvoke).toHaveBeenCalledWith("get_credential", { id: 1 });
  });

  it("createCredential sends input", async () => {
    mockInvoke.mockResolvedValue(view);
    const result = await createCredential(input);
    expect(result).toEqual(view);
    expect(mockInvoke).toHaveBeenCalledWith("create_credential", { input });
  });

  it("updateCredential sends id + input", async () => {
    mockInvoke.mockResolvedValue({ ...view, notes: "updated" });
    const result = await updateCredential(1, input);
    expect(result.notes).toBe("updated");
    expect(mockInvoke).toHaveBeenCalledWith("update_credential", { id: 1, input });
  });

  it("deleteCredential sends id", async () => {
    mockInvoke.mockResolvedValue(undefined);
    await deleteCredential(1);
    expect(mockInvoke).toHaveBeenCalledWith("delete_credential", { id: 1 });
  });
});

describe("api — error helpers", () => {
  it("isAppError identifies AppError shape", () => {
    const err: AppError = { code: "internal", key: "errors.internal", message: "nope" };
    expect(isAppError(err)).toBe(true);
    expect(isAppError(new Error("nope"))).toBe(false);
    expect(isAppError(null)).toBe(false);
  });

  it("toAppError passes through AppError", () => {
    const err: AppError = { code: "locked", key: "errors.vault_locked", message: "locked" };
    expect(toAppError(err)).toBe(err);
  });

  it("toAppError wraps unknown errors as internal", () => {
    const result = toAppError("something broke");
    expect(result.code).toBe("internal");
    expect(result.key).toBe("errors.internal");
  });
});
