import { describe, it, expect, vi, beforeEach } from "vitest";
import { useSessionStore } from "../stores/session";

// Mock the API module
vi.mock("../lib/api", () => ({
  vaultStatus: vi.fn(),
  createVault: vi.fn(),
  unlock: vi.fn(),
  lockVault: vi.fn(),
  listCredentials: vi.fn(),
  getCredential: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
  deleteCredential: vi.fn(),
  toAppError: vi.fn((err: unknown) => ({
    code: "internal",
    key: "errors.internal",
    message: String(err),
  })),
}));

import * as api from "../lib/api";
import type { CredentialView, CredentialInput } from "../lib/types";

const mockApi = vi.mocked(api);

beforeEach(() => {
  vi.resetAllMocks();
  useSessionStore.setState({
    status: "Locked",
    credentials: [],
    error: null,
    loading: false,
  });
});

const view: CredentialView = {
  id: 1,
  service_name: "github",
  username: "octocat",
  password: "s3cret!",
  url: "https://github.com",
  category: "dev",
  notes: "work",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("session store — fetchStatus", () => {
  it("sets status from vault_status", async () => {
    mockApi.vaultStatus.mockResolvedValue("Locked");
    await useSessionStore.getState().fetchStatus();
    expect(useSessionStore.getState().status).toBe("Locked");
    expect(useSessionStore.getState().loading).toBe(false);
  });

  it("fetches credentials when Unlocked", async () => {
    mockApi.vaultStatus.mockResolvedValue("Unlocked");
    mockApi.listCredentials.mockResolvedValue([view]);
    await useSessionStore.getState().fetchStatus();
    expect(useSessionStore.getState().credentials).toEqual([view]);
  });
});

describe("session store — createVault", () => {
  it("creates vault and fetches credentials", async () => {
    mockApi.createVault.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([view]);
    await useSessionStore.getState().createVault("pw123!ABCdef", "pw123!ABCdef");
    expect(useSessionStore.getState().status).toBe("Unlocked");
    expect(useSessionStore.getState().credentials).toEqual([view]);
  });

  it("sets error on failure", async () => {
    const err = { code: "validation", key: "errors.passwords_mismatch", message: "no match" };
    mockApi.createVault.mockRejectedValue(err);
    mockApi.toAppError.mockReturnValue(err);
    await expect(
      useSessionStore.getState().createVault("pw123!ABCdef", "wrong"),
    ).rejects.toEqual(err);
    expect(useSessionStore.getState().error).toEqual(err);
  });
});

describe("session store — unlock", () => {
  it("unlocks and loads credentials", async () => {
    mockApi.unlock.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([view]);
    await useSessionStore.getState().unlock("correct");
    expect(useSessionStore.getState().status).toBe("Unlocked");
    expect(useSessionStore.getState().credentials).toEqual([view]);
  });

  it("sets error on failure (CRY-04 opaque)", async () => {
    const err = { code: "unlock_failed", key: "errors.unlock_failed", message: "unable" };
    mockApi.unlock.mockRejectedValue(err);
    mockApi.toAppError.mockReturnValue(err);
    await expect(useSessionStore.getState().unlock("wrong")).rejects.toEqual(err);
    expect(useSessionStore.getState().error).toEqual(err);
  });
});

describe("session store — lock", () => {
  it("locks and clears credentials", async () => {
    mockApi.lockVault.mockResolvedValue(undefined);
    useSessionStore.setState({ status: "Unlocked", credentials: [view] });
    await useSessionStore.getState().lock();
    expect(useSessionStore.getState().status).toBe("Locked");
    expect(useSessionStore.getState().credentials).toEqual([]);
  });
});

describe("session store — credential CRUD", () => {
  const input: CredentialInput = {
    service_name: "github",
    username: "octocat",
    password: "s3cret!",
    url: "https://github.com",
    category: "dev",
    notes: "work",
  };

  it("createCredential adds to list", async () => {
    useSessionStore.setState({ credentials: [] });
    mockApi.createCredential.mockResolvedValue(view);
    const result = await useSessionStore.getState().createCredential(input);
    expect(result).toEqual(view);
    expect(useSessionStore.getState().credentials).toEqual([view]);
  });

  it("updateCredential replaces in list", async () => {
    const updated = { ...view, notes: "updated" };
    useSessionStore.setState({ credentials: [view] });
    mockApi.updateCredential.mockResolvedValue(updated);
    await useSessionStore.getState().updateCredential(1, input);
    expect(useSessionStore.getState().credentials[0]!.notes).toBe("updated");
  });

  it("deleteCredential removes from list", async () => {
    useSessionStore.setState({ credentials: [view] });
    mockApi.deleteCredential.mockResolvedValue(undefined);
    await useSessionStore.getState().deleteCredential(1);
    expect(useSessionStore.getState().credentials).toEqual([]);
  });

  it("fetchCredentials is a no-op when locked", async () => {
    useSessionStore.setState({ status: "Locked" });
    await useSessionStore.getState().fetchCredentials();
    expect(mockApi.listCredentials).not.toHaveBeenCalled();
  });
});

describe("session store — error code coverage", () => {
  it("no_vault error: vault_status returning no_vault sets error state", async () => {
    const err = { code: "no_vault", key: "errors.no_vault", message: "no vault" };
    mockApi.vaultStatus.mockRejectedValue(err);
    mockApi.toAppError.mockReturnValue(err);
    await useSessionStore.getState().fetchStatus();
    expect(useSessionStore.getState().error).toEqual(err);
    expect(useSessionStore.getState().loading).toBe(false);
  });

  it("locked error: lock failure sets error state", async () => {
    const err = { code: "locked", key: "errors.vault_locked", message: "locked" };
    mockApi.lockVault.mockRejectedValue(err);
    mockApi.toAppError.mockReturnValue(err);
    await useSessionStore.getState().lock();
    expect(useSessionStore.getState().error).toEqual(err);
  });

  it("not_found error: delete of nonexistent credential sets error state", async () => {
    const err = { code: "not_found", key: "errors.not_found", message: "gone" };
    useSessionStore.setState({ credentials: [view] });
    mockApi.deleteCredential.mockRejectedValue(err);
    mockApi.toAppError.mockReturnValue(err);
    await expect(useSessionStore.getState().deleteCredential(999)).rejects.toEqual(err);
    expect(useSessionStore.getState().error).toEqual(err);
  });

  it("NoVault→Unlocked state transition (first-run flow)", async () => {
    useSessionStore.setState({ status: "NoVault", credentials: [] });
    mockApi.createVault.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([view]);
    await useSessionStore.getState().createVault("pw123!ABCdef", "pw123!ABCdef");
    expect(useSessionStore.getState().status).toBe("Unlocked");
    expect(useSessionStore.getState().credentials).toEqual([view]);
  });

  it("Locked→Unlocked→Locked full lifecycle", async () => {
    useSessionStore.setState({ status: "Locked", credentials: [] });

    // Unlock
    mockApi.unlock.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([view]);
    await useSessionStore.getState().unlock("correct");
    expect(useSessionStore.getState().status).toBe("Unlocked");
    expect(useSessionStore.getState().credentials).toEqual([view]);

    // Lock
    mockApi.lockVault.mockResolvedValue(undefined);
    await useSessionStore.getState().lock();
    expect(useSessionStore.getState().status).toBe("Locked");
    expect(useSessionStore.getState().credentials).toEqual([]);
  });
});

describe("session store — W4 edge cases", () => {
  it("special characters in service_name round-trip through createCredential", async () => {
    const specialInput: CredentialInput = {
      service_name: "O'Reilly",
      username: "'; DROP TABLE--",
      password: "🔑 password",
      url: "",
      category: "test",
      notes: "edge case",
    };
    const specialView: CredentialView = {
      id: 42,
      ...specialInput,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
    useSessionStore.setState({ credentials: [] });
    mockApi.createCredential.mockResolvedValue(specialView);
    const result = await useSessionStore.getState().createCredential(specialInput);
    expect(result.service_name).toBe("O'Reilly");
    expect(result.username).toBe("'; DROP TABLE--");
    expect(result.password).toBe("🔑 password");
    expect(useSessionStore.getState().credentials[0]!.service_name).toBe("O'Reilly");
  });
});
