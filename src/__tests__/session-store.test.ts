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
  vi.clearAllMocks();
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
