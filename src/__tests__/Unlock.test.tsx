import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Mock Tauri APIs
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: vi.fn(() => ({
    theme: vi.fn().mockResolvedValue("dark"),
    onThemeChanged: vi.fn().mockResolvedValue(() => {}),
  })),
}));

// Mock i18n
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { language: "en", changeLanguage: vi.fn() },
  }),
  Trans: ({ children }: { children: React.ReactNode }) => children,
  initReactI18next: { type: "3rdParty", init: vi.fn() },
}));

// Mock api module
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
  toAppError: (err: unknown) => {
    if (typeof err === "object" && err !== null && "code" in err) return err;
    return { code: "internal", key: "errors.internal", message: String(err) };
  },
}));

import * as api from "../lib/api";
import { useSessionStore } from "../stores/session";
import { useUiStore } from "../stores/ui";
import { Unlock } from "../views/Unlock";

const mockApi = vi.mocked(api);

beforeEach(() => {
  vi.resetAllMocks();
  useSessionStore.setState({
    status: "Locked",
    credentials: [],
    error: null,
    loading: false,
  });
  useUiStore.setState({ toasts: [] });
});

describe("Unlock", () => {
  it("renders single password field and unlock button", () => {
    render(<Unlock />);
    expect(screen.getByLabelText("unlock.password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "unlock.submit" })).toBeInTheDocument();
  });

  it("calls unlock on submit", async () => {
    const user = userEvent.setup();
    mockApi.unlock.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([]);

    render(<Unlock />);

    await user.type(screen.getByLabelText("unlock.password"), "correct-pw");
    await user.click(screen.getByRole("button", { name: "unlock.submit" }));

    expect(mockApi.unlock).toHaveBeenCalledWith("correct-pw");
  });

  it("shows spinner/loading during loading", () => {
    useSessionStore.setState({ loading: true });
    render(<Unlock />);
    expect(screen.getByRole("button", { name: "unlock.unlocking" })).toBeDisabled();
  });

  it("shows opaque error on unlock_failed (always the SAME i18n key)", async () => {
    const user = userEvent.setup();
    const err = { code: "unlock_failed", key: "errors.unlock_failed", message: "wrong pw" };
    mockApi.unlock.mockRejectedValue(err);

    render(<Unlock />);

    await user.type(screen.getByLabelText("unlock.password"), "wrong");
    await user.click(screen.getByRole("button", { name: "unlock.submit" }));

    // CRY-04: always shows errors.unlock_failed regardless of cause
    expect(screen.getByText("errors.unlock_failed")).toBeInTheDocument();
  });

  it("shows opaque error on wrong password (same unlock_failed message)", async () => {
    const user = userEvent.setup();
    // Simulate different underlying error but still unlock_failed code
    const err = { code: "unlock_failed", key: "errors.unlock_failed", message: "auth failed" };
    mockApi.unlock.mockRejectedValue(err);

    render(<Unlock />);

    await user.type(screen.getByLabelText("unlock.password"), "bad");
    await user.click(screen.getByRole("button", { name: "unlock.submit" }));

    // Same message regardless of cause
    expect(screen.getByText("errors.unlock_failed")).toBeInTheDocument();
  });

  it("shows internal error as inline message (not toast)", async () => {
    const user = userEvent.setup();
    mockApi.unlock.mockRejectedValue(new Error("something"));

    render(<Unlock />);

    await user.type(screen.getByLabelText("unlock.password"), "pw");
    await user.click(screen.getByRole("button", { name: "unlock.submit" }));

    // Internal errors show as inline error via setUnlockError, not toast
    expect(screen.getByText("errors.internal")).toBeInTheDocument();
    // No toast should be added
    expect(useUiStore.getState().toasts).toHaveLength(0);
  });

  it("submit is disabled during loading", () => {
    useSessionStore.setState({ loading: true });
    render(<Unlock />);
    expect(screen.getByRole("button", { name: "unlock.unlocking" })).toBeDisabled();
  });
});
