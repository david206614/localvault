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
import { CreateVault } from "../views/CreateVault";

const mockApi = vi.mocked(api);

beforeEach(() => {
  vi.resetAllMocks();
  useSessionStore.setState({
    status: "NoVault",
    credentials: [],
    error: null,
    loading: false,
  });
  useUiStore.setState({ toasts: [] });
});

/** Get the password input by its id (avoids label ambiguity with eye-toggle button). */
function getPwInput() {
  return document.getElementById("pw") as HTMLInputElement;
}
function getPwConfirmInput() {
  return document.getElementById("pw-confirm") as HTMLInputElement;
}

describe("CreateVault", () => {
  it("renders two password fields and a submit button", () => {
    render(<CreateVault />);
    expect(getPwInput()).toBeInTheDocument();
    expect(getPwConfirmInput()).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "create.submit" })).toBeInTheDocument();
  });

  it("calls createVault on submit with matching passwords", async () => {
    const user = userEvent.setup();
    mockApi.createVault.mockResolvedValue(undefined);
    mockApi.listCredentials.mockResolvedValue([]);

    render(<CreateVault />);

    await user.type(getPwInput(), "MyP@ss123456");
    await user.type(getPwConfirmInput(), "MyP@ss123456");
    await user.click(screen.getByRole("button", { name: "create.submit" }));

    expect(mockApi.createVault).toHaveBeenCalledWith("MyP@ss123456", "MyP@ss123456");
  });

  it("shows validation policy hints", () => {
    render(<CreateVault />);
    expect(screen.getByText("create.policy.length")).toBeInTheDocument();
    expect(screen.getByText("create.policy.uppercase")).toBeInTheDocument();
    expect(screen.getByText("create.policy.lowercase")).toBeInTheDocument();
    expect(screen.getByText("create.policy.digit")).toBeInTheDocument();
    expect(screen.getByText("create.policy.symbol")).toBeInTheDocument();
  });

  it("shows loading text when loading=true", () => {
    useSessionStore.setState({ loading: true });
    render(<CreateVault />);
    expect(screen.getByRole("button", { name: "create.creating" })).toBeDisabled();
  });

  it("shows validation error on validation failure", async () => {
    const user = userEvent.setup();
    const err = { code: "validation", key: "errors.passwords_mismatch", message: "no match" };
    mockApi.createVault.mockRejectedValue(err);

    render(<CreateVault />);

    await user.type(getPwInput(), "short");
    await user.type(getPwConfirmInput(), "different");
    await user.click(screen.getByRole("button", { name: "create.submit" }));

    expect(screen.getByText("errors.passwords_mismatch")).toBeInTheDocument();
  });

  it("shows opaque error on unlock_failed (via createVault error)", async () => {
    const user = userEvent.setup();
    const err = { code: "unlock_failed", key: "errors.unlock_failed", message: "failed" };
    mockApi.createVault.mockRejectedValue(err);

    render(<CreateVault />);

    await user.type(getPwInput(), "MyP@ss123456");
    await user.type(getPwConfirmInput(), "MyP@ss123456");
    await user.click(screen.getByRole("button", { name: "create.submit" }));

    // unlock_failed is not validation → should show as toast
    const toasts = useUiStore.getState().toasts;
    expect(toasts.length).toBeGreaterThan(0);
    expect(toasts[0]!.message).toBe("errors.unlock_failed");
  });

  it("shows toast on internal error", async () => {
    const user = userEvent.setup();
    mockApi.createVault.mockRejectedValue(new Error("something"));

    render(<CreateVault />);

    await user.type(getPwInput(), "MyP@ss123456");
    await user.type(getPwConfirmInput(), "MyP@ss123456");
    await user.click(screen.getByRole("button", { name: "create.submit" }));

    const toasts = useUiStore.getState().toasts;
    expect(toasts.length).toBeGreaterThan(0);
    expect(toasts[0]!.type).toBe("error");
  });

  it("submit is disabled during loading", () => {
    useSessionStore.setState({ loading: true });
    render(<CreateVault />);
    expect(screen.getByRole("button", { name: "create.creating" })).toBeDisabled();
  });
});
