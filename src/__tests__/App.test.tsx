import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

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

// Mock theme module
vi.mock("../lib/theme", () => ({
  getSystemTheme: vi.fn(),
  onThemeChanged: vi.fn(),
  applyTheme: vi.fn(),
}));

import * as api from "../lib/api";
import * as theme from "../lib/theme";
import { useSessionStore } from "../stores/session";
import { useUiStore } from "../stores/ui";
import { App } from "../App";

const mockApi = vi.mocked(api);
const mockTheme = vi.mocked(theme);

beforeEach(() => {
  vi.resetAllMocks();
  // Re-mock theme functions after resetAllMocks clears implementations
  mockTheme.getSystemTheme.mockResolvedValue("dark");
  mockTheme.onThemeChanged.mockResolvedValue(() => {});
  mockTheme.applyTheme.mockImplementation(() => {});
  useSessionStore.setState({
    status: "Locked",
    credentials: [],
    error: null,
    loading: false,
  });
  useUiStore.setState({ toasts: [] });
  mockApi.vaultStatus.mockResolvedValue("Locked");
  mockApi.listCredentials.mockResolvedValue([]);
});

describe("App — vault_status routing", () => {
  it("NoVault → renders CreateVault", () => {
    useSessionStore.setState({ status: "NoVault" });
    render(<App />);
    expect(screen.getByText("create.title")).toBeInTheDocument();
  });

  it("Locked → renders Unlock", async () => {
    useSessionStore.setState({ status: "Locked" });
    render(<App />);
    // App calls fetchStatus on mount → brief loading gate → then Unlock renders
    expect(await screen.findByText("unlock.title")).toBeInTheDocument();
  });

  it("Unlocked → renders VaultList", () => {
    useSessionStore.setState({ status: "Unlocked" });
    render(<App />);
    expect(screen.getByText("list.title")).toBeInTheDocument();
  });
});
