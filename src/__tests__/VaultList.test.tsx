import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CredentialView } from "../lib/types";

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
import { VaultList } from "../views/VaultList";

const mockApi = vi.mocked(api);

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

beforeEach(() => {
  vi.resetAllMocks();
  useSessionStore.setState({
    status: "Unlocked",
    credentials: [view],
    error: null,
    loading: false,
  });
  useUiStore.setState({ toasts: [] });
});

describe("VaultList", () => {
  it("renders list of credentials with service_name, username, and category", () => {
    render(<VaultList />);
    expect(screen.getByText("github")).toBeInTheDocument();
    expect(screen.getByText("octocat")).toBeInTheDocument();
    expect(screen.getByText("dev")).toBeInTheDocument();
  });

  it("renders empty state when list is empty", () => {
    useSessionStore.setState({ credentials: [] });
    render(<VaultList />);
    expect(screen.getByText("list.empty")).toBeInTheDocument();
  });

  it("delete: click delete → ConfirmDialog opens → confirm → deleteCredential called → toast", async () => {
    const user = userEvent.setup();
    mockApi.deleteCredential.mockResolvedValue(undefined);

    render(<VaultList />);

    // Click delete button
    await user.click(screen.getByLabelText("list.delete"));

    // ConfirmDialog should open
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("confirm.message")).toBeInTheDocument();

    // Click confirm
    await user.click(screen.getByText("confirm.yes"));

    expect(mockApi.deleteCredential).toHaveBeenCalledWith(1);
    const toasts = useUiStore.getState().toasts;
    expect(toasts.some((t) => t.message === "toast.credential_deleted")).toBe(true);
  });

  it("delete double-click protection: confirm button is disabled during loading", async () => {
    const user = userEvent.setup();
    // Make deleteCredential hang (never resolve) to keep loading state
    mockApi.deleteCredential.mockReturnValue(new Promise(() => {}));

    render(<VaultList />);

    // Click delete
    await user.click(screen.getByLabelText("list.delete"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    // Click confirm — button should become disabled
    const confirmBtn = screen.getByText("confirm.yes");
    await user.click(confirmBtn);

    // After click, confirm button should be disabled (loading state)
    expect(confirmBtn).toBeDisabled();
  });

  it("edit: click edit opens CredentialForm", async () => {
    const user = userEvent.setup();
    render(<VaultList />);

    await user.click(screen.getByLabelText("list.edit"));

    // CredentialForm should render with edit title
    expect(screen.getByText("form.edit_title")).toBeInTheDocument();
  });

  it("search placeholder renders", () => {
    render(<VaultList />);
    expect(screen.getByPlaceholderText("list.search")).toBeInTheDocument();
  });

  it("renders credential details when expanded", async () => {
    const user = userEvent.setup();
    render(<VaultList />);

    // Click eye to expand
    await user.click(screen.getByLabelText("list.show_password"));

    expect(screen.getByText(view.password)).toBeInTheDocument();
    expect(screen.getByText(view.url!)).toBeInTheDocument();
    expect(screen.getByText(view.notes!)).toBeInTheDocument();
  });
});
