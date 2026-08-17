import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CredentialInput, CredentialView } from "../lib/types";
import { FIELD_CAPS } from "../lib/types";

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
    t: (key: string, opts?: Record<string, unknown>) => {
      if (opts?.max) return `${key}:${opts.max}`;
      return key;
    },
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

import { CredentialForm } from "../views/CredentialForm";

const existingCredential: CredentialView = {
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
  vi.clearAllMocks();
});

// Labels in CredentialForm are rendered as `{t("form.service_name")} *` for required fields.
// Use getByLabelText with regex to match the i18n key prefix (ignoring the ` *` suffix).
function svcInput() {
  return screen.getByLabelText(/form\.service_name/) as HTMLInputElement;
}
function usrInput() {
  return screen.getByLabelText(/form\.username/) as HTMLInputElement;
}
function pwInput() {
  return screen.getByLabelText(/^form\.password$/) as HTMLInputElement;
}
function urlInput() {
  return screen.getByLabelText(/form\.url/) as HTMLInputElement;
}
function catInput() {
  return screen.getByLabelText(/form\.category/) as HTMLInputElement;
}
function notesInput() {
  return screen.getByLabelText(/form\.notes/) as HTMLInputElement;
}

describe("CredentialForm", () => {
  describe("create mode", () => {
    it("renders empty form with 6 fields and save button", () => {
      render(<CredentialForm onSave={vi.fn()} onCancel={vi.fn()} />);
      expect(screen.getByText("form.create_title")).toBeInTheDocument();
      expect(svcInput()).toBeInTheDocument();
      expect(usrInput()).toBeInTheDocument();
      expect(pwInput()).toBeInTheDocument();
      expect(urlInput()).toBeInTheDocument();
      expect(catInput()).toBeInTheDocument();
      expect(notesInput()).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "form.save" })).toBeInTheDocument();
    });

    it("submit calls onSave with full object", async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      render(<CredentialForm onSave={onSave} onCancel={vi.fn()} />);

      await user.type(svcInput(), "myservice");
      await user.type(usrInput(), "myuser");
      await user.type(pwInput(), "mypass");
      await user.type(urlInput(), "https://example.com");
      await user.type(catInput(), "cat1");
      await user.type(notesInput(), "some notes");
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(onSave).toHaveBeenCalledWith({
        service_name: "myservice",
        username: "myuser",
        password: "mypass",
        url: "https://example.com",
        category: "cat1",
        notes: "some notes",
      } satisfies CredentialInput);
    });

    it("CRU-06: submit with EMPTY password succeeds (no validation error)", async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      render(<CredentialForm onSave={onSave} onCancel={vi.fn()} />);

      await user.type(svcInput(), "svc");
      await user.type(usrInput(), "usr");
      // Leave password empty
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ password: "" }),
      );
    });
  });

  describe("edit mode", () => {
    it("fields are pre-populated from credential prop", () => {
      render(
        <CredentialForm
          credential={existingCredential}
          onSave={vi.fn()}
          onCancel={vi.fn()}
        />,
      );
      expect(screen.getByText("form.edit_title")).toBeInTheDocument();
      expect(svcInput()).toHaveValue("github");
      expect(usrInput()).toHaveValue("octocat");
      expect(pwInput()).toHaveValue("s3cret!");
      expect(urlInput()).toHaveValue("https://github.com");
      expect(catInput()).toHaveValue("dev");
      expect(notesInput()).toHaveValue("work");
    });

    it("submit calls onSave with full object (REPLACE-NOT-MERGE)", async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      render(
        <CredentialForm
          credential={existingCredential}
          onSave={onSave}
          onCancel={vi.fn()}
        />,
      );

      // Clear url and notes (CRU-03 REPLACE-NOT-MERGE)
      await user.clear(urlInput());
      await user.clear(notesInput());
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          service_name: "github",
          username: "octocat",
          password: "s3cret!",
          url: "",
          category: "dev",
          notes: "",
        }),
      );
    });

    it("CRU-03: update with empty url+notes clears those fields", async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      render(
        <CredentialForm
          credential={existingCredential}
          onSave={onSave}
          onCancel={vi.fn()}
        />,
      );

      await user.clear(urlInput());
      await user.clear(notesInput());
      await user.click(screen.getByRole("button", { name: "form.save" }));

      const calledWith = onSave.mock.calls[0]![0] as CredentialInput;
      expect(calledWith.url).toBe("");
      expect(calledWith.notes).toBe("");
    });
  });

  describe("field caps", () => {
    it("inputs have maxLength from FIELD_CAPS", () => {
      render(<CredentialForm onSave={vi.fn()} onCancel={vi.fn()} />);
      expect(svcInput()).toHaveAttribute("maxlength", String(FIELD_CAPS.service_name));
      expect(usrInput()).toHaveAttribute("maxlength", String(FIELD_CAPS.username));
      expect(urlInput()).toHaveAttribute("maxlength", String(FIELD_CAPS.url));
      expect(catInput()).toHaveAttribute("maxlength", String(FIELD_CAPS.category));
    });

    it("accepts value at EXACTLY FIELD_CAPS boundary (256 chars)", async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const user = userEvent.setup();
      render(<CredentialForm onSave={onSave} onCancel={vi.fn()} />);

      const atLimit = "a".repeat(FIELD_CAPS.service_name);
      await user.type(svcInput(), atLimit);
      await user.type(usrInput(), "usr");
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ service_name: atLimit }),
      );
    });

    it("HTML maxLength is set correctly (256 for service_name)", () => {
      render(<CredentialForm onSave={vi.fn()} onCancel={vi.fn()} />);
      expect(svcInput()).toHaveAttribute("maxlength", "256");
    });
  });

  describe("validation errors", () => {
    it("AppError code validation maps to form field error display", async () => {
      const onSave = vi.fn().mockRejectedValue({
        code: "validation",
        key: "errors.empty_service_name",
        message: "service name required",
      });
      const user = userEvent.setup();
      render(<CredentialForm onSave={onSave} onCancel={vi.fn()} />);

      await user.type(svcInput(), "svc");
      await user.type(usrInput(), "usr");
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(screen.getByText("errors.empty_service_name")).toBeInTheDocument();
    });
  });

  describe("saving state", () => {
    it("submit button is disabled during saving", async () => {
      const user = userEvent.setup();
      // Make onSave hang to keep saving state
      const onSave = vi.fn().mockReturnValue(new Promise(() => {}));
      render(<CredentialForm onSave={onSave} onCancel={vi.fn()} />);

      await user.type(svcInput(), "svc");
      await user.type(usrInput(), "usr");
      await user.click(screen.getByRole("button", { name: "form.save" }));

      expect(screen.getByRole("button", { name: "form.save" })).toBeDisabled();
      expect(screen.getByRole("button", { name: "form.cancel" })).toBeDisabled();
    });
  });
});
