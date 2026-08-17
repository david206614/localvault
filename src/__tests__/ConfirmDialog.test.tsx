import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Mock Tauri invoke
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// Mock the Tauri window API
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

import { ConfirmDialog } from "../views/ConfirmDialog";

describe("ConfirmDialog", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <ConfirmDialog open={false} onConfirm={() => {}} onCancel={() => {}} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders dialog when open", () => {
    render(<ConfirmDialog open={true} onConfirm={() => {}} onCancel={() => {}} />);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("confirm.title")).toBeInTheDocument();
    expect(screen.getByText("confirm.message")).toBeInTheDocument();
  });

  it("calls onConfirm when confirm button clicked", async () => {
    const onConfirm = vi.fn();
    render(<ConfirmDialog open={true} onConfirm={onConfirm} onCancel={() => {}} />);
    await userEvent.click(screen.getByText("confirm.yes"));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("calls onCancel when cancel button clicked", async () => {
    const onCancel = vi.fn();
    render(<ConfirmDialog open={true} onConfirm={() => {}} onCancel={onCancel} />);
    await userEvent.click(screen.getByText("confirm.no"));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
