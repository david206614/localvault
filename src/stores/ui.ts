import { create } from "zustand";
import type { AppError } from "../lib/types";

export interface Toast {
  id: string;
  message: string;
  type: "success" | "error" | "info";
}

interface UiState {
  theme: "dark" | "light";
  locale: string;
  toasts: Toast[];
  setTheme: (theme: "dark" | "light") => void;
  setLocale: (locale: string) => void;
  addToast: (message: string, type?: Toast["type"]) => void;
  removeToast: (id: string) => void;
  /** Convenience: show an AppError as a toast. Returns the toast ID. */
  addErrorToast: (error: AppError, fallbackKey?: string) => string;
}

let toastCounter = 0;

export const useUiStore = create<UiState>((set) => ({
  theme: "dark",
  locale: "en",
  toasts: [],

  setTheme: (theme) => set({ theme }),
  setLocale: (locale) => set({ locale }),

  addToast: (message, type = "info") =>
    set((s) => ({
      toasts: [...s.toasts, { id: `t${++toastCounter}`, message, type }],
    })),

  removeToast: (id) =>
    set((s) => ({
      toasts: s.toasts.filter((t) => t.id !== id),
    })),

  addErrorToast: (error, fallbackKey) => {
    const id = `t${++toastCounter}`;
    set((s) => ({
      toasts: [
        ...s.toasts,
        {
          id,
          message: fallbackKey ?? error.key,
          type: "error" as const,
        },
      ],
    }));
    return id;
  },
}));
