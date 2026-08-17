import { getCurrentWindow } from "@tauri-apps/api/window";
import type { UnlistenFn } from "@tauri-apps/api/event";

export type Theme = "dark" | "light";

/**
 * Read the current system theme from the Tauri window.
 * Falls back to 'dark' if the API is unavailable (e.g. test env).
 */
export async function getSystemTheme(): Promise<Theme> {
  try {
    const t = await getCurrentWindow().theme();
    return t === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

/**
 * Subscribe to live OS theme changes (SHE-03).
 * Returns an unlisten function.
 */
export async function onThemeChanged(callback: (theme: Theme) => void): Promise<UnlistenFn> {
  try {
    return getCurrentWindow().onThemeChanged(({ payload }) => {
      callback(payload === "light" ? "light" : "dark");
    });
  } catch {
    return () => {};
  }
}

/** Apply theme to <html> data-theme attribute. */
export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
}
