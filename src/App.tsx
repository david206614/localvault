import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useSessionStore } from "./stores/session";
import { useUiStore } from "./stores/ui";
import { getSystemTheme, onThemeChanged, applyTheme } from "./lib/theme";
import { persistLocale } from "./i18n";
import { CreateVault } from "./views/CreateVault";
import { Unlock } from "./views/Unlock";
import { VaultList } from "./views/VaultList";

/**
 * App — the root component.
 * Calls vault_status() on mount → routes to CreateVault | Unlock | VaultList (SHE-01).
 */
export function App() {
  const { t, i18n } = useTranslation();
  const status = useSessionStore((s) => s.status);
  const loading = useSessionStore((s) => s.loading);
  const fetchStatus = useSessionStore((s) => s.fetchStatus);
  const error = useSessionStore((s) => s.error);
  const setTheme = useUiStore((s) => s.setTheme);
  const setLocale = useUiStore((s) => s.setLocale);
  const toasts = useUiStore((s) => s.toasts);
  const removeToast = useUiStore((s) => s.removeToast);

  // On mount: fetch vault status and subscribe to theme changes (SHE-03)
  useEffect(() => {
    void fetchStatus();

    // System theme detection (live-reactive via onThemeChanged)
    void getSystemTheme().then((t_) => {
      setTheme(t_);
      applyTheme(t_);
    });

    let unlisten: (() => void) | undefined;
    void onThemeChanged((theme) => {
      setTheme(theme);
      applyTheme(theme);
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      unlisten?.();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function handleLocaleChange(lng: string) {
    void i18n.changeLanguage(lng);
    persistLocale(lng);
    setLocale(lng);
  }

  // Loading gate (initial status fetch)
  if (loading && status === "Locked" && !error) {
    return (
      <div className="app-loading">
        <div className="spinner" />
        <p>Loading…</p>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-title">{t("app.title")}</h1>
        <div className="header-controls">
          <label className="sr-only" htmlFor="locale-select">
            Language
          </label>
          <select
            id="locale-select"
            value={i18n.language}
            onChange={(e) => handleLocaleChange(e.target.value)}
          >
            <option value="en">EN</option>
            <option value="es">ES</option>
          </select>
        </div>
      </header>

      <main className="app-main">
        {status === "NoVault" && <CreateVault />}
        {status === "Locked" && <Unlock />}
        {status === "Unlocked" && <VaultList />}
      </main>

      {/* Toast container */}
      <div className="toast-container" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            <span>{t(toast.message)}</span>
            <button
              type="button"
              className="toast-close"
              onClick={() => removeToast(toast.id)}
              aria-label="Close"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
