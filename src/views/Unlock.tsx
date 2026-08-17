import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useSessionStore } from "../stores/session";
import { useUiStore } from "../stores/ui";
import { toAppError } from "../lib/api";

/**
 * Unlock view — single pw field, spinner during KDF (SES-03).
 * CRY-04: single opaque error for all unlock failures.
 */
export function Unlock() {
  const { t } = useTranslation();
  const unlock = useSessionStore((s) => s.unlock);
  const loading = useSessionStore((s) => s.loading);
  const addToast = useUiStore((s) => s.addToast);

  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setUnlockError(null);

    try {
      await unlock(password);
    } catch (err) {
      const appErr = toAppError(err);
      // CRY-04: always show the same opaque message — never reveal cause
      if (appErr.code === "unlock_failed") {
        setUnlockError(t("errors.unlock_failed"));
      } else if (appErr.code === "no_vault") {
        // Shouldn't happen if status routing is correct, but handle gracefully
        addToast(t("errors.no_vault"), "error");
      } else {
        setUnlockError(t("errors.internal"));
      }
    }
  }

  return (
    <div className="view view-unlock">
      <h1>{t("unlock.title")}</h1>

      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="unlock-pw">{t("unlock.password")}</label>
          <div className="input-group">
            <input
              id="unlock-pw"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              autoComplete="current-password"
              autoFocus
              required
            />
            <button
              type="button"
              className="btn-icon"
              onClick={() => setShowPassword((v) => !v)}
              aria-label="toggle password visibility"
              disabled={loading}
            >
              {showPassword ? "🙈" : "👁"}
            </button>
          </div>
        </div>

        {unlockError && <div className="field-error">{unlockError}</div>}

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? t("unlock.unlocking") : t("unlock.submit")}
        </button>
      </form>
    </div>
  );
}
