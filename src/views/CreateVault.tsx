import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useSessionStore } from "../stores/session";
import { useUiStore } from "../stores/ui";
import { toAppError } from "../lib/api";

/**
 * CreateVault view — first-run gate (SHE-01).
 * Two pw fields (create + confirm), show/hide toggle, policy hints (SES-01),
 * error mapping (validation → field errors, internal → toast).
 * Spinner + disabled inputs during KDF.
 */
export function CreateVault() {
  const { t } = useTranslation();
  const createVault = useSessionStore((s) => s.createVault);
  const loading = useSessionStore((s) => s.loading);
  const addToast = useUiStore((s) => s.addToast);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});

    try {
      await createVault(password, confirm);
    } catch (err) {
      const appErr = toAppError(err);
      // Map validation errors to form fields
      if (appErr.code === "validation") {
        setErrors({ [getValidationField(appErr.key)]: t(appErr.key) });
      } else {
        // Internal / other → toast
        addToast(t(appErr.key), "error");
      }
    }
  }

  const inputType = showPassword ? "text" : "password";

  return (
    <div className="view view-create">
      <h1>{t("create.title")}</h1>

      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="pw">{t("create.password")}</label>
          <div className="input-group">
            <input
              id="pw"
              type={inputType}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              autoComplete="new-password"
              required
            />
            <button
              type="button"
              className="btn-icon"
              onClick={() => setShowPassword((v) => !v)}
              aria-label={showPassword ? t("create.password") : t("create.password")}
              disabled={loading}
            >
              {showPassword ? "🙈" : "👁"}
            </button>
          </div>
          {errors.password && <span className="field-error">{errors.password}</span>}
        </div>

        <div className="field">
          <label htmlFor="pw-confirm">{t("create.confirm")}</label>
          <input
            id="pw-confirm"
            type={inputType}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            disabled={loading}
            autoComplete="new-password"
            required
          />
          {errors.confirm && <span className="field-error">{errors.confirm}</span>}
        </div>

        <ul className="policy-hints">
          <li>{t("create.policy.length")}</li>
          <li>{t("create.policy.uppercase")}</li>
          <li>{t("create.policy.lowercase")}</li>
          <li>{t("create.policy.digit")}</li>
          <li>{t("create.policy.symbol")}</li>
        </ul>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? t("create.creating") : t("create.submit")}
        </button>
      </form>
    </div>
  );
}

/** Map validation error keys to form field names. */
function getValidationField(key: string): string {
  if (key.includes("password_too_short")) return "password";
  if (key.includes("password_missing")) return "password";
  if (key.includes("passwords_mismatch")) return "confirm";
  return "password";
}
