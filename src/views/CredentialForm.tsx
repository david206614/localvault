import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import type { CredentialInput, CredentialView } from "../lib/types";
import { FIELD_CAPS } from "../lib/types";
import { toAppError } from "../lib/api";
import { useUiStore } from "../stores/ui";

interface CredentialFormProps {
  /** Existing credential for edit mode, or undefined for create mode. */
  credential?: CredentialView;
  onSave: (input: CredentialInput) => Promise<void>;
  onCancel: () => void;
}

const EMPTY: CredentialInput = {
  service_name: "",
  username: "",
  password: "",
  url: "",
  category: "",
  notes: "",
};

/**
 * Create/edit mode credential form.
 * - All fields sent as full object (REPLACE-NOT-MERGE).
 * - Empty password allowed (CRU-06 — never disable save for empty password).
 * - maxLength from MAX_*_EN caps (S8).
 * - AppError validation/field_too_long mapped to form fields.
 */
export function CredentialForm({ credential, onSave, onCancel }: CredentialFormProps) {
  const { t } = useTranslation();
  const addToast = useUiStore((s) => s.addToast);
  const [form, setForm] = useState<CredentialInput>(
    credential
      ? {
          service_name: credential.service_name,
          username: credential.username,
          password: credential.password,
          url: credential.url,
          category: credential.category,
          notes: credential.notes,
        }
      : { ...EMPTY },
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  // Reset form when credential prop changes (e.g. switching between edit targets)
  useEffect(() => {
    if (credential) {
      setForm({
        service_name: credential.service_name,
        username: credential.username,
        password: credential.password,
        url: credential.url,
        category: credential.category,
        notes: credential.notes,
      });
    } else {
      setForm({ ...EMPTY });
    }
    setErrors({});
  }, [credential]);

  function update<K extends keyof CredentialInput>(field: K, value: string) {
    setForm((prev) => ({ ...prev, [field]: value }));
    // Clear field error on change
    if (errors[field]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    setSaving(true);

    try {
      await onSave(form);
    } catch (err) {
      const appErr = toAppError(err);
      if (appErr.code === "validation") {
        const field = mapValidationToField(appErr.key);
        setErrors({ [field]: t(appErr.key, { max: extractMax(appErr.message) }) });
      } else {
        addToast(t(appErr.key), "error");
      }
    } finally {
      setSaving(false);
    }
  }

  const isEdit = !!credential;

  return (
    <div className="view view-form">
      <h2>{isEdit ? t("form.edit_title") : t("form.create_title")}</h2>

      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="svc">{t("form.service_name")} *</label>
          <input
            id="svc"
            type="text"
            value={form.service_name}
            onChange={(e) => update("service_name", e.target.value)}
            maxLength={FIELD_CAPS.service_name}
            disabled={saving}
            required
          />
          {errors.service_name && <span className="field-error">{errors.service_name}</span>}
        </div>

        <div className="field">
          <label htmlFor="usr">{t("form.username")} *</label>
          <input
            id="usr"
            type="text"
            value={form.username}
            onChange={(e) => update("username", e.target.value)}
            maxLength={FIELD_CAPS.username}
            disabled={saving}
            required
          />
          {errors.username && <span className="field-error">{errors.username}</span>}
        </div>

        <div className="field">
          <label htmlFor="pw">{t("form.password")}</label>
          <input
            id="pw"
            type="text"
            value={form.password}
            onChange={(e) => update("password", e.target.value)}
            maxLength={FIELD_CAPS.password}
            disabled={saving}
          />
          {errors.password && <span className="field-error">{errors.password}</span>}
        </div>

        <div className="field">
          <label htmlFor="url">{t("form.url")}</label>
          <input
            id="url"
            type="url"
            value={form.url}
            onChange={(e) => update("url", e.target.value)}
            maxLength={FIELD_CAPS.url}
            disabled={saving}
          />
          {errors.url && <span className="field-error">{errors.url}</span>}
        </div>

        <div className="field">
          <label htmlFor="cat">{t("form.category")}</label>
          <input
            id="cat"
            type="text"
            value={form.category}
            onChange={(e) => update("category", e.target.value)}
            maxLength={FIELD_CAPS.category}
            disabled={saving}
          />
          {errors.category && <span className="field-error">{errors.category}</span>}
        </div>

        <div className="field">
          <label htmlFor="notes">{t("form.notes")}</label>
          <textarea
            id="notes"
            value={form.notes}
            onChange={(e) => update("notes", e.target.value)}
            maxLength={FIELD_CAPS.notes}
            disabled={saving}
            rows={3}
          />
          {errors.notes && <span className="field-error">{errors.notes}</span>}
        </div>

        <div className="form-actions">
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={saving}>
            {t("form.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {t("form.save")}
          </button>
        </div>
      </form>
    </div>
  );
}

/** Map AppError validation keys to form field names. */
function mapValidationToField(key: string): string {
  if (key.includes("service_name")) return "service_name";
  if (key.includes("username")) return "username";
  return "password";
}

/** Extract the max number from an error message like "field must be at most 256 characters". */
function extractMax(message: string): string {
  const match = message.match(/at most (\d+)/);
  return match?.[1] ?? "";
}
