import { useTranslation } from "react-i18next";

interface ConfirmDialogProps {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  loading?: boolean;
}

/**
 * Confirmation dialog for destructive actions (CRU-04).
 * Delete fires ONLY after explicit confirm.
 * When loading=true, confirm button is disabled (double-click protection).
 */
export function ConfirmDialog({ open, onConfirm, onCancel, loading = false }: ConfirmDialogProps) {
  const { t } = useTranslation();

  if (!open) return null;

  return (
    <div className="dialog-overlay" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="dialog">
        <h2 id="confirm-title">{t("confirm.title")}</h2>
        <p>{t("confirm.message")}</p>
        <div className="dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={loading}>
            {t("confirm.no")}
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? "..." : t("confirm.yes")}
          </button>
        </div>
      </div>
    </div>
  );
}
