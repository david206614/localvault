import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { CredentialView } from "../lib/types";
import { useSessionStore } from "../stores/session";
import { useUiStore } from "../stores/ui";
import { ConfirmDialog } from "./ConfirmDialog";
import { CredentialForm } from "./CredentialForm";

/**
 * VaultList view — list credentials (CRU-02).
 * Shows service_name, username, category with expand/eye to show password.
 * Empty state, delete via ConfirmDialog (CRU-04), create + edit buttons.
 * Search/filter is FUTURE scope (RF-06) — visual placeholder only.
 */
export function VaultList() {
  const { t } = useTranslation();
  const credentials = useSessionStore((s) => s.credentials);
  const lock = useSessionStore((s) => s.lock);
  const deleteCredential = useSessionStore((s) => s.deleteCredential);
  const addToast = useUiStore((s) => s.addToast);
  const createCredential = useSessionStore((s) => s.createCredential);
  const updateCredential = useSessionStore((s) => s.updateCredential);

  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CredentialView | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [showForm, setShowForm] = useState<"create" | CredentialView | null>(null);

  async function handleDeleteConfirm() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteCredential(deleteTarget.id);
      addToast(t("toast.credential_deleted"), "success");
    } catch {
      // error is already in session store
    } finally {
      setDeleting(false);
      setDeleteTarget(null);
    }
  }

  async function handleSave(input: Parameters<typeof createCredential>[0]) {
    if (showForm === "create") {
      await createCredential(input);
      addToast(t("toast.credential_created"), "success");
    } else if (showForm && typeof showForm === "object") {
      await updateCredential(showForm.id, input);
      addToast(t("toast.credential_updated"), "success");
    }
    setShowForm(null);
  }

  // Create/edit form overlay
  if (showForm) {
    return (
      <div className="view view-list">
        <CredentialForm
          credential={typeof showForm === "object" ? showForm : undefined}
          onSave={handleSave}
          onCancel={() => setShowForm(null)}
        />
      </div>
    );
  }

  return (
    <div className="view view-list">
      <header className="list-header">
        <h1>{t("list.title")}</h1>
        <div className="list-actions">
          <button type="button" className="btn btn-primary" onClick={() => setShowForm("create")}>
            {t("list.create")}
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => void lock()}>
            Lock
          </button>
        </div>
      </header>

      {/* Search placeholder (RF-06: FUTURE scope — layout only, no filtering logic) */}
      <div className="list-search-placeholder">
        <input type="text" placeholder={t("list.search")} disabled aria-label={t("list.search")} />
      </div>

      {credentials.length === 0 ? (
        <div className="empty-state">
          <p>{t("list.empty")}</p>
        </div>
      ) : (
        <ul className="credential-list">
          {credentials.map((cred) => (
            <li key={cred.id} className="credential-item">
              <div className="credential-summary">
                <span className="credential-service">{cred.service_name}</span>
                <span className="credential-username">{cred.username}</span>
                {cred.category && (
                  <span className="credential-category">{cred.category}</span>
                )}
                <div className="credential-actions">
                  <button
                    type="button"
                    className="btn-icon"
                    onClick={() => setExpandedId(expandedId === cred.id ? null : cred.id)}
                    aria-label={
                      expandedId === cred.id ? t("list.hide_password") : t("list.show_password")
                    }
                  >
                    {expandedId === cred.id ? "🙈" : "👁"}
                  </button>
                  <button
                    type="button"
                    className="btn-icon"
                    onClick={() => setShowForm(cred)}
                    aria-label={t("list.edit")}
                  >
                    ✏️
                  </button>
                  <button
                    type="button"
                    className="btn-icon"
                    onClick={() => setDeleteTarget(cred)}
                    aria-label={t("list.delete")}
                  >
                    🗑️
                  </button>
                </div>
              </div>

              {expandedId === cred.id && (
                <div className="credential-details">
                  <div className="detail-row">
                    <span className="detail-label">{t("list.password")}:</span>
                    <span className="detail-value password-value">{cred.password || "—"}</span>
                  </div>
                  {cred.url && (
                    <div className="detail-row">
                      <span className="detail-label">{t("form.url")}:</span>
                      <a
                        className="detail-value"
                        href={cred.url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {cred.url}
                      </a>
                    </div>
                  )}
                  {cred.notes && (
                    <div className="detail-row">
                      <span className="detail-label">{t("form.notes")}:</span>
                      <span className="detail-value">{cred.notes}</span>
                    </div>
                  )}
                  <div className="detail-row">
                    <span className="detail-label">Created:</span>
                    <span className="detail-value">
                      {new Date(cred.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">Updated:</span>
                    <span className="detail-value">
                      {new Date(cred.updated_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      <ConfirmDialog
        open={!!deleteTarget}
        onConfirm={() => void handleDeleteConfirm()}
        onCancel={() => setDeleteTarget(null)}
        loading={deleting}
      />
    </div>
  );
}
