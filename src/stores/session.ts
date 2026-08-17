import { create } from "zustand";
import type { AppError, CredentialInput, CredentialView, SessionState } from "../lib/types";
import * as api from "../lib/api";

interface SessionState_ {
  status: SessionState;
  credentials: CredentialView[];
  error: AppError | null;
  loading: boolean;

  /** Fetch the current vault status from the backend. */
  fetchStatus: () => Promise<void>;
  /** Create a new vault (SES-01 + SES-02). */
  createVault: (password: string, confirm: string) => Promise<void>;
  /** Unlock the vault (CRY-04: opaque error). */
  unlock: (password: string) => Promise<void>;
  /** Lock the vault (SES-04). */
  lock: () => Promise<void>;
  /** Fetch all credentials (CRU-02). */
  fetchCredentials: () => Promise<void>;
  /** Create a credential (CRU-01). */
  createCredential: (input: CredentialInput) => Promise<CredentialView>;
  /** Update a credential (CRU-03). Full-object replace. */
  updateCredential: (id: number, input: CredentialInput) => Promise<CredentialView>;
  /** Delete a credential (CRU-04). Confirmation is the UI's job. */
  deleteCredential: (id: number) => Promise<void>;
  /** Clear the current error. */
  clearError: () => void;
}

export const useSessionStore = create<SessionState_>((set, get) => ({
  status: "Locked",
  credentials: [],
  error: null,
  loading: false,

  fetchStatus: async () => {
    try {
      set({ loading: true, error: null });
      const status = await api.vaultStatus();
      set({ status, loading: false });
      // If unlocked, fetch credentials too
      if (status === "Unlocked") {
        const credentials = await api.listCredentials();
        set({ credentials });
      }
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
    }
  },

  createVault: async (password, confirm) => {
    try {
      set({ loading: true, error: null });
      await api.createVault(password, confirm);
      // Create ends Unlocked — fetch credentials
      const credentials = await api.listCredentials();
      set({ status: "Unlocked", credentials, loading: false });
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
      throw appErr;
    }
  },

  unlock: async (password) => {
    try {
      set({ loading: true, error: null });
      await api.unlock(password);
      const credentials = await api.listCredentials();
      set({ status: "Unlocked", credentials, loading: false });
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
      throw appErr;
    }
  },

  lock: async () => {
    try {
      await api.lockVault();
      set({ status: "Locked", credentials: [], error: null });
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr });
    }
  },

  fetchCredentials: async () => {
    if (get().status !== "Unlocked") return;
    try {
      set({ loading: true, error: null });
      const credentials = await api.listCredentials();
      set({ credentials, loading: false });
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
    }
  },

  createCredential: async (input) => {
    try {
      set({ loading: true, error: null });
      const view = await api.createCredential(input);
      set((s) => ({
        credentials: [...s.credentials, view],
        loading: false,
      }));
      return view;
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
      throw appErr;
    }
  },

  updateCredential: async (id, input) => {
    try {
      set({ loading: true, error: null });
      const view = await api.updateCredential(id, input);
      set((s) => ({
        credentials: s.credentials.map((c) => (c.id === id ? view : c)),
        loading: false,
      }));
      return view;
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
      throw appErr;
    }
  },

  deleteCredential: async (id) => {
    try {
      set({ loading: true, error: null });
      await api.deleteCredential(id);
      set((s) => ({
        credentials: s.credentials.filter((c) => c.id !== id),
        loading: false,
      }));
    } catch (err) {
      const appErr = api.toAppError(err);
      set({ error: appErr, loading: false });
      throw appErr;
    }
  },

  clearError: () => set({ error: null }),
}));
