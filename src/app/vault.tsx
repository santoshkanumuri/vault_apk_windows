import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, onVaultChanged, type AppSnapshot, type LocalNote, type VaultEntry, type VaultGroup } from "../lib/api";

export const fallbackSnapshot: AppSnapshot = {
  vaultState: "notConfigured",
  helloEnabled: false,
  counts: { cards: 0, logins: 0, codes: 0, questions: 0, autofill: 0, notes: 0 },
  pairedDevices: 0,
  enrolled: false,
  pendingChanges: 0,
  revision: 0,
  chainState: "empty"
};

type VaultValue = {
  ready: boolean;
  snapshot: AppSnapshot;
  unlocked: boolean;
  entries: VaultEntry[];
  notes: LocalNote[];
  groups: VaultGroup[];
  loaded: boolean;
  loadError: string;
  setSnapshot: (snapshot: AppSnapshot) => void;
  /** Re-read snapshot and lists after a change. */
  refresh: () => Promise<void>;
  /** Apply a saved entry immediately, before the full refresh lands. */
  upsertEntry: (entry: VaultEntry) => void;
  removeEntry: (id: string) => void;
  upsertNote: (note: LocalNote) => void;
  removeNote: (id: string) => void;
};

const VaultContext = createContext<VaultValue | null>(null);

export function VaultProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [snapshot, setSnapshotState] = useState<AppSnapshot>(fallbackSnapshot);
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [notes, setNotes] = useState<LocalNote[]>([]);
  const [groups, setGroups] = useState<VaultGroup[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const unlocked = snapshot.vaultState === "unlocked";
  const loadToken = useRef(0);

  const setSnapshot = useCallback((next: AppSnapshot) => {
    setSnapshotState((current) => JSON.stringify(current) === JSON.stringify(next) ? current : next);
  }, []);

  useEffect(() => {
    api.snapshot().then(setSnapshot).catch(() => setSnapshot(fallbackSnapshot)).finally(() => setReady(true));
  }, [setSnapshot]);

  // The unlock window and the tray can open or lock the vault while this window is hidden.
  useEffect(() => onVaultChanged(() => {
    api.snapshot().then(setSnapshot).catch(() => { /* The next change or poll catches up. */ });
  }), [setSnapshot]);

  const loadLists = useCallback(async () => {
    const token = ++loadToken.current;
    try {
      const [nextEntries, nextNotes, nextGroups] = await Promise.all([api.listEntries(), api.listNotes(), api.listGroups()]);
      if (token !== loadToken.current) return;
      setEntries(nextEntries);
      setNotes(nextNotes);
      setGroups(nextGroups);
      setLoadError("");
    } catch (error) {
      if (token === loadToken.current) setLoadError(String(error));
    } finally {
      if (token === loadToken.current) setLoaded(true);
    }
  }, []);

  // Load lists when the vault opens and whenever its revision changes (local edits or sync).
  useEffect(() => {
    if (!unlocked) {
      loadToken.current++;
      setEntries([]); setNotes([]); setGroups([]); setLoaded(false);
      return;
    }
    void loadLists();
  }, [unlocked, snapshot.revision, loadLists]);

  // Poll for changes made by sync or the browser extension.
  useEffect(() => {
    if (!unlocked) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "hidden") return;
      api.snapshot().then(setSnapshot).catch(() => { /* Keep the current view during a temporary IPC failure. */ });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [unlocked, setSnapshot]);

  const refresh = useCallback(async () => {
    try { setSnapshot(await api.snapshot()); } catch { /* Lists still refresh below. */ }
    await loadLists();
  }, [loadLists, setSnapshot]);

  const upsertEntry = useCallback((entry: VaultEntry) => setEntries((current) => [entry, ...current.filter((item) => item.id !== entry.id)]), []);
  const removeEntry = useCallback((id: string) => setEntries((current) => current.filter((item) => item.id !== id)), []);
  const upsertNote = useCallback((note: LocalNote) => setNotes((current) => [note, ...current.filter((item) => item.id !== note.id)]), []);
  const removeNote = useCallback((id: string) => setNotes((current) => current.filter((item) => item.id !== id)), []);

  const value = useMemo<VaultValue>(() => ({
    ready, snapshot, unlocked, entries, notes, groups, loaded, loadError, setSnapshot, refresh, upsertEntry, removeEntry, upsertNote, removeNote
  }), [ready, snapshot, unlocked, entries, notes, groups, loaded, loadError, setSnapshot, refresh, upsertEntry, removeEntry, upsertNote, removeNote]);

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault(): VaultValue {
  const context = useContext(VaultContext);
  if (!context) throw new Error("useVault outside VaultProvider");
  return context;
}
