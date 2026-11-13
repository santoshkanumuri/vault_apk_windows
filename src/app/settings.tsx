import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export const AUTO_LOCK_KEY = "nuvori.autoLockMinutes";
export const CLIPBOARD_KEY = "nuvori.clipboardClearSeconds";

export const autoLockChoices = [0, 1, 5, 15, 30] as const;
export const clipboardChoices = [0, 15, 30, 60, 90] as const;

function readNumber(key: string, fallback: number, allowed: readonly number[]): number {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    const value = Number(raw);
    return allowed.includes(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

function writeNumber(key: string, value: number) {
  try { localStorage.setItem(key, String(value)); } catch { /* Preference stays for this session only. */ }
}

type Preferences = {
  autoLockMinutes: number;
  clipboardSeconds: number;
  setAutoLockMinutes: (value: number) => void;
  setClipboardSeconds: (value: number) => void;
};

const PreferencesContext = createContext<Preferences | null>(null);

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [autoLockMinutes, setAutoLock] = useState(() => readNumber(AUTO_LOCK_KEY, 15, autoLockChoices));
  const [clipboardSeconds, setClipboard] = useState(() => readNumber(CLIPBOARD_KEY, 30, clipboardChoices));
  const setAutoLockMinutes = useCallback((value: number) => { setAutoLock(value); writeNumber(AUTO_LOCK_KEY, value); }, []);
  const setClipboardSeconds = useCallback((value: number) => { setClipboard(value); writeNumber(CLIPBOARD_KEY, value); }, []);
  const value = useMemo(() => ({ autoLockMinutes, clipboardSeconds, setAutoLockMinutes, setClipboardSeconds }), [autoLockMinutes, clipboardSeconds, setAutoLockMinutes, setClipboardSeconds]);
  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

export function usePreferences(): Preferences {
  const context = useContext(PreferencesContext);
  if (!context) throw new Error("usePreferences outside PreferencesProvider");
  return context;
}
