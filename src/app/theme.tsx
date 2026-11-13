import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export const THEME_KEY = "nuvori.theme";
const LEGACY_KEY = "nuvori-theme";

export function readThemePreference(): ThemePreference {
  try {
    const value = localStorage.getItem(THEME_KEY) ?? localStorage.getItem(LEGACY_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

function systemTheme(): ResolvedTheme {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/** Applies the theme to <html>. Called before React renders (see public/theme-init.js and main.tsx) to avoid a flash. */
export function applyTheme(preference: ThemePreference): ResolvedTheme {
  const resolved = preference === "system" ? systemTheme() : preference;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", resolved === "light" ? "#F8FAF5" : "#050705");
  return resolved;
}

type ThemeContextValue = { preference: ThemePreference; resolved: ResolvedTheme; setPreference: (value: ThemePreference) => void; toggle: () => ThemePreference };

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readThemePreference);
  const [resolved, setResolved] = useState<ResolvedTheme>(() => applyTheme(readThemePreference()));

  useEffect(() => {
    setResolved(applyTheme(preference));
    try {
      localStorage.setItem(THEME_KEY, preference);
      localStorage.removeItem(LEGACY_KEY);
    } catch { /* Storage can be unavailable; the theme still applies for this session. */ }
    if (preference !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const update = () => setResolved(applyTheme("system"));
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [preference]);

  const setPreference = useCallback((value: ThemePreference) => setPreferenceState(value), []);
  const toggle = useCallback(() => {
    // Quick toggle flips between light and dark based on what is showing now.
    const next: ThemePreference = (document.documentElement.dataset.theme === "light") ? "dark" : "light";
    setPreferenceState(next);
    return next;
  }, []);

  const value = useMemo(() => ({ preference, resolved, setPreference, toggle }), [preference, resolved, setPreference, toggle]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme outside ThemeProvider");
  return context;
}
