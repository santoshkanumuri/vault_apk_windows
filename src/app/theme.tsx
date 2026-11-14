import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import palette from "../appearance/nuvori-appearance-v1.json";
import { api, onAppearanceChanged, type Appearance } from "../lib/api";

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

export const APPEARANCE_KEY = "nuvori.appearance";
export const DEFAULT_ACCENT: string = palette.defaults.accent;
export const DEFAULT_SURFACE: string = palette.defaults.surface;
export const accentChoices = palette.accents;
export const surfaceChoices = palette.surfaces;
const ID_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

/** Returns a known accent id, or the default for anything else. */
export function cleanAccent(id: unknown): string {
  return typeof id === "string" && ID_PATTERN.test(id) && accentChoices.some((item) => item.id === id) ? id : DEFAULT_ACCENT;
}
export function cleanSurface(id: unknown): string {
  return typeof id === "string" && ID_PATTERN.test(id) && surfaceChoices.some((item) => item.id === id) ? id : DEFAULT_SURFACE;
}

type AppearanceState = { accent: string; surface: string; pendingSync: boolean };

function readCachedAppearance(): AppearanceState {
  try {
    const parsed = JSON.parse(localStorage.getItem(APPEARANCE_KEY) ?? "null");
    return { accent: cleanAccent(parsed?.accent), surface: cleanSurface(parsed?.surface), pendingSync: false };
  } catch {
    return { accent: DEFAULT_ACCENT, surface: DEFAULT_SURFACE, pendingSync: false };
  }
}

let appearanceState: AppearanceState = readCachedAppearance();
const appearanceListeners = new Set<(state: AppearanceState) => void>();

function surfaceBackground(surface: string, mode: ResolvedTheme): string | undefined {
  return surfaceChoices.find((item) => item.id === surface)?.[mode].background;
}

function paintThemeColor(mode: ResolvedTheme) {
  const color = surfaceBackground(appearanceState.surface, mode) ?? (mode === "light" ? "#F8FAF5" : "#050705");
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", color);
}

/** Applies an appearance to <html>, caches it for the next start, and tells listeners. */
function applyAppearance(next: Appearance | AppearanceState) {
  appearanceState = { accent: cleanAccent(next.accent), surface: cleanSurface(next.surface), pendingSync: Boolean(next.pendingSync) };
  const root = document.documentElement;
  root.dataset.accent = appearanceState.accent;
  root.dataset.surface = appearanceState.surface;
  paintThemeColor(root.dataset.theme === "light" ? "light" : "dark");
  try {
    localStorage.setItem(APPEARANCE_KEY, JSON.stringify({ accent: appearanceState.accent, surface: appearanceState.surface }));
  } catch { /* Storage can be unavailable; the colors still apply for this session. */ }
  appearanceListeners.forEach((listener) => listener(appearanceState));
}

let appearanceStarted = false;
/**
 * Loads the stored appearance and follows changes (sync, other windows). Works in every window,
 * also while the vault is locked. Safe to call more than once.
 */
export function startAppearance() {
  applyAppearance(appearanceState);
  if (appearanceStarted) return;
  appearanceStarted = true;
  api.getAppearance().then(applyAppearance).catch(() => { /* Keep the cached colors. */ });
  onAppearanceChanged(applyAppearance);
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
  paintThemeColor(resolved);
  return resolved;
}

type ThemeContextValue = {
  accent: string; surface: string; pendingSync: boolean;
  setAppearance: (accent: string, surface: string) => Promise<void>;
  preference: ThemePreference; resolved: ResolvedTheme; setPreference: (value: ThemePreference) => void; toggle: () => ThemePreference };

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

  const [appearance, setAppearanceState] = useState<AppearanceState>(appearanceState);
  useEffect(() => {
    startAppearance();
    appearanceListeners.add(setAppearanceState);
    setAppearanceState(appearanceState);
    return () => { appearanceListeners.delete(setAppearanceState); };
  }, []);
  const setAppearance = useCallback(async (accent: string, surface: string) => {
    applyAppearance(await api.setAppearance(cleanAccent(accent), cleanSurface(surface)));
  }, []);

  const setPreference = useCallback((value: ThemePreference) => setPreferenceState(value), []);
  const toggle = useCallback(() => {
    // Quick toggle flips between light and dark based on what is showing now.
    const next: ThemePreference = (document.documentElement.dataset.theme === "light") ? "dark" : "light";
    setPreferenceState(next);
    return next;
  }, []);

  const value = useMemo(() => ({ ...appearance, setAppearance, preference, resolved, setPreference, toggle }), [appearance, setAppearance, preference, resolved, setPreference, toggle]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme outside ThemeProvider");
  return context;
}
