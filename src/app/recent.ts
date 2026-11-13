// Remembers which items were opened or copied recently, by id only (no titles or secrets), for Home's quick access.
const KEY = "nuvori.recentItems";
const MAX = 16;

export function readRecent(): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) ?? "[]") as unknown;
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string").slice(0, MAX) : [];
  } catch {
    return [];
  }
}

export function markUsed(id: string) {
  try {
    localStorage.setItem(KEY, JSON.stringify([id, ...readRecent().filter((value) => value !== id)].slice(0, MAX)));
  } catch { /* Quick access falls back to recently updated items. */ }
}

const DISMISS_KEY = "nuvori.dismissedHints";

export function readDismissed(): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(DISMISS_KEY) ?? "[]") as unknown;
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : [];
  } catch {
    return [];
  }
}

export function dismissHint(key: string) {
  try { localStorage.setItem(DISMISS_KEY, JSON.stringify([...new Set([...readDismissed(), key])])); } catch { /* Session only. */ }
}
