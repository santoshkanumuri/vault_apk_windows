import { DEFAULT_SETTINGS, normalizeSettings, type GeneratorSettings } from "./generator";

/** The EFF large word list: 7,776 words, one per line (see README > Third-party notices). */
export const WORD_COUNT = 7776;

let words: Promise<readonly string[]> | null = null;

/** Loads the word list on first use, in its own chunk, so the main bundle stays small. */
export function loadWordList(): Promise<readonly string[]> {
  words ??= import("./eff-large-wordlist.txt?raw").then(({ default: text }) => {
    const list = text.split(/\r?\n/).filter(Boolean);
    if (list.length !== WORD_COUNT) throw new Error("The word list is damaged");
    return Object.freeze(list);
  }).catch((error: unknown) => {
    words = null;
    throw error;
  });
  return words;
}

const SETTINGS_KEY = "nuvori.generator";

/** The last generator settings on this PC. They are not secret and are not synced. */
export function readGeneratorSettings(): GeneratorSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? normalizeSettings(JSON.parse(raw)) : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveGeneratorSettings(settings: GeneratorSettings) {
  try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(normalizeSettings(settings))); } catch { /* Kept for this session only. */ }
}
