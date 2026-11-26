import { codeText } from "../strings.ts";
// Password and passphrase generator. The Android app has the same rules and limits
// (security/PasswordGenerator.kt): keep the two in step.
//
// This file has no imports, so `node --test` can load it directly (src/lib/generator.test.mjs).
// The word list comes from the caller: the EFF large word list, 7,776 words (wordlist.ts).

export type GeneratorMode = "password" | "passphrase";
export type Separator = "-" | "." | "_" | " ";

export type GeneratorSettings = {
  mode: GeneratorMode;
  /** Password mode. */
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Leaves out characters that are easy to confuse: l, I, O, 0 and 1. */
  avoidSimilar: boolean;
  /** Passphrase mode. */
  words: number;
  separator: Separator;
  capitalize: boolean;
  /** Adds one digit to the end of one random word. */
  includeNumber: boolean;
};

export const LENGTH_RANGE = { min: 8, max: 64 } as const;
export const WORDS_RANGE = { min: 3, max: 10 } as const;
export const SEPARATORS: readonly Separator[] = ["-", ".", "_", " "];

export const DEFAULT_SETTINGS: GeneratorSettings = {
  mode: "password",
  length: 20,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  avoidSimilar: true,
  words: 5,
  separator: "-",
  capitalize: true,
  includeNumber: true,
};

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*-_=+?";
const SIMILAR = "lIO01";

/** Fills `count` random 32-bit values. Tests pass a fixed source. */
export type RandomSource = (count: number) => Uint32Array;

export const secureRandom: RandomSource = (count) => {
  const values = new Uint32Array(count);
  crypto.getRandomValues(values);
  return values;
};

/** A uniform integer in [0, bound). Rejects the top values that would make some results more likely. */
export function randomBelow(bound: number, random: RandomSource = secureRandom): number {
  if (!Number.isInteger(bound) || bound < 1 || bound > 2 ** 32) throw new RangeError("bound");
  const limit = 2 ** 32 - (2 ** 32 % bound);
  for (;;) {
    const value = random(1)[0];
    if (value < limit) return value % bound;
  }
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.min(max, Math.max(min, Math.round(value))) : fallback;
}

/** Settings from storage or the UI, with every value inside its limits. At least one character set stays on. */
export function normalizeSettings(value: unknown): GeneratorSettings {
  const raw = (typeof value === "object" && value !== null ? value : {}) as Partial<Record<keyof GeneratorSettings, unknown>>;
  const flag = (key: keyof GeneratorSettings) => (typeof raw[key] === "boolean" ? raw[key] as boolean : DEFAULT_SETTINGS[key] as boolean);
  const settings: GeneratorSettings = {
    mode: raw.mode === "passphrase" ? "passphrase" : "password",
    length: clampInt(raw.length, LENGTH_RANGE.min, LENGTH_RANGE.max, DEFAULT_SETTINGS.length),
    uppercase: flag("uppercase"),
    lowercase: flag("lowercase"),
    digits: flag("digits"),
    symbols: flag("symbols"),
    avoidSimilar: flag("avoidSimilar"),
    words: clampInt(raw.words, WORDS_RANGE.min, WORDS_RANGE.max, DEFAULT_SETTINGS.words),
    separator: SEPARATORS.includes(raw.separator as Separator) ? raw.separator as Separator : DEFAULT_SETTINGS.separator,
    capitalize: flag("capitalize"),
    includeNumber: flag("includeNumber"),
  };
  if (!settings.uppercase && !settings.lowercase && !settings.digits && !settings.symbols) settings.lowercase = true;
  return settings;
}

function characterSets(settings: GeneratorSettings): string[] {
  const strip = (set: string) => (settings.avoidSimilar ? [...set].filter((c) => !SIMILAR.includes(c)).join("") : set);
  return [
    settings.lowercase && strip(LOWER),
    settings.uppercase && strip(UPPER),
    settings.digits && strip(DIGITS),
    settings.symbols && SYMBOLS,
  ].filter((set): set is string => Boolean(set));
}

function shuffle<T>(items: T[], random: RandomSource) {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1, random);
    [items[i], items[j]] = [items[j], items[i]];
  }
}

/** A random password: at least one character from each chosen set, then a shuffle. */
export function generatePasswordWith(input: GeneratorSettings, random: RandomSource = secureRandom): string {
  const settings = normalizeSettings({ ...input, mode: "password" });
  const sets = characterSets(settings);
  const all = sets.join("");
  const chars = sets.map((set) => set[randomBelow(set.length, random)]);
  while (chars.length < settings.length) chars.push(all[randomBelow(all.length, random)]);
  shuffle(chars, random);
  return chars.join("");
}

/** Words picked at random from `wordList`, joined by the separator. */
export function generatePassphrase(input: GeneratorSettings, wordList: readonly string[], random: RandomSource = secureRandom): string {
  if (wordList.length < 1024) throw new Error("The word list is missing");
  const settings = normalizeSettings({ ...input, mode: "passphrase" });
  const words = Array.from({ length: settings.words }, () => {
    const word = wordList[randomBelow(wordList.length, random)];
    return settings.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word;
  });
  if (settings.includeNumber) {
    const index = randomBelow(words.length, random);
    words[index] += String(randomBelow(10, random));
  }
  return words.join(settings.separator);
}

export function generate(settings: GeneratorSettings, wordList: readonly string[], random: RandomSource = secureRandom): string {
  return settings.mode === "passphrase" ? generatePassphrase(settings, wordList, random) : generatePasswordWith(settings, random);
}

/**
 * Bits of randomness in a result, rounded down. A password counts every position from the full
 * pool (the guaranteed characters remove a little; this ignores that). A passphrase counts its
 * words, plus the digit and its position.
 */
export function entropyBits(input: GeneratorSettings, wordCount: number): number {
  const settings = normalizeSettings(input);
  if (settings.mode === "passphrase") {
    const number = settings.includeNumber ? Math.log2(10) + Math.log2(settings.words) : 0;
    return Math.floor(settings.words * Math.log2(wordCount) + number);
  }
  return Math.floor(settings.length * Math.log2(characterSets(settings).join("").length));
}

/** A label for `bits`: below 50 is weak for a website password, 80 and above resists any offline attack. */
export function strengthLabel(bits: number): "Weak" | "Fair" | "Strong" | "Very strong" {
  return bits < 50 ? "Weak" : bits < 65 ? "Fair" : bits < 80 ? "Strong" : codeText.veryStrong;
}
