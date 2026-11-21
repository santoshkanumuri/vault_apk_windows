// Run with `npm test`. Node strips the TypeScript types of generator.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  DEFAULT_SETTINGS, entropyBits, generate, generatePassphrase, generatePasswordWith, normalizeSettings, randomBelow, strengthLabel,
} from "./generator.ts";

const wordFile = readFileSync(new URL("./eff-large-wordlist.txt", import.meta.url));
const words = wordFile.toString("utf8").split(/\r?\n/).filter(Boolean);

test("the word list is the EFF large list, the same file as in the Android app", () => {
  // SHA-256 of the 7,776 words, one per line. card_app: app/src/main/assets/eff_large_wordlist.txt.
  assert.equal(createHash("sha256").update(wordFile).digest("hex"), "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522");
  assert.equal(words.length, 7776);
  assert.equal(new Set(words).size, 7776);
  assert.equal(words[0], "abacus");
  assert.equal(words.at(-1), "zoom");
});

test("passwords have the length and at least one character of each chosen set", () => {
  for (let i = 0; i < 200; i++) {
    const password = generatePasswordWith(DEFAULT_SETTINGS);
    assert.equal(password.length, 20);
    assert.match(password, /[a-z]/);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[0-9]/);
    assert.match(password, /[!@#$%^&*\-_=+?]/);
    assert.doesNotMatch(password, /[lIO01]/, "similar characters are left out by default");
  }
  const digitsOnly = { ...DEFAULT_SETTINGS, length: 8, uppercase: false, lowercase: false, symbols: false, avoidSimilar: false };
  assert.match(generatePasswordWith(digitsOnly), /^[0-9]{8}$/);
});

test("passphrases use list words, the separator, capitals and one digit", () => {
  const settings = { ...DEFAULT_SETTINGS, mode: "passphrase", words: 6, separator: "." };
  for (let i = 0; i < 200; i++) {
    const phrase = generatePassphrase(settings, words);
    const parts = phrase.split(".");
    assert.equal(parts.length, 6, phrase);
    assert.equal(parts.filter((part) => /\d$/.test(part)).length, 1, phrase);
    for (const part of parts) {
      const word = part.replace(/\d$/, "");
      assert.ok(words.includes(word.toLowerCase()), word);
      assert.equal(word[0], word[0].toUpperCase());
    }
  }
  const plain = generatePassphrase({ ...settings, capitalize: false, includeNumber: false, separator: " " }, words);
  assert.match(plain, /^[a-z-]+( [a-z-]+){5}$/);
  assert.throws(() => generatePassphrase(settings, ["too", "short"]), /word list/);
});

test("random choices are uniform: no value is favored", () => {
  // A source that returns the values that modulo bias would favor: they must be rejected.
  const limit = 2 ** 32 - (2 ** 32 % 7776);
  const queue = [limit, 2 ** 32 - 1, 7777];
  const fixed = () => Uint32Array.of(queue.shift());
  assert.equal(randomBelow(7776, fixed), 1);
  assert.equal(queue.length, 0);
  // 60,000 draws over 6 values: each count stays near 10,000.
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 60_000; i++) counts[randomBelow(6)]++;
  for (const count of counts) assert.ok(count > 9_400 && count < 10_600, String(counts));
});

test("stored settings are kept inside their limits", () => {
  const bad = normalizeSettings({ mode: "other", length: 9999, words: -2, separator: "<", uppercase: false, lowercase: false, digits: false, symbols: false });
  assert.equal(bad.mode, "password");
  assert.equal(bad.length, 64);
  assert.equal(bad.words, 3);
  assert.equal(bad.separator, "-");
  assert.equal(bad.lowercase, true, "one character set always stays on");
  assert.deepEqual(normalizeSettings("not an object"), DEFAULT_SETTINGS);
  assert.deepEqual(normalizeSettings(JSON.parse(JSON.stringify(DEFAULT_SETTINGS))), DEFAULT_SETTINGS);
});

test("strength estimates match the choices", () => {
  // 20 characters from 70: a-z without l (25), A-Z without I and O (24), 2-9 (8), 13 symbols. 122 bits.
  assert.equal(entropyBits(DEFAULT_SETTINGS, 7776), 122);
  // 5 words: 64.6 bits, plus a digit (3.3) at one of 5 places (2.3).
  assert.equal(entropyBits({ ...DEFAULT_SETTINGS, mode: "passphrase" }, 7776), 70);
  assert.equal(entropyBits({ ...DEFAULT_SETTINGS, mode: "passphrase", words: 3, includeNumber: false }, 7776), 38);
  assert.equal(strengthLabel(38), "Weak");
  assert.equal(strengthLabel(70), "Strong");
  assert.equal(strengthLabel(122), "Very strong");
  assert.equal(generate({ ...DEFAULT_SETTINGS, length: 12 }, []).length, 12);
});
