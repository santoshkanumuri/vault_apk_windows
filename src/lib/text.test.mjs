// Run with `npm test`. Node strips the TypeScript types of text.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fold, highlight, tokenize } from "./text.ts";

test("folding ignores case and accents", () => {
  assert.equal(fold("Café"), "cafe");
  assert.equal(fold("ÉCOLE"), "ecole");
  assert.equal(fold("Ünïcödé"), "unicode");
  assert.equal(fold(""), "");
  // Characters that are not accents are left as they are.
  assert.equal(fold("Straße"), "straße");
  assert.equal(fold("P@ssw0rd!"), "p@ssw0rd!");
});

test("a query becomes the words that have to match", () => {
  assert.deepEqual(tokenize("  bank  card "), ["bank", "card"]);
  assert.deepEqual(tokenize("Café Münchén"), ["cafe", "munchen"]);
  assert.deepEqual(tokenize(""), []);
  assert.deepEqual(tokenize("   \t "), []);
  assert.deepEqual(tokenize("one"), ["one"]);
});

test("highlighting marks the match and leaves the text as the person wrote it", () => {
  assert.deepEqual(highlight("Bank card", ["card"]), [
    { text: "Bank ", match: false },
    { text: "card", match: true },
  ]);
  // The folded match is mapped back, so the accent survives in what is shown.
  assert.deepEqual(highlight("Café Rio", ["cafe"]), [
    { text: "Café", match: true },
    { text: " Rio", match: false },
  ]);
  // Every word is marked, wherever it is, and more than once.
  assert.deepEqual(highlight("red bed red", ["red"]).filter((part) => part.match).length, 2);
  assert.deepEqual(highlight("Bank card", ["bank", "card"]).filter((part) => part.match).map((part) => part.text), ["Bank", "card"]);
  // Nothing to mark: one plain piece, so a caller can render the same way either way.
  assert.deepEqual(highlight("Bank card", []), [{ text: "Bank card", match: false }]);
  assert.deepEqual(highlight("", ["card"]), [{ text: "", match: false }]);
  assert.deepEqual(highlight("Bank", ["safe"]), [{ text: "Bank", match: false }]);
  // Whatever the marks, the pieces still spell the original text.
  const text = "Crédit Agricole · ****1234";
  assert.equal(highlight(text, ["agricole", "1234"]).map((part) => part.text).join(""), text);
});
