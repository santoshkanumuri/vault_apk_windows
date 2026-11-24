// Run with `npm test`. The fixtures are shared with the Android app (vault_apk docs/rich-notes/fixtures.json),
// so both apps read the same documents and write byte-identical JSON for them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  decode, encode, fromPlain, hash, linkFromInput, load, normalize, plainText, sameDocument, sanitizeLink, sanitizeText,
  sha256Hex, span, storageFields, textBlock, NoteTooLargeError, MAX_JSON_BYTES,
} from "./richNote.ts";

const shared = JSON.parse(readFileSync(new URL("../../docs/rich-notes/fixtures.json", import.meta.url), "utf8"));

test("SHA-256 matches known values", () => {
  const hex = (text) => sha256Hex(new TextEncoder().encode(text));
  assert.equal(hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(hex("a".repeat(1000)), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
});

for (const fixture of shared.fixtures) {
  test(`shared fixture: ${fixture.name}`, () => {
    const decoded = decode(JSON.stringify(fixture.document));
    assert.ok(decoded);
    assert.equal(plainText(decoded.document), fixture.plain);
    assert.equal(hash(fixture.plain), fixture.hash);
    // Byte-identical to what the Android app writes.
    assert.equal(encode(decoded.document), fixture.encoded);
    const reread = load(fixture.plain, fixture.encoded);
    assert.equal(reread.source, "rich");
    assert.ok(sameDocument(reread.document, decoded.document));
    assert.deepEqual(storageFields(reread.document), [fixture.plain, fixture.encoded]);
    if (fixture.normalized) assert.ok(sameDocument(decode(JSON.stringify(fixture.normalized)).document, decoded.document));
  });
}

test("shared link rules", () => {
  for (const { input, safe } of shared.links) assert.equal(sanitizeLink(input), safe, input);
  for (const { input, link } of shared.typedLinks) assert.equal(linkFromInput(input), link, input);
});

test("plain notes stay plain and keep their text", () => {
  const text = "Wi-Fi: home\n\n  indented line\nlast";
  assert.deepEqual(storageFields(fromPlain(text)), [text, ""]);
  assert.equal(load(text, "").source, "plain");
});

test("text edited by an app without rich notes wins", () => {
  const [plain, json] = storageFields({ blocks: [textBlock("check", [span("Milk")])] });
  assert.equal(plain, "☐ Milk");
  const loaded = load("☐ Milk\n☐ Bread", json);
  assert.equal(loaded.source, "diverged");
  assert.equal(plainText(loaded.document), "☐ Milk\n☐ Bread");
  assert.equal(load(`${plain}  \r\n`, json).source, "rich", "trailing space and Windows line breaks are not edits");
});

test("newer versions and broken JSON fall back to the text", () => {
  assert.equal(load("Hi", `{"format":"nuvori.richnote","version":2,"plainHash":"x","blocks":[]}`).source, "newer");
  for (const json of ["{", "[]", `{"format":"other","version":1,"plainHash":"","blocks":[]}`, `{"format":"nuvori.richnote","plainHash":"","blocks":[]}`])
    assert.equal(load("Hi", json).source, "plain", json);
});

test("unknown blocks, marks and colors are dropped; unsafe links removed", () => {
  const json = JSON.stringify({ format: "nuvori.richnote", version: 1, plainHash: "", blocks: [
    { type: "video", src: "x" },
    { type: "paragraph", spans: [{ text: "a", bold: true, glow: true, color: "neon" }, { text: "b", link: "javascript:alert(1)", bold: true }] },
  ] });
  const doc = decode(json).document;
  assert.equal(doc.blocks.length, 1);
  assert.deepEqual(doc.blocks[0].spans, [{ text: "ab", marks: { bold: true } }]);
});

test("control and direction characters are removed", () => {
  assert.equal(sanitizeText("safe‮txt.exe\u0007\r\nnext"), "safetxt.exe\nnext");
});

test("text with line breaks becomes one block per line, keeping its style", () => {
  const doc = normalize({ blocks: [textBlock("bullet", [span("one\ntwo", { italic: true })], { indent: 9 })] });
  assert.equal(doc.blocks.length, 2);
  assert.deepEqual(doc.blocks.map((b) => [b.kind, b.indent, b.spans[0].text]), [["bullet", 4, "one"], ["bullet", 4, "two"]]);
});

test("limits are enforced", () => {
  assert.throws(() => encode({ blocks: [{ type: "table", header: true, rows: Array.from({ length: 51 }, () => [[span("x")]]) }] }), NoteTooLargeError);
  assert.throws(() => encode({ blocks: [textBlock("paragraph", [span("x".repeat(200_001), { bold: true })])] }), NoteTooLargeError);
  const lines = Array.from({ length: 100 }, () => textBlock("paragraph", [span("界".repeat(1600), { bold: true })]));
  assert.ok(new TextEncoder().encode(encode({ blocks: lines })).length < MAX_JSON_BYTES);
  assert.throws(() => storageFields({ blocks: lines }), NoteTooLargeError, "too large for one sync payload");
});

test("JSON strings are escaped like the Android app", () => {
  const doc = { blocks: [textBlock("code", [span("tab\there \"q\" \\ \u2028 <&>")])] };
  const json = encode(doc);
  assert.ok(json.includes('"tab\\there \\"q\\" \\\\ \\u2028 <&>"'), json);
  assert.ok(sameDocument(decode(json).document, normalize(doc)));
});
