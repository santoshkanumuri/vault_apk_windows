// Run with `npm test`. The editor draws a note as HTML and reads it back on every edit, so a note
// opened and saved on Windows must come back byte-identical: the Android -> Windows -> Android round trip.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decode, encode, plainText, sameDocument, storageFields, load, span, textBlock } from "./richNote.ts";
import { fromNodes, fromPastedText, toHtml } from "./richNoteHtml.ts";

const shared = JSON.parse(readFileSync(new URL("../../docs/rich-notes/fixtures.json", import.meta.url), "utf8"));

// A small HTML parser, enough for the editor's own markup and the paste samples below.
const VOID = new Set(["br", "hr", "img", "input", "meta", "link", "col", "source", "wbr"]);
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'" };
const unescape = (text) => text.replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);/gi, (all, name) =>
  name[0] === "#" ? String.fromCodePoint(name[1].toLowerCase() === "x" ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10)) : ENTITIES[name] ?? all);
function element(name, attrs) {
  return { nodeType: 1, nodeName: name.toUpperCase(), nodeValue: null, childNodes: [], getAttribute: (key) => (key in attrs ? attrs[key] : null) };
}
export function parse(html) {
  const root = { nodeType: 11, nodeName: "#document-fragment", nodeValue: null, childNodes: [] };
  const stack = [root];
  const token = /<!--[\s\S]*?-->|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[a-z-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+)/gi;
  let match;
  while ((match = token.exec(html))) {
    const [, close, open, rawAttrs, text] = match;
    const top = stack[stack.length - 1];
    if (text !== undefined) top.childNodes.push({ nodeType: 3, nodeName: "#text", nodeValue: unescape(text), childNodes: [] });
    else if (close) {
      const index = stack.map((n) => n.nodeName).lastIndexOf(close.toUpperCase());
      if (index > 0) stack.length = index;
    } else if (open) {
      const attrs = {};
      for (const [, key, , dq, sq, bare] of (rawAttrs ?? "").matchAll(/([a-z-]+)(\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/gi))
        attrs[key.toLowerCase()] = unescape(dq ?? sq ?? bare ?? "");
      const node = element(open, attrs);
      top.childNodes.push(node);
      if (!VOID.has(open.toLowerCase())) stack.push(node);
    }
  }
  return root;
}

const readBack = (document) => fromNodes(parse(toHtml(document)), { preserveSpace: true });
const paste = (html) => fromNodes(parse(html));
const lines = (document) => document.blocks.map((b) => b.type === "text" ? `${b.kind}${b.kind === "heading" ? b.level : ""}${b.indent ? `+${b.indent}` : ""}${b.checked ? "x" : ""}:${b.spans.map((s) => s.text).join("")}` : b.type);

for (const fixture of shared.fixtures) {
  test(`editor round trip keeps every byte: ${fixture.name}`, () => {
    const loaded = load(fixture.plain, fixture.encoded);
    assert.equal(loaded.source, "rich");
    const back = readBack(loaded.document);
    assert.ok(sameDocument(back, loaded.document), JSON.stringify(back));
    // What the Windows app saves is exactly what the Android app wrote.
    assert.deepEqual(storageFields(back), [fixture.plain, fixture.encoded]);
  });
}

test("every mark, color, line style and table survives the editor", () => {
  const marks = [{ bold: true }, { italic: true }, { underline: true }, { strike: true }, { code: true }, { color: "red" }, { bg: "yellow" },
    { link: "https://example.com/a?b=1&c=\"2\"" }, { bold: true, italic: true, underline: true, strike: true, code: true, color: "blue", bg: "pink", link: "mailto:a@b.co" }];
  const doc = { blocks: [
    textBlock("heading", [span("Title")], { level: 1 }), textBlock("heading", [span("Sub")], { level: 2 }), textBlock("heading", [span("Small")], { level: 3 }),
    textBlock("paragraph", marks.map((m, i) => span(`part${i} `, m))),
    textBlock("bullet", [span("a")]), textBlock("bullet", [span("b")], { indent: 2 }),
    textBlock("numbered", [span("one")]), textBlock("numbered", [span("two")]), textBlock("numbered", [span("two.one")], { indent: 1 }),
    textBlock("check", [span("done")], { checked: true }), textBlock("check", [span("todo")], { indent: 1 }),
    textBlock("quote", [span("quoted <b>not bold</b> & more")]), textBlock("code", [span("  let x = 1;  // spaces kept")]),
    textBlock("paragraph", []), { type: "divider" },
    { type: "table", header: true, rows: [[[span("Name", { bold: true })], [span("Value")]], [[span("x", { color: "green" })], []]] },
    { type: "table", header: false, rows: [[[span("no header")]]] },
    textBlock("paragraph", [span("tab\there  nbsp  two spaces")]),
  ] };
  const back = readBack(doc);
  assert.equal(encode(back), encode(doc));
  assert.equal(plainText(back), plainText(doc));
});

test("pasted HTML keeps only what notes have", () => {
  const doc = paste(`<meta charset="utf-8"><style>p{color:red}</style><script>alert(1)</script>
    <h1>Heading</h1><h4>Small</h4>
    <p>Some <b>bold</b>, <i>italic</i>, <span style="text-decoration: underline">under</span> and <del>gone</del>
    <a href="javascript:alert(1)">bad link</a> <a href="https://ok.example/path">good link</a> <img src=x onerror=alert(1)>
    <iframe src="https://evil.example"></iframe></p>
    <b style="font-weight:normal" id="docs-internal-guid"><span style="font-weight:700">docs bold</span> plain</b>
    <ul><li>one</li><li>two<ul><li>nested</li></ul></li></ul>
    <ol><li>first</li><li>second</li></ol>
    <ul><li><input type="checkbox" checked> done</li><li><input type="checkbox"> open</li></ul>
    <blockquote><p>q1</p><p>q2</p></blockquote>
    <pre>line 1
  line 2</pre>
    <hr>
    <table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td><p>x</p><p>y</p></td><td></td></tr></tbody></table>`);
  assert.deepEqual(lines(doc), [
    "heading1:Heading", "heading3:Small",
    "paragraph:Some bold, italic, under and gone bad link good link",
    "paragraph:docs bold plain",
    "bullet:one", "bullet:two", "bullet+1:nested", "numbered:first", "numbered:second", "checkx:done", "check:open",
    "quote:q1", "quote:q2", "code:line 1", "code:  line 2", "divider", "table",
  ]);
  const spans = doc.blocks[2].spans;
  assert.deepEqual(spans.find((s) => s.text === "bold").marks, { bold: true });
  assert.deepEqual(spans.find((s) => s.text === "under").marks, { underline: true });
  assert.deepEqual(spans.find((s) => s.text === "gone").marks, { strike: true });
  assert.deepEqual(spans.find((s) => s.text.includes("bad link")).marks, {}, "unsafe link dropped, text kept");
  assert.deepEqual(spans.find((s) => s.text === "good link").marks, { link: "https://ok.example/path" });
  assert.deepEqual(doc.blocks[3].spans, [{ text: "docs bold", marks: { bold: true } }, { text: " plain", marks: {} }]);
  const table = doc.blocks[doc.blocks.length - 1];
  assert.equal(table.header, true);
  assert.deepEqual(table.rows.map((row) => row.map((cell) => cell.map((s) => s.text).join(""))), [["A", "B"], ["x y", ""]]);
  assert.ok(!JSON.stringify(doc).includes("alert"));
  assert.ok(!JSON.stringify(doc).includes("evil"));
});

test("line breaks inside paragraphs and empty paragraphs", () => {
  assert.deepEqual(lines(paste("<p>a<br>b<br></p><p><br></p><p></p><div>c</div>")), ["paragraph:a", "paragraph:b", "paragraph:", "paragraph:", "paragraph:c"]);
  assert.deepEqual(lines(readBack({ blocks: [textBlock(), textBlock("bullet"), textBlock()] })), ["paragraph:", "bullet:", "paragraph:"]);
});

test("pasted tables are cut to the size notes allow", () => {
  const row = `<tr>${"<td>c</td>".repeat(20)}</tr>`;
  const doc = paste(`<table>${row.repeat(60)}</table>`);
  assert.equal(doc.blocks[0].rows.length, 50);
  assert.equal(doc.blocks[0].rows[0].length, 12);
  assert.ok(encode(doc));
});

test("plain pasted text becomes lines", () => {
  assert.deepEqual(lines(fromPastedText("a\r\nb\n\nc")), ["paragraph:a", "paragraph:b", "paragraph:", "paragraph:c"]);
});

test("decoded Android JSON with every feature round trips", () => {
  const json = shared.fixtures.map((f) => f.encoded);
  for (const encoded of json) {
    const doc = decode(encoded).document;
    assert.equal(encode(readBack(doc)), encoded);
  }
});
