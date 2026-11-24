// Run with `npm test`. Editing operations behind the Windows note editor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encode, plainText, span, textBlock } from "./richNote.ts";
import {
  activeMarks, backspaceAtLineStart, deleteAtLineEnd, deleteRange, editTable, indent, insertBlock, insertDocument, insertText,
  linkRangeAt, newTable, setLineKind, setLink, slice, slots, splitLine, toggleChecked, toggleMark,
} from "./richNoteEdit.ts";

const doc = (...blocks) => ({ blocks });
const p = (text, marks) => textBlock("paragraph", text ? [span(text, marks)] : []);
const at = (slot, offset) => ({ start: { slot, offset }, end: { slot, offset } });
const range = (s1, o1, s2, o2) => ({ start: { slot: s1, offset: o1 }, end: { slot: s2, offset: o2 } });
const texts = (d) => d.blocks.map((b) => b.type === "text" ? `${b.kind}${b.indent ? `+${b.indent}` : ""}:${b.spans.map((s) => s.text).join("")}` : b.type);

test("bold toggles on, then off, across two lines", () => {
  const start = doc(p("hello world"), p("second"));
  const bold = toggleMark(start, range(0, 6, 1, 3), "bold");
  assert.deepEqual(bold.blocks[0].spans, [span("hello "), span("world", { bold: true })]);
  assert.deepEqual(bold.blocks[1].spans, [span("sec", { bold: true }), span("ond")]);
  assert.equal(activeMarks(bold, range(0, 6, 1, 3)).bold, true);
  const plain = toggleMark(bold, range(0, 6, 1, 3), "bold");
  assert.equal(encode(plain), encode(start));
});

test("typing continues the marks before the caret, but not a link at its end", () => {
  const d = doc(textBlock("paragraph", [span("ab", { italic: true }), span("link", { link: "https://a.example" })]));
  assert.deepEqual(activeMarks(d, at(0, 2)), { italic: true });
  assert.deepEqual(activeMarks(d, at(0, 3)), { link: "https://a.example" });
  assert.deepEqual(activeMarks(d, at(0, 6)), {});
  const typed = insertText(d, at(0, 2).start, "c\nd", activeMarks(d, at(0, 2)));
  assert.equal(typed.document.blocks[0].spans[0].text, "abc d");
  assert.deepEqual(typed.selection.start, { slot: 0, offset: 5 });
});

test("line styles toggle and lists indent", () => {
  const d = doc(p("a"), p("b"));
  const bullets = setLineKind(d, range(0, 0, 1, 1), "bullet");
  assert.deepEqual(texts(bullets), ["bullet:a", "bullet:b"]);
  assert.deepEqual(texts(indent(bullets, at(1, 0), 1)), ["bullet:a", "bullet+1:b"]);
  assert.deepEqual(texts(setLineKind(bullets, range(0, 0, 1, 0), "bullet")), ["paragraph:a", "paragraph:b"]);
  const h2 = setLineKind(d, at(0, 0), "heading", 2);
  assert.equal(h2.blocks[0].level, 2);
  assert.equal(setLineKind(h2, at(0, 0), "heading", 1).blocks[0].level, 1);
  assert.deepEqual(texts(indent(d, at(0, 0), 1)), ["paragraph:a", "paragraph:b"], "only list lines indent");
});

test("Enter splits a line and continues the list; on an empty item it steps out", () => {
  const d = doc(textBlock("check", [span("buy milk")], { checked: true, indent: 1 }));
  const split = splitLine(d, at(0, 3));
  assert.deepEqual(texts(split.document), ["check+1:buy", "check+1: milk"]);
  assert.equal(split.document.blocks[1].checked, false, "a new item starts unchecked");
  assert.deepEqual(split.selection.start, { slot: 1, offset: 0 });
  const empty = splitLine(splitLine(split.document, at(1, 5)).document, at(2, 0));
  assert.deepEqual(texts(empty.document), ["check+1:buy", "check+1: milk", "check:"]);
  const out = splitLine(empty.document, at(2, 0));
  assert.deepEqual(texts(out.document), ["check+1:buy", "check+1: milk", "paragraph:"]);
  const heading = splitLine(doc(textBlock("heading", [span("Title")])), at(0, 5));
  assert.deepEqual(texts(heading.document), ["heading:Title", "paragraph:"]);
  const top = splitLine(doc(textBlock("heading", [span("Title")])), at(0, 0));
  assert.deepEqual(texts(top.document), ["paragraph:", "heading:Title"]);
});

test("Backspace at a line start: style first, then join; Delete at the end joins the next line", () => {
  const d = doc(p("one"), textBlock("bullet", [span("two")], { indent: 1 }));
  const outdented = backspaceAtLineStart(d, at(1, 0).start);
  assert.deepEqual(texts(outdented.document), ["paragraph:one", "bullet:two"]);
  const plain = backspaceAtLineStart(outdented.document, at(1, 0).start);
  assert.deepEqual(texts(plain.document), ["paragraph:one", "paragraph:two"]);
  const joined = backspaceAtLineStart(plain.document, at(1, 0).start);
  assert.deepEqual(texts(joined.document), ["paragraph:onetwo"]);
  assert.deepEqual(joined.selection.start, { slot: 0, offset: 3 });
  assert.deepEqual(texts(deleteAtLineEnd(plain.document, at(0, 3).start).document), ["paragraph:onetwo"]);
  const withDivider = doc(p("a"), { type: "divider" }, p("b"));
  assert.deepEqual(texts(backspaceAtLineStart(withDivider, at(1, 0).start).document), ["paragraph:a", "paragraph:b"]);
  assert.equal(backspaceAtLineStart(d, at(1, 1).start), null, "not at a line start");
});

test("a selection across lines, a divider and a table is deleted cleanly", () => {
  const d = doc(p("keep this"), { type: "divider" }, p("middle"), p("and this end"));
  const removed = deleteRange(d, range(0, 4, 2, 8));
  assert.deepEqual(texts(removed.document), ["paragraph:keep end"]);
  const withTable = doc(p("before"), newTable(1, 2, false), p("after"));
  const kept = deleteRange(withTable, range(0, 3, 3, 2));
  assert.deepEqual(texts(kept.document), ["paragraph:befter"], "a table inside the selection goes");
});

test("pasting several lines joins the first and last with the text around the caret", () => {
  const d = doc(p("Hello world"));
  const pasted = doc(p("big", { bold: true }), textBlock("bullet", [span("item")]), p("end "));
  const result = insertDocument(d, at(0, 6), pasted);
  assert.deepEqual(texts(result.document), ["paragraph:Hello big", "bullet:item", "paragraph:end world"]);
  assert.deepEqual(result.selection.start, { slot: 2, offset: 4 });
  const oneLine = insertDocument(d, at(0, 5), doc(p(",", { italic: true })));
  assert.equal(plainText(oneLine.document), "Hello, world");
});

test("tables: insert, grow, shrink, header and remove", () => {
  const inserted = insertBlock(doc(p("")), at(0, 0), newTable(2, 2, true));
  assert.deepEqual(texts(inserted.document), ["table", "paragraph:"]);
  assert.deepEqual(inserted.selection.start, { slot: 0, offset: 0 });
  const cell = slots(inserted.document)[3];
  assert.deepEqual(cell, { block: 0, row: 1, col: 1 });
  let t = editTable(inserted.document, cell, "addRowBelow");
  t = editTable(t, cell, "addColumnRight");
  assert.equal(t.blocks[0].rows.length, 3);
  assert.equal(t.blocks[0].rows[0].length, 3);
  t = editTable(t, cell, "removeColumn");
  t = editTable(t, cell, "toggleHeader");
  assert.equal(t.blocks[0].header, false);
  assert.deepEqual(texts(editTable(t, cell, "removeTable")), ["paragraph:"]);
  const typed = insertText(t, slots(t).length > 2 ? { slot: 2, offset: 0 } : { slot: 0, offset: 0 }, "x", {});
  assert.equal(typed.document.blocks[0].rows[1][0][0].text, "x");
});

test("links: add to a selection, find around the caret, remove", () => {
  const d = doc(p("see the site now"));
  const linked = setLink(d, range(0, 8, 0, 12), "https://site.example");
  const found = linkRangeAt(linked.document, at(0, 10).start);
  assert.equal(found.link, "https://site.example");
  assert.equal(found.label, "site");
  const unlinked = setLink(linked.document, found.selection, null);
  assert.equal(encode(unlinked.document), encode(d));
  const labeled = setLink(d, at(0, 4), "mailto:me@site.example", "mail me");
  assert.equal(plainText(labeled.document), "see mail methe site now");
});

test("checklist items toggle; copying a selection keeps its formatting", () => {
  const d = doc(textBlock("check", [span("a")]), p("bold part", { bold: true }));
  assert.equal(toggleChecked(d, 0).blocks[0].checked, true);
  const copied = slice(d, range(0, 0, 1, 4));
  assert.deepEqual(texts(copied), ["check:a", "paragraph:bold"]);
  assert.deepEqual(copied.blocks[1].spans[0].marks, { bold: true });
});
