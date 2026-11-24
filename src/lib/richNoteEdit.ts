// Editing operations on a rich note document (richNote.ts). The editor keeps the document as its
// source of truth: formatting, Enter, Backspace at a line start, paste and undo all go through
// these functions, and the page is redrawn from the result.
//
// A position is a "slot" (a text line, or one table cell, in document order) and a character offset
// in that slot's text.

import {
  cleanMarks, isListKind, MAX_INDENT, MAX_TABLE_COLUMNS, MAX_TABLE_ROWS, normalize, normalizeSpans, sameMarks, sanitizeText,
  spansText, textBlock, type Block, type Marks, type RichDocument, type Span, type TableBlock, type TextBlock, type TextKind,
} from "./richNote.ts";

export type Position = { slot: number; offset: number };
export type Selection = { start: Position; end: Position };
export type SlotRef = { block: number; row?: number; col?: number };
export type Edited = { document: RichDocument; selection: Selection };
export type MarkKey = "bold" | "italic" | "underline" | "strike" | "code";

export function slots(document: RichDocument): SlotRef[] {
  const out: SlotRef[] = [];
  document.blocks.forEach((block, index) => {
    if (block.type === "text") out.push({ block: index });
    else if (block.type === "table") block.rows.forEach((row, r) => row.forEach((_, c) => out.push({ block: index, row: r, col: c })));
  });
  return out;
}

export function slotSpans(document: RichDocument, ref: SlotRef): Span[] {
  const block = document.blocks[ref.block];
  if (block.type === "text") return block.spans;
  if (block.type === "table") return block.rows[ref.row ?? 0][ref.col ?? 0];
  return [];
}

const clone = (document: RichDocument): RichDocument => ({ blocks: document.blocks.map((block) =>
  block.type === "text" ? { ...block, spans: [...block.spans] }
    : block.type === "table" ? { ...block, rows: block.rows.map((row) => row.map((cell) => [...cell])) } : block) });

function setSlotSpans(document: RichDocument, ref: SlotRef, spans: Span[]) {
  const block = document.blocks[ref.block];
  if (block.type === "text") document.blocks[ref.block] = { ...block, spans: normalizeSpans(spans) };
  else if (block.type === "table") block.rows[ref.row ?? 0][ref.col ?? 0] = normalizeSpans(spans);
}

export const collapsed = (selection: Selection) => comparePositions(selection.start, selection.end) === 0;

export function comparePositions(a: Position, b: Position) { return a.slot - b.slot || a.offset - b.offset; }

export function ordered(selection: Selection): Selection {
  return comparePositions(selection.start, selection.end) <= 0 ? selection : { start: selection.end, end: selection.start };
}

const caret = (position: Position): Selection => ({ start: position, end: position });

/** Splits spans at [offset]: the parts before and after. */
export function splitSpans(spans: Span[], offset: number): [Span[], Span[]] {
  const before: Span[] = [];
  const after: Span[] = [];
  let index = 0;
  for (const s of spans) {
    const end = index + s.text.length;
    if (end <= offset) before.push(s);
    else if (index >= offset) after.push(s);
    else { before.push({ text: s.text.slice(0, offset - index), marks: s.marks }); after.push({ text: s.text.slice(offset - index), marks: s.marks }); }
    index = end;
  }
  return [before, after];
}

/** Calls [fn] for the selected part of each slot in the selection. */
function eachSelectedPart(document: RichDocument, selection: Selection, fn: (ref: SlotRef, from: number, to: number) => void) {
  const { start, end } = ordered(selection);
  const refs = slots(document);
  for (let slot = start.slot; slot <= end.slot && slot < refs.length; slot++) {
    const length = spansText(slotSpans(document, refs[slot])).length;
    const from = slot === start.slot ? start.offset : 0;
    const to = slot === end.slot ? end.offset : length;
    fn(refs[slot], Math.max(0, from), Math.min(length, to));
  }
}

function mapRange(spans: Span[], from: number, to: number, fn: (marks: Marks) => Marks): Span[] {
  const [head, rest] = splitSpans(spans, from);
  const [middle, tail] = splitSpans(rest, to - from);
  return [...head, ...middle.map((s) => ({ text: s.text, marks: cleanMarks(fn(s.marks)) })), ...tail];
}

/** The marks that typing at [position] would get: those of the character before it (a link only inside). */
export function marksAt(document: RichDocument, position: Position): Marks {
  const ref = slots(document)[position.slot];
  if (!ref) return {};
  const spans = slotSpans(document, ref);
  let index = 0;
  for (let i = 0; i < spans.length; i++) {
    const s = spans[i];
    const end = index + s.text.length;
    if (position.offset > index && position.offset <= end) {
      const atEnd = position.offset === end;
      const next = spans[i + 1];
      const keepLink = !atEnd || (next?.marks.link && next.marks.link === s.marks.link);
      return cleanMarks({ ...s.marks, link: keepLink ? s.marks.link : undefined });
    }
    index = end;
  }
  if (position.offset === 0 && spans[0]) return cleanMarks({ ...spans[0].marks, link: undefined });
  return {};
}

/** Marks that every selected character has (for a collapsed selection, the typing marks). */
export function activeMarks(document: RichDocument, selection: Selection): Marks {
  if (collapsed(selection)) return marksAt(document, selection.start);
  let result: Marks | null = null;
  eachSelectedPart(document, selection, (ref, from, to) => {
    let index = 0;
    for (const s of slotSpans(document, ref)) {
      const end = index + s.text.length;
      if (end > from && index < to) {
        const m = s.marks;
        result = result === null ? { ...m } : {
          bold: result.bold && m.bold, italic: result.italic && m.italic, underline: result.underline && m.underline,
          strike: result.strike && m.strike, code: result.code && m.code,
          color: result.color === m.color ? m.color : undefined, bg: result.bg === m.bg ? m.bg : undefined,
          link: result.link === m.link ? m.link : undefined,
        };
      }
      index = end;
    }
  });
  return cleanMarks(result ?? {});
}

/** Turns a simple mark on for the selection, or off when all of it already has it. */
export function toggleMark(document: RichDocument, selection: Selection, key: MarkKey): RichDocument {
  const on = !activeMarks(document, selection)[key];
  return updateMarks(document, selection, (marks) => ({ ...marks, [key]: on }));
}

export function updateMarks(document: RichDocument, selection: Selection, fn: (marks: Marks) => Marks): RichDocument {
  const next = clone(document);
  eachSelectedPart(document, selection, (ref, from, to) => {
    if (to > from) setSlotSpans(next, ref, mapRange(slotSpans(next, ref), from, to, fn));
  });
  return next;
}

export function clearFormatting(document: RichDocument, selection: Selection): RichDocument {
  return updateMarks(document, selection, (marks) => ({ link: marks.link }));
}

/** The text lines (block indexes) the selection touches. */
export function selectedLines(document: RichDocument, selection: Selection): number[] {
  const { start, end } = ordered(selection);
  const refs = slots(document);
  const lines = new Set<number>();
  for (let slot = start.slot; slot <= end.slot && slot < refs.length; slot++)
    if (document.blocks[refs[slot].block].type === "text") lines.add(refs[slot].block);
  return [...lines];
}

/** Sets the line style, or back to normal text when every selected line already has it. */
export function setLineKind(document: RichDocument, selection: Selection, kind: TextKind, level = 1): RichDocument {
  const lines = selectedLines(document, selection);
  const all = lines.length > 0 && lines.every((index) => {
    const block = document.blocks[index] as TextBlock;
    return block.kind === kind && (kind !== "heading" || block.level === level);
  });
  const next = clone(document);
  for (const index of lines) {
    const block = next.blocks[index] as TextBlock;
    const target: TextKind = all ? "paragraph" : kind;
    next.blocks[index] = { ...block, kind: target, level: target === "heading" ? level : 1,
      indent: isListKind(target) ? block.indent : 0, checked: target === "check" ? block.checked : false };
  }
  return next;
}

export function indent(document: RichDocument, selection: Selection, delta: number): RichDocument {
  const next = clone(document);
  for (const index of selectedLines(document, selection)) {
    const block = next.blocks[index] as TextBlock;
    if (isListKind(block.kind)) next.blocks[index] = { ...block, indent: Math.min(MAX_INDENT, Math.max(0, block.indent + delta)) };
  }
  return next;
}

export function toggleChecked(document: RichDocument, blockIndex: number): RichDocument {
  const block = document.blocks[blockIndex];
  if (block?.type !== "text" || block.kind !== "check") return document;
  const next = clone(document);
  next.blocks[blockIndex] = { ...block, checked: !block.checked };
  return next;
}

/** Puts a link on the selection, or replaces the selection with [label] linked. */
export function setLink(document: RichDocument, selection: Selection, link: string | null, label?: string): Edited {
  const range = ordered(selection);
  if (label && link) {
    const removed = deleteRange(document, range);
    const at = removed.selection.start;
    const inserted = insertText(removed.document, at, label, { ...marksAt(removed.document, at), link });
    return { document: inserted.document, selection: { start: at, end: inserted.selection.end } };
  }
  return { document: updateMarks(document, range, (marks) => ({ ...marks, link: link ?? undefined })), selection: range };
}

/** The whole link around a collapsed caret, so the link box can edit or remove it. */
export function linkRangeAt(document: RichDocument, position: Position): { selection: Selection; link: string; label: string } | null {
  const ref = slots(document)[position.slot];
  if (!ref) return null;
  let index = 0;
  for (const s of slotSpans(document, ref)) {
    const end = index + s.text.length;
    if (s.marks.link && position.offset >= index && position.offset <= end)
      return { selection: { start: { slot: position.slot, offset: index }, end: { slot: position.slot, offset: end } }, link: s.marks.link, label: s.text };
    index = end;
  }
  return null;
}

export function insertText(document: RichDocument, position: Position, text: string, marks: Marks): Edited {
  const ref = slots(document)[position.slot];
  if (!ref) return { document, selection: caret(position) };
  const clean = sanitizeText(text).replace(/\n/g, " ");
  const next = clone(document);
  const [before, after] = splitSpans(slotSpans(next, ref), position.offset);
  setSlotSpans(next, ref, [...before, { text: clean, marks: cleanMarks(marks) }, ...after]);
  return { document: next, selection: caret({ slot: position.slot, offset: position.offset + clean.length }) };
}

/** Removes the selected text. Whole lines, tables and dividers between the ends go too. */
export function deleteRange(document: RichDocument, selection: Selection): Edited {
  const { start, end } = ordered(selection);
  if (comparePositions(start, end) === 0) return { document, selection: caret(start) };
  const refs = slots(document);
  const a = refs[start.slot];
  const b = refs[end.slot];
  if (!a || !b) return { document, selection: caret(start) };
  const next = clone(document);
  if (start.slot === end.slot || (a.block === b.block && document.blocks[a.block].type === "table")) {
    // Inside one line, or across cells of one table: clear the text of each part.
    eachSelectedPart(document, { start, end }, (ref, from, to) => {
      const [head, rest] = splitSpans(slotSpans(next, ref), from);
      setSlotSpans(next, ref, [...head, ...splitSpans(rest, to - from)[1]]);
    });
    return { document: next, selection: caret(start) };
  }
  const startBlock = document.blocks[a.block];
  const endBlock = document.blocks[b.block];
  const head = startBlock.type === "text" ? splitSpans(startBlock.spans, start.offset)[0] : null;
  const tail = endBlock.type === "text" ? splitSpans(endBlock.spans, end.offset)[1] : null;
  const blocks: Block[] = [...next.blocks.slice(0, a.block)];
  if (startBlock.type === "text") blocks.push({ ...startBlock, spans: normalizeSpans([...(head ?? []), ...(endBlock.type === "text" ? tail ?? [] : [])]) });
  else blocks.push(next.blocks[a.block]);
  if (endBlock.type !== "text") blocks.push(next.blocks[b.block]);
  blocks.push(...next.blocks.slice(b.block + 1));
  const result = { blocks };
  const slot = slots(result).findIndex((ref) => ref.block === a.block && ref.row === a.row && ref.col === a.col);
  return { document: result, selection: caret({ slot: Math.max(0, slot), offset: startBlock.type === "text" ? start.offset : 0 }) };
}

/** The style a new line gets after Enter on a line of [block]'s style. */
function continuation(block: TextBlock): TextBlock {
  if (isListKind(block.kind)) return textBlock(block.kind, [], { indent: block.indent });
  if (block.kind === "quote" || block.kind === "code") return textBlock(block.kind);
  return textBlock();
}

/** Enter: splits the line at the caret. An empty list item steps out instead. */
export function splitLine(document: RichDocument, selection: Selection): Edited {
  const removed = deleteRange(document, selection);
  const { start } = removed.selection;
  const ref = slots(removed.document)[start.slot];
  if (!ref || ref.row !== undefined) return removed;
  const block = removed.document.blocks[ref.block] as TextBlock;
  const next = clone(removed.document);
  if (!spansText(block.spans) && (isListKind(block.kind) || block.kind === "quote" || block.kind === "code")) {
    next.blocks[ref.block] = block.indent > 0 ? { ...block, indent: block.indent - 1 } : textBlock();
    return { document: next, selection: caret(start) };
  }
  const [before, after] = splitSpans(block.spans, start.offset);
  if (start.offset === 0 && spansText(block.spans)) {
    // At the start of a line: a new line above, and this line keeps its style.
    next.blocks.splice(ref.block, 0, { ...continuation(block), kind: isListKind(block.kind) ? block.kind : "paragraph" });
    return { document: next, selection: caret({ slot: start.slot + 1, offset: 0 }) };
  }
  next.blocks[ref.block] = { ...block, spans: normalizeSpans(before) };
  next.blocks.splice(ref.block + 1, 0, { ...continuation(block), spans: normalizeSpans(after) });
  return { document: next, selection: caret({ slot: start.slot + 1, offset: 0 }) };
}

/** Backspace at the start of a line: a styled line becomes plain first, then joins the line above. */
export function backspaceAtLineStart(document: RichDocument, position: Position): Edited | null {
  const ref = slots(document)[position.slot];
  if (!ref || ref.row !== undefined || position.offset !== 0) return null;
  const block = document.blocks[ref.block] as TextBlock;
  const next = clone(document);
  if (block.kind !== "paragraph") {
    next.blocks[ref.block] = isListKind(block.kind) && block.indent > 0 ? { ...block, indent: block.indent - 1 } : textBlock("paragraph", block.spans);
    return { document: next, selection: caret(position) };
  }
  const previous = document.blocks[ref.block - 1];
  if (!previous) return { document, selection: caret(position) };
  if (previous.type === "divider") {
    next.blocks.splice(ref.block - 1, 1);
    return { document: next, selection: caret({ slot: position.slot, offset: 0 }) };
  }
  if (previous.type === "table") {
    // Removing a table takes the Delete table button, not a stray Backspace.
    if (!spansText(block.spans) && ref.block < document.blocks.length - 1) {
      next.blocks.splice(ref.block, 1);
      const cells = slots(next).filter((s) => s.block === ref.block - 1);
      const last = slots(next).length ? slots(next).indexOf(cells[cells.length - 1]) : 0;
      return { document: next, selection: caret({ slot: Math.max(0, last), offset: spansText(slotSpans(next, cells[cells.length - 1])).length }) };
    }
    return { document, selection: caret(position) };
  }
  const length = spansText(previous.spans).length;
  next.blocks[ref.block - 1] = { ...previous, spans: normalizeSpans([...previous.spans, ...block.spans]) };
  next.blocks.splice(ref.block, 1);
  return { document: next, selection: caret({ slot: position.slot - 1, offset: length }) };
}

/** Pastes a document at the selection: its first and last lines join the lines around the caret. */
export function insertDocument(document: RichDocument, selection: Selection, pasted: RichDocument): Edited {
  const removed = deleteRange(document, selection);
  const { start } = removed.selection;
  const ref = slots(removed.document)[start.slot];
  const incoming = normalize(pasted).blocks;
  if (!ref) return removed;
  if (ref.row !== undefined) {
    // Into a table cell only text fits.
    const text = incoming.map((block) => block.type === "text" ? spansText(block.spans) : "").filter(Boolean).join(" ");
    return insertText(removed.document, start, text, marksAt(removed.document, start));
  }
  const block = removed.document.blocks[ref.block] as TextBlock;
  const [before, after] = splitSpans(block.spans, start.offset);
  const first = incoming[0];
  const last = incoming[incoming.length - 1];
  if (incoming.length === 1 && first.type === "text") {
    const next = clone(removed.document);
    next.blocks[ref.block] = { ...block, spans: normalizeSpans([...before, ...first.spans, ...after]) };
    return { document: next, selection: caret({ slot: start.slot, offset: start.offset + spansText(first.spans).length }) };
  }
  const blocks: Block[] = [];
  let middle = incoming;
  if (first.type === "text") { blocks.push({ ...block, spans: normalizeSpans([...before, ...first.spans]) }); middle = middle.slice(1); }
  else if (spansText(before)) blocks.push({ ...block, spans: normalizeSpans(before) });
  let endBlock: TextBlock;
  if (last.type === "text" && middle.length > 0) {
    middle = middle.slice(0, -1);
    endBlock = { ...last, spans: normalizeSpans([...last.spans, ...after]) };
  } else endBlock = { ...continuation(block), kind: block.kind === "heading" ? "paragraph" : block.kind, spans: normalizeSpans(after) };
  const caretOffset = last.type === "text" && endBlock.spans !== undefined ? spansText(last.spans).length : 0;
  blocks.push(...middle, endBlock);
  const result = { blocks: [...removed.document.blocks.slice(0, ref.block), ...blocks, ...removed.document.blocks.slice(ref.block + 1)] };
  const endIndex = ref.block + blocks.length - 1;
  const slot = slots(result).findIndex((s) => s.block === endIndex);
  return { document: result, selection: caret({ slot, offset: last.type === "text" && incoming.length > 1 ? caretOffset : 0 }) };
}

/** Inserts a table or divider after the caret's line (in place of an empty line), with a line after it to type in. */
export function insertBlock(document: RichDocument, selection: Selection, block: Block): Edited {
  const ref = slots(document)[ordered(selection).end.slot];
  const at = ref ? ref.block : document.blocks.length - 1;
  const current = document.blocks[at];
  const replace = current?.type === "text" && !spansText(current.spans) && current.kind === "paragraph";
  const blocks = [...document.blocks];
  const index = replace ? at : at + 1;
  blocks.splice(index, replace ? 1 : 0, block);
  if (blocks[index + 1]?.type !== "text") blocks.splice(index + 1, 0, textBlock());
  const result = { blocks };
  const all = slots(result);
  const target = block.type === "table" ? all.findIndex((s) => s.block === index) : all.findIndex((s) => s.block === index + 1);
  return { document: result, selection: caret({ slot: Math.max(0, target), offset: 0 }) };
}

export function newTable(rows: number, columns: number, header: boolean): TableBlock {
  const r = Math.min(MAX_TABLE_ROWS, Math.max(1, rows));
  const c = Math.min(MAX_TABLE_COLUMNS, Math.max(1, columns));
  return { type: "table", header, rows: Array.from({ length: r }, () => Array.from({ length: c }, () => [] as Span[])) };
}

export type TableAction = "addRowAbove" | "addRowBelow" | "addColumnLeft" | "addColumnRight" | "removeRow" | "removeColumn" | "toggleHeader" | "removeTable";

/** Changes the table at [ref] (a cell slot). */
export function editTable(document: RichDocument, ref: SlotRef, action: TableAction): RichDocument {
  const block = document.blocks[ref.block];
  if (block?.type !== "table") return document;
  const row = ref.row ?? 0;
  const col = ref.col ?? 0;
  const rows = block.rows.map((cells) => [...cells]);
  const width = rows[0]?.length ?? 1;
  const empty = () => [] as Span[];
  switch (action) {
    case "addRowAbove": case "addRowBelow":
      if (rows.length < MAX_TABLE_ROWS) rows.splice(row + (action === "addRowBelow" ? 1 : 0), 0, Array.from({ length: width }, empty));
      break;
    case "addColumnLeft": case "addColumnRight":
      if (width < MAX_TABLE_COLUMNS) rows.forEach((cells) => cells.splice(col + (action === "addColumnRight" ? 1 : 0), 0, empty()));
      break;
    case "removeRow": if (rows.length > 1) rows.splice(row, 1); break;
    case "removeColumn": if (width > 1) rows.forEach((cells) => cells.splice(col, 1)); break;
    case "toggleHeader": break;
    case "removeTable": {
      const blocks = document.blocks.filter((_, index) => index !== ref.block);
      return normalize({ blocks });
    }
  }
  const next = { blocks: [...document.blocks] };
  next.blocks[ref.block] = { ...block, header: action === "toggleHeader" ? !block.header : block.header, rows };
  return next;
}

export const sameMarksAt = (a: Marks, b: Marks) => sameMarks(cleanMarks(a), cleanMarks(b));

/** Delete at the end of a line: the next line joins this one, or a divider after it goes. Tables stay. */
export function deleteAtLineEnd(document: RichDocument, position: Position): Edited | null {
  const ref = slots(document)[position.slot];
  if (!ref || ref.row !== undefined) return null;
  const block = document.blocks[ref.block] as TextBlock;
  if (position.offset !== spansText(block.spans).length) return null;
  const following = document.blocks[ref.block + 1];
  if (!following || following.type === "table") return { document, selection: caret(position) };
  const next = clone(document);
  if (following.type === "divider") next.blocks.splice(ref.block + 1, 1);
  else {
    next.blocks[ref.block] = { ...block, spans: normalizeSpans([...block.spans, ...following.spans]) };
    next.blocks.splice(ref.block + 1, 1);
  }
  return { document: next, selection: caret(position) };
}

/** The selected part of the document, for copying inside the editor. */
export function slice(document: RichDocument, selection: Selection): RichDocument {
  const { start, end } = ordered(selection);
  const refs = slots(document);
  const a = refs[start.slot];
  const b = refs[end.slot];
  if (!a || !b) return { blocks: [textBlock()] };
  const cut = (spans: Span[], from: number, to: number) => splitSpans(splitSpans(spans, from)[1], to - from)[0];
  if (start.slot === end.slot) return normalize({ blocks: [textBlock("paragraph", cut(slotSpans(document, a), start.offset, end.offset))] });
  const blocks: Block[] = [];
  for (let index = a.block; index <= b.block; index++) {
    const block = document.blocks[index];
    if (block.type === "text") {
      const from = index === a.block ? start.offset : 0;
      const to = index === b.block ? end.offset : spansText(block.spans).length;
      blocks.push({ ...block, spans: cut(block.spans, from, to) });
    } else blocks.push(block);
  }
  return normalize({ blocks });
}
