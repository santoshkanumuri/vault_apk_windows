// Rich notes, format v1 ("nuvori.richnote"). The same format as the Android app
// (app/src/main/java/com/privatevault/app/notes/RichNote.kt in vault_apk; plan in docs/RICH-NOTES-PLAN.md).
// A note keeps its plain text in `notes` (the entry's body here) and its formatting as JSON in
// `fourthValue`. Apps that don't know rich notes keep showing the plain text. Both apps run the
// shared fixtures in docs/rich-notes/fixtures.json, so they read and write the same JSON.

export const FORMAT = "nuvori.richnote";
export const VERSION = 1;
export const MAX_INDENT = 4;
export const MAX_BLOCKS = 4000;
export const MAX_TABLE_ROWS = 50;
export const MAX_TABLE_COLUMNS = 12;
export const MAX_TEXT_CHARS = 200_000;
export const MAX_JSON_BYTES = 512 * 1024;
export const MAX_STORED_BYTES = 900_000;
export const MAX_LINK_CHARS = 2048;
export const DIVIDER_TEXT = "———";

export const NOTE_COLORS = ["gray", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink"] as const;
export type NoteColor = (typeof NOTE_COLORS)[number];

export type Marks = {
  bold?: boolean; italic?: boolean; underline?: boolean; strike?: boolean; code?: boolean;
  color?: NoteColor; bg?: NoteColor; link?: string;
};
export type Span = { text: string; marks: Marks };
export type TextKind = "paragraph" | "heading" | "bullet" | "numbered" | "check" | "quote" | "code";
export const TEXT_KINDS: readonly TextKind[] = ["paragraph", "heading", "bullet", "numbered", "check", "quote", "code"];
export type TextBlock = { type: "text"; kind: TextKind; spans: Span[]; level: number; indent: number; checked: boolean };
export type DividerBlock = { type: "divider" };
export type TableBlock = { type: "table"; header: boolean; rows: Span[][][] };
export type Block = TextBlock | DividerBlock | TableBlock;
export type RichDocument = { blocks: Block[] };
export type Source = "rich" | "plain" | "diverged" | "newer";
export type Loaded = { document: RichDocument; source: Source };

export class NoteTooLargeError extends Error {}

export const isListKind = (kind: TextKind) => kind === "bullet" || kind === "numbered" || kind === "check";

export function textBlock(kind: TextKind = "paragraph", spans: Span[] = [], extra: Partial<Omit<TextBlock, "type" | "kind" | "spans">> = {}): TextBlock {
  return { type: "text", kind, spans, level: extra.level ?? 1, indent: extra.indent ?? 0, checked: extra.checked ?? false };
}

export const span = (text: string, marks: Marks = {}): Span => ({ text, marks: cleanMarks(marks) });

export const spansText = (spans: Span[]) => spans.map((s) => s.text).join("");

/** Marks with only the set values, so two equal mark sets compare equal. */
export function cleanMarks(marks: Marks): Marks {
  const out: Marks = {};
  if (marks.bold) out.bold = true;
  if (marks.italic) out.italic = true;
  if (marks.underline) out.underline = true;
  if (marks.strike) out.strike = true;
  if (marks.code) out.code = true;
  if (marks.color && NOTE_COLORS.includes(marks.color)) out.color = marks.color;
  if (marks.bg && NOTE_COLORS.includes(marks.bg)) out.bg = marks.bg;
  if (marks.link) out.link = marks.link;
  return out;
}

export function sameMarks(a: Marks, b: Marks): boolean {
  return !!a.bold === !!b.bold && !!a.italic === !!b.italic && !!a.underline === !!b.underline && !!a.strike === !!b.strike &&
    !!a.code === !!b.code && (a.color ?? null) === (b.color ?? null) && (a.bg ?? null) === (b.bg ?? null) && (a.link ?? null) === (b.link ?? null);
}

const isPlainMarks = (marks: Marks) => Object.keys(cleanMarks(marks)).length === 0;

// ---- Reading ----

/** Reads a note the way every app must (plan: "Reading rules"). Never throws. */
export function load(plain: string, json: string): Loaded {
  if (!json || !json.trim()) return { document: fromPlain(plain), source: "plain" };
  let decoded: Decoded | null = null;
  try { decoded = decode(json); } catch { decoded = null; }
  if (!decoded) return { document: fromPlain(plain), source: "plain" };
  if (decoded.version > VERSION) return { document: fromPlain(plain), source: "newer" };
  if (decoded.plainHash !== hash(plain)) return { document: fromPlain(plain), source: "diverged" };
  return { document: decoded.document, source: "rich" };
}

/** The values to store: [plain text for the body, JSON for fourthValue ("" for plain notes)]. */
export function storageFields(document: RichDocument): [string, string] {
  const clean = normalize(document);
  const plain = plainText(clean);
  if (isPlainParagraphs(clean)) return [plain, ""];
  const json = encode(clean);
  const stored = utf8Length(jsonString(plain)) + utf8Length(jsonString(json));
  if (stored > MAX_STORED_BYTES) throw new NoteTooLargeError("This note is too long. Split it into two notes.");
  return [plain, json];
}

/** One paragraph per line; its plain text is the original text (after trimming). */
export function fromPlain(text: string): RichDocument {
  const normalized = trimText(normalizeNewlines(text));
  if (!normalized) return { blocks: [textBlock()] };
  return { blocks: normalized.split("\n").map((line) => textBlock("paragraph", line ? [span(sanitizeText(line))] : [])) };
}

export function plainText(document: RichDocument): string {
  const lines: string[] = [];
  let numbers = new Array<number>(MAX_INDENT + 1).fill(0);
  const reset = () => { numbers = new Array<number>(MAX_INDENT + 1).fill(0); };
  for (const block of document.blocks) {
    if (block.type === "text") {
      const indent = clamp(block.indent, 0, MAX_INDENT);
      const pad = "  ".repeat(indent);
      if (block.kind !== "numbered") reset();
      const text = spansText(block.spans);
      switch (block.kind) {
        case "paragraph": case "heading": case "code": lines.push(text); break;
        case "quote": lines.push(text.split("\n").map((line) => `> ${line}`).join("\n")); break;
        case "bullet": lines.push(`${pad}• ${text}`); break;
        case "check": lines.push(`${pad}${block.checked ? "☑" : "☐"} ${text}`); break;
        case "numbered": {
          numbers[indent] += 1;
          for (let deeper = indent + 1; deeper <= MAX_INDENT; deeper++) numbers[deeper] = 0;
          lines.push(`${pad}${numbers[indent]}. ${text}`);
          break;
        }
      }
    } else if (block.type === "divider") {
      reset(); lines.push(DIVIDER_TEXT);
    } else {
      reset();
      for (const row of block.rows) lines.push(row.map((cell) => spansText(cell).replace(/\n/g, " ")).join(" | "));
    }
  }
  return trimText(normalizeNewlines(lines.join("\n")));
}

/** First 32 hex characters of SHA-256 over the normalized plain text. */
export function hash(plain: string): string {
  return sha256Hex(new TextEncoder().encode(trimText(normalizeNewlines(plain)))).slice(0, 32);
}

export const normalizeNewlines = (text: string) => text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

// Kotlin's trim(): Unicode space separators and ASCII controls that Java counts as whitespace.
const EDGE_SPACE = /^[\p{Zs}\p{Zl}\p{Zp}\t\n\u000B\f\r\u001C-\u001F]+|[\p{Zs}\p{Zl}\p{Zp}\t\n\u000B\f\r\u001C-\u001F]+$/gu;

/** Trims the way the Android app does, so both apps hash the same text. */
export const trimText = (text: string) => text.replace(EDGE_SPACE, "");

/** Removes control characters (except line breaks and tabs) and bidirectional overrides. */
export function sanitizeText(text: string): string {
  const normalized = normalizeNewlines(text);
  let out = "";
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    const control = (code < 0x20 && code !== 0x0a && code !== 0x09) || code === 0x7f || (code >= 0x80 && code <= 0x9f);
    const bidi = (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) || code === 0x200e || code === 0x200f;
    if (!control && !bidi) out += normalized[i];
  }
  return out;
}

const HOST = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$|^\[[0-9A-Fa-f:.]+]$/;
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
// Characters java.net.URI refuses outside of escapes; Android drops such links, so this app does too.
const URI_ILLEGAL = /["<>\\^`{|}]/;

/** The host of an http(s) address as java.net.URI reads it, or null. */
function uriHost(value: string): string | null {
  if (URI_ILLEGAL.test(value) || /%(?![0-9A-Fa-f]{2})/.test(value)) return null;
  if ((value.match(/#/g) ?? []).length > 1) return null;
  const rest = value.slice(value.indexOf("://") + 3);
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  const path = end < 0 ? "" : rest.slice(end);
  if (/[[\]]/.test(path)) return null;
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (hostPort.startsWith("[")) {
    const close = hostPort.indexOf("]");
    if (close < 0) return null;
    const after = hostPort.slice(close + 1);
    if (after && !/^:\d*$/.test(after)) return null;
    return hostPort.slice(0, close + 1);
  }
  const colon = hostPort.lastIndexOf(":");
  if (colon >= 0 && !/^\d*$/.test(hostPort.slice(colon + 1))) return null;
  const host = colon >= 0 ? hostPort.slice(0, colon) : hostPort;
  return host || null;
}

/** Only http, https and mailto links are kept; anything else is dropped. */
export function sanitizeLink(link: string | null | undefined): string | null {
  const value = link == null ? undefined : trimText(link);
  if (!value || value.length > MAX_LINK_CHARS) return null;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f || /\s/.test(value[i])) return null;
  }
  const colon = value.indexOf(":");
  const scheme = colon < 0 ? "" : value.slice(0, colon).toLowerCase();
  if (scheme === "https" || scheme === "http") {
    if (!value.slice(scheme.length).startsWith("://")) return null;
    const host = uriHost(value);
    return host && HOST.test(host) ? value : null;
  }
  if (scheme === "mailto") return value.length > 7 ? value : null;
  return null;
}

/** Adds https:// to a bare address typed into the link box, then applies sanitizeLink. */
export function linkFromInput(input: string): string | null {
  const trimmed = input.trim();
  if (SCHEME.test(trimmed) && !trimmed.includes("://") && !/^mailto:/i.test(trimmed) && !/^[^:/]+:\d+(\/|$)/.test(trimmed)) return null;
  const withScheme = trimmed.includes("://") || /^mailto:/i.test(trimmed) ? trimmed
    : trimmed.includes("@") && !trimmed.includes("/") ? `mailto:${trimmed}` : `https://${trimmed}`;
  return sanitizeLink(withScheme);
}

/** Merges adjacent spans with equal marks, drops empty spans, clamps values, one line per text block. */
export function normalize(document: RichDocument): RichDocument {
  const blocks: Block[] = [];
  for (const block of document.blocks) {
    if (block.type === "text") {
      const kind = TEXT_KINDS.includes(block.kind) ? block.kind : "paragraph";
      for (const line of splitLines(block.spans)) {
        blocks.push({
          type: "text", kind, spans: normalizeSpans(line),
          level: clamp(Number.isFinite(block.level) ? Math.trunc(block.level) : 1, 1, 3),
          indent: isListKind(kind) ? clamp(Number.isFinite(block.indent) ? Math.trunc(block.indent) : 0, 0, MAX_INDENT) : 0,
          checked: kind === "check" && !!block.checked,
        });
      }
    } else if (block.type === "divider") {
      blocks.push({ type: "divider" });
    } else {
      const rows = block.rows.filter((row) => row.length > 0);
      if (!rows.length) continue;
      const columns = Math.max(...rows.map((row) => row.length));
      blocks.push({ type: "table", header: !!block.header, rows: rows.map((row) =>
        [...row, ...Array.from({ length: columns - row.length }, () => [] as Span[])].map(normalizeSpans)) });
    }
  }
  return { blocks: blocks.length ? blocks : [textBlock()] };
}

function splitLines(spans: Span[]): Span[][] {
  const lines: Span[][] = [[]];
  for (const s of spans) {
    normalizeNewlines(s.text).split("\n").forEach((part, index) => {
      if (index > 0) lines.push([]);
      if (part) lines[lines.length - 1].push({ text: part, marks: s.marks });
    });
  }
  return lines;
}

export function normalizeSpans(spans: Span[]): Span[] {
  const out: Span[] = [];
  for (const raw of spans) {
    const text = sanitizeText(raw.text).replace(/\n/g, " ");
    if (!text) continue;
    const marks = cleanMarks({ ...raw.marks, link: sanitizeLink(raw.marks.link) ?? undefined });
    const last = out[out.length - 1];
    if (last && sameMarks(last.marks, marks)) out[out.length - 1] = { text: last.text + text, marks };
    else out.push({ text, marks });
  }
  return out;
}

function isPlainParagraphs(document: RichDocument): boolean {
  return document.blocks.every((block) => block.type === "text" && block.kind === "paragraph" &&
    block.spans.every((s) => isPlainMarks(s.marks)) && !spansText(block.spans).includes("\n")) &&
    sameDocument(fromPlain(plainText(document)), document);
}

export function sameDocument(a: RichDocument, b: RichDocument): boolean {
  return a.blocks.length === b.blocks.length && a.blocks.every((block, index) => sameBlock(block, b.blocks[index]));
}

const sameSpans = (a: Span[], b: Span[]) => a.length === b.length && a.every((s, i) => s.text === b[i].text && sameMarks(s.marks, b[i].marks));

export function sameBlock(a: Block, b: Block): boolean {
  if (a.type !== b.type) return false;
  if (a.type === "text" && b.type === "text")
    return a.kind === b.kind && a.level === b.level && a.indent === b.indent && a.checked === b.checked && sameSpans(a.spans, b.spans);
  if (a.type === "table" && b.type === "table")
    return a.header === b.header && a.rows.length === b.rows.length &&
      a.rows.every((row, r) => row.length === b.rows[r].length && row.every((cell, c) => sameSpans(cell, b.rows[r][c])));
  return true;
}

// ---- JSON ----

type Decoded = { version: number; plainHash: string; document: RichDocument };
type JsonObject = Record<string, unknown>;

const isObject = (value: unknown): value is JsonObject => typeof value === "object" && value !== null && !Array.isArray(value);
const str = (o: JsonObject, key: string) => (typeof o[key] === "string" ? (o[key] as string) : null);
const bool = (o: JsonObject, key: string) => (typeof o[key] === "boolean" ? (o[key] as boolean) : null);
const int = (o: JsonObject, key: string) => {
  const value = o[key];
  return typeof value === "number" && Number.isInteger(value) && value >= -1e6 && value <= 1e6 ? value : null;
};

export function encode(document: RichDocument): string {
  const clean = normalize(document);
  if (clean.blocks.length > MAX_BLOCKS) throw new NoteTooLargeError("This note is too long. Split it into two notes.");
  const plain = plainText(clean);
  let textChars = 0;
  for (const block of clean.blocks) {
    if (block.type === "text") textChars += spansText(block.spans).length;
    else if (block.type === "table") for (const row of block.rows) for (const cell of row) textChars += spansText(cell).length;
  }
  if (textChars > MAX_TEXT_CHARS) throw new NoteTooLargeError("This note is too long. Split it into two notes.");
  for (const block of clean.blocks) {
    if (block.type === "table" && (block.rows.length > MAX_TABLE_ROWS || Math.max(...block.rows.map((r) => r.length)) > MAX_TABLE_COLUMNS))
      throw new NoteTooLargeError(`Tables can have up to ${MAX_TABLE_ROWS} rows and ${MAX_TABLE_COLUMNS} columns.`);
  }
  // Key order and escaping match the Android app's encoder (Gson), so both write identical JSON.
  const json = `{"format":${jsonString(FORMAT)},"version":${VERSION},"plainHash":${jsonString(hash(plain))},"blocks":[${clean.blocks.map(blockJson).join(",")}]}`;
  if (utf8Length(json) > MAX_JSON_BYTES) throw new NoteTooLargeError("This note has too much formatting to save. Split it into two notes.");
  return json;
}

function blockJson(block: Block): string {
  if (block.type === "divider") return `{"type":"divider"}`;
  if (block.type === "table") {
    const rows = block.rows.map((row) => `[${row.map((cell) => `{"spans":${spansJson(cell)}}`).join(",")}]`);
    return `{"type":"table","header":${block.header},"rows":[${rows.join(",")}]}`;
  }
  let out = `{"type":${jsonString(block.kind)}`;
  if (block.kind === "heading") out += `,"level":${block.level}`;
  if (isListKind(block.kind) && block.indent > 0) out += `,"indent":${block.indent}`;
  if (block.kind === "check") out += `,"checked":${block.checked}`;
  return `${out},"spans":${spansJson(block.spans)}}`;
}

function spansJson(spans: Span[]): string {
  return `[${spans.map((s) => {
    const m = s.marks;
    let out = `{"text":${jsonString(s.text)}`;
    if (m.bold) out += `,"bold":true`;
    if (m.italic) out += `,"italic":true`;
    if (m.underline) out += `,"underline":true`;
    if (m.strike) out += `,"strike":true`;
    if (m.code) out += `,"code":true`;
    if (m.color) out += `,"color":${jsonString(m.color)}`;
    if (m.bg) out += `,"bg":${jsonString(m.bg)}`;
    if (m.link) out += `,"link":${jsonString(m.link)}`;
    return `${out}}`;
  }).join(",")}]`;
}

/** A JSON string literal escaped the way Gson writes it. */
export function jsonString(value: string): string {
  let out = "\"";
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    const code = value.charCodeAt(i);
    if (char === "\"") out += "\\\"";
    else if (char === "\\") out += "\\\\";
    else if (char === "\t") out += "\\t";
    else if (char === "\b") out += "\\b";
    else if (char === "\n") out += "\\n";
    else if (char === "\r") out += "\\r";
    else if (char === "\f") out += "\\f";
    else if (code < 0x20 || code === 0x2028 || code === 0x2029) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += char;
  }
  return `${out}"`;
}

export function decode(json: string): Decoded | null {
  if (utf8Length(json) > MAX_JSON_BYTES) return null;
  let root: unknown;
  try { root = JSON.parse(json); } catch { return null; }
  if (!isObject(root) || str(root, "format") !== FORMAT) return null;
  const rawVersion = root.version;
  if (typeof rawVersion !== "number" || !Number.isFinite(rawVersion)) return null;
  const version = Math.trunc(rawVersion);
  const plainHash = str(root, "plainHash");
  if (plainHash === null) return null;
  if (version > VERSION) return { version, plainHash, document: { blocks: [] } };
  const list = root.blocks;
  if (!Array.isArray(list) || list.length > MAX_BLOCKS) return null;
  let textChars = 0;
  const blocks: Block[] = [];
  for (const element of list) {
    if (!isObject(element)) continue;
    const type = str(element, "type");
    if (type === "divider") { blocks.push({ type: "divider" }); continue; }
    if (type === "table") {
      const rows = element.rows;
      if (!Array.isArray(rows)) continue;
      if (rows.length > MAX_TABLE_ROWS) return null;
      const parsed: Span[][][] = [];
      for (const row of rows) {
        if (!Array.isArray(row) || row.length > MAX_TABLE_COLUMNS) return null;
        parsed.push(row.map((cell) => {
          const spans = parseSpans(isObject(cell) ? cell.spans : undefined);
          textChars += spansText(spans).length;
          return spans;
        }));
      }
      blocks.push({ type: "table", header: bool(element, "header") ?? true, rows: parsed });
      continue;
    }
    if (!type || !TEXT_KINDS.includes(type as TextKind)) continue;
    const spans = parseSpans(element.spans);
    textChars += spansText(spans).length;
    blocks.push({ type: "text", kind: type as TextKind, spans, level: int(element, "level") ?? 1,
      indent: int(element, "indent") ?? 0, checked: bool(element, "checked") ?? false });
  }
  if (textChars > MAX_TEXT_CHARS) return null;
  return { version, plainHash, document: normalize({ blocks }) };
}

function parseSpans(value: unknown): Span[] {
  if (!Array.isArray(value)) return [];
  const spans: Span[] = [];
  for (const item of value) {
    if (!isObject(item)) continue;
    const text = str(item, "text");
    if (text === null) continue;
    const color = str(item, "color");
    const bg = str(item, "bg");
    spans.push({ text: sanitizeText(text), marks: cleanMarks({
      bold: bool(item, "bold") === true, italic: bool(item, "italic") === true,
      underline: bool(item, "underline") === true, strike: bool(item, "strike") === true,
      code: bool(item, "code") === true,
      color: NOTE_COLORS.includes(color as NoteColor) ? (color as NoteColor) : undefined,
      bg: NOTE_COLORS.includes(bg as NoteColor) ? (bg as NoteColor) : undefined,
      link: sanitizeLink(str(item, "link")) ?? undefined,
    }) });
  }
  return spans;
}

// ---- Helpers ----

function clamp(value: number, min: number, max: number) { return Math.min(max, Math.max(min, value)); }

export const utf8Length = (text: string) => new TextEncoder().encode(text).length;

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256, synchronous so a note's hash can be computed while saving. */
export function sha256Hex(data: Uint8Array): string {
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const length = data.length;
  const padded = new Uint8Array(((length + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(length / 0x20000000));
  view.setUint32(padded.length - 4, (length << 3) >>> 0);
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const t1 = (hh + s1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  return Array.from(h, (x) => x.toString(16).padStart(8, "0")).join("");
}
