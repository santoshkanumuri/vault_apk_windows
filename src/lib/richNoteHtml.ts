// Between rich note documents (richNote.ts) and HTML.
//
// toHtml draws a document as the editor's markup. fromNodes reads markup back: the editor's own
// (every keystroke) and anything pasted, through an allow-list. Nothing from pasted HTML survives
// but text, the marks and line styles the note format has, palette colors, and safe links.
// fromNodes works on a tiny node interface, so the same code runs on the browser DOM and in tests.

import {
  cleanMarks, isListKind, MAX_INDENT, MAX_TABLE_COLUMNS, MAX_TABLE_ROWS, NOTE_COLORS, normalize, normalizeSpans,
  sanitizeLink, spansText, textBlock, type Block, type Marks, type NoteColor, type RichDocument, type Span, type TextBlock, type TextKind,
} from "./richNote.ts";

// ---- Document to HTML ----

const escapeText = (text: string) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/ /g, "&nbsp;");
const escapeAttr = (text: string) => text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/ /g, "&nbsp;");

/** One span, wrapped from the outside in: link, code, bold, italic, underline, strike, colors. */
export function spanHtml(s: Span): string {
  let html = escapeText(s.text);
  const m = s.marks;
  if (m.color || m.bg) {
    const attrs = `${m.color ? ` data-color="${m.color}"` : ""}${m.bg ? ` data-bg="${m.bg}"` : ""}`;
    html = `<span class="rn-c"${attrs}>${html}</span>`;
  }
  if (m.strike) html = `<s>${html}</s>`;
  if (m.underline) html = `<u>${html}</u>`;
  if (m.italic) html = `<em>${html}</em>`;
  if (m.bold) html = `<strong>${html}</strong>`;
  if (m.code) html = `<code>${html}</code>`;
  // In the editor a link has no href, so a click edits it rather than opening anything.
  if (m.link) html = `<a class="rn-link" data-link="${escapeAttr(m.link)}">${html}</a>`;
  return html;
}

const spansHtml = (spans: Span[]) => (spans.length ? spans.map(spanHtml).join("") : "<br>");

/** The number each numbered line shows (0 for other lines), counted like the plain text. */
export function listNumbers(document: RichDocument): number[] {
  const out: number[] = [];
  let numbers = new Array<number>(MAX_INDENT + 1).fill(0);
  for (const block of document.blocks) {
    if (block.type === "text" && block.kind === "numbered") {
      numbers[block.indent] += 1;
      for (let deeper = block.indent + 1; deeper <= MAX_INDENT; deeper++) numbers[deeper] = 0;
      out.push(numbers[block.indent]);
    } else {
      numbers = new Array<number>(MAX_INDENT + 1).fill(0);
      out.push(0);
    }
  }
  return out;
}

export function textBlockHtml(block: TextBlock, number: number): string {
  const inner = spansHtml(block.spans);
  switch (block.kind) {
    case "paragraph": return `<p class="rn-slot">${inner}</p>`;
    case "heading": return `<h${block.level} class="rn-slot">${inner}</h${block.level}>`;
    case "quote": return `<blockquote class="rn-slot">${inner}</blockquote>`;
    case "code": return `<pre class="rn-slot">${inner}</pre>`;
    default: {
      const extra = block.kind === "numbered" ? ` data-number="${number}"` : block.kind === "check" ? ` data-checked="${block.checked}"` : "";
      return `<div class="rn-slot rn-li" data-kind="${block.kind}" data-indent="${block.indent}"${extra}>${inner}</div>`;
    }
  }
}

export function toHtml(document: RichDocument): string {
  const numbers = listNumbers(document);
  return document.blocks.map((block, index) => {
    if (block.type === "text") return textBlockHtml(block, numbers[index]);
    if (block.type === "divider") return `<hr contenteditable="false">`;
    const rows = block.rows.map((row, r) => {
      const tag = block.header && r === 0 ? "th" : "td";
      return `<tr>${row.map((cell) => `<${tag} class="rn-slot">${spansHtml(cell)}</${tag}>`).join("")}</tr>`;
    }).join("");
    return `<table class="rn-table"${block.header ? ` data-header="true"` : ""}><tbody>${rows}</tbody></table>`;
  }).join("");
}

// ---- HTML to document ----

/** The part of a DOM node the reader needs. Browser nodes fit it as they are. */
export type HtmlNode = {
  nodeType: number;
  nodeName: string;
  nodeValue: string | null;
  childNodes: ArrayLike<HtmlNode>;
  getAttribute?: (name: string) => string | null;
};

const TEXT_NODE = 3;
const ELEMENT_NODE = 1;

/** Never read: their text is code, styling or hidden content. */
const SKIPPED = new Set(["SCRIPT", "STYLE", "TEMPLATE", "IFRAME", "OBJECT", "EMBED", "SVG", "MATH", "IMG", "PICTURE", "VIDEO",
  "AUDIO", "CANVAS", "INPUT", "BUTTON", "SELECT", "TEXTAREA", "NOSCRIPT", "HEAD", "META", "LINK", "TITLE", "BASE", "FRAME",
  "FRAMESET", "APPLET", "DIALOG", "PORTAL", "SOURCE", "TRACK", "MAP", "AREA", "COLGROUP", "COL", "CAPTION"]);

const BLOCKS = new Set(["P", "DIV", "H1", "H2", "H3", "H4", "H5", "H6", "BLOCKQUOTE", "PRE", "UL", "OL", "LI", "SECTION",
  "ARTICLE", "MAIN", "HEADER", "FOOTER", "NAV", "ASIDE", "FIGURE", "FIGCAPTION", "DL", "DT", "DD", "ADDRESS", "FIELDSET",
  "FORM", "CENTER", "DETAILS", "SUMMARY", "BODY", "HTML", "LEGEND", "HGROUP"]);

type LineStyle = { kind: TextKind; level: number; indent: number; checked: boolean };
type Context = { marks: Marks; style: LineStyle; listDepth: number; listKind: "bullet" | "numbered"; pre: boolean };
type Options = { /** Keep spaces as typed (the editor's own markup); pasted HTML collapses them like a browser. */ preserveSpace: boolean };

const attr = (node: HtmlNode, name: string) => node.getAttribute?.(name) ?? null;
const color = (value: string | null): NoteColor | undefined =>
  value && (NOTE_COLORS as readonly string[]).includes(value) ? (value as NoteColor) : undefined;
const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

/** Marks an inline element adds. Pasted inline styles count for bold, italic, underline and strike only. */
function inlineMarks(node: HtmlNode, name: string, marks: Marks): Marks {
  const next: Marks = { ...marks };
  switch (name) {
    case "B": case "STRONG": next.bold = true; break;
    case "I": case "EM": case "CITE": case "DFN": next.italic = true; break;
    case "U": case "INS": next.underline = true; break;
    case "S": case "STRIKE": case "DEL": next.strike = true; break;
    case "CODE": case "KBD": case "SAMP": case "TT": next.code = true; break;
    case "A": {
      const link = sanitizeLink(attr(node, "data-link") ?? attr(node, "href"));
      next.link = link ?? undefined;
      break;
    }
  }
  const textColor = color(attr(node, "data-color"));
  const background = color(attr(node, "data-bg"));
  if (textColor) next.color = textColor;
  if (background) next.bg = background;
  const style = (attr(node, "style") ?? "").toLowerCase();
  if (style) {
    const weight = /font-weight\s*:\s*([a-z0-9]+)/.exec(style)?.[1];
    if (weight) next.bold = weight === "bold" || weight === "bolder" || Number(weight) >= 600;
    const fontStyle = /font-style\s*:\s*([a-z]+)/.exec(style)?.[1];
    if (fontStyle) next.italic = fontStyle === "italic" || fontStyle === "oblique";
    const decoration = /text-decoration(?:-line)?\s*:\s*([a-z -]+)/.exec(style)?.[1];
    if (decoration) {
      if (decoration.includes("underline")) next.underline = true;
      if (decoration.includes("line-through")) next.strike = true;
    }
  }
  return next;
}

class Reader {
  blocks: Block[] = [];
  private spans: Span[] = [];
  private style: LineStyle = { kind: "paragraph", level: 1, indent: 0, checked: false };
  private fromBreak = false;
  private pushedLines = 0;

  private options: Options;

  constructor(options: Options) { this.options = options; }

  private hasText() { return this.spans.some((s) => s.text.length > 0); }

  /** Ends the current line: kept when it has text, or when [keepEmpty] (an empty paragraph, or a line break). */
  private endLine(keepEmpty: boolean) {
    // Pasted markup is full of spaces and line breaks between tags: a line of only those is no line.
    const spans = this.options.preserveSpace || this.style.kind === "code" ? this.spans : trimSpans(this.spans);
    if (spans.some((s) => s.text.length > 0) || keepEmpty) {
      this.blocks.push({ ...textBlock(this.style.kind, spans, this.style) });
      this.pushedLines++;
    }
    this.spans = [];
    this.fromBreak = false;
  }

  private addText(text: string, context: Context) {
    const keep = this.options.preserveSpace || context.pre;
    const lines = keep ? text.replace(/\r\n?/g, "\n").split("\n") : [text.replace(/[\t\n\r\f ]+/g, " ")];
    lines.forEach((line, index) => {
      if (index > 0) { this.style = context.style; this.endLine(true); this.fromBreak = true; }
      if (!line) return;
      if (!this.hasText()) this.style = context.style;
      this.spans.push({ text: line, marks: cleanMarks(context.marks) });
    });
  }

  read(node: HtmlNode, context: Context) {
    if (node.nodeType === TEXT_NODE) { if (node.nodeValue) this.addText(node.nodeValue, context); return; }
    if (node.nodeType !== ELEMENT_NODE && node.nodeName !== "#document" && node.nodeName !== "#document-fragment") return;
    const name = node.nodeName.toUpperCase();
    if (SKIPPED.has(name)) return;
    if (attr(node, "aria-hidden") === "true" || attr(node, "hidden") !== null) return;
    if (name === "BR") { this.style = context.style; this.endLine(true); this.fromBreak = true; return; }
    if (name === "HR") { this.endLine(false); this.blocks.push({ type: "divider" }); this.pushedLines++; return; }
    if (name === "TABLE") { this.endLine(false); this.readTable(node, context); return; }
    if (name === "TR" || name === "TD" || name === "TH" || name === "TBODY" || name === "THEAD" || name === "TFOOT") {
      // Table parts outside a table: read as lines.
      this.readBlock(node, context, context.style);
      return;
    }
    if (BLOCKS.has(name)) { this.readBlock(node, context, this.blockStyle(node, name, context)); return; }
    const inner = { ...context, marks: inlineMarks(node, name, context.marks) };
    for (const child of Array.from(node.childNodes)) this.read(child, inner);
  }

  private blockStyle(node: HtmlNode, name: string, context: Context): LineStyle {
    const style = { ...context.style };
    const kind = attr(node, "data-kind");
    if (kind === "bullet" || kind === "numbered" || kind === "check") {
      return { kind, level: 1, indent: clamp(Number(attr(node, "data-indent")) || 0, 0, MAX_INDENT), checked: kind === "check" && attr(node, "data-checked") === "true" };
    }
    switch (name) {
      case "H1": return { ...style, kind: "heading", level: 1, indent: 0 };
      case "H2": return { ...style, kind: "heading", level: 2, indent: 0 };
      case "H3": case "H4": case "H5": case "H6": return { ...style, kind: "heading", level: 3, indent: 0 };
      case "BLOCKQUOTE": return { ...style, kind: "quote", indent: 0 };
      case "PRE": return { ...style, kind: "code", indent: 0 };
      case "LI": {
        const box = findCheckbox(node);
        if (box) return { kind: "check", level: 1, indent: clamp(context.listDepth - 1, 0, MAX_INDENT), checked: box.checked };
        return { kind: context.listKind, level: 1, indent: clamp(context.listDepth - 1, 0, MAX_INDENT), checked: false };
      }
    }
    return style;
  }

  private readBlock(node: HtmlNode, context: Context, style: LineStyle) {
    this.endLine(false);
    const name = node.nodeName.toUpperCase();
    const inner: Context = {
      ...context, style,
      pre: context.pre || name === "PRE",
      listDepth: name === "UL" || name === "OL" ? context.listDepth + 1 : context.listDepth,
      listKind: name === "OL" ? "numbered" : name === "UL" ? "bullet" : context.listKind,
      marks: inlineMarks(node, name, context.marks),
    };
    const before = this.pushedLines;
    this.style = style;
    for (const child of Array.from(node.childNodes)) this.read(child, inner);
    // A trailing line break only holds the line open; an empty block is an empty line.
    const emptyBlock = this.pushedLines === before && !this.hasText() && name !== "UL" && name !== "OL";
    if (this.fromBreak && !this.hasText()) { this.spans = []; this.fromBreak = false; }
    else this.endLine(emptyBlock);
    this.style = context.style;
  }

  private readTable(node: HtmlNode, context: Context) {
    const rows: { cells: Span[][]; header: boolean }[] = [];
    const walk = (parent: HtmlNode, inHead: boolean) => {
      for (const child of Array.from(parent.childNodes)) {
        if (child.nodeType !== ELEMENT_NODE) continue;
        const name = child.nodeName.toUpperCase();
        if (name === "THEAD" || name === "TBODY" || name === "TFOOT") walk(child, name === "THEAD");
        else if (name === "TR" && rows.length < MAX_TABLE_ROWS) {
          const cells: Span[][] = [];
          let allHeader = true;
          for (const cell of Array.from(child.childNodes)) {
            const cellName = cell.nodeName.toUpperCase();
            if (cell.nodeType !== ELEMENT_NODE || (cellName !== "TD" && cellName !== "TH")) continue;
            if (cells.length >= MAX_TABLE_COLUMNS) break;
            if (cellName !== "TH") allHeader = false;
            const reader = new Reader(this.options);
            for (const part of Array.from(cell.childNodes)) reader.read(part, { ...context, style: { kind: "paragraph", level: 1, indent: 0, checked: false }, listDepth: 0 });
            reader.finish();
            const lines = reader.blocks.filter((block): block is TextBlock => block.type === "text").map((block) => block.spans);
            const joined: Span[] = [];
            lines.forEach((spans, index) => { if (index > 0 && spans.length) joined.push({ text: " ", marks: {} }); joined.push(...spans); });
            cells.push(normalizeSpans(joined));
          }
          if (cells.length) rows.push({ cells, header: inHead || allHeader });
        }
      }
    };
    walk(node, false);
    if (!rows.length) return;
    const header = attr(node, "data-header") === "true" || rows[0].header;
    this.blocks.push({ type: "table", header, rows: rows.map((row) => row.cells) });
    this.pushedLines++;
  }

  finish() { this.endLine(false); }
}

function findCheckbox(node: HtmlNode): { checked: boolean } | null {
  for (const child of Array.from(node.childNodes)) {
    if (child.nodeType !== ELEMENT_NODE) continue;
    const name = child.nodeName.toUpperCase();
    if (name === "INPUT" && (attr(child, "type") ?? "").toLowerCase() === "checkbox") return { checked: attr(child, "checked") !== null };
    if (name === "UL" || name === "OL" || name === "LI") continue;
    const inner = findCheckbox(child);
    if (inner) return inner;
  }
  return null;
}

function trimSpans(spans: Span[]): Span[] {
  const out = spans.map((s) => ({ ...s }));
  while (out.length && !out[0].text.trimStart()) out.shift();
  while (out.length && !out[out.length - 1].text.trimEnd()) out.pop();
  if (out.length) {
    out[0] = { ...out[0], text: out[0].text.trimStart() };
    out[out.length - 1] = { ...out[out.length - 1], text: out[out.length - 1].text.trimEnd() };
  }
  return out;
}

/** Reads the children of [root] into a document. */
export function fromNodes(root: HtmlNode, options: Options = { preserveSpace: false }): RichDocument {
  const reader = new Reader(options);
  const context: Context = { marks: {}, style: { kind: "paragraph", level: 1, indent: 0, checked: false }, listDepth: 0, listKind: "bullet", pre: false };
  for (const child of Array.from(root.childNodes)) reader.read(child, context);
  reader.finish();
  return normalize({ blocks: reader.blocks });
}

/** Plain text pasted as lines, keeping nothing but the text. */
export function fromPastedText(text: string): RichDocument {
  return normalize({ blocks: text.replace(/\r\n?/g, "\n").split("\n").map((line) => textBlock("paragraph", line ? [{ text: line, marks: {} }] : [])) });
}

/** True when the document is one line of plain text (pasting it needs nothing but the text). */
export const isSingleLine = (document: RichDocument) =>
  document.blocks.length === 1 && document.blocks[0].type === "text" && !isListKind(document.blocks[0].kind) && !!spansText(document.blocks[0].spans);
