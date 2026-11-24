import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ClipboardEvent as ReactClipboardEvent, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from "react";
import {
  Baseline, Bold, CheckSquare, ChevronDown, Code, Columns2, Eraser, Heading, Highlighter, Indent, Italic, Link2, List, ListOrdered,
  Minus, Outdent, Quote, Redo2, Rows2, SquareCode, Strikethrough, Table, Trash2, Underline, Undo2, Unlink,
} from "lucide-react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import { cx } from "../../lib/format";
import { linkFromInput, NOTE_COLORS, plainText, sameDocument, spansText, type Marks, type NoteColor, type RichDocument, type TextKind } from "../../lib/richNote";
import {
  activeMarks, backspaceAtLineStart, clearFormatting, collapsed, deleteAtLineEnd, deleteRange, editTable, indent, insertBlock, insertDocument,
  insertText, linkRangeAt, marksAt, newTable, ordered, setLineKind, setLink, slice, slots, splitLine, toggleChecked, toggleMark, updateMarks,
  type Edited, type MarkKey, type Position, type Selection, type TableAction,
} from "../../lib/richNoteEdit";
import { fromNodes, fromPastedText, toHtml, type HtmlNode } from "../../lib/richNoteHtml";
import { useOpenNoteLink } from "./RichNoteView";

export const COLOR_NAMES: Record<NoteColor, string> = {
  gray: "Gray", red: "Red", orange: "Orange", yellow: "Yellow", green: "Green", teal: "Teal", blue: "Blue", purple: "Purple", pink: "Pink",
};

type Snapshot = { document: RichDocument; selection: Selection | null };
type Toolbar = { marks: Marks; kind: TextKind; level: number; inList: boolean; inTable: boolean; link: string | null };

const UNDO_LIMIT = 200;
const TYPING_GROUP_MS = 1200;

// Copy inside the editor keeps formatting without putting HTML on the system clipboard: the
// clipboard gets plain text, and this remembers the formatted copy until something else is copied.
let lastCopy: { plain: string; document: RichDocument } | null = null;

type Props = { initial: RichDocument; onChange: (document: RichDocument) => void; label: string; autoFocus?: boolean; error?: string };

/** The rich note editor: a toolbar over an editable page that always reflects the note's document. */
export function RichNoteEditor({ initial, onChange, label, autoFocus, error }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const doc = useRef(initial);
  const undo = useRef<Snapshot[]>([]);
  const redo = useRef<Snapshot[]>([]);
  const lastTyping = useRef(0);
  const composing = useRef(false);
  const pending = useRef<{ position: Position; marks: Marks } | null>(null);
  const [toolbar, setToolbar] = useState<Toolbar>({ marks: {}, kind: "paragraph", level: 1, inList: false, inTable: false, link: null });
  const [history, setHistory] = useState({ undo: false, redo: false });
  const [linkDialog, setLinkDialog] = useState<{ selection: Selection; link: string; label: string; existing: boolean; needsLabel: boolean } | null>(null);
  const savedSelection = useRef<Selection | null>(null);
  const openLink = useOpenNoteLink();
  const labelId = useId();

  // ---- DOM positions ----

  const slotElements = () => Array.from(root.current?.querySelectorAll<HTMLElement>(".rn-slot") ?? []);

  const toPosition = useCallback((node: Node, offset: number): Position | null => {
    const editor = root.current;
    if (!editor || !editor.contains(node)) return null;
    const elements = slotElements();
    const element = (node.nodeType === Node.ELEMENT_NODE ? (node as Element) : node.parentElement)?.closest<HTMLElement>(".rn-slot");
    if (element && editor.contains(element)) {
      const range = document.createRange();
      range.setStart(element, 0);
      range.setEnd(node, offset);
      return { slot: elements.indexOf(element), offset: range.toString().length };
    }
    // Between lines (on the editor itself, a divider or a table's edge): the nearest line after the point,
    // or the end of the last line before it.
    if (node.nodeType === Node.ELEMENT_NODE && offset < node.childNodes.length) {
      const marker = node.childNodes[offset];
      const after = elements.findIndex((slot) => marker === slot || marker.contains(slot) || (marker.compareDocumentPosition(slot) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0);
      if (after >= 0) return { slot: after, offset: 0 };
    }
    let before = -1;
    elements.forEach((slot, index) => { if (node.contains(slot) || (slot.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0) before = index; });
    const last = before >= 0 ? before : elements.length - 1;
    return last >= 0 ? { slot: last, offset: elements[last].textContent?.length ?? 0 } : null;
  }, []);

  const readSelection = useCallback((): Selection | null => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0 || !selection.anchorNode || !selection.focusNode) return null;
    const start = toPosition(selection.anchorNode, selection.anchorOffset);
    const end = toPosition(selection.focusNode, selection.focusOffset);
    return start && end ? { start, end } : null;
  }, [toPosition]);

  const toPoint = (position: Position): [Node, number] | null => {
    const element = slotElements()[position.slot];
    if (!element) return null;
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let remaining = position.offset;
    let node = walker.nextNode();
    let last: Node | null = null;
    while (node) {
      const length = node.nodeValue?.length ?? 0;
      if (remaining <= length) return [node, remaining];
      remaining -= length;
      last = node;
      node = walker.nextNode();
    }
    return last ? [last, last.nodeValue?.length ?? 0] : [element, 0];
  };

  const applySelection = (selection: Selection) => {
    const start = toPoint(selection.start);
    const end = toPoint(selection.end);
    const current = window.getSelection();
    if (!start || !end || !current) return;
    current.setBaseAndExtent(start[0], start[1], end[0], end[1]);
  };

  // ---- Toolbar state ----

  const refreshToolbar = useCallback(() => {
    const selection = readSelection();
    if (!selection) return;
    const document = doc.current;
    const ref = slots(document)[selection.start.slot];
    const block = ref ? document.blocks[ref.block] : undefined;
    const hold = pending.current;
    const marks = hold && collapsed(selection) && hold.position.slot === selection.start.slot && hold.position.offset === selection.start.offset
      ? hold.marks : activeMarks(document, selection);
    if (hold && marks !== hold.marks) pending.current = null;
    const text = block?.type === "text" ? block : null;
    setToolbar({
      marks, kind: text?.kind ?? "paragraph", level: text?.level ?? 1,
      inList: !!text && (text.kind === "bullet" || text.kind === "numbered" || text.kind === "check"),
      inTable: block?.type === "table",
      link: collapsed(selection) ? linkRangeAt(document, selection.start)?.link ?? null : activeMarks(document, selection).link ?? null,
    });
  }, [readSelection]);

  useEffect(() => {
    const onSelection = () => { if (root.current?.contains(document.activeElement)) refreshToolbar(); };
    document.addEventListener("selectionchange", onSelection);
    return () => document.removeEventListener("selectionchange", onSelection);
  }, [refreshToolbar]);

  // ---- Drawing ----

  const render = useCallback((selection: Selection | null) => {
    if (!root.current) return;
    root.current.innerHTML = toHtml(doc.current);
    if (selection && document.activeElement === root.current) applySelection(selection);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useLayoutEffect(() => {
    render(null);
    if (autoFocus) root.current?.focus();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const syncHistory = () => setHistory({ undo: undo.current.length > 0, redo: redo.current.length > 0 });

  const remember = (selection: Selection | null) => {
    undo.current.push({ document: doc.current, selection });
    if (undo.current.length > UNDO_LIMIT) undo.current.shift();
    redo.current = [];
    syncHistory();
  };

  /** Applies an edit made on the document: records undo, redraws, and puts the caret back. */
  const commit = (edited: Edited | { document: RichDocument; selection: Selection }, before: Selection | null) => {
    if (sameDocument(edited.document, doc.current)) { render(edited.selection); refreshToolbar(); return; }
    remember(before);
    lastTyping.current = 0;
    doc.current = edited.document;
    render(edited.selection);
    onChange(doc.current);
    refreshToolbar();
  };

  /** After the browser changed the page itself (typing): read it back, and redraw if it drifted from the document's markup. */
  const readBack = () => {
    const editor = root.current;
    if (!editor || composing.current) return;
    const next = fromNodes(editor as unknown as HtmlNode, { preserveSpace: true });
    if (toHtml(next) !== editor.innerHTML) {
      const selection = readSelection();
      doc.current = next;
      render(selection);
    } else doc.current = next;
    onChange(doc.current);
    refreshToolbar();
  };

  const rememberTyping = (selection: Selection | null) => {
    const now = Date.now();
    if (now - lastTyping.current > TYPING_GROUP_MS) remember(selection);
    lastTyping.current = now;
  };

  const step = (from: Snapshot[], to: Snapshot[]) => {
    const snapshot = from.pop();
    if (!snapshot) return;
    to.push({ document: doc.current, selection: readSelection() });
    doc.current = snapshot.document;
    lastTyping.current = 0;
    render(snapshot.selection);
    onChange(doc.current);
    syncHistory();
    refreshToolbar();
  };
  const doUndo = () => step(undo.current, redo.current);
  const doRedo = () => step(redo.current, undo.current);

  // ---- Commands ----

  const current = () => readSelection() ?? savedSelection.current;

  const markCommand = (update: (marks: Marks) => Marks) => {
    const selection = current();
    if (!selection) return;
    if (collapsed(selection)) {
      const base = pending.current?.marks ?? marksAt(doc.current, selection.start);
      pending.current = { position: selection.start, marks: update(base) };
      refreshToolbar();
      return;
    }
    commit({ document: updateMarks(doc.current, selection, update), selection }, selection);
  };

  const toggle = (key: MarkKey) => {
    const selection = current();
    if (!selection) return;
    if (collapsed(selection)) markCommand((marks) => ({ ...marks, [key]: !marks[key] }));
    else commit({ document: toggleMark(doc.current, selection, key), selection }, selection);
  };

  const lineCommand = (kind: TextKind, level = 1) => {
    const selection = current();
    if (selection) commit({ document: setLineKind(doc.current, selection, kind, level), selection }, selection);
  };

  const indentCommand = (delta: number) => {
    const selection = current();
    if (selection) commit({ document: indent(doc.current, selection, delta), selection }, selection);
  };

  const clearCommand = () => {
    const selection = current();
    if (!selection) return;
    if (collapsed(selection)) { pending.current = { position: selection.start, marks: {} }; refreshToolbar(); return; }
    commit({ document: clearFormatting(doc.current, selection), selection }, selection);
  };

  const openLinkDialog = () => {
    const selection = current();
    if (!selection) return;
    const around = collapsed(selection) ? linkRangeAt(doc.current, selection.start) : null;
    if (around) { setLinkDialog({ selection: around.selection, link: around.link, label: around.label, existing: true, needsLabel: false }); return; }
    const link = activeMarks(doc.current, selection).link;
    setLinkDialog({ selection: ordered(selection), link: link ?? "", label: "", existing: !!link, needsLabel: collapsed(selection) });
  };

  const removeLink = () => {
    const selection = current();
    if (!selection) return;
    const target = collapsed(selection) ? linkRangeAt(doc.current, selection.start)?.selection : selection;
    if (target) commit(setLink(doc.current, target, null), selection);
  };

  const insertTable = (rows: number, columns: number) => {
    const selection = current();
    if (selection) commit(insertBlock(doc.current, selection, newTable(rows, columns, true)), selection);
  };

  const insertDivider = () => {
    const selection = current();
    if (selection) commit(insertBlock(doc.current, selection, { type: "divider" }), selection);
  };

  const tableCommand = (action: TableAction) => {
    const selection = current();
    if (!selection) return;
    const ref = slots(doc.current)[selection.start.slot];
    if (!ref || ref.row === undefined) return;
    const next = editTable(doc.current, ref, action);
    const count = slots(next).length;
    const slot = Math.min(selection.start.slot, count - 1);
    commit({ document: next, selection: { start: { slot, offset: 0 }, end: { slot, offset: 0 } } }, selection);
  };

  /** Keeps the editor's selection while a toolbar button takes the click. */
  const keep = (event: ReactMouseEvent) => {
    savedSelection.current = readSelection() ?? savedSelection.current;
    event.preventDefault();
  };

  // ---- Browser editing ----

  const inCell = (selection: Selection) => slots(doc.current)[selection.start.slot]?.row !== undefined;
  const slotLength = (slot: number) => {
    const ref = slots(doc.current)[slot];
    if (!ref) return 0;
    const block = doc.current.blocks[ref.block];
    return block.type === "text" ? spansText(block.spans).length : block.type === "table" ? spansText(block.rows[ref.row ?? 0][ref.col ?? 0]).length : 0;
  };

  const onBeforeInput = (event: InputEvent) => {
    if (event.isComposing || composing.current) return;
    const selection = readSelection();
    if (!selection) return;
    const type = event.inputType;
    const multi = !collapsed(selection);
    const stop = () => event.preventDefault();

    if (type === "historyUndo") { stop(); doUndo(); return; }
    if (type === "historyRedo") { stop(); doRedo(); return; }
    if (type.startsWith("format")) { stop(); return; }
    if (type === "insertParagraph" || type === "insertLineBreak") {
      stop();
      if (inCell(selection)) {
        // Enter in a table moves to the cell below.
        const ref = slots(doc.current)[selection.start.slot];
        const below = slots(doc.current).findIndex((s) => s.block === ref.block && s.row === (ref.row ?? 0) + 1 && s.col === ref.col);
        if (below >= 0) applySelection({ start: { slot: below, offset: 0 }, end: { slot: below, offset: 0 } });
        return;
      }
      commit(splitLine(doc.current, selection), selection);
      return;
    }
    if (type === "insertFromDrop" || type === "deleteByDrag" || type === "insertFromYank" || type === "deleteByCut" || type === "insertFromPaste" || type === "insertFromPasteAsQuotation") { stop(); return; }
    if (type === "insertText" || type === "insertReplacementText") {
      const text = event.data ?? event.dataTransfer?.getData("text/plain") ?? "";
      const hold = pending.current;
      const atHold = hold && !multi && hold.position.slot === selection.start.slot && hold.position.offset === selection.start.offset;
      const before = marksAt(doc.current, selection.start);
      // Typing right after a link doesn't extend it, though the browser would.
      const linkEnd = !multi && !before.link && selection.start.offset > 0 &&
        !!activeMarks(doc.current, { start: { slot: selection.start.slot, offset: selection.start.offset - 1 }, end: selection.start }).link;
      if (multi || atHold || linkEnd || type === "insertReplacementText") {
        stop();
        const removed = deleteRange(doc.current, selection);
        const marks = atHold ? hold.marks : marksAt(doc.current, ordered(selection).start);
        const typed = insertText(removed.document, removed.selection.start, text, marks);
        pending.current = null;
        commit(typed, selection);
        lastTyping.current = Date.now();
        return;
      }
      rememberTyping(selection);
      return;
    }
    if (type.startsWith("delete")) {
      const backward = type.includes("Backward");
      if (multi) { stop(); commit(deleteRange(doc.current, selection), selection); return; }
      if (backward && selection.start.offset === 0) {
        stop();
        if (inCell(selection)) return;
        const edited = backspaceAtLineStart(doc.current, selection.start);
        if (edited) commit(edited, selection);
        return;
      }
      if (!backward && selection.start.offset >= slotLength(selection.start.slot)) {
        stop();
        if (inCell(selection)) return;
        const edited = deleteAtLineEnd(doc.current, selection.start);
        if (edited) commit(edited, selection);
        return;
      }
      rememberTyping(selection);
      return;
    }
    if (type !== "insertCompositionText") stop();
  };

  useEffect(() => {
    const editor = root.current;
    if (!editor) return;
    const handler = (event: Event) => onBeforeInput(event as InputEvent);
    editor.addEventListener("beforeinput", handler);
    return () => editor.removeEventListener("beforeinput", handler);
  });

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const mod = event.ctrlKey || event.metaKey;
    const key = event.key.toLowerCase();
    const run = (action: () => void) => { event.preventDefault(); action(); };
    if (mod && !event.altKey) {
      if (key === "z" && !event.shiftKey) return run(doUndo);
      if (key === "y" || (key === "z" && event.shiftKey)) return run(doRedo);
      if (key === "b" && !event.shiftKey) return run(() => toggle("bold"));
      if (key === "i" && !event.shiftKey) return run(() => toggle("italic"));
      if (key === "u" && !event.shiftKey) return run(() => toggle("underline"));
      if (key === "x" && event.shiftKey) return run(() => toggle("strike"));
      if (key === "e" && !event.shiftKey) return run(() => toggle("code"));
      if (key === "k") return run(openLinkDialog);
      if (key === "\\") return run(clearCommand);
      if (event.shiftKey && event.code === "Digit7") return run(() => lineCommand("numbered"));
      if (event.shiftKey && event.code === "Digit8") return run(() => lineCommand("bullet"));
      if (event.shiftKey && event.code === "Digit9") return run(() => lineCommand("check"));
    }
    if (mod && event.altKey && /^Digit[0-3]$/.test(event.code)) {
      const level = Number(event.code.slice(5));
      return run(() => (level === 0 ? lineCommand("paragraph") : lineCommand("heading", level)));
    }
    if (event.key === "Tab" && !mod && !event.altKey) {
      const selection = readSelection();
      if (!selection) return;
      if (inCell(selection)) {
        const next = selection.start.slot + (event.shiftKey ? -1 : 1);
        const ref = slots(doc.current)[selection.start.slot];
        const target = slots(doc.current)[next];
        if (target && target.block === ref.block) return run(() => applySelection({ start: { slot: next, offset: 0 }, end: { slot: next, offset: slotLength(next) } }));
        return;
      }
      if (toolbar.inList) return run(() => indentCommand(event.shiftKey ? -1 : 1));
    }
  };

  const onMouseDown = (event: ReactMouseEvent<HTMLDivElement>) => {
    // The box in front of a checklist line ticks it.
    const item = (event.target as Element).closest?.<HTMLElement>('.rn-li[data-kind="check"]');
    if (!item || !root.current?.contains(item)) return;
    const indentLevel = Number(item.dataset.indent ?? 0);
    const left = item.getBoundingClientRect().left + indentLevel * 24;
    if (event.clientX < left || event.clientX > left + 26) return;
    event.preventDefault();
    const slot = slotElements().indexOf(item);
    const ref = slots(doc.current)[slot];
    if (ref) commit({ document: toggleChecked(doc.current, ref.block), selection: readSelection() ?? { start: { slot, offset: 0 }, end: { slot, offset: 0 } } }, readSelection());
  };

  const onCopy = (event: ReactClipboardEvent<HTMLDivElement>, cut: boolean) => {
    const selection = readSelection();
    if (!selection || collapsed(selection)) return;
    event.preventDefault();
    const part = slice(doc.current, selection);
    const plain = plainText(part);
    lastCopy = { plain, document: part };
    // Plain text only: no formatted copy of the note on the system clipboard.
    event.clipboardData.setData("text/plain", plain);
    if (cut) commit(deleteRange(doc.current, selection), selection);
  };

  const onPaste = (event: ReactClipboardEvent<HTMLDivElement>) => {
    event.preventDefault();
    const selection = readSelection();
    if (!selection) return;
    const text = event.clipboardData.getData("text/plain");
    const html = event.clipboardData.getData("text/html");
    let pasted: RichDocument | null = null;
    if (lastCopy && text === lastCopy.plain) pasted = lastCopy.document;
    else if (html) {
      // DOMParser builds an inert document: nothing in it runs or loads.
      const parsed = new DOMParser().parseFromString(html, "text/html");
      pasted = fromNodes(parsed.body as unknown as HtmlNode);
      if (!plainText(pasted)) pasted = null;
    }
    if (!pasted && text) pasted = fromPastedText(text);
    if (!pasted) return;
    commit(insertDocument(doc.current, selection, pasted), selection);
  };

  const saveLink = (link: string, label: string) => {
    const dialog = linkDialog;
    setLinkDialog(null);
    if (!dialog) return;
    root.current?.focus();
    commit(setLink(doc.current, dialog.selection, link, dialog.needsLabel ? label || link : undefined), dialog.selection);
  };

  const marks = toolbar.marks;
  const tool = (props: { label: string; shortcut?: string; icon: typeof Bold; active?: boolean; onClick: () => void; disabled?: boolean }) => (
    <button type="button" className={cx("rn-tool", props.active && "is-active")} aria-label={props.label} aria-pressed={props.active ?? undefined}
      title={props.shortcut ? `${props.label} (${props.shortcut})` : props.label} onMouseDown={keep} onClick={props.onClick} disabled={props.disabled}>
      <props.icon aria-hidden="true" />
    </button>
  );

  return (
    <div className={cx("field rn-field", error && "has-error")}>
      <div className="field-label-row"><label id={labelId} onClick={() => root.current?.focus()}>{label}</label></div>
      <div className="rn-toolbar" role="toolbar" aria-label="Formatting">
        {tool({ label: "Undo", shortcut: "Ctrl+Z", icon: Undo2, onClick: doUndo, disabled: !history.undo })}
        {tool({ label: "Redo", shortcut: "Ctrl+Y", icon: Redo2, onClick: doRedo, disabled: !history.redo })}
        <span className="rn-sep" />
        <HeadingPicker kind={toolbar.kind} level={toolbar.level} keep={keep} onPick={(kind, level) => lineCommand(kind, level)} />
        <span className="rn-sep" />
        {tool({ label: "Bold", shortcut: "Ctrl+B", icon: Bold, active: !!marks.bold, onClick: () => toggle("bold") })}
        {tool({ label: "Italic", shortcut: "Ctrl+I", icon: Italic, active: !!marks.italic, onClick: () => toggle("italic") })}
        {tool({ label: "Underline", shortcut: "Ctrl+U", icon: Underline, active: !!marks.underline, onClick: () => toggle("underline") })}
        {tool({ label: "Strikethrough", shortcut: "Ctrl+Shift+X", icon: Strikethrough, active: !!marks.strike, onClick: () => toggle("strike") })}
        {tool({ label: "Inline code", shortcut: "Ctrl+E", icon: Code, active: !!marks.code, onClick: () => toggle("code") })}
        <ColorPicker label="Text color" icon={Baseline} value={marks.color} keep={keep} onPick={(color) => markCommand((m) => ({ ...m, color }))} kind="color" />
        <ColorPicker label="Highlight" icon={Highlighter} value={marks.bg} keep={keep} onPick={(bg) => markCommand((m) => ({ ...m, bg }))} kind="bg" />
        {tool({ label: toolbar.link ? "Edit link" : "Add link", shortcut: "Ctrl+K", icon: Link2, active: !!toolbar.link, onClick: openLinkDialog })}
        {tool({ label: "Clear formatting", shortcut: "Ctrl+\\", icon: Eraser, onClick: clearCommand })}
        <span className="rn-sep" />
        {tool({ label: "Bulleted list", shortcut: "Ctrl+Shift+8", icon: List, active: toolbar.kind === "bullet", onClick: () => lineCommand("bullet") })}
        {tool({ label: "Numbered list", shortcut: "Ctrl+Shift+7", icon: ListOrdered, active: toolbar.kind === "numbered", onClick: () => lineCommand("numbered") })}
        {tool({ label: "Checklist", shortcut: "Ctrl+Shift+9", icon: CheckSquare, active: toolbar.kind === "check", onClick: () => lineCommand("check") })}
        {tool({ label: "Decrease indent", shortcut: "Shift+Tab", icon: Outdent, onClick: () => indentCommand(-1), disabled: !toolbar.inList })}
        {tool({ label: "Increase indent", shortcut: "Tab", icon: Indent, onClick: () => indentCommand(1), disabled: !toolbar.inList })}
        {tool({ label: "Quote", icon: Quote, active: toolbar.kind === "quote", onClick: () => lineCommand("quote") })}
        {tool({ label: "Code block", icon: SquareCode, active: toolbar.kind === "code", onClick: () => lineCommand("code") })}
        <span className="rn-sep" />
        <TablePicker keep={keep} onPick={insertTable} />
        {tool({ label: "Divider", icon: Minus, onClick: insertDivider })}
      </div>
      {toolbar.inTable && (
        <div className="rn-subbar" role="toolbar" aria-label="Table">
          <span className="rn-subbar-label"><Table aria-hidden="true" />Table</span>
          <SubButton keep={keep} icon={Rows2} onClick={() => tableCommand("addRowAbove")}>Row above</SubButton>
          <SubButton keep={keep} icon={Rows2} onClick={() => tableCommand("addRowBelow")}>Row below</SubButton>
          <SubButton keep={keep} icon={Columns2} onClick={() => tableCommand("addColumnLeft")}>Column left</SubButton>
          <SubButton keep={keep} icon={Columns2} onClick={() => tableCommand("addColumnRight")}>Column right</SubButton>
          <SubButton keep={keep} onClick={() => tableCommand("toggleHeader")}>Header row</SubButton>
          <SubButton keep={keep} onClick={() => tableCommand("removeRow")}>Delete row</SubButton>
          <SubButton keep={keep} onClick={() => tableCommand("removeColumn")}>Delete column</SubButton>
          <SubButton keep={keep} icon={Trash2} danger onClick={() => tableCommand("removeTable")}>Delete table</SubButton>
        </div>
      )}
      {toolbar.link && !toolbar.inTable && (
        <div className="rn-subbar" aria-live="polite">
          <span className="rn-subbar-link" title={toolbar.link}>{toolbar.link}</span>
          <SubButton keep={keep} onClick={() => void openLink(toolbar.link!)}>Open</SubButton>
          <SubButton keep={keep} onClick={openLinkDialog}>Edit</SubButton>
          <SubButton keep={keep} icon={Unlink} onClick={removeLink}>Remove</SubButton>
        </div>
      )}
      <div ref={root} className="rn-doc rn-editor" contentEditable suppressContentEditableWarning role="textbox" aria-multiline="true"
        aria-labelledby={labelId} spellCheck autoCorrect="off" onInput={readBack} onKeyDown={onKeyDown} onMouseDown={onMouseDown}
        onCopy={(event) => onCopy(event, false)} onCut={(event) => onCopy(event, true)} onPaste={onPaste}
        onDrop={(event) => event.preventDefault()} onDragStart={(event) => event.preventDefault()}
        onCompositionStart={() => { composing.current = true; }} onCompositionEnd={() => { composing.current = false; readBack(); }}
        onBlur={() => { savedSelection.current = readSelection() ?? savedSelection.current; }} />
      {error && <p className="field-error">{error}</p>}
      <LinkDialog state={linkDialog} onClose={() => { setLinkDialog(null); root.current?.focus(); }} onSave={saveLink}
        onRemove={() => { const dialog = linkDialog; setLinkDialog(null); root.current?.focus(); if (dialog) commit(setLink(doc.current, dialog.selection, null), dialog.selection); }} />
    </div>
  );
}

function SubButton({ keep, icon: Icon, onClick, children, danger }: { keep: (event: ReactMouseEvent) => void; icon?: typeof Bold; onClick: () => void; children: ReactNode; danger?: boolean }) {
  return (
    <button type="button" className={cx("rn-subbutton", danger && "is-danger")} onMouseDown={keep} onClick={onClick}>
      {Icon && <Icon aria-hidden="true" />}{children}
    </button>
  );
}

/** A toolbar button with a small panel under it; closes on Esc or a click elsewhere. */
function Popover({ label, button, children, keep, active }: { label: string; button: ReactNode; children: (close: () => void) => ReactNode; keep: (event: ReactMouseEvent) => void; active?: boolean }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => { if (!wrap.current?.contains(event.target as Node)) setOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => { document.removeEventListener("mousedown", close); document.removeEventListener("keydown", escape); };
  }, [open]);
  return (
    <span className="rn-popover-wrap" ref={wrap}>
      <button type="button" className={cx("rn-tool rn-tool-wide", (open || active) && "is-active")} aria-label={label} title={label} aria-haspopup="true" aria-expanded={open}
        onMouseDown={keep} onClick={() => setOpen((value) => !value)}>
        {button}<ChevronDown aria-hidden="true" className="rn-caret" />
      </button>
      {open && <div className="rn-popover" role="dialog" aria-label={label} onMouseDown={keep}>{children(() => setOpen(false))}</div>}
    </span>
  );
}

const HEADINGS: { label: string; kind: TextKind; level: number; shortcut: string }[] = [
  { label: "Normal text", kind: "paragraph", level: 1, shortcut: "Ctrl+Alt+0" },
  { label: "Heading 1", kind: "heading", level: 1, shortcut: "Ctrl+Alt+1" },
  { label: "Heading 2", kind: "heading", level: 2, shortcut: "Ctrl+Alt+2" },
  { label: "Heading 3", kind: "heading", level: 3, shortcut: "Ctrl+Alt+3" },
];

function HeadingPicker({ kind, level, keep, onPick }: { kind: TextKind; level: number; keep: (event: ReactMouseEvent) => void; onPick: (kind: TextKind, level: number) => void }) {
  const currentLabel = kind === "heading" ? `Heading ${level}` : "Text";
  return (
    <Popover label="Text style" keep={keep} active={kind === "heading"} button={<><Heading aria-hidden="true" /><span className="rn-tool-text">{currentLabel}</span></>}>
      {(close) => (
        <div className="rn-menu">
          {HEADINGS.map((item) => (
            <button key={item.label} type="button" className={cx("rn-menu-item", `rn-menu-${item.kind}${item.level}`, (kind === item.kind && (kind !== "heading" || level === item.level)) && "is-active")}
              onMouseDown={keep} onClick={() => { close(); onPick(item.kind, item.level); }}>
              <span>{item.label}</span><span className="rn-shortcut">{item.shortcut}</span>
            </button>
          ))}
        </div>
      )}
    </Popover>
  );
}

function ColorPicker({ label, icon: Icon, value, keep, onPick, kind }: { label: string; icon: typeof Bold; value?: NoteColor; keep: (event: ReactMouseEvent) => void; onPick: (color: NoteColor | undefined) => void; kind: "color" | "bg" }) {
  return (
    <Popover label={label} keep={keep} active={!!value} button={<span className="rn-color-icon"><Icon aria-hidden="true" /><span className="rn-color-bar rn-c" data-color={kind === "color" ? value : undefined} data-bg={kind === "bg" ? value : undefined} data-kind={kind} /></span>}>
      {(close) => (
        <div className="rn-swatches" role="listbox" aria-label={label}>
          <button type="button" role="option" aria-selected={!value} className={cx("rn-swatch rn-swatch-none", !value && "is-active")} title="Default" aria-label="Default"
            onMouseDown={keep} onClick={() => { close(); onPick(undefined); }} />
          {NOTE_COLORS.map((color) => (
            <button key={color} type="button" role="option" aria-selected={value === color} title={COLOR_NAMES[color]} aria-label={COLOR_NAMES[color]}
              className={cx("rn-swatch rn-c", value === color && "is-active")} data-swatch={kind} {...(kind === "color" ? { "data-color": color } : { "data-bg": color })}
              onMouseDown={keep} onClick={() => { close(); onPick(color); }}>{kind === "color" ? "A" : ""}</button>
          ))}
        </div>
      )}
    </Popover>
  );
}

function TablePicker({ keep, onPick }: { keep: (event: ReactMouseEvent) => void; onPick: (rows: number, columns: number) => void }) {
  const [size, setSize] = useState({ rows: 0, columns: 0 });
  return (
    <Popover label="Insert table" keep={keep} button={<Table aria-hidden="true" />}>
      {(close) => (
        <div className="rn-grid-picker">
          <div className="rn-grid" onMouseLeave={() => setSize({ rows: 0, columns: 0 })}>
            {Array.from({ length: 6 }, (_, r) => Array.from({ length: 6 }, (_, c) => (
              <button key={`${r}-${c}`} type="button" aria-label={`${r + 1} by ${c + 1} table`} className={cx("rn-grid-cell", r < size.rows && c < size.columns && "is-active")}
                onMouseEnter={() => setSize({ rows: r + 1, columns: c + 1 })} onFocus={() => setSize({ rows: r + 1, columns: c + 1 })}
                onMouseDown={keep} onClick={() => { close(); onPick(r + 1, c + 1); }} />
            )))}
          </div>
          <span className="rn-grid-label">{size.rows ? `${size.rows} × ${size.columns}, first row as header` : "Pick a size"}</span>
        </div>
      )}
    </Popover>
  );
}

function LinkDialog({ state, onClose, onSave, onRemove }: {
  state: { link: string; label: string; existing: boolean; needsLabel: boolean } | null;
  onClose: () => void; onSave: (link: string, label: string) => void; onRemove: () => void;
}) {
  const [link, setLinkValue] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState("");
  useEffect(() => { if (state) { setLinkValue(state.link); setLabel(state.label); setError(""); } }, [state]);
  const save = () => {
    const safe = linkFromInput(link);
    if (!safe) { setError("Enter a web address (https://…) or an email address."); return; }
    onSave(safe, label.trim());
  };
  return (
    <Dialog open={state !== null} title={state?.existing ? "Edit link" : "Add link"} onClose={onClose}
      footer={<>
        {state?.existing && <Button variant="ghost" icon={Unlink} onClick={onRemove}>Remove link</Button>}
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={save}>Save</Button>
      </>}>
      <form className="form-stack" onSubmit={(event) => { event.preventDefault(); save(); }}>
        {state?.needsLabel && <TextField label="Text" value={label} onValue={setLabel} maxLength={500} />}
        <TextField label="Link" value={link} onValue={(value) => { setLinkValue(value); setError(""); }} error={error} placeholder="https://example.com or name@example.com"
          autoFocus inputMode="url" spellCheck={false} maxLength={2048} hint="Links open only after you confirm." />
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
