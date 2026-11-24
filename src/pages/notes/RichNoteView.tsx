import { useCallback, type ClipboardEvent, type KeyboardEvent, type ReactNode } from "react";
import { useConfirm } from "../../app/confirm";
import { useToast } from "../../app/toast";
import { api } from "../../lib/api";
import { cx } from "../../lib/format";
import type { RichDocument, Span, TextBlock } from "../../lib/richNote";
import { listNumbers } from "../../lib/richNoteHtml";

/** Opens a note's link only after the person sees the full address and confirms. */
export function useOpenNoteLink() {
  const confirm = useConfirm();
  const toast = useToast();
  return useCallback(async (link: string) => {
    const ok = await confirm({
      title: link.toLowerCase().startsWith("mailto:") ? "Write an email?" : "Open this link?",
      message: <span className="rn-confirm-link">{link}</span>,
      confirmLabel: "Open",
    });
    if (!ok) return;
    try { await api.openNoteLink(link); } catch (failure) { toast.error(failure, "Couldn't open the link."); }
  }, [confirm, toast]);
}

function SpanView({ span, onLink }: { span: Span; onLink: (link: string) => void }) {
  const m = span.marks;
  let node: ReactNode = span.text;
  if (m.color || m.bg) node = <span className="rn-c" data-color={m.color} data-bg={m.bg}>{node}</span>;
  if (m.strike) node = <s>{node}</s>;
  if (m.underline) node = <u>{node}</u>;
  if (m.italic) node = <em>{node}</em>;
  if (m.bold) node = <strong>{node}</strong>;
  if (m.code) node = <code>{node}</code>;
  if (m.link) {
    const link = m.link;
    const open = () => onLink(link);
    node = (
      <a className="rn-link" role="link" tabIndex={0} title={link} onClick={open}
        onKeyDown={(event: KeyboardEvent) => { if (event.key === "Enter") { event.preventDefault(); open(); } }}>{node}</a>
    );
  }
  return <>{node}</>;
}

const spansView = (spans: Span[], onLink: (link: string) => void) =>
  spans.length ? spans.map((span, index) => <SpanView key={index} span={span} onLink={onLink} />) : <br />;

/** A note's formatted text, read-only. Checklist boxes can be ticked when [onToggleCheck] is given. */
export function RichNoteView({ document, onToggleCheck, className }: { document: RichDocument; onToggleCheck?: (blockIndex: number) => void; className?: string }) {
  const openLink = useOpenNoteLink();
  const onLink = (link: string) => void openLink(link);
  const numbers = listNumbers(document);

  // Copying from the note gives plain text: no formatted copy on the system clipboard.
  const onCopy = (event: ClipboardEvent<HTMLElement>) => {
    const text = window.getSelection()?.toString() ?? "";
    if (!text) return;
    event.preventDefault();
    event.clipboardData.setData("text/plain", text);
  };

  const line = (block: TextBlock, index: number) => {
    const inner = spansView(block.spans, onLink);
    switch (block.kind) {
      case "paragraph": return <p key={index}>{inner}</p>;
      case "heading": {
        const Tag = (`h${block.level}` as "h1" | "h2" | "h3");
        return <Tag key={index}>{inner}</Tag>;
      }
      case "quote": return <blockquote key={index}>{inner}</blockquote>;
      case "code": return <pre key={index}>{inner}</pre>;
      case "check":
        return (
          <div key={index} className="rn-li rn-li-check" data-kind="check" data-indent={block.indent} data-checked={block.checked}>
            <button type="button" role="checkbox" aria-checked={block.checked} className="rn-checkbox" disabled={!onToggleCheck}
              aria-label={block.checked ? "Done. Mark as not done" : "Not done. Mark as done"} onClick={() => onToggleCheck?.(index)} />
            {inner}
          </div>
        );
      default:
        return <div key={index} className="rn-li" data-kind={block.kind} data-indent={block.indent} data-number={block.kind === "numbered" ? numbers[index] : undefined}>{inner}</div>;
    }
  };

  return (
    <div className={cx("rn-doc rn-view", className)} onCopy={onCopy}>
      {document.blocks.map((block, index) => {
        if (block.type === "text") return line(block, index);
        if (block.type === "divider") return <hr key={index} />;
        return (
          <div key={index} className="rn-table-scroll">
            <table className="rn-table">
              <tbody>
                {block.rows.map((row, r) => (
                  <tr key={r}>{row.map((cell, c) => block.header && r === 0
                    ? <th key={c} scope="col">{spansView(cell, onLink)}</th>
                    : <td key={c}>{spansView(cell, onLink)}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
}
