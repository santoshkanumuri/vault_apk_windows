import { useRef, type CSSProperties, type PointerEvent } from "react";
import { Nfc, Star } from "lucide-react";
import type { VaultEntry } from "../lib/api";
import { DEFAULT_CARD_COLOR, css, inkFor, needsOutline } from "../lib/cardColors";
import { cardNetwork, maskedCardNumber, networkMark } from "../lib/cardFace";
import { cardLast4, cx } from "../lib/format";

type Props = {
  entry: VaultEntry;
  /** "lg" on the card's own page. */
  size?: "md" | "lg";
  /** Makes the card a button that opens it. */
  onOpen?: () => void;
  className?: string;
};

/**
 * A card drawn like the real thing, in its own color: name, credit or debit, chip, the number with
 * only the last four digits shown, cardholder, expiry and network mark. Never shows the full number
 * or the security code; the card's page reveals and copies those on request.
 */
export function CardFace({ entry, size = "md", onOpen, className }: Props) {
  const color = entry.color ?? DEFAULT_CARD_COLOR;
  const ink = inkFor(color);
  const network = entry.network.trim() || cardNetwork(entry.primaryValue);
  const mark = networkMark(network, ink === "#ffffff");
  const kind = entry.cardKind === "DEBIT" ? "Debit" : "Credit";
  const last4 = cardLast4(entry.primaryValue);
  const title = entry.title.trim() || "Card";
  const face = useRef<HTMLElement | null>(null);

  // The card leans slightly toward the pointer and a soft glare follows it.
  const lean = (event: PointerEvent<HTMLElement>) => {
    const el = face.current;
    if (!el || event.pointerType === "touch") return;
    const box = el.getBoundingClientRect();
    const x = (event.clientX - box.left) / box.width;
    const y = (event.clientY - box.top) / box.height;
    el.style.setProperty("--mx", `${(x * 100).toFixed(1)}%`);
    el.style.setProperty("--my", `${(y * 100).toFixed(1)}%`);
    el.style.setProperty("--rx", `${((0.5 - y) * 7).toFixed(2)}deg`);
    el.style.setProperty("--ry", `${((x - 0.5) * 9).toFixed(2)}deg`);
  };
  const settle = () => { for (const name of ["--mx", "--my", "--rx", "--ry"]) face.current?.style.removeProperty(name); };

  const style = { "--card": css(color), "--ink": ink } as CSSProperties;
  const body = (
    <span className="cf-body">
      <span className="cf-sheen" aria-hidden="true" />
      <span className="cf-glare" aria-hidden="true" />
      <span className="cf-top">
        <span className="cf-title">{title}</span>
        <span className="cf-kind">{entry.favorite && <Star aria-label="Favorite" />}{kind}</span>
      </span>
      <span className="cf-middle" aria-hidden="true">
        <span className="cf-chip" />
        <Nfc className="cf-contactless" />
      </span>
      <span className="cf-number mono">{maskedCardNumber(entry.primaryValue)}</span>
      <span className="cf-bottom">
        <span className="cf-meta">
          <span className="cf-label">Cardholder</span>
          <span className="cf-value">{entry.secondaryValue.trim() || "—"}</span>
        </span>
        <span className="cf-meta">
          <span className="cf-label">Expires</span>
          <span className="cf-value mono">{entry.tertiaryValue.trim() || "—"}</span>
        </span>
        <span className="cf-network">
          {mark ? <svg viewBox={mark.viewBox} role="img" aria-label={network} dangerouslySetInnerHTML={{ __html: mark.body }} />
            : network ? <span className="cf-network-text">{network}</span> : null}
        </span>
      </span>
    </span>
  );
  const classes = cx("card-face", `card-face-${size}`, needsOutline(color) && "is-outlined", onOpen && "is-interactive", className);
  const label = `${title}, ${kind.toLowerCase()} card${last4 ? ` ending in ${last4}` : ""}`;
  return onOpen ? (
    <button type="button" ref={(el) => { face.current = el; }} className={classes} style={style} onClick={onOpen}
      onPointerMove={lean} onPointerLeave={settle} aria-label={`Open ${label}`}>
      {body}
    </button>
  ) : (
    <div ref={(el) => { face.current = el; }} className={classes} style={style} role="img" aria-label={label}
      onPointerMove={lean} onPointerLeave={settle}>
      {body}
    </div>
  );
}
