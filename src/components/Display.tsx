import { useEffect, useRef, type ReactNode } from "react";
import { ChevronRight, type LucideIcon } from "lucide-react";
import { css, inkFor } from "../lib/cardColors";
import { cx, hashIndex, monogram } from "../lib/format";
import { useSiteIcon } from "../app/siteIcons";
import { glyphColor, needsBorder } from "../lib/siteIcons";
import { codeText } from "../strings";

/**
 * A letter avatar. `cardColor` (a card's own ARGB color) paints it in that card's color.
 * `site` (a login's website or a passkey's RP ID) swaps the letter for the site's icon when one is known.
 */
/** [site]: a website or RP ID whose icon replaces the letter. [brand]: a code's issuer name, tried after [site]. */
export function Avatar({ title, icon: Icon, size = "md", cardColor, site, brand }: { title: string; icon?: LucideIcon; size?: "sm" | "md" | "lg"; cardColor?: number; site?: string; brand?: string }) {
  const found = useSiteIcon(cardColor === undefined ? site : undefined, cardColor === undefined ? brand : undefined);
  const tint = hashIndex(title.toLocaleLowerCase(), 6);
  const card = cardColor !== undefined ? { background: css(cardColor), color: inkFor(cardColor) } : undefined;
  if (found?.kind === "captured") {
    return (
      <span className={cx("avatar", `avatar-${size}`, "avatar-site-image")} aria-hidden="true">
        <img src={found.src} alt="" draggable={false} />
      </span>
    );
  }
  if (found?.kind === "builtin") {
    return (
      <span className={cx("avatar", `avatar-${size}`, "avatar-site-brand", needsBorder(found.hex) && "has-border")} style={{ background: `#${found.hex}` }} aria-hidden="true">
        <svg viewBox="0 0 24 24" focusable="false"><path d={found.path} fill={glyphColor(found.hex)} /></svg>
      </span>
    );
  }
  return (
    <span className={cx("avatar", `avatar-${size}`, card ? "avatar-card" : `tint-${tint}`)} style={card} aria-hidden="true">
      {Icon ? <Icon /> : monogram(title)}
    </span>
  );
}

export function EmptyState({ icon: Icon, title, body, action }: { icon: LucideIcon; title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true"><Icon /></span>
      <strong>{title}</strong>
      {body && <p>{body}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

/** A flat card with a hairline border. */
export function Card({ title, actions, children, className, id, padded = true, as: Tag = "section", description }: { title?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string; id?: string; padded?: boolean; as?: "section" | "div"; description?: ReactNode }) {
  return (
    <Tag className={cx("card", padded && "card-padded", className)} aria-labelledby={title && id ? `${id}-title` : undefined} id={id}>
      {(title || actions) && (
        <header className="card-header">
          <div className="card-heading">
            {title && <h2 id={id ? `${id}-title` : undefined}>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </Tag>
  );
}

/** Phone-style settings group: a caption followed by a card of rows. */
export function SettingsGroup({ title, children, id, description }: { title: string; children: ReactNode; id?: string; description?: ReactNode }) {
  return (
    <section className="settings-group" aria-labelledby={id ? `${id}-title` : undefined} id={id}>
      <h2 className="group-caption" id={id ? `${id}-title` : undefined}>{title}</h2>
      {description && <p className="group-description">{description}</p>}
      <div className="card rows">{children}</div>
    </section>
  );
}

type SettingsRowProps = { icon?: LucideIcon; title: ReactNode; description?: ReactNode; control?: ReactNode; onClick?: () => void; danger?: boolean; children?: ReactNode; id?: string };

export function SettingsRow({ icon: Icon, title, description, control, onClick, danger, children, id }: SettingsRowProps) {
  const body = (
    <>
      {Icon && <span className={cx("row-icon", danger && "is-danger")} aria-hidden="true"><Icon /></span>}
      <span className="row-text">
        <span className={cx("row-title", danger && "is-danger")} id={id}>{title}</span>
        {description && <span className="row-description">{description}</span>}
      </span>
      {onClick ? <ChevronRight aria-hidden="true" className="row-chevron" /> : control && <span className="row-control">{control}</span>}
    </>
  );
  return (
    <div className="settings-row-wrap">
      {onClick ? <button type="button" className="settings-row is-link" onClick={onClick}>{body}</button> : <div className="settings-row">{body}</div>}
      {children && <div className="settings-row-extra">{children}</div>}
    </div>
  );
}

/** Small countdown ring for TOTP codes. Turns warning-colored for the last 5 seconds. */
export function CountdownRing({ seconds, period, size = 28 }: { seconds: number; period: number; size?: number }) {
  const radius = size / 2 - 3;
  const circumference = 2 * Math.PI * radius;
  const fraction = Math.max(0, Math.min(1, seconds / period));
  const urgent = seconds <= 5;
  // When a new period starts the ring jumps back to full rather than sweeping backwards.
  const previous = useRef(seconds);
  const reset = seconds > previous.current;
  useEffect(() => { previous.current = seconds; });
  return (
    <span className={cx("ring", urgent && "is-urgent", reset && "is-reset")} style={{ width: size, height: size }} aria-label={codeText.secondsLeft(seconds)} role="img">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle className="ring-track" cx={size / 2} cy={size / 2} r={radius} />
        <circle className="ring-value" cx={size / 2} cy={size / 2} r={radius} strokeDasharray={circumference} strokeDashoffset={circumference * (1 - fraction)} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      </svg>
      <span className="ring-label" aria-hidden="true">{seconds}</span>
    </span>
  );
}

export function Highlighted({ segments }: { segments: Array<{ text: string; match: boolean }> }) {
  return <>{segments.map((segment, index) => segment.match ? <mark key={index}>{segment.text}</mark> : <span key={index}>{segment.text}</span>)}</>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}
