import { useState, type ReactNode } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { useCopy } from "../app/clipboard";
import { cx } from "../lib/format";
import { IconButton } from "./Button";

export function CopyButton({ value, label, secret, message, size = "md", variant = "ghost" }: { value: string | (() => Promise<string | null> | string | null); label: string; secret?: boolean; message?: string; size?: "sm" | "md"; variant?: "ghost" | "secondary" }) {
  const copy = useCopy();
  const [done, setDone] = useState(false);
  return (
    <IconButton label={`Copy ${label.toLowerCase()}`} icon={done ? Check : Copy} size={size} variant={variant} className={cx(done && "is-done")}
      onClick={async (event) => {
        event.stopPropagation();
        if (await copy(value, { label, secret, message })) {
          setDone(true);
          window.setTimeout(() => setDone(false), 1400);
        }
      }} />
  );
}

type DetailFieldProps = {
  label: string;
  value: string;
  /** Hidden until revealed. Reveal state resets when the view closes. */
  secret?: boolean;
  /** What the masked value looks like, e.g. "•••• 4242". */
  masked?: string;
  /** Text shown when revealed, if different from the copied value (e.g. grouped card number). */
  display?: string;
  copy?: boolean;
  copyValue?: string;
  mono?: boolean;
  multiline?: boolean;
  extra?: ReactNode;
};

export function DetailField({ label, value, secret, masked, display, copy = true, copyValue, mono, multiline, extra }: DetailFieldProps) {
  const [revealed, setRevealed] = useState(false);
  const empty = !value;
  const shown = empty ? "Not set" : secret && !revealed ? (masked ?? "••••••••••") : (display ?? value);
  return (
    <div className="detail-field">
      <div className="detail-field-text">
        <span className="detail-label">{label}</span>
        <span className={cx("detail-value", mono && "mono", multiline && "multiline", empty && "is-empty", secret && !revealed && !empty && "is-masked")}>{shown}</span>
      </div>
      <div className="detail-actions">
        {extra}
        {secret && !empty && <IconButton label={revealed ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} icon={revealed ? EyeOff : Eye} aria-pressed={revealed} onClick={() => setRevealed((current) => !current)} />}
        {copy && !empty && <CopyButton value={copyValue ?? value} label={label} secret={secret} />}
      </div>
    </div>
  );
}
