import { LoaderCircle } from "lucide-react";
import { cx } from "../lib/format";

export function Spinner({ size = 18, label, className }: { size?: number; label?: string; className?: string }) {
  return (
    <span className={cx("spinner", className)} role={label ? "status" : undefined}>
      <LoaderCircle aria-hidden="true" width={size} height={size} className="spin" />
      {label && <span className="sr-only">{label}</span>}
    </span>
  );
}

export function ProgressBar({ value, max, label, indeterminate }: { value?: number; max?: number; label: string; indeterminate?: boolean }) {
  const known = !indeterminate && value !== undefined && max !== undefined && max > 0;
  const percent = known ? Math.min(100, Math.max(0, (value! / max!) * 100)) : 0;
  return (
    <div className={cx("progress", !known && "is-indeterminate")} role="progressbar" aria-label={label} aria-valuemin={known ? 0 : undefined} aria-valuemax={known ? max : undefined} aria-valuenow={known ? value : undefined}>
      <span style={known ? { width: `${percent}%` } : undefined} />
    </div>
  );
}
