import type { ReactNode } from "react";
import { CircleCheck, CircleX, Info, LoaderCircle, TriangleAlert, type LucideIcon } from "lucide-react";
import { cx } from "../lib/format";

/** Meaning of a status. Colors and icons follow the meaning, never the screen. */
export type StatusKind = "success" | "info" | "progress" | "warning" | "error" | "neutral";

export const statusIcons: Record<StatusKind, LucideIcon> = {
  success: CircleCheck,
  info: Info,
  progress: LoaderCircle,
  warning: TriangleAlert,
  error: CircleX,
  neutral: Info
};

export function StatusIcon({ kind, size = 16 }: { kind: StatusKind; size?: number }) {
  const Icon = statusIcons[kind];
  return <Icon aria-hidden="true" className={cx("status-icon", kind === "progress" && "spin")} width={size} height={size} />;
}

export function StatusChip({ kind, label, title, onClick, className }: { kind: StatusKind; label: string; title?: string; onClick?: () => void; className?: string }) {
  const content = <><StatusIcon kind={kind} size={14} /><span>{label}</span></>;
  if (onClick) return <button type="button" className={cx("chip", `tone-${kind}`, "chip-button", className)} title={title} onClick={onClick}>{content}</button>;
  return <span className={cx("chip", `tone-${kind}`, className)} title={title}>{content}</span>;
}

export function StatusBanner({ kind, title, children, action, className }: { kind: StatusKind; title?: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cx("banner", `tone-${kind}`, className)} role={kind === "error" ? "alert" : "status"}>
      <StatusIcon kind={kind} size={18} />
      <div className="banner-body">
        {title && <strong>{title}</strong>}
        {children && <div className="banner-text">{children}</div>}
      </div>
      {action && <div className="banner-action">{action}</div>}
    </div>
  );
}
