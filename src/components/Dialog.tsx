import { useEffect, useId, useRef, type ReactNode } from "react";
import { X } from "lucide-react";
import { cx } from "../lib/format";
import { IconButton } from "./Button";

type DialogProps = {
  open: boolean;
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children?: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
  className?: string;
  /** Prevent closing with Esc / backdrop while something is in progress. */
  locked?: boolean;
  initialFocus?: string;
};

/** Modal built on the native <dialog>, which makes the rest of the app inert and traps focus. */
export function Dialog({ open, title, description, onClose, children, footer, size = "sm", className, locked, initialFocus }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      const previous = document.activeElement as HTMLElement | null;
      dialog.showModal();
      const target = initialFocus ? dialog.querySelector<HTMLElement>(initialFocus) : dialog.querySelector<HTMLElement>("[data-autofocus], input:not([type=hidden]):not(:disabled), textarea, select");
      (target ?? dialog.querySelector<HTMLElement>(".dialog-footer button:last-child"))?.focus();
      return () => { if (dialog.open) dialog.close(); previous?.focus?.(); };
    }
    if (!open && dialog.open) dialog.close();
  }, [open, initialFocus]);

  return (
    <dialog
      ref={ref}
      className={cx("dialog", `dialog-${size}`, className)}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={(event) => { event.preventDefault(); if (!locked) onCloseRef.current(); }}
      onMouseDown={(event) => { if (event.target === ref.current && !locked) onCloseRef.current(); }}
    >
      {open && <div className="dialog-surface">
        <header className="dialog-header">
          <h2 id={titleId}>{title}</h2>
          <IconButton label="Close" icon={X} size="sm" onClick={() => onCloseRef.current()} disabled={locked} />
        </header>
        {description && <div id={descriptionId} className="dialog-description">{description}</div>}
        {children && <div className="dialog-body">{children}</div>}
        {footer && <footer className="dialog-footer">{footer}</footer>}
      </div>}
    </dialog>
  );
}
