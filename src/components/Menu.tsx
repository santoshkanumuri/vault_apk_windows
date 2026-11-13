import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cx } from "../lib/format";

export type MenuItem = { key: string; label: string; icon?: LucideIcon; hint?: string; onSelect: () => void };

type TriggerProps = { "aria-haspopup": "menu"; "aria-expanded": boolean; "aria-controls": string; onClick: () => void; ref: (element: HTMLButtonElement | null) => void };

/** Small popup menu (e.g. the Add type picker). Arrow keys move, Esc closes and returns focus. */
export function Menu({ trigger, items, align = "end", label }: { trigger: (props: TriggerProps) => ReactNode; items: MenuItem[]; align?: "start" | "end"; label: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const wrap = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement | null>(null);
  const list = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    list.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
    const close = (event: MouseEvent) => { if (!wrap.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const options = Array.from(list.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? []);
    const index = options.indexOf(document.activeElement as HTMLElement);
    if (event.key === "ArrowDown") { event.preventDefault(); options[(index + 1) % options.length]?.focus(); }
    else if (event.key === "ArrowUp") { event.preventDefault(); options[(index - 1 + options.length) % options.length]?.focus(); }
    else if (event.key === "Home") { event.preventDefault(); options[0]?.focus(); }
    else if (event.key === "End") { event.preventDefault(); options[options.length - 1]?.focus(); }
    else if (event.key === "Escape" || event.key === "Tab") {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); button.current?.focus(); }
      setOpen(false);
    }
  };

  return (
    <div className="menu-wrap" ref={wrap}>
      {trigger({ "aria-haspopup": "menu", "aria-expanded": open, "aria-controls": id, onClick: () => setOpen((value) => !value), ref: (element) => { button.current = element; } })}
      {open && (
        <div className={cx("menu", align === "start" ? "menu-start" : "menu-end")} role="menu" id={id} aria-label={label} ref={list} onKeyDown={onKeyDown}>
          {items.map(({ key, label: itemLabel, icon: Icon, hint, onSelect }) => (
            <button key={key} type="button" role="menuitem" className="menu-item" tabIndex={-1} onClick={() => { setOpen(false); onSelect(); }}>
              {Icon && <span className="menu-icon" aria-hidden="true"><Icon /></span>}
              <span className="menu-text"><span>{itemLabel}</span>{hint && <span className="menu-hint">{hint}</span>}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
