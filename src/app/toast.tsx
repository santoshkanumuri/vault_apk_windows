import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { StatusIcon } from "../components/Status";
import { humanError } from "../lib/errors";
import { cx } from "../lib/format";

export type ToastKind = "success" | "info" | "progress" | "warning" | "error";
export type ToastAction = { label: string; run: () => void | Promise<void> };
type ToastItem = { id: number; kind: ToastKind; message: string; leaving?: boolean; action?: ToastAction };

export type ProgressHandle = {
  update: (message: string) => void;
  success: (message: string) => void;
  error: (error: unknown, fallback?: string) => void;
  info: (message: string) => void;
  warning: (message: string) => void;
  dismiss: () => void;
};

export type ToastApi = {
  success: (message: string, options?: { action?: ToastAction }) => number;
  info: (message: string) => number;
  warning: (message: string) => number;
  /** Accepts raw errors and turns them into human messages. */
  error: (error: unknown, fallback?: string) => number;
  progress: (message: string) => ProgressHandle;
  dismiss: (id: number) => void;
};

const ToastContext = createContext<ToastApi | null>(null);
const MAX_VISIBLE = 3;
const DURATION: Record<ToastKind, number> = { success: 4000, info: 4000, warning: 5500, error: 7000, progress: 0 };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToastsState] = useState<ToastItem[]>([]);
  const current = useRef<ToastItem[]>([]);
  const timers = useRef(new Map<number, number>());
  const counter = useRef(0);
  const setToasts = useCallback((update: (items: ToastItem[]) => ToastItem[]) => {
    current.current = update(current.current);
    setToastsState(current.current);
  }, []);

  const remove = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer) window.clearTimeout(timer);
    timers.current.delete(id);
    setToasts((items) => items.map((toast) => toast.id === id ? { ...toast, leaving: true } : toast));
    window.setTimeout(() => setToasts((items) => items.filter((toast) => toast.id !== id)), 160);
  }, [setToasts]);

  const schedule = useCallback((id: number, kind: ToastKind, duration?: number) => {
    const existing = timers.current.get(id);
    if (existing) window.clearTimeout(existing);
    timers.current.delete(id);
    const ms = duration ?? DURATION[kind];
    if (ms > 0) timers.current.set(id, window.setTimeout(() => remove(id), ms));
  }, [remove]);

  const push = useCallback((kind: ToastKind, message: string, action?: ToastAction) => {
    const id = ++counter.current;
    setToasts((items) => {
      const next = [...items.filter((toast) => !toast.leaving), { id, kind, message, action }];
      // Keep at most MAX_VISIBLE; drop the oldest non-progress toasts first.
      while (next.length > MAX_VISIBLE) {
        const index = next.findIndex((toast) => toast.kind !== "progress");
        next.splice(index >= 0 ? index : 0, 1);
      }
      return next;
    });
    // Toasts with an action (Undo) stay a little longer so there is time to react.
    schedule(id, kind, action ? 6000 : undefined);
    return id;
  }, [schedule, setToasts]);

  const set = useCallback((id: number, kind: ToastKind, message: string) => {
    // If the progress toast was pushed out or dismissed, show the result as a new toast.
    if (!current.current.some((toast) => toast.id === id && !toast.leaving)) {
      if (kind !== "progress") push(kind, message);
      return;
    }
    setToasts((items) => items.map((toast) => toast.id === id ? { ...toast, kind, message } : toast));
    schedule(id, kind);
  }, [push, schedule, setToasts]);

  const api = useMemo<ToastApi>(() => ({
    success: (message, options) => push("success", message, options?.action),
    info: (message) => push("info", message),
    warning: (message) => push("warning", message),
    error: (error, fallback) => push("error", humanError(error, fallback)),
    progress: (message) => {
      const id = push("progress", message);
      return {
        update: (text) => set(id, "progress", text),
        success: (text) => set(id, "success", text),
        info: (text) => set(id, "info", text),
        warning: (text) => set(id, "warning", text),
        error: (error, fallback) => set(id, "error", humanError(error, fallback)),
        dismiss: () => remove(id)
      };
    },
    dismiss: remove
  }), [push, set, remove]);

  useEffect(() => () => { timers.current.forEach((timer) => window.clearTimeout(timer)); }, []);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts" aria-live="polite" aria-relevant="additions text">
        {toasts.map((toast) => (
          <div key={toast.id} className={cx("toast", `tone-${toast.kind}`, toast.leaving && "is-leaving")} role={toast.kind === "error" ? "alert" : "status"}
            onMouseEnter={() => { const timer = timers.current.get(toast.id); if (timer) { window.clearTimeout(timer); timers.current.delete(toast.id); } }}
            onMouseLeave={() => schedule(toast.id, toast.kind, toast.action ? 6000 : undefined)}>
            <StatusIcon kind={toast.kind} size={18} />
            <span className="toast-message">{toast.message}</span>
            {toast.action && <button type="button" className="toast-action" onClick={() => { const action = toast.action!; remove(toast.id); void action.run(); }}>{toast.action.label}</button>}
            {toast.kind !== "progress" && <button type="button" className="toast-close" aria-label="Dismiss notification" onClick={() => remove(toast.id)}><X aria-hidden="true" /></button>}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast outside ToastProvider");
  return context;
}
