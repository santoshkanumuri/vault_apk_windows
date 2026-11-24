import { api } from "../lib/api";

/** At most one report this often: the backend's idle time counts in whole seconds anyway. */
const REPORT_EVERY_MS = 15_000;
const EVENTS = ["mousemove", "mousedown", "keydown", "wheel", "touchstart", "focus"] as const;

/**
 * Tells the backend's auto-lock (auto_lock.rs) that the user is using this window, so the vault
 * doesn't lock under them. Every window reports; the backend decides when to lock.
 */
export function startUserActivityReports(): () => void {
  let last = 0;
  const report = () => {
    const now = Date.now();
    if (now - last < REPORT_EVERY_MS) return;
    last = now;
    void api.noteUserActivity().catch(() => { /* An older backend: nothing to report to. */ });
  };
  EVENTS.forEach((name) => window.addEventListener(name, report, { passive: true }));
  return () => EVENTS.forEach((name) => window.removeEventListener(name, report));
}
