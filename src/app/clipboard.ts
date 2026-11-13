import { useCallback } from "react";
import { usePreferences } from "./settings";
import { useToast } from "./toast";

let clearTimer: number | undefined;
let generation = 0;

async function writeClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    // Fall back to a temporary textarea when the async clipboard API is unavailable.
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.value = "";
    area.remove();
    if (!ok) throw new Error("Clipboard is unavailable");
  }
}

/** Clears any pending secret on lock or exit. */
export function clearClipboardNow() {
  if (clearTimer === undefined) return;
  window.clearTimeout(clearTimer);
  clearTimer = undefined;
  void writeClipboard("").catch(() => undefined);
}

export type CopyOptions = { label: string; secret?: boolean; message?: string };

/**
 * Copy helper that shows a toast and, for secrets, clears the clipboard after the configured delay
 * (best effort: the WebView can only overwrite the clipboard while the app is running).
 * The value is never logged or kept in React state.
 */
export function useCopy() {
  const toast = useToast();
  const { clipboardSeconds } = usePreferences();
  return useCallback(async (value: string | (() => Promise<string | null> | string | null), options: CopyOptions) => {
    try {
      const text = typeof value === "function" ? await value() : value;
      if (!text) { toast.warning(`Nothing to copy for ${options.label.toLowerCase()}.`); return false; }
      await writeClipboard(text);
      const mine = ++generation;
      if (clearTimer !== undefined) { window.clearTimeout(clearTimer); clearTimer = undefined; }
      if (options.secret && clipboardSeconds > 0) {
        clearTimer = window.setTimeout(() => {
          clearTimer = undefined;
          // Only clear if nothing newer was copied from Nuvori since.
          if (mine === generation) void writeClipboard("").catch(() => undefined);
        }, clipboardSeconds * 1000);
      }
      // Clearing is best effort (only while Nuvori is running), so the toast does not promise it.
      toast.success(options.message ?? `${options.label} copied`);
      return true;
    } catch (error) {
      toast.error(error, `Couldn't copy ${options.label.toLowerCase()}.`);
      return false;
    }
  }, [toast, clipboardSeconds]);
}
