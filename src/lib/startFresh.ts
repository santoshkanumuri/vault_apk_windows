// The locked app's screens: "Welcome back" for a vault from an earlier install, the choices behind
// "Forgot the password or starting over?", the unlock form, and vault setup. Kept apart from the
// page so the rules can be tested without a browser.

import { relativeTime } from "./format.ts";
import { codeText } from "../strings.ts";

/** The word the person types to confirm "Start fresh on this PC" (START_FRESH_WORD in lib.rs). */
export const START_FRESH_WORD = "RESET";

/** Exactly RESET, as the backend checks: no trimming, no other case. */
export function startFreshConfirmed(typed: string): boolean {
  return typed === START_FRESH_WORD;
}

export type LockedView = "create" | "welcome" | "choices" | "unlock";
/** What the person picked on this screen: "" for nothing yet. */
export type LockedChoice = "" | "unlock" | "choices";

export function lockedView(snapshot: { vaultState: string; welcomeBack?: boolean }, chosen: LockedChoice): LockedView {
  if (snapshot.vaultState !== "locked") return "create";
  if (chosen) return chosen;
  return snapshot.welcomeBack ? "welcome" : "unlock";
}

/** "Last used 3 days ago", "Last used yesterday", "Last used on 12 Mar 2025"; "" when unknown. */
export function lastUsedText(lastUsedAt: number | undefined, now = Date.now()): string {
  if (!lastUsedAt || lastUsedAt <= 0) return "";
  const relative = relativeTime(lastUsedAt, now);
  if (relative === "Just now" || relative === "Yesterday") return codeText.lastUsed(relative.toLowerCase());
  if (/ago$/.test(relative)) return codeText.lastUsed(relative);
  return codeText.lastUsedOn(relative);
}
