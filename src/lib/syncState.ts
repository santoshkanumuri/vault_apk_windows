import type { AppSnapshot, BrowserStatus, SyncStatus } from "./api";
import type { StatusKind } from "../components/Status";

export type Indicator = { kind: StatusKind; label: string; detail?: string };

const ACTIVE_PHASES = new Set(["connecting", "sending", "receiving", "applying"]);

function looksUnreachable(text: string): boolean {
  const lower = text.toLowerCase();
  return ["unreachable", "no paired device answered", "refused", "timed out", "timeout", "no route", "could not connect", "couldn't reach", "not reachable", "10061", "10060", "offline"].some((word) => lower.includes(word));
}

export function isSyncing(status: SyncStatus | null): boolean {
  if (!status) return false;
  return status.running || (status.phase !== undefined && ACTIVE_PHASES.has(status.phase));
}

/**
 * Sync status words shared with the phone (Android `DeviceSyncPhase` titles), so both devices
 * name the same state the same way. Keep this list and the phone's in step.
 */
export const SYNC_WORDS = {
  off: "Device sync is off",
  paused: "Sync paused",
  searching: "Looking for your devices",
  connecting: "Verifying device",
  transferring: "Syncing changes",
  received: "Changes still waiting",
  checked: "Last check complete",
  attention: "Sync needs attention",
} as const;

export function phaseLabel(status: SyncStatus): string {
  switch (status.phase) {
    case "connecting": return "Checking that the device belongs to your vault.";
    case "sending": return "Sending encrypted changes.";
    case "receiving": return "Receiving encrypted changes.";
    case "applying": return "Applying received changes.";
    default: return "Sending and receiving encrypted changes.";
  }
}

/** Phone sync indicator. Uses the newer status fields when present, else falls back to running/message. */
export function syncIndicator(snapshot: AppSnapshot, status: SyncStatus | null, unavailable = false): Indicator {
  if (!snapshot.enrolled) return { kind: "neutral", label: SYNC_WORDS.off, detail: "Pair a device to start syncing." };
  if (unavailable || !status) return { kind: "neutral", label: SYNC_WORDS.searching };
  if (isSyncing(status)) {
    return { kind: "progress", label: status.phase === "connecting" ? SYNC_WORDS.connecting : SYNC_WORDS.transferring, detail: phaseLabel(status) };
  }
  if (!status.automatic) return { kind: "neutral", label: SYNC_WORDS.paused, detail: "Automatic checks are off. Sync now still works." };
  const failures = status.consecutiveFailures ?? 0;
  const lastError = status.lastError ?? "";
  // A busy or unreachable device is still being looked for, as the phone shows it.
  if (lastError.includes("busy syncing")) return { kind: "warning", label: SYNC_WORDS.searching, detail: lastError };
  if (status.phase === "error" || (lastError && failures > 0)) {
    const text = lastError || status.message;
    return looksUnreachable(text) ? { kind: "warning", label: SYNC_WORDS.searching, detail: text } : { kind: "error", label: SYNC_WORDS.attention, detail: text };
  }
  if (status.conflicts > 0) return { kind: "warning", label: "Needs review", detail: `${status.conflicts} edited on both devices` };
  const waiting = status.waitingToApply - (status.setAside ?? 0);
  if (waiting > 0) return { kind: "info", label: SYNC_WORDS.received, detail: "Received changes apply on a later sync." };
  if (status.lastSync) return { kind: "success", label: SYNC_WORDS.checked };
  return { kind: "info", label: SYNC_WORDS.searching };
}

export function browserIndicator(snapshot: AppSnapshot, status: BrowserStatus | null, unavailable = false): Indicator {
  if (unavailable || !status) return { kind: "neutral", label: "Unavailable" };
  const registered = status.hosts.chrome || status.hosts.brave || status.hosts.edge;
  if (!registered) return { kind: "warning", label: "Not set up" };
  if (!status.listening) return { kind: "warning", label: "Not listening" };
  if (snapshot.vaultState !== "unlocked") return { kind: "neutral", label: "Locked" };
  if (status.lastRequestAt && Date.now() - status.lastRequestAt < 10 * 60 * 1000) return { kind: "success", label: "Connected" };
  return { kind: "success", label: "Ready" };
}
