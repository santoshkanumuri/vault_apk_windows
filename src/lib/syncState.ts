import type { AppSnapshot, BrowserStatus, CloudStatus, SyncStatus } from "./api";
import type { StatusKind } from "../components/Status";
import { waitingToApplyHere } from "./syncOverview.ts";
import { codeText, strings } from "../strings.ts";

export type Indicator = { kind: StatusKind; label: string; detail?: string };

const ACTIVE_PHASES = new Set(["connecting", "sending", "receiving", "applying"]);

function looksUnreachable(text: string): boolean {
  const lower = text.toLowerCase();
  return ["unreachable", "no paired device answered", "refused", "timed out", "timeout", "no route", "could not connect", "couldn't reach", "not reachable", "10061", "10060", "offline"].some((word) => lower.includes(word));
}

/**
 * The newest of several ISO times; "" when none is set. Wi-Fi sync and Google Drive sync each
 * keep their own last-sync time, and the vault is as fresh as the newer one.
 */
export function newestTime(...times: Array<string | null | undefined>): string {
  let best = "";
  let bestAt = Number.NEGATIVE_INFINITY;
  for (const time of times) {
    const at = time ? Date.parse(time) : Number.NaN;
    if (!Number.isNaN(at) && at > bestAt) { best = time as string; bestAt = at; }
  }
  return best;
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
    case "connecting": return codeText.checkingThatTheDeviceBelongsTo;
    case "sending": return codeText.sendingEncryptedChanges;
    case "receiving": return codeText.receivingEncryptedChanges;
    case "applying": return codeText.applyingReceivedChanges;
    default: return codeText.sendingAndReceivingEncryptedChanges;
  }
}

/**
 * Phone sync indicator. Uses the newer status fields when present, else falls back to running/message.
 * `lastSync`: the newer of the Wi-Fi and Google Drive last syncs (`useLastSync`), so a PC that syncs
 * only through Google Drive is not shown as still looking for its devices (H1).
 */
export function syncIndicator(snapshot: AppSnapshot, status: SyncStatus | null, unavailable = false, lastSync?: string, cloud?: CloudStatus | null): Indicator {
  if (!snapshot.enrolled) return { kind: "neutral", label: SYNC_WORDS.off, detail: codeText.pairADeviceToStartSyncing };
  if (unavailable || !status) return { kind: "neutral", label: SYNC_WORDS.searching };
  if (isSyncing(status)) {
    return { kind: "progress", label: status.phase === "connecting" ? SYNC_WORDS.connecting : SYNC_WORDS.transferring, detail: phaseLabel(status) };
  }
  const failures = status.consecutiveFailures ?? 0;
  const lastError = status.lastError ?? "";
  const driveOn = Boolean(cloud?.connected);
  // M12: "Sync paused" covers automatic Wi-Fi checks only. It never hides a refusal or a Google
  // Drive problem, and it is not shown while Google Drive keeps syncing.
  const failed = status.phase === "error" || Boolean(lastError && failures > 0);
  const text = lastError || status.message;
  if (failed && !looksUnreachable(text) && !lastError.includes("busy syncing")) return { kind: "error", label: SYNC_WORDS.attention, detail: text };
  if (driveOn && cloud?.needsSignIn) return { kind: "error", label: SYNC_WORDS.attention, detail: codeText.googleDriveNeedsYouToSign };
  if (!status.automatic) {
    // Google Drive is then the only automatic way, so its problem is the status.
    if (driveOn && cloud?.lastError) return { kind: "warning", label: SYNC_WORDS.attention, detail: cloud.lastError };
    if (!driveOn) return { kind: "neutral", label: SYNC_WORDS.paused, detail: codeText.automaticChecksAreOffSyncNow };
  }
  // A busy or unreachable device is still being looked for, as the phone shows it.
  if (lastError.includes("busy syncing")) return { kind: "warning", label: SYNC_WORDS.searching, detail: lastError };
  if (failed) return { kind: "warning", label: SYNC_WORDS.searching, detail: text };
  if (status.conflicts > 0) return { kind: "warning", label: strings.needsReview, detail: codeText.editedOnBothDevices(status.conflicts) };
  const update = (status.needsUpdate ?? []).reduce((sum, device) => sum + device.count, 0);
  if (update > 0) return { kind: "warning", label: SYNC_WORDS.attention, detail: `Update Nuvori to apply ${update} ${update === 1 ? "change" : "changes"} from another device.` };
  const waiting = waitingToApplyHere(status);
  if (waiting > 0) return { kind: "info", label: SYNC_WORDS.received, detail: codeText.receivedChangesApplyOnALater };
  if (lastSync || status.lastSync) return { kind: "success", label: SYNC_WORDS.checked };
  return { kind: "info", label: SYNC_WORDS.searching };
}

export function browserIndicator(snapshot: AppSnapshot, status: BrowserStatus | null, unavailable = false): Indicator {
  if (unavailable || !status) return { kind: "neutral", label: codeText.unavailable };
  const registered = status.hosts.chrome || status.hosts.brave || status.hosts.edge || status.hosts.firefox;
  if (!registered) return { kind: "warning", label: codeText.notSetUp };
  if (!status.listening) return { kind: "warning", label: codeText.notListening };
  if (snapshot.vaultState !== "unlocked") return { kind: "neutral", label: codeText.locked };
  if (status.lastRequestAt && Date.now() - status.lastRequestAt < 10 * 60 * 1000) return { kind: "success", label: codeText.connected };
  return { kind: "success", label: codeText.ready };
}
