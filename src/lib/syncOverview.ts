// One sync status for both transports (Wi-Fi and Google Drive), the same rules as Android
// `sync/SyncOverview.kt`. A success on either transport counts. A device is up to date when its
// verified progress (a Wi-Fi exchange or a signed Drive `p.` file, both in `sync_peer_progress`) shows
// it applied this PC's latest change, whichever transport carried it. A transport failure is only a
// quiet note while the other one keeps devices in step.
import type { CloudStatus, MembershipStatus, SyncReport, SyncStatus } from "./api";
import type { StatusKind } from "../components/Status";
import { plural, relativeTime, toMillis } from "./format.ts";
import { syncStatusText as words } from "../strings.ts";

export type TransportHealth = "off" | "ok" | "failed";
export type PeerAck = "upToDate" | "waiting" | "silent" | "notChecked";
export type OverallSync = "syncing" | "attention" | "keys" | "conflicts" | "waiting" | "waitingHere" | "stale" | "notYet" | "upToDate";
export type AttentionCause = "bothFailed" | "wifiOnlyFailed" | "driveOnlyFailed" | "localProblem" | "rejected" | "deviceSilent";
export type TransportNote = "wifiFailedDriveKeptUp" | "wifiFailedDriveCarries" | "wifiFailed" | "driveFailedWifiKeptUp" | "driveFailedWifiCarries" | "driveFailed" | "paused";

/** One active paired device. `unconfirmed`: this PC's changes it has not applied yet. */
export type PeerFacts = { deviceId: string; name: string; unconfirmed: number; reported: boolean; lastSeen: number; wifiFailed?: boolean;
  /** H1: its own changes that an active device reports applied but that have not arrived here. */
  missingHere?: number };

export type SyncFacts = {
  now: number;
  peers: PeerFacts[];
  busy?: boolean;
  wifi: TransportHealth;
  drive: TransportHealth;
  paused?: boolean;
  /** This PC's last successful Wi-Fi sync and Google Drive pass (Unix ms; 0 = never). */
  lastWifiSync?: number;
  lastDriveSync?: number;
  /** A Wi-Fi problem on this PC that is not about reaching a device. */
  localProblem?: string;
  conflicts?: number;
  /** Changes this PC set aside because it couldn't read them. */
  rejected?: number;
  waitingForKeys?: boolean;
  waitingHere?: boolean;
};

export type SyncOverview = {
  state: OverallSync;
  cause?: AttentionCause;
  peers: Record<string, PeerAck>;
  waitingFor: PeerFacts[];
  /** This PC's changes that not every active device has applied yet, over both transports. */
  waitingChanges: number;
  lastSynced: number;
  days: number;
  note?: TransportNote;
  noteDevices: string[];
  /** Devices with changes another device applied that have not arrived here, the most first (H1). */
  missingFrom: PeerFacts[];
};

/** A device unheard for this long, or no device heard from for this long, is a problem. */
export const STALE_AFTER_MS = 3 * 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

export function peerAck(peer: PeerFacts, now: number): PeerAck {
  if (peer.unconfirmed > 0) return peer.lastSeen > 0 && now - peer.lastSeen > STALE_AFTER_MS ? "silent" : "waiting";
  if (peer.lastSeen === 0 && !peer.reported) return "notChecked";
  return "upToDate";
}

export function syncOverview(facts: SyncFacts): SyncOverview {
  const { now } = facts;
  const peers = Object.fromEntries(facts.peers.map((peer) => [peer.deviceId, peerAck(peer, now)])) as Record<string, PeerAck>;
  const waitingFor = facts.peers.filter((peer) => peer.unconfirmed > 0)
    .sort((a, b) => (a.lastSeen || Number.MAX_SAFE_INTEGER) - (b.lastSeen || Number.MAX_SAFE_INTEGER));
  const waitingChanges = Math.max(0, ...waitingFor.map((peer) => peer.unconfirmed));
  const lastHeard = Math.max(0, ...facts.peers.map((peer) => peer.lastSeen));
  const lastSynced = Math.max(lastHeard, facts.lastDriveSync ?? 0, facts.lastWifiSync ?? 0);
  const silent = waitingFor.find((peer) => peers[peer.deviceId] === "silent");
  const inStep = waitingFor.length === 0;
  const wifiFailed = facts.wifi === "failed";
  const driveFailed = facts.drive === "failed";
  const flagged = facts.peers.filter((peer) => peer.wifiFailed).map((peer) => peer.name);
  const failedNames = flagged.length ? flagged : facts.peers.length === 1 ? [facts.peers[0].name] : [];

  let note: TransportNote | undefined;
  if (wifiFailed && !driveFailed) note = facts.drive === "ok" ? (inStep ? "wifiFailedDriveKeptUp" : "wifiFailedDriveCarries") : "wifiFailed";
  else if (driveFailed && !wifiFailed) note = facts.wifi === "ok" ? (inStep ? "driveFailedWifiKeptUp" : "driveFailedWifiCarries") : "driveFailed";
  else if (!wifiFailed && !driveFailed && facts.paused) note = "paused";
  const noteDevices = note?.startsWith("wifi") ? failedNames : [];
  const missingFrom = facts.peers.filter((peer) => (peer.missingHere ?? 0) > 0).sort((a, b) => (b.missingHere ?? 0) - (a.missingHere ?? 0));
  const result = (state: OverallSync, cause?: AttentionCause, days = 0): SyncOverview =>
    ({ state, cause, peers, waitingFor, waitingChanges, lastSynced, days, note, noteDevices, missingFrom });

  // No transport is left to carry waiting changes: one failed and the other is off or failed too.
  const noTransport = (wifiFailed || driveFailed) && facts.wifi !== "ok" && facts.drive !== "ok";
  if (facts.busy) return result("syncing");
  if (wifiFailed && driveFailed) return result("attention", "bothFailed");
  if (facts.localProblem) return result("attention", "localProblem");
  if ((facts.rejected ?? 0) > 0) return result("attention", "rejected");
  if (silent) return result("attention", "deviceSilent", Math.floor((now - silent.lastSeen) / DAY_MS));
  if (noTransport && !inStep) return result("attention", wifiFailed ? "wifiOnlyFailed" : "driveOnlyFailed");
  if (facts.waitingForKeys) return result("keys");
  if ((facts.conflicts ?? 0) > 0) return result("conflicts");
  if (!inStep) return result("waiting");
  // "Up to date" only when this PC also holds everything any device applied (H1).
  if (facts.waitingHere || missingFrom.length > 0) return result("waitingHere");
  if (lastSynced === 0) return result("notYet");
  if (facts.peers.length > 0 && lastHeard > 0 && now - lastHeard > STALE_AFTER_MS) return result("stale", undefined, Math.floor((now - lastHeard) / DAY_MS));
  if (facts.peers.length > 0 && lastHeard === 0) return result("notYet");
  return result("upToDate");
}

function looksUnreachable(text: string): boolean {
  const lower = text.toLowerCase();
  return ["unreachable", "no paired device answered", "refused", "timed out", "timeout", "no route", "could not connect", "couldn't reach", "not reachable", "10061", "10060", "offline"].some((word) => lower.includes(word));
}

const ACTIVE_PHASES = new Set(["connecting", "sending", "receiving", "applying"]);

/**
 * The facts from what the backend reports. Device progress and "last seen" come only from verified
 * sources: a Wi-Fi exchange or a signed Drive report of an active member (`cloud_sync.rs`).
 */
export function syncFacts(sync: SyncStatus | null, cloud: CloudStatus | null, membership: MembershipStatus | null, conflicts: number, now = Date.now()): SyncFacts {
  const failures = sync?.consecutiveFailures ?? 0;
  const lastError = sync?.lastError ?? "";
  const failedText = sync && (sync.phase === "error" || (lastError && failures > 0)) && !lastError.includes("busy syncing") ? lastError || sync.message : "";
  const reachFailed = Boolean(failedText) && looksUnreachable(failedText);
  const wifi: TransportHealth = reachFailed ? "failed" : !sync || !sync.automatic ? "off" : "ok";
  const drive: TransportHealth = !cloud?.connected ? "off" : cloud.needsSignIn || cloud.lastError ? "failed" : "ok";
  const peers = (membership?.devices ?? []).filter((device) => device.status === "active" && !device.isThisDevice).map((device) => {
    const counts = device.counts;
    return {
      deviceId: device.deviceId,
      name: device.name || "Paired device",
      // Older backends lack `unconfirmed`: what was not received there plus what was not applied there.
      unconfirmed: counts?.unconfirmed ?? (counts ? counts.toSend + counts.receivedThere : 0),
      reported: Boolean(counts?.checked),
      lastSeen: device.lastSeen ?? 0,
      missingHere: counts?.missingHere ?? 0,
    };
  });
  const waiting = sync ? sync.waitingToApply - (sync.setAside ?? 0) : 0;
  return {
    now, peers,
    busy: Boolean(sync && (sync.running || (sync.phase !== undefined && ACTIVE_PHASES.has(sync.phase)))),
    wifi, drive,
    paused: Boolean(sync && !sync.automatic),
    lastWifiSync: toMillis(sync?.lastSync),
    lastDriveSync: cloud?.connected ? toMillis(cloud.lastSync) : 0,
    localProblem: failedText && !reachFailed ? failedText : undefined,
    conflicts,
    rejected: sync?.setAside ?? 0,
    waitingForKeys: Boolean(sync?.waitingForKeys),
    waitingHere: waiting > 0,
  };
}

/** "Just now" and "5 min ago" read in lower case inside a sentence; a date keeps its capital. */
function inSentence(when: string): string {
  return /^(Just now|Yesterday|\d)/.test(when) ? when.charAt(0).toLowerCase() + when.slice(1) : when;
}

export type OverviewText = { kind: StatusKind; title: string; detail: string; note?: string; lastSynced?: string };
export type PeerAckText = { kind: StatusKind; label: string; detail: string };

const TRANSPORT_CAUSES = new Set<AttentionCause>(["bothFailed", "wifiOnlyFailed", "driveOnlyFailed"]);

/** The status card's headline, its detail, the quiet transport line and "Last synced". */
export function overviewText(facts: SyncFacts, overview: SyncOverview): OverviewText {
  const one = overview.noteDevices.length === 1;
  const names = one ? overview.noteDevices[0] : words.yourDevices;
  const waitingName = overview.waitingFor.length === 1 ? overview.waitingFor[0].name : undefined;
  let text: Omit<OverviewText, "note" | "lastSynced">;
  switch (overview.state) {
    case "syncing": text = { kind: "progress", title: words.syncing, detail: "" }; break;
    case "attention": {
      const silent = overview.waitingFor.find((peer) => overview.peers[peer.deviceId] === "silent");
      const detail = overview.cause === "bothFailed" ? words.detailBothFailed
        : overview.cause === "wifiOnlyFailed" ? words.detailWifiOnlyFailed(names, one)
        : overview.cause === "driveOnlyFailed" ? words.detailDriveOnlyFailed
        : overview.cause === "localProblem" ? facts.localProblem ?? ""
        : overview.cause === "rejected" ? words.detailRejected(facts.rejected ?? 0)
        : words.detailDeviceSilent(silent?.name ?? "", overview.days);
      text = { kind: "error", title: words.attention, detail };
      break;
    }
    case "keys": text = { kind: "info", title: words.keys, detail: words.detailKeys }; break;
    case "conflicts": text = { kind: "warning", title: words.conflicts, detail: words.detailConflicts(facts.conflicts ?? 0) }; break;
    case "waiting": text = {
      kind: "info",
      title: waitingName ? words.waitingFor(waitingName) : words.waitingForDevices(overview.waitingFor.length),
      detail: waitingName ? words.detailWaitingOne(overview.waitingChanges, waitingName) : words.detailWaitingMany(overview.waitingChanges),
    }; break;
    case "waitingHere": {
      const from = overview.missingFrom;
      const missing = from.reduce((sum, peer) => sum + (peer.missingHere ?? 0), 0);
      const detail = from.length === 0 ? words.detailWaitingHere
        : from.length === 1 ? words.detailMissingFrom(missing, from[0].name) : words.detailMissingMany(missing);
      text = { kind: "warning", title: words.waitingHere, detail };
      break;
    }
    case "stale": text = { kind: "warning", title: words.stale(overview.days), detail: facts.drive !== "off" ? words.detailStaleDrive : words.detailStaleWifi }; break;
    case "notYet": text = { kind: "neutral", title: words.notYet, detail: words.detailNotYet }; break;
    default: text = { kind: "success", title: words.upToDate, detail: words.detailUpToDate };
  }
  const noteText: Record<TransportNote, string> = {
    wifiFailedDriveKeptUp: words.noteWifiFailedDriveKeptUp(names, one),
    wifiFailedDriveCarries: words.noteWifiFailedDriveCarries(names),
    wifiFailed: words.noteWifiFailed(names),
    driveFailedWifiKeptUp: words.noteDriveFailedWifiKeptUp,
    driveFailedWifiCarries: words.noteDriveFailedWifiCarries,
    driveFailed: words.noteDriveFailed,
    paused: words.notePaused,
  };
  const hideNote = overview.state === "attention" && overview.cause !== undefined && TRANSPORT_CAUSES.has(overview.cause);
  return {
    ...text,
    note: overview.note && !hideNote ? noteText[overview.note] : undefined,
    lastSynced: overview.lastSynced > 0 ? words.lastSynced(inSentence(relativeTime(overview.lastSynced, facts.now))) : undefined,
  };
}

/** A device row's chip and its one-line state, by its verified progress over either transport. */
export function peerAckText(peer: PeerFacts, ack: PeerAck, now: number): PeerAckText {
  switch (ack) {
    case "upToDate": return { kind: "success", label: words.peerUpToDate, detail: words.peerDetailUpToDate };
    case "waiting": return { kind: "info", label: words.peerWaiting, detail: words.peerDetailWaiting(peer.unconfirmed, peer.name) };
    case "silent": return { kind: "error", label: words.peerSilent, detail: words.peerDetailSilent(Math.floor((now - peer.lastSeen) / DAY_MS)) };
    default: return { kind: "neutral", label: words.peerNotChecked, detail: words.peerDetailNotChecked };
  }
}

export type SyncNowOutcome = { kind: "success" | "info" | "warning"; text: string };

/**
 * The message after Sync now (H1). It says the vault is in step only when the overview, read after
 * the attempt, is up to date: every known device, or Google Drive, was checked and nothing is
 * missing here. `after` is that overview; without it (an older backend) the report decides alone.
 */
export function syncNowOutcome(report: SyncReport, after?: { overview: SyncOverview; text: OverviewText }): SyncNowOutcome {
  const parts = [report.sent ? `sent ${report.sent}` : "", report.received ? `received ${report.received}` : ""].filter(Boolean);
  const driveOnly = Boolean(report.cloud) && !report.peersChecked;
  const state = after?.overview.state;
  const settled = !after || state === "upToDate" || state === "syncing";
  const summary = parts.length ? `${driveOnly ? "Synced through Google Drive" : "Synced"} · ${parts.join(", ")}`
    : driveOnly ? (settled ? "Google Drive is up to date" : "Google Drive checked") : "Sync check complete";
  if (report.conflicts) return { kind: "warning", text: `${summary}. ${plural(report.conflicts, "change")} need review.` };
  if (report.waitingToApply) return { kind: "info", text: `${summary}. ${report.waitingToApply} still waiting to apply.` };
  if (report.peersWaiting && !report.cloud) return { kind: "info", text: `${summary}. ${plural(report.peersWaiting, "device")} will catch up when connected.` };
  if (!settled && after) {
    const kind = after.text.kind === "error" || after.text.kind === "warning" ? "warning" : "info";
    return { kind, text: `${summary}. ${after.text.detail || after.text.title}` };
  }
  return { kind: "success", text: summary };
}
