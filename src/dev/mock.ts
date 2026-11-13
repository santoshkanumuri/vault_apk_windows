// Development-only stand-in for the Tauri backend so the UI can be previewed in a plain browser
// (`npm run dev`, then open http://localhost:1420). Synthetic data only. Never bundled in production:
// it is reached solely through a branch guarded by `import.meta.env.DEV`.
import type { ActivityEvent, AppSnapshot, BrowserStatus, BuildStatus, CloudStatus, EntryPhoto, LocalNote, MembershipStatus, PairingStatus, PasskeySummary, SyncConflict, SyncStatus, VaultEntry, VaultGroup } from "../lib/api";

const now = Date.now();
const minutes = (n: number) => now - n * 60_000;
let nextId = 100;
const id = () => `mock-${nextId++}`;

type Draft = Partial<VaultEntry> & { type: VaultEntry["type"]; title: string };
const entry = (draft: Draft, age: number): VaultEntry => ({
  id: id(), primaryValue: "", secondaryValue: "", tertiaryValue: "", fourthValue: "", cardKind: "CREDIT", network: "", totpAlgorithm: "SHA1", totpDigits: 6, totpPeriod: 30,
  notes: "", tags: "", favorite: false, createdAt: minutes(age + 5000), updatedAt: minutes(age), groupIds: [], ...draft
});

const state = {
  vault: "locked" as AppSnapshot["vaultState"],
  hello: true,
  enrolled: true,
  revision: 1,
  entries: [
    entry({ type: "PASSWORD", title: "GitHub", primaryValue: "dev@example.com", secondaryValue: "correct-horse-battery", tertiaryValue: "https://github.com/login", favorite: true, tags: "work, code" }, 30),
    entry({ type: "PASSWORD", title: "Gmail", primaryValue: "someone@gmail.com", secondaryValue: "S3cure!mail-2026", tertiaryValue: "https://accounts.google.com" }, 120),
    entry({ type: "PASSWORD", title: "Café Münster", primaryValue: "guest", secondaryValue: "latte4ever", tertiaryValue: "https://cafe-muenster.de", notes: "Wi-Fi portal login" }, 600),
    entry({ type: "PASSWORD", title: "Netflix", primaryValue: "family@example.com", secondaryValue: "popcorn-night-42", tertiaryValue: "netflix.com" }, 2000),
    entry({ type: "PASSWORD", title: "Bank of Example", primaryValue: "jdoe", secondaryValue: "vault-door-77", tertiaryValue: "https://online.bank.example", favorite: true, tags: "finance" }, 4000),
    ...Array.from({ length: 24 }, (_, i) => entry({ type: "PASSWORD", title: `Service ${String.fromCharCode(65 + i)}${i % 3 === 0 ? " Cloud" : ""}`, primaryValue: `user${i}@example.com`, secondaryValue: `pw-${i}-xyz`, tertiaryValue: `https://service${i}.example.com` }, 5000 + i * 90)),
    entry({ type: "CARD", title: "Travel card", primaryValue: "4111111111111111", secondaryValue: "J DOE", tertiaryValue: "08/29", fourthValue: "123", network: "Visa", favorite: true }, 90),
    entry({ type: "CARD", title: "Groceries debit", primaryValue: "5555555555554444", secondaryValue: "J DOE", tertiaryValue: "11/27", fourthValue: "456", network: "Mastercard", cardKind: "DEBIT" }, 3000),
    entry({ type: "AUTHENTICATOR", title: "GitHub", primaryValue: "dev@example.com", secondaryValue: "JBSWY3DPEHPK3PXP" }, 50),
    entry({ type: "AUTHENTICATOR", title: "AWS root", primaryValue: "ops@example.com", secondaryValue: "GEZDGNBVGY3TQOJQ", favorite: true }, 500),
    entry({ type: "AUTHENTICATOR", title: "Dropbox", primaryValue: "me@example.com", secondaryValue: "MFRGGZDFMZTWQ2LK", totpDigits: 8 }, 900),
    entry({ type: "QUESTION", title: "Bank security question", primaryValue: "First pet's name?", secondaryValue: "Biscuit" }, 7000),
    entry({ type: "AUTOFILL", title: "Home", primaryValue: JSON.stringify({ name: "Jamie Doe", email: "jamie@example.com", phone: "+1 555 0100", address1: "1 Example Street", city: "Springfield", country: "US" }) }, 8000)
  ] as VaultEntry[],
  notes: [
    { id: id(), title: "Home Wi-Fi", body: "Network: Example-5G\nPassword is on the router sticker.", createdAt: minutes(9000), updatedAt: minutes(200), groupIds: [] },
    { id: id(), title: "Recovery steps", body: "1. Find the paper backup\n2. Restore on phone first", createdAt: minutes(20000), updatedAt: minutes(4000), groupIds: [] }
  ] as LocalNote[],
  groups: [{ id: "g-work", name: "Work", notes: "", folderType: "PASSWORD" }, { id: "g-home", name: "Home", notes: "", folderType: "" }] as VaultGroup[],
  passkeys: [{ id: id(), rpId: "github.com", username: "dev@example.com", displayName: "Dev", createdAt: minutes(30000) }] as PasskeySummary[],
  photos: new Map<string, EntryPhoto[]>(),
  sync: { lastSync: new Date(minutes(3)).toISOString(), waitingToApply: 0, conflicts: 0, phoneAddress: "192.168.1.24", automatic: true, running: false, message: "Sent 2 changes and received 1.", phase: "idle", progressDone: 0, progressTotal: 0, lastError: "", lastAttempt: new Date(minutes(1)).toISOString(), consecutiveFailures: 0, nextRetrySeconds: 0, wifiCheckSeconds: 60, driveCheckSeconds: 15 } as SyncStatus,
  pairing: { stage: "", confirmation: "", message: "", invitation: "" } as PairingStatus,
  activity: [] as ActivityEvent[],
  conflicts: [] as SyncConflict[],
  removedNotice: null as MembershipStatus["removedNotice"],
  pendingLeave: false,
  photos_waiting: 2,
  cloud: { available: true, connected: false, account: "", lastSync: "", lastError: "", connecting: false, needsSignIn: false, checkSeconds: 15 } as CloudStatus
};
state.entries[0].groupIds = ["g-work"];
state.conflicts = [
  { id: "c-1", entityType: "entry", entityId: state.entries[1].id, title: state.entries[1].title, localUpdatedAt: minutes(42), remoteUpdatedAt: minutes(18), remoteDevice: "Pixel 8", summary: "Password changed on both devices" },
  { id: "c-2", entityType: "note", entityId: state.notes[0].id, title: state.notes[0].title, localUpdatedAt: minutes(300), remoteUpdatedAt: minutes(260), remoteDevice: "Pixel 8", summary: "Note text edited on both devices" }
];
state.sync.conflicts = state.conflicts.length;
// Preview the "removed from group" notice with ?removed in the URL.
if (window.location.search.includes("removed")) {
  state.enrolled = false;
  state.removedNotice = { by: "Pixel 8", at: minutes(60 * 26) };
}

function log(level: ActivityEvent["level"], category: ActivityEvent["category"], message: string) {
  state.activity.unshift({ id: nextId++, at: Date.now(), level, category, message });
}
log("success", "sync", "Sync finished: sent 2, received 1");
log("info", "browser", "Filled a login on github.com");
log("success", "vault", "Vault unlocked");

function snapshot(): AppSnapshot {
  const count = (type: VaultEntry["type"]) => state.entries.filter((e) => e.type === type).length;
  return {
    vaultState: state.vault, helloEnabled: state.hello,
    counts: { cards: count("CARD"), logins: count("PASSWORD"), codes: count("AUTHENTICATOR"), questions: count("QUESTION"), autofill: count("AUTOFILL"), notes: state.notes.length },
    pairedDevices: state.enrolled ? 2 : 0, enrolled: state.enrolled, pendingChanges: 3, revision: state.revision, chainState: "recorded"
  };
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const requireUnlocked = () => { if (state.vault !== "unlocked") throw "Unlock the vault first"; };

export async function mockInvoke(command: string, args: Record<string, unknown> = {}): Promise<unknown> {
  await delay(command.startsWith("list") || command.endsWith("status") || command === "app_snapshot" ? 30 : 250);
  switch (command) {
    case "app_snapshot": return snapshot();
    case "hello_available": return true;
    case "unlock_vault": case "create_vault":
      if (args.password === "wrong") { log("error", "security", "Unlock failed"); throw "Wrong password or damaged vault key."; }
      state.vault = "unlocked"; log("success", "vault", "Vault unlocked"); return snapshot();
    case "unlock_hello": state.vault = "unlocked"; log("success", "vault", "Vault unlocked with Windows Hello"); return snapshot();
    case "enable_hello": state.hello = true; log("success", "security", "Windows Hello turned on"); return snapshot();
    case "disable_hello": state.hello = false; log("info", "security", "Windows Hello turned off"); return snapshot();
    case "lock_vault": state.vault = "locked"; log("info", "vault", "Vault locked"); return snapshot();
    case "stop_sharing": state.enrolled = false; log("info", "pairing", "Stopped sharing"); return snapshot();
    case "reset_vault": state.vault = "notConfigured"; state.enrolled = false; return snapshot();
    case "show_main_window": case "close_unlock_prompt": case "approve_card_code": case "decline_card_code": return null;
    case "pending_card_code": return { id: "preview", title: "Travel card", card: "Visa · •••• 1111 · 12/29", site: "shop.example", helloAvailable: false };
    case "list_entries": requireUnlocked(); return state.entries.map((e) => ({ ...e }));
    case "save_entry": {
      requireUnlocked();
      const draft = args.entry as VaultEntry;
      const saved = { ...draft, id: draft.id ?? id(), createdAt: draft.createdAt ?? Date.now(), updatedAt: Date.now() };
      state.entries = [saved, ...state.entries.filter((e) => e.id !== saved.id)];
      state.revision++; log("success", "items", "Item saved"); return saved;
    }
    case "delete_entry": state.entries = state.entries.filter((e) => e.id !== args.id); state.revision++; log("info", "items", "Item deleted"); return null;
    case "list_entry_photos": return state.photos.get(String(args.entryId)) ?? [];
    case "add_entry_photo": {
      const list = state.photos.get(String(args.entryId)) ?? [];
      list.push({ id: id(), mimeType: String(args.mimeType), dataUrl: `data:${args.mimeType};base64,${args.data}` });
      state.photos.set(String(args.entryId), list); return null;
    }
    case "delete_entry_photo": for (const [key, list] of state.photos) state.photos.set(key, list.filter((p) => p.id !== args.photoId)); return null;
    case "list_notes": requireUnlocked(); return state.notes.map((n) => ({ ...n }));
    case "save_note": {
      const existing = state.notes.find((n) => n.id === args.id);
      const saved: LocalNote = { id: (args.id as string) ?? id(), title: String(args.title), body: String(args.body), groupIds: (args.groupIds as string[]) ?? [], createdAt: existing?.createdAt ?? Date.now(), updatedAt: Date.now() };
      state.notes = [saved, ...state.notes.filter((n) => n.id !== saved.id)]; state.revision++; log("success", "items", "Note saved"); return saved;
    }
    case "delete_note": state.notes = state.notes.filter((n) => n.id !== args.id); state.revision++; return null;
    case "list_groups": requireUnlocked(); return state.groups.map((g) => ({ ...g }));
    case "save_group": {
      const saved: VaultGroup = { id: (args.id as string) ?? id(), name: String(args.name), notes: String(args.notes ?? ""), folderType: String(args.folderType ?? "") };
      state.groups = [...state.groups.filter((g) => g.id !== saved.id), saved]; state.revision++; log("success", "items", "Folder saved"); return saved;
    }
    case "delete_group": state.groups = state.groups.filter((g) => g.id !== args.id); state.revision++; return null;
    case "list_passkeys": return state.passkeys;
    case "delete_passkey": state.passkeys = state.passkeys.filter((p) => p.id !== args.id); return null;
    case "sync_status": requireUnlocked(); return { ...state.sync };
    case "configure_sync": state.sync.phoneAddress = String(args.address); state.sync.automatic = Boolean(args.automatic); return null;
    case "set_sync_schedule":
      if (args.wifiSeconds != null) state.sync.wifiCheckSeconds = Number(args.wifiSeconds);
      if (args.driveSeconds != null) { state.sync.driveCheckSeconds = Number(args.driveSeconds); state.cloud.checkSeconds = Number(args.driveSeconds); }
      return null;
    case "sync_now": {
      state.sync = { ...state.sync, running: true, phase: "connecting", progressDone: 0, progressTotal: 0, lastAttempt: new Date().toISOString() };
      log("progress", "sync", "Sync started");
      await delay(700); state.sync = { ...state.sync, phase: "sending", progressDone: 1, progressTotal: 3 };
      await delay(700); state.sync = { ...state.sync, phase: "receiving", progressDone: 2, progressTotal: 3 };
      await delay(700);
      if (String(args.address).startsWith("10.")) {
        state.sync = { ...state.sync, running: false, phase: "error", lastError: "Couldn't reach your phone at this address.", consecutiveFailures: state.sync.consecutiveFailures! + 1, nextRetrySeconds: 60 };
        log("error", "sync", "Sync failed: phone unreachable");
        throw "Connection refused (os error 10061)";
      }
      state.sync = { ...state.sync, running: false, phase: "done", progressDone: 3, progressTotal: 3, lastSync: new Date().toISOString(), lastError: "", consecutiveFailures: 0, nextRetrySeconds: 0, message: "Sent 1 change and received 0." };
      log("success", "sync", "Sync finished: sent 1, received 0");
      return { sent: 1, received: 0, waitingToApply: 0, conflicts: 0 };
    }
    case "pairing_status": return { ...state.pairing };
    case "start_pairing": case "start_reverse_pairing":
      state.pairing = command === "start_reverse_pairing"
        ? { stage: "offering", confirmation: "", message: "Scan this QR on the managing Android phone within two minutes.", invitation: "nuvori-pair://v3/mock-invitation" }
        : { stage: "connecting", confirmation: "", message: "Connecting to the phone on this Wi-Fi network", invitation: "" };
      setTimeout(() => { state.pairing = { stage: "confirm", confirmation: "482 913", message: "Compare this code with the one on your phone. Confirm on both devices.", invitation: "" }; }, 2500);
      return null;
    case "approve_pairing":
      state.pairing = { stage: "transferring", confirmation: "", message: "Receiving the encrypted vault copy", invitation: "" };
      setTimeout(() => { state.pairing = { stage: "paired", confirmation: "", message: "Vault copied.", invitation: "" }; state.enrolled = true; }, 2000);
      return null;
    case "cancel_pairing": state.pairing = { stage: "", confirmation: "", message: "", invitation: "" }; return null;
    case "activity_log": return state.activity.slice(0, Number(args.limit ?? 500));
    case "clear_activity_log": state.activity = []; return null;
    case "list_conflicts": requireUnlocked(); return state.conflicts.map((c) => ({ ...c }));
    case "resolve_conflict": {
      state.conflicts = state.conflicts.filter((c) => c.id !== args.id);
      state.sync.conflicts = state.conflicts.length;
// Preview the "removed from group" notice with ?removed in the URL.
if (window.location.search.includes("removed")) {
  state.enrolled = false;
  state.removedNotice = { by: "Pixel 8", at: minutes(60 * 26) };
} state.revision++;
      log("success", "sync", `Conflict resolved (kept ${args.keep === "local" ? "this PC's" : "the phone's"} version)`);
      return snapshot();
    }
    case "membership_status": {
      requireUnlocked();
      const status: MembershipStatus = {
        managerDeviceId: "dev-pixel", managerName: "Pixel 8", localDeviceId: "dev-pc",
        devices: state.enrolled ? [
          { deviceId: "dev-pixel", name: "Pixel 8", platform: "android", status: "active", isManager: true, isThisDevice: false },
          { deviceId: "dev-pc", name: "This PC", platform: "windows", status: "active", isManager: false, isThisDevice: true },
          { deviceId: "dev-tab", name: "Galaxy Tab", platform: "android", status: "active", isManager: false, isThisDevice: false },
          { deviceId: "dev-old", name: "Old phone", platform: "android", status: "removed", isManager: false, isThisDevice: false }
        ] : [],
        pendingTransferTo: state.enrolled ? "dev-tab" : "", transferAccepted: false,
        removedNotice: state.removedNotice, pendingLeave: state.pendingLeave
      };
      return status;
    }
    case "leave_group": state.enrolled = false; state.pendingLeave = true; log("info", "pairing", "Left the sync group; leave request queued for the managing device"); return snapshot();
    case "dismiss_removed_notice": state.removedNotice = null; return null;
    case "photo_sync_status": {
      const total = 3_400_000;
      const done = state.photos_waiting > 0 ? Math.min(total, ((Date.now() / 1000) % 20) / 20 * total) : total;
      return { waiting: state.photos_waiting, transferredBytes: Math.round(done), totalBytes: total };
    }
    case "connect_browsers": return { browsers: ["chrome", "edge"], changed: true };
    case "build_status": return { version: "2.1.9", storeBuild: true, installerBuildInstalled: true, passkeyProvider: "off" } satisfies BuildStatus;
    case "open_windows_settings": return undefined;
    case "cloud_status": return { ...state.cloud };
    case "cloud_connect": state.cloud = { ...state.cloud, connected: true, account: "you@gmail.com", lastSync: new Date().toISOString() }; return { ...state.cloud };
    case "cloud_cancel_connect": return undefined;
    case "cloud_disconnect": state.cloud = { ...state.cloud, connected: false, account: "", lastSync: "" }; return { ...state.cloud };
    case "browser_status": return { hosts: { chrome: true, brave: false, edge: true }, listening: true, lastRequestAt: minutes(4), lastAction: "Filled a login on github.com", requestsSinceUnlock: 3 } satisfies BrowserStatus;
    default: throw `Command ${command} not found`;
  }
}
