import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type VaultState = "locked" | "unlocked" | "notConfigured";

export type AppSnapshot = {
  vaultState: VaultState;
  helloEnabled: boolean;
  counts: Record<"cards" | "logins" | "codes" | "questions" | "autofill" | "notes", number>;
  pairedDevices: number;
  enrolled: boolean;
  pendingChanges: number;
  revision: number;
  chainState: "empty" | "recorded" | "invalid";
};

export type EntryType = "CARD" | "PASSWORD" | "AUTHENTICATOR" | "QUESTION" | "AUTOFILL";

export type VaultEntry = {
  id: string;
  type: EntryType;
  title: string;
  primaryValue: string;
  secondaryValue: string;
  tertiaryValue: string;
  fourthValue: string;
  cardKind: "CREDIT" | "DEBIT";
  network: string;
  totpAlgorithm: string;
  totpDigits: number;
  totpPeriod: number;
  notes: string;
  tags: string;
  favorite: boolean;
  createdAt: number;
  updatedAt: number;
  groupIds: string[];
};

export type EntryDraft = Omit<VaultEntry, "id" | "createdAt" | "updatedAt"> & { id?: string };
export type LocalNote = { id: string; title: string; body: string; createdAt: number; updatedAt: number; groupIds: string[] };
export type VaultGroup = { id: string; name: string; notes: string; folderType: string };
export type PasskeySummary = { id: string; rpId: string; username: string; displayName: string; createdAt: number };
export type EntryPhoto = { id: string; mimeType: string; dataUrl: string; isCover?: boolean; addedAt?: number };

export type SyncPhase = "idle" | "connecting" | "sending" | "receiving" | "applying" | "done" | "error";
export type SyncStatus = {
  lastSync: string;
  waitingToApply: number;
  /** Part of waitingToApply: changes this PC could not read. They are retried on each sync. */
  setAside?: number;
  conflicts: number;
  phoneAddress: string;
  automatic: boolean;
  running: boolean;
  message: string;
  // Additive fields from the Rust stream. Absent on older builds.
  phase?: SyncPhase;
  progressDone?: number;
  progressTotal?: number;
  lastError?: string;
  lastAttempt?: string;
  consecutiveFailures?: number;
  nextRetrySeconds?: number;
  /** How often automatic sync checks devices on this Wi-Fi: 30, 60, 300 or 900. */
  wifiCheckSeconds?: number;
  /** How often it checks Google Drive: 15, 60 or 300; 0 = only on Sync now. */
  driveCheckSeconds?: number;
};
export type SyncReport = { peersChecked: number; peersWaiting: number; sent: number; received: number; waitingToApply: number; conflicts: number; /** The pass also went through Google Drive. */ cloud?: boolean };
/** Sync through the user's own Google Drive. */
export type CloudStatus = {
  /** False when this build has no Google sign-in configured. */
  available: boolean;
  connected: boolean;
  account: string;
  lastSync: string;
  lastError: string;
  connecting: boolean;
  needsSignIn: boolean;
  /** How often automatic sync checks Google Drive; 0 = only on Sync now. Absent on older builds. */
  checkSeconds?: number;
};
export type PairingStage = "" | "connecting" | "offering" | "confirm" | "transferring" | "canceling" | "paired" | "failed";
export type PairingStatus = { stage: PairingStage | string; confirmation: string; message: string; invitation: string };

export type ActivityLevel = "info" | "success" | "warning" | "error" | "progress";
export type ActivityCategory = "vault" | "items" | "sync" | "pairing" | "browser" | "security";
export type ActivityEvent = { id: number; at: number; level: ActivityLevel; category: ActivityCategory; message: string };

export type BrowserStatus = {
  hosts: { chrome: boolean; brave: boolean; edge: boolean };
  listening: boolean;
  lastRequestAt: number;
  lastAction: string;
  requestsSinceUnlock: number;
};

/** Whether Windows can use Nuvori's passkeys (Windows Settings > Accounts > Passkeys). */
export type PasskeyProviderState = "installerBuild" | "unsupported" | "notRegistered" | "off" | "on";
export type BuildStatus = {
  version: string;
  /** The Microsoft Store (MSIX) build; false for the MSI or setup EXE build. */
  storeBuild: boolean;
  /** Store build only: the MSI or setup EXE build is installed too. */
  installerBuildInstalled: boolean;
  passkeyProvider: PasskeyProviderState;
};

export type SyncConflict = {
  id: string;
  entityType: "entry" | "note" | "folder" | "passkey" | "photo";
  entityId: string;
  title: string;
  localUpdatedAt: number;
  remoteUpdatedAt: number;
  remoteDevice: string;
  summary: string;
};

export type MemberDevice = {
  deviceId: string;
  name: string;
  platform: "android" | "windows" | "unknown";
  status: "active" | "removed";
  isManager: boolean;
  isThisDevice: boolean;
  /** Unix ms of the last completed exchange; 0 = not yet. */
  lastSeen?: number;
  counts?: PeerCounts;
};
/** Changes still moving between this PC and one device (same counts as the phone). */
export type PeerCounts = { checked: boolean; toSend: number; toApplyHere: number; receivedThere: number; toReceiveHere: number };
export type MembershipStatus = {
  managerDeviceId: string;
  managerName: string;
  localDeviceId: string;
  devices: MemberDevice[];
  pendingTransferTo: string;
  transferAccepted: boolean;
  removedNotice: null | { by: string; at: number };
  pendingLeave: boolean;
  /** First address a leave request goes to (typed or last confirmed route); empty when none. */
  leaveAddress?: string;
};

export type PhotoSyncStatus = { waiting: number; transferredBytes: number; totalBytes: number };

/** True when running in a plain browser during development (no Tauri runtime). */
export const usingDevMock = import.meta.env.DEV && !("__TAURI_INTERNALS__" in window) && !window.location.search.includes("nomock");

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  // The whole branch is statically false in production builds, so the mock module is never bundled.
  if (import.meta.env.DEV && usingDevMock) {
    const { mockInvoke } = await import("../dev/mock");
    return mockInvoke(command, args) as Promise<T>;
  }
  return invoke<T>(command, args);
}

export type CardCodeRequest = { id: string; title: string; card: string; site: string; helloAvailable: boolean };

/**
 * Which window this page runs in: "main", the small "unlock" window, or the "card-code" approval
 * window, both opened for the browser extension. `?view=` previews them in a plain browser.
 */
export function currentWindowLabel(): string {
  const internals = (window as { __TAURI_INTERNALS__?: { metadata?: { currentWindow?: { label?: string } } } }).__TAURI_INTERNALS__;
  if (internals) return internals.metadata?.currentWindow?.label || "main";
  return (import.meta.env.DEV && new URLSearchParams(window.location.search).get("view")) || "main";
}

/** Runs `handler` when any window unlocks or locks the vault. Returns the unsubscribe function. */
export function onVaultChanged(handler: () => void): () => void {
  if (usingDevMock) return () => {};
  const pending = listen("vault-changed", handler);
  return () => { void pending.then((unlisten) => unlisten()).catch(() => {}); };
}

export const api = {
  snapshot: () => call<AppSnapshot>("app_snapshot"),
  createVault: (password: string) => call<AppSnapshot>("create_vault", { password }),
  unlockVault: (password: string) => call<AppSnapshot>("unlock_vault", { password }),
  helloAvailable: () => call<boolean>("hello_available"),
  unlockHello: () => call<AppSnapshot>("unlock_hello"),
  enableHello: (password: string) => call<AppSnapshot>("enable_hello", { password }),
  disableHello: () => call<AppSnapshot>("disable_hello"),
  lockVault: () => call<AppSnapshot>("lock_vault"),
  stopSharing: () => call<AppSnapshot>("stop_sharing"),
  resetVault: (password: string) => call<AppSnapshot>("reset_vault", { password }),
  showMainWindow: () => call<void>("show_main_window"),
  closeUnlockPrompt: () => call<void>("close_unlock_prompt"),
  pendingCardCode: () => call<CardCodeRequest | null>("pending_card_code"),
  approveCardCode: (id: string, password?: string) => call<void>("approve_card_code", { id, password: password ?? null }),
  declineCardCode: (id: string) => call<void>("decline_card_code", { id }),

  listEntries: () => call<VaultEntry[]>("list_entries"),
  saveEntry: (entry: EntryDraft) => call<VaultEntry>("save_entry", { entry }),
  deleteEntry: (id: string) => call<void>("delete_entry", { id }),
  listEntryPhotos: (entryId: string) => call<EntryPhoto[]>("list_entry_photos", { entryId }),
  addEntryPhoto: (entryId: string, mimeType: string, data: string) => call<void>("add_entry_photo", { entryId, mimeType, data }),
  deleteEntryPhoto: (photoId: string) => call<void>("delete_entry_photo", { photoId }),

  listNotes: () => call<LocalNote[]>("list_notes"),
  saveNote: (note: { id?: string; title: string; body: string; groupIds: string[] }) =>
    call<LocalNote>("save_note", { id: note.id ?? null, title: note.title, body: note.body, groupIds: note.groupIds }),
  deleteNote: (id: string) => call<void>("delete_note", { id }),

  listGroups: () => call<VaultGroup[]>("list_groups"),
  saveGroup: (group: { id?: string; name: string; notes: string; folderType: string }) =>
    call<VaultGroup>("save_group", { id: group.id, name: group.name, notes: group.notes, folderType: group.folderType }),
  deleteGroup: (id: string) => call<void>("delete_group", { id }),

  listPasskeys: () => call<PasskeySummary[]>("list_passkeys"),
  deletePasskey: (id: string) => call<void>("delete_passkey", { id }),

  syncStatus: () => call<SyncStatus>("sync_status"),
  configureSync: (address: string, automatic: boolean) => call<void>("configure_sync", { address, automatic }),
  /** Saves the check interval of one or both ways; a value left out keeps its saved choice. */
  setSyncSchedule: (schedule: { wifiSeconds?: number; driveSeconds?: number }) =>
    call<void>("set_sync_schedule", { wifiSeconds: schedule.wifiSeconds ?? null, driveSeconds: schedule.driveSeconds ?? null }),
  syncNow: (address: string) => call<SyncReport>("sync_now", { address }),

  pairingStatus: () => call<PairingStatus>("pairing_status"),
  startPairing: (setupLink: string, masterPassword: string) => call<void>("start_pairing", { setupLink, masterPassword }),
  startReversePairing: (masterPassword: string) => call<void>("start_reverse_pairing", { masterPassword }),
  approvePairing: () => call<void>("approve_pairing"),
  cancelPairing: () => call<void>("cancel_pairing"),

  activityLog: (limit?: number) => call<ActivityEvent[]>("activity_log", limit === undefined ? {} : { limit }),
  clearActivityLog: () => call<void>("clear_activity_log"),
  browserStatus: () => call<BrowserStatus>("browser_status"),
  connectBrowsers: () => call<{ browsers: string[]; changed: boolean }>("connect_browsers"),
  buildStatus: () => call<BuildStatus>("build_status"),
  cloudStatus: () => call<CloudStatus>("cloud_status"),
  cloudConnect: () => call<CloudStatus>("cloud_connect"),
  cloudCancelConnect: () => call<void>("cloud_cancel_connect"),
  cloudDisconnect: () => call<CloudStatus>("cloud_disconnect"),
  openWindowsSettings: (page: "passkeys" | "apps") => call<void>("open_windows_settings", { page }),
  listConflicts: () => call<SyncConflict[]>("list_conflicts"),
  resolveConflict: (id: string, keep: "local" | "remote") => call<AppSnapshot>("resolve_conflict", { id, keep }),
  photoSyncStatus: () => call<PhotoSyncStatus>("photo_sync_status"),
  membershipStatus: () => call<MembershipStatus>("membership_status"),
  leaveGroup: (keepItems = true) => call<AppSnapshot>("leave_group", { keepItems }),
  dismissRemovedNotice: () => call<void>("dismiss_removed_notice")
};
