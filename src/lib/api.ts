import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { SignInsState } from "./signIns";

export type { SignIn, SignInsState } from "./signIns";

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
  /** A locked vault left by an earlier install of Nuvori: show "Welcome back" (install_marker.rs). */
  welcomeBack?: boolean;
  /** While locked: when the vault was last changed (Unix ms, a file time); 0 when unknown. */
  lastUsedAt?: number;
};

export type { AuthenticatorReview, AuthenticatorSource, AuthenticatorSummary } from "./authenticatorImport";
import type { AuthenticatorReview, AuthenticatorSource, AuthenticatorSummary } from "./authenticatorImport";
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
  /** A login's "Linked code": the id of an authenticator item in this vault, or "". */
  linkedAuthenticatorId: string;
  notes: string;
  tags: string;
  favorite: boolean;
  /** Card color as opaque ARGB (0xFFRRGGBB); synced with the phone. */
  color?: number;
  createdAt: number;
  updatedAt: number;
  groupIds: string[];
};

export type EntryDraft = Omit<VaultEntry, "id" | "createdAt" | "updatedAt"> & { id?: string };
/** `rich` is the note's formatting (lib/richNote.ts), "" for a plain note. */
export type LocalNote = { id: string; title: string; body: string; createdAt: number; updatedAt: number; groupIds: string[]; rich?: string };

/** What a KeePass file holds (preview), or what an import saved. No secrets. */
export type KeepassSummary = {
  logins: number; codes: number; notes: number; groups: string[];
  inRecycleBin: number; withoutContent: number; attachments: number; passkeys: number;
  /** After an import: logins already in Nuvori, skipped. */
  duplicates: number;
  /** After an import: codes Nuvori could not use. */
  codesSkipped: number;
};

/** A login's earlier password, kept on this PC only (newest first, up to 10). */
export type { ColumnMapping, ImportChoices, ImportPreview, ImportSummary } from "./passwordImport";
import type { ColumnMapping, ImportChoices, ImportPreview, ImportSummary } from "./passwordImport";

export type PreviousPassword = { password: string; replacedAt: number };

/** The "Website icons" setting and the icons the browser extension saved: site -> `data:image/png;base64,...`. */
export type SiteIconsState = { enabled: boolean; icons: Record<string, string> };

/** A deleted item kept on this PC for 30 days, or this PC's version of an item set aside when it joined a group. */
export type TrashedItem = {
  id: string;
  /** The deleted item's ID. */
  itemId: string;
  kind: "entry" | "note";
  itemType: EntryType | "NOTE";
  title: string;
  deletedAt: number;
  /** Deleted on a paired device; this PC kept its copy. */
  deletedElsewhere: boolean;
  /** When it is deleted for good; 0 for a join copy, which stays until the person acts. */
  expiresAt: number;
  /** "join": the group had another version when this PC joined, so this PC's version waits here for review. */
  reason?: "" | "join" | "removal";
};
export type VaultGroup = { id: string; name: string; notes: string; folderType: string };
export type PasskeySummary = { id: string; rpId: string; username: string; displayName: string; createdAt: number };
export type EntryPhoto = { id: string; mimeType: string; dataUrl: string; isCover?: boolean; addedAt?: number };
/**
 * One request Windows passed to Nuvori's passkey provider. `create` is a new passkey, otherwise a
 * sign-in; `site` is empty when the request never named one; `reason` is why Nuvori didn't offer a
 * passkey, and is empty when it did. Kept on this PC only.
 */
export type PasskeyRequest = { at: number; create: boolean; site: string; offered: boolean; reason: string };

export type SyncPhase = "idle" | "connecting" | "sending" | "receiving" | "applying" | "done" | "error";
export type SyncStatus = {
  lastSync: string;
  waitingToApply: number;
  /** Part of waitingToApply: changes this PC could not read. They are retried on each sync. */
  setAside?: number;
  /** A device was removed with new sync keys and this PC's keys have not arrived: it only receives until they do. */
  waitingForKeys?: boolean;
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
  /** One pass over Wi-Fi and Google Drive each time Nuvori opens, also with automatic sync off. */
  syncOnOpen?: boolean;
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
export type PairingStatus = { stage: PairingStage | string; confirmation: string; message: string; invitation: string;
  /** After a join: this PC's items that differ from the phone's, now in Recently deleted. */
  needsReview?: number;
  /** After a join that kept item IDs: items with the same ID and other content, waiting in Sync conflicts. */
  conflicts?: number };

export type ActivityLevel = "info" | "success" | "warning" | "error" | "progress";
export type ActivityCategory = "vault" | "items" | "sync" | "pairing" | "browser" | "security";
export type ActivityEvent = { id: number; at: number; level: ActivityLevel; category: ActivityCategory; message: string };

export type BrowserStatus = {
  hosts: { chrome: boolean; brave: boolean; edge: boolean; firefox: boolean };
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
  /** Unix ms of the last completed Wi-Fi exchange or signed Google Drive progress report; 0 = not yet. */
  lastSeen?: number;
  counts?: PeerCounts;
};
/** Changes still moving between this PC and one device (same counts as the phone). */
export type PeerCounts = { checked: boolean; toSend: number; toApplyHere: number; receivedThere: number; toReceiveHere: number;
  /** This PC's changes the device has not applied, by its verified progress over Wi-Fi or Google Drive. Absent on older builds. */
  unconfirmed?: number };
export type MembershipStatus = {
  managerDeviceId: string;
  managerName: string;
  localDeviceId: string;
  devices: MemberDevice[];
  pendingTransferTo: string;
  transferAccepted: boolean;
  /** `kept`: received items that had not applied before the removal, now in Recently deleted. */
  removedNotice: null | { by: string; at: number; kept?: number };
  pendingLeave: boolean;
  /** First address a leave request goes to (typed or last confirmed route); empty when none. */
  leaveAddress?: string;
  /** "Mark as lost": this PC takes no new changes from the managing phone and may pair with a new one. */
  managerLost?: boolean;
  /** [device ID, text]: a device silent for months holds back the cleanup of old sync history. A suggestion only. */
  cleanupHint?: [string, string] | null;
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

/** `saved` is false until the backend has its own value; the main window then sends its old one. */
export type AutoLockStatus = { minutes: number; saved: boolean };

/** Auto-type (auto_type.rs): a shortcut that types a login into any desktop app. */
export type AutoTypeStatus = {
  enabled: boolean;
  preset: string;
  shortcut: string;
  pressEnter: boolean;
  state: "off" | "active" | "inUse";
  presets: Array<{ id: string; label: string }>;
};

/** The window the auto-type shortcut recorded. */
export type BrowserFamily = "chromium" | "firefox";
/** One installed browser. `family` is "unknown" until the user picks what it is built on. */
export type Browser = { id: string; name: string; family: BrowserFamily | "unknown"; connected: boolean; askAtStart: boolean; lastSeen: number | null; registered: boolean };
export type AutoTypeTarget = { title: string; app: string };

export type QuickSearchStatus = {
  enabled: boolean;
  preset: string;
  shortcut: string;
  /** "inUse" means another app already owns the key. */
  state: "off" | "active" | "inUse";
  presets: Array<{ id: string; label: string }>;
};

export type CardCodeRequest = { id: string; title: string; card: string; site: string; helloAvailable: boolean };

/**
 * The vault appearance, synced to the whole group (protocol `appearance-v1`). Ids follow
 * `^[a-z][a-z0-9-]{0,31}$`; an id this build's palette does not know (a newer palette) is kept as
 * received, so show the default for it. `pendingSync`: chosen here, not yet sent to the group.
 */
export type Appearance = { accent: string; surface: string; pendingSync: boolean };

/**
 * One set of logins whose saved fields and folders match exactly ("duplicate_passwords").
 * `keep` is the oldest copy, which stays; `remove` holds the others, oldest first. Only IDs
 * cross over: the review draws each copy from the item list this window already holds.
 */
export type DuplicateSet = { keep: string; remove: string[] };

/** The Tauri event sent to every window when the stored appearance changes (here or by sync). */
export const APPEARANCE_CHANGED_EVENT = "appearance-changed";
/** The dev mock's stand-in for the Tauri event, sent on `window`. */
export const MOCK_APPEARANCE_EVENT = "nuvori-mock-appearance-changed";

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

/** Runs `handler` when the auto-type shortcut is pressed in another app. */
export function onAutoType(handler: (target: AutoTypeTarget) => void): () => void {
  if (usingDevMock) return () => {};
  const pending = listen<AutoTypeTarget>("auto-type", (event) => handler(event.payload));
  return () => { void pending.then((unlisten) => unlisten()).catch(() => {}); };
}

/** Runs `handler` when the browser extension saved a new website icon. */
export function onSiteIconsChanged(handler: () => void): () => void {
  if (usingDevMock) return () => {};
  const pending = listen("site-icons-changed", handler);
  return () => { void pending.then((unlisten) => unlisten()).catch(() => {}); };
}

/** Runs `handler` when the browser extension remembered a sign-in method. */
export function onSignInsChanged(handler: () => void): () => void {
  if (usingDevMock) return () => {};
  const pending = listen("sign-ins-changed", handler);
  return () => { void pending.then((unlisten) => unlisten()).catch(() => {}); };
}

/** Runs `handler` when the quick search shortcut is pressed. `hadFocus` is true if Nuvori was already in front. */
export function onQuickSearch(handler: (hadFocus: boolean) => void): () => void {
  if (usingDevMock) return () => {};
  const pending = listen<boolean>("quick-search", (event) => handler(event.payload === true));
  return () => { void pending.then((unlisten) => unlisten()).catch(() => {}); };
}

/** Runs `handler` with the new appearance whenever it changes. Returns the unsubscribe function. */
export function onAppearanceChanged(handler: (appearance: Appearance) => void): () => void {
  if (usingDevMock) {
    const listener = (event: Event) => handler((event as CustomEvent<Appearance>).detail);
    window.addEventListener(MOCK_APPEARANCE_EVENT, listener);
    return () => window.removeEventListener(MOCK_APPEARANCE_EVENT, listener);
  }
  const pending = listen<Appearance>(APPEARANCE_CHANGED_EVENT, (event) => handler(event.payload));
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
  /** Deletes this PC's locked vault without its password. `confirmation` is the typed word RESET. */
  startFresh: (confirmation: string) => call<AppSnapshot>("start_fresh", { confirmation }),
  showMainWindow: () => call<void>("show_main_window"),
  hideMainWindow: () => call<void>("hide_main_window"),
  /** Auto-lock lives in the backend (auto_lock.rs): it locks with no window open. */
  autoLockStatus: () => call<AutoLockStatus>("auto_lock_status"),
  setAutoLock: (minutes: number) => call<AutoLockStatus>("set_auto_lock", { minutes }),
  noteUserActivity: () => call<void>("note_user_activity"),
  /** A secret on the clipboard without history or cloud sync; the backend clears it (clipboard.rs). */
  copySecret: (text: string, clearAfterSeconds: number) => call<void>("copy_secret", { text, clearAfterSeconds }),
  clearSecretClipboard: () => call<void>("clear_secret_clipboard"),
  quickSearchStatus: () => call<QuickSearchStatus>("quick_search_status"),
  setQuickSearch: (enabled: boolean, preset?: string) => call<QuickSearchStatus>("set_quick_search", { enabled, preset: preset ?? null }),
  takeQuickSearchRequest: () => call<boolean>("take_quick_search_request"),
  autoTypeStatus: () => call<AutoTypeStatus>("auto_type_status"),
  setAutoType: (enabled: boolean, preset?: string, pressEnter?: boolean) =>
    call<AutoTypeStatus>("set_auto_type", { enabled, preset: preset ?? null, pressEnter: pressEnter ?? null }),
  autoTypePending: () => call<AutoTypeTarget | null>("auto_type_pending"),
  autoTypeCancel: () => call<void>("auto_type_cancel"),
  /** Types the login into the recorded window. Nuvori minimizes itself first. */
  autoTypeLogin: (id: string) => call<void>("auto_type_login", { id }),
  /** Works while the vault is locked. */
  getAppearance: () => call<Appearance>("get_appearance"),
  /** Saves the choice on this PC and sends it to the group once every device can read it. */
  setAppearance: (accent: string, surface: string) => call<Appearance>("set_appearance", { accent, surface }),
  closeUnlockPrompt: () => call<void>("close_unlock_prompt"),
  pendingCardCode: () => call<CardCodeRequest | null>("pending_card_code"),
  approveCardCode: (id: string, password?: string) => call<void>("approve_card_code", { id, password: password ?? null }),
  declineCardCode: (id: string) => call<void>("decline_card_code", { id }),

  listEntries: () => call<VaultEntry[]>("list_entries"),
  saveEntry: (entry: EntryDraft) => call<VaultEntry>("save_entry", { entry }),
  deleteEntry: (id: string) => call<void>("delete_entry", { id }),
  /** Opens a KeePass file (base64) in memory and lists what an import would add. */
  authenticatorsPreview: (sources: AuthenticatorSource[]) => call<AuthenticatorReview>("authenticators_preview", { sources }),
  authenticatorsImport: (sources: AuthenticatorSource[]) => call<AuthenticatorSummary>("authenticators_import", { sources }),
  keepassPreview: (data: string, password: string, keyFile: string | null) => call<KeepassSummary>("keepass_preview", { data, password, keyFile }),
  keepassImport: (data: string, password: string, keyFile: string | null) => call<KeepassSummary>("keepass_import", { data, password, keyFile }),
  passwordsPreview: (data: string, mapping: ColumnMapping | null) => call<ImportPreview>("passwords_preview", { data, mapping }),
  passwordsImport: (data: string, mapping: ColumnMapping | null, choices: ImportChoices) => call<ImportSummary>("passwords_import", { data, mapping, choices }),
  previousPasswords: (entryId: string) => call<PreviousPassword[]>("previous_passwords", { entryId }),
  clearPreviousPasswords: (entryId: string) => call<void>("clear_previous_passwords", { entryId }),
  siteIcons: () => call<SiteIconsState>("site_icons"),
  setSiteIcons: (enabled: boolean) => call<SiteIconsState>("set_site_icons", { enabled }),
  clearSiteIcons: () => call<SiteIconsState>("clear_site_icons"),
  /** Sign-in methods the extension remembered ("Continue with GitHub" and the account). */
  signIns: () => call<SignInsState>("sign_ins"),
  setSignIns: (enabled: boolean) => call<SignInsState>("set_sign_ins", { enabled }),
  deleteSignIn: (id: string) => call<SignInsState>("delete_sign_in", { id }),
  /** An empty account means "not known". */
  editSignIn: (id: string, account: string) => call<SignInsState>("edit_sign_in", { id, account: account.trim() || null }),
  listTrash: () => call<TrashedItem[]>("list_trash"),
  /** Restores as a new item. Returns its kind, new ID and type. */
  restoreTrashed: (id: string) => call<{ kind: "entry" | "note"; id: string; type: EntryType | "NOTE" }>("restore_trashed", { id }),
  forgetTrashed: (id: string) => call<void>("forget_trashed", { id }),
  emptyTrash: () => call<void>("empty_trash"),
  listEntryPhotos: (entryId: string) => call<EntryPhoto[]>("list_entry_photos", { entryId }),
  addEntryPhoto: (entryId: string, mimeType: string, data: string) => call<void>("add_entry_photo", { entryId, mimeType, data }),
  deleteEntryPhoto: (photoId: string) => call<void>("delete_entry_photo", { photoId }),
  /** Makes this photo the one lists and the item's page show first, on every paired device. */
  setCoverPhoto: (photoId: string) => call<void>("set_cover_photo", { photoId }),

  listNotes: () => call<LocalNote[]>("list_notes"),
  /** `rich` replaces the note's formatting ("" makes it plain); leaving it out keeps what the note had. */
  saveNote: (note: { id?: string; title: string; body: string; groupIds: string[]; rich?: string }) =>
    call<LocalNote>("save_note", { id: note.id ?? null, title: note.title, body: note.body, groupIds: note.groupIds, rich: note.rich ?? null }),
  deleteNote: (id: string) => call<void>("delete_note", { id }),
  /** A new item with the same details and folders, without the item's secrets (`item_copy.rs`). Not for authenticators. */
  duplicateEntry: (id: string) => call<VaultEntry>("duplicate_entry", { id }),
  /** A new note "<title> copy" with the same text, formatting and folders. */
  duplicateNote: (id: string) => call<LocalNote>("duplicate_note", { id }),

  listGroups: () => call<VaultGroup[]>("list_groups"),
  saveGroup: (group: { id?: string; name: string; notes: string; folderType: string }) =>
    call<VaultGroup>("save_group", { id: group.id, name: group.name, notes: group.notes, folderType: group.folderType }),
  deleteGroup: (id: string) => call<void>("delete_group", { id }),

  listPasskeys: () => call<PasskeySummary[]>("list_passkeys"),
  /** Ids of the logins with a passkey for the same site and username ("passkey_mark"). */
  passkeyLoginIds: () => call<string[]>("passkey_login_ids"),
  deletePasskey: (id: string) => call<void>("delete_passkey", { id }),

  duplicatePasswords: () => call<DuplicateSet[]>("duplicate_passwords"),
  /** Deletes the chosen copies. The vault works the sets out again, so a stale review is refused. */
  deleteDuplicatePasswords: (ids: string[]) => call<number>("delete_duplicate_passwords", { ids }),

  syncStatus: () => call<SyncStatus>("sync_status"),
  configureSync: (address: string, automatic: boolean) => call<void>("configure_sync", { address, automatic }),
  /** Saves the check interval of one or both ways; a value left out keeps its saved choice. */
  setSyncSchedule: (schedule: { wifiSeconds?: number; driveSeconds?: number }) =>
    call<void>("set_sync_schedule", { wifiSeconds: schedule.wifiSeconds ?? null, driveSeconds: schedule.driveSeconds ?? null }),
  syncNow: (address: string) => call<SyncReport>("sync_now", { address }),
  /** Turns "Sync when Nuvori opens" on or off on this PC. */
  setSyncOnOpen: (enabled: boolean) => call<void>("set_sync_on_open", { enabled }),

  pairingStatus: () => call<PairingStatus>("pairing_status"),
  startPairing: (setupLink: string, masterPassword: string) => call<void>("start_pairing", { setupLink, masterPassword }),
  startReversePairing: (masterPassword: string) => call<void>("start_reverse_pairing", { masterPassword }),
  approvePairing: () => call<void>("approve_pairing"),
  cancelPairing: () => call<void>("cancel_pairing"),

  activityLog: (limit?: number) => call<ActivityEvent[]>("activity_log", limit === undefined ? {} : { limit }),
  clearActivityLog: () => call<void>("clear_activity_log"),
  /** What Windows asked this PC's passkey provider, newest first. Reads while the vault is locked. */
  passkeyRequests: () => call<PasskeyRequest[]>("passkey_requests"),
  clearPasskeyRequests: () => call<void>("clear_passkey_requests"),
  browserStatus: () => call<BrowserStatus>("browser_status"),
  listBrowsers: () => call<Browser[]>("list_browsers"),
  setBrowser: (id: string, change: { connected?: boolean; askAtStart?: boolean; family?: BrowserFamily }) =>
    call<Browser[]>("set_browser", { id, connected: change.connected ?? null, askAtStart: change.askAtStart ?? null, family: change.family ?? null }),
  connectBrowsers: () => call<{ browsers: string[]; changed: boolean }>("connect_browsers"),
  buildStatus: () => call<BuildStatus>("build_status"),
  cloudStatus: () => call<CloudStatus>("cloud_status"),
  cloudConnect: () => call<CloudStatus>("cloud_connect"),
  cloudCancelConnect: () => call<void>("cloud_cancel_connect"),
  cloudDisconnect: () => call<CloudStatus>("cloud_disconnect"),
  openWindowsSettings: (page: "passkeys" | "apps") => call<void>("open_windows_settings", { page }),
  /** Opens a web or mail link from a note, after the person confirmed it. */
  openNoteLink: (link: string) => call<void>("open_note_link", { link }),
  listConflicts: () => call<SyncConflict[]>("list_conflicts"),
  resolveConflict: (id: string, keep: "local" | "remote") => call<AppSnapshot>("resolve_conflict", { id, keep }),
  photoSyncStatus: () => call<PhotoSyncStatus>("photo_sync_status"),
  membershipStatus: () => call<MembershipStatus>("membership_status"),
  leaveGroup: (keepItems = true) => call<AppSnapshot>("leave_group", { keepItems }),
  dismissRemovedNotice: () => call<void>("dismiss_removed_notice"),
  markManagerLost: (lost: boolean) => call<MembershipStatus>("mark_manager_lost", { lost })
};
