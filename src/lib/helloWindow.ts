// "Require the master password again" (hello_window.rs, Android's LockTiming.kt): how long Windows
// Hello may open the vault after the master password was last typed. Kept apart from the pages so
// the rules can be tested without a browser.

export const DAY_MS = 86_400_000;
export const WEEK_MS = 604_800_000;

/** Every unlock, after 1 day or after 1 week, as on Android. Never longer than a week. */
export const MASTER_PASSWORD_INTERVALS = [0, DAY_MS, WEEK_MS] as const;
export type MasterPasswordInterval = (typeof MASTER_PASSWORD_INTERVALS)[number];

/** What the lock screen does about Windows Hello (`VaultStore::hello_lock_screen`). */
export type HelloUnlock = "off" | "ready" | "password" | "everyUnlock";

export type HelloLockScreen = {
  /** Offer the Windows Hello button. */
  button: boolean;
  /** Why it isn't offered, when Windows Hello is on: the master password first, or every unlock. */
  notice: "" | "password" | "everyUnlock";
};

/**
 * What the lock screen shows about Windows Hello. `available` is whether Windows Hello works on
 * this PC now. A build without `helloUnlock` offers the button whenever Windows Hello is on.
 */
export function helloLockScreen(snapshot: { helloEnabled: boolean; helloUnlock?: HelloUnlock }, available: boolean): HelloLockScreen {
  if (!snapshot.helloEnabled || !available) return { button: false, notice: "" };
  const state = snapshot.helloUnlock ?? "ready";
  if (state === "ready") return { button: true, notice: "" };
  if (state === "password" || state === "everyUnlock") return { button: false, notice: state };
  return { button: false, notice: "" };
}

/** A stored or typed value brought within the three choices, like Android's capMasterPasswordInterval. */
export function capInterval(value: number | null | undefined): MasterPasswordInterval {
  if (value === 0 || value === DAY_MS || value === WEEK_MS) return value;
  if (typeof value !== "number" || Number.isNaN(value)) return DAY_MS;
  if (value <= 0) return 0;
  return value >= WEEK_MS ? WEEK_MS : DAY_MS;
}

/** As on Android, only moving to 1 week asks first: the master password is typed less often. */
export function confirmsFirst(current: number, next: number): boolean {
  return next === WEEK_MS && capInterval(current) !== WEEK_MS;
}
