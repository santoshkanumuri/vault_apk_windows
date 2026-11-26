// What the Backups page shows for Google Drive backup. The schedule's rules live in the backend
// (`drive_backup_plan.rs`, as Android's `DriveBackupPlan`); these are the intervals it accepts, the
// words for them and the chip in the card's corner.
import type { DriveBackupStatus } from "./api";
import type { StatusKind } from "../components/Status";
import { driveBackupText as words } from "../strings.ts";

export const HOUR = 3_600_000;
export const DAY = 86_400_000;
export const WEEK = 7 * DAY;
export const MONTH = 30 * DAY;

/** The intervals the backend accepts, in the order the control shows them. */
export const INTERVALS = [
  { value: String(HOUR), label: words.hourly, every: words.everyHour },
  { value: String(DAY), label: words.daily, every: words.everyDay },
  { value: String(WEEK), label: words.weekly, every: words.everyWeek },
  { value: String(MONTH), label: words.monthly, every: words.everyMonth },
] as const;

export const DEFAULT_INTERVAL = DAY;

/** "every day" for an interval, and the default's words for anything else. */
export function everyWords(intervalMs: number): string {
  return INTERVALS.find((option) => option.value === String(intervalMs))?.every
    ?? INTERVALS.find((option) => option.value === String(DEFAULT_INTERVAL))?.every
    ?? words.everyDay;
}

/**
 * The chip in the card's corner. A backup under way comes first, then the master password the
 * backups need, then a failure: each is more use to the person than "On".
 */
export function driveBackupIndicator(status: DriveBackupStatus): { kind: StatusKind; label: string } {
  if (status.running) return { kind: "progress", label: words.chipRunning };
  if (!status.enabled) return { kind: "neutral", label: words.chipOff };
  if (status.needsPassword) return { kind: "warning", label: words.chipPassword };
  if (status.lastError) return { kind: "warning", label: words.chipAttention };
  return { kind: "success", label: words.chipOn };
}
