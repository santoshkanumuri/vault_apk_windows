import assert from "node:assert/strict";
import { test } from "node:test";
import { DAY, DEFAULT_INTERVAL, HOUR, INTERVALS, MONTH, WEEK, driveBackupIndicator, everyWords } from "./driveBackup.ts";

/** A status with backups on and nothing wrong. */
function status(change = {}) {
  return {
    available: true,
    connected: true,
    account: "someone@example.com",
    enabled: true,
    intervalMs: DAY,
    lastBackupAt: 1_764_000_000_000,
    running: false,
    needsPassword: false,
    needsSignIn: false,
    passwordSetAt: 1_763_000_000_000,
    lastError: "",
    ...change,
  };
}

test("the intervals are the ones the backend accepts", () => {
  assert.deepEqual(
    INTERVALS.map((option) => Number(option.value)),
    [3_600_000, 86_400_000, 7 * 86_400_000, 30 * 86_400_000],
    "drive_backup_plan.rs: HOUR, DAY, WEEK, MONTH in milliseconds",
  );
  assert.equal(DEFAULT_INTERVAL, DAY, "drive_backup_plan.rs DEFAULT_INTERVAL");
});

test("every interval has words of its own", () => {
  assert.equal(everyWords(HOUR), "every hour");
  assert.equal(everyWords(DAY), "every day");
  assert.equal(everyWords(WEEK), "every week");
  assert.equal(everyWords(MONTH), "every month");
});

test("an interval from somewhere else reads as the default", () => {
  for (const interval of [0, -1, 1, DAY + 1, 365 * DAY, Number.NaN]) {
    assert.equal(everyWords(interval), everyWords(DEFAULT_INTERVAL), String(interval));
  }
});

test("the chip says what the card is doing", () => {
  assert.deepEqual(driveBackupIndicator(status()), { kind: "success", label: "On" });
  assert.deepEqual(driveBackupIndicator(status({ enabled: false })), { kind: "neutral", label: "Off" });
  assert.deepEqual(driveBackupIndicator(status({ running: true })), { kind: "progress", label: "Backing up" });
  assert.deepEqual(driveBackupIndicator(status({ needsPassword: true })), { kind: "warning", label: "Needs your password" });
  assert.deepEqual(driveBackupIndicator(status({ lastError: "Can't reach Google Drive. The backup runs again later." })),
    { kind: "warning", label: "Needs attention" });
});

test("a backup under way, a password and a failure come in that order", () => {
  const everything = { running: true, needsPassword: true, lastError: "Your Google Drive is full. Free some space, then back up again." };
  assert.equal(driveBackupIndicator(status(everything)).label, "Backing up");
  assert.equal(driveBackupIndicator(status({ ...everything, running: false })).label, "Needs your password");
  assert.equal(driveBackupIndicator(status({ ...everything, running: false, needsPassword: false })).label, "Needs attention");
});

test("backups that are off say so, whatever else is true", () => {
  assert.equal(driveBackupIndicator(status({ enabled: false, needsPassword: true, lastError: "anything" })).label, "Off");
});
