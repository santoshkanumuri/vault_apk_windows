// Run with `npm test`. Node strips the TypeScript types of syncState.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { newestTime, syncIndicator } from "./syncState.ts";

test("the last sync is the newer of the Wi-Fi and Google Drive times", () => {
  const wifi = "2026-11-15T10:00:00Z";
  const drive = "2026-11-20T15:40:00Z";
  assert.equal(newestTime(wifi, drive), drive, "a Drive sync today beats a Wi-Fi sync 5 days ago");
  assert.equal(newestTime(drive, wifi), drive);
  assert.equal(newestTime(wifi, ""), wifi, "Drive not connected");
  assert.equal(newestTime(undefined, null, ""), "");
  assert.equal(newestTime("not a time", wifi), wifi);
  // Different offsets compare by the real moment, not by the text.
  assert.equal(newestTime("2026-11-20T10:00:00-06:00", "2026-11-20T15:30:00Z"), "2026-11-20T10:00:00-06:00");
});

test("H1: the indicator counts a Google Drive sync, not only Wi-Fi's", () => {
  const snapshot = { enrolled: true };
  const status = { lastSync: "", waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: true, running: false, message: "" };
  assert.equal(syncIndicator(snapshot, status).label, "Looking for your devices");
  assert.equal(syncIndicator(snapshot, status, false, "2026-11-25T10:00:00Z").label, "Last check complete");
});

test("M12: Sync paused hides no refusal and no Google Drive problem", () => {
  const snapshot = { enrolled: true };
  const paused = { lastSync: "2026-11-25T10:00:00Z", waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: false, running: false, message: "" };
  assert.equal(syncIndicator(snapshot, paused).label, "Sync paused");
  const refused = { ...paused, phase: "error", lastError: "A paired device sent changes Nuvori on this PC can't accept. Update Nuvori on both devices." };
  assert.deepEqual(syncIndicator(snapshot, refused), { kind: "error", label: "Sync needs attention", detail: refused.lastError });
  const drive = { available: true, connected: true, account: "", lastSync: "2026-11-25T10:00:00Z", lastError: "", connecting: false, needsSignIn: false };
  assert.equal(syncIndicator(snapshot, paused, false, "", drive).label, "Last check complete", "Drive keeps syncing: not paused");
  assert.equal(syncIndicator(snapshot, paused, false, "", { ...drive, lastError: "Google Drive is out of space." }).detail, "Google Drive is out of space.");
  assert.equal(syncIndicator(snapshot, { ...paused, automatic: true }, false, "", { ...drive, needsSignIn: true }).kind, "error");
  // An unreachable device while paused stays quiet.
  assert.equal(syncIndicator(snapshot, { ...paused, phase: "error", lastError: "No paired device answered." }).label, "Sync paused");
});
