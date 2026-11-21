// Run with `npm test`. Node strips the TypeScript types of syncState.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { newestTime } from "./syncState.ts";

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
