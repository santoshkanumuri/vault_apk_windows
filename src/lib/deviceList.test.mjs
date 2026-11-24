// Run with `npm test`. Node strips the TypeScript types of deviceList.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isStale, removeHelp, splitDevices, staleHint } from "./deviceList.ts";

const DAY = 24 * 60 * 60 * 1000;
const now = 1_800_000_000_000;
const device = (name, extra = {}) => ({ deviceId: name, name, platform: "android", status: "active", isManager: false, isThisDevice: false, lastSeen: now - DAY, ...extra });

test("removed devices get their own list, after the active ones", () => {
  const { active, removed } = splitDevices([
    device("Old phone", { status: "removed" }), device("Tablet"), device("This PC", { isThisDevice: true, platform: "windows" }),
    device("Pixel", { isManager: true }), device("Lost PC", { status: "removed", platform: "windows" })
  ]);
  assert.deepEqual(active.map((d) => d.name), ["Pixel", "This PC", "Tablet"]);
  assert.deepEqual(removed.map((d) => d.name), ["Lost PC", "Old phone"]);
});

test("only another active device that synced before and not for 30 days is stale", () => {
  assert.equal(isStale(device("Tablet", { lastSeen: now - 31 * DAY }), now), true);
  assert.equal(isStale(device("Tablet", { lastSeen: now - 29 * DAY }), now), false);
  assert.equal(isStale(device("New", { lastSeen: 0 }), now), false, "never seen is 'Not checked yet', not stale");
  assert.equal(isStale(device("This PC", { isThisDevice: true, lastSeen: now - 90 * DAY }), now), false);
  assert.equal(isStale(device("Gone", { status: "removed", lastSeen: now - 90 * DAY }), now), false);
});

test("the PC says that devices are removed on the managing phone", () => {
  assert.match(removeHelp("Pixel 8"), /open Nuvori on Pixel 8, go to Settings > Devices & sync/);
  assert.match(removeHelp(""), /your managing phone/);
  assert.match(staleHint(device("Tablet", { lastSeen: now - 40 * DAY }), "Pixel 8", now), /^Not seen for 40 days\. If you no longer use it, remove it on Pixel 8/);
  assert.match(staleHint(device("Pixel 8", { isManager: true, lastSeen: now - 40 * DAY }), "Pixel 8", now), /managing role/);
});
