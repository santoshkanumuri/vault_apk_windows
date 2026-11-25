// Run with `npm test`. The same cases as Android `SyncOverviewTest` and `SyncOverviewTextTest`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { overviewText, peerAck, peerAckText, syncFacts, syncNowOutcome, syncOverview, waitingToApplyHere } from "./syncOverview.ts";

const now = 1_790_000_000_000;
const minute = 60_000;
const day = 24 * 60 * minute;
const peer = (name, { unconfirmed = 0, seenAgo = 5 * minute, reported = true, wifiFailed = false } = {}) =>
  ({ deviceId: `id-${name}`, name, unconfirmed, reported, lastSeen: seenAgo === null ? 0 : now - seenAgo, wifiFailed });
const facts = (peers, extra = {}) => ({ now, peers, wifi: "ok", drive: "off", ...extra });
const both = (f) => { const overview = syncOverview(f); return { overview, text: overviewText(f, overview) }; };

test("the owner's case: Wi-Fi failed and Google Drive delivered everything reads as up to date", () => {
  const { overview, text } = both(facts([peer("Pixel 8", { wifiFailed: true })], { wifi: "failed", drive: "ok", lastDriveSync: now - minute }));
  assert.equal(overview.state, "upToDate");
  assert.equal(text.kind, "success");
  assert.equal(text.title, "Up to date");
  assert.equal(text.detail, "Every device has your latest changes.");
  assert.equal(text.note, "Wi-Fi couldn't reach Pixel 8. Google Drive kept it in sync.");
  assert.equal(text.lastSynced, "Last synced 1 min ago");
  const two = both(facts([peer("Pixel 8"), peer("Tablet")], { wifi: "failed", drive: "ok" }));
  assert.equal(two.text.note, "Wi-Fi couldn't reach your devices. Google Drive kept them in sync.");
  // Changes still on the way: Drive carries them, so it is waiting, not an error.
  const waiting = both(facts([peer("Pixel 8", { unconfirmed: 2 })], { wifi: "failed", drive: "ok" }));
  assert.equal(waiting.overview.state, "waiting");
  assert.equal(waiting.text.note, "Wi-Fi couldn't reach Pixel 8. Changes go through Google Drive.");
});

test("a Drive failure is a quiet note while Wi-Fi keeps devices in step", () => {
  const { overview, text } = both(facts([peer("Pixel 8")], { drive: "failed" }));
  assert.equal(overview.state, "upToDate");
  assert.equal(text.note, "Google Drive didn't finish. Wi-Fi kept your devices in sync.");
});

test("both transports failing, or the only one while changes wait, is an error", () => {
  const bothFailed = both(facts([peer("Pixel 8")], { wifi: "failed", drive: "failed" }));
  assert.equal(bothFailed.overview.cause, "bothFailed");
  assert.equal(bothFailed.text.title, "Sync needs attention");
  assert.equal(bothFailed.text.detail, "Couldn't reach your devices over Wi-Fi or Google Drive.");
  assert.equal(bothFailed.text.note, undefined);
  // Wi-Fi only, every device confirmed: synced, with a quiet note.
  assert.equal(both(facts([peer("Pixel 8")], { wifi: "failed" })).text.note, "Wi-Fi couldn't reach Pixel 8 on the last check.");
  const stuck = both(facts([peer("Pixel 8", { unconfirmed: 1 })], { wifi: "failed" }));
  assert.equal(stuck.overview.cause, "wifiOnlyFailed");
  assert.equal(stuck.text.detail, "Wi-Fi couldn't reach Pixel 8. Your changes wait until it connects.");
  assert.equal(stuck.text.note, undefined, "the failure is the headline, not a second line");
  assert.equal(syncOverview(facts([peer("Pixel 8", { unconfirmed: 1 })], { wifi: "off", drive: "failed" })).cause, "driveOnlyFailed");
});

test("waiting counts changes not every active device applied, over both transports", () => {
  const { overview, text } = both(facts([peer("Pixel 8", { unconfirmed: 2 }), peer("Tablet", { unconfirmed: 5 }), peer("PC")]));
  assert.equal(overview.state, "waiting");
  assert.equal(overview.waitingChanges, 5);
  assert.equal(overview.peers["id-PC"], "upToDate");
  assert.equal(text.title, "Waiting for 2 devices");
  assert.equal(text.detail, "5 changes aren't on every device yet.");
  const one = both(facts([peer("Pixel 8", { unconfirmed: 3 }), peer("Tablet")]));
  assert.equal(one.text.title, "Waiting for Pixel 8");
  assert.equal(one.text.detail, "Pixel 8 hasn't confirmed 3 changes yet.");
});

test("a device silent for long with waiting changes is an error; no device heard for days is stale", () => {
  const silent = both(facts([peer("Tablet", { unconfirmed: 2, seenAgo: 4 * day }), peer("Pixel 8")], { drive: "ok" }));
  assert.equal(silent.overview.cause, "deviceSilent");
  assert.equal(silent.text.detail, "Tablet hasn't synced in 4 days and doesn't have your latest changes.");
  assert.equal(syncOverview(facts([peer("Tablet", { seenAgo: 4 * day }), peer("Pixel 8")])).state, "upToDate");
  const stale = both(facts([peer("Pixel 8", { seenAgo: 5 * day })], { drive: "ok", lastDriveSync: now - minute }));
  assert.equal(stale.overview.state, "stale");
  assert.equal(stale.text.title, "Devices haven't synced in 5 days");
  assert.equal(stale.text.detail, "Open Nuvori on your other device so it syncs with Google Drive.");
});

test("real problems stay visible", () => {
  assert.equal(syncOverview(facts([peer("Pixel 8")], { localProblem: "Photo sync needs more free space." })).cause, "localProblem");
  assert.equal(syncOverview(facts([peer("Pixel 8")], { rejected: 2 })).cause, "rejected");
  assert.equal(syncOverview(facts([peer("Pixel 8")], { waitingForKeys: true })).state, "keys");
  assert.equal(syncOverview(facts([peer("Pixel 8")], { conflicts: 1 })).state, "conflicts");
  assert.equal(syncOverview(facts([peer("Pixel 8")], { waitingHere: true })).state, "waitingHere");
  assert.equal(syncOverview(facts([peer("Pixel 8", { seenAgo: null, reported: false })])).state, "notYet");
  assert.equal(peerAck(peer("Pixel 8", { unconfirmed: 1, seenAgo: null, reported: false }), now), "waiting");
});

test("device rows", () => {
  assert.equal(peerAckText(peer("Pixel 8"), "upToDate", now).label, "Up to date");
  assert.equal(peerAckText(peer("Pixel 8", { unconfirmed: 1 }), "waiting", now).detail, "Waiting for Pixel 8 to confirm 1 change.");
  const silent = peerAckText(peer("Tablet", { unconfirmed: 2, seenAgo: 6 * day }), "silent", now);
  assert.equal(silent.kind, "error");
  assert.equal(silent.detail, "Hasn't synced in 6 days. Open Nuvori on it to catch up.");
});

test("facts read the backend: unreachable Wi-Fi is a transport failure, other errors stay errors", () => {
  const sync = { lastSync: new Date(now - day).toISOString(), waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: true, running: false,
    message: "", phase: "error", lastError: "No paired device answered", consecutiveFailures: 2 };
  const cloud = { available: true, connected: true, account: "a", lastSync: new Date(now - minute).toISOString(), lastError: "", connecting: false, needsSignIn: false };
  const membership = { devices: [
    { deviceId: "pc", name: "This PC", platform: "windows", status: "active", isManager: false, isThisDevice: true },
    { deviceId: "phone", name: "Pixel 8", platform: "android", status: "active", isManager: true, isThisDevice: false, lastSeen: now - 2 * minute,
      counts: { checked: true, toSend: 0, toApplyHere: 0, receivedThere: 0, toReceiveHere: 0, unconfirmed: 0 } },
    { deviceId: "old", name: "Old", platform: "android", status: "removed", isManager: false, isThisDevice: false },
  ] };
  const f = syncFacts(sync, cloud, membership, 0, now);
  assert.equal(f.wifi, "failed");
  assert.equal(f.drive, "ok");
  assert.equal(f.localProblem, undefined);
  assert.deepEqual(f.peers.map((p) => p.deviceId), ["phone"], "this PC and removed devices never count");
  assert.equal(syncOverview(f).state, "upToDate");
  const full = syncFacts({ ...sync, lastError: "Photo sync needs more free space." }, cloud, membership, 0, now);
  assert.equal(full.wifi, "ok");
  assert.equal(full.localProblem, "Photo sync needs more free space.");
  assert.equal(syncFacts(sync, { ...cloud, needsSignIn: true }, membership, 0, now).drive, "failed");
  // An older backend without `unconfirmed`: not received plus not applied there.
  const older = { devices: [{ ...membership.devices[1], counts: { checked: true, toSend: 1, toApplyHere: 0, receivedThere: 2, toReceiveHere: 0 } }] };
  assert.equal(syncFacts(sync, cloud, older, 0, now).peers[0].unconfirmed, 3);
});

test("M4: changes that need a newer Nuvori here name the update, not a later sync", () => {
  const status = { waitingToApply: 5, setAside: 1, needsUpdate: [{ deviceId: "phone", name: "a paired device", count: 3 }] };
  assert.equal(waitingToApplyHere(status), 1, "only what applies on a later sync");
  assert.equal(waitingToApplyHere({ waitingToApply: 2 }), 2, "an older backend reports no needsUpdate");
  const membership = { devices: [{ deviceId: "phone", name: "Pixel 8", platform: "android", status: "active", isManager: true,
    isThisDevice: false, lastSeen: now - minute, counts: { checked: true, toSend: 0, toApplyHere: 0, receivedThere: 0, toReceiveHere: 0, unconfirmed: 0 } }] };
  const sync = { lastSync: new Date(now - minute).toISOString(), conflicts: 0, phoneAddress: "", automatic: true, running: false, message: "",
    ...status, waitingToApply: 4, setAside: 0 };
  const f = syncFacts(sync, null, membership, 0, now);
  assert.deepEqual(f.updateFrom, [{ name: "Pixel 8", count: 3 }], "the device's own name");
  assert.equal(f.waitingHere, true);
  const { overview, text } = both(f);
  assert.equal(overview.cause, "appUpdate");
  assert.equal(text.title, "Sync needs attention");
  assert.equal(text.detail, "Update Nuvori to apply 3 changes from Pixel 8.");
  // Set-aside changes stay first, as on Android.
  assert.equal(syncOverview({ ...f, rejected: 1 }).cause, "rejected");
  assert.equal(syncOverview({ ...f, updateFrom: [] , waitingHere: false }).state, "upToDate");
});

test("H1: changes another device applied that never arrived here are not up to date", () => {
  const behind = (name, missingHere) => ({ ...peer(name), missingHere });
  const one = both(facts([behind("Pixel 8", 4), peer("Tablet")], { drive: "ok" }));
  assert.equal(one.overview.state, "waitingHere");
  assert.equal(one.text.kind, "warning");
  assert.equal(one.text.detail, "4 changes from Pixel 8 haven't arrived here yet.");
  assert.equal(both(facts([behind("Pixel 8", 1)])).text.detail, "1 change from Pixel 8 hasn't arrived here yet.");
  const many = both(facts([behind("Pixel 8", 2), behind("Tablet", 3)]));
  assert.deepEqual(many.overview.missingFrom.map((p) => p.name), ["Tablet", "Pixel 8"], "the most first");
  assert.equal(many.text.detail, "5 changes from your other devices haven't arrived here yet.");
  // Arrived and waiting to apply keeps the old sentence; this PC's own changes waiting elsewhere come first.
  assert.equal(both(facts([peer("Pixel 8")], { waitingHere: true })).text.detail, "Changes arrived and are waiting to apply on this PC.");
  assert.equal(syncOverview(facts([{ ...behind("Pixel 8", 2), unconfirmed: 1 }])).state, "waiting");
  assert.equal(syncOverview(facts([behind("Pixel 8", 0)])).state, "upToDate");
  // The backend's count reaches the facts; an older backend without it reads as nothing missing.
  const membership = { devices: [{ deviceId: "phone", name: "Pixel 8", status: "active", isThisDevice: false, lastSeen: now - minute,
    counts: { checked: true, toSend: 0, toApplyHere: 0, receivedThere: 0, toReceiveHere: 0, unconfirmed: 0, missingHere: 6 } }] };
  const sync = { lastSync: new Date(now - minute).toISOString(), waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: true, running: false, message: "" };
  assert.equal(syncOverview(syncFacts(sync, null, membership, 0, now)).state, "waitingHere");
  const older = { devices: [{ ...membership.devices[0], counts: { ...membership.devices[0].counts, missingHere: undefined } }] };
  assert.equal(syncOverview(syncFacts(sync, null, older, 0, now)).state, "upToDate");
});

test("H1: Sync now says up to date only when the overview after the attempt is", () => {
  const report = { peersChecked: 1, peersWaiting: 0, sent: 0, received: 2, waitingToApply: 0, conflicts: 0, cloud: false };
  const after = (f) => { const overview = syncOverview(f); return { overview, text: overviewText(f, overview) }; };
  assert.deepEqual(syncNowOutcome(report, after(facts([peer("Pixel 8")]))), { kind: "success", text: "Synced · received 2" });
  const missing = syncNowOutcome(report, after(facts([{ ...peer("Pixel 8"), missingHere: 3 }])));
  assert.deepEqual(missing, { kind: "warning", text: "Synced · received 2. 3 changes from Pixel 8 haven't arrived here yet." });
  const drive = { ...report, peersChecked: 0, received: 0, cloud: true };
  assert.equal(syncNowOutcome(drive, after(facts([peer("Pixel 8")], { drive: "ok" }))).text, "Google Drive is up to date");
  assert.deepEqual(syncNowOutcome(drive, after(facts([peer("Pixel 8", { unconfirmed: 2 })], { drive: "ok" }))),
    { kind: "info", text: "Google Drive checked. Pixel 8 hasn't confirmed 2 changes yet." });
  // Without a status to read (an older backend), the report decides as before.
  assert.deepEqual(syncNowOutcome(report), { kind: "success", text: "Synced · received 2" });
  assert.equal(syncNowOutcome({ ...report, conflicts: 1 }).kind, "warning");
  assert.equal(syncNowOutcome({ ...report, peersWaiting: 1 }).text, "Synced · received 2. 1 device will catch up when connected.");
});

test("M12: a device's refusal shows on its row; a dropped link is a Wi-Fi note", () => {
  const membership = { devices: [
    { deviceId: "phone", name: "Pixel 8", status: "active", isThisDevice: false, lastSeen: now - minute,
      counts: { checked: true, toSend: 0, toApplyHere: 0, receivedThere: 0, toReceiveHere: 0, unconfirmed: 0 } },
    { deviceId: "tablet", name: "Tablet", status: "active", isThisDevice: false, lastSeen: now - minute,
      counts: { checked: true, toSend: 0, toApplyHere: 0, receivedThere: 0, toReceiveHere: 0, unconfirmed: 0 } },
  ] };
  const refusal = "Sent changes this PC can't accept. Update Nuvori on both. If it keeps happening, pair it again.";
  const sync = { lastSync: new Date(now - minute).toISOString(), waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: true, running: false,
    message: "", phase: "error", lastError: "A paired device sent changes Nuvori on this PC can't accept. Update Nuvori on both devices.", consecutiveFailures: 0,
    deviceFailures: [{ deviceId: "phone", kind: "refused", message: refusal }, { deviceId: "tablet", kind: "temporary", message: "Connection interrupted." }] };
  const f = syncFacts(sync, null, membership, 0, now);
  const overview = syncOverview(f);
  assert.equal(overview.state, "attention", "the worst is the headline, though the tablet synced");
  assert.equal(overviewText(f, overview).detail, sync.lastError);
  assert.equal(overview.peers.phone, "failed");
  assert.deepEqual(peerAckText(f.peers[0], "failed", now), { kind: "error", label: "Can't sync", detail: refusal });
  assert.equal(f.peers[1].wifiFailed, true);
  assert.equal(overview.peers.tablet, "upToDate");
  // An older backend without the list changes nothing.
  assert.equal(syncFacts({ ...sync, deviceFailures: undefined }, null, membership, 0, now).peers[0].failure, undefined);
});

test("M14: a Drive sign-in is the headline, never a quiet note, even while Wi-Fi keeps up", () => {
  const { overview, text } = both(facts([peer("Pixel 8")], { drive: "failed", driveSignIn: true }));
  assert.equal(overview.state, "attention");
  assert.equal(overview.cause, "driveSignIn");
  assert.equal(text.kind, "error");
  assert.equal(text.detail, "Google Drive needs you to sign in again. Until then, changes don't go through Drive.");
  assert.equal(text.note, undefined, "the headline already says it");
  // Read from the backend: only a connected drive that needs a sign-in counts.
  const sync = { lastSync: new Date(now - minute).toISOString(), waitingToApply: 0, conflicts: 0, phoneAddress: "", automatic: true,
    running: false, message: "", consecutiveFailures: 0 };
  const cloud = { available: true, connected: true, account: "a", lastSync: "", lastError: "", connecting: false, needsSignIn: true, checkSeconds: 900 };
  assert.equal(syncFacts(sync, cloud, null, 0, now).driveSignIn, true);
  assert.equal(syncFacts(sync, { ...cloud, connected: false }, null, 0, now).driveSignIn, false);
});
