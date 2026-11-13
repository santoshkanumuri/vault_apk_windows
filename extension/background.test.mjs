import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(fileURLToPath(new URL("./background.js", import.meta.url)), "utf8");

function area(data) {
  return {
    get: async (keys) => {
      const list = keys == null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((key) => key in data).map((key) => [key, structuredClone(data[key])]));
    },
    set: async (value) => Object.assign(data, structuredClone(value)),
  };
}

async function worker(hostReply, { tabUrl = "https://example.com/next", setTimeout = () => 0, frames = [], frameReply } = {}) {
  const data = {};
  const session = {};
  const requests = [];
  const sent = [];
  const clock = { now: 1_700_000_000_000 };
  let listener;
  let startup;
  let alarm;
  let uuid = 0;
  const alarms = [];
  class FakeDate extends Date { static now() { return clock.now; } }
  const chrome = {
    storage: { local: area(data), session: area(session) },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {}, setTitle: async () => {}, openPopup: async () => {} },
    scripting: { executeScript: async () => frames },
    tabs: {
      sendMessage: async (tabId, message, options) => { sent.push({ tabId, message: structuredClone(message), options }); return frameReply ? frameReply(message, options) : { status: "ok", filled: 1 }; },
      query: async () => [],
      get: async (id) => ({ id, url: typeof tabUrl === "function" ? tabUrl(id) : tabUrl }),
      onActivated: { addListener() {} }, onUpdated: { addListener() {} }, onRemoved: { addListener() {} },
    },
    alarms: { create: async (name, info) => { alarms.push({ name, info }); }, onAlarm: { addListener: (callback) => { alarm = callback; } } },
    runtime: {
      onMessage: { addListener: (callback) => { listener = callback; } },
      onStartup: { addListener: (callback) => { startup = callback; } },
      sendNativeMessage: async (_host, request) => {
        requests.push(request);
        return hostReply(request);
      },
    },
  };
  vm.runInNewContext(source, { chrome, URL, Date: FakeDate, setTimeout, crypto: { randomUUID: () => `id-${++uuid}` } });
  await new Promise(setImmediate);
  const send = (message, sender = {}) => new Promise((resolve) => { if (!listener(message, sender, resolve)) resolve({ status: "rejected" }); });
  return { data, session, requests, sent, send, alarm, alarms, clock, startup: () => startup() };
}

const page = (url = "https://example.com/login", tab = 1, extra = {}) => ({ tab: { id: tab }, frameId: 0, url, ...extra });
const sealing = (review) => (request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
  : request.action === "review_login" ? review(request)
  : request.action === "query_credentials" ? { status: "ok", credentials: [] }
  : { status: "saved" };

test("an encrypted login waits while locked and saves after unlock", async () => {
  let unlocked = false;
  const state = await worker(() => ({ status: unlocked ? "saved" : "locked" }));
  const queued = await state.send({ action: "queue_login", origin: "https://example.com", sealed: "encrypted-blob" });
  assert.equal(queued.pending, 1);
  assert.equal(state.data.pendingLogins[0].sealed, "encrypted-blob");
  assert.equal(JSON.stringify(state.data).includes("plaintext-password"), false);
  unlocked = true;
  const flushed = await state.send({ action: "flush_pending" });
  assert.equal(flushed.status, "saved");
  assert.equal(state.data.pendingLogins.length, 0);
  assert.equal(state.requests[1].action, "commit_login");
  assert.equal(state.requests[1].origin, "https://example.com");
});

test("a different saved password stays queued for review", async () => {
  const state = await worker(() => ({ status: "account_exists" }));
  await state.send({ action: "queue_login", origin: "https://example.com", sealed: "encrypted-blob" });
  assert.equal(state.data.pendingLogins[0].state, "review");
  const status = await state.send({ action: "pending_status" });
  assert.equal(status.review, 1);
  assert.equal(status.items[0].sealed, undefined);
  await state.send({ action: "remove_pending", id: status.items[0].id });
  assert.equal(state.data.pendingLogins.length, 0);
});

test("submitted logins remain encrypted until the user approves saving", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  const sender = page();
  const result = await state.send({ action: "capture_submitted_login", username: "synthetic-user", password: "synthetic-password", origin: "https://wrong-site.com" }, sender);
  assert.equal(result.status, "review");
  assert.equal(result.prompt.kind, "save");
  assert.equal(result.prompt.host, "example.com");
  assert.equal(state.session.capturedLogins[0].state, "confirm");
  assert.deepEqual(state.data.pendingLogins, [], "an unapproved capture never reaches chrome.storage.local");
  assert.equal(JSON.stringify(state.data).includes("synthetic-password"), false);
  assert.equal(JSON.stringify(state.session).includes("synthetic-password"), false);
  assert.equal(JSON.stringify(result).includes("synthetic-password"), false);
  assert.equal(state.requests.some(request => request.action === "commit_login"), false);
  assert.equal(state.requests.find(request => request.action === "seal_login").origin, "https://example.com");
  await state.send({ action: "flush_pending" });
  assert.equal((await state.send({ action: "pending_status" })).pending, 1);
  const id = state.session.capturedLogins[0].id;
  assert.equal((await state.send({ action: "approve_pending", id }, sender)).status, "rejected");
  await state.send({ action: "approve_pending", id });
  assert.equal(state.data.pendingLogins[0].approved, true, "approval moves it to local storage");
  await state.send({ action: "flush_pending" });
  assert.equal(state.data.pendingLogins.length, 0);
});

test("an already saved submitted login does not prompt again", async () => {
  const state = await worker(request => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" } : { status: "already_saved" });
  const result = await state.send({ action: "capture_submitted_login", username: "user", password: "synthetic-password" }, page("https://example.com/"));
  assert.equal(result.status, "already_saved");
  assert.equal(state.data.pendingLogins, undefined);
  assert.equal((await state.send({ action: "inline_pending" }, page())).status, "none");
});

test("replacement needs its review token and never retries an expired update", async () => {
  const choice = { id: "account", title: "Example", username: "user", selectionToken: "review-token" };
  const state = await worker(request => request.action === "update_login" ? { status: "selection_expired" } : { status: "account_exists", credentials: [choice] });
  await state.send({ action: "queue_login", origin: "https://example.com", sealed: "protected-login" });
  const id = state.data.pendingLogins[0].id;
  const result = await state.send({ action: "update_pending", id });
  assert.equal(result.status, "review");
  assert.equal(state.requests.filter(request => request.action === "update_login").length, 1);
  assert.equal(state.requests.find(request => request.action === "update_login").selectionToken, "review-token");
  await state.send({ action: "flush_pending" });
  assert.equal(state.requests.filter(request => request.action === "update_login").length, 1);
  assert.equal(state.data.pendingLogins[0].state, "review");
});

test("refreshing a removed account asks for save approval and does not commit", async () => {
  const state = await worker(request => ({ status: request.action === "review_login" ? "needs_save" : "account_exists" }));
  await state.send({ action: "queue_login", origin: "https://example.com", sealed: "protected-login" });
  const id = state.data.pendingLogins[0].id;
  const commits = state.requests.filter(request => request.action === "commit_login").length;
  await state.send({ action: "retry_pending", id });
  await state.send({ action: "flush_pending" });
  assert.equal(state.data.pendingLogins[0].state, "confirm");
  assert.equal(state.requests.filter(request => request.action === "commit_login").length, commits);
});

// --- Inline suggestions ------------------------------------------------------

test("inline queries take the origin from the sender, return metadata only, and are cached", async () => {
  const state = await worker((request) => request.action === "query_credentials"
    ? { status: "ok", credentials: [{ id: "a", title: "Work", username: "alice", selectionToken: "secret-token" }] }
    : { status: "ok" });
  const result = await state.send({ action: "inline_query", origin: "https://evil.example" }, page("https://example.com/login?next=1"));
  assert.equal(result.status, "ok");
  assert.deepEqual(JSON.parse(JSON.stringify(result.accounts)), [{ id: "a", title: "Work", username: "alice" }]);
  assert.equal(JSON.stringify(result).includes("secret-token"), false);
  assert.equal(state.requests[0].origin, "https://example.com");
  await state.send({ action: "inline_query" }, page());
  assert.equal(state.requests.filter((request) => request.action === "query_credentials").length, 1, "second focus uses the cache");
  state.clock.now += 13_000;
  await state.send({ action: "inline_query" }, page());
  assert.equal(state.requests.filter((request) => request.action === "query_credentials").length, 2, "cache expires");
});

test("inline actions are refused outside the top frame, off HTTPS, and from extension pages", async () => {
  const state = await worker(() => ({ status: "ok", credentials: [] }));
  for (const sender of [
    { tab: { id: 1 }, frameId: 3, url: "https://example.com/" },
    { tab: { id: 1 }, frameId: 0, url: "http://example.com/" },
    { tab: { id: 1 }, frameId: 0, url: "https://example.com/", origin: "https://other.example" },
    {},
  ]) {
    for (const action of ["inline_query", "inline_fill", "inline_pending", "inline_approve", "inline_dont_suggest"]) {
      assert.equal((await state.send({ action, credentialId: "a", id: "x", decision: "save" }, sender)).status, "rejected", `${action} from ${JSON.stringify(sender)}`);
    }
  }
  assert.equal(state.requests.length, 0);
});

test("inline fill uses the cached token, refreshes it once on expiry, and returns only to the same site", async () => {
  let fills = 0;
  let queries = 0;
  const state = await worker((request) => {
    if (request.action === "query_credentials") return { status: "ok", credentials: [{ id: "a", title: "Work", username: "alice", selectionToken: `token-${++queries}` }] };
    if (request.action === "fill_credential") return ++fills === 1 ? { status: "selection_expired" } : { status: "ok", credential: { id: "a", username: "alice", password: "synthetic-secret" } };
    return { status: "ok" };
  });
  await state.send({ action: "inline_query" }, page());
  const result = await state.send({ action: "inline_fill", credentialId: "a" }, page());
  assert.equal(result.status, "ok");
  assert.equal(result.password, "synthetic-secret");
  const fillRequests = state.requests.filter((request) => request.action === "fill_credential");
  assert.deepEqual(fillRequests.map((request) => request.selectionToken), ["token-1", "token-2"]);
  assert.ok(fillRequests.every((request) => request.origin === "https://example.com"));
  assert.equal(JSON.stringify(state.data).includes("synthetic-secret"), false);
  assert.equal(JSON.stringify(state.session).includes("synthetic-secret"), false);
  assert.equal(JSON.stringify(state.session.diagnostics).includes("alice"), false, "diagnostics never hold usernames");
  assert.equal(JSON.stringify(state.data).includes("alice"), false, "the account name of a sign-in is never written to disk");
  assert.equal(state.session.signInSteps[1].username, "alice", "the filled account is remembered for this tab, in memory only");
  const events = state.session.diagnostics;
  assert.ok(events.length > 0);
  for (const event of events) assert.deepEqual(Object.keys(event).sort(), ["action", "at", "host", "status"]);
});

test("a username-only fill never returns the password, and a navigated tab gets nothing", async () => {
  let url = "https://example.com/login";
  const state = await worker((request) => request.action === "query_credentials"
    ? { status: "ok", credentials: [{ id: "a", title: "Work", username: "alice", selectionToken: "t" }] }
    : { status: "ok", credential: { id: "a", username: "alice", password: "synthetic-secret" } }, { tabUrl: () => url });
  const usernameOnly = await state.send({ action: "inline_fill", credentialId: "a", want: "username" }, page());
  assert.equal(usernameOnly.status, "ok");
  assert.equal(usernameOnly.password, undefined);
  url = "https://attacker.example/";
  const moved = await state.send({ action: "inline_fill", credentialId: "a" }, page());
  assert.equal(moved.status, "error");
  assert.equal(moved.password, undefined);
});

test("inline suggestions respect the global switch and the per-site list", async () => {
  const state = await worker(() => ({ status: "ok", credentials: [] }));
  assert.equal((await state.send({ action: "inline_dont_suggest" }, page())).status, "ok");
  assert.deepEqual(state.data.noSuggest, ["https://example.com"]);
  assert.equal((await state.send({ action: "inline_query" }, page())).status, "disabled");
  assert.equal((await state.send({ action: "inline_query" }, page("https://other.example/"))).status, "ok");
  state.data.inlineSuggestions = false;
  assert.equal((await state.send({ action: "inline_query" }, page("https://other.example/"))).status, "disabled");
});

// --- In-page save / update prompts ------------------------------------------

test("a captured login's prompt survives navigation in the same tab and site, then expires", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  const captured = await state.send({ action: "capture_submitted_login", username: "synthetic-user", password: "synthetic-password" }, page("https://example.com/login", 7));
  const pending = await state.send({ action: "inline_pending" }, page("https://example.com/home", 7));
  assert.equal(pending.status, "ok");
  assert.equal(pending.prompt.id, captured.prompt.id);
  assert.equal(pending.prompt.username, "synthetic-user");
  assert.equal(JSON.stringify(state.data).includes("synthetic-user"), false, "usernames stay out of persistent storage");
  assert.equal((await state.send({ action: "inline_pending" }, page("https://example.com/home", 8))).status, "none", "other tab");
  assert.equal((await state.send({ action: "inline_pending" }, page("https://other.example/", 7))).status, "none", "other site");
  state.clock.now += 2 * 60 * 1000 + 1;
  assert.equal((await state.send({ action: "inline_pending" }, page("https://example.com/home", 7))).status, "none", "expired");
  assert.equal((await state.send({ action: "pending_status" })).pending, 0, "an unanswered capture expires with its prompt");
  assert.equal(JSON.stringify(state.data).includes("protected-login"), false);
});

test("approval is accepted only from the tab and site that created the prompt", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page("https://example.com/login", 7));
  for (const sender of [page("https://example.com/", 8), page("https://other.example/", 7), { tab: { id: 7 }, frameId: 2, url: "https://example.com/" }]) {
    const result = await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, sender);
    assert.notEqual(result.status, "saved");
  }
  assert.equal(state.requests.some((request) => request.action === "commit_login"), false);
  assert.equal((await state.send({ action: "inline_approve", id: "someone-else", decision: "save" }, page("https://example.com/", 7))).status, "missing");
  const saved = await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, page("https://example.com/", 7));
  assert.equal(saved.status, "saved");
  assert.equal(state.data.pendingLogins.length, 0);
  assert.equal((await state.send({ action: "inline_pending" }, page("https://example.com/", 7))).status, "none");
});

test("decisions must fit the item's state", async () => {
  const choice = { id: "account", title: "Example", username: "u", selectionToken: "t".repeat(64) };
  const state = await worker(sealing(() => ({ status: "account_exists", credentials: [choice] })));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.equal(prompt.kind, "update");
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, page())).status, "error");
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "never" }, page())).status, "error");
  assert.equal(state.requests.some((request) => request.action === "commit_login"), false);
  const updated = await state.send({ action: "inline_approve", id: prompt.id, decision: "update" }, page());
  assert.equal(updated.status, "updated");
  assert.equal(state.requests.find((request) => request.action === "update_login").selectionToken, choice.selectionToken);
});

test("an expired update approval is reviewed again and never retried automatically", async () => {
  let token = 0;
  const state = await worker((request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : request.action === "update_login" ? { status: "selection_expired" }
    : request.action === "review_login" ? { status: "account_exists", credentials: [{ id: "account", username: "u", selectionToken: `review-${++token}` }] }
    : { status: "ok", credentials: [] });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  const result = await state.send({ action: "inline_approve", id: prompt.id, decision: "update" }, page());
  assert.equal(result.status, "review");
  assert.equal(result.prompt.kind, "update");
  assert.equal(state.requests.filter((request) => request.action === "update_login").length, 1);
  assert.equal(state.session.capturedLogins[0].updateChoices[0].selectionToken, "review-2");
  await state.send({ action: "flush_pending" });
  assert.equal(state.requests.filter((request) => request.action === "update_login").length, 1);
});

test("saving while locked keeps the sealed login queued for later", async () => {
  let unlocked = false;
  const state = await worker((request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : unlocked ? { status: request.action === "query_credentials" ? "ok" : "saved", credentials: [] } : { status: "locked" });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.equal(prompt.kind, "save");
  assert.equal(prompt.locked, true);
  const result = await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, page());
  assert.equal(result.status, "queued");
  assert.equal(state.data.pendingLogins.length, 1);
  assert.equal(state.data.pendingLogins[0].state, undefined, "approved and waiting");
  assert.equal(state.data.pendingLogins[0].sealed, "protected-login");
  unlocked = true;
  await state.send({ action: "flush_pending" });
  assert.equal(state.data.pendingLogins.length, 0);
});

test("Never for this site discards the capture and stops future prompts", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "never" }, page())).status, "never");
  assert.deepEqual(state.data.neverSave, ["https://example.com"]);
  assert.equal(state.data.pendingLogins.length, 0);
  const seals = state.requests.filter((request) => request.action === "seal_login").length;
  assert.equal((await state.send({ action: "capture_submitted_login", username: "u", password: "p2" }, page())).status, "never");
  assert.equal(state.requests.filter((request) => request.action === "seal_login").length, seals, "nothing is sealed for a never-save site");
});

test("Not now discards the capture; a second submit replaces the unanswered one", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  await state.send({ action: "capture_submitted_login", username: "u", password: "wrong" }, page());
  state.clock.now += 5_000;
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "right" }, page());
  assert.equal(state.session.capturedLogins.length, 1, "the earlier capture was replaced");
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "dismiss" }, page())).status, "dismissed");
  assert.equal(state.session.capturedLogins.length, 0);
});

test("clipboard clearing and diagnostics logging are popup-only", async () => {
  const state = await worker(() => ({ status: "ok" }));
  assert.equal((await state.send({ action: "clipboard_clear_later" }, page())).status, "rejected");
  assert.equal((await state.send({ action: "log_event", event: { action: "x", status: "y" } }, page())).status, "rejected");
  assert.equal((await state.send({ action: "clipboard_clear_later" })).status, "ok");
  assert.ok(state.alarms.some((entry) => entry.name === "clearClipboard" && entry.info.delayInMinutes === 0.5));
  await state.send({ action: "log_event", event: { action: "fill_credential", status: "ok<script>", origin: "https://example.com", username: "alice" } });
  const entry = state.session.diagnostics[0];
  assert.deepEqual(entry, { at: state.clock.now, action: "fill_credential", status: "okscript", host: "example.com" });
});

// --- Additive host features (protocol 2) ------------------------------------

const FEATURES = ["status_no_origin", "login_title", "password_only", "multi_update"];

function featureHost({ features, review = () => ({ status: "needs_save" }), commit = () => ({ status: "saved" }) }) {
  return (request) => {
    if (request.action === "status") return features ? { status: "ok", features } : { status: "ok" };
    if (request.action === "seal_login") return { status: "sealed", sealedLogin: "protected-login" };
    if (request.action === "review_login") return review(request);
    if (request.action === "commit_login") return commit(request);
    if (request.action === "query_credentials") return { status: "ok", credentials: [] };
    return { status: "saved" };
  };
}

test("an older host gets no new fields: placeholder status origin, no titles, no password-only saves", async () => {
  const state = await worker(featureHost({ features: undefined }));
  const status = await state.send({ action: "connection_status" });
  assert.equal(status.status, "ok");
  assert.deepEqual([...status.features], []);
  assert.equal(state.requests.at(-1).origin, "https://status.nuvori.invalid");
  const passwordOnly = await state.send({ action: "capture_submitted_login", username: "", password: "p" }, page());
  assert.equal(passwordOnly.status, "unsupported");
  assert.equal(state.requests.some((request) => request.action === "seal_login"), false);
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p", titleHint: "Example" }, page());
  assert.equal(prompt.canTitle, false);
  await state.send({ action: "inline_approve", id: prompt.id, decision: "save", title: "My name" }, page());
  const commit = state.requests.find((request) => request.action === "commit_login");
  assert.equal("title" in commit, false);
  assert.ok(state.requests.every((request) => !("title" in request)));
});

test("a current host gets an empty status origin, the chosen name on commit, and password-only captures", async () => {
  const state = await worker(featureHost({ features: FEATURES }));
  await state.send({ action: "connection_status" });
  await state.send({ action: "connection_status" });
  const pings = state.requests.filter((request) => request.action === "status");
  assert.deepEqual(pings.map((request) => request.origin), ["https://status.nuvori.invalid", ""]);
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "", password: "p", titleHint: "Example\nSite" }, page("https://www.example.com/login"));
  assert.equal(state.requests.find((request) => request.action === "seal_login").username, "");
  assert.equal(prompt.canTitle, true);
  assert.equal(prompt.username, "");
  assert.equal(prompt.title, "Example Site", "control characters never reach the name");
  const saved = await state.send({ action: "inline_approve", id: prompt.id, decision: "save", title: "  Home\trouter  " }, page("https://www.example.com/"));
  assert.equal(saved.status, "saved");
  assert.equal(state.requests.find((request) => request.action === "commit_login").title, "Home router");
  assert.equal(JSON.stringify(state.session.diagnostics).includes("router"), false, "titles never reach diagnostics");
  assert.equal(state.requests.filter((request) => request.action === "status").length, 2, "features are cached");
});

test("whitespace-only usernames are always rejected", async () => {
  const state = await worker(featureHost({ features: FEATURES }));
  const result = await state.send({ action: "capture_submitted_login", username: "   ", password: "p" }, page());
  assert.equal(result.status, "error");
  assert.equal(state.requests.some((request) => request.action === "seal_login"), false);
});

test("a name chosen while locked is kept with the queued login and sent when it saves", async () => {
  let unlocked = false;
  const state = await worker((request) => request.action === "status" ? { status: unlocked ? "ok" : "locked", features: FEATURES }
    : request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : unlocked ? { status: "saved" } : { status: "locked" });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "save", title: "Work" }, page())).status, "queued");
  assert.equal(state.data.pendingLogins[0].title, "Work");
  unlocked = true;
  await state.send({ action: "flush_pending" });
  assert.equal(state.requests.filter((request) => request.action === "commit_login").at(-1).title, "Work");
  assert.equal(state.data.pendingLogins.length, 0);
});

const twoAccounts = [
  { id: "a", title: "Personal", username: "u", selectionToken: "a".repeat(64) },
  { id: "b", title: "Work", username: "u", selectionToken: "b".repeat(64) },
];

test("several matching accounts: the page sees choices without tokens and must pick one", async () => {
  const state = await worker(featureHost({ features: FEATURES, review: () => ({ status: "account_exists", message: "Choose which saved account to update.", credentials: twoAccounts }) }));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.equal(prompt.kind, "update");
  assert.deepEqual(prompt.choices.map((choice) => ({ ...choice })), [{ id: "a", title: "Personal", username: "u" }, { id: "b", title: "Work", username: "u" }]);
  assert.equal(JSON.stringify(prompt).includes("a".repeat(64)), false);
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "update" }, page())).status, "choose");
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "update", credentialId: "zzz" }, page())).status, "choose");
  assert.equal(state.requests.some((request) => request.action === "update_login"), false);
  const updated = await state.send({ action: "inline_approve", id: prompt.id, decision: "update", credentialId: "b" }, page());
  assert.equal(updated.status, "updated");
  const update = state.requests.find((request) => request.action === "update_login");
  assert.equal(update.credentialId, "b");
  assert.equal(update.selectionToken, "b".repeat(64));
});

test("committing an approved login that turns out to exist offers every matching account", async () => {
  const state = await worker(featureHost({ features: FEATURES, commit: () => ({ status: "account_exists", credentials: twoAccounts }) }));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  const result = await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, page());
  assert.equal(result.status, "review");
  assert.equal(result.message, "Choose which saved account to update.");
  assert.equal(result.prompt.choices.length, 2);
});

test("the popup lists choices and updates the one picked; legacy single-choice items still work", async () => {
  const state = await worker(featureHost({ features: FEATURES }));
  state.data.pendingLogins = [
    { id: "multi", origin: "https://example.com", sealed: "s1", state: "review", approved: true, updateChoices: twoAccounts },
    { id: "legacy", origin: "https://example.com", sealed: "s2", state: "review", approved: true, updateChoice: twoAccounts[0] },
  ];
  const status = await state.send({ action: "pending_status" });
  assert.equal(status.items[0].choices.length, 2);
  assert.equal(JSON.stringify(status).includes("a".repeat(64)), false);
  assert.equal(status.items[1].canUpdate, true);
  assert.equal((await state.send({ action: "update_pending", id: "multi" })).status, "choose");
  assert.equal((await state.send({ action: "update_pending", id: "multi", credentialId: "a" })).status, "saved");
  assert.equal((await state.send({ action: "update_pending", id: "legacy" })).status, "saved");
  assert.deepEqual(state.requests.filter((request) => request.action === "update_login").map((request) => request.credentialId), ["a", "a"]);
});

test("feature and status messages are popup-only", async () => {
  const state = await worker(featureHost({ features: FEATURES }));
  assert.equal((await state.send({ action: "host_features" }, page())).status, "rejected");
  assert.equal((await state.send({ action: "connection_status" }, page())).status, "rejected");
  assert.deepEqual([...(await state.send({ action: "host_features" })).features], FEATURES);
});

// --- Security review regressions (M1, M2, M3, L4) ---------------------------

test("M1: captures are rate limited per tab and per site, before any host call", async () => {
  const state = await worker(sealing(() => ({ status: "needs_save" })));
  const capture = (password, tab = 1, url = "https://example.com/") => state.send({ action: "capture_submitted_login", username: "alice", password }, page(url, tab));
  assert.equal((await capture("guess-1")).status, "review");
  const seals = state.requests.filter((request) => request.action === "seal_login").length;
  assert.equal((await capture("guess-2")).status, "limited", "one capture per tab per 5 seconds");
  assert.equal(state.requests.filter((request) => request.action === "seal_login").length, seals, "a limited guess never reaches the host");
  for (let tab = 2; tab <= 4; tab++) assert.equal((await capture(`guess-${tab}`, tab)).status, "review");
  assert.equal((await capture("guess-5", 5)).status, "limited", "four per site per minute");
  assert.equal((await capture("other", 6, "https://other.example/")).status, "review", "other sites are unaffected");
  state.clock.now += 61_000;
  assert.equal((await capture("later", 5)).status, "review");
});

test("M2: unapproved captures stay in memory and only approved ones reach local storage", async () => {
  const state = await worker((request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : request.action === "review_login" ? { status: "needs_save" } : { status: "locked" });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "alice", password: "typo-pass" }, page());
  assert.deepEqual(state.data.pendingLogins, []);
  assert.equal(state.session.capturedLogins.length, 1);
  state.clock.now += 6 * 24 * 60 * 60 * 1000;
  assert.equal((await state.send({ action: "pending_status" })).pending, 0);
  state.clock.now -= 6 * 24 * 60 * 60 * 1000;
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "save" }, page())).status, "queued");
  assert.equal(state.data.pendingLogins.length, 1, "Save while locked keeps it for later");
  assert.equal(state.data.pendingLogins[0].approved, true);
});

test("M2: Update while locked is kept for later without its expired token", async () => {
  const choice = { id: "account", title: "T", username: "u", selectionToken: "t".repeat(64) };
  const state = await worker((request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : request.action === "review_login" ? { status: "account_exists", credentials: [choice] } : { status: "locked" });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p" }, page());
  assert.deepEqual(state.data.pendingLogins, []);
  assert.equal((await state.send({ action: "inline_approve", id: prompt.id, decision: "update" }, page())).status, "queued_update");
  const kept = state.data.pendingLogins[0];
  assert.equal(kept.state, "review");
  assert.equal(kept.approved, true);
  assert.equal(kept.updateChoices, undefined, "the popup reviews again before replacing");
});

test("M2: unapproved items left in local storage by older versions are dropped", async () => {
  const state = await worker(() => ({ status: "locked" }));
  state.data.pendingLogins = [
    { id: "old-confirm", origin: "https://a.example", sealed: "s", state: "confirm" },
    { id: "old-review", origin: "https://a.example", sealed: "s", state: "review", updateChoice: { id: "x", selectionToken: "y" } },
    { id: "approved-wait", origin: "https://a.example", sealed: "s" },
    { id: "approved-review", origin: "https://a.example", sealed: "s", state: "review", approved: true },
  ];
  const status = await state.send({ action: "pending_status" });
  assert.deepEqual([...status.items.map((item) => item.id)], ["approved-wait", "approved-review"]);
});

test("M3: one site can't fill the queue", async () => {
  const state = await worker(() => ({ status: "locked" }));
  for (let index = 0; index < 5; index++) {
    assert.equal((await state.send({ action: "queue_login", origin: "https://evil.example", sealed: `s${index}` })).status === "error", false);
  }
  assert.equal((await state.send({ action: "queue_login", origin: "https://evil.example", sealed: "s6" })).status, "error");
  assert.notEqual((await state.send({ action: "queue_login", origin: "https://bank.example", sealed: "real" })).status, "error");
  const captures = await worker(sealing(() => ({ status: "needs_save" })));
  for (let tab = 1; tab <= 6; tab++) {
    captures.clock.now += 16_000;
    await captures.send({ action: "capture_submitted_login", username: `u${tab}`, password: "p" }, page("https://evil.example/", tab));
  }
  assert.equal(captures.session.capturedLogins.filter((item) => item.origin === "https://evil.example").length, 3, "oldest captures from one site are dropped");
  const real = await captures.send({ action: "capture_submitted_login", username: "me", password: "real" }, page("https://bank.example/", 99));
  assert.equal(real.status, "review");
});

test("L4: titles lose control and format characters, including bidi overrides", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ["login_title"] }
    : request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : request.action === "review_login" ? { status: "needs_save" } : { status: "saved" });
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "u", password: "p", titleHint: "Pay\u202Elap\u200B" }, page());
  assert.equal(prompt.title, "Paylap");
  await state.send({ action: "inline_approve", id: prompt.id, decision: "save", title: "My\u202E\u2066 Bank\u0007" }, page());
  assert.equal(state.requests.find((request) => request.action === "commit_login").title, "My Bank");
});

test("browser start asks Nuvori to show its unlock window when it is locked or not running", async () => {
  for (const status of ["locked", "desktop_unavailable"]) {
    const state = await worker((request) => request.action === "status" ? { status, features: ["status_no_origin", "unlock_prompt"] }
      : request.action === "unlock_prompt" ? { status: status === "locked" ? "locked" : "starting" } : { status: "locked" });
    state.startup();
    await new Promise(setImmediate);
    await new Promise(setImmediate);
    const unlock = state.requests.find((request) => request.action === "unlock_prompt");
    assert.ok(unlock, `${status}: unlock_prompt was sent`);
    assert.equal(unlock.origin, "");
    assert.deepEqual(Object.keys(unlock).sort(), ["action", "origin", "requestId", "version"]);
  }
});

test("browser start stays quiet when unlocked, turned off, or the host is too old", async () => {
  const cases = [
    [{ status: "ok", features: ["unlock_prompt"] }, {}],
    [{ status: "locked", features: ["unlock_prompt"] }, { unlockOnStartup: false }],
    [{ status: "desktop_unavailable", features: ["status_no_origin"] }, {}],
  ];
  for (const [reply, settings] of cases) {
    const state = await worker(() => reply);
    Object.assign(state.data, settings);
    state.startup();
    await new Promise(setImmediate);
    await new Promise(setImmediate);
    assert.equal(state.requests.some((request) => request.action === "unlock_prompt"), false, JSON.stringify(reply));
  }
});

test("the popup and a trusted page button can ask for the unlock window", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "locked", features: ["status_no_origin", "unlock_prompt"] }
    : request.action === "unlock_prompt" ? { status: "locked" } : { status: "locked" });
  assert.equal((await state.send({ action: "unlock_app" })).status, "locked");
  assert.equal((await state.send({ action: "inline_unlock" }, page())).status, "locked");
  assert.equal(state.requests.filter((request) => request.action === "unlock_prompt").length, 2);
  // A page script can't use the popup's message.
  assert.equal((await state.send({ action: "unlock_app" }, page())).status, "rejected");
});

// --- Cards, addresses and codes --------------------------------------------------

const ALL_FEATURES = ["status_no_origin", "login_title", "password_only", "multi_update", "unlock_prompt", "cards", "profiles", "codes", "save_details", "login_edit"];
const immediate = (callback) => { queueMicrotask(callback); return 0; };

test("cards: the page gets titles, then one card without its code; the code waits for approval in Nuvori", async () => {
  let polls = 0;
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "query_items") return { status: "ok", credentials: [{ id: "c1", title: "Travel", username: "Visa · •••• 1111", selectionToken: "t".repeat(64) }] };
    if (request.action === "fill_item") return { status: "ok", item: { id: "c1", kind: "card", card: { number: "4111111111111111", name: "A", expiry: "07/29", network: "Visa" }, cvvToken: "v".repeat(64) } };
    if (request.action === "request_cvv") return { status: "pending" };
    if (request.action === "fill_cvv") return ++polls < 3 ? { status: "pending" } : { status: "ok", item: { id: "c1", kind: "card", card: { cvv: "123" } } };
    return { status: "error" };
  }, { setTimeout: immediate });
  const listed = await state.send({ action: "inline_items", kind: "card" }, page());
  assert.equal(listed.status, "ok");
  assert.deepEqual(JSON.parse(JSON.stringify(listed.items)), [{ id: "c1", title: "Travel", subtitle: "Visa · •••• 1111" }]);
  assert.equal(JSON.stringify(listed).includes("t".repeat(64)), false, "tokens stay in the worker");
  const filled = await state.send({ action: "inline_fill_item", kind: "card", id: "c1" }, page());
  assert.deepEqual(JSON.parse(JSON.stringify(filled.card)), { number: "4111111111111111", name: "A", expiry: "07/29", network: "Visa", hasCode: true });
  assert.equal(JSON.stringify(filled).includes("v".repeat(64)), false);
  const code = await state.send({ action: "inline_card_code", id: "c1" }, page());
  assert.equal(code.status, "ok");
  assert.equal(code.code, "123");
  assert.equal(polls, 3);
  const ask = state.requests.find((request) => request.action === "request_cvv");
  assert.deepEqual([ask.kind, ask.credentialId, ask.selectionToken], ["card", "c1", "v".repeat(64)]);
  assert.equal((await state.send({ action: "inline_card_code", id: "c1" }, page())).status, "expired", "one approval per fill");
  // Another tab or site can't use this card's code token.
  await state.send({ action: "inline_fill_item", kind: "card", id: "c1" }, page());
  assert.equal((await state.send({ action: "inline_card_code", id: "c1" }, page("https://example.com/login", 2))).status, "expired");
});

test("codes: matches by default, all on request; off switches stay quiet", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES }
    : request.action === "query_items" ? { status: "ok", credentials: request.all ? [{ id: "k1", title: "Bank", username: "", selectionToken: "x" }] : [] }
    : request.action === "fill_item" ? { status: "ok", item: { id: "k1", kind: "code", code: { value: "287082", secondsLeft: 9 } } } : { status: "error" });
  assert.equal((await state.send({ action: "inline_items", kind: "code" }, page())).items.length, 0);
  assert.equal((await state.send({ action: "inline_items", kind: "code", all: true }, page())).items.length, 1);
  const filled = await state.send({ action: "inline_fill_item", kind: "code", id: "k1" }, page());
  assert.equal(filled.code.value, "287082");
  state.data.fillCodes = false;
  assert.equal((await state.send({ action: "inline_items", kind: "code" }, page())).status, "disabled");
  assert.equal((await state.send({ action: "inline_items", kind: "nope" }, page())).status, "error");
});

test("an older host without the feature never gets item requests", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ["status_no_origin"] } : { status: "error" });
  assert.equal((await state.send({ action: "inline_items", kind: "card" }, page())).status, "unsupported");
  assert.equal(state.requests.some((request) => request.action === "query_items"), false);
});

test("a submitted card is sealed by the host and saved only after Save, with the chosen name", async () => {
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "seal_details") return { status: "sealed", sealedLogin: "sealed-card" };
    if (request.action === "review_details") return { status: "needs_save" };
    if (request.action === "commit_details") return { status: "saved" };
    return { status: "none" };
  });
  const captured = await state.send({ action: "capture_details", kind: "card", card: { number: "4111111111111111", name: "A Person", expiry: "07/29" } }, page());
  assert.equal(captured.status, "review");
  assert.equal(captured.prompt.kind, "save_card");
  assert.equal(captured.prompt.title, "Visa •••• 1111");
  assert.equal(JSON.stringify(captured).includes("4111111111111111"), false, "the prompt never repeats the full number");
  const seal = state.requests.find((request) => request.action === "seal_details");
  assert.deepEqual([seal.kind, seal.card.number, seal.card.network, "cvv" in seal.card], ["card", "4111111111111111", "Visa", false]);
  assert.equal(state.requests.some((request) => request.action === "commit_details"), false, "nothing saves without approval");
  assert.equal(JSON.stringify(state.data).includes("sealed-card"), false, "unanswered captures stay out of local storage");
  const pending = await state.send({ action: "inline_pending" }, page());
  assert.equal(pending.prompt.id, captured.prompt.id);
  const saved = await state.send({ action: "inline_approve", id: captured.prompt.id, decision: "save", title: "Travel" }, page());
  assert.equal(saved.status, "saved");
  const commit = state.requests.find((request) => request.action === "commit_details");
  assert.deepEqual([commit.sealedLogin, commit.title], ["sealed-card", "Travel"]);
  assert.equal((await state.send({ action: "inline_pending" }, page())).status, "none");
});

test("details: invalid cards are refused, Never stops prompts, and the setting turns saving off", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES }
    : request.action === "seal_details" ? { status: "sealed", sealedLogin: "s" } : request.action === "review_details" ? { status: "needs_save" } : { status: "none" });
  assert.equal((await state.send({ action: "capture_details", kind: "card", card: { number: "41111", expiry: "" } }, page())).status, "error");
  assert.equal((await state.send({ action: "capture_details", kind: "card", card: { number: "4111111111111111", expiry: "13/29" } }, page())).status, "error");
  const captured = await state.send({ action: "capture_details", kind: "profile", profile: { address1: "1 Main Road", city: "Pune", extra: "x" } }, page());
  assert.equal(captured.prompt.kind, "save_profile");
  assert.equal("extra" in state.requests.find((request) => request.action === "seal_details").profile, false);
  await state.send({ action: "inline_approve", id: captured.prompt.id, decision: "never" }, page());
  assert.deepEqual([...state.data.neverSave], ["https://example.com"]);
  assert.equal((await state.send({ action: "capture_details", kind: "profile", profile: { address1: "2 Road", city: "Pune" } }, page())).status, "never");
  const other = await worker(() => ({ status: "ok", features: ALL_FEATURES }));
  other.data.saveDetails = false;
  assert.equal((await other.send({ action: "capture_details", kind: "profile", profile: { address1: "1", city: "P" } }, page())).status, "never");
});

test("login_edit: the corrected username goes with commit_login", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES } : sealing(() => ({ status: "needs_save" }))(request));
  const { prompt } = await state.send({ action: "capture_submitted_login", username: "typo-user", password: "p" }, page());
  assert.equal(prompt.canEditUsername, true);
  await state.send({ action: "inline_approve", id: prompt.id, decision: "save", username: "  real-user " }, page());
  assert.equal(state.requests.find((request) => request.action === "commit_login").username, "real-user");
});

test("a login saved for another page of the same site is listed after exact ones and marked", async () => {
  const state = await worker((request) => request.action === "query_credentials" ? { status: "ok", credentials: [
    { id: "a", title: "Example", username: "alice", selectionToken: "t1" },
    { id: "b", title: "Example login", username: "bob", selectionToken: "t2", related: true }] } : { status: "ok" });
  const result = await state.send({ action: "inline_query" }, page());
  assert.equal(JSON.stringify(result.accounts), JSON.stringify([
    { id: "a", title: "Example", username: "alice" },
    { id: "b", title: "Example login", username: "bob", related: true }]));
});

test("two-step sign-in: the account from the first page leads the list and names a password-only save", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES }
    : request.action === "query_credentials" ? { status: "ok", credentials: [
      { id: "a", title: "Work", username: "alice@example.com", selectionToken: "t1" },
      { id: "b", title: "Home", username: "Bob@Example.com", selectionToken: "t2" }] }
    : request.action === "query_items" ? { status: "ok", credentials: [
      { id: "c1", title: "Example", username: "alice@example.com", selectionToken: "c1" },
      { id: "c2", title: "Example", username: "bob@example.com", selectionToken: "c2" }] }
    : request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" }
    : request.action === "review_login" ? { status: "needs_save" }
    : { status: "ok" });
  const before = await state.send({ action: "inline_query" }, page());
  assert.deepEqual(Array.from(before.accounts, (account) => account.id), ["a", "b"]);
  assert.ok(before.accounts.every((account) => !account.recent));

  // The user typed "bob@example.com" on the identifier-first page.
  assert.equal((await state.send({ action: "remember_username", username: " bob@example.com " }, page())).status, "ok");
  const after = await state.send({ action: "inline_query" }, page("https://example.com/password"));
  assert.equal(JSON.stringify(after.accounts.map((account) => [account.id, account.recent === true])), JSON.stringify([["b", true], ["a", false]]));
  const codes = await state.send({ action: "inline_items", kind: "code" }, page("https://example.com/otp"));
  assert.deepEqual(Array.from(codes.items, (item) => item.id), ["c2", "c1"], "the code of the account in use comes first");

  // Another tab gets nothing from this tab's sign-in.
  const otherTab = await state.send({ action: "inline_query" }, page("https://example.com/password", 2));
  assert.deepEqual(Array.from(otherTab.accounts, (account) => account.id), ["a", "b"]);

  // The password page has no account field: the capture carries the remembered name.
  const captured = await state.send({ action: "capture_submitted_login", username: "", password: "synthetic-secret" }, page("https://example.com/password"));
  assert.equal(captured.status, "review");
  assert.equal(captured.prompt.username, "bob@example.com");
  const sealed = state.requests.find((request) => request.action === "seal_login");
  assert.equal(sealed.username, "bob@example.com");
  assert.equal(JSON.stringify(state.data).includes("bob@example.com"), false, "nothing about the step reaches disk");

  // A blank name is ignored.
  await state.send({ action: "remember_username", username: "   " }, page("https://other.example/", 3));
  assert.equal(state.session.signInSteps[3], undefined);
});

test("frames: a focused card field is shown on the top page, and the card goes only to frames of that origin", async () => {
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "query_items") return { status: "ok", credentials: [{ id: "c1", title: "Travel", username: "Visa · •••• 1111", selectionToken: "t".repeat(64) }] };
    if (request.action === "fill_item") return { status: "ok", item: { id: "c1", kind: "card", card: { number: "4111111111111111", name: "A", expiry: "07/29", network: "Visa" }, cvvToken: "v".repeat(64) } };
    return { status: "error" };
  }, { tabUrl: "https://shop.example/checkout", frames: [
    { frameId: 0, result: "https://shop.example" }, { frameId: 3, result: "https://pay.example" },
    { frameId: 5, result: "https://pay.example" }, { frameId: 7, result: "https://ads.example" }] });
  const frame = (frameId, url = "https://pay.example/card") => ({ tab: { id: 1 }, frameId, url });
  const top = { tab: { id: 1 }, frameId: 0, url: "https://shop.example/checkout" };
  const rect = { left: 4, top: 8, width: 200, height: 30 };

  assert.equal((await state.send({ action: "frame_field", detail: "card", rect }, top)).status, "rejected", "only frames report");
  assert.equal((await state.send({ action: "frame_field", detail: "card", rect }, frame(3, "http://pay.example/card"))).status, "rejected");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect }, frame(3))).status, "error", "logins are never filled in a frame");
  assert.equal((await state.send({ action: "frame_field", detail: "card", rect }, frame(3))).status, "ok");
  const shown = state.sent.at(-1);
  assert.deepEqual([shown.options.frameId, shown.message.target, shown.message.frameId, shown.message.detail], [0, "nuvori-top", 3, "card"]);

  // A frame cannot ask for the item itself; only the top page can, for the reported frame.
  assert.equal((await state.send({ action: "inline_fill_frame", kind: "card", id: "c1", frameId: 3 }, frame(3))).status, "rejected");
  assert.equal((await state.send({ action: "inline_fill_frame", kind: "card", id: "c1", frameId: 5 }, top)).status, "missing");
  state.sent.length = 0;
  const filled = await state.send({ action: "inline_fill_frame", kind: "card", id: "c1", frameId: 3 }, top);
  assert.equal(filled.status, "ok");
  assert.equal(filled.codeLeft, true, "the security code is left for the user in a frame");
  assert.deepEqual(state.sent.map((entry) => entry.options.frameId), [3, 5], "never the top page or another site's frame");
  for (const entry of state.sent) {
    assert.deepEqual(entry.message.card, { number: "4111111111111111", name: "A", expiry: "07/29" });
    assert.equal(JSON.stringify(entry.message).includes("v".repeat(64)), false, "no security-code token leaves the worker");
  }
  assert.equal((await state.send({ action: "inline_fill_frame", kind: "card", id: "c1", frameId: 3 }, top)).status, "missing", "one report, one fill");
});
