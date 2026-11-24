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

async function worker(hostReply, { tabUrl = "https://example.com/next", setTimeout = () => 0, frames = [], frameReply, extensionUrl } = {}) {
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
    // Like Chrome: a target with frameIds runs only in those frames. `frames` may also be a function of the call.
    scripting: { executeScript: async (details) => typeof frames === "function" ? frames(details)
      : details?.target?.frameIds ? frames.filter((entry) => details.target.frameIds.includes(entry.frameId)) : frames },
    tabs: {
      sendMessage: async (tabId, message, options) => { sent.push({ tabId, message: structuredClone(message), options }); return frameReply ? frameReply(message, options) : { status: "ok", filled: 1 }; },
      query: async () => [],
      get: async (id) => ({ id, url: typeof tabUrl === "function" ? tabUrl(id) : tabUrl }),
      onActivated: { addListener() {} }, onUpdated: { addListener() {} }, onRemoved: { addListener() {} },
    },
    alarms: { create: async (name, info) => { alarms.push({ name, info }); }, onAlarm: { addListener: (callback) => { alarm = callback; } } },
    runtime: {
      onMessage: { addListener: (callback) => { listener = callback; } },
      ...(extensionUrl ? { getURL: (path) => extensionUrl + path } : {}),
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
  // The next page of the same site shows "Already saved" once (sign-ins usually navigate away).
  const next = await state.send({ action: "inline_pending" }, page("https://example.com/home"));
  assert.equal(next.status, "notice");
  assert.equal(next.text, "Already saved in Nuvori.");
  assert.equal((await state.send({ action: "inline_pending" }, page())).status, "none");
});

test("the 'Already saved' note goes only to the same site in the same tab", async () => {
  const state = await worker(request => request.action === "seal_login" ? { status: "sealed", sealedLogin: "protected-login" } : { status: "already_saved" });
  await state.send({ action: "capture_submitted_login", username: "user", password: "synthetic-password" }, page("https://example.com/"));
  assert.equal((await state.send({ action: "inline_pending" }, page("https://other.example/"))).status, "none");
  assert.equal((await state.send({ action: "inline_pending" }, page("https://example.com/"))).status, "none", "a note is used up by the first page that asks");
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

test("browser start sends startup only when the app lists startup_browsers, and skipped is quiet", async () => {
  for (const [features, expected] of [[["unlock_prompt"], false], [["unlock_prompt", "startup_browsers"], true]]) {
    const state = await worker((request) => request.action === "status" ? { status: "locked", features }
      : request.action === "unlock_prompt" ? { status: expected ? "skipped" : "locked" } : { status: "locked" });
    state.startup();
    await new Promise(setImmediate);
    await new Promise(setImmediate);
    const unlock = state.requests.find((request) => request.action === "unlock_prompt");
    assert.ok(unlock);
    assert.equal(unlock.startup === true, expected);
    assert.equal("startup" in unlock, expected);
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

const ALL_FEATURES = ["status_no_origin", "login_title", "password_only", "multi_update", "unlock_prompt", "cards", "profiles", "codes", "save_details", "login_edit", "all_logins"];
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

test("codes: the page gets this site's codes only; every code is refused to pages; off switches stay quiet", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES }
    : request.action === "query_items" ? { status: "ok", credentials: request.all ? [{ id: "k1", title: "Bank", username: "", selectionToken: "x" }] : [] }
    : request.action === "fill_item" ? { status: "ok", item: { id: "k1", kind: "code", code: { value: "287082", secondsLeft: 9 } } } : { status: "error" });
  assert.equal((await state.send({ action: "inline_items", kind: "code" }, page())).items.length, 0);
  assert.equal((await state.send({ action: "inline_items", kind: "code", all: true }, page())).status, "disabled");
  // A code listed only under "every code" can't be filled from a page either.
  assert.equal((await state.send({ action: "inline_fill_item", kind: "code", id: "k1" }, page())).status, "missing");
  assert.equal(state.requests.some((request) => request.all === true), false, "the vault was never asked for every code");
  state.data.fillCodes = false;
  assert.equal((await state.send({ action: "inline_items", kind: "code" }, page())).status, "disabled");
  assert.equal((await state.send({ action: "inline_items", kind: "nope" }, page())).status, "error");
});

test("addresses: the listing carries each address's values for its row, and only text parts; cards never do", async () => {
  const home = { name: " Alice Smith ", email: "alice@example.com", postalCode: "78701", city: 42, password: "nope", country: "" };
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES }
    : request.action === "query_items" ? { status: "ok", credentials: [{ id: request.kind === "card" ? "c1" : "p1", title: "Home", username: "Alice Smith", selectionToken: "x", preview: home }] }
    : { status: "error" }, { tabUrl: "https://shop.example/" });
  const addresses = await state.send({ action: "inline_items", kind: "profile" }, page());
  assert.equal(JSON.stringify(addresses.items[0].preview), JSON.stringify({ name: "Alice Smith", email: "alice@example.com", postalCode: "78701" }));
  const cards = await state.send({ action: "inline_items", kind: "card" }, page());
  assert.equal(cards.items[0].preview, undefined, "values are passed on for addresses only");
  // A frame's address field names its part; the top page gets it for addresses only.
  const frame = { tab: { id: 1 }, frameId: 4, url: "https://pay.example/address" };
  const rect = { left: 1, top: 2, width: 50, height: 20 };
  await state.send({ action: "frame_field", detail: "profile", role: "postalCode", rect, nonce: "e".repeat(32) }, frame);
  assert.equal(state.sent.at(-1).message.role, "postalCode");
  await state.send({ action: "frame_field", detail: "profile", role: "password", rect, nonce: "e".repeat(32) }, frame);
  assert.equal(state.sent.at(-1).message.role, undefined);
  await state.send({ action: "frame_field", detail: "card", role: "email", rect, nonce: "e".repeat(32) }, frame);
  assert.equal(state.sent.at(-1).message.role, undefined);
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

test("passkey_mark: a login with a passkey for the same account keeps the mark, and only a true value counts", async () => {
  const state = await worker((request) => request.action === "query_credentials" ? { status: "ok", credentials: [
    { id: "a", title: "Example", username: "alice", selectionToken: "t1", passkey: true },
    { id: "b", title: "Example login", username: "bob", selectionToken: "t2", related: true, passkey: "yes" }] } : { status: "ok" });
  const result = await state.send({ action: "inline_query" }, page());
  assert.equal(JSON.stringify(result.accounts), JSON.stringify([
    { id: "a", title: "Example", username: "alice", passkey: true },
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

  assert.equal((await state.send({ action: "frame_field", detail: "card", rect, nonce: "c".repeat(32) }, top)).status, "rejected", "only frames report");
  assert.equal((await state.send({ action: "frame_field", detail: "card", rect, nonce: "c".repeat(32) }, frame(3, "http://pay.example/card"))).status, "rejected");
  assert.equal((await state.send({ action: "frame_field", detail: "card", rect, nonce: "c".repeat(32) }, frame(3))).status, "ok");
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

test("frames: a sign-in frame lists logins for its own site, and the login goes only to that frame", async () => {
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "query_credentials") {
      if (request.all) return { status: "ok", credentials: [{ id: "x", title: "Other", username: "o", selectionToken: "x".repeat(64), site: "other.example" }] };
      return { status: "ok", credentials: request.origin === "https://login.bank.example" ? [{ id: "b1", title: "Bank", username: "me", selectionToken: "b".repeat(64) }] : [] };
    }
    if (request.action === "fill_credential") return { status: "ok", credential: { id: request.credentialId, username: "me", password: "bank-secret" } };
    return { status: "error" };
  }, { tabUrl: "https://bank.example/", frames: [{ frameId: 0, result: "https://bank.example" }, { frameId: 4, result: "https://login.bank.example" }] });
  const frame = { tab: { id: 1 }, frameId: 4, url: "https://login.bank.example/signin" };
  const top = { tab: { id: 1 }, frameId: 0, url: "https://bank.example/" };
  const rect = { left: 4, top: 8, width: 200, height: 30 };

  assert.equal((await state.send({ action: "frame_field", detail: "login", want: "both", rect, nonce: "c".repeat(32) }, frame)).status, "ok");
  const shown = state.sent.at(-1);
  assert.deepEqual([shown.options.frameId, shown.message.action, shown.message.frameId, shown.message.detail, shown.message.host],
    [0, "frame_field", 4, "login", "login.bank.example"]);
  const list = await state.send({ action: "inline_query", frameId: 4 }, top);
  assert.deepEqual(Array.from(list.accounts, (account) => account.id), ["b1"]);
  assert.equal(list.host, "login.bank.example");
  assert.equal(state.requests.filter((request) => request.action === "query_credentials").at(-1).origin, "https://login.bank.example");
  assert.equal((await state.send({ action: "inline_query", frameId: 9 }, top)).status, "missing", "only the frame that reported");
  assert.equal((await state.send({ action: "inline_query", frameId: 4 }, frame)).status, "rejected", "a frame cannot ask for the list");

  state.sent.length = 0;
  const filled = await state.send({ action: "inline_fill_frame", kind: "login", id: "b1", frameId: 4 }, top);
  assert.equal(filled.status, "ok");
  assert.equal(JSON.stringify(filled).includes("bank-secret"), false, "the top page never gets the password");
  assert.deepEqual(state.sent.map((entry) => [entry.options.frameId, entry.message.action, entry.message.username, entry.message.password]),
    [[4, "fill_login", "me", "bank-secret"]]);
  assert.equal(state.requests.find((request) => request.action === "fill_credential").origin, "https://login.bank.example");
  assert.equal((await state.send({ action: "inline_fill_frame", kind: "login", id: "b1", frameId: 4 }, top)).status, "missing", "one report, one fill");

  // Every login, or a login saved for another site, is never listed or filled for a page or frame.
  await state.send({ action: "frame_field", detail: "login", rect, nonce: "c".repeat(32) }, frame);
  assert.equal((await state.send({ action: "inline_all_logins", frameId: 4 }, top)).status, "disabled");
  state.sent.length = 0;
  assert.equal((await state.send({ action: "inline_fill_frame", kind: "login", id: "x", frameId: 4, all: true }, top)).status, "disabled");
  assert.equal(state.sent.length, 0);
  assert.equal(state.requests.some((request) => request.all === true), false, "the vault was never asked for every login");
});

test("frames: the login still fills only while the frame shows the same site", async () => {
  let frameOrigin = "https://login.bank.example";
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "query_credentials") return { status: "ok", credentials: [{ id: "b1", title: "Bank", username: "me", selectionToken: "b".repeat(64) }] };
    if (request.action === "fill_credential") return { status: "ok", credential: { id: "b1", username: "me", password: "bank-secret" } };
    return { status: "error" };
  }, { tabUrl: "https://bank.example/", frames: (details) => [{ frameId: 4, result: frameOrigin }]
    .filter((entry) => !details.target.frameIds || details.target.frameIds.includes(entry.frameId)) });
  const frame = { tab: { id: 1 }, frameId: 4, url: "https://login.bank.example/signin" };
  const top = { tab: { id: 1 }, frameId: 0, url: "https://bank.example/" };
  await state.send({ action: "frame_field", detail: "login", rect: { left: 0, top: 0, width: 10, height: 10 }, nonce: "c".repeat(32) }, frame);
  frameOrigin = "https://evil.example";
  state.sent.length = 0;
  const result = await state.send({ action: "inline_fill_frame", kind: "login", id: "b1", frameId: 4 }, top);
  assert.equal(result.status, "error");
  assert.equal(state.sent.length, 0, "no password is sent anywhere");
});

test("frames: the top page gets the frame's one-time code to find the frame element; a report without one is refused", async () => {
  const state = await worker((request) => request.action === "status" ? { status: "ok", features: ALL_FEATURES } : { status: "ok", credentials: [] }, { tabUrl: "https://shop.example/" });
  const inner = { tab: { id: 1 }, frameId: 6, url: "https://pay.example/login" };
  const rect = { left: 1, top: 2, width: 50, height: 20 };
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect }, inner)).status, "error");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "not-a-code" }, inner)).status, "error");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "d".repeat(32) }, inner)).status, "ok");
  const last = state.sent.at(-1);
  assert.deepEqual([last.options.frameId, last.message.frameId, last.message.nonce], [0, 6, "d".repeat(32)]);
  const list = await state.send({ action: "inline_query", frameId: 6 }, { tab: { id: 1 }, frameId: 0, url: "https://shop.example/" });
  assert.deepEqual([list.status, list.host], ["ok", "pay.example"]);
});

test("frames: a frame the page built without an address counts as the page's site; other frames without one never do", async () => {
  const state = await worker(() => ({ status: "ok", features: ALL_FEATURES }), { tabUrl: "https://shop.example/" });
  const rect = { left: 0, top: 0, width: 10, height: 10 };
  const blank = (origin) => ({ tab: { id: 1 }, frameId: 3, url: "about:blank", origin });
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "c".repeat(32) }, blank("https://shop.example"))).status, "ok");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "c".repeat(32) }, blank("null"))).status, "rejected");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "c".repeat(32) }, blank("http://shop.example"))).status, "rejected");
  assert.equal((await state.send({ action: "frame_field", detail: "login", rect, nonce: "c".repeat(32) }, { tab: { id: 1 }, frameId: 3, url: "data:text/html,x", origin: "null" })).status, "rejected");
});

test("frames: a login submitted in a frame is saved for the frame's site, and its card shows on the top page", async () => {
  const state = await worker((request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "seal_login") return { status: "sealed", sealedLogin: "protected-login" };
    if (request.action === "review_login") return { status: "needs_save" };
    return { status: "ok" };
  }, { tabUrl: "https://www.seedr.cc/" });
  const frame = { tab: { id: 1 }, frameId: 2, url: "https://www.seedr.cc/api/v0.1/auth/pages/login" };
  const top = { tab: { id: 1 }, frameId: 0, url: "https://www.seedr.cc/" };
  const captured = await state.send({ action: "capture_submitted_login", username: "me@example.com", password: "synthetic-secret" }, frame);
  assert.equal(captured.status, "shown");
  const card = state.sent.at(-1);
  assert.deepEqual([card.options.frameId, card.message.action, card.message.prompt.kind, card.message.prompt.host], [0, "show_prompt", "save", "www.seedr.cc"]);
  assert.equal(state.requests.find((request) => request.action === "seal_login").origin, "https://www.seedr.cc");
  // The top page (also after it moves to another page of the site) can answer it.
  const pending = await state.send({ action: "inline_pending" }, top);
  assert.equal(pending.status, "ok");
});

test("search all logins: refused to pages on every browser; nothing reaches the vault", async () => {
  const host = (request) => {
    if (request.action === "status") return { status: "ok", features: ALL_FEATURES };
    if (request.action === "query_credentials") return request.all
      ? { status: "ok", credentials: [{ id: "s", title: "Seedr", username: "me@example.com", selectionToken: "s".repeat(64), site: "seedr.cc" }] }
      : { status: "ok", credentials: [] };
    if (request.action === "fill_credential") return { status: "ok", credential: { id: "s", username: "me@example.com", password: "seedr-secret" } };
    return { status: "error" };
  };
  for (const extensionUrl of ["chrome-extension://kapellkbongejlglcengbmjnpblemmjm/", FIREFOX_URL, undefined]) {
    const state = await worker(host, { tabUrl: "https://example.com/login", extensionUrl });
    const top = page("https://example.com/login");
    const every = await state.send({ action: "inline_all_logins" }, top);
    assert.equal(every.status, "disabled", extensionUrl);
    assert.equal(every.accounts, undefined);
    const filled = await state.send({ action: "inline_fill_any", id: "s", want: "both" }, top);
    assert.equal(filled.status, "disabled");
    assert.equal(JSON.stringify(filled).includes("seedr-secret"), false);
    // The site's own fill can't be used to pull a login saved for another site either.
    assert.equal((await state.send({ action: "inline_fill", credentialId: "s", want: "both" }, top)).status, "missing");
    assert.equal(state.requests.some((request) => request.all === true || request.action === "fill_credential"), false);
  }
});

// ---------------------------------------------------------------------------
// Firefox (moz-extension): no IntersectionObserver v2, so data not tied to the page's site is
// refused to the page and offered in the popup instead.

const FIREFOX_URL = "moz-extension://4b6c3a1e-0000-4000-8000-000000000001/";
const cardHost = (request) => request.action === "status" ? { status: "ok", features: ["cards", "profiles", "codes", "all_logins", "status_no_origin"] }
  : request.action === "query_items" ? { status: "ok", credentials: [{ id: "visa", title: "Everyday", username: "Visa · •••• 1111", selectionToken: "t1" }] }
  : request.action === "fill_item" ? { status: "ok", item: { id: "visa", kind: "card", card: { number: "4111111111111111", name: "Alex", expiry: "12/29", network: "Visa" } } }
  : { status: "ok", credentials: [] };

test("Firefox: the page can't list cards, addresses, every code or every login", async () => {
  const state = await worker(cardHost, { extensionUrl: FIREFOX_URL, tabUrl: "https://shop.example/pay" });
  for (const message of [{ action: "inline_items", kind: "card" }, { action: "inline_items", kind: "profile" }, { action: "inline_items", kind: "code", all: true },
    { action: "inline_all_logins" }, { action: "inline_fill_any", id: "x", want: "both" }, { action: "inline_fill_frame", kind: "card", id: "visa", frameId: 3 }]) {
    assert.equal((await state.send(message, page("https://shop.example/pay"))).status, "disabled", JSON.stringify(message));
  }
  assert.equal(state.requests.some((request) => ["query_items", "fill_item"].includes(request.action) || request.all === true), false, "nothing reached the vault");
});

test("Chrome keeps every in-page list", async () => {
  const state = await worker(cardHost, { extensionUrl: "chrome-extension://kapellkbongejlglcengbmjnpblemmjm/", tabUrl: "https://shop.example/pay" });
  assert.notEqual((await state.send({ action: "inline_items", kind: "card" }, page("https://shop.example/pay"))).status, "disabled");
});

test("popup cards: listed for the tab, filled into the page's form, and only for the extension's own page", async () => {
  const state = await worker(cardHost, { extensionUrl: FIREFOX_URL, tabUrl: "https://shop.example/pay",
    frameReply: (message) => message.action === "popup_forms" ? { card: true, profile: false } : { status: "ok", filled: 3, codeAsked: false } });
  const popup = { url: FIREFOX_URL + "popup.html" };
  assert.equal((await state.send({ action: "popup_items", tabId: 7, kind: "card" }, page("https://shop.example/pay"))).status, "rejected", "a page can't use the popup's actions");
  const forms = await state.send({ action: "popup_forms", tabId: 7 }, popup);
  assert.equal(JSON.stringify(forms), JSON.stringify({ card: true, profile: false }));
  const listed = await state.send({ action: "popup_items", tabId: 7, kind: "card" }, popup);
  assert.equal(listed.status, "ok");
  assert.equal(JSON.stringify(listed.items.map((item) => [item.id, item.title])), JSON.stringify([["visa", "Everyday"]]));
  assert.equal(JSON.stringify(listed).includes("t1"), false, "tokens stay in the background");
  const filled = await state.send({ action: "popup_fill_item", tabId: 7, kind: "card", id: "visa" }, popup);
  assert.equal(filled.status, "ok");
  const delivered = state.sent.find((entry) => entry.message.action === "popup_fill");
  assert.equal(delivered.options.frameId, 0, "the card goes to the top page only");
  assert.equal(delivered.message.card.number, "4111111111111111");
});
