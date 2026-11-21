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

const PNG_BYTES = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3]);

/** Loads background.js with fake chrome.* and fake image APIs. Returns the sandbox so tests can call its functions. */
function load({ reply, tab = {}, fetchReply } = {}) {
  const session = {};
  const requests = [];
  const fetches = [];
  const drawn = [];
  let updated;
  const chrome = {
    storage: { local: area({}), session: area(session) },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {}, setTitle: async () => {}, openPopup: async () => {} },
    scripting: { executeScript: async () => [] },
    tabs: {
      get: async (id) => ({ id, url: "https://example.com/page", favIconUrl: "https://example.com/favicon.png", ...tab }),
      query: async () => [],
      onActivated: { addListener() {} }, onUpdated: { addListener: (callback) => { updated = callback; } }, onRemoved: { addListener() {} },
    },
    alarms: { create: async () => {}, onAlarm: { addListener() {} } },
    runtime: {
      onMessage: { addListener() {} },
      onStartup: { addListener() {} },
      sendNativeMessage: async (_host, request) => { requests.push(request); return reply(request); },
    },
  };
  const sandbox = {
    chrome, URL, setTimeout, clearTimeout, crypto: { randomUUID: () => `id-${requests.length + 1}` },
    AbortController, Blob, btoa,
    fetch: async (url, options) => { fetches.push({ url, options }); return fetchReply ? fetchReply(url) : imageResponse(); },
    createImageBitmap: async () => ({ width: 32, height: 16, close() {} }),
    OffscreenCanvas: class {
      getContext() { return { drawImage: (...args) => drawn.push(args), imageSmoothingQuality: "" }; }
      async convertToBlob(options) { assert.equal(options.type, "image/png"); return new Blob([PNG_BYTES], { type: "image/png" }); }
    },
  };
  vm.runInNewContext(source, sandbox);
  const visit = async (url = "https://example.com/page") => {
    updated(1, { status: "complete" }, { url });
    for (let i = 0; i < 30; i++) await new Promise(setImmediate);
  };
  return { sandbox, requests, fetches, drawn, visit, session };
}

function imageResponse({ type = "image/png", size = 100, length, url = "https://example.com/favicon.png" } = {}) {
  const body = new Uint8Array(size);
  return {
    ok: true, url,
    headers: { get: (name) => name === "content-type" ? type : name === "content-length" ? (length ?? null) : null },
    body: { getReader: () => { let sent = false; return { read: async () => sent ? { done: true } : (sent = true, { done: false, value: body }), cancel: async () => {} }; } },
  };
}

const wanted = (request) => request.action === "query_credentials" ? { status: "ok", credentials: [], iconWanted: true } : { status: "ok" };

test("favicon URLs: https and data:image are accepted, everything else is rejected", () => {
  const { sandbox } = load({ reply: wanted });
  const kind = sandbox.iconSourceKind;
  assert.equal(kind("https://example.com/favicon.ico"), "https");
  assert.equal(kind("data:image/png;base64,AAAA"), "data");
  for (const bad of ["http://example.com/a.png", "javascript:alert(1)", "blob:https://example.com/x", "file:///c:/a.png",
    "chrome://favicon/x", "chrome-extension://abc/a.png", "data:text/html,<b>", "data:text/plain;base64,AAAA", "", "not a url", undefined, null, 5]) {
    assert.equal(kind(bad), "", String(bad));
  }
});

test("contain scaling keeps the aspect ratio and centers the image", () => {
  const { sandbox } = load({ reply: wanted });
  assert.deepEqual({ ...sandbox.containRect(32, 16) }, { x: 0, y: 16, w: 64, h: 32 });
  assert.deepEqual({ ...sandbox.containRect(16, 32) }, { x: 16, y: 0, w: 32, h: 64 });
  assert.deepEqual({ ...sandbox.containRect(64, 64) }, { x: 0, y: 0, w: 64, h: 64 });
  assert.deepEqual({ ...sandbox.containRect(256, 128) }, { x: 0, y: 16, w: 64, h: 32 });
  assert.equal(sandbox.containRect(0, 10), null);
});

test("size and type checks", () => {
  const { sandbox } = load({ reply: wanted });
  const ok = sandbox.iconBlobAcceptable;
  assert.equal(ok("image/png", 1000), true);
  assert.equal(ok("image/x-icon; charset=binary", 1000), true);
  assert.equal(ok("application/octet-stream", 1000), true);
  assert.equal(ok("text/html", 1000), false);
  assert.equal(ok("image/png", 256 * 1024), true);
  assert.equal(ok("image/png", 256 * 1024 + 1), false);
  assert.equal(ok("image/png", 0), false);
});

test("throttle: one attempt per host per 6 hours", async () => {
  const { sandbox } = load({ reply: wanted });
  const t0 = 1_700_000_000_000;
  const hour = 3600_000;
  assert.equal(await sandbox.claimIconAttempt("a.example.com", t0), true);
  assert.equal(await sandbox.claimIconAttempt("a.example.com", t0 + 1000), false);
  assert.equal(await sandbox.claimIconAttempt("b.example.com", t0 + 1000), true, "another host is independent");
  assert.equal(await sandbox.claimIconAttempt("a.example.com", t0 + 6 * hour - 1), false);
  assert.equal(await sandbox.claimIconAttempt("a.example.com", t0 + 6 * hour), true);
});

test("nothing is sent and nothing is fetched when the app does not ask for an icon", async () => {
  const absent = load({ reply: () => ({ status: "ok", credentials: [] }) });
  await absent.visit();
  assert.equal(absent.requests.some((r) => r.action === "query_credentials"), true);
  assert.equal(absent.requests.some((r) => r.action === "save_site_icon"), false);
  assert.equal(absent.fetches.length, 0);
  const falsy = load({ reply: () => ({ status: "ok", credentials: [], iconWanted: false }) });
  await falsy.visit();
  assert.equal(falsy.fetches.length, 0);
});

test("when wanted, the extension sends exactly action, origin and a 64x64 PNG icon", async () => {
  const state = load({ reply: wanted });
  await state.visit();
  const save = state.requests.filter((r) => r.action === "save_site_icon");
  assert.equal(save.length, 1);
  assert.deepEqual(Object.keys(save[0]).sort(), ["action", "icon", "origin", "requestId", "version"]);
  assert.equal(save[0].origin, "https://example.com");
  assert.equal(save[0].version, 2);
  assert.deepEqual([...Buffer.from(save[0].icon, "base64")], [...PNG_BYTES], "the re-encoded PNG, not the fetched bytes");
  assert.deepEqual(state.drawn[0].slice(1), [0, 16, 64, 32], "32x16 is drawn contained into 64x64");
  const { options } = state.fetches[0];
  assert.equal(options.credentials, "omit");
  assert.equal(options.referrerPolicy, "no-referrer");
  assert.equal(options.redirect, "follow");
  assert.ok(options.signal);
});

test("a second page view of the same host within 6 hours does not fetch again", async () => {
  const state = load({ reply: wanted });
  await state.visit();
  await state.visit();
  assert.equal(state.fetches.length, 1);
  assert.equal(state.requests.filter((r) => r.action === "save_site_icon").length, 1);
});

test("no capture for incognito tabs, http or data:text favicons, oversized or non-image responses", async () => {
  const cases = [
    { tab: { incognito: true } },
    { tab: { favIconUrl: "http://example.com/favicon.png" } },
    { tab: { favIconUrl: "data:text/html,hi" } },
    { tab: { favIconUrl: undefined } },
    { tab: { url: "https://other.example.org/" } },
    { fetchReply: () => imageResponse({ length: "300000" }) },
    { fetchReply: () => imageResponse({ size: 300000 }) },
    { fetchReply: () => imageResponse({ type: "text/html" }) },
    { fetchReply: () => imageResponse({ url: "http://example.com/favicon.png" }) },
    { fetchReply: () => { throw new Error("network"); } },
  ];
  for (const options of cases) {
    const state = load({ reply: wanted, ...options });
    await state.visit();
    assert.equal(state.requests.some((r) => r.action === "save_site_icon"), false, JSON.stringify(options));
  }
});
