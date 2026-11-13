import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(fileURLToPath(new URL("./popup.js", import.meta.url)), "utf8");

class FakeElement {
  constructor(name, events) {
    this.name = name;
    this.events = events;
    this.dataset = {};
    this.attributes = {};
    this.children = [];
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.type = "";
    this.checked = false;
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  addEventListener(type, callback) { this.events[`${this.name}:${type}`] = callback; (this.own ||= {})[type] = callback; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  querySelectorAll(selector) {
    const found = [];
    const walk = (node) => { for (const child of node.children || []) { if (selector === "button" && child.tag === "button") found.push(child); walk(child); } };
    walk(this);
    return found;
  }
  allText() { return [this.textContent, ...this.children.map((child) => child.allText?.() ?? "")].join(" "); }
}

async function popup(frameResults, hostReply, url = "https://www.seedr.cc/", { local = {}, session = {}, messageReply = () => undefined, chromeExtra = {}, navigatorExtra = {} } = {}) {
  const timers = [];
  const events = {};
  const requests = [];
  const injections = [];
  const messages = [];
  const clipboard = [];
  const elements = {};
  const element = (selector) => (elements[selector] ||= new FakeElement(selector, events));
  element("#review-password").type = "password";
  const tabs = ["site", "pending", "settings"].map((view) => { const tab = element(`[data-view=${view}]`); tab.dataset.view = view; return tab; });
  const context = vm.createContext({
    URL,
    Date,
    setTimeout: (callback, delay) => { timers.push({ callback, delay }); return timers.length; },
    clearTimeout() {},
    confirm: () => true,
    crypto: { randomUUID: () => "test-request" },
    navigator: { clipboard: { writeText: async (text) => { clipboard.push(text); } }, ...navigatorExtra },
    document: {
      querySelector: element,
      querySelectorAll: (selector) => selector === "[data-view]" ? tabs : [],
      createElement: (tag) => { const node = new FakeElement(`<${tag}>`, {}); node.tag = tag; return node; },
    },
    chrome: {
      tabs: { query: async () => [{ id: 1, url }] },
      runtime: {
        id: "abcdefghijklmnopabcdefghijklmnop",
        sendNativeMessage: async (_name, request) => {
          requests.push(request);
          return hostReply(request, requests.length);
        },
        sendMessage: async (message) => { messages.push(message); return messageReply(message) ?? { pending: 0, items: [] }; },
      },
      storage: {
        local: { get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((key) => key in local).map((key) => [key, local[key]])), set: async (value) => Object.assign(local, value) },
        session: { get: async (key) => ({ [key]: session[key] }), set: async (value) => Object.assign(session, value) },
        onChanged: { addListener() {} },
      },
      ...chromeExtra,
      scripting: { executeScript: async (injection) => {
        injections.push(injection);
        return injections.length === 1 ? frameResults : [{ result: { filled: true } }];
      } },
    },
  });
  vm.runInContext(source, context);
  await new Promise(setImmediate);
  return { context, elements, requests, injections, timers, events, messages, clipboard, local, session };
}

const button = (row, label) => {
  const found = [];
  const walk = (node) => { for (const child of node.children || []) { if (child.tag === "button") found.push(child); walk(child); } };
  walk(row);
  return found.find((node) => node.attributes["aria-label"] === label || node.textContent === label);
};

test("an expired selection refreshes only the chosen account and fills one frame", async () => {
  const state = await popup(
    [{ frameId: 2, documentId: "login-document", result: { fillable: true } },
      { frameId: 3, result: { filled: false } }],
    (request, number) => number === 1 ? { status: "ok", credentials: [] }
      : number === 2 ? { status: "selection_expired" }
      : number === 3 ? { status: "ok", credentials: [
        { id: "chosen", selectionToken: "fresh" }, { id: "other", selectionToken: "unused" },
      ] } : { status: "ok", credential: { id: "chosen", username: "alice", password: "secret" } },
  );
  await state.context.fillSelected({ id: "chosen", selectionToken: "expired" });
  assert.deepEqual(state.requests.map((request) => request.action),
    ["query_credentials", "fill_credential", "query_credentials", "fill_credential"]);
  assert.equal(state.requests[3].credentialId, "chosen");
  assert.equal(state.requests[3].selectionToken, "fresh");
  assert.equal(state.injections[1].target.tabId, 1);
  assert.equal(state.injections[1].target.documentIds[0], "login-document");
  assert.equal(state.injections[1].target.documentIds.length, 1);
  assert.equal(state.injections[0].args[0], null);
  assert.equal(state.injections[1].args[0].password, "secret");
  assert.match(state.elements["#message"].textContent, /Filled the selected account/);
});

test("no visible form does not request a password", async () => {
  const state = await popup([{ frameId: 0, result: { filled: false } }],
    () => ({ status: "ok", credentials: [] }));
  await state.context.fillSelected({ id: "chosen", selectionToken: "token" });
  assert.deepEqual(state.requests.map((request) => request.action), ["query_credentials"]);
  assert.match(state.elements["#message"].textContent, /No supported sign-in form/);
});

test("a login iframe is usable only when it is in front", async () => {
  const state = await popup([], () => ({ status: "ok" }));
  const top = {};
  top.top = top;
  const frame = {
    ownerDocument: { defaultView: { getComputedStyle: () => ({ visibility: "visible" }) }, elementFromPoint: () => frame },
    getBoundingClientRect: () => ({ x: 10, y: 10, width: 200, height: 100 }),
  };
  const password = {
    type: "password", disabled: false, readOnly: false,
    getBoundingClientRect: () => ({ x: 20, y: 20, width: 100, height: 30 }),
    getRootNode: () => ({ elementFromPoint: () => password }),
  };
  state.context.window = { top, parent: top, frameElement: frame };
  state.context.location = { origin: "https://www.seedr.cc" };
  state.context.getComputedStyle = () => ({ display: "block", visibility: "visible" });
  state.context.document.querySelectorAll = (selector) => selector === "input" ? [password] : [];
  assert.equal(state.context.fillLoginForm(null, "https://www.seedr.cc").fillable, true);
  frame.ownerDocument.elementFromPoint = () => ({ id: "covering-dialog" });
  assert.equal(state.context.fillLoginForm(null, "https://www.seedr.cc").fillable, undefined);
});

test("a locked vault retries queries after unlock without automatically filling", async () => {
  let locked = true;
  const state = await popup([], () => locked ? { status: "locked" } : { status: "ok", credentials: [] });
  assert.equal(state.elements["#connection"].dataset.state, "locked");
  assert.equal(state.elements["#connection-text"].textContent, "Locked");
  assert.equal(state.timers[0].delay, 2000);
  locked = false;
  await state.timers[0].callback();
  assert.equal(state.elements["#connection"].dataset.state, "ready");
  assert.equal(state.elements["#connection-text"].textContent, "Connected · Unlocked");
  assert.deepEqual(state.requests.map(request => request.action), ["query_credentials", "query_credentials"]);
  assert.equal(state.injections.length, 0);
  assert.equal(state.elements["#accounts-empty"].hidden, false);
});

test("missing native host gives setup guidance and bounded retry delays", async () => {
  const state = await popup([], () => { throw new Error("Specified native messaging host not found."); });
  assert.equal(state.elements["#connection"].dataset.state, "offline");
  assert.equal(state.elements["#connection-text"].textContent, "Not connected");
  assert.equal(state.elements["#setup"].hidden, false);
  assert.match(state.elements["#setup-lead"].textContent, /native host/);
  assert.equal(state.elements["#ext-id"].textContent, "abcdefghijklmnopabcdefghijklmnop");
  assert.match(state.elements["#message"].textContent, /Register the Nuvori native host/);
  for (let index = 0; index < 5; index++) await state.timers[index].callback();
  assert.deepEqual(state.timers.map(timer => timer.delay), [2000, 4000, 8000, 15000, 15000, 15000]);
  const logged = state.messages.filter((entry) => entry.action === "log_event");
  assert.ok(logged.length > 0);
  assert.equal(logged[0].event.status, "host_missing");
});

test("capture starts hidden and cancel clears both the password and capture", async () => {
  const state = await popup([{ result: { username: "synthetic-user", password: "synthetic-password" } }], () => ({ status: "ok", credentials: [] }));
  await state.events["#capture:click"]();
  assert.equal(state.elements["#review-password"].type, "password");
  assert.equal(state.elements["#review-password"].value, "synthetic-password");
  state.events["#show-password:click"]();
  assert.equal(state.elements["#review-password"].type, "text");
  assert.equal(state.elements["#show-password"].attributes["aria-pressed"], "true");
  state.events["#cancel-save:click"]();
  assert.equal(state.elements["#review-password"].value, "");
  assert.equal(state.elements["#review-password"].type, "password");
  assert.equal(state.elements["#save-review"].hidden, true);
  await state.events["#save:click"]();
  assert.deepEqual(state.requests.map(request => request.action), ["query_credentials"]);
});

test("HTTP pages disable capture and never request credentials, but still show the connection", async () => {
  const state = await popup([], () => { throw new Error("Must not call the host"); }, "http://example.com/",
    { messageReply: (message) => message.action === "connection_status" ? { status: "locked", features: [] } : undefined });
  assert.equal(state.elements["#capture"].disabled, true);
  assert.equal(state.elements["#find"].disabled, true);
  assert.equal(state.requests.length, 0, "the background pings status; the popup asks for nothing");
  assert.ok(state.messages.some((message) => message.action === "connection_status"));
  assert.equal(state.elements["#connection"].dataset.state, "locked");
  assert.equal(state.elements["#site"].textContent, "Not a secure site");
});

test("Test connection reports a missing host with setup steps", async () => {
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { messageReply: (message) => message.action === "connection_status" ? { status: "host_missing", features: [] } : undefined });
  await state.events["#test-connection:click"]();
  assert.equal(state.elements["#connection"].dataset.state, "offline");
  assert.equal(state.elements["#setup"].hidden, false);
  assert.match(state.elements["#setup-lead"].textContent, /native host/);
});

const ALL = ["status_no_origin", "login_title", "password_only", "multi_update"];

test("the manual save sends a name and allows no username only when the host supports it", async () => {
  for (const features of [[], ALL]) {
    const state = await popup([{ result: { username: "", password: "synthetic-password" } }],
      (request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "sealed" } : { status: "ok", credentials: [] },
      "https://www.seedr.cc/", { messageReply: (message) => message.action === "host_features" ? { features } : message.action === "queue_login" ? { status: "saved" } : undefined });
    await state.events["#capture:click"]();
    assert.equal(state.injections[0].args[1], features.includes("password_only"));
    assert.equal(state.elements["#save-name-row"].hidden, !features.includes("login_title"));
    assert.equal(state.elements["#save-name"].value, "seedr.cc");
    state.elements["#save-name"].value = "Seedr\tmedia";
    await state.events["#save:click"]();
    const seal = state.requests.find((request) => request.action === "seal_login");
    if (features.length) {
      assert.equal(seal.title, "Seedr media");
      assert.equal(seal.username, "");
      assert.match(state.elements["#save-summary"].textContent, /no username/);
    } else {
      assert.equal("title" in seal, false, "older hosts never see a title");
    }
  }
});

test("several saved accounts: the Pending view needs a pick before Update", async () => {
  const items = [{ id: "multi", origin: "https://example.com", state: "review", canUpdate: true,
    choices: [{ id: "a", title: "Personal", username: "u" }, { id: "b", title: "Work", username: "u" }] }];
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { messageReply: (message) => message.action === "pending_status" ? { pending: 1, items } : message.action === "update_pending" ? { status: "saved" } : undefined });
  const [row] = state.elements["#pending"].children;
  const picker = row.children.find((child) => child.className === "choice-list");
  assert.equal(picker.children.length, 2);
  assert.match(picker.children[1].allText(), /Work/);
  const update = row.children.find((child) => child.className === "actions").children.find((child) => child.textContent === "Update");
  assert.equal(update.disabled, true);
  await update.own.click();
  assert.equal(state.messages.some((message) => message.action === "update_pending"), false);
  const radio = picker.children[1].children[0];
  radio.checked = true;
  radio.own.change();
  assert.equal(update.disabled, false);
  await update.own.click();
  const sent = state.messages.find((message) => message.action === "update_pending");
  assert.equal(sent.credentialId, "b");
  assert.equal(JSON.stringify(sent).includes("selectionToken"), false);
});

test("account rows offer Fill and copy actions; copying a password uses a one-use release", async () => {
  const state = await popup([], (request) => request.action === "query_credentials"
    ? { status: "ok", credentials: [{ id: "a", title: "Work", username: "alice", selectionToken: "token-1" }] }
    : { status: "ok", credential: { id: "a", username: "alice", password: "synthetic-secret" } });
  const [row] = state.elements["#choices"].children;
  assert.match(row.allText(), /Work/);
  assert.match(row.allText(), /alice/);
  assert.ok(button(row, "Fill"));
  await button(row, "Copy username").own.click();
  assert.deepEqual(state.clipboard, ["alice"]);
  await button(row, "Copy password").own.click();
  assert.deepEqual(state.clipboard, ["alice", "synthetic-secret"]);
  const fill = state.requests.find((request) => request.action === "fill_credential");
  assert.equal(fill.selectionToken, "token-1");
  assert.equal(fill.origin, "https://www.seedr.cc");
  assert.ok(state.messages.some((entry) => entry.action === "clipboard_clear_later"));
  assert.equal(state.elements["#message"].textContent, "Password copied.");
  assert.equal(JSON.stringify(state.messages).includes("synthetic-secret"), false, "the password never reaches extension messages");
  assert.equal(JSON.stringify(state.messages.filter((entry) => entry.action === "log_event")).includes("alice"), false);
});

test("settings toggle inline suggestions and manage site lists", async () => {
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { local: { inlineSuggestions: true, neverSave: ["https://a.example", "https://b.example"], noSuggest: [] } });
  assert.equal(state.elements["#inline-toggle"].checked, true);
  assert.equal(state.elements["#never-list"].children.length, 2);
  assert.equal(state.elements["#never-empty"].hidden, true);
  assert.equal(state.elements["#nosuggest-empty"].hidden, false);
  state.elements["#inline-toggle"].checked = false;
  state.events["#inline-toggle:change"]();
  assert.equal(state.local.inlineSuggestions, false);
  await button(state.elements["#never-list"].children[0], "Remove").own.click();
  await new Promise(setImmediate);
  assert.deepEqual(state.local.neverSave, ["https://b.example"]);
});

test("diagnostics show action, status, host and time only", async () => {
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { session: { diagnostics: [{ at: 1, action: "fill_credential", status: "ok", host: "example.com" }, { at: 2, action: "query_credentials", status: "locked", host: "example.com" }] } });
  state.events["[data-view=settings]:click"]();
  await new Promise(setImmediate);
  const rows = state.elements["#diag-list"].children;
  assert.equal(rows.length, 2);
  assert.match(rows[0].allText(), /Release login · example\.com/);
  assert.equal(rows[1].children[2].dataset.tone, "warning");
  assert.equal(state.elements["[data-view=settings]"].attributes["aria-selected"], "true");
  assert.equal(state.elements["#view-site"].hidden, true);
});

// --- Security review regressions ----------------------------------------------

test("L4: the popup's manual-save name drops format characters such as bidi overrides", async () => {
  const state = await popup([{ result: { username: "u", password: "synthetic-password" } }],
    (request) => request.action === "seal_login" ? { status: "sealed", sealedLogin: "sealed" } : { status: "ok", credentials: [] },
    "https://www.seedr.cc/", { messageReply: (message) => message.action === "host_features" ? { features: ["login_title"] } : message.action === "queue_login" ? { status: "saved" } : undefined });
  await state.events["#capture:click"]();
  state.elements["#save-name"].value = "Seedr‮​ Media\u0007";
  await state.events["#save:click"]();
  assert.equal(state.requests.find((request) => request.action === "seal_login").title, "Seedr Media");
});

test("M2: Update while locked tells the user it was kept for later", async () => {
  const items = [{ id: "one", origin: "https://example.com", state: "review", canUpdate: true, choices: [{ id: "a", title: "T", username: "u" }] }];
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { messageReply: (message) => message.action === "pending_status" ? { pending: 1, items } : message.action === "update_pending" ? { status: "queued_update" } : undefined });
  const [row] = state.elements["#pending"].children;
  await row.children.find((child) => child.className === "actions").children.find((child) => child.textContent === "Update").own.click();
  assert.match(state.elements["#message"].textContent, /Saved for later/);
});

test("without activeTab, a tab whose URL is hidden is treated as not secure and never queried", async () => {
  const state = await popup([], () => { throw new Error("Must not query"); }, null,
    { messageReply: (message) => message.action === "connection_status" ? { status: "ok", features: [] } : undefined });
  assert.equal(state.requests.length, 0);
  assert.equal(state.elements["#site"].textContent, "Not a secure site");
  assert.match(state.elements["#message"].textContent, /secure website/);
});

test("manifest: least privilege, HTTPS-only hosts, no activeTab", () => {
  const manifest = JSON.parse(readFileSync(fileURLToPath(new URL("./manifest.json", import.meta.url)), "utf8"));
  assert.equal(manifest.version, "0.7.2");
  // The Chrome Web Store needs a 128 px icon in the package; every listed icon must exist.
  assert.equal(manifest.icons["128"], "icons/icon-128.png");
  for (const path of [...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon)]) {
    assert.ok(existsSync(fileURLToPath(new URL(`./${path}`, import.meta.url))), `${path} exists`);
  }
  assert.match(manifest.key, /^[A-Za-z0-9+/]+=*$/, "a public key fixes the extension ID in every folder");
  assert.deepEqual(manifest.host_permissions, ["https://*/*"]);
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "clipboardWrite", "nativeMessaging", "offscreen", "scripting", "storage"]);
  assert.deepEqual(manifest.optional_permissions, ["privacy"], "privacy is asked for only when the user turns the switch on");
  assert.equal(manifest.minimum_chrome_version, "127");
  assert.deepEqual(manifest.content_scripts[0].matches, ["https://*/*"]);
  // Frames get the script for card, address and code forms; no permission was added for it.
  assert.equal(manifest.content_scripts[0].all_frames, true);
  assert.equal(manifest.content_scripts[0].match_about_blank, undefined);
});

// --- Browser password manager (chrome.privacy) -------------------------------

const PRIVACY_NAMES = ["passwordSavingEnabled", "autofillAddressEnabled", "autofillCreditCardEnabled"];

function browserMocks({ answer = true, granted = false, levels = {} } = {}) {
  const calls = [];
  const values = {};
  const permissions = {
    granted,
    requests: 0,
    removed: 0,
    contains: async () => permissions.granted,
    request: async ({ permissions: list }) => { permissions.requests++; calls.push(["request", ...list]); permissions.granted = answer; return answer; },
    remove: async () => { permissions.removed++; return true; },
  };
  const setting = (name) => ({
    get: async () => name in values
      ? { value: values[name], levelOfControl: "controlled_by_this_extension" }
      : { value: true, levelOfControl: levels[name] || "controllable_by_this_extension" },
    set: async ({ value }) => { calls.push(["set", name, value]); values[name] = value; },
    clear: async () => { calls.push(["clear", name]); delete values[name]; },
  });
  const privacy = { services: Object.fromEntries(PRIVACY_NAMES.map((name) => [name, setting(name)])) };
  return { calls, values, permissions, chromeExtra: { permissions, privacy } };
}

const settle = () => new Promise(setImmediate);

test("turning on 'Use Nuvori' asks for the privacy permission from the click and turns off browser saving", async () => {
  const mocks = browserMocks();
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/", { chromeExtra: mocks.chromeExtra });
  assert.equal(state.elements["#browser-saving-toggle"].checked, false, "off by default");
  assert.equal(state.elements["#browser-chip"].hidden, true);
  state.elements["#browser-saving-toggle"].checked = true;
  await state.events["#browser-saving-toggle:change"]();
  assert.equal(mocks.permissions.requests, 1);
  assert.deepEqual(mocks.calls.filter((call) => call[0] !== "request"), [["set", "passwordSavingEnabled", false]]);
  assert.equal(state.elements["#browser-saving-toggle"].checked, true);
  assert.equal(state.elements["#browser-chip"].hidden, false);
  assert.equal(state.elements["#browser-autofill-toggle"].disabled, false);
  const logged = state.messages.filter((message) => message.action === "log_event").map((message) => message.event);
  assert.ok(logged.some((event) => event.action === "browser_saving_on" && event.status === "ok"));
});

test("a refused permission changes nothing", async () => {
  const mocks = browserMocks({ answer: false });
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/", { chromeExtra: mocks.chromeExtra });
  state.elements["#browser-saving-toggle"].checked = true;
  await state.events["#browser-saving-toggle:change"]();
  assert.equal(mocks.calls.some((call) => call[0] === "set"), false);
  assert.equal(state.elements["#browser-saving-toggle"].checked, false);
  assert.match(state.elements["#browser-pm-note"].textContent, /needs permission/);
});

test("settings controlled by policy or another extension are reported, never claimed", async () => {
  for (const [level, text] of [["not_controllable", /organization controls/], ["controlled_by_other_extensions", /Another extension controls/]]) {
    const mocks = browserMocks({ levels: { passwordSavingEnabled: level } });
    const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/", { chromeExtra: mocks.chromeExtra });
    state.elements["#browser-saving-toggle"].checked = true;
    await state.events["#browser-saving-toggle:change"]();
    assert.equal(mocks.calls.some((call) => call[0] === "set"), false, level);
    assert.equal(state.elements["#browser-saving-toggle"].checked, false);
    assert.equal(state.elements["#browser-saving-toggle"].disabled, true);
    assert.match(state.elements["#browser-pm-note"].textContent, text);
    assert.equal(state.elements["#browser-pm-note"].hidden, false);
    assert.equal(state.elements["#browser-chip"].hidden, true);
    assert.doesNotMatch(state.elements["#message"].textContent, /won't offer/);
    const event = state.messages.filter((message) => message.action === "log_event").at(-1).event;
    assert.deepEqual({ ...event }, { action: "browser_saving_on", status: level, origin: "" });
  }
});

test("address and card autofill follow the second switch, and turning everything off clears our values", async () => {
  const mocks = browserMocks({ granted: true });
  mocks.values.passwordSavingEnabled = false; // already ours from an earlier session
  const state = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/", { chromeExtra: mocks.chromeExtra });
  await settle();
  assert.equal(state.elements["#browser-saving-toggle"].checked, true, "the switch reflects the real browser state");
  assert.equal(state.elements["#browser-chip"].hidden, false);
  state.elements["#browser-autofill-toggle"].checked = true;
  await state.events["#browser-autofill-toggle:change"]();
  assert.deepEqual(mocks.calls.filter((call) => call[0] === "set").map((call) => call[1]), ["autofillAddressEnabled", "autofillCreditCardEnabled"]);
  assert.equal(state.elements["#browser-autofill-toggle"].checked, true);
  state.elements["#browser-saving-toggle"].checked = false;
  await state.events["#browser-saving-toggle:change"]();
  assert.deepEqual(mocks.calls.filter((call) => call[0] === "clear").map((call) => call[1]).sort(), [...PRIVACY_NAMES].sort());
  assert.equal(mocks.permissions.removed, 0, "the permission stays so the switch can be turned on again without a prompt");
  assert.equal(mocks.permissions.requests, 0);
  assert.equal(state.elements["#browser-chip"].hidden, true);
  assert.equal(state.elements["#browser-autofill-toggle"].disabled, true);
});

test("the password-export hint opens Chrome's page only on Chrome and shows the path elsewhere", async () => {
  const opened = [];
  const chromeMocks = browserMocks();
  const chromeState = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { chromeExtra: { ...chromeMocks.chromeExtra, tabs: { query: async () => [{ id: 1, url: "https://www.seedr.cc/" }], create: async ({ url }) => { opened.push(url); } } } });
  await settle();
  assert.equal(chromeState.elements["#browser-pm-path"].textContent, "chrome://password-manager/settings");
  assert.equal(chromeState.elements["#open-password-settings"].hidden, false);
  await chromeState.events["#open-password-settings:click"]();
  assert.deepEqual(opened, ["chrome://password-manager/settings"]);
  const edge = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { chromeExtra: browserMocks().chromeExtra, navigatorExtra: { userAgent: "Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0" } });
  await settle();
  assert.equal(edge.elements["#browser-pm-path"].textContent, "edge://wallet/passwords");
  assert.equal(edge.elements["#open-password-settings"].hidden, true);
  const brave = await popup([], () => ({ status: "ok", credentials: [] }), "https://www.seedr.cc/",
    { chromeExtra: browserMocks().chromeExtra, navigatorExtra: { brave: {} } });
  await settle();
  assert.equal(brave.elements["#browser-pm-path"].textContent, "brave://password-manager/settings");
  assert.equal(brave.elements["#open-password-settings"].hidden, true);
});
