// A test stand-in for the Nuvori native host + desktop app (protocol 2).
// Chrome starts one process per sendNativeMessage call, so all state lives in a JSON file.
// It mirrors src-tauri/src/bin/nuvori-native-host.rs, browser_ipc.rs (handle_request) and the
// vault rules in vault.rs closely enough to exercise the extension end to end. No real secrets.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const STATE_DIR = process.env.NUVORI_E2E_STATE || path.join(here, "..", ".state");
const STATE = path.join(STATE_DIR, "vault.json");
const LOG = path.join(STATE_DIR, "host-log.jsonl");
const LOCK = path.join(STATE_DIR, "lock");
const FEATURES = ["status_no_origin", "login_title", "password_only", "multi_update", "unlock_prompt",
  "cards", "profiles", "codes", "save_details", "login_edit", "related_logins", "all_logins"];
const GRANT_TTL_MS = 2 * 60 * 1000;

// ---------------------------------------------------------------------------- framing
function frame(object) {
  const body = Buffer.from(JSON.stringify(object), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

// ---------------------------------------------------------------------------- state + lock
function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function withLock(fn) {
  for (let attempt = 0; ; attempt++) {
    try { fs.mkdirSync(LOCK); break; } catch {
      if (attempt > 400) { try { fs.rmdirSync(LOCK); } catch {} continue; }
      sleepSync(10);
    }
  }
  try {
    const state = JSON.parse(fs.readFileSync(STATE, "utf8"));
    const result = fn(state);
    const tmp = STATE + "." + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, STATE);
    return result;
  } finally { try { fs.rmdirSync(LOCK); } catch {} }
}
function log(entry) { fs.appendFileSync(LOG, JSON.stringify({ at: Date.now(), ...entry }) + "\n"); }

// ---------------------------------------------------------------------------- site rules
const MULTI_SUFFIX = new Set(["co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "github.io", "herokuapp.com", "co.nz", "com.mx"]);
function canonicalOrigin(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return url.origin === value ? url.origin : null;
  } catch { return null; }
}
function storedOrigin(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  try { const url = new URL(/^[a-z]+:\/\//i.test(text) ? text : "https://" + text); return url.protocol === "https:" ? url.origin : null; } catch { return null; }
}
function site(origin) {
  try {
    const host = new URL(origin).hostname;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host === "localhost") return host;
    const parts = host.split(".");
    const last2 = parts.slice(-2).join(".");
    return MULTI_SUFFIX.has(last2) ? parts.slice(-3).join(".") : last2;
  } catch { return null; }
}
function siteLabel(origin) {
  const registrable = site(origin);
  return registrable ? registrable.split(".")[0].toLowerCase().replace(/[^a-z0-9]/g, "") : null;
}
const squash = (value) => String(value).toLowerCase().replace(/[^a-z0-9]/g, "");
const digits = (value) => String(value || "").replace(/\D/g, "");
function luhn(number) {
  let sum = 0;
  for (let i = 0; i < number.length; i++) {
    let d = Number(number[number.length - 1 - i]);
    if (i % 2) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return number.length >= 12 && number.length <= 19 && sum % 10 === 0;
}
function network(number) {
  if (/^4/.test(number)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(number)) return "Mastercard";
  if (/^3[47]/.test(number)) return "American Express";
  if (/^6(011|5)/.test(number)) return "Discover";
  return "";
}
function newTitle(title, origin) {
  const wanted = String(title || "").trim();
  if (wanted) return wanted.slice(0, 200);
  return new URL(origin).hostname.replace(/^www\./, "");
}

// ---------------------------------------------------------------------------- TOTP
function base32(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secret.replace(/=+$/, "").toUpperCase().replace(/\s/g, "")) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totp(secret, period = 30, length = 6) {
  const now = Math.floor(Date.now() / 1000);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / period)));
  const mac = crypto.createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** length;
  return { value: String(code).padStart(length, "0"), secondsLeft: period - (now % period) };
}

// ---------------------------------------------------------------------------- vault queries
const logins = (state) => state.vault.filter((entry) => entry.type === "PASSWORD");
const exactLogins = (state, origin) => logins(state).filter((entry) => storedOrigin(entry.url) === origin);
const relatedLogins = (state, origin) => logins(state).filter((entry) => {
  const stored = storedOrigin(entry.url);
  return stored && stored !== origin && site(stored) === site(origin);
});
const sha = (text) => crypto.createHash("sha256").update(text).digest("hex");
const token = () => crypto.randomBytes(32).toString("hex"); // 64 characters, as the app issues

function issue(state, id, origin, kind, extra = {}) {
  const value = token();
  state.grants[value] = { id, origin, kind, at: Date.now(), ...extra };
  return value;
}
function consume(state, value, id, origin, kinds) {
  const grant = state.grants[value];
  if (!grant || grant.id !== id || grant.origin !== origin || !kinds.includes(grant.kind) || Date.now() - grant.at > GRANT_TTL_MS) return null;
  delete state.grants[value];
  return grant;
}
function pruneGrants(state) {
  for (const [key, grant] of Object.entries(state.grants)) if (Date.now() - grant.at > GRANT_TTL_MS * 2) delete state.grants[key];
}

const base = (request, status, message = "") => ({ version: 2, requestId: request.requestId || "", status, message });
const invalid = (request, message) => base(request, "invalid_request", message);
const seal = (object) => Buffer.from(JSON.stringify(object)).toString("base64url");
const unseal = (text) => JSON.parse(Buffer.from(String(text), "base64url").toString("utf8"));

function review(state, origin, username, password) {
  let conflict = false;
  for (const entry of exactLogins(state, origin)) {
    if (entry.username === username) {
      if (entry.password === password) return "already_saved";
      conflict = true;
    }
  }
  return conflict ? "account_exists" : "needs_save";
}
function updateChoices(state, origin, username) {
  return exactLogins(state, origin).filter((entry) => entry.username === username)
    .map((entry) => ({ id: entry.id, title: entry.title, username: entry.username,
      selectionToken: issue(state, entry.id, origin, "update", { hash: sha(entry.password) }) }));
}

function profileOf(entry) {
  const p = entry.profile || {};
  return { name: p.name || "", email: p.email || "", phone: p.phone || "", address1: p.address1 || "", address2: p.address2 || "",
    unit: p.unit || "", city: p.city || "", state: p.state || "", postalCode: p.postalCode || "", country: p.country || "" };
}

// ---------------------------------------------------------------------------- dispatch
function handle(request, state) {
  pruneGrants(state);
  const { action } = request;
  if (request.version !== 2) return invalid(request, "Unsupported protocol version.");
  const status = action === "status";
  const unlock = action === "unlock_prompt";
  if (unlock) {
    if (request.origin !== "") return invalid(request, "The browser request is incomplete.");
    state.unlockPrompts = (state.unlockPrompts || 0) + 1;
    if (state.autoUnlockOnPrompt) state.locked = false;
    return base(request, state.locked ? "locked" : "ok");
  }
  const origin = canonicalOrigin(request.origin);
  if (!origin && !(status && request.origin === "")) return invalid(request, "Only HTTPS site origins are allowed.");

  // Host-only actions (DPAPI in the real host; base64 JSON here).
  if (action === "seal_login") {
    if (typeof request.password !== "string" || typeof request.username !== "string") return invalid(request, "Could not encrypt this login.");
    const title = typeof request.title === "string" && request.title.trim() ? request.title : undefined;
    return { ...base(request, "sealed"), sealedLogin: seal({ version: 1, origin, username: request.username, password: request.password, createdAt: Math.floor(Date.now() / 1000), title }) };
  }
  if (action === "seal_details") {
    return { ...base(request, "sealed"), sealedLogin: seal({ version: 1, origin, kind: request.kind, card: request.card, profile: request.profile, createdAt: Math.floor(Date.now() / 1000) }) };
  }
  if (state.offline) return base(request, "desktop_unavailable", "Unlock Nuvori for Windows to use browser filling.");
  if (state.locked) {
    const locked = base(request, "locked", "Unlock Nuvori for Windows to use browser filling.");
    return status ? { ...locked, features: FEATURES, appearance: state.appearance } : locked;
  }

  switch (action) {
    case "status":
      return { ...base(request, "ok"), features: FEATURES, appearance: state.appearance };
    case "query_credentials": {
      if (request.all === true) {
        return { ...base(request, "ok"), credentials: logins(state).map((entry) => ({ id: entry.id, title: entry.title, username: entry.username,
          selectionToken: issue(state, entry.id, origin, "any"), site: storedOrigin(entry.url) ? new URL(storedOrigin(entry.url)).host : "" })) };
      }
      const exact = exactLogins(state, origin).map((entry) => ({ entry, related: false }));
      const related = relatedLogins(state, origin).map((entry) => ({ entry, related: true }));
      return { ...base(request, "ok"), credentials: [...exact, ...related].map(({ entry, related: rel }) => ({ id: entry.id, title: entry.title,
        username: entry.username, selectionToken: issue(state, entry.id, origin, "login"), ...(rel ? { related: true } : {}) })) };
    }
    case "fill_credential": {
      const grant = consume(state, request.selectionToken, request.credentialId, origin, ["login", "any"]);
      if (!grant) return base(request, "selection_expired", "Choose the account again; this selection expired.");
      const entry = logins(state).find((item) => item.id === request.credentialId);
      const allowed = entry && (grant.kind === "any" || storedOrigin(entry.url) === origin || site(storedOrigin(entry.url)) === site(origin));
      if (!allowed) return base(request, "credential_unavailable", "The selected account is no longer available for this site.");
      state.fills.push({ at: Date.now(), kind: "login", id: entry.id, origin });
      return { ...base(request, "ok"), credential: { id: entry.id, username: entry.username, password: entry.password } };
    }
    case "review_login":
    case "commit_login":
    case "update_login": {
      let pending;
      try { pending = unseal(request.sealedLogin); } catch { return invalid(request, "Invalid pending login."); }
      if (pending.origin !== origin) return invalid(request, "This pending login expired or belongs to another site.");
      const username = typeof request.username === "string" && action === "commit_login" ? request.username.trim() : pending.username;
      if (action === "update_login") {
        const grant = consume(state, request.selectionToken, request.credentialId, origin, ["update"]);
        if (!grant) return base(request, "selection_expired", "Review this update again; its approval expired.");
        const entry = logins(state).find((item) => item.id === request.credentialId);
        if (!entry || entry.username !== username || sha(entry.password) !== grant.hash) return { ...base(request, "account_exists", "Review this account before replacing its saved password.") };
        entry.password = pending.password;
        entry.updatedAt = Date.now();
        state.events.push({ at: Date.now(), event: "updated", id: entry.id, origin, username });
        return base(request, "saved", "Saved in your Windows vault.");
      }
      const verdict = review(state, origin, username, pending.password);
      if (verdict === "already_saved") return base(request, "already_saved", "This login is already saved.");
      if (verdict === "account_exists") {
        const credentials = updateChoices(state, origin, username);
        return { ...base(request, "account_exists", credentials.length > 1 ? "Choose which saved account to update." : "Review this account before replacing its saved password."), credentials };
      }
      if (action === "review_login") return base(request, "needs_save", "Review this new account before saving it.");
      const title = newTitle(typeof request.title === "string" ? request.title : pending.title, origin);
      const id = "login-" + crypto.randomUUID();
      state.vault.push({ id, type: "PASSWORD", title, username, password: pending.password, url: origin, createdAt: Date.now(), source: "browser" });
      state.events.push({ at: Date.now(), event: "saved_login", id, origin, username, title });
      return base(request, "saved", "Saved in your Windows vault.");
    }
    case "query_items": {
      const kind = request.kind;
      let items = [];
      if (kind === "card") {
        items = state.vault.filter((e) => e.type === "CARD").map((e) => {
          const number = digits(e.number);
          const label = [e.network || network(number) || "Card", `•••• ${number.slice(-4)}`, e.expiry].filter(Boolean).join(" · ");
          return { id: e.id, title: e.title, username: label, ...(Number.isSafeInteger(e.color) ? { color: e.color } : {}) };
        });
      } else if (kind === "profile") {
        items = state.vault.filter((e) => e.type === "AUTOFILL").map((e) => {
          const p = profileOf(e);
          return { id: e.id, title: e.title, username: [p.name, p.email, p.city].filter(Boolean).join(" · "), preview: p };
        });
      } else if (kind === "code") {
        const label = siteLabel(origin);
        const names = exactLogins(state, origin).map((e) => e.username.trim().toLowerCase()).filter(Boolean);
        items = state.vault.filter((e) => e.type === "AUTHENTICATOR").map((e) => {
          const service = squash(e.title);
          const named = label && ((label.length >= 3 && service.includes(label)) || (service.length >= 4 && label.includes(service)));
          const listed = (e.autofillOrigins || []).some((s) => storedOrigin(s) === origin);
          const sameAccount = e.account && names.includes(e.account.trim().toLowerCase());
          return { matched: Boolean(named || listed || sameAccount), e };
        }).filter(({ matched }) => matched || request.all === true)
          .sort((a, b) => Number(b.matched) - Number(a.matched) || a.e.title.localeCompare(b.e.title))
          .map(({ e }) => ({ id: e.id, title: e.title, username: e.account || "" }));
      } else return invalid(request, "The browser request is incomplete.");
      return { ...base(request, "ok"), credentials: items.map((item) => ({ ...item, selectionToken: issue(state, item.id, origin, "item:" + kind) })) };
    }
    case "fill_item": {
      const kind = request.kind;
      if (!consume(state, request.selectionToken, request.credentialId, origin, ["item:" + kind])) return base(request, "selection_expired", "Choose the item again; this selection expired.");
      const e = state.vault.find((item) => item.id === request.credentialId);
      if (!e) return base(request, "credential_unavailable", "This item is no longer available.");
      state.fills.push({ at: Date.now(), kind, id: e.id, origin });
      const item = { id: e.id, kind };
      if (kind === "card") {
        const number = digits(e.number);
        item.card = { number, name: e.name || "", expiry: e.expiry || "", network: e.network || network(number) };
        if (e.cvv) item.cvvToken = issue(state, e.id, origin, "cvv");
      } else if (kind === "profile") item.profile = profileOf(e);
      else item.code = totp(e.secret, e.period || 30, e.digits || 6);
      return { ...base(request, "ok"), item };
    }
    case "request_cvv": {
      const grant = state.grants[request.selectionToken];
      if (!grant || grant.kind !== "cvv" || grant.id !== request.credentialId || grant.origin !== origin) return base(request, "selection_expired", "Choose the item again; this selection expired.");
      grant.asked = Date.now();
      grant.decision = state.cvvDecision || "approve"; // what the "Windows Hello" window answers in this run
      state.cvvRequests = (state.cvvRequests || 0) + 1;
      return base(request, "pending", "Approve the security code in Nuvori.");
    }
    case "fill_cvv": {
      const grant = state.grants[request.selectionToken];
      if (!grant || grant.kind !== "cvv" || grant.id !== request.credentialId || grant.origin !== origin || !grant.asked) return base(request, "selection_expired", "Choose the item again; this selection expired.");
      if (grant.decision === "wait") return base(request, "pending", "Approve the security code in Nuvori.");
      delete state.grants[request.selectionToken];
      if (grant.decision === "deny") return base(request, "denied", "The security code was not approved.");
      const e = state.vault.find((item) => item.id === request.credentialId);
      return { ...base(request, "ok"), item: { id: e.id, kind: "card", card: { number: "", name: "", expiry: "", network: "", cvv: e.cvv } } };
    }
    case "review_details":
    case "commit_details": {
      let pending;
      try { pending = unseal(request.sealedLogin); } catch { return invalid(request, "Invalid captured details."); }
      if (pending.origin !== origin) return invalid(request, "These details expired or belong to another site.");
      let exists = false;
      if (pending.kind === "card") {
        if (!pending.card || !luhn(digits(pending.card.number))) return invalid(request, "These details expired or belong to another site.");
        exists = state.vault.some((e) => e.type === "CARD" && digits(e.number) === digits(pending.card.number));
      } else if (pending.kind === "profile") {
        const p = pending.profile || {};
        const same = (a, b) => String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
        exists = state.vault.some((e) => e.type === "AUTOFILL" && Object.entries(profileOf(e)).every(([key, saved]) => !String(p[key] || "").trim() || same(saved, p[key])));
      } else return invalid(request, "These details expired or belong to another site.");
      if (exists) return base(request, "already_saved", "These details are already saved.");
      if (action === "review_details") return base(request, "needs_save", "Review these details before saving them.");
      const id = pending.kind + "-" + crypto.randomUUID();
      const title = typeof request.title === "string" && request.title.trim() ? request.title.trim() : undefined;
      if (pending.kind === "card") {
        const number = digits(pending.card.number);
        state.vault.push({ id, type: "CARD", title: title || `${network(number) || "Card"} •••• ${number.slice(-4)}`, number, name: pending.card.name || "", expiry: pending.card.expiry || "", network: pending.card.network || network(number), source: "browser" });
      } else {
        state.vault.push({ id, type: "AUTOFILL", title: title || pending.profile.name || "Address", profile: pending.profile, source: "browser" });
      }
      state.events.push({ at: Date.now(), event: "saved_" + pending.kind, id, origin, title });
      return base(request, "saved", "Saved in your Windows vault.");
    }
    default:
      return invalid(request, "The browser request is incomplete.");
  }
}

// ---------------------------------------------------------------------------- main
// Chrome keeps stdin open until it reads the reply, so answer each complete message at once.
let pending = Buffer.alloc(0);
function answer(body) {
  let request;
  try { request = JSON.parse(body.toString("utf8")); } catch { process.stdout.write(frame({ version: 2, requestId: "", status: "invalid_request", message: "Malformed JSON request." })); return; }
  let response;
  try { response = withLock((state) => handle(request, state)); } catch (error) { response = { version: 2, requestId: request.requestId || "", status: "invalid_request", message: "fake host error: " + error.message }; }
  // Log the shape only: never passwords or codes.
  log({ caller: process.argv[2] || "", action: request.action, origin: request.origin, kind: request.kind, all: request.all,
    username: request.username, title: request.title, status: response.status, count: response.credentials?.length });
  process.stdout.write(frame(response));
}
process.stdin.on("data", (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (pending.length >= 4) {
    const length = pending.readUInt32LE(0);
    if (pending.length < 4 + length) break;
    const body = pending.subarray(4, 4 + length);
    pending = pending.subarray(4 + length);
    answer(body);
  }
});
process.stdin.on("end", () => process.exit(0));
