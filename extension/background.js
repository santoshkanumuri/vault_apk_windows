const HOST_NAME = "com.nuvori.desktop";
const STORAGE_KEY = "pendingLogins";
const PROMPTS_KEY = "inlinePrompts";
const DIAGNOSTICS_KEY = "diagnostics";
const ALARM_NAME = "retryPendingLogins";
const CLIPBOARD_ALARM = "clearClipboard";
const MAX_PENDING = 20;            // approved logins waiting in chrome.storage.local
const MAX_PENDING_PER_ORIGIN = 5;
const MAX_CAPTURES = 20;           // unapproved captures, memory only (chrome.storage.session)
const MAX_CAPTURES_PER_ORIGIN = 3;
const CAPTURES_KEY = "capturedLogins";
const CAPTURE_TAB_INTERVAL_MS = 5 * 1000;
const CAPTURE_ORIGIN_LIMIT = 4;
const CAPTURE_ORIGIN_WINDOW_MS = 60 * 1000;
const MAX_DIAGNOSTICS = 20;
const PROMPT_TTL_MS = 2 * 60 * 1000;
const PENDING_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const QUERY_TTL_OK_MS = 12 * 1000;
const QUERY_TTL_OTHER_MS = 4 * 1000;
const THEMES = ["system", "light", "dark"];
const FEATURES_KEY = "hostFeatures";
const FEATURE_TTL_MS = 5 * 60 * 1000;
const UNLOCK_WATCH_MS = 2 * 60 * 1000;
const UNLOCK_POLL_MS = 4 * 1000;
const DETAILS_KEY = "detailCaptures";
const MAX_DETAIL_CAPTURES = 10;
const CARD_CODE_POLL_MS = 1500;
const CARD_CODE_WAIT_MS = 2 * 60 * 1000;
// Item kinds and the host feature each needs.
const ITEM_FEATURES = { card: "cards", profile: "profiles", code: "codes" };
const PROFILE_KEYS = ["name", "email", "phone", "address1", "address2", "unit", "city", "state", "postalCode", "country"];
// Older hosts need an HTTPS origin even for "status"; this reserved name is the fallback.
const STATUS_ORIGIN = "https://status.nuvori.invalid";
const MAX_TITLE = 256;
const MAX_CHOICES = 20;
const BADGE = { success: "#1E7A33", warning: "#8A5300", text: "#FFFFFF" };
// Firefox has no IntersectionObserver v2, so the page can't prove Nuvori's in-page list is really
// visible before a click. There the list fills only what is tied to the page's own site (its
// logins and its matching codes); cards, addresses, every code and every login fill from the popup.
const LIMITED_PAGE_UI = String(chrome.runtime.getURL?.("") || "").startsWith("moz-extension:");
// On every browser, a page (its content scripts) may list and fill only what is tied to that page's
// own site. Cross-site lists (every login, every code) and filling a login saved for another site are
// refused to pages, so a page that tricks the user into a click, or a compromised renderer, can't
// enumerate the vault or pull another site's password. Older content scripts get "disabled".

// ---------------------------------------------------------------------------
// Diagnostics: action, status, site host and time only. Never usernames,
// titles, passwords, tokens, or sealed logins.

const cleanWord = (value) => typeof value === "string" ? value.replace(/[^a-z0-9_ .-]/gi, "").slice(0, 40) : "";
const hostOf = (origin) => { try { return origin === STATUS_ORIGIN ? "" : new URL(origin).host; } catch { return ""; } };
let diagnosticsWrite = Promise.resolve();

function logEvent(action, status, origin) {
  const store = chrome.storage.session;
  if (!store) return diagnosticsWrite;
  const entry = { at: Date.now(), action: cleanWord(action), status: cleanWord(status), host: hostOf(origin) };
  diagnosticsWrite = diagnosticsWrite.then(async () => {
    const saved = await store.get(DIAGNOSTICS_KEY);
    const list = Array.isArray(saved?.[DIAGNOSTICS_KEY]) ? saved[DIAGNOSTICS_KEY] : [];
    list.unshift(entry);
    await store.set({ [DIAGNOSTICS_KEY]: list.slice(0, MAX_DIAGNOSTICS) });
  }).catch(() => {});
  return diagnosticsWrite;
}

// ---------------------------------------------------------------------------
// Native host

function hostErrorStatus(error) {
  const detail = error instanceof Error ? error.message : String(error);
  return /not found|not registered|specified native messaging host|forbidden/i.test(detail) ? "host_missing" : "offline";
}

async function native(action, origin, details = {}) {
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, { version: 2, requestId: crypto.randomUUID(), action, origin, ...details });
    if (action === "status") await noteFeatures(response);
    void logEvent(action, response?.status || "empty", origin);
    return response;
  } catch (error) {
    void logEvent(action, hostErrorStatus(error), origin);
    throw error;
  }
}

/** Update choices from review_login/commit_login. Older hosts send one; "multi_update" hosts send one per matching account. */
function updateChoices(response) {
  if (response?.status !== "account_exists" || !Array.isArray(response.credentials)) return [];
  return response.credentials.filter((choice) => choice && typeof choice.id === "string" && choice.id && choice.id.length <= 256 &&
    typeof choice.selectionToken === "string" && choice.selectionToken).slice(0, MAX_CHOICES)
    .map(({ id, title, username, selectionToken }) => ({ id, title: typeof title === "string" ? title : "", username: typeof username === "string" ? username : "", selectionToken }));
}

/** Items stored by 0.4.0 carry a single `updateChoice`. */
function choicesOf(item) {
  if (Array.isArray(item.updateChoices)) return item.updateChoices;
  return item.updateChoice ? [item.updateChoice] : [];
}

function setChoices(item, choices) {
  delete item.updateChoice;
  if (choices.length) item.updateChoices = choices;
  else delete item.updateChoices;
}

const publicChoices = (item) => choicesOf(item).map(({ id, title, username }) => ({ id, title: title || "", username: username || "" }));

/** A login name: control characters removed, at most 256 characters, trimmed. Empty lets the host choose. */
function cleanTitle(value) {
  if (typeof value !== "string") return "";
  // Control characters become spaces; format characters (zero-width, bidi overrides such as U+202E) are removed.
  return value.replace(/\p{Cc}/gu, " ").replace(/\p{Cf}/gu, "").slice(0, MAX_TITLE).trim();
}

// ---------------------------------------------------------------------------
// Host features: additive protocol-2 capabilities listed on "status" responses.
// New request fields are sent only when listed, because older hosts reject unknown fields.

let featureCache = null;

// The desktop's accent and background ids ride on "status" responses; cache valid ones for the popup and pages.
const APPEARANCE_ID = /^[a-z][a-z0-9-]{0,31}$/;

async function noteAppearance(response) {
  const value = response?.appearance;
  if (!value || typeof value.accent !== "string" || typeof value.surface !== "string"
    || !APPEARANCE_ID.test(value.accent) || !APPEARANCE_ID.test(value.surface)) return;
  const saved = (await chrome.storage.local.get("appearance")).appearance;
  if (saved?.accent === value.accent && saved?.surface === value.surface) return;
  await chrome.storage.local.set({ appearance: { accent: value.accent, surface: value.surface } });
}

async function noteFeatures(response) {
  if (!["ok", "locked", "desktop_unavailable"].includes(response?.status)) return;
  await noteAppearance(response).catch(() => {});
  const list = Array.isArray(response.features) ? response.features.filter((entry) => typeof entry === "string").slice(0, 32) : [];
  featureCache = { list, at: Date.now() };
  await chrome.storage.session?.set({ [FEATURES_KEY]: featureCache });
}

async function cachedFeatures() {
  if (featureCache) return featureCache;
  const saved = await chrome.storage.session?.get(FEATURES_KEY);
  const entry = saved?.[FEATURES_KEY];
  if (entry && Array.isArray(entry.list) && typeof entry.at === "number") featureCache = entry;
  return featureCache;
}

/** Ping the host (refreshing the feature list) and return its status word. */
async function pingStatus() {
  const known = (await cachedFeatures())?.list || [];
  try {
    const response = await native("status", known.includes("status_no_origin") ? "" : STATUS_ORIGIN);
    return response?.status || "error";
  } catch (error) {
    return hostErrorStatus(error);
  }
}

async function getFeatures({ refresh = false } = {}) {
  const cached = await cachedFeatures();
  if (!refresh && cached && Date.now() - cached.at < FEATURE_TTL_MS) return cached.list;
  await pingStatus();
  return featureCache?.list || [];
}

// ---------------------------------------------------------------------------
// Settings (chrome.storage.local; written by the popup and by in-page choices)

async function readSettings() {
  const saved = await chrome.storage.local.get(["inlineSuggestions", "neverSave", "noSuggest", "theme", "unlockOnStartup",
    "fillCards", "fillProfiles", "fillCodes", "saveDetails", "neverSignIn"]);
  const list = (value) => Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : [];
  return {
    inlineSuggestions: saved?.inlineSuggestions !== false,
    unlockOnStartup: saved?.unlockOnStartup !== false,
    fill: { card: saved?.fillCards !== false, profile: saved?.fillProfiles !== false, code: saved?.fillCodes !== false },
    saveDetails: saved?.saveDetails !== false,
    neverSave: list(saved?.neverSave),
    noSuggest: list(saved?.noSuggest),
    neverSignIn: list(saved?.neverSignIn),
    theme: THEMES.includes(saved?.theme) ? saved.theme : "system",
  };
}

async function addToList(key, origin) {
  const settings = await readSettings();
  const current = Array.isArray(settings[key]) ? settings[key] : [];
  if (!current.includes(origin)) await chrome.storage.local.set({ [key]: [...current, origin].slice(-500) });
}

// ---------------------------------------------------------------------------
// Sign-in steps. Many sites ask for the account name on one page and the password or a code on
// the next. The account name used in a tab (filled by Nuvori, or typed on an identifier-first
// page) is kept for that tab and site for a few minutes, in memory only (chrome.storage.session).
// It puts the matching login and its authenticator code first on the next page, and it names
// the account when the password page has no account field. It is never a secret and never
// leaves this worker except as the order of the list and the name on the save card.

const STEPS_KEY = "signInSteps";
const STEP_TTL_MS = 10 * 60 * 1000;
const MAX_STEPS = 32;

async function readSteps() {
  const stored = (await chrome.storage.session.get(STEPS_KEY))[STEPS_KEY];
  const steps = {};
  if (stored && typeof stored === "object") {
    for (const [tabId, step] of Object.entries(stored)) {
      if (step && typeof step.username === "string" && typeof step.origin === "string" && Date.now() - step.at < STEP_TTL_MS) steps[tabId] = step;
    }
  }
  return steps;
}

async function rememberStep(page, username) {
  const name = typeof username === "string" ? username.replace(/\p{Cc}/gu, "").trim() : "";
  if (!name || name.length > 1024) return;
  const steps = await readSteps();
  steps[page.tabId] = { origin: page.origin, username: name, at: Date.now() };
  const oldest = Object.entries(steps).sort((a, b) => a[1].at - b[1].at);
  for (const [tabId] of oldest.slice(0, Math.max(0, oldest.length - MAX_STEPS))) delete steps[tabId];
  await chrome.storage.session.set({ [STEPS_KEY]: steps });
}

/** The account name used in this tab on this site a moment ago, or "". */
async function stepName(page) {
  const step = (await readSteps())[page.tabId];
  return step && step.origin === page.origin ? step.username : "";
}

async function forgetStep(tabId) {
  const steps = await readSteps();
  if (!(tabId in steps)) return;
  delete steps[tabId];
  await chrome.storage.session.set({ [STEPS_KEY]: steps });
}

const sameName = (left, right) => left.trim().toLowerCase() === right.trim().toLowerCase();
/** Stable: entries that `first` accepts come first, the rest keep their order. */
const firstBy = (list, first) => [...list.filter(first), ...list.filter((entry) => !first(entry))];

// ---------------------------------------------------------------------------
// Website icon capture. Only when the app answers a query with iconWanted: true (it says so only for a
// site that already has a login or passkey). The page's favicon is fetched with no cookies, re-encoded
// to a 64x64 PNG here, and only that PNG goes to the app: it never receives the site's own bytes.

const ICON_SIZE = 64;
const ICON_MAX_BYTES = 256 * 1024;
const ICON_TIMEOUT_MS = 5000;
const ICON_RETRY_MS = 6 * 60 * 60 * 1000;
const ICON_ATTEMPTS_KEY = "iconAttempts";
const iconAttemptsMemory = new Map();

/** "https" or "data" for a favicon address we may read; "" for anything else (http, blob, file, data:text ...). */
function iconSourceKind(value) {
  if (typeof value !== "string") return "";
  if (/^data:image\//i.test(value)) return "data";
  try { return new URL(value).protocol === "https:" ? "https" : ""; } catch { return ""; }
}

/** The "contain" box for a width x height image inside a size x size square, centered. */
function containRect(width, height, size = ICON_SIZE) {
  if (!(width > 0) || !(height > 0)) return null;
  const scale = Math.min(size / width, size / height);
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  return { x: Math.round((size - w) / 2), y: Math.round((size - h) / 2), w, h };
}

/** A blob we are willing to decode: an image (or the generic type .ico files often carry), 1 B to 256 KB. */
function iconBlobAcceptable(type, size) {
  const kind = String(type || "").split(";")[0].trim().toLowerCase();
  return (kind.startsWith("image/") || kind === "application/octet-stream") && size > 0 && size <= ICON_MAX_BYTES;
}

/** True (and records the attempt) when this host had no attempt in the last 6 hours. Kept in session storage so it survives worker sleep. */
async function claimIconAttempt(host, now = Date.now()) {
  let stored = null;
  try { stored = (await chrome.storage.session.get(ICON_ATTEMPTS_KEY))?.[ICON_ATTEMPTS_KEY]; } catch { stored = null; }
  const attempts = stored && typeof stored === "object" ? stored : Object.fromEntries(iconAttemptsMemory);
  const last = attempts[host];
  if (typeof last === "number" && now - last >= 0 && now - last < ICON_RETRY_MS) return false;
  attempts[host] = now;
  for (const [key, at] of Object.entries(attempts)) if (now - at >= ICON_RETRY_MS || now - at < 0) delete attempts[key];
  attempts[host] = now;
  const keys = Object.keys(attempts);
  for (const key of keys.slice(0, Math.max(0, keys.length - 200))) delete attempts[key];
  iconAttemptsMemory.clear();
  for (const [key, at] of Object.entries(attempts)) iconAttemptsMemory.set(key, at);
  try { await chrome.storage.session.set({ [ICON_ATTEMPTS_KEY]: attempts }); } catch { /* the memory copy is enough */ }
  return true;
}

function bytesToBase64(bytes) {
  let text = "";
  for (let at = 0; at < bytes.length; at += 0x8000) text += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  return btoa(text);
}

/** Reads the body but stops once it passes the cap, so a hostile server cannot make us download more. */
async function readIconBody(response) {
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > ICON_MAX_BYTES) return null;
  const reader = response.body?.getReader?.();
  if (!reader) {
    const blob = await response.blob();
    return iconBlobAcceptable(blob.type, blob.size) ? blob : null;
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > ICON_MAX_BYTES) { await reader.cancel().catch(() => {}); return null; }
    chunks.push(value);
  }
  const blob = new Blob(chunks, { type: response.headers?.get?.("content-type") || "" });
  return iconBlobAcceptable(blob.type, blob.size) ? blob : null;
}

/** Fetches the favicon (https or data:image) with no cookies, no referrer and a 5 s limit. Null when it is not acceptable. */
async function fetchIconBlob(source) {
  const kind = iconSourceKind(source);
  if (!kind) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ICON_TIMEOUT_MS);
  try {
    const response = await fetch(source, { credentials: "omit", cache: "force-cache", redirect: "follow", referrerPolicy: "no-referrer", signal: controller.signal });
    if (!response.ok) return null;
    if (kind === "https" && iconSourceKind(response.url || source) !== "https") return null;
    return await readIconBody(response);
  } catch { return null; }
  finally { clearTimeout(timer); }
}

/** Draws a decoded image into a 64x64 transparent canvas with contain scaling and returns PNG bytes. */
async function drawIcon(image, width, height) {
  const box = containRect(width, height);
  if (!box) return null;
  const canvas = new OffscreenCanvas(ICON_SIZE, ICON_SIZE);
  const context = canvas.getContext("2d");
  context.imageSmoothingQuality = "high";
  context.drawImage(image, box.x, box.y, box.w, box.h);
  const png = await canvas.convertToBlob({ type: "image/png" });
  return new Uint8Array(await png.arrayBuffer());
}

/** Rasterizes SVG through an <img> (scripts never run there) where a DOM exists: the Firefox background page, or Chrome's offscreen document. */
async function rasterizeSvg(blob) {
  const dataUrl = `data:image/svg+xml;base64,${bytesToBase64(new Uint8Array(await blob.arrayBuffer()))}`;
  if (typeof document !== "undefined" && typeof Image !== "undefined") return rasterizeInDocument(dataUrl);
  if (!chrome.offscreen) return null;
  // Only one offscreen document can exist, and the clipboard cleanup owns it while it runs: skip then.
  if (await chrome.offscreen.hasDocument?.()) return null;
  // Close only a document this call created: if the clipboard cleanup created one in between,
  // createDocument throws here, and closing would stop the password from being cleared.
  let created = false;
  try {
    await chrome.offscreen.createDocument({ url: "offscreen.html", reasons: ["BLOBS"], justification: "Draw a site's SVG icon as a small PNG." });
    created = true;
    const reply = await chrome.runtime.sendMessage({ target: "offscreen", action: "rasterize_icon", svg: dataUrl });
    return typeof reply?.png === "string" ? reply.png : null;
  } catch { return null; }
  finally { if (created) await chrome.offscreen.closeDocument().catch(() => {}); }
}

function rasterizeInDocument(dataUrl) {
  return new Promise((resolve) => {
    const image = new Image();
    const timer = setTimeout(() => resolve(null), ICON_TIMEOUT_MS);
    image.onload = async () => {
      clearTimeout(timer);
      try {
        const bytes = await drawIcon(image, image.naturalWidth || ICON_SIZE, image.naturalHeight || ICON_SIZE);
        resolve(bytes ? bytesToBase64(bytes) : null);
      } catch { resolve(null); }
    };
    image.onerror = () => { clearTimeout(timer); resolve(null); };
    image.src = dataUrl;
  });
}

/** Any accepted icon blob to base64 of a 64x64 PNG, or null when it cannot be decoded. */
async function iconToPngBase64(blob) {
  if (/svg/i.test(blob.type)) return rasterizeSvg(blob);
  if (typeof createImageBitmap !== "function" || typeof OffscreenCanvas === "undefined") return null;
  const bitmap = await createImageBitmap(blob);
  try {
    const bytes = await drawIcon(bitmap, bitmap.width, bitmap.height);
    return bytes ? bytesToBase64(bytes) : null;
  } finally { bitmap.close?.(); }
}

/** Runs after a query_credentials answer with iconWanted. Never throws and never delays filling. */
async function captureSiteIcon(tabId, origin) {
  try {
    const tab = await chrome.tabs.get(tabId);
    let page;
    try { page = new URL(tab?.url || ""); } catch { return; }
    if (!tab || tab.incognito === true || page.protocol !== "https:" || page.origin !== origin) return;
    if (!iconSourceKind(tab.favIconUrl)) return;
    if (!(await claimIconAttempt(page.hostname.toLowerCase()))) return;
    const blob = await fetchIconBlob(tab.favIconUrl);
    if (!blob) return;
    const icon = await iconToPngBase64(blob);
    if (!icon) return;
    await native("save_site_icon", origin, { icon });
  } catch { /* Icons are optional: give up silently. */ }
}

// ---------------------------------------------------------------------------
// Sign-in methods ("sign_in_methods" hosts; signins.js). Notices a finished "Sign in with <provider>"
// on a site, asks the user, and reminds them next time. The flow state (provider, sites, at most an
// account name) lives in chrome.storage.session, in memory only; never a URL, code or token.
// Nothing happens in private windows, or when the app lists no "sign_in_methods" (setting off).

if (typeof NuvoriSignIns === "undefined" && typeof importScripts === "function") {
  try { importScripts("signins.js"); } catch { /* reminders stay off */ }
}
const SIGNINS = () => (typeof NuvoriSignIns === "object" && NuvoriSignIns ? NuvoriSignIns : null);
const SIGNIN_FLOWS_KEY = "signInFlows";
const SIGNIN_CACHE_MS = 30 * 1000;
const MAX_SIGNIN_REMINDERS = 3;
let signInTracker = null;
let signInWork = Promise.resolve();
// Authorize requests queued but not yet in the tracker: a redirect right behind one must not be skipped.
let signInQueued = 0;
/** Nothing under way: events can return at once without waking the queue. */
const signInIdle = () => signInQueued === 0 && Boolean(signInTracker) && !signInTracker.active();
const signInCache = new Map(); // origin -> { at, promise }

function signInStep(work) {
  const result = signInWork.then(work, work);
  signInWork = result.catch(() => {});
  return result;
}

async function signInFlows() {
  if (!signInTracker) {
    const saved = (await chrome.storage.session?.get(SIGNIN_FLOWS_KEY))?.[SIGNIN_FLOWS_KEY];
    signInTracker = signInTracker || SIGNINS().createTracker(saved);
  }
  return signInTracker;
}

const keepSignInFlows = () => chrome.storage.session?.set({ [SIGNIN_FLOWS_KEY]: signInTracker.toJSON() });
const signInsSupported = async () => (await getFeatures()).includes("sign_in_methods");
const tabOf = async (tabId) => { try { return await chrome.tabs.get(tabId); } catch { return null; } };
const originOf = (value) => { try { const url = new URL(value); return url.protocol === "https:" ? url.origin : undefined; } catch { return undefined; } };
/** "app.example.com" belongs to the site "example.com". */
const onSite = (origin, site) => { const name = hostOf(origin).toLowerCase(); return Boolean(site) && (name === site || name.endsWith(`.${site}`)); };

/** True for a tab in a popup window (window.open with a size or features). */
async function inPopupWindow(tab) {
  if (!chrome.windows?.get || !Number.isInteger(tab?.windowId)) return false;
  try { return (await chrome.windows.get(tab.windowId))?.type === "popup"; } catch { return false; }
}

/**
 * The tab that opened a sign-in popup, when the browser does not say: Firefox sets openerTabId only
 * for a tab in the opener's own window, and a popup opened with noopener has none. The page that
 * opened it is, in order: the tab where the user just clicked a sign-in button, else the active tab of the
 * last focused normal window when its page is the site that started the request (`initiator`), else
 * the only tab showing that site. Never a tab of the other profile (private windows).
 */
async function guessOpener(tab, flows, initiator) {
  const site = originOf(initiator || "");
  const clicked = flows.recentClick({ at: Date.now(), except: tab.id });
  let active = null;
  try {
    const last = await chrome.windows.getLastFocused({ windowTypes: ["normal"] });
    [active] = await chrome.tabs.query({ active: true, windowId: last.id });
  } catch { /* no normal window */ }
  for (const [id, trusted] of [[clicked, true], [active?.id, false]]) {
    if (!Number.isInteger(id) || id === tab.id) continue;
    const home = await tabOf(id);
    if (!home || Boolean(home.incognito) !== Boolean(tab.incognito)) continue;
    if (trusted || !site || originOf(home.url || "") === site) return home.id;
  }
  if (!site) return null;
  let same = [];
  try { same = (await chrome.tabs.query({})).filter((other) => other.id !== tab.id && Boolean(other.incognito) === Boolean(tab.incognito) && originOf(other.url || "") === site); } catch { /* none */ }
  return same.length === 1 ? same[0].id : null;
}

/**
 * The tab a sign-in in `tab` belongs to, or null for the tab itself: the opener noted when the popup
 * opened, a same-window opener (a new tab with nothing in it yet, or opened straight at the
 * provider), or a guessed opener for a popup window.
 */
async function homeTabFor(tab, url, flows, initiator) {
  const noted = flows.homeOf(tab.id);
  if (noted !== null && (await tabOf(noted))) return noted;
  const popupWindow = await inPopupWindow(tab);
  if (Number.isInteger(tab.openerTabId) && tab.openerTabId !== tab.id) {
    if (popupWindow || !tab.url || tab.url === "about:blank" || tab.url === url) return tab.openerTabId;
  }
  return popupWindow ? guessOpener(tab, flows, initiator) : null;
}

/**
 * tabs.onCreated: a popup window, or a tab a page opened straight at a provider or a broker, may
 * become a sign-in. Note its opener now: a broker's popup (Auth0, Firebase) reaches the provider only
 * after its own page, whose address says nothing about the site. A blank new tab in a normal window
 * is not noted (any new tab can be blank at first); homeTabFor links it when it asks the provider.
 */
function onSignInTabCreated(tab) {
  if (!SIGNINS() || !(tab?.id >= 0) || tab.incognito) return;
  void signInStep(async () => {
    const opener = Number.isInteger(tab.openerTabId) && tab.openerTabId !== tab.id ? tab.openerTabId : null;
    const pending = tab.pendingUrl || tab.url || "";
    const signInPage = Boolean(SIGNINS().parseAuthorize(pending)) || SIGNINS().isBroker(pending);
    const popupWindow = await inPopupWindow(tab);
    if (!popupWindow && !(opener !== null && signInPage)) return;
    const flows = await signInFlows();
    const home = opener ?? await guessOpener(tab, flows, null);
    if (home === null) return;
    flows.opened({ tabId: tab.id, homeTabId: home, at: Date.now() });
    await keepSignInFlows();
  }).catch(() => {});
}

/** Asks the opener's page to note its storage key names now (a popup sign-in begins). */
function watchOpener(homeTabId) {
  try { void chrome.tabs.sendMessage(homeTabId, { target: "nuvori-top", action: "signin_watch" }, { frameId: 0 })?.catch?.(() => {}); } catch { /* no page there */ }
}

/** The opener of a popup that closed by itself: an answer shows as a navigation or new storage keys. */
function checkOpener(homeTabId, popupTabId, delays = [1000, 3000, 6000, 10000, 16000]) {
  for (const delay of delays) {
    setTimeout(() => void signInStep(async () => {
      const flows = await signInFlows();
      if (flows.flowOf(popupTabId)?.phase !== "awaiting") return;
      let answer = null;
      try { answer = await chrome.tabs.sendMessage(homeTabId, { target: "nuvori-top", action: "signin_changed" }, { frameId: 0 }); } catch { answer = null; }
      if (answer?.changed !== true) return;
      const home = await tabOf(homeTabId);
      const keys = flows.homeChanged({ tabId: homeTabId, url: home?.url || "", at: Date.now() });
      await keepSignInFlows();
      for (const key of keys) setTimeout(() => void settleSignIn(key), SIGNINS().SETTLE_MS + 100);
    }).catch(() => {}), delay);
  }
}

/** webRequest: a provider's authorize request, or a page request in a tab with a sign-in under way. */
function onSignInRequest(details) {
  if (!(details?.tabId >= 0) || !SIGNINS()) return;
  const authorize = SIGNINS().parseAuthorize(details.url);
  if (!authorize && signInIdle()) return;
  if (authorize) signInQueued++;
  void signInStep(async () => {
    if (authorize) signInQueued--;
    const flows = await signInFlows();
    if (!authorize && !flows.flowOf(details.tabId)) return;
    if (authorize && !(await signInsSupported())) return;
    const tab = await tabOf(details.tabId);
    if (!tab || tab.incognito) { flows.forget(details.tabId); return; }
    const initiator = details.initiator || originOf(details.originUrl || "");
    const opener = authorize && details.type === "main_frame" ? await homeTabFor(tab, details.url, flows, initiator) : null;
    const home = opener === null ? null : await tabOf(opener);
    const started = flows.request({
      tabId: details.tabId, url: details.url, type: details.type, at: Date.now(), initiator,
      startUrl: home ? home.url : tab.url, homeTabId: home ? home.id : details.tabId,
    });
    await keepSignInFlows();
    if (started?.started && started.homeTabId !== details.tabId) watchOpener(started.homeTabId);
  }).catch(() => {});
}

/** Requests to any site: only the answer of a provider (a form POST it started) matters. */
function onSignInPage(details) {
  if (SIGNINS()?.parseAuthorize(details?.url)) return; // the authorize listener has it
  onSignInRequest(details);
}

function onSignInRedirect(details) {
  if (!(details?.tabId >= 0) || !SIGNINS() || signInIdle()) return;
  void signInStep(async () => {
    const flows = await signInFlows();
    if (!flows.flowOf(details.tabId)) return;
    flows.redirect({ tabId: details.tabId, url: details.url, redirectUrl: details.redirectUrl, at: Date.now() });
    await keepSignInFlows();
  }).catch(() => {});
}

function onSignInTabUpdated(tabId, change, tab) {
  if ((change?.status !== "complete" && !change?.url) || !SIGNINS() || signInIdle()) return;
  void signInStep(async () => {
    const flows = await signInFlows();
    // The opener of a popup that closed by itself loaded a page or changed its address (pushState).
    const answered = flows.homeChanged({ tabId, url: tab?.url || change.url || "", at: Date.now() });
    if (answered.length) {
      await keepSignInFlows();
      for (const key of answered) setTimeout(() => void settleSignIn(key), SIGNINS().SETTLE_MS + 100);
    }
    // The same move while the popup is still open: it often closes a moment later.
    if (change.url && flows.homeMoved({ tabId, url: change.url, at: Date.now() })) await keepSignInFlows();
    if (change.status !== "complete") return;
    const flow = flows.flowOf(tabId);
    if (!flow) return;
    const homeUrl = flow.homeTabId === tabId ? tab?.url : (await tabOf(flow.homeTabId))?.url;
    if (flows.committed({ tabId, url: tab?.url || "", homeUrl, at: Date.now() })) {
      await keepSignInFlows();
      setTimeout(() => void settleSignIn(tabId), SIGNINS().SETTLE_MS + 100);
    }
  }).catch(() => {});
}

function settleSignIn(tabId) {
  return signInStep(async () => {
    const flows = await signInFlows();
    const found = flows.settle({ tabId, at: Date.now() });
    await keepSignInFlows();
    if (found) await offerSignIn(found);
  }).catch(() => {});
}

function onSignInTabRemoved(tabId) {
  if (!SIGNINS() || signInIdle()) return;
  void signInStep(async () => {
    const flows = await signInFlows();
    const flow = flows.flowOf(tabId);
    const homeUrl = flow && flow.homeTabId !== tabId ? (await tabOf(flow.homeTabId))?.url : undefined;
    const found = flows.closed({ tabId, homeUrl, at: Date.now() });
    await keepSignInFlows();
    if (found) await offerSignIn(found);
    const waiting = flows.flowOf(tabId);
    if (waiting?.phase === "awaiting") checkOpener(waiting.homeTabId, tabId);
    // The opener took the answer just before the popup closed.
    if (waiting?.phase === "returned") setTimeout(() => void settleSignIn(tabId), SIGNINS().SETTLE_MS + 100);
  }).catch(() => {});
}

/** Messages from content scripts: a sign-in button click on a site, or an account a provider's page showed. */
async function handleSignInMessage(sender, message) {
  const tabId = sender.tab.id;
  if (sender.tab.incognito === true || !SIGNINS()) return { status: "ignored" };
  const url = typeof sender.url === "string" && sender.url.startsWith("https://") ? sender.url : "";
  if (!url) return { status: "ignored" };
  return signInStep(async () => {
    const flows = await signInFlows();
    if (message.action === "signin_click") {
      if (typeof message.provider !== "string") return { status: "ignored" };
      // From a frame: a provider's own button frame (Google's GIS button) counts for that provider
      // only; a site's sign-in frame (its login service) reports its buttons like the page does.
      if (sender.frameId !== 0) {
        let page = null;
        try { page = new URL(url); } catch { /* checked above */ }
        const button = SIGNINS().buttonFrameProvider(page?.hostname, page?.pathname);
        if (button ? button !== message.provider : SIGNINS().providerOfPage(page?.hostname, page?.pathname)) return { status: "ignored" };
      }
      flows.click({ tabId, provider: message.provider, at: Date.now() });
    } else {
      if (!flows.flowOf(tabId)) return { status: "ignored" };
      flows.account({ tabId, url, account: typeof message.account === "string" ? message.account.slice(0, 512) : "",
        chosen: message.chosen === true, cancel: message.cancel === true, homeUrl: sender.tab.url, at: Date.now() });
      const flow = flows.flowOf(tabId);
      if (flow?.kind === "onetap" && flow.phase === "returned") setTimeout(() => void settleSignIn(tabId), SIGNINS().SETTLE_MS + 100);
    }
    await keepSignInFlows();
    return { status: "ok" };
  });
}

/** The methods remembered for the site of `origin`: { status, site, methods }. Cached for 30 seconds. */
function querySignIns(origin, { fresh = false } = {}) {
  const hit = signInCache.get(origin);
  if (!fresh && hit && Date.now() - hit.at < SIGNIN_CACHE_MS) return hit.promise;
  const entry = { at: Date.now(), promise: (async () => {
    try {
      const response = await native("query_sign_ins", origin);
      if (response?.status === "ok" && response.signIns && typeof response.signIns.site === "string") {
        const known = new Set(SIGNINS()?.PROVIDERS.map((provider) => provider.id) || []);
        const methods = (Array.isArray(response.signIns.methods) ? response.signIns.methods : [])
          .filter((method) => known.has(method?.provider))
          .map((method) => ({ provider: method.provider, account: clip(method.account), lastUsedAt: Number(method.lastUsedAt) || 0 }));
        return { status: "ok", site: clip(response.signIns.site, 253), methods };
      }
      if (["disabled", "locked"].includes(response?.status)) return { status: response.status, methods: [] };
      if (response?.status === "desktop_unavailable") return { status: "offline", methods: [] };
      return { status: "none", methods: [] };
    } catch (error) {
      return { status: hostErrorStatus(error), methods: [] };
    }
  })() };
  signInCache.set(origin, entry);
  while (signInCache.size > 32) signInCache.delete(signInCache.keys().next().value);
  return entry.promise;
}

async function recordSignIn(origin, provider, account) {
  signInCache.delete(origin);
  try { return await native("record_sign_in", origin, { signIn: { provider, ...(account ? { account } : {}) } }); }
  catch { return { status: "desktop_unavailable" }; }
}

/** Reminders for a page: the most recent methods of its site, or none. */
async function signInReminders(origin, { fresh = false } = {}) {
  if (!SIGNINS() || !(await signInsSupported())) return { status: "unsupported", methods: [] };
  const answer = await querySignIns(origin, { fresh });
  return { status: answer.status, site: answer.site, methods: answer.methods.slice(0, MAX_SIGNIN_REMINDERS) };
}

const sameAccount = (left, right) => String(left || "").trim().toLowerCase() === String(right || "").trim().toLowerCase();
/** Already remembered: the same provider and account, or the provider when the account is not known now. */
const knownMethod = (methods, provider, account) => methods.some((method) => method.provider === provider && (!account || sameAccount(method.account, account)));

function signInPromptView(prompt) {
  return { id: prompt.id, kind: "signin", provider: prompt.provider, providerName: SIGNINS()?.nameOf(prompt.provider) || prompt.provider,
    host: prompt.site, account: prompt.account || "", locked: Boolean(prompt.locked) };
}

/** A finished sign-in: remember it quietly when it is already known, else ask on the landing page. */
async function offerSignIn(found) {
  if (!(await signInsSupported())) return;
  const tab = await tabOf(found.tabId);
  if (!tab || tab.incognito) return;
  let account = found.account;
  // The account typed on the provider's own sign-in page (sign-in steps), when its page showed none.
  if (!account && found.providerOrigin) account = SIGNINS().cleanAccount(await stepName({ tabId: found.providerTabId, origin: found.providerOrigin }));
  const answer = await querySignIns(found.origin, { fresh: true });
  if (["disabled", "none"].includes(answer.status)) return;
  const site = answer.site || hostOf(found.origin).replace(/^www\./, "");
  const settings = await readSettings();
  if (settings.neverSignIn.includes(site)) return;
  if (answer.status === "ok" && knownMethod(answer.methods, found.provider, account)) {
    const saved = await recordSignIn(found.origin, found.provider, account);
    void logEvent("signin_used", saved?.status || "empty", found.origin);
    return;
  }
  const prompts = await readPrompts();
  if (prompts[found.tabId] && !prompts[found.tabId].signin) return; // a login or card prompt is open there
  prompts[found.tabId] = { id: crypto.randomUUID(), signin: true, origin: found.origin, site, provider: found.provider, account,
    createdAt: Date.now(), locked: answer.status !== "ok" };
  await writePrompts(prompts);
  void logEvent("signin_detected", found.evidence, found.origin);
  if (onSite(tab.url || "", site)) {
    await chrome.tabs.sendMessage(found.tabId, { target: "nuvori-top", action: "show_prompt", prompt: signInPromptView(prompts[found.tabId]), theme: settings.theme },
      { frameId: 0 }).catch(() => {});
  }
}

/** The answer to the sign-in card: Save (with the account as the user left it), Not now, Never for this site. */
async function handleSignInApprove(page, message, prompts, prompt) {
  if (prompt.id !== message.id || !onSite(page.origin, prompt.site)) return { status: "missing", message: "This prompt expired." };
  const finish = async () => { delete prompts[page.tabId]; await writePrompts(prompts); };
  if (message.decision === "dismiss" || message.decision === "never") {
    await finish();
    if (message.decision === "never") await addToList("neverSignIn", prompt.site);
    void logEvent(`signin_${message.decision}`, "ok", page.origin);
    return { status: message.decision === "never" ? "never_signin" : "dismissed" };
  }
  if (message.decision !== "save") return { status: "error", message: "Unknown choice." };
  // The user may type any name here; the app checks it again.
  const account = typeof message.account === "string" ? message.account.replace(/[\p{Cc}\p{Cf}]/gu, "").trim().slice(0, 256) : prompt.account;
  const response = await recordSignIn(prompt.origin, prompt.provider, account);
  void logEvent("signin_save", response?.status || "empty", page.origin);
  if (response?.status === "saved") { await finish(); return { status: "remembered" }; }
  if (["locked", "desktop_unavailable"].includes(response?.status)) {
    prompt.createdAt = Date.now();
    prompt.account = account;
    await writePrompts(prompts);
    void requestUnlock();
    return { status: "locked_details", message: "Unlock Nuvori in its window, then choose Save again." };
  }
  await finish();
  if (response?.status === "disabled") return { status: "error", message: "Remembering sign-in methods is off in Nuvori's settings." };
  return { status: "error", message: response?.message || "Nuvori couldn't remember this sign-in." };
}

// ---------------------------------------------------------------------------
// Account metadata cache. Selection tokens stay in this worker; pages only
// ever see { id, title, username }.

const queryCache = new Map();

function queryOrigin(tabId, origin, { fresh = false } = {}) {
  const key = `${tabId}|${origin}`;
  const hit = queryCache.get(key);
  if (!fresh && hit) {
    const ttl = hit.status === "ok" || hit.status === undefined ? QUERY_TTL_OK_MS : QUERY_TTL_OTHER_MS;
    if (Date.now() - hit.at < ttl) return hit.promise;
  }
  const entry = { at: Date.now(), status: undefined, promise: undefined };
  entry.promise = (async () => {
    let result;
    try {
      const response = await native("query_credentials", origin);
      if (response?.iconWanted === true) void captureSiteIcon(tabId, origin);
      if (response?.status === "ok" && Array.isArray(response.credentials)) {
        result = { status: "ok", credentials: response.credentials.filter((choice) =>
          typeof choice?.id === "string" && choice.id && typeof choice.selectionToken === "string") };
      } else if (response?.status === "locked") result = { status: "locked", credentials: [] };
      else if (response?.status === "desktop_unavailable") result = { status: "offline", credentials: [] };
      else result = { status: "error", credentials: [] };
    } catch (error) {
      result = { status: hostErrorStatus(error), credentials: [] };
    }
    entry.status = result.status;
    entry.at = Date.now();
    return result;
  })();
  queryCache.set(key, entry);
  while (queryCache.size > 64) queryCache.delete(queryCache.keys().next().value);
  return entry.promise;
}

function forgetQueries(tabId) {
  for (const key of [...queryCache.keys()]) if (key.startsWith(`${tabId}|`)) queryCache.delete(key);
}

// ---------------------------------------------------------------------------
// Cards, addresses and authenticator codes. As with logins, selection tokens stay in this
// worker; pages get { id, title, subtitle } and, after a pick, only that item's fields.

const itemCache = new Map();
// A filled card's security-code token, until the page asks for the code: "tab|origin|id" -> { token, at }.
const cardCodeTokens = new Map();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** A card's own color from the host: an opaque ARGB whole number, or nothing. */
const cardColor = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff ? value : undefined;
const clip = (value, max = 256) => typeof value === "string" ? value.slice(0, max) : "";
/** The parts of an address a field can hold, as the content script names them. */
const PROFILE_ROLES = ["name", "given", "family", "email", "phone", "address1", "address2", "unit", "city", "state", "postalCode", "country"];
const PREVIEW_KEYS = ["name", "email", "phone", "address1", "address2", "unit", "city", "state", "postalCode", "country"];
/** An address's values from the host, for its suggestion row: known text parts only, or nothing. */
function profilePreview(value) {
  if (!value || typeof value !== "object") return undefined;
  const preview = {};
  for (const key of PREVIEW_KEYS) if (typeof value[key] === "string" && value[key].trim()) preview[key] = value[key].trim().slice(0, 200);
  return Object.keys(preview).length ? preview : undefined;
}

function queryItems(tabId, origin, kind, all = false, { fresh = false } = {}) {
  const key = `${tabId}|${origin}|${kind}|${all ? "all" : "match"}`;
  const hit = itemCache.get(key);
  if (!fresh && hit) {
    const ttl = hit.status === "ok" || hit.status === undefined ? QUERY_TTL_OK_MS : QUERY_TTL_OTHER_MS;
    if (Date.now() - hit.at < ttl) return hit.promise;
  }
  const entry = { at: Date.now(), status: undefined, promise: undefined };
  entry.promise = (async () => {
    let result;
    try {
      const response = await native("query_items", origin, all ? { kind, all: true } : { kind });
      if (response?.status === "ok" && Array.isArray(response.credentials)) {
        result = { status: "ok", items: response.credentials.filter((choice) =>
          typeof choice?.id === "string" && choice.id && typeof choice.selectionToken === "string") };
      } else if (response?.status === "locked") result = { status: "locked", items: [] };
      else if (response?.status === "desktop_unavailable") result = { status: "offline", items: [] };
      else result = { status: "error", items: [] };
    } catch (error) {
      result = { status: hostErrorStatus(error), items: [] };
    }
    entry.status = result.status;
    entry.at = Date.now();
    return result;
  })();
  itemCache.set(key, entry);
  while (itemCache.size > 64) itemCache.delete(itemCache.keys().next().value);
  return entry.promise;
}

function forgetItems(tabId, origin, kind) {
  for (const key of [...itemCache.keys()]) {
    if (key.startsWith(`${tabId}|`) && (!origin || key.startsWith(`${tabId}|${origin}|${kind}|`))) itemCache.delete(key);
  }
}

/** Does the host offer this kind? When it isn't known yet, ask (a locked app still lists features). */
async function itemsUnavailable(kind) {
  if ((await getFeatures()).includes(ITEM_FEATURES[kind])) return null;
  const status = await pingStatus();
  if ((featureCache?.list || []).includes(ITEM_FEATURES[kind])) return null;
  return status === "desktop_unavailable" ? "offline" : status === "host_missing" ? "host_missing" : "unsupported";
}

async function handleItems(page, message) {
  const kind = message.kind;
  const settings = await readSettings();
  if (!ITEM_FEATURES[kind]) return { status: "error" };
  if (!settings.inlineSuggestions || settings.noSuggest.includes(page.origin) || !settings.fill[kind]) return { status: "disabled", theme: settings.theme };
  const unavailable = await itemsUnavailable(kind);
  if (unavailable) return { status: unavailable, theme: settings.theme, items: [] };
  const result = await queryItems(page.tabId, page.origin, kind, false);
  // The code for the account used on the previous page comes first.
  const name = kind === "code" ? (await stepName(page)).toLowerCase() : "";
  const items = name
    ? firstBy(result.items, (choice) => `${choice.title || ""} ${choice.username || ""}`.toLowerCase().includes(name))
    : result.items;
  return {
    status: result.status, theme: settings.theme, host: hostOf(page.origin),
    items: items.slice(0, 50).map((choice) => ({
      id: choice.id, title: clip(choice.title), subtitle: clip(choice.username), color: cardColor(choice.color),
      preview: kind === "profile" ? profilePreview(choice.preview) : undefined,
    })),
  };
}

/**
 * Secrets go back only while the tab still shows the same page, and, for a field in a frame, while
 * that frame still shows the same site. `target` is a page ({ tabId, origin }) or a frame field
 * ({ tabId, origin, frameId, documentId, pageOrigin }).
 */
async function stillThere(target) {
  const tab = await chrome.tabs.get(target.tabId).catch(() => null);
  let top = "";
  try { top = new URL(tab?.url || "").origin; } catch { return false; }
  if (top !== (target.pageOrigin || target.origin)) return false;
  if (target.frameId === undefined) return true;
  const where = target.documentId ? { documentIds: [target.documentId] } : { frameIds: [target.frameId] };
  const results = await chrome.scripting.executeScript({ target: { tabId: target.tabId, ...where }, func: () => self.origin }).catch(() => []);
  return results?.[0]?.result === target.origin;
}

async function handleFillItem(page, message) {
  const { kind, id } = message;
  if (!ITEM_FEATURES[kind] || typeof id !== "string" || !id || id.length > 256) return { status: "error", message: "Choose it again." };
  // Only an item listed for this page's own site (never one from the every-code list) fills here.
  const find = async (fresh) => {
    const listing = await queryItems(page.tabId, page.origin, kind, false, { fresh });
    return { listing, choice: listing.items.find((entry) => entry.id === id) };
  };
  let { listing, choice } = await find(false);
  if (!choice) ({ listing, choice } = await find(true));
  if (!choice) return { status: listing.status === "ok" ? "missing" : listing.status, message: "This item is no longer available." };
  let response;
  try {
    response = await native("fill_item", page.origin, { kind, credentialId: id, selectionToken: choice.selectionToken });
    if (response?.status === "selection_expired") {
      ({ choice } = await find(true));
      if (!choice) return { status: "missing", message: "This item is no longer available." };
      response = await native("fill_item", page.origin, { kind, credentialId: id, selectionToken: choice.selectionToken });
    }
  } catch (error) {
    forgetItems(page.tabId, page.origin, kind);
    return { status: hostErrorStatus(error) };
  }
  forgetItems(page.tabId, page.origin, kind); // Tokens are single use.
  if (response?.status === "locked") return { status: "locked" };
  if (response?.status === "desktop_unavailable") return { status: "offline" };
  const item = response?.item;
  if (response?.status !== "ok" || !item || item.id !== id || item.kind !== kind) return { status: "error", message: "Nuvori could not release this item. Try again." };
  if (!(await stillThere(page))) return { status: "error", message: "The page changed. Try again." };
  if (kind === "card" && item.card) {
    const key = `${page.tabId}|${page.origin}|${id}`;
    cardCodeTokens.delete(key);
    if (typeof item.cvvToken === "string" && item.cvvToken) cardCodeTokens.set(key, { token: item.cvvToken, at: Date.now() });
    while (cardCodeTokens.size > 32) cardCodeTokens.delete(cardCodeTokens.keys().next().value);
    const card = item.card;
    return { status: "ok", card: { number: clip(card.number, 19), name: clip(card.name, 200), expiry: clip(card.expiry, 5), network: clip(card.network, 40), hasCode: cardCodeTokens.has(key) } };
  }
  if (kind === "profile" && item.profile) {
    return { status: "ok", profile: Object.fromEntries(PROFILE_KEYS.map((key) => [key, clip(item.profile[key])])) };
  }
  if (kind === "code" && item.code && /^\d{6,8}$/.test(item.code.value)) {
    return { status: "ok", code: { value: item.code.value, secondsLeft: Number(item.code.secondsLeft) || 0 } };
  }
  return { status: "error", message: "Nuvori could not release this item. Try again." };
}

/**
 * A card's security code: Nuvori shows its own approval window (Windows Hello or the master
 * password), then this waits for the answer. The code comes back only to the same tab and site.
 */
async function handleCardCode(page, message) {
  const id = message.id;
  const key = `${page.tabId}|${page.origin}|${id}`;
  const saved = cardCodeTokens.get(key);
  cardCodeTokens.delete(key);
  if (typeof id !== "string" || !saved || Date.now() - saved.at > CARD_CODE_WAIT_MS) return { status: "expired" };
  const details = { kind: "card", credentialId: id, selectionToken: saved.token };
  let response;
  try {
    response = await native("request_cvv", page.origin, details);
    if (response?.status !== "pending") return { status: response?.status === "locked" ? "locked" : "expired" };
    const until = Date.now() + CARD_CODE_WAIT_MS;
    do {
      await sleep(CARD_CODE_POLL_MS);
      response = await native("fill_cvv", page.origin, details);
    } while (response?.status === "pending" && Date.now() < until);
  } catch (error) {
    return { status: hostErrorStatus(error) };
  }
  if (response?.status === "denied") return { status: "denied" };
  const code = response?.item?.card?.cvv;
  if (response?.status !== "ok" || typeof code !== "string" || !/^\d{3,4}$/.test(code)) return { status: "expired" };
  if (!(await stillThere(page))) return { status: "error", message: "The page changed. Try again." };
  return { status: "ok", code };
}

// ---------------------------------------------------------------------------
// Saving a card or address typed into a page ("save_details"). The native host seals it with
// DPAPI; the sealed copy lives in chrome.storage.session until the user answers the prompt.

function cardNetwork(digits) {
  if (/^4/.test(digits)) return "Visa";
  if (/^3[47]/.test(digits)) return "American Express";
  if (/^(5[1-5]|2(2[2-9][1-9]|2[3-9]|[3-6]|7[01]|720))/.test(digits)) return "Mastercard";
  if (/^(60(?!11)|81|82|508)/.test(digits)) return "RuPay";
  if (/^(6011|65|64[4-9])/.test(digits)) return "Discover";
  return "";
}

const cleanField = (value, max = 256) => typeof value === "string"
  ? value.replace(/\p{Cc}/gu, " ").replace(/\p{Cf}/gu, "").trim().slice(0, max) : "";

async function readDetailCaptures() {
  const saved = await chrome.storage.session?.get(DETAILS_KEY);
  const fresh = Date.now() - PROMPT_TTL_MS;
  return (Array.isArray(saved?.[DETAILS_KEY]) ? saved[DETAILS_KEY] : []).filter((item) => typeof item.createdAt === "number" && item.createdAt >= fresh);
}

async function writeDetailCaptures(items) {
  await chrome.storage.session?.set({ [DETAILS_KEY]: items.slice(-MAX_DETAIL_CAPTURES) });
}

function detailsPromptView(prompt) {
  return {
    id: prompt.id, kind: prompt.kind === "card" ? "save_card" : "save_profile", host: hostOf(prompt.origin),
    title: prompt.title, summary: prompt.summary, canTitle: true, locked: Boolean(prompt.locked),
  };
}

async function handleDetailsCapture(page, message) {
  const settings = await readSettings();
  if (!settings.saveDetails || settings.neverSave.includes(page.origin)) return { status: "never" };
  if (!(await getFeatures()).includes("save_details")) return { status: "unsupported" };
  const kind = message.kind;
  let fields;
  let summary;
  let title;
  if (kind === "card") {
    const number = typeof message.card?.number === "string" ? message.card.number : "";
    const expiry = typeof message.card?.expiry === "string" ? message.card.expiry : "";
    if (!/^\d{12,19}$/.test(number) || !(expiry === "" || /^(0[1-9]|1[0-2])\/\d{2}$/.test(expiry))) throw new Error("Invalid card fields");
    const name = cleanField(message.card.name, 200);
    const network = cardNetwork(number);
    fields = { card: { number, name, expiry, network } };
    title = `${network || "Card"} •••• ${number.slice(-4)}`;
    summary = [["Card", title], ["Expires", expiry], ["Name on card", name]].filter(([, value]) => value);
  } else if (kind === "profile") {
    const profile = Object.fromEntries(PROFILE_KEYS.map((key) => [key, cleanField(message.profile?.[key])]));
    if (!Object.values(profile).some(Boolean)) throw new Error("Invalid address fields");
    fields = { profile };
    title = profile.name || "Address";
    summary = [["Name", profile.name], ["Address", [profile.address1, profile.city, profile.postalCode].filter(Boolean).join(", ")],
      ["Email", profile.email], ["Phone", profile.phone]].filter(([, value]) => value);
  } else {
    throw new Error("Unknown details");
  }
  if (!captureAllowed(page)) return { status: "limited" };
  let sealed;
  try { sealed = await native("seal_details", page.origin, { kind, ...fields }); }
  catch { throw new Error("Open Nuvori on Windows to save these details."); }
  if (sealed?.status !== "sealed" || typeof sealed.sealedLogin !== "string") throw new Error("Open Nuvori on Windows to save these details.");
  const review = await native("review_details", page.origin, { sealedLogin: sealed.sealedLogin }).catch(() => ({ status: "offline" }));
  if (review?.status === "already_saved") return { status: "already_saved" };
  const id = crypto.randomUUID();
  const captures = (await readDetailCaptures()).filter((item) => item.tabId !== page.tabId);
  captures.push({ id, origin: page.origin, tabId: page.tabId, kind, sealed: sealed.sealedLogin, createdAt: Date.now() });
  await writeDetailCaptures(captures);
  const prompts = await readPrompts();
  prompts[page.tabId] = { id, origin: page.origin, details: true, kind, title, summary, createdAt: Date.now(), locked: review?.status !== "needs_save" };
  await writePrompts(prompts);
  return { status: "review", prompt: detailsPromptView(prompts[page.tabId]), theme: settings.theme };
}

async function handleDetailsApprove(page, message, prompts, prompt) {
  const decision = message.decision;
  const finish = async (captures) => {
    delete prompts[page.tabId];
    await writePrompts(prompts);
    await writeDetailCaptures(captures.filter((item) => item.id !== prompt.id));
  };
  const captures = await readDetailCaptures();
  const item = captures.find((entry) => entry.id === prompt.id && entry.origin === page.origin && entry.tabId === page.tabId);
  if (!item) { await finish(captures); return { status: "missing", message: "This prompt expired. Submit the form again to save." }; }
  if (decision === "dismiss" || decision === "never") {
    await finish(captures);
    if (decision === "never") await addToList("neverSave", page.origin);
    void logEvent(`details_${decision}`, "ok", page.origin);
    return { status: decision === "never" ? "never" : "dismissed" };
  }
  if (decision !== "save") return { status: "error", message: "Unknown choice." };
  const details = { sealedLogin: item.sealed };
  const title = cleanTitle(message.title);
  if (title) details.title = title;
  let response;
  try { response = await native("commit_details", page.origin, details); }
  catch { response = { status: "desktop_unavailable" }; }
  void logEvent("details_save", response?.status || "empty", page.origin);
  if (response?.status === "saved" || response?.status === "already_saved") { await finish(captures); return { status: "saved" }; }
  if (["locked", "desktop_unavailable", "retry"].includes(response?.status)) {
    // Keep the prompt and bring up Nuvori's unlock window; Save works again once it is open.
    prompt.createdAt = item.createdAt = Date.now();
    await writePrompts(prompts);
    await writeDetailCaptures(captures);
    void requestUnlock();
    return { status: "locked_details", message: "Unlock Nuvori in its window, then choose Save again." };
  }
  await finish(captures);
  return { status: "error", message: response?.message || "These details expired. Submit the form again to save." };
}

// ---------------------------------------------------------------------------
// Badge

async function setBadge(tabId, { status, count, pending }) {
  const text = pending ? "!" : count ? String(count) : status === "locked" ? "L" : "";
  const color = pending || status === "locked" ? BADGE.warning : BADGE.success;
  const title = pending ? "Nuvori: review a captured login"
    : count ? `Nuvori: ${count} saved login${count === 1 ? "" : "s"} for this site`
    : status === "locked" ? "Nuvori is locked"
    : status === "ok" ? "Nuvori: no saved login for this site"
    : "Nuvori: not connected";
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeTextColor?.({ tabId, color: BADGE.text });
  await chrome.action.setTitle({ tabId, title });
}

async function pageStatus(tab) {
  const parsed = new URL(tab.url);
  if (parsed.protocol !== "https:") return { status: "unsupported", count: 0 };
  const pending = (await readPending()).filter((item) => item.origin === parsed.origin && ["confirm", "review"].includes(item.state));
  const result = await queryOrigin(tab.id, parsed.origin);
  const count = result.status === "ok" ? result.credentials.length : 0;
  await setBadge(tab.id, { status: result.status, count, pending: pending.length });
  return { status: result.status, count, pending: pending.length };
}

async function refreshActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url?.startsWith("https://")) await pageStatus(tab);
}

// ---------------------------------------------------------------------------
// Unlock prompt ("unlock_prompt"). Nuvori shows its own small password window; the password
// never passes through the browser. When Nuvori isn't running, the native host starts it in
// the background first, and it stays in the Windows tray afterwards.

let unlockWatch = null;

/**
 * Returns "ok" (already unlocked), "locked" (window shown), "starting", "skipped" (this browser is
 * turned off for startup prompts in the app), or why it couldn't ask. `startup` marks a browser
 * start so the app can apply its per-browser setting; only apps that list "startup_browsers" get it.
 */
async function requestUnlock({ startup = false } = {}) {
  const status = await pingStatus();
  if (status === "ok") return "ok";
  if (!["locked", "desktop_unavailable"].includes(status)) return status;
  const features = await getFeatures();
  if (!features.includes("unlock_prompt")) return "unsupported";
  let response;
  try { response = await native("unlock_prompt", "", startup && features.includes("startup_browsers") ? { startup: true } : {}); } catch (error) { return hostErrorStatus(error); }
  const result = response?.status || "error";
  if (result === "locked" || result === "starting") watchForUnlock();
  return result; // "skipped" is a quiet no-op: nothing to watch
}

/** After asking, notice the unlock so badges and waiting logins update without a page reload. */
function watchForUnlock() {
  if (unlockWatch) return;
  const until = Date.now() + UNLOCK_WATCH_MS;
  const tick = async () => {
    const status = await pingStatus();
    if (status !== "ok" && Date.now() < until) { unlockWatch = setTimeout(tick, UNLOCK_POLL_MS); return; }
    unlockWatch = null;
    if (status === "ok") {
      void runInOrder(flushPending);
      void refreshActiveTab().catch(() => {});
    }
  };
  unlockWatch = setTimeout(tick, UNLOCK_POLL_MS);
}

/** Browser start: ask for the Nuvori password once, unless turned off in Settings. */
async function unlockOnStartup() {
  if (!(await readSettings()).unlockOnStartup) return;
  const result = await requestUnlock({ startup: true });
  void logEvent("startup_unlock", result, "");
}

// ---------------------------------------------------------------------------
// Encrypted pending queue (chrome.storage.local holds sealed logins only)

let nextWork = Promise.resolve();

function runInOrder(work) {
  const result = nextWork.then(work, work);
  nextWork = result.catch(() => {});
  return result;
}

/**
 * The queue has two parts. Unapproved captures (from page submits) live only in
 * chrome.storage.session, in memory, and expire with their 2-minute prompt. Only logins the
 * user approved (Save/Update while the vault is locked or offline, or the popup's manual save)
 * are written to chrome.storage.local. Unapproved items left in local storage by older
 * versions are dropped.
 */
async function readPending() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const stored = Array.isArray(result?.[STORAGE_KEY]) ? result[STORAGE_KEY] : [];
  const oldest = Date.now() - PENDING_MAX_AGE_MS;
  const approved = stored.filter((item) => !(typeof item.createdAt === "number" && item.createdAt < oldest) &&
    (!["confirm", "review"].includes(item.state) || item.approved === true)).map((item) => { delete item.transient; return item; });
  const saved = await chrome.storage.session?.get(CAPTURES_KEY);
  const fresh = Date.now() - PROMPT_TTL_MS;
  const captures = (Array.isArray(saved?.[CAPTURES_KEY]) ? saved[CAPTURES_KEY] : [])
    .filter((item) => typeof item.createdAt === "number" && item.createdAt >= fresh)
    .map((item) => ({ ...item, transient: true }));
  return [...approved, ...captures];
}

/** May this approved item move to chrome.storage.local without crowding out other sites? */
function roomToPersist(items, item) {
  const persisted = items.filter((entry) => !entry.transient && entry !== item);
  return persisted.length < MAX_PENDING && persisted.filter((entry) => entry.origin === item.origin).length < MAX_PENDING_PER_ORIGIN;
}

async function savePending(items) {
  const approved = items.filter((item) => !item.transient);
  const captures = items.filter((item) => item.transient).map(({ transient, ...item }) => item);
  await chrome.storage.local.set({ [STORAGE_KEY]: approved });
  await chrome.storage.session?.set({ [CAPTURES_KEY]: captures });
  const waiting = items.filter((item) => ["confirm", "review"].includes(item.state)).length;
  await chrome.action.setBadgeText({ text: waiting ? "!" : "" });
  await chrome.action.setBadgeBackgroundColor({ color: BADGE.warning });
}

/** Send one approved item to the vault. Never used for password replacement. */
async function commitItem(item) {
  const details = { sealedLogin: item.sealed };
  const features = await getFeatures();
  if (item.title && features.includes("login_title")) details.title = item.title;
  // "login_edit": the username the user corrected on the save card.
  if (typeof item.username === "string" && features.includes("login_edit")) details.username = item.username;
  let response;
  try { response = await native("commit_login", item.origin, details); }
  catch { return { outcome: "wait" }; }
  if (response?.status === "saved" || response?.status === "already_saved") return { outcome: response.status };
  if (response?.status === "account_exists") return { outcome: "review", choices: updateChoices(response) };
  if (response?.status === "invalid_request") return { outcome: "invalid" };
  return { outcome: "wait" }; // locked, desktop_unavailable, retry
}

async function flushPending() {
  const items = await readPending();
  let lastStatus = "none";
  for (let index = 0; index < items.length;) {
    const item = items[index];
    if (["review", "confirm"].includes(item.state)) { index++; continue; }
    const result = await commitItem(item);
    if (result.outcome === "saved" || result.outcome === "already_saved") {
      lastStatus = result.outcome;
      items.splice(index, 1);
      await savePending(items);
    } else if (result.outcome === "review") {
      item.state = "review";
      setChoices(item, result.choices);
      lastStatus = "review";
      await savePending(items);
      index++;
    } else if (result.outcome === "invalid") {
      // Expired (older than the host's limit) or bound to another site: it can never be saved.
      items.splice(index, 1);
      await savePending(items);
    } else {
      break;
    }
  }
  return { status: lastStatus, pending: items.length, review: items.filter((item) => item.state === "review").length };
}

/** Replace a saved password with explicit, single-use approval. Never retried automatically. */
async function applyUpdate(items, item, credentialId) {
  const choices = choicesOf(item);
  const choice = typeof credentialId === "string" ? choices.find((entry) => entry.id === credentialId)
    : choices.length === 1 ? choices[0] : undefined;
  if (!choice) return { status: "choose", message: choices.length ? "Choose which saved account to update." : "Refresh this account review before updating." };
  let response;
  try {
    response = await native("update_login", item.origin, { sealedLogin: item.sealed, credentialId: choice.id, selectionToken: choice.selectionToken });
  } catch {
    return { status: "error", unavailable: true, message: "Can't reach Nuvori for Windows. Open the app and try again." };
  }
  if (response?.status === "saved") {
    items.splice(items.indexOf(item), 1);
    await savePending(items);
    return { status: "saved" };
  }
  // A stale approval never retries the replacement automatically.
  if (["selection_expired", "account_exists"].includes(response?.status)) {
    const review = await native("review_login", item.origin, { sealedLogin: item.sealed }).catch(() => ({ status: "offline" }));
    if (review?.status === "already_saved") {
      items.splice(items.indexOf(item), 1);
      await savePending(items);
      return { status: "saved" };
    }
    if (review?.status === "needs_save") { item.state = "confirm"; setChoices(item, []); }
    else setChoices(item, updateChoices(review));
    await savePending(items);
    return { status: "review", message: "The account changed or approval expired. Review it, then choose Update again." };
  }
  if (response?.status === "locked" || response?.status === "desktop_unavailable") {
    return { status: "error", unavailable: true, message: "Nuvori is locked. Unlock it on Windows, then choose Update again." };
  }
  return { status: "error", message: response?.message || "Unlock the Windows vault, then review this update again." };
}

// ---------------------------------------------------------------------------
// In-page prompts: kept in chrome.storage.session (memory only, not readable by
// content scripts) and bound to one tab + origin for PROMPT_TTL_MS.

async function readPrompts() {
  const store = chrome.storage.session;
  if (!store) return {};
  const saved = await store.get(PROMPTS_KEY);
  const prompts = saved?.[PROMPTS_KEY] && typeof saved[PROMPTS_KEY] === "object" ? saved[PROMPTS_KEY] : {};
  const now = Date.now();
  for (const key of Object.keys(prompts)) if (!(now - prompts[key]?.createdAt <= PROMPT_TTL_MS)) delete prompts[key];
  return prompts;
}

async function writePrompts(prompts) {
  await chrome.storage.session?.set({ [PROMPTS_KEY]: prompts });
}

function promptView(prompt, item, features = []) {
  const choices = publicChoices(item);
  const kind = item.state === "confirm" ? "save" : item.state === "review" ? (choices.length ? "update" : "conflict") : "queued";
  return {
    id: item.id, kind, host: hostOf(item.origin),
    username: kind === "update" && choices.length === 1 ? choices[0].username : prompt.username,
    choices: kind === "update" ? choices : [],
    title: prompt.title || hostOf(item.origin).replace(/^www\./, ""),
    canTitle: kind === "save" && features.includes("login_title"),
    canEditUsername: kind === "save" && features.includes("login_edit"),
    locked: Boolean(prompt.locked),
  };
}

/**
 * The pending item this exact page (tab + origin) may act on, or null. A login typed into a frame
 * is saved for the frame's site; its prompt shows on the page around it (`pageOrigin`).
 */
async function promptFor(page, id) {
  const prompts = await readPrompts();
  const prompt = prompts[page.tabId];
  if (!prompt || (prompt.pageOrigin || prompt.origin) !== page.origin || (id !== undefined && prompt.id !== id)) return { prompts, prompt: null };
  const items = await readPending();
  const item = items.find((entry) => entry.id === prompt.id && entry.origin === prompt.origin && entry.tabId === page.tabId);
  if (!item) {
    delete prompts[page.tabId];
    await writePrompts(prompts);
    return { prompts, prompt: null };
  }
  return { prompts, prompt, items, item };
}

// ---------------------------------------------------------------------------
// Messages from content scripts. The origin always comes from the browser-supplied sender,
// never from the message.

function pageSender(sender) {
  if (!sender?.tab || typeof sender.tab.id !== "number" || sender.frameId !== 0 || typeof sender.url !== "string") return null;
  let parsed;
  try { parsed = new URL(sender.url); } catch { return null; }
  if (parsed.protocol !== "https:") return null;
  if (sender.origin !== undefined && sender.origin !== parsed.origin) return null;
  return { tabId: sender.tab.id, origin: parsed.origin, url: sender.url };
}

/**
 * A frame's HTTPS origin. A frame the page built without an address of its own (about:blank,
 * about:srcdoc) has its creator's origin; the browser reports it as `sender.origin`.
 */
function senderOrigin(sender) {
  let parsed;
  try { parsed = new URL(sender.url); } catch { return null; }
  if (parsed.protocol === "https:") return sender.origin === undefined || sender.origin === parsed.origin ? parsed.origin : null;
  if (parsed.protocol !== "about:" || typeof sender.origin !== "string") return null;
  try {
    const origin = new URL(sender.origin);
    return origin.protocol === "https:" && origin.origin === sender.origin ? sender.origin : null;
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Forms inside frames: logins (a site's own sign-in frame, or another site's), payment, address
// and code forms. The frame draws nothing: it reports a focused field, the top page shows the list
// next to that frame, and the chosen item goes only to that frame, for the frame's own site, like
// a browser's password manager. A card also goes to the other frames of the same origin, because
// payment forms often put number and expiry in separate frames. A card's security code is not
// filled in a frame.

const FRAME_DETAILS = ["login", "card", "profile", "code"];
const FRAME_FIELD_TTL_MS = 60 * 1000;
const MAX_FILL_FRAMES = 16;
/** tabId -> the last frame field the user focused in that tab: { frameId, documentId, origin, detail, anchorFrameId, want, at }. */
const frameFields = new Map();

function frameSender(sender) {
  if (!sender?.tab || typeof sender.tab.id !== "number" || typeof sender.frameId !== "number" || sender.frameId === 0) return null;
  if (typeof sender.url !== "string") return null;
  const origin = senderOrigin(sender);
  if (!origin) return null;
  return { tabId: sender.tab.id, frameId: sender.frameId, origin, documentId: typeof sender.documentId === "string" ? sender.documentId : undefined };
}

const finite = (value, limit) => typeof value === "number" && Number.isFinite(value) && Math.abs(value) <= limit;

/** The page shown in a tab: its origin and address, or null for anything but an HTTPS page. */
async function tabPage(tabId) {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  try {
    const url = new URL(tab?.url || "");
    return url.protocol === "https:" ? { tabId, origin: url.origin, url: url.href } : null;
  } catch { return null; }
}

async function handleFrameField(frame, message) {
  const rect = message.rect;
  if (!FRAME_DETAILS.includes(message.detail) || !rect || !["left", "top"].every((key) => finite(rect[key], 100_000)) ||
      !["width", "height"].every((key) => finite(rect[key], 10_000) && rect[key] >= 0)) return { status: "error" };
  const page = await tabPage(frame.tabId);
  if (!page) return { status: "none" };
  const settings = await readSettings();
  const detail = message.detail;
  if (!settings.inlineSuggestions || (detail !== "login" && !settings.fill[detail]) ||
      settings.noSuggest.includes(page.origin) || settings.noSuggest.includes(frame.origin)) return { status: "disabled" };
  // The frame posted this one-time code to its parent window; the top page finds the frame element by it.
  if (typeof message.nonce !== "string" || !/^[0-9a-f]{32}$/.test(message.nonce)) return { status: "error" };
  const field = {
    frameId: frame.frameId, documentId: frame.documentId, origin: frame.origin, detail, anchorFrameId: frame.frameId,
    want: message.want === "username" ? "username" : "both", at: Date.now(),
  };
  frameFields.set(frame.tabId, field);
  while (frameFields.size > 64) frameFields.delete(frameFields.keys().next().value);
  const shown = await chrome.tabs.sendMessage(frame.tabId, {
    target: "nuvori-top", action: "frame_field", frameId: frame.frameId, nonce: message.nonce, detail,
    quiet: message.quiet === true, force: message.force === true, host: hostOf(frame.origin),
    role: detail === "profile" && PROFILE_ROLES.includes(message.role) ? message.role : undefined,
    rect: { left: rect.left, top: rect.top, width: rect.width, height: rect.height },
  }, { frameId: 0 }).catch(() => null);
  return { status: shown?.status === "ok" ? "ok" : "none" };
}

/** Where a list or a fill applies: the page itself, or the frame field it showed a list for (same tab, still fresh). */
function scopeOf(page, message, kind) {
  if (message.frameId === undefined) return page;
  const field = frameFields.get(page.tabId);
  if (!Number.isInteger(message.frameId) || !field || field.anchorFrameId !== message.frameId ||
      Date.now() - field.at > FRAME_FIELD_TTL_MS || (kind && field.detail !== kind)) return null;
  return { tabId: page.tabId, origin: field.origin, frameId: field.frameId, documentId: field.documentId, pageOrigin: page.origin, url: page.url, field };
}

const toFrame = (target, payload) => chrome.tabs.sendMessage(target.tabId, payload,
  target.documentId ? { documentId: target.documentId } : { frameId: target.frameId }).catch(() => null);

/** Frames of the tab whose origin is `origin`, by asking each frame (no extra permission). */
async function framesOf(tabId, origin) {
  const results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: () => self.origin }).catch(() => []);
  return (results || []).filter((entry) => entry.frameId !== 0 && entry.result === origin).map((entry) => entry.frameId).slice(0, MAX_FILL_FRAMES);
}

/** The top page chose an item or a login for the frame field the user focused. */
async function handleFillFrame(page, message) {
  const kind = message.kind;
  const target = scopeOf(page, message, kind);
  if (!target) return { status: "missing", message: "Click the field again." };
  if (kind === "login") {
    // Only a login listed for the frame's own site fills here (no cross-site "all" fill).
    if (message.all === true) return { status: "disabled" };
    const result = await handleFill(target, { credentialId: message.id, want: target.field.want });
    if (result.status !== "ok") return result;
    const payload = { target: "nuvori-frame", action: "fill_login", username: result.username, password: result.password };
    result.password = undefined;
    const reply = await toFrame(target, payload);
    payload.password = undefined;
    frameFields.delete(page.tabId);
    if (!(reply?.status === "ok" && Number.isInteger(reply.filled) && reply.filled > 0)) return { status: "error", message: "Couldn't fill the form in this frame." };
    return { status: "ok", filled: reply.filled };
  }
  if (!ITEM_FEATURES[kind]) return { status: "error", message: "Choose it again." };
  const result = await handleFillItem(target, { kind, id: message.id });
  // A security code is approved per page and filled only where it was asked for.
  cardCodeTokens.delete(`${target.tabId}|${target.origin}|${message.id}`);
  if (result.status !== "ok") return result;
  const payload = { target: "nuvori-frame", action: "fill_item", kind };
  if (result.card) payload.card = { number: result.card.number, name: result.card.name, expiry: result.card.expiry };
  if (result.profile) payload.profile = result.profile;
  if (result.code) payload.code = result.code;
  let filled = 0;
  const reply = await toFrame(target, payload);
  if (reply?.status === "ok" && Number.isInteger(reply.filled)) filled += reply.filled;
  if (kind === "card") {
    for (const frameId of (await framesOf(page.tabId, target.origin)).filter((id) => id !== target.frameId)) {
      const other = await chrome.tabs.sendMessage(page.tabId, payload, { frameId }).catch(() => null);
      if (other?.status === "ok" && Number.isInteger(other.filled)) filled += other.filled;
    }
  }
  frameFields.delete(page.tabId);
  if (!filled) return { status: "error", message: "Couldn't fill the form in this frame." };
  return { status: "ok", filled, codeLeft: Boolean(result.card?.hasCode) };
}

/** Messages from frames: a focused field, an account name typed on a sign-in step, a submitted login. */
async function handleFrameMessage(frame, message) {
  if (message.action === "frame_field") return handleFrameField(frame, message);
  if (message.action === "frame_blur") {
    const field = frameFields.get(frame.tabId);
    if (!field || field.frameId !== frame.frameId) return { status: "ok" };
    await chrome.tabs.sendMessage(frame.tabId, { target: "nuvori-top", action: "frame_blur", frameId: field.anchorFrameId }, { frameId: 0 }).catch(() => null);
    return { status: "ok" };
  }
  const page = await tabPage(frame.tabId);
  if (!page) return { status: "error" };
  const target = { tabId: frame.tabId, origin: frame.origin, url: page.url, pageOrigin: page.origin };
  if (message.action === "remember_username") {
    await rememberStep(target, message.username);
    return { status: "ok" };
  }
  // A login typed into a frame is saved for the frame's site; the save card shows on the top page.
  const result = await runInOrder(() => handleCapture(target, message));
  const show = (payload) => chrome.tabs.sendMessage(frame.tabId, { target: "nuvori-top", ...payload }, { frameId: 0 }).catch(() => null);
  if (result?.status === "review" && result.prompt) {
    await show({ action: "show_prompt", prompt: result.prompt, theme: result.theme });
    return { status: "shown" };
  }
  if (result?.status === "already_saved") {
    await show({ action: "show_notice", tone: "success", text: "Already saved in Nuvori.", theme: (await readSettings()).theme });
    return { status: "shown" };
  }
  return result;
}

const FRAME_ACTIONS = ["frame_field", "frame_blur", "remember_username", "capture_submitted_login"];

// "Already saved" after a sign-in, for the next page of that site in the same tab. Memory only;
// it carries no account detail, only that the submitted login matched the vault.
const SAVED_NOTE_MS = 15 * 1000;
const savedNotes = new Map(); // tabId -> { origin, at }
function noteSaved(page) {
  savedNotes.set(page.tabId, { origin: page.origin, at: Date.now() });
  while (savedNotes.size > 64) savedNotes.delete(savedNotes.keys().next().value);
}
function takeSavedNote(page) {
  const note = savedNotes.get(page.tabId);
  if (!note) return false;
  savedNotes.delete(page.tabId);
  return note.origin === page.origin && Date.now() - note.at < SAVED_NOTE_MS;
}

const PAGE_ACTIONS = ["page_status", "open_popup", "capture_submitted_login", "remember_username", "inline_query", "inline_fill", "inline_pending", "inline_approve",
  "inline_dont_suggest", "inline_unlock", "inline_items", "inline_fill_item", "inline_card_code", "capture_details", "inline_fill_frame",
  "inline_all_logins", "inline_fill_any", "signin_reminders"];

// Capture rate limits: page scripts can submit forms (requestSubmit) during a user gesture, so
// each tab gets one capture per 5 seconds and each site four per minute.
const captureLog = { tabs: new Map(), origins: new Map() };

function captureAllowed(page) {
  const time = Date.now();
  const last = captureLog.tabs.get(page.tabId);
  if (last !== undefined && time - last < CAPTURE_TAB_INTERVAL_MS) return false;
  const recent = (captureLog.origins.get(page.origin) || []).filter((at) => time - at < CAPTURE_ORIGIN_WINDOW_MS);
  if (recent.length >= CAPTURE_ORIGIN_LIMIT) return false;
  recent.push(time);
  captureLog.origins.set(page.origin, recent);
  captureLog.tabs.set(page.tabId, time);
  for (const map of [captureLog.tabs, captureLog.origins]) while (map.size > 256) map.delete(map.keys().next().value);
  return true;
}

async function handleCapture(page, message) {
  const { password } = message;
  let { username } = message;
  // An empty username is a password-only form; a whitespace-only one is never valid.
  if (typeof username !== "string" || (username !== "" && !username.trim()) || username.length > 1024 ||
      typeof password !== "string" || !password || password.length > 4096) throw new Error("Invalid login fields");
  // A password page without an account field: use the name from the previous page of this
  // sign-in (same tab, same site). The save card shows it and lets the user correct it.
  if (username === "") username = await stepName(page);
  const settings = await readSettings();
  if (settings.neverSave.includes(page.origin)) return { status: "never" };
  const features = await getFeatures();
  if (username === "" && !features.includes("password_only")) return { status: "unsupported" };
  if (!captureAllowed(page)) return { status: "limited" };
  let sealed;
  try { sealed = await native("seal_login", page.origin, { username: username.trim(), password }); }
  catch { throw new Error("Open Nuvori on Windows to save this login."); }
  if (sealed?.status !== "sealed" || typeof sealed.sealedLogin !== "string") throw new Error("Open Nuvori on Windows to save this login.");
  const review = await native("review_login", page.origin, { sealedLogin: sealed.sealedLogin }).catch(() => ({ status: "offline" }));
  if (review?.status === "already_saved") return { status: "already_saved" };
  const prompts = await readPrompts();
  let items = await readPending();
  // A newer submit on the same page replaces the earlier, unanswered capture.
  const previous = prompts[page.tabId];
  if (previous?.origin === page.origin) {
    items = items.filter((item) => !(item.transient && item.id === previous.id));
  }
  // One site keeps at most a few unanswered captures (oldest dropped), so it can't crowd out others.
  const sameSite = items.filter((item) => item.transient && item.origin === page.origin);
  for (const extra of sameSite.slice(0, Math.max(0, sameSite.length - MAX_CAPTURES_PER_ORIGIN + 1))) items.splice(items.indexOf(extra), 1);
  if (items.filter((item) => item.transient).length >= MAX_CAPTURES) throw new Error("Answer the open Nuvori prompts before saving more.");
  const item = {
    id: crypto.randomUUID(), origin: page.origin, sealed: sealed.sealedLogin,
    state: review?.status === "account_exists" ? "review" : "confirm",
    tabId: page.tabId, createdAt: Date.now(), transient: true,
  };
  setChoices(item, updateChoices(review));
  items.push(item);
  await savePending(items);
  const locked = !["account_exists", "needs_save"].includes(review?.status);
  prompts[page.tabId] = { id: item.id, origin: page.origin, username: username.trim(), title: cleanTitle(message.titleHint).slice(0, 80), createdAt: Date.now(), locked,
    ...(page.pageOrigin && page.pageOrigin !== page.origin ? { pageOrigin: page.pageOrigin } : {}) };
  await writePrompts(prompts);
  await pageStatus({ id: page.tabId, url: page.url }).catch(() => {});
  return { status: "review", prompt: promptView(prompts[page.tabId], item, features), theme: settings.theme };
}

async function handleApprove(page, message) {
  const decision = message.decision;
  if (typeof message.id !== "string" || !["save", "update", "dismiss", "never"].includes(decision)) return { status: "error", message: "Unknown choice." };
  const current = (await readPrompts());
  if (current[page.tabId]?.signin) return handleSignInApprove(page, message, current, current[page.tabId]);
  if (current[page.tabId]?.details) {
    const prompt = current[page.tabId];
    if (prompt.origin !== page.origin || prompt.id !== message.id) return { status: "missing", message: "This prompt expired." };
    return handleDetailsApprove(page, message, current, prompt);
  }
  const { prompts, prompt, items, item } = await promptFor(page, message.id);
  if (!prompt) return { status: "missing", message: "This prompt expired. Open Nuvori to review pending logins." };
  const finish = async () => { delete prompts[page.tabId]; await writePrompts(prompts); };
  const allowed = { save: ["confirm"], never: ["confirm"], update: ["review"], dismiss: ["confirm", "review"] }[decision];
  if (!allowed.includes(item.state)) return { status: "error", message: "This login changed. Open Nuvori to review it." };

  if (decision === "dismiss" || decision === "never") {
    items.splice(items.indexOf(item), 1);
    await savePending(items);
    if (decision === "never") await addToList("neverSave", item.origin);
    await finish();
    void logEvent(`inline_${decision}`, "ok", page.origin);
    return { status: decision === "never" ? "never" : "dismissed" };
  }

  if (decision === "update") {
    if (!choicesOf(item).length) return { status: "error", message: "Open Nuvori to review this account." };
    const result = await applyUpdate(items, item, message.credentialId);
    if (result.status === "saved") { await finish(); forgetQueries(page.tabId); return { status: "updated" }; }
    if (result.status === "review") {
      prompt.createdAt = item.createdAt = Date.now();
      await savePending(items);
      await writePrompts(prompts);
      return { ...result, prompt: promptView(prompt, item, await getFeatures()) };
    }
    if (result.unavailable && item.transient) {
      // The user chose Update while the vault was locked: keep it (encrypted) for the popup to finish.
      if (!roomToPersist(items, item)) return { status: "error", message: "Too many logins are waiting for this site. Review them in Nuvori first." };
      delete item.transient;
      item.approved = true;
      setChoices(item, []); // Update tokens expire; the popup reviews again before replacing.
      await savePending(items);
      await finish();
      return { status: "queued_update" };
    }
    return { status: result.status, message: result.message };
  }

  // save: approve this capture (with the name the user chose), then try to commit it right away.
  // It stays in memory unless the vault can't take it now.
  delete item.state;
  setChoices(item, []);
  item.approved = true;
  const title = cleanTitle(message.title);
  if (title) item.title = title;
  if (typeof message.username === "string" && (await getFeatures()).includes("login_edit")) {
    const username = message.username.replace(/\p{Cc}/gu, "").trim();
    if (username.length <= 1024) item.username = username;
  }
  const result = await commitItem(item);
  if (result.outcome === "saved" || result.outcome === "already_saved") {
    items.splice(items.indexOf(item), 1);
    await savePending(items);
    await finish();
    forgetQueries(page.tabId); // The new login shows in the list at once.
    return { status: "saved" };
  }
  if (result.outcome === "review") {
    item.state = "review";
    setChoices(item, result.choices);
    prompt.createdAt = item.createdAt = Date.now();
    await savePending(items);
    await writePrompts(prompts);
    const message = result.choices.length > 1 ? "Choose which saved account to update." : "A different password is saved for this account.";
    return { status: "review", message, prompt: promptView(prompt, item, await getFeatures()) };
  }
  if (result.outcome === "invalid") {
    items.splice(items.indexOf(item), 1);
    await savePending(items);
    await finish();
    return { status: "error", message: "This login expired. Sign in again to save it." };
  }
  if (!roomToPersist(items, item)) {
    items.splice(items.indexOf(item), 1);
    await savePending(items);
    await finish();
    return { status: "error", message: "Too many logins are waiting for this site. Review them in Nuvori first." };
  }
  delete item.transient;
  await savePending(items);
  await finish();
  return { status: "queued" };
}

/**
 * Release one login for `page` (a page or a frame field). `all`: the user picked it from every
 * saved login ("Search all logins"), so it may be saved for another site.
 */
async function handleFill(page, message) {
  const { credentialId } = message;
  if (typeof credentialId !== "string" || !credentialId || credentialId.length > 256) return { status: "error", message: "Choose an account again." };
  const key = `${page.tabId}|${page.origin}`;
  const list = (fresh) => queryOrigin(page.tabId, page.origin, { fresh });
  const cache = queryCache;
  let listing = await list(false);
  let choice = listing.credentials.find((entry) => entry.id === credentialId);
  if (!choice) {
    listing = await list(true);
    choice = listing.credentials.find((entry) => entry.id === credentialId);
    if (!choice) return { status: listing.status === "ok" ? "missing" : listing.status, message: "This account is no longer available for this site." };
  }
  let response;
  try {
    response = await native("fill_credential", page.origin, { credentialId, selectionToken: choice.selectionToken });
    if (response?.status === "selection_expired") {
      const refreshed = await list(true);
      const replacement = refreshed.credentials.find((entry) => entry.id === credentialId);
      if (!replacement) return { status: refreshed.status === "ok" ? "missing" : refreshed.status, message: "This account is no longer available for this site." };
      response = await native("fill_credential", page.origin, { credentialId, selectionToken: replacement.selectionToken });
    }
  } catch (error) {
    cache.delete(key);
    return { status: hostErrorStatus(error) };
  }
  // Tokens are single use; the next listing must ask the host again.
  cache.delete(key);
  if (response?.status === "locked") return { status: "locked" };
  if (response?.status === "desktop_unavailable") return { status: "offline" };
  if (response?.status !== "ok" || !response.credential || response.credential.id !== credentialId) {
    return { status: "error", message: "Nuvori could not release this login. Try again." };
  }
  // Release the secret only if the same tab (and frame) still shows the same site.
  if (!(await stillThere(page))) return { status: "error", message: "The page changed. Try again." };
  await rememberStep(page, response.credential.username);
  return {
    status: "ok",
    username: typeof response.credential.username === "string" ? response.credential.username : "",
    password: message.want === "username" ? undefined : response.credential.password,
  };
}

async function handlePageMessage(page, message) {
  switch (message.action) {
    case "page_status":
      return pageStatus({ id: page.tabId, url: page.url });
    case "open_popup":
      return chrome.action.openPopup().then(() => ({ status: "ok" }), () => ({ status: "error", message: "Click the Nuvori toolbar icon to continue." }));
    case "capture_submitted_login": {
      const result = await runInOrder(() => handleCapture(page, message));
      // Most sign-ins navigate at once, which would erase the page's "Already saved" note; the
      // next page of the same site in this tab shows it instead (once, within a few seconds).
      if (result?.status === "already_saved") noteSaved(page);
      return result;
    }
    case "inline_query": {
      const settings = await readSettings();
      const scope = scopeOf(page, message, "login");
      if (!scope) return { status: "missing", message: "Click the field again.", theme: settings.theme };
      if (!settings.inlineSuggestions || settings.noSuggest.includes(page.origin) || settings.noSuggest.includes(scope.origin)) return { status: "disabled", theme: settings.theme };
      const reminders = scope.origin === page.origin ? signInReminders(page.origin).catch(() => null) : null;
      const result = await queryOrigin(page.tabId, scope.origin);
      const signIns = (await reminders)?.methods || [];
      const text = (value) => typeof value === "string" ? value.slice(0, 256) : "";
      // The login for the account name used on the previous page comes first.
      const name = await stepName(scope);
      const used = (choice) => Boolean(name) && typeof choice.username === "string" && sameName(choice.username, name);
      return {
        status: result.status, theme: settings.theme, host: hostOf(scope.origin),
        accounts: firstBy(result.credentials, used).slice(0, 50).map((choice) => ({
          id: choice.id, title: text(choice.title), username: text(choice.username),
          ...(used(choice) ? { recent: true } : {}),
          // Saved for another page of this site (hosts with "related_logins").
          ...(choice.related === true ? { related: true } : {}),
          // A passkey for the same account is saved too (hosts with "passkey_mark").
          ...(choice.passkey === true ? { passkey: true } : {}),
        })),
        ...(signIns.length ? { signIns } : {}),
      };
    }
    case "signin_reminders": {
      const reminders = await signInReminders(page.origin);
      return { ...reminders, theme: (await readSettings()).theme };
    }
    case "remember_username":
      await rememberStep(page, message.username);
      return { status: "ok" };
    case "inline_fill": {
      const result = await handleFill(page, message);
      void logEvent("inline_fill", result.status, page.origin);
      return result;
    }
    case "inline_items": {
      // Every code (not only this site's) is a cross-site list: refused to pages on every browser.
      if (message.all === true || (LIMITED_PAGE_UI && message.kind !== "code")) return { status: "disabled" };
      const scope = scopeOf(page, message, message.kind);
      return scope ? handleItems(scope, message) : { status: "missing", message: "Click the field again." };
    }
    // Every saved login, and filling one saved for another site: cross-site, refused to pages on
    // every browser (older content scripts still send these).
    case "inline_all_logins":
    case "inline_fill_any":
      void logEvent(message.action, "disabled", page.origin);
      return { status: "disabled", theme: (await readSettings()).theme };
    case "inline_fill_item": {
      const result = await handleFillItem(page, message);
      void logEvent(`fill_${ITEM_FEATURES[message.kind] ? message.kind : "item"}`, result.status, page.origin);
      return result;
    }
    case "inline_card_code": {
      const result = await handleCardCode(page, message);
      void logEvent("fill_card_code", result.status, page.origin);
      return result;
    }
    case "capture_details":
      return runInOrder(() => handleDetailsCapture(page, message));
    case "inline_pending":
      return runInOrder(async () => {
        const prompts = await readPrompts();
        const details = prompts[page.tabId];
        if (details?.signin) {
          return onSite(page.origin, details.site) ? { status: "ok", prompt: signInPromptView(details), theme: (await readSettings()).theme } : { status: "none" };
        }
        if (details?.details) {
          const live = details.origin === page.origin && (await readDetailCaptures()).some((entry) => entry.id === details.id);
          return live ? { status: "ok", prompt: detailsPromptView(details), theme: (await readSettings()).theme } : { status: "none" };
        }
        const { prompt, item } = await promptFor(page);
        if (!prompt || !["confirm", "review"].includes(item.state)) {
          return takeSavedNote(page) ? { status: "notice", text: "Already saved in Nuvori.", theme: (await readSettings()).theme } : { status: "none" };
        }
        return { status: "ok", prompt: promptView(prompt, item, await getFeatures()), theme: (await readSettings()).theme };
      });
    case "inline_approve":
      return runInOrder(() => handleApprove(page, message));
    case "inline_fill_frame": {
      if (message.all === true || (LIMITED_PAGE_UI && !["login", "code"].includes(message.kind))) return { status: "disabled" };
      const result = await handleFillFrame(page, message);
      void logEvent(`fill_frame_${ITEM_FEATURES[message.kind] ? message.kind : "item"}`, result.status, page.origin);
      return result;
    }
    case "inline_dont_suggest":
      await addToList("noSuggest", page.origin);
      void logEvent("inline_dont_suggest", "ok", page.origin);
      return { status: "ok" };
    case "inline_unlock":
      forgetQueries(page.tabId);
      return { status: await requestUnlock() };
    default:
      return { status: "error" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target === "offscreen") return false;
  if ((message?.action === "signin_click" || message?.action === "signin_account") && typeof sender?.tab?.id === "number") {
    handleSignInMessage(sender, message).then(sendResponse, () => sendResponse({ status: "error" }));
    return true;
  }
  if (FRAME_ACTIONS.includes(message?.action) && typeof sender?.frameId === "number" && sender.frameId !== 0) {
    const frame = frameSender(sender);
    if (!frame) return false;
    handleFrameMessage(frame, message).then(sendResponse, (error) => sendResponse({ status: "error", message: error?.message || "Something went wrong." }));
    return true;
  }
  if (PAGE_ACTIONS.includes(message?.action)) {
    const page = pageSender(sender);
    if (!page) return false;
    handlePageMessage(page, message).then(sendResponse, (error) => sendResponse({ status: "error", message: error?.message || "Something went wrong." }));
    return true;
  }
  // Page scripts can only use the page actions above. Saving, replacement,
  // and queue management otherwise require the extension's own pages.
  if (sender.tab) return false;
  if (message?.action === "update_pending") {
    runInOrder(async () => {
      const items = await readPending();
      const item = items.find((entry) => entry.id === message.id);
      if (!item || item.state !== "review" || !choicesOf(item).length) return { status: "error", message: "Refresh this account review before updating." };
      const result = await applyUpdate(items, item, message.credentialId);
      if (result.unavailable && item.transient && roomToPersist(items, item)) {
        delete item.transient;
        item.approved = true;
        setChoices(item, []);
        await savePending(items);
        return { status: "queued_update", message: "Saved for later. Unlock Nuvori on Windows, then refresh this review to finish." };
      }
      return { status: result.status, message: result.message };
    }).then(sendResponse, () => sendResponse({ status: "error", message: "Cannot update yet. Open and unlock Nuvori on Windows." }));
    return true;
  }
  if (message?.action === "queue_login") {
    runInOrder(async () => {
      const { origin, sealed } = message;
      if (typeof origin !== "string" || new URL(origin).origin !== origin ||
          !origin.startsWith("https://") || typeof sealed !== "string" ||
          sealed.length === 0 || sealed.length > 32768) {
        throw new Error("The encrypted login is invalid.");
      }
      const items = await readPending();
      const item = { id: crypto.randomUUID(), origin, sealed, createdAt: Date.now(), approved: true };
      if (!roomToPersist(items, item)) throw new Error("Too many logins are waiting. Unlock Nuvori before saving more.");
      items.push(item);
      await savePending(items);
      return await flushPending();
    }).then(sendResponse, (error) => sendResponse({ status: "error", message: error.message }));
    return true;
  }
  if (message?.action === "pending_status" || message?.action === "flush_pending") {
    runInOrder(async () => message.action === "flush_pending"
      ? flushPending()
      : readPending().then((items) => ({ pending: items.length, review: items.filter((item) => item.state === "review").length,
        items: items.map((item) => {
          const choices = publicChoices(item);
          return { id: item.id, origin: item.origin, state: item.state, createdAt: item.createdAt, title: choices[0]?.title, username: choices[0]?.username, choices, canUpdate: choices.length > 0 };
        }) }))
    ).then(sendResponse, () => sendResponse({ status: "error", message: "Could not read pending logins." }));
    return true;
  }
  if (["remove_pending", "retry_pending", "approve_pending"].includes(message?.action)) {
    runInOrder(async () => {
      const items = await readPending();
      const index = items.findIndex((item) => item.id === message.id);
      if (index < 0) return { status: "missing" };
      if (message.action === "retry_pending") {
        const item = items[index];
        const response = await native("review_login", item.origin, { sealedLogin: item.sealed });
        if (response?.status === "already_saved") items.splice(index, 1);
        else if (response?.status === "account_exists") { item.state = "review"; setChoices(item, updateChoices(response)); }
        else if (response?.status === "needs_save") { item.state = "confirm"; setChoices(item, []); }
        else return { status: "error", message: response?.message || "Open and unlock Windows to refresh this review." };
        await savePending(items);
        return { status: "ok" };
      }
      if (message.action === "approve_pending" && items[index].state !== "confirm") return { status: "error" };
      if (message.action === "remove_pending") items.splice(index, 1);
      else {
        const item = items[index];
        if (item.transient && !roomToPersist(items, item)) return { status: "error", message: "Too many logins are waiting for this site." };
        delete item.state;
        delete item.transient;
        item.approved = true;
      }
      await savePending(items);
      return { status: "ok" };
    }).then(sendResponse, () => sendResponse({ status: "error" }));
    return true;
  }
  if (message?.action === "log_event") {
    const event = message.event || {};
    let origin = "";
    try { origin = typeof event.origin === "string" && event.origin.startsWith("https://") ? new URL(event.origin).origin : ""; } catch { /* ignore */ }
    logEvent(event.action, event.status, origin).then(() => sendResponse({ status: "ok" }));
    return true;
  }
  if (message?.action === "host_features" || message?.action === "connection_status") {
    (async () => {
      if (message.action === "connection_status") {
        const status = await pingStatus();
        return { status, features: featureCache?.list || [] };
      }
      return { status: "ok", features: await getFeatures() };
    })().then(sendResponse, () => sendResponse({ status: "error", features: [] }));
    return true;
  }
  // The popup's "Codes for this site": matching codes, and one code to copy.
  if (message?.action === "popup_codes" || message?.action === "popup_copy_code") {
    (async () => {
      const origin = typeof message.origin === "string" && message.origin.startsWith("https://") ? new URL(message.origin).origin : "";
      if (!origin) return { status: "error" };
      const unavailable = await itemsUnavailable("code");
      if (unavailable) return { status: unavailable, items: [] };
      const page = { tabId: -1, origin };
      if (message.action === "popup_codes") {
        const result = await queryItems(-1, origin, "code", false);
        return { status: result.status, items: result.items.slice(0, 20).map((choice) => ({ id: choice.id, title: clip(choice.title), subtitle: clip(choice.username), color: cardColor(choice.color) })) };
      }
      const listing = await queryItems(-1, origin, "code", false);
      const choice = listing.items.find((entry) => entry.id === message.id);
      if (!choice) return { status: "missing" };
      const response = await native("fill_item", origin, { kind: "code", credentialId: choice.id, selectionToken: choice.selectionToken });
      forgetItems(-1, origin, "code");
      const value = response?.item?.code?.value;
      void logEvent("copy_code", response?.status || "empty", page.origin);
      return response?.status === "ok" && /^\d{6,8}$/.test(value || "") ? { status: "ok", value, secondsLeft: Number(response.item.code.secondsLeft) || 0 } : { status: response?.status || "error" };
    })().then(sendResponse, () => sendResponse({ status: "error" }));
    return true;
  }
  // The popup's cards and addresses for the open tab: list them, and fill one into the page.
  if (message?.action === "popup_items" || message?.action === "popup_fill_item" || message?.action === "popup_forms") {
    if (sender?.tab || !chrome.runtime.getURL || !String(sender?.url || "").startsWith(chrome.runtime.getURL(""))) return false;
    handlePopupItems(message).then(sendResponse, () => sendResponse({ status: "error" }));
    return true;
  }
  // The popup's "Sign-in methods" for the open tab's site.
  if (message?.action === "popup_sign_ins") {
    if (sender?.tab) return false;
    const origin = originOf(typeof message.origin === "string" ? message.origin : "");
    if (!origin) return false;
    signInReminders(origin, { fresh: true }).then(sendResponse, () => sendResponse({ status: "error", methods: [] }));
    return true;
  }
  if (message?.action === "unlock_app") {
    requestUnlock().then((status) => sendResponse({ status }), () => sendResponse({ status: "error" }));
    return true;
  }
  if (message?.action === "clipboard_clear_later") {
    chrome.alarms.create(CLIPBOARD_ALARM, { delayInMinutes: 0.5 });
    sendResponse({ status: "ok" });
    return false;
  }
  return false;
});

async function handlePopupItems(message) {
  if (message.action === "popup_forms") {
    // Which kinds of form the page has: the top page's own forms, or a frame field focused just now.
    if (!Number.isInteger(message.tabId) || !(await tabPage(message.tabId))) return { card: false, profile: false };
    const forms = await chrome.tabs.sendMessage(message.tabId, { target: "nuvori-top", action: "popup_forms" }, { frameId: 0 }).catch(() => null);
    const field = frameFields.get(message.tabId);
    const recent = field && Date.now() - field.at <= FRAME_FIELD_TTL_MS ? field.detail : "";
    return { card: forms?.card === true || recent === "card", profile: forms?.profile === true || recent === "profile" };
  }
  const kind = message.kind;
  if ((kind !== "card" && kind !== "profile") || !Number.isInteger(message.tabId)) return { status: "error" };
  const page = await tabPage(message.tabId);
  if (!page) return { status: "error", message: "Open an HTTPS page first." };
  const settings = await readSettings();
  if (!settings.fill[kind]) return { status: "disabled", items: [] };
  const unavailable = await itemsUnavailable(kind);
  if (unavailable) return { status: unavailable, items: [] };
  if (message.action === "popup_items") {
    const result = await queryItems(page.tabId, page.origin, kind, false, { fresh: true });
    return { status: result.status, items: result.items.slice(0, 20).map((choice) => ({ id: choice.id, title: clip(choice.title), subtitle: clip(choice.username), color: cardColor(choice.color) })) };
  }
  if (typeof message.id !== "string" || !message.id || message.id.length > 256) return { status: "error" };
  // A payment or address form in a frame that the user focused a moment ago gets it there.
  const field = frameFields.get(page.tabId);
  let result;
  if (field && field.detail === kind && Date.now() - field.at <= FRAME_FIELD_TTL_MS) {
    result = await handleFillFrame(page, { kind, id: message.id, frameId: field.anchorFrameId });
  } else {
    const item = await handleFillItem(page, { kind, id: message.id });
    if (item.status !== "ok") return item;
    const payload = { target: "nuvori-top", action: "popup_fill", kind, id: message.id, card: item.card, profile: item.profile };
    const reply = await chrome.tabs.sendMessage(page.tabId, payload, { frameId: 0 }).catch(() => null);
    payload.card = payload.profile = item.card = item.profile = undefined;
    if (!(reply?.status === "ok" && Number.isInteger(reply.filled) && reply.filled > 0)) {
      cardCodeTokens.delete(`${page.tabId}|${page.origin}|${message.id}`);
      result = { status: "error", message: kind === "card" ? "No payment form found. Click the card number field first, then try again." : "No address form found. Click a field of the form first, then try again." };
    } else result = { status: "ok", filled: reply.filled, codeAsked: reply.codeAsked === true };
  }
  void logEvent(`popup_fill_${kind}`, result.status, page.origin);
  return result;
}

// ---------------------------------------------------------------------------
// Clipboard auto-clear: an offscreen document in Chrome (service workers have no clipboard).
// Firefox has no offscreen documents; its background page writes the clipboard itself.

async function clearClipboard() {
  if (!chrome.offscreen) {
    try { await navigator.clipboard?.writeText(" "); } catch { /* best effort */ }
    return;
  }
  try {
    if (!(await chrome.offscreen.hasDocument?.())) {
      await chrome.offscreen.createDocument({ url: "offscreen.html", reasons: ["CLIPBOARD"], justification: "Clear a copied password from the clipboard." });
    }
    await chrome.runtime.sendMessage({ target: "offscreen", action: "clear_clipboard" });
  } catch { /* Nothing else to do; the user can copy something else. */ }
  finally { await chrome.offscreen.closeDocument().catch(() => {}); }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) { void runInOrder(flushPending); void refreshActiveTab().catch(() => {}); }
  if (alarm.name === CLIPBOARD_ALARM) void clearClipboard();
});

chrome.runtime.onStartup?.addListener(() => void unlockOnStartup().catch(() => {}));
chrome.tabs.onActivated.addListener(() => void refreshActiveTab().catch(() => {}));
chrome.tabs.onUpdated.addListener((id, change, tab) => {
  if (change.status === "complete" && tab.url?.startsWith("https://")) void pageStatus({ id, url: tab.url }).catch(() => {});
});
chrome.tabs.onRemoved?.addListener((tabId) => {
  void forgetStep(tabId).catch(() => {});
  forgetQueries(tabId);
  void runInOrder(async () => {
    const prompts = await readPrompts();
    if (prompts[tabId]) { delete prompts[tabId]; await writePrompts(prompts); }
    const items = await readPending();
    const kept = items.filter((item) => !(item.transient && item.tabId === tabId));
    if (kept.length !== items.length) await savePending(kept);
  });
});

// Sign-in methods: the browser's own navigation events, never page scripts. Firefox and Chrome both
// offer non-blocking webRequest; without it (or signins.js) the feature stays off.
if (SIGNINS() && chrome.webRequest?.onBeforeRequest) {
  chrome.webRequest.onBeforeRequest.addListener(onSignInRequest, { urls: SIGNINS().authorizePatterns(), types: ["main_frame", "sub_frame"] });
  chrome.webRequest.onBeforeRequest.addListener(onSignInPage, { urls: ["https://*/*"], types: ["main_frame"] });
  // Every redirect: a provider's last hop can leave from another of its hosts (accounts.youtube.com).
  chrome.webRequest.onBeforeRedirect.addListener(onSignInRedirect, { urls: ["https://*/*"], types: ["main_frame", "sub_frame"] });
  chrome.tabs.onCreated?.addListener(onSignInTabCreated);
  chrome.tabs.onUpdated.addListener(onSignInTabUpdated);
  chrome.tabs.onRemoved?.addListener(onSignInTabRemoved);
}

void chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
// Drop unapproved captures that older versions left in chrome.storage.local.
void runInOrder(async () => {
  const saved = await chrome.storage.local.get(STORAGE_KEY);
  const stored = Array.isArray(saved?.[STORAGE_KEY]) ? saved[STORAGE_KEY] : [];
  if (stored.some((item) => ["confirm", "review"].includes(item.state) && item.approved !== true)) await savePending(await readPending());
});
void runInOrder(flushPending);
