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
    "fillCards", "fillProfiles", "fillCodes", "saveDetails"]);
  const list = (value) => Array.isArray(value) ? value.filter((entry) => typeof entry === "string") : [];
  return {
    inlineSuggestions: saved?.inlineSuggestions !== false,
    unlockOnStartup: saved?.unlockOnStartup !== false,
    fill: { card: saved?.fillCards !== false, profile: saved?.fillProfiles !== false, code: saved?.fillCodes !== false },
    saveDetails: saved?.saveDetails !== false,
    neverSave: list(saved?.neverSave),
    noSuggest: list(saved?.noSuggest),
    theme: THEMES.includes(saved?.theme) ? saved.theme : "system",
  };
}

async function addToList(key, origin) {
  const settings = await readSettings();
  const current = key === "neverSave" ? settings.neverSave : settings.noSuggest;
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
  for (const cache of [queryCache, allCache]) for (const key of [...cache.keys()]) if (key.startsWith(`${tabId}|`)) cache.delete(key);
}

// "Search all logins" ("all_logins" hosts): every saved login, listed for this page, so the user can fill
// any of them here. Tokens from this listing release a login only on the page it was listed for.
const allCache = new Map();

function queryAll(tabId, origin, { fresh = false } = {}) {
  const key = `${tabId}|${origin}`;
  const hit = allCache.get(key);
  if (!fresh && hit && Date.now() - hit.at < (hit.status === "ok" ? QUERY_TTL_OK_MS : QUERY_TTL_OTHER_MS)) return hit.promise;
  const entry = { at: Date.now(), status: undefined, promise: undefined };
  entry.promise = (async () => {
    let result;
    try {
      const response = await native("query_credentials", origin, { all: true });
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
  allCache.set(key, entry);
  while (allCache.size > 16) allCache.delete(allCache.keys().next().value);
  return entry.promise;
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
  const result = await queryItems(page.tabId, page.origin, kind, kind === "code" && message.all === true);
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
  const find = async (fresh) => {
    for (const all of kind === "code" ? [false, true] : [false]) {
      const listing = await queryItems(page.tabId, page.origin, kind, all, { fresh });
      const choice = listing.items.find((entry) => entry.id === id);
      if (choice || fresh) return { listing, choice };
    }
    return { listing: { status: "error", items: [] }, choice: undefined };
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

/** Returns "ok" (already unlocked), "locked" (window shown), "starting", or why it couldn't ask. */
async function requestUnlock() {
  const status = await pingStatus();
  if (status === "ok") return "ok";
  if (!["locked", "desktop_unavailable"].includes(status)) return status;
  if (!(await getFeatures()).includes("unlock_prompt")) return "unsupported";
  let response;
  try { response = await native("unlock_prompt", ""); } catch (error) { return hostErrorStatus(error); }
  const result = response?.status || "error";
  if (result === "locked" || result === "starting") watchForUnlock();
  return result;
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
  const result = await requestUnlock();
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
    const result = await handleFill(target, { credentialId: message.id, want: target.field.want }, { all: message.all === true });
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
  "inline_all_logins", "inline_fill_any"];

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
async function handleFill(page, message, { all = false } = {}) {
  const { credentialId } = message;
  if (typeof credentialId !== "string" || !credentialId || credentialId.length > 256) return { status: "error", message: "Choose an account again." };
  const key = `${page.tabId}|${page.origin}`;
  const list = (fresh) => all ? queryAll(page.tabId, page.origin, { fresh }) : queryOrigin(page.tabId, page.origin, { fresh });
  const cache = all ? allCache : queryCache;
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
      const result = await queryOrigin(page.tabId, scope.origin);
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
      };
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
      if (LIMITED_PAGE_UI && (message.kind !== "code" || message.all === true)) return { status: "disabled" };
      const scope = scopeOf(page, message, message.kind);
      return scope ? handleItems(scope, message) : { status: "missing", message: "Click the field again." };
    }
    case "inline_all_logins": {
      if (LIMITED_PAGE_UI) return { status: "disabled" };
      const settings = await readSettings();
      const scope = scopeOf(page, message, "login");
      if (!scope) return { status: "missing", message: "Click the field again.", theme: settings.theme };
      if (!(await getFeatures()).includes("all_logins") && !(await getFeatures({ refresh: true })).includes("all_logins")) {
        return { status: featureCache ? "unsupported" : "offline", theme: settings.theme };
      }
      const result = await queryAll(page.tabId, scope.origin, { fresh: message.fresh === true });
      const text = (value, max = 256) => typeof value === "string" ? value.slice(0, max) : "";
      return {
        status: result.status, theme: settings.theme, host: hostOf(scope.origin),
        accounts: result.credentials.slice(0, 1000).map((choice) => ({ id: choice.id, title: text(choice.title), username: text(choice.username), site: text(choice.site, 80),
          ...(choice.passkey === true ? { passkey: true } : {}) })),
      };
    }
    case "inline_fill_any": {
      if (LIMITED_PAGE_UI) return { status: "disabled" };
      // A login the user chose from every saved login, for this page.
      const result = await handleFill(page, { credentialId: message.id, want: message.want }, { all: true });
      void logEvent("inline_fill_any", result.status, page.origin);
      return result;
    }
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
      if (LIMITED_PAGE_UI && (!["login", "code"].includes(message.kind) || message.all === true)) return { status: "disabled" };
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

void chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
// Drop unapproved captures that older versions left in chrome.storage.local.
void runInOrder(async () => {
  const saved = await chrome.storage.local.get(STORAGE_KEY);
  const stored = Array.isArray(saved?.[STORAGE_KEY]) ? saved[STORAGE_KEY] : [];
  if (stored.some((item) => ["confirm", "review"].includes(item.state) && item.approved !== true)) await savePending(await readPending());
});
void runInOrder(flushPending);
