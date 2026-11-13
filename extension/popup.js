const HOST_NAME = "com.nuvori.desktop";

const $ = (selector) => document.querySelector(selector);
const site = $("#site");
const message = $("#message");
const findButton = $("#find");
const choices = $("#choices");
const captureButton = $("#capture");
const saveButton = $("#save");
const cancelSaveButton = $("#cancel-save");
const saveReview = $("#save-review");
const saveSummary = $("#save-summary");
const pendingList = $("#pending");
const pendingEmpty = $("#pending-empty");
const connection = $("#connection");
const connectionText = $("#connection-text");
const setupPanel = $("#setup");
const setupLead = $("#setup-lead");
const reviewPassword = $("#review-password");
const showPassword = $("#show-password");
const emptyAccounts = $("#accounts-empty");
const retryPendingButton = $("#retry-pending");
const inlineToggle = $("#inline-toggle");
const startupUnlockToggle = $("#startup-unlock-toggle");
const codesSection = $("#codes-section");
const codesList = $("#codes");
// Settings switches stored in chrome.storage.local (all on by default).
const SWITCHES = { "#fill-cards-toggle": "fillCards", "#fill-profiles-toggle": "fillProfiles", "#fill-codes-toggle": "fillCodes", "#save-details-toggle": "saveDetails" };
const unlockButton = $("#unlock-app");
const saveNameRow = $("#save-name-row");
const saveName = $("#save-name");

const ICON = {
  key: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>',
  user: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>',
  copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
  lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>',
  clock: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
};

let tabId;
let origin;
let capturedLogin;
let busy = false;
let retryTimer;
let retryDelay = 2000;
let pendingLoaded = false;
// Additive host capabilities, from the background's cached "status" response.
let features = [];
const supports = (feature) => features.includes(feature);

async function loadFeatures() {
  try {
    const result = await chrome.runtime.sendMessage({ action: "host_features" });
    features = Array.isArray(result?.features) ? result.features : [];
  } catch { features = []; }
  return features;
}

/** A login name for "login_title" hosts: no control characters, at most 256 characters. */
function cleanTitle(value) {
  // Control characters become spaces; format characters (zero-width, bidi overrides such as U+202E) are removed.
  return String(value || "").replace(/\p{Cc}/gu, " ").replace(/\p{Cf}/gu, "").slice(0, 256).trim();
}

// ---------------------------------------------------------------------------
// Connection state

const CONNECTION_TEXT = { ready: "Connected · Unlocked", locked: "Locked", offline: "Not connected", checking: "Checking…", unsupported: "Not checked" };

function setConnection(state, text = CONNECTION_TEXT[state], cause) {
  connection.dataset.state = state;
  if (connectionText) connectionText.textContent = text;
  // Nuvori can show its unlock window, or start in the background, unless the host itself is missing.
  if (unlockButton) unlockButton.hidden = !(state === "locked" || (state === "offline" && cause !== "host"));
  if (setupPanel) {
    setupPanel.hidden = state !== "offline";
    if (setupLead) {
      setupLead.textContent = cause === "host"
        ? "This browser can't find the Nuvori native host. Register it for this extension."
        : "Nuvori for Windows isn't running or isn't reachable.";
    }
  }
}

function logEvent(action, status, eventOrigin) {
  // Action, status and site only. Never usernames or passwords.
  chrome.runtime.sendMessage({ action: "log_event", event: { action, status, origin: eventOrigin } })?.catch?.(() => {});
}

function makeRequest(action, requestOrigin, details = {}) {
  return {
    version: 2,
    requestId: crypto.randomUUID(),
    action,
    origin: requestOrigin,
    ...details,
  };
}

async function callHost(request) {
  try {
    const response = await chrome.runtime.sendNativeMessage(HOST_NAME, request);
    logEvent(request.action, response?.status || "empty", request.origin);
    if (response?.status === "locked") setConnection("locked");
    else if (response?.status === "desktop_unavailable") setConnection("offline", CONNECTION_TEXT.offline, "app");
    else if (["ok", "selection_expired", "saved", "already_saved", "needs_save", "account_exists"].includes(response?.status)) setConnection("ready");
    return response;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const missing = /not found|not registered|specified native messaging host|forbidden/i.test(detail);
    setConnection("offline", CONNECTION_TEXT.offline, missing ? "host" : "app");
    logEvent(request.action, missing ? "host_missing" : "offline", request.origin);
    throw new Error(missing
      ? "Register the Nuvori native host for this extension. Setup steps are above."
      : "Open Nuvori on Windows and unlock your vault. Retrying the connection...");
  }
}

/** Ask the background to ping the host; it also refreshes the feature list. */
async function checkConnection() {
  setConnection("checking");
  let result;
  try { result = await chrome.runtime.sendMessage({ action: "connection_status" }); } catch { result = { status: "offline" }; }
  if (Array.isArray(result?.features)) features = result.features;
  if (result?.status === "ok") { setConnection("ready"); return "ready"; }
  if (result?.status === "locked") { setConnection("locked"); return "locked"; }
  setConnection("offline", CONNECTION_TEXT.offline, result?.status === "host_missing" ? "host" : "app");
  return "offline";
}

// ---------------------------------------------------------------------------
// General UI

function showMessage(text) {
  message.textContent = text;
}

function setBusy(value) {
  busy = value;
  findButton.disabled = value;
  captureButton.disabled = value || !origin;
  saveButton.disabled = value;
  cancelSaveButton.disabled = value;
  showPassword.disabled = value;
  retryPendingButton.disabled = value;
  for (const button of choices.querySelectorAll("button")) button.disabled = value;
}

function selectView(name) {
  for (const tab of document.querySelectorAll("[data-view]")) {
    const selected = tab.dataset.view === name;
    tab.setAttribute("aria-selected", String(selected));
    const view = document.querySelector(`#view-${tab.dataset.view}`);
    if (view) view.hidden = !selected;
  }
  if (name !== "site") clearCapture();
  if (name === "settings") void loadDiagnostics();
}

for (const tab of document.querySelectorAll("[data-view]")) tab.addEventListener("click", () => selectView(tab.dataset.view));

function iconNode(name, className = "") {
  const span = document.createElement("span");
  if (className) span.className = className;
  span.innerHTML = ICON[name]; // Static, extension-defined markup only.
  return span;
}

function iconButton(name, label, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-btn";
  button.setAttribute("aria-label", label);
  button.title = label;
  button.innerHTML = ICON[name];
  button.addEventListener("click", onClick);
  return button;
}

function textButton(text, className, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = text;
  button.addEventListener("click", onClick);
  return button;
}

async function currentHttpsTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) throw new Error("Open a secure website first.");
  const parsed = new URL(tab.url);
  if (parsed.protocol !== "https:") throw new Error("Nuvori fills passwords only on HTTPS sites.");
  return { tabId: tab.id, origin: parsed.origin };
}

async function sameTabStillOpen() {
  const current = await currentHttpsTab();
  if (current.tabId !== tabId || current.origin !== origin) {
    throw new Error("The active tab changed. Reopen Nuvori and choose an account again.");
  }
}

// ---------------------------------------------------------------------------
// Manual "Review this page's login" flow

function clearCapture() {
  capturedLogin = undefined;
  saveReview.hidden = true;
  reviewPassword.value = "";
  reviewPassword.type = "password";
  showPassword.textContent = "Show";
  showPassword.setAttribute("aria-label", "Show password");
  showPassword.setAttribute("aria-pressed", "false");
}

showPassword.addEventListener("click", () => {
  const visible = reviewPassword.type === "password";
  reviewPassword.type = visible ? "text" : "password";
  showPassword.textContent = visible ? "Hide" : "Show";
  showPassword.setAttribute("aria-label", visible ? "Hide password" : "Show password");
  showPassword.setAttribute("aria-pressed", String(visible));
});

function readLoginForm(expectedOrigin, allowPasswordOnly = false) {
  if (location.origin !== expectedOrigin) return null;
  for (let current = window; current !== current.top; current = current.parent) {
    const frame = current.frameElement;
    if (!frame) return null;
    const rect = frame.getBoundingClientRect();
    const style = frame.ownerDocument.defaultView.getComputedStyle(frame);
    if (!rect.width || !rect.height || style.visibility === "hidden" ||
        frame.ownerDocument.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2) !== frame) return null;
  }
  const inputs = (root) => {
    const found = [...root.querySelectorAll("input")];
    for (const element of root.querySelectorAll("*")) if (element.shadowRoot) found.push(...inputs(element.shadowRoot));
    return found;
  };
  const visible = (input) => {
    const rect = input.getBoundingClientRect();
    const style = getComputedStyle(input);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden" &&
      input.getRootNode().elementFromPoint?.(rect.x + rect.width / 2, rect.y + rect.height / 2) === input;
  };
  const passwords = inputs(document).filter((input) => input.type === "password" && visible(input) && !input.disabled);
  if (passwords.length < 1 || passwords.length > 2 || !passwords[0].value ||
      passwords.some((input) => input.value !== passwords[0].value)) return null;
  const form = passwords[0].form;
  const fields = form ? inputs(form) : inputs(passwords[0].getRootNode());
  const username = fields.find((input) => visible(input) && !input.disabled && !input.readOnly &&
    (input.autocomplete === "username" || input.type === "email") && input.value.trim()) ||
    fields.find((input) => visible(input) && !input.disabled && !input.readOnly &&
      ["text", "email"].includes(input.type) && input.value.trim());
  if (passwords[0].value.length > 4096) return null;
  if (!username) {
    // Password-only sign-in (host "password_only"): one password field, and never a numeric PIN.
    const mode = String(passwords[0].getAttribute?.("inputmode") || "").toLowerCase();
    if (!allowPasswordOnly || passwords.length !== 1 || mode === "numeric" || mode === "decimal") return null;
    return { username: "", password: passwords[0].value };
  }
  if (username.value.trim().length > 1024) return null;
  return { username: username.value.trim(), password: passwords[0].value };
}

captureButton.addEventListener("click", async () => {
  clearCapture();
  setBusy(true);
  try {
    const current = await currentHttpsTab();
    const frames = await chrome.scripting.executeScript({
      target: { tabId: current.tabId, allFrames: true },
      func: readLoginForm, args: [current.origin, supports("password_only")],
    });
    const matches = frames.filter((frame) => typeof frame.result?.username === "string" && frame.result?.password);
    if (matches.length !== 1) throw new Error("Enter a username and password in one visible sign-in form, then try again.");
    capturedLogin = { ...matches[0].result, tabId: current.tabId, origin: current.origin };
    const host = new URL(current.origin).host;
    saveSummary.textContent = `Save ${capturedLogin.username || "a login with no username"} for ${host}?`;
    if (saveNameRow) saveNameRow.hidden = !supports("login_title");
    if (saveName) saveName.value = host.replace(/^www\./, "");
    reviewPassword.value = capturedLogin.password;
    saveReview.hidden = false;
    showMessage("Check the account, then choose Save login.");
  } catch (error) {
    clearCapture();
    showMessage(error.message);
  } finally {
    setBusy(false);
  }
});

cancelSaveButton.addEventListener("click", clearCapture);

saveButton.addEventListener("click", async () => {
  if (!capturedLogin) return;
  setBusy(true);
  try {
    const current = await currentHttpsTab();
    if (current.tabId !== capturedLogin.tabId || current.origin !== capturedLogin.origin) {
      throw new Error("The tab changed. Review the login again.");
    }
    const details = { username: capturedLogin.username, password: capturedLogin.password };
    const title = supports("login_title") ? cleanTitle(saveName?.value) : "";
    if (title) details.title = title; // Older hosts reject unknown fields, so only when supported.
    const response = await callHost(makeRequest("seal_login", capturedLogin.origin, details));
    if (response?.status !== "sealed" || !response.sealedLogin) {
      throw new Error(response?.message || "The Windows host could not encrypt this login. Update the native host and try again.");
    }
    const queued = await chrome.runtime.sendMessage({
      action: "queue_login", origin: capturedLogin.origin, sealed: response.sealedLogin,
    });
    if (queued?.status === "error") throw new Error(queued.message);
    clearCapture();
    showMessage(queued?.status === "saved" || queued?.status === "already_saved"
      ? "Saved in your Windows vault."
      : queued?.status === "review" ? "A different password is already saved. Open Pending to review the update."
      : "Encrypted locally. Nuvori saves it after the Windows vault unlocks.");
    await refreshPending();
  } catch (error) {
    showMessage(error.message);
  } finally {
    setBusy(false);
  }
});

// ---------------------------------------------------------------------------
// Pending queue

function pendingRow(item) {
  const row = document.createElement("li");
  row.className = "pending-row";
  const host = document.createElement("span");
  host.className = "pending-host";
  try { host.textContent = new URL(item.origin).host; } catch { host.textContent = item.origin; }
  const state = document.createElement("div");
  state.className = "pending-state";
  const text = document.createElement("span");
  if (item.state === "review") {
    state.dataset.tone = "warning";
    state.append(iconNode("info"));
    const count = item.choices?.length || 0;
    text.textContent = count > 1 ? "Choose which saved account to update."
      : item.canUpdate ? `A different password is saved${item.username ? ` for ${item.username}` : ""}. Choose Update to replace it.`
      : "A different password is saved for this site. Refresh the review to continue.";
  } else if (item.state === "confirm") {
    state.dataset.tone = "info";
    state.append(iconNode("key"));
    text.textContent = "Captured from a sign-in form. Choose Save to keep it.";
  } else {
    state.dataset.tone = "neutral";
    state.append(iconNode("clock"));
    text.textContent = "Encrypted. Waiting for the Windows vault to unlock.";
  }
  state.append(text);

  const run = (work) => async () => {
    if (busy) return;
    setBusy(true);
    try { await work(); } catch (error) { showMessage(error.message); }
    finally { setBusy(false); }
  };
  const actions = document.createElement("div");
  actions.className = "actions";
  const many = item.state === "review" && (item.choices?.length || 0) > 1;
  let picked = null;
  let picker = null;
  let updateButton = null;
  if (many) {
    picker = document.createElement("div");
    picker.className = "choice-list";
    picker.setAttribute("role", "radiogroup");
    picker.setAttribute("aria-label", "Saved accounts");
    for (const choice of item.choices) {
      const label = document.createElement("label");
      label.className = "choice-row";
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = `choice-${item.id}`;
      radio.value = choice.id;
      radio.addEventListener("change", () => {
        if (!radio.checked) return;
        picked = choice.id;
        if (updateButton) updateButton.disabled = false;
      });
      const words = document.createElement("span");
      words.className = "row-text";
      const name = document.createElement("span");
      name.className = "title";
      name.textContent = choice.title || host.textContent;
      const user = document.createElement("span");
      user.className = "username";
      user.textContent = choice.username || "No username";
      words.append(name, user);
      label.append(radio, words);
      picker.append(label);
    }
  }
  if (item.state === "review" && item.canUpdate) {
    updateButton = textButton("Update", "btn primary small", run(async () => {
      if (many && !picked) { showMessage("Choose which saved account to update."); return; }
      const request = { action: "update_pending", id: item.id };
      if (many) request.credentialId = picked;
      const result = await chrome.runtime.sendMessage(request);
      showMessage(result?.status === "saved" ? "Password updated in your Windows vault."
        : result?.status === "queued_update" ? "Saved for later. Unlock Nuvori on Windows, then refresh this review to finish."
        : result?.message || "Review this account again before updating.");
      await refreshPending();
    }));
    if (many) updateButton.disabled = true;
    actions.append(updateButton);
  }
  if (item.state === "review") {
    actions.append(textButton("Refresh review", "btn small", run(async () => {
      const result = await chrome.runtime.sendMessage({ action: "retry_pending", id: item.id });
      if (result?.status === "error") showMessage(result.message);
      await refreshPending();
    })));
  }
  if (item.state === "confirm") {
    actions.append(textButton("Save", "btn primary small", run(async () => {
      await chrome.runtime.sendMessage({ action: "approve_pending", id: item.id });
      const result = await chrome.runtime.sendMessage({ action: "flush_pending" });
      showMessage(result?.status === "review" ? "A password is already saved. Review its update below."
        : result?.pending ? "Encrypted. Saves when Windows unlocks." : "Login saved.");
      await refreshPending();
    })));
  }
  actions.append(textButton("Discard", "btn small", run(async () => {
    if (!confirm(`Discard the pending login for ${host.textContent}?`)) return;
    await chrome.runtime.sendMessage({ action: "remove_pending", id: item.id });
    await refreshPending();
  })));
  row.append(host, state);
  if (picker) row.append(picker);
  row.append(actions);
  return row;
}

async function refreshPending() {
  const state = await chrome.runtime.sendMessage({ action: "pending_status" });
  if (state?.status === "error") throw new Error(state.message || "Could not read pending logins.");
  const items = state?.items || [];
  pendingList.replaceChildren(...items.map(pendingRow));
  if (pendingEmpty) pendingEmpty.hidden = items.length > 0;
  retryPendingButton.hidden = !items.some((item) => !["confirm", "review"].includes(item.state));
  const count = state?.pending || 0;
  $("#pending-title").textContent = count ? `Waiting to save (${count})` : "Waiting to save";
  const badge = $("#pending-count");
  badge.textContent = String(count);
  badge.dataset.zero = String(count === 0);
  if (!pendingLoaded && items.some((item) => ["confirm", "review"].includes(item.state))) selectView("pending");
  pendingLoaded = true;
}

retryPendingButton.addEventListener("click", async () => {
  if (busy) return;
  setBusy(true);
  try {
    const result = await chrome.runtime.sendMessage({ action: "flush_pending" });
    if (result?.status === "error") throw new Error(result.message);
    await refreshPending();
    showMessage(result?.pending ? "Still waiting. Open and unlock Nuvori on Windows, then retry." : "All pending logins are saved.");
  } catch (error) { showMessage(error.message); }
  finally { setBusy(false); }
});

// ---------------------------------------------------------------------------
// Accounts for this site: fill, copy username, copy password

/** Ask Windows for one selected login, refreshing an expired one-use token once. */
async function releaseCredential(choice) {
  let response = await callHost(makeRequest("fill_credential", origin, {
    credentialId: choice.id,
    selectionToken: choice.selectionToken,
  }));
  if (response?.status === "selection_expired") {
    const refreshed = await callHost(makeRequest("query_credentials", origin));
    const replacement = refreshed?.credentials?.find((item) => item.id === choice.id);
    if (!replacement?.selectionToken) {
      throw new Error("This account is no longer available for this site. Refresh and try again.");
    }
    response = await callHost(makeRequest("fill_credential", origin, {
      credentialId: choice.id,
      selectionToken: replacement.selectionToken,
    }));
  }
  choice.selectionToken = ""; // One use only; the next action asks for a fresh token.
  if (response?.status !== "ok" || !response.credential) {
    throw new Error(response?.message || "Nuvori could not release the selected password.");
  }
  if (response.credential.id !== choice.id) throw new Error("The selected account changed. Try again.");
  return response.credential;
}

async function fillSelected(choice) {
  setBusy(true);
  try {
    await sameTabStillOpen();
    const frames = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: fillLoginForm,
      args: [null, origin],
    });
    const matches = frames.filter((frame) => frame.result?.fillable);
    if (matches.length !== 1) {
      if (matches.length > 1 || frames.some((frame) => frame.result?.multiplePasswordFields)) {
        throw new Error("More than one sign-in form is visible. Close the extra form and try again.");
      }
      throw new Error("No supported sign-in form was found. Open the site's login form and try again.");
    }

    const credential = await releaseCredential(choice);
    await sameTabStillOpen();

    const result = await chrome.scripting.executeScript({
      target: matches[0].documentId
        ? { tabId, documentIds: [matches[0].documentId] }
        : { tabId, frameIds: [matches[0].frameId] },
      func: fillLoginForm,
      args: [{ username: credential.username, password: credential.password }, origin],
    });
    credential.password = "";
    if (!result[0]?.result?.filled) {
      if (result[0]?.result?.wrongOrigin) throw new Error("The page changed before filling. Reopen Nuvori and try again.");
      if (result[0]?.result?.multiplePasswordFields) throw new Error("This page has multiple sign-in forms. Choose a form before filling.");
      throw new Error("No visible sign-in form was found on this page.");
    }
    showMessage("Filled the selected account. Review the form and submit it yourself.");
  } catch (error) {
    showMessage(error instanceof Error ? error.message : "Could not fill this account.");
  } finally {
    setBusy(false);
  }
}

async function copyPassword(choice) {
  setBusy(true);
  try {
    await sameTabStillOpen();
    const credential = await releaseCredential(choice);
    let secret = credential.password;
    credential.password = "";
    try { await navigator.clipboard.writeText(secret); }
    finally { secret = ""; }
    await chrome.runtime.sendMessage({ action: "clipboard_clear_later" });
    // Best effort only (the browser may close first), so the message promises nothing.
    showMessage("Password copied.");
  } catch (error) {
    showMessage(error instanceof Error ? error.message : "Could not copy the password.");
  } finally {
    setBusy(false);
  }
}

async function copyUsername(choice) {
  try {
    await navigator.clipboard.writeText(choice.username || "");
    showMessage("Username copied.");
  } catch {
    showMessage("Could not copy the username.");
  }
}

function fillLoginForm(credentials, expectedOrigin) {
  if (location.origin !== expectedOrigin) return { filled: false, wrongOrigin: true };
  for (let current = window; current !== current.top; current = current.parent) {
    const frame = current.frameElement;
    if (!frame) return { filled: false };
    const rect = frame.getBoundingClientRect();
    const style = frame.ownerDocument.defaultView.getComputedStyle(frame);
    if (!rect.width || !rect.height || style.visibility === "hidden" ||
        frame.ownerDocument.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2) !== frame) {
      return { filled: false };
    }
  }
  const inputs = (root) => {
    const found = [...root.querySelectorAll("input")];
    for (const element of root.querySelectorAll("*")) {
      if (element.shadowRoot) found.push(...inputs(element.shadowRoot));
    }
    return found;
  };
  const visible = (input) => {
    const style = getComputedStyle(input);
    const rect = input.getBoundingClientRect();
    const hit = input.getRootNode().elementFromPoint?.(rect.x + rect.width / 2, rect.y + rect.height / 2);
    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0 && hit === input;
  };
  const passwords = inputs(document).filter((input) =>
    input.type === "password" && visible(input) && !input.disabled && !input.readOnly);
  if (passwords.length > 1) return { filled: false, multiplePasswordFields: true };
  const password = passwords[0];
  if (!password) return { filled: false };
  if (!credentials) return { fillable: true };

  const form = password.form;
  const fields = form ? inputs(form) : inputs(password.getRootNode());
  const username = fields.find((input) =>
    visible(input) && !input.disabled && !input.readOnly && input !== password &&
    (input.autocomplete === "username" || input.type === "email")
  ) || fields.find((input) =>
    visible(input) && !input.disabled && !input.readOnly && input !== password &&
    ["text", "email", "tel"].includes(input.type)
  );

  const setValue = (input, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  if (username && credentials.username) setValue(username, credentials.username);
  setValue(password, credentials.password);
  password.focus();
  return { filled: true };
}

function accountRow(choice) {
  const item = document.createElement("li");
  item.className = "row";
  const text = document.createElement("span");
  text.className = "row-text";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = choice.title || choice.username || "Saved login";
  const username = document.createElement("span");
  username.className = "username";
  username.textContent = choice.username || "No username";
  text.append(title, username);
  const actions = document.createElement("span");
  actions.className = "row-actions";
  actions.append(
    iconButton("user", "Copy username", () => copyUsername(choice)),
    iconButton("copy", "Copy password", () => copyPassword(choice)),
    textButton("Fill", "btn primary small", () => fillSelected(choice)),
  );
  item.append(iconNode("key", "avatar"), text, actions);
  return item;
}

// ---------------------------------------------------------------------------
// Authenticator codes for this site: copy the current code. The setup key stays in Nuvori.

async function copyCode(code) {
  let result;
  try { result = await chrome.runtime.sendMessage({ action: "popup_copy_code", origin, id: code.id }); } catch { result = { status: "error" }; }
  if (result?.status !== "ok" || typeof result.value !== "string") {
    showMessage(result?.status === "locked" ? "Unlock Nuvori on Windows first." : "Could not get this code. Try again.");
    return;
  }
  let value = result.value;
  result.value = "";
  try {
    await navigator.clipboard.writeText(value);
    await chrome.runtime.sendMessage({ action: "clipboard_clear_later" });
    showMessage(result.secondsLeft > 0 ? `Code copied. It changes in ${result.secondsLeft} s.` : "Code copied.");
  } catch {
    showMessage("Could not copy the code.");
  } finally {
    value = "";
  }
}

function codeRow(code) {
  const item = document.createElement("li");
  item.className = "row";
  const text = document.createElement("span");
  text.className = "row-text";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = code.title || "Authenticator code";
  const account = document.createElement("span");
  account.className = "username";
  account.textContent = code.subtitle || "";
  text.append(title, account);
  const actions = document.createElement("span");
  actions.className = "row-actions";
  actions.append(textButton("Copy code", "btn small", () => copyCode(code)));
  item.append(iconNode("clock", "avatar"), text, actions);
  return item;
}

async function loadCodes() {
  if (!codesSection || !codesList || !origin) return;
  let result;
  try { result = await chrome.runtime.sendMessage({ action: "popup_codes", origin }); } catch { result = null; }
  const items = result?.status === "ok" && Array.isArray(result.items) ? result.items : [];
  codesList.replaceChildren(...items.map(codeRow));
  codesSection.hidden = items.length === 0;
}

async function findAccounts() {
  if (busy) return;
  clearTimeout(retryTimer);
  setBusy(true);
  choices.replaceChildren();
  emptyAccounts.hidden = true;
  try {
    ({ tabId, origin } = await currentHttpsTab());
    const response = await callHost(makeRequest("query_credentials", origin));
    if (response?.status !== "ok" || !Array.isArray(response.credentials)) {
      throw new Error(response?.status === "locked" ? "Unlock Nuvori on Windows. Accounts refresh automatically."
        : response?.status === "desktop_unavailable" ? "Open Nuvori on Windows. Retrying the connection..."
        : response?.message || "Could not find matching accounts.");
    }
    retryDelay = 2000;
    void loadCodes();
    const usable = response.credentials.filter((choice) => typeof choice.id === "string" && typeof choice.selectionToken === "string");
    if (usable.length === 0) {
      emptyAccounts.hidden = false;
      showMessage("");
      return;
    }
    showMessage("");
    choices.append(...usable.map(accountRow));
  } catch (error) {
    showMessage(error instanceof Error ? error.message : "Could not reach Nuvori for Windows.");
    if (["locked", "offline"].includes(connection.dataset.state)) {
      retryTimer = setTimeout(findAccounts, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 15000);
    }
  } finally {
    setBusy(false);
  }
}

findButton.addEventListener("click", findAccounts);

// ---------------------------------------------------------------------------
// Settings: inline suggestions, site lists, diagnostics

function siteList(listSelector, emptySelector, key, entries) {
  const list = $(listSelector);
  const empty = $(emptySelector);
  const valid = Array.isArray(entries) ? entries.filter((entry) => typeof entry === "string") : [];
  list.replaceChildren(...valid.map((entry) => {
    const row = document.createElement("li");
    const label = document.createElement("span");
    try { label.textContent = new URL(entry).host; } catch { label.textContent = entry; }
    row.append(label, textButton("Remove", "text-btn", async () => {
      const saved = await chrome.storage.local.get(key);
      const next = (Array.isArray(saved[key]) ? saved[key] : []).filter((value) => value !== entry);
      await chrome.storage.local.set({ [key]: next });
      await loadSettings();
    }));
    return row;
  }));
  empty.hidden = valid.length > 0;
}

async function loadSettings() {
  const saved = await chrome.storage.local.get(["inlineSuggestions", "neverSave", "noSuggest", "unlockOnStartup", ...Object.values(SWITCHES)]);
  inlineToggle.checked = saved?.inlineSuggestions !== false;
  for (const [selector, key] of Object.entries(SWITCHES)) { const toggle = $(selector); if (toggle) toggle.checked = saved?.[key] !== false; }
  if (startupUnlockToggle) startupUnlockToggle.checked = saved?.unlockOnStartup !== false;
  siteList("#never-list", "#never-empty", "neverSave", saved?.neverSave);
  siteList("#nosuggest-list", "#nosuggest-empty", "noSuggest", saved?.noSuggest);
}

// ---------------------------------------------------------------------------
// Browser password manager: chrome.privacy (optional "privacy" permission, asked for on click).
// Turning a switch off clears our value, which hands control back to the browser.

const BROWSER_SETTINGS = { saving: ["passwordSavingEnabled"], autofill: ["autofillAddressEnabled", "autofillCreditCardEnabled"] };
const BLOCKED_TEXT = {
  not_controllable: "Your organization controls this setting, so Nuvori can't change it.",
  controlled_by_other_extensions: "Another extension controls this setting, so Nuvori can't change it.",
};
const PASSWORD_SETTINGS = { chrome: "chrome://password-manager/settings", brave: "brave://password-manager/settings", edge: "edge://wallet/passwords" };
const browserSavingToggle = $("#browser-saving-toggle");
const browserAutofillToggle = $("#browser-autofill-toggle");
const browserNote = $("#browser-pm-note");

function browserKind() {
  const brands = (navigator.userAgentData?.brands || []).map((entry) => entry.brand);
  if (navigator.brave || brands.includes("Brave")) return "brave";
  if (brands.includes("Microsoft Edge") || /Edg\//.test(navigator.userAgent || "")) return "edge";
  return "chrome";
}

const privacySetting = (name) => chrome.privacy?.services?.[name];

async function hasPrivacyPermission() {
  try { return Boolean(await chrome.permissions.contains({ permissions: ["privacy"] })); } catch { return false; }
}

async function readPrivacy(name) {
  const setting = privacySetting(name);
  if (!setting) return null;
  try { return await setting.get({}); } catch { return null; }
}

function browserMessage(text) {
  browserNote.textContent = text;
  browserNote.hidden = !text;
}

/** Set (enable) or clear one group of browser settings. Never reports success it didn't get. */
async function applyBrowserSettings(group, enable) {
  const names = BROWSER_SETTINGS[group];
  if (!enable) {
    for (const name of names) { try { await privacySetting(name)?.clear({}); } catch { /* already the browser's */ } }
    return "cleared";
  }
  for (const name of names) {
    const state = await readPrivacy(name);
    if (!state) return "unavailable";
    if (BLOCKED_TEXT[state.levelOfControl]) return state.levelOfControl;
  }
  for (const name of names) {
    try { await privacySetting(name).set({ value: false }); } catch { return "error"; }
  }
  for (const name of names) {
    const state = await readPrivacy(name);
    if (state?.levelOfControl !== "controlled_by_this_extension" || state.value !== false) return BLOCKED_TEXT[state?.levelOfControl] ? state.levelOfControl : "error";
  }
  return "ok";
}

async function renderBrowserState() {
  const kind = browserKind();
  $("#browser-pm-path").textContent = PASSWORD_SETTINGS[kind];
  // Only Chrome reliably opens its own password page from an extension; elsewhere the path is shown as text.
  $("#open-password-settings").hidden = kind !== "chrome";
  const granted = await hasPrivacyPermission();
  const [saving, address, card] = granted
    ? await Promise.all([...BROWSER_SETTINGS.saving, ...BROWSER_SETTINGS.autofill].map(readPrivacy))
    : [null, null, null];
  const ours = (state) => state?.levelOfControl === "controlled_by_this_extension" && state.value === false;
  const savingOurs = ours(saving);
  browserSavingToggle.checked = savingOurs;
  browserAutofillToggle.checked = savingOurs && ours(address) && ours(card);
  browserAutofillToggle.disabled = !savingOurs;
  browserSavingToggle.disabled = Boolean(saving && BLOCKED_TEXT[saving.levelOfControl]);
  $("#browser-chip").hidden = !savingOurs;
  if (saving && BLOCKED_TEXT[saving.levelOfControl]) browserMessage(BLOCKED_TEXT[saving.levelOfControl]);
  return { granted, savingOurs };
}

function reportBrowserResult(group, enable, result) {
  logEvent(`browser_${group}_${enable ? "on" : "off"}`, result, "");
  if (result === "ok" || result === "cleared") {
    browserMessage("");
    showMessage(group === "saving"
      ? (enable ? "The browser won't offer to save passwords. Nuvori will." : "The browser's password saving is back under its own settings.")
      : (enable ? "The browser's address and card autofill is off." : "The browser's address and card autofill is back under its own settings."));
  } else if (BLOCKED_TEXT[result]) {
    browserMessage(BLOCKED_TEXT[result]);
  } else if (result === "denied") {
    browserMessage("Nuvori needs permission to change this browser setting. Nothing was changed.");
  } else {
    browserMessage("This browser didn't accept the change. Nothing was changed.");
  }
}

browserSavingToggle.addEventListener("change", async () => {
  const enable = Boolean(browserSavingToggle.checked);
  if (enable) {
    // Asked for from the click itself: no install-time warning, and only if the user wants this.
    let granted = false;
    try { granted = await chrome.permissions.request({ permissions: ["privacy"] }); } catch { granted = false; }
    if (!granted) {
      reportBrowserResult("saving", true, "denied");
      await renderBrowserState();
      return;
    }
  }
  const result = await applyBrowserSettings("saving", enable);
  if (!enable) await applyBrowserSettings("autofill", false); // The second switch depends on the first.
  reportBrowserResult("saving", enable, result);
  await renderBrowserState();
});

browserAutofillToggle.addEventListener("change", async () => {
  const enable = Boolean(browserAutofillToggle.checked);
  const result = (await hasPrivacyPermission()) ? await applyBrowserSettings("autofill", enable) : "denied";
  reportBrowserResult("autofill", enable, result);
  await renderBrowserState();
});

$("#open-password-settings").addEventListener("click", async () => {
  const url = PASSWORD_SETTINGS[browserKind()];
  try {
    await chrome.tabs.create({ url });
    logEvent("open_password_settings", "ok", "");
  } catch {
    logEvent("open_password_settings", "error", "");
    showMessage(`Open a new tab and go to ${url}`);
  }
});

for (const [selector, key] of Object.entries(SWITCHES)) {
  const toggle = $(selector);
  toggle?.addEventListener?.("change", () => { void chrome.storage.local.set({ [key]: Boolean(toggle.checked) }); });
}

startupUnlockToggle?.addEventListener("change", () => {
  void chrome.storage.local.set({ unlockOnStartup: Boolean(startupUnlockToggle.checked) });
  showMessage(startupUnlockToggle.checked ? "Nuvori will ask for its password when the browser starts." : "Nuvori won't ask when the browser starts. Use Unlock Nuvori when you need it.");
});

const UNLOCK_TEXT = {
  ok: "Nuvori is already unlocked.",
  locked: "Enter your master password in the Nuvori window.",
  starting: "Nuvori is starting. Enter your master password in its window.",
  unsupported: "Update Nuvori for Windows to unlock it from here.",
  host_missing: "Register the Nuvori native host for this extension. Setup steps are above.",
};

unlockButton?.addEventListener("click", async () => {
  unlockButton.disabled = true;
  let result;
  try { result = await chrome.runtime.sendMessage({ action: "unlock_app" }); } catch { result = { status: "error" }; }
  unlockButton.disabled = false;
  showMessage(UNLOCK_TEXT[result?.status] || "Couldn't open Nuvori. Start it from the Windows Start menu.");
  if (result?.status === "ok") await checkConnection();
});

inlineToggle.addEventListener("change", () => {
  void chrome.storage.local.set({ inlineSuggestions: Boolean(inlineToggle.checked) });
  showMessage(inlineToggle.checked ? "Nuvori suggests logins in pages." : "In-page suggestions are off. Use this popup to fill.");
});

const ACTION_LABEL = {
  browser_saving_on: "Browser saving off", browser_saving_off: "Browser saving restored",
  browser_autofill_on: "Browser autofill off", browser_autofill_off: "Browser autofill restored",
  open_password_settings: "Open browser passwords",
  status: "Status check", query_credentials: "Find logins", fill_credential: "Release login", seal_login: "Encrypt capture",
  commit_login: "Save login", update_login: "Update password", review_login: "Review capture", inline_fill: "Fill in page",
  inline_never: "Never save", inline_dismiss: "Not now", inline_dont_suggest: "Stop suggestions",
};
const STATUS_TONE = {
  cleared: "success", denied: "warning", not_controllable: "warning", controlled_by_other_extensions: "warning", unavailable: "error",
  ok: "success", saved: "success", already_saved: "success", sealed: "success", needs_save: "success",
  locked: "warning", selection_expired: "warning", account_exists: "warning", missing: "warning",
  offline: "error", host_missing: "error", desktop_unavailable: "error", error: "error", invalid_request: "error", retry: "warning",
};

async function loadDiagnostics() {
  const list = $("#diag-list");
  const empty = $("#diag-empty");
  let entries = [];
  try {
    const saved = await chrome.storage.session?.get("diagnostics");
    entries = Array.isArray(saved?.diagnostics) ? saved.diagnostics : [];
  } catch { entries = []; }
  list.replaceChildren(...entries.slice(0, 20).map((entry) => {
    const row = document.createElement("li");
    const time = document.createElement("span");
    time.className = "diag-time";
    time.textContent = new Date(entry.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    const what = document.createElement("span");
    what.className = "diag-what";
    what.textContent = `${ACTION_LABEL[entry.action] || entry.action}${entry.host ? ` · ${entry.host}` : ""}`;
    const status = document.createElement("span");
    status.className = "diag-status";
    status.dataset.tone = STATUS_TONE[entry.status] || "neutral";
    status.textContent = String(entry.status || "").replace(/_/g, " ");
    row.append(time, what, status);
    return row;
  }));
  empty.hidden = entries.length > 0;
}

$("#test-connection").addEventListener("click", async () => {
  const state = await checkConnection();
  showMessage(state === "ready" ? "Connected. The Windows vault is unlocked."
    : state === "locked" ? "Connected, but the Windows vault is locked."
    : "Can't reach Nuvori for Windows. Follow the setup steps above.");
  await loadDiagnostics();
});

$("#diag-clear").addEventListener("click", async () => {
  await chrome.storage.session?.set({ diagnostics: [] });
  await loadDiagnostics();
});

$("#reconnect").addEventListener("click", async () => {
  retryDelay = 2000;
  if (origin) await findAccounts();
  else await checkConnection();
});

// ---------------------------------------------------------------------------
// Start

const extId = $("#ext-id");
if (extId) extId.textContent = chrome.runtime.id || "<extension ID>";

void loadFeatures();
void renderBrowserState().catch(() => {});
void refreshPending().catch((error) => showMessage(error.message));
void loadSettings().catch(() => {});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.pendingLogins) void refreshPending().catch((error) => showMessage(error.message));
  if (area === "local" && (changes.inlineSuggestions || changes.neverSave || changes.noSuggest || changes.unlockOnStartup)) void loadSettings().catch(() => {});
  if (area === "session" && changes.diagnostics) void loadDiagnostics();
});

currentHttpsTab().then(({ tabId: currentTabId, origin: currentOrigin }) => {
  tabId = currentTabId;
  origin = currentOrigin;
  site.textContent = new URL(currentOrigin).host;
  setConnection("checking");
  void findAccounts();
}).catch((error) => {
  origin = undefined;
  site.textContent = "Not a secure site";
  findButton.disabled = true;
  captureButton.disabled = true;
  showMessage(error.message);
  void checkConnection();
});
