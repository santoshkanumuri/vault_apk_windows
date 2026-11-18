// Drives Playwright's Chromium with the unpacked extension. Nuvori draws its list and cards in a
// closed shadow root, so the driver reads them through the DevTools protocol (DOM.getDocument with
// pierce), then clicks real mouse coordinates. The extension's own checks (trusted event, 400 ms
// delay, IntersectionObserver v2 visibility, hit test) stay fully on.
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.join(here, "..");
export const EXTENSION = path.join(ROOT, "..", "..", "extension");
export const STATE_DIR = path.join(ROOT, ".state");
const CHROMIUM = process.env.NUVORI_CHROMIUM
  || path.join(process.env.LOCALAPPDATA, "ms-playwright", "chromium-1234", "chrome-win64", "chrome.exe");

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function launch({ headless = process.env.HEADED ? false : true, profile = "profile" } = {}) {
  const userDataDir = path.join(STATE_DIR, profile);
  fs.rmSync(userDataDir, { recursive: true, force: true });
  const context = await chromium.launchPersistentContext(userDataDir, {
    executablePath: CHROMIUM,
    headless,
    viewport: { width: 1280, height: 900 },
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${EXTENSION}`,
      `--load-extension=${EXTENSION}`,
      "--ignore-certificate-errors",
      "--disable-features=PasswordManagerOnboarding,AutofillServerCommunication",
      "--password-store=basic",
    ],
  });
  let worker = context.serviceWorkers()[0];
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 15000 });
  return { context, worker };
}

export function readState() { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, "vault.json"), "utf8")); }
export function patchState(patch) {
  const state = readState();
  Object.assign(state, typeof patch === "function" ? patch(state) || {} : patch);
  fs.writeFileSync(path.join(STATE_DIR, "vault.json"), JSON.stringify(state, null, 2));
}
export function hostLog() {
  return fs.readFileSync(path.join(STATE_DIR, "host-log.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// ---------------------------------------------------------------------------- overlay reading
const cdpSessions = new WeakMap();
async function cdp(page) {
  let session = cdpSessions.get(page);
  if (!session) { session = await page.context().newCDPSession(page); cdpSessions.set(page, session); }
  return session;
}

function textOf(node) {
  if (!node) return "";
  if (node.nodeType === 3) return node.nodeValue;
  let out = "";
  for (const child of node.children || []) out += textOf(child) + (child.nodeType === 1 && /^(DIV|LI|P|LABEL)$/.test(child.nodeName) ? "\n" : " ");
  return out;
}
const attr = (node, name) => {
  const list = node.attributes || [];
  for (let i = 0; i < list.length; i += 2) if (list[i] === name) return list[i + 1];
  return undefined;
};
const hasClass = (node, cls) => (attr(node, "class") || "").split(/\s+/).includes(cls);

function* walk(node) {
  if (!node) return;
  yield node;
  for (const child of node.children || []) yield* walk(child);
  for (const root of node.shadowRoots || []) yield* walk(root);
  if (node.contentDocument) yield* walk(node.contentDocument);
}

/** Every Nuvori surface on the top page: { kind: "list"|"card"|"other", text, options, buttons, inputs }. */
export async function surfaces(page) {
  const session = await cdp(page);
  const { root } = await session.send("DOM.getDocument", { depth: -1, pierce: true });
  const found = [];
  for (const node of walk(root)) {
    if (node.nodeName !== "DIV" || !(node.shadowRoots || []).some((r) => r.shadowRootType === "closed")) continue;
    const shadow = node.shadowRoots.find((r) => r.shadowRootType === "closed");
    const nv = [...walk(shadow)].find((n) => n.nodeName === "DIV" && hasClass(n, "nv"));
    if (!nv) continue;
    const all = [...walk(nv)];
    const options = all.filter((n) => (n.nodeName === "LI" && hasClass(n, "option")) || hasClass(n, "choice")).map((n) => ({ nodeId: n.nodeId, text: textOf(n).replace(/\s+/g, " ").trim() }));
    const buttons = all.filter((n) => n.nodeName === "BUTTON" && attr(n, "hidden") === undefined).map((n) => ({ nodeId: n.nodeId, text: textOf(n).replace(/\s+/g, " ").trim() }));
    const inputs = all.filter((n) => n.nodeName === "INPUT").map((n) => ({ nodeId: n.nodeId, label: attr(n, "aria-label") || attr(n, "placeholder") || "" }));
    const text = textOf(nv).replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
    // The save/notice card's body is div.card; the suggestion list has none.
    const kind = all.some((n) => n.nodeName === "DIV" && hasClass(n, "card")) ? "card" : all.some((n) => hasClass(n, "panel")) ? "list" : "other";
    found.push({ kind, text, options, buttons, inputs, hostId: node.nodeId });
  }
  return found;
}

async function boxCenter(page, nodeId) {
  const session = await cdp(page);
  const { model } = await session.send("DOM.getBoxModel", { nodeId });
  const q = model.border;
  return { x: (q[0] + q[2] + q[4] + q[6]) / 4, y: (q[1] + q[3] + q[5] + q[7]) / 4 };
}

export async function waitForSurface(page, predicate, { timeout = 8000 } = {}) {
  const until = Date.now() + timeout;
  let last = [];
  while (Date.now() < until) {
    last = await surfaces(page).catch(() => []);
    const hit = last.find(predicate);
    if (hit) return hit;
    await sleep(200);
  }
  return null;
}
export const listSurface = (page, opts) => waitForSurface(page, (s) => s.kind === "list" && (s.options.length || /locked|unlock|no saved|start nuvori|not connected|search/i.test(s.text)), opts);

/** Click a Nuvori option or button whose text matches, after the activation delay. */
export async function clickInSurface(page, surface, match, { delay = surface.kind === "card" ? 1200 : 700 } = {}) {
  const re = match instanceof RegExp ? match : new RegExp(match.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  const target = [...surface.options, ...surface.buttons].find((entry) => re.test(entry.text));
  if (!target) throw new Error(`no Nuvori control matching ${re} in: ${[...surface.options, ...surface.buttons].map((e) => e.text).join(" | ")}`);
  await sleep(delay);
  const point = await boxCenter(page, target.nodeId);
  await page.mouse.move(point.x, point.y);
  await sleep(150);
  await page.mouse.click(point.x, point.y);
  return target.text;
}

export async function typeInSurfaceInput(page, surface, index, text) {
  const input = surface.inputs[index];
  const point = await boxCenter(page, input.nodeId);
  await sleep(700);
  await page.mouse.click(point.x, point.y);
  await page.keyboard.press("Control+A");
  await page.keyboard.type(text);
}

/** Focus a page field with a real click (frames included via locator). */
export async function focusField(locator) {
  await locator.scrollIntoViewIfNeeded().catch(() => {});
  await locator.click({ timeout: 8000 });
}

export async function diagnostics(worker) {
  return worker.evaluate(async () => (await chrome.storage.session.get("diagnostics")).diagnostics || []);
}
export async function setSettings(worker, values) {
  await worker.evaluate(async (v) => chrome.storage.local.set(v), values);
}
export async function shot(page, name) {
  const dir = path.join(STATE_DIR, "shots");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name.replace(/[^a-z0-9-]+/gi, "_") + ".png");
  await page.screenshot({ path: file }).catch(() => {});
  return file;
}
