// Firefox smoke test: installs the Firefox package as a temporary add-on in Playwright's Firefox
// (through the remote debugging protocol, as about:debugging does), registers the fake native host
// under HKCU\Software\Mozilla\NativeMessagingHosts, and checks the Firefox-specific behaviour.
//   node firefox-smoke.mjs <unpacked Firefox package dir>
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { firefox } from "playwright";
import { seedVault, register as registerChromium, unregister as unregisterChromium, STATE_DIR } from "./setup.mjs";
import { start as startFixtures } from "./fixtures/server.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ADDON_ID = "password-fill@nuvori.santoshkanumuri.com";
const KEY = "HKCU\\Software\\Mozilla\\NativeMessagingHosts\\com.nuvori.desktop";
const source = path.resolve(process.argv[2] || path.join(STATE_DIR, "ff-src"));
const shots = path.join(STATE_DIR, "shots");
fs.mkdirSync(shots, { recursive: true });

function registerFirefoxHost() {
  registerChromium(); // writes .state/host.bat
  const manifest = path.join(STATE_DIR, "com.nuvori.desktop.firefox.json");
  fs.writeFileSync(manifest, JSON.stringify({ name: "com.nuvori.desktop", description: "fake host (e2e)", path: path.join(STATE_DIR, "host.bat"), type: "stdio", allowed_extensions: [ADDON_ID] }, null, 2));
  execFileSync("reg", ["add", KEY, "/ve", "/t", "REG_SZ", "/d", manifest, "/f"], { stdio: "ignore" });
}
function unregisterFirefoxHost() {
  try { execFileSync("reg", ["delete", KEY, "/f"], { stdio: "ignore" }); } catch {}
  unregisterChromium();
}

/** Remote debugging protocol: "length:json" frames. Installs a temporary add-on from a folder. */
async function installTemporaryAddon(port, dir) {
  const socket = await new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => resolve(s));
    s.on("error", reject);
  });
  let buffer = "";
  const waiters = [];
  socket.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    for (;;) {
      const colon = buffer.indexOf(":");
      if (colon < 0) break;
      const length = Number(buffer.slice(0, colon));
      if (buffer.length < colon + 1 + length) break;
      const packet = JSON.parse(buffer.slice(colon + 1, colon + 1 + length));
      buffer = buffer.slice(colon + 1 + length);
      const index = waiters.findIndex((w) => w.match(packet));
      if (index >= 0) waiters.splice(index, 1)[0].resolve(packet);
    }
  });
  const next = (match) => new Promise((resolve) => waiters.push({ match, resolve }));
  const send = (packet) => { const text = JSON.stringify(packet); socket.write(`${Buffer.byteLength(text)}:${text}`); };
  await next((p) => p.from === "root" && p.applicationType);
  send({ to: "root", type: "getRoot" });
  const root = await next((p) => p.from === "root" && p.addonsActor);
  send({ to: root.addonsActor, type: "installTemporaryAddon", addonPath: dir });
  const installed = await next((p) => p.from === root.addonsActor);
  socket.end();
  if (!installed.addon) throw new Error("install failed: " + JSON.stringify(installed));
  return installed.addon.id;
}

const log = () => fs.readFileSync(path.join(STATE_DIR, "host-log.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
const results = [];
const check = (name, ok, note) => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"} ${name} — ${note}`); };

seedVault();
registerFirefoxHost();
const stopFixtures = startFixtures();
const port = 6123;
const browser = await firefox.launchPersistentContext(path.join(STATE_DIR, "ff-profile-" + Date.now()), {
  headless: !process.env.HEADED,
  viewport: { width: 1280, height: 900 },
  ignoreHTTPSErrors: true,
  args: ["-start-debugger-server", String(port)],
  firefoxUserPrefs: {
    "devtools.debugger.remote-enabled": true,
    "devtools.debugger.prompt-connection": false,
    "devtools.chrome.enabled": true,
    "extensions.experiments.enabled": true,
  },
});
try {
  await sleep(2000);
  const id = await installTemporaryAddon(port, source);
  check("install", id === ADDON_ID, `temporary add-on ${id}`);
  await sleep(2500);
  const page = await browser.newPage();

  // 1. A login for this site: list appears and fills with ↓ + Enter (no IntersectionObserver v2).
  await page.goto("https://the-internet.herokuapp.com/login", { waitUntil: "load" });
  await sleep(2000);
  await page.locator("#username").click();
  await sleep(1500);
  await page.screenshot({ path: path.join(shots, "ff-1-list.png") });
  await page.keyboard.press("ArrowDown");
  await sleep(700);
  await page.keyboard.press("Enter");
  await sleep(1500);
  const user = await page.inputValue("#username"), pass = await page.inputValue("#password");
  check("login list fills (keyboard)", user === "tomsmith" && pass === "SuperSecretPassword!", `username="${user}", password ${pass ? "filled" : "empty"}`);

  // 2. The same with a real mouse click on the first option (guard without a visibility report).
  await page.goto("https://the-internet.herokuapp.com/login", { waitUntil: "load" });
  await sleep(2000);
  const box = await page.locator("#username").boundingBox();
  await page.locator("#username").click();
  await sleep(1500);
  await page.screenshot({ path: path.join(shots, "ff-2-list.png") });
  await page.mouse.move(box.x + 60, box.y + box.height + 62);
  await sleep(300);
  await page.mouse.click(box.x + 60, box.y + box.height + 62);
  await sleep(1500);
  check("login list fills (mouse click)", (await page.inputValue("#password")) === "SuperSecretPassword!", `password ${(await page.inputValue("#password")) ? "filled" : "empty"}`);

  // 3. Save prompt after submit, then "Already saved" style flow: submit and look for the card.
  await page.locator("button[type=submit]").click();
  await page.waitForURL(/secure/, { timeout: 15000 });
  await sleep(2000);
  await page.screenshot({ path: path.join(shots, "ff-3-after-submit.png") });
  const captured = log().filter((e) => e.action === "review_login" && /herokuapp/.test(e.origin));
  check("capture on submit", captured.some((e) => e.status === "already_saved"), `review_login: ${captured.map((e) => e.status).join(", ") || "none"}`);

  // 4. Card fields: no in-page card list in Firefox.
  const before = log().length;
  await page.goto("https://autofill.me/form/credit-card-simple", { waitUntil: "load" });
  await sleep(2000);
  await page.locator("#cc-number").click();
  await sleep(1200);
  await page.keyboard.press("ArrowDown");
  await sleep(1200);
  await page.screenshot({ path: path.join(shots, "ff-4-card.png") });
  const cardQueries = log().slice(before).filter((e) => e.action === "query_items" && e.kind === "card");
  check("no in-page card list", cardQueries.length === 0, `${cardQueries.length} card queries reached the vault`);

  // 5. A new login on a site with nothing saved: Save prompt after sign-in.
  await page.goto("https://www.saucedemo.com/", { waitUntil: "load" });
  await sleep(1500);
  await page.locator("#user-name").click(); await page.keyboard.press("Escape");
  await page.locator("#user-name").pressSequentially("standard_user");
  await page.locator("#password").click(); await page.keyboard.press("Escape");
  await page.locator("#password").pressSequentially("secret_sauce");
  await page.locator("#login-button").click();
  await page.waitForURL(/inventory/, { timeout: 15000 });
  await sleep(3000);
  await page.screenshot({ path: path.join(shots, "ff-5-save-card.png") });
  const review = log().filter((e) => e.action === "review_login" && /saucedemo/.test(e.origin));
  check("save prompt for a new login", review.some((e) => e.status === "needs_save"), `review_login: ${review.map((e) => e.status).join(", ") || "none"} (see ff-5-save-card.png)`);

  // 6. Click Save on the card (top-right, 352 px wide, buttons at its bottom-left).
  const vp = page.viewportSize();
  for (const [dx, dy] of [[50, 268], [50, 250], [50, 285]]) {
    await page.mouse.move(vp.width - 16 - 352 + dx, dy); await sleep(500);
    await page.mouse.click(vp.width - 16 - 352 + dx, dy); await sleep(1500);
    if (log().some((e) => e.action === "commit_login" && /saucedemo/.test(e.origin))) break;
  }
  await page.screenshot({ path: path.join(shots, "ff-6-saved.png") });
  const committed = log().filter((e) => e.action === "commit_login" && /saucedemo/.test(e.origin));
  check("Save on the card stores the login", committed.some((e) => e.status === "saved"), `commit_login: ${committed.map((e) => e.status).join(", ") || "none"}`);
} finally {
  await browser.close();
  stopFixtures();
  unregisterFirefoxHost();
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
