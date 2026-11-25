// End-to-end: "Sign in with <provider>" detection and the "Remember that you use ...?" card, in
// Playwright's Chromium with the unpacked extension, a throwaway profile and the fake native host.
// Every page is synthetic and local: the browser resolves accounts.google.com,
// login.microsoftonline.com and *.nuvori-e2e.test to a local HTTPS server (--host-resolver-rules),
// so no real provider, account or site is ever contacted.
//   node signins.mjs          (after node setup.mjs; needs .state/key.pem and cert.pem for those names, see README)
//   HEADED=1 node signins.mjs
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import * as d from "./lib/driver.mjs";
import { seedVault, register, unregister } from "./setup.mjs";

const PORT = 8445;
const SITE = "https://app.nuvori-e2e.test";
const BROKER = "https://auth.nuvori-e2e.test";
const GOOGLE = "https://accounts.google.com";
const MICROSOFT = "https://login.microsoftonline.com";
const results = [];

// ---------------------------------------------------------------------------- local pages
const html = (title, body, script = "") => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>body{font:16px system-ui;margin:32px}button,[role=link]{display:block;margin:10px 0;font:inherit;padding:8px 14px;cursor:pointer}
[role=link]{border:1px solid #888;border-radius:8px;width:320px}</style></head><body>${body}<script>${script}</script></body></html>`;

const SITE_HOME = html("E2E app", `<h1>E2E app</h1>
  <p id="who">Signed out</p>
  <iframe id="gsi" src="${GOOGLE}/gsi/button?client_id=e2e.apps.googleusercontent.com" width="300" height="60" style="border:0"></iframe>
  <button id="quick">Continue with Google (one account)</button>
  <button id="ms">Sign in with Microsoft</button>
  <button id="fb">Continue with Google (Firebase)</button>
  <button id="redirect">Sign in with Google (full page)</button>
  <div popover id="team" style="padding:20px;border:2px solid #333">Team search</div>`, `
  // The page's own keyboard shortcuts, like a dashboard's "t" for team search: on window (capture)
  // and on document (bubbling), ignoring keys typed into the page's own fields.
  window.pageKeys = [];
  const typing = (event) => /^(INPUT|TEXTAREA)$/.test(event.target.tagName) || event.target.isContentEditable;
  window.addEventListener("keydown", (event) => { if (!typing(event)) window.pageKeys.push("capture:" + event.key); }, true);
  document.addEventListener("keydown", (event) => {
    if (typing(event)) return;
    window.pageKeys.push(event.key);
    if (event.key === "t") document.getElementById("team").showPopover();
  });
  // A press anywhere else closes the team search, as menus do.
  document.addEventListener("mousedown", () => { try { document.getElementById("team").hidePopover(); } catch {} });
  window.addEventListener("message", (event) => {
    if (!event.data || !event.data.signedIn) return;
    document.getElementById("who").textContent = "Welcome";
    history.pushState({}, "", "/home");
  });
  const popup = (url, name) => window.open(url, name, "width=480,height=640");
  document.getElementById("quick").onclick = () => popup("${GOOGLE}/o/oauth2/v2/auth?client_id=e2e&redirect_uri=" + encodeURIComponent("storagerelay://https/app.nuvori-e2e.test?id=auth1") + "&response_type=permission%20id_token&scope=openid%20email%20profile&e2e_auto=1", "g1");
  document.getElementById("ms").onclick = () => popup("${MICROSOFT}/common/oauth2/v2.0/authorize?client_id=e2e&scope=openid%20profile%20offline_access&response_mode=fragment&response_type=code&redirect_uri=" + encodeURIComponent("${SITE}/blank.html"), "ms");
  // Google Identity Services in redirect mode: the whole page goes to Google, which posts back to login_uri.
  document.getElementById("redirect").onclick = () => { location.href = "${GOOGLE}/gsi/select?client_id=e2e.apps.googleusercontent.com&ux_mode=redirect&login_uri=" + encodeURIComponent("${SITE}/login/google"); };
  document.getElementById("fb").onclick = () => popup("${BROKER}/__/auth/handler?apiKey=e2e&authType=signInViaPopup&providerId=google.com", "fb");`);

const CHOOSER = html("Sign in - Google Accounts", `<h1>Choose an account</h1><div>to continue to app.nuvori-e2e.test</div>
  <ul style="list-style:none;padding:0">
  <li><div role="link" tabindex="0" data-identifier="jamie.e2e@example.com"><div>Jamie E2E</div><div data-email="jamie.e2e@example.com">jamie.e2e@example.com</div></div></li>
  <li><div role="link" tabindex="0" data-identifier="work.e2e@example.org"><div>Jamie (Work)</div><div data-email="work.e2e@example.org">work.e2e@example.org</div></div></li>
  <li><div role="link" tabindex="0">Use another account</div></li></ul>`, `
  const params = new URLSearchParams(location.search);
  for (const tile of document.querySelectorAll("[data-identifier]")) tile.onclick = () => {
    const redirect = params.get("redirect_uri") || "";
    // GIS redirect mode: post the credential to the site's login_uri, as Google does.
    const login = new URL(params.get("continue") || location.href).searchParams.get("login_uri") || "";
    if (login.startsWith("https://")) {
      const form = document.createElement("form");
      form.method = "post";
      form.action = login;
      form.innerHTML = '<input type="hidden" name="credential" value="e2e-id-token">';
      document.body.append(form);
      form.submit();
      return;
    }
    // OAuth redirect mode (a broker's handler) or the GIS popup answering its opener by postMessage.
    if (redirect.startsWith("https://")) { location.href = redirect + "?state=s&code=e2e-code"; return; }
    window.opener && window.opener.postMessage({ signedIn: tile.dataset.identifier }, "*");
    window.close();
  };`);

function route(host, url) {
  const query = url.searchParams;
  if (host === "app.nuvori-e2e.test") {
    if (url.pathname === "/" || url.pathname === "/home") return { body: SITE_HOME };
    if (url.pathname === "/login/google") return { status: 302, location: "/home" };
    if (url.pathname === "/blank.html") return { body: html("", "", `window.opener && window.opener.postMessage({ signedIn: "ms" }, "*"); setTimeout(() => window.close(), 50);`) };
  }
  if (host === "auth.nuvori-e2e.test" && url.pathname === "/__/auth/handler") {
    if (query.get("code")) return { body: html("Firebase", "", `window.opener && window.opener.postMessage({ signedIn: "fb" }, "*"); setTimeout(() => window.close(), 50);`) };
    return { body: html("Firebase", "Redirecting", `location.href = "${GOOGLE}/o/oauth2/auth?response_type=code&client_id=e2e&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email%20profile&redirect_uri=" + encodeURIComponent("${BROKER}/__/auth/handler");`) };
  }
  if (host === "accounts.google.com") {
    if (url.pathname === "/gsi/button") {
      // Google's button frame: the popup opens from this frame and answers it; the frame tells the page.
      return { body: html("GIS button", `<div role="button" id="b" tabindex="0" style="border:1px solid #888;padding:8px">Sign in with Google</div>`, `
        document.getElementById("b").onclick = () => window.open("${GOOGLE}/gsi/select?client_id=e2e.apps.googleusercontent.com&ux_mode=popup&ui_mode=card&channel_id=c1&origin=" + encodeURIComponent("${SITE}"), "gsi", "width=480,height=640");
        window.addEventListener("message", (event) => { if (event.data && event.data.signedIn) parent.postMessage(event.data, "*"); });`) };
    }
    if (url.pathname === "/gsi/select") return { status: 302, location: `/v3/signin/accountchooser?client_id=${query.get("client_id")}&continue=${encodeURIComponent(url.href)}&flowName=GeneralOAuthLite` };
    if (url.pathname === "/o/oauth2/v2/auth" || url.pathname === "/o/oauth2/auth") {
      // One account, consent given before: the popup answers and closes itself, no click.
      if (query.get("e2e_auto")) return { body: html("Signing in", "One moment", `setTimeout(() => { window.opener && window.opener.postMessage({ signedIn: "auto" }, "*"); window.close(); }, 600);`) };
      const next = new URL("/v3/signin/accountchooser", GOOGLE);
      for (const [key, value] of query) next.searchParams.set(key, value);
      return { status: 302, location: next.pathname + next.search };
    }
    if (url.pathname === "/v3/signin/accountchooser") return { body: CHOOSER };
  }
  if (host === "login.microsoftonline.com" && url.pathname === "/common/oauth2/v2.0/authorize") {
    // A single-page sign-in: the identity banner appears without a page load ("Approve sign in
    // request" in the Authenticator app), then the page answers by itself. No click on the page.
    return { body: html("Sign in to your account", `<div id="app"><div>Sign in</div></div>`, `
      setTimeout(() => { document.getElementById("app").innerHTML = '<div class="identityBanner"><div id="displayName" class="identity">sam.e2e@contoso.example</div></div><div>Approve sign in request</div><div>42</div>'; }, 900);
      setTimeout(() => { location.href = new URLSearchParams(location.search).get("redirect_uri") + "#code=e2e-code&state=s"; }, 3200);`) };
  }
  return { status: 404, body: "not found" };
}

function startServer() {
  const dir = path.join(d.STATE_DIR);
  const tls = { key: fs.readFileSync(path.join(dir, "key.pem")), cert: fs.readFileSync(path.join(dir, "cert.pem")) };
  const server = https.createServer(tls, (request, response) => {
    const host = String(request.headers.host || "").replace(/:\d+$/, "");
    const answer = route(host, new URL(request.url, `https://${host}`));
    if (answer.location) { response.writeHead(answer.status || 302, { location: answer.location }); response.end(); return; }
    response.writeHead(answer.status || 200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end(answer.body);
  });
  return new Promise((resolve) => server.listen(PORT, "127.0.0.1", () => resolve(server)));
}

// ---------------------------------------------------------------------------- helpers
function expect(condition, message) { if (!condition) throw new Error(message); }
const signInCard = (page, provider, timeout = 15000) =>
  d.waitForSurface(page, (surface) => surface.kind === "card" && new RegExp(`Remember that you use ${provider}`).test(surface.text), { timeout });

const inputValue = d.inputValue;

async function openSite(context) {
  const page = await context.newPage();
  await page.goto(`${SITE}/`, { waitUntil: "load" });
  await d.sleep(1500); // content scripts at document_idle
  return page;
}

const remembered = () => d.readState().signIns || [];

// ---------------------------------------------------------------------------- scenarios
const S = [];
const scenario = (id, title, fn) => S.push({ id, title, fn });

scenario("G1", "Google GIS button popup: chosen account is prefilled; typing never reaches the page; one click saves", async ({ context }) => {
  const page = await openSite(context);
  const popupPromise = context.waitForEvent("page");
  await page.frameLocator("#gsi").locator("#b").click();
  const popup = await popupPromise;
  await popup.waitForLoadState("load");
  await d.sleep(1200);
  await popup.locator("[data-identifier='work.e2e@example.org']").click();
  const card = await signInCard(page, "Google");
  expect(card, "no sign-in card after the Google popup");
  const field = card.inputs.find((input) => /Account you used/.test(input.label));
  expect(field, "no account field");
  const prefilled = await inputValue(page, field.nodeId);
  expect(prefilled === "work.e2e@example.org", `account prefilled as ${JSON.stringify(prefilled)}`);
  // Keyboard isolation: "t" must not open the page's team search, and no page listener sees a key.
  await page.evaluate(() => { window.pageKeys = []; });
  await d.typeInSurfaceInput(page, card, card.inputs.indexOf(field), "team.t@example.org");
  const pageKeys = await page.evaluate(() => window.pageKeys);
  const teamOpen = await page.evaluate(() => document.getElementById("team").matches(":popover-open"));
  if (!process.env.E2E_IGNORE_KEYS) expect(pageKeys.length === 0 && !teamOpen, `the page saw keys ${JSON.stringify(pageKeys)} (team search open: ${teamOpen})`);
  const typed = await inputValue(page, field.nodeId);
  expect(typed === "team.t@example.org", `the field holds ${JSON.stringify(typed)}`);
  // One click on Save.
  const before = d.hostLog().filter((entry) => entry.action === "record_sign_in").length;
  await d.clickInSurface(page, card, /^Save$/, { delay: 600 });
  const done = await d.waitForSurface(page, (surface) => surface.kind === "card" && /Remembered/.test(surface.text), { timeout: 6000 });
  expect(done, "Save needed more than one click");
  const calls = d.hostLog().filter((entry) => entry.action === "record_sign_in").length - before;
  const row = remembered().find((entry) => entry.site === "app.nuvori-e2e.test" && entry.provider === "google");
  expect(calls === 1 && row?.account === "team.t@example.org", `record_sign_in calls ${calls}, stored ${JSON.stringify(remembered())}`);
  await page.close();
});

scenario("G2", "Google popup that answers and closes by itself (no click in it): the opener's pushState counts", async ({ context }) => {
  const page = await openSite(context);
  const known = remembered().some((entry) => entry.site === "app.nuvori-e2e.test" && entry.provider === "google");
  const calls = () => d.hostLog().filter((entry) => entry.action === "record_sign_in").length;
  const before = calls();
  await page.locator("#quick").click();
  if (known) {
    // Google is already remembered here and this popup showed no account: Nuvori notes the use quietly.
    let quiet = false;
    for (let waited = 0; waited < 15000 && !quiet; waited += 500) { await d.sleep(500); quiet = calls() > before; }
    expect(quiet, "the known sign-in was not noted");
  } else {
    const card = await signInCard(page, "Google");
    expect(card, "no sign-in card after a self-closing popup");
  }
  await page.close();
});

scenario("G3", "Google Identity Services in redirect mode (full page, posts to login_uri): asked on the site after the post", async ({ context }) => {
  const page = await openSite(context);
  await page.locator("#redirect").click();
  await page.waitForURL(/accountchooser/, { timeout: 10000 });
  await d.sleep(1200);
  await page.locator("[data-identifier='jamie.e2e@example.com']").click();
  await page.waitForURL(/app\.nuvori-e2e\.test\/home/, { timeout: 10000 });
  await d.sleep(1500);
  const known = remembered().some((entry) => entry.site === "app.nuvori-e2e.test" && entry.provider === "google" && entry.account === "jamie.e2e@example.com");
  const card = known ? true : await signInCard(page, "Google");
  expect(card, "no sign-in card after the full-page GIS sign-in");
  if (card !== true) {
    const field = card.inputs.find((input) => /Account you used/.test(input.label));
    const value = await inputValue(page, field.nodeId);
    expect(value === "jamie.e2e@example.com", `account prefilled as ${JSON.stringify(value)}`);
  }
  await page.close();
});

scenario("M1", "Microsoft MSAL-style popup: the account appears in the single-page step (no click) and is prefilled", async ({ context }) => {
  const page = await openSite(context);
  await page.locator("#ms").click();
  const card = await signInCard(page, "Microsoft", 20000);
  expect(card, "no sign-in card after the Microsoft popup");
  const field = card.inputs.find((input) => /Account you used/.test(input.label));
  const value = await inputValue(page, field.nodeId);
  expect(value === "sam.e2e@contoso.example", `account prefilled as ${JSON.stringify(value)}`);
  await page.close();
});

scenario("B1", "Broker popup (Firebase handler, then Google, then back): asked on the site with the chosen account", async ({ context }) => {
  const page = await openSite(context);
  const popupPromise = context.waitForEvent("page");
  await page.locator("#fb").click();
  const popup = await popupPromise;
  await popup.waitForURL(/accountchooser/, { timeout: 10000 });
  await d.sleep(1200);
  await popup.locator("[data-identifier='jamie.e2e@example.com']").click();
  const card = await signInCard(page, "Google");
  expect(card, "no sign-in card after the broker popup");
  expect(/app\.nuvori-e2e\.test/.test(card.text) && !/auth\.nuvori-e2e\.test/.test(card.text), `asked for the wrong site: ${card.text}`);
  const field = card.inputs.find((input) => /Account you used/.test(input.label));
  const value = await inputValue(page, field.nodeId);
  expect(value === "jamie.e2e@example.com", `account prefilled as ${JSON.stringify(value)}`);
  await page.close();
});

// ---------------------------------------------------------------------------- run
const filters = process.argv.slice(2).map((word) => word.toLowerCase());
seedVault();
register();
const server = await startServer();
const rules = ["accounts.google.com", "login.microsoftonline.com", "*.nuvori-e2e.test"].map((host) => `MAP ${host} 127.0.0.1:${PORT}`).join(",");
const { context, worker } = await d.launch({ profile: "profile-signins", args: [`--host-resolver-rules=${rules}`] });
try {
  for (const { id, title, fn } of S) {
    if (filters.length && !filters.some((word) => `${id} ${title}`.toLowerCase().includes(word))) continue;
    const started = Date.now();
    try {
      await fn({ context, worker });
      results.push({ id, title, ok: true, ms: Date.now() - started });
      console.log(`PASS ${id} ${title}`);
    } catch (error) {
      results.push({ id, title, ok: false, error: String(error.message || error) });
      console.log(`FAIL ${id} ${title}\n     ${error.message || error}`);
      for (const page of context.pages()) await d.shot(page, `signins-${id}-${page.url()}`);
      if (process.env.E2E_DEBUG) console.log(JSON.stringify(await worker.evaluate(async () => chrome.storage.session.get(null)), null, 1).slice(0, 4000));
    }
  }
} finally {
  await context.close();
  server.close();
  unregister();
}
fs.writeFileSync(path.join(d.STATE_DIR, "signins-results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
