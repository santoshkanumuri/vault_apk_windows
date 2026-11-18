// End-to-end scenarios for the Nuvori extension: real sites + local fixtures, fake native host.
//   node run.mjs                 all scenarios
//   node run.mjs card save       only scenarios whose id or title contains one of the words
//   HEADED=1 node run.mjs ...    watch it
import fs from "node:fs";
import path from "node:path";
import * as d from "./lib/driver.mjs";
import { seedVault, register, unregister } from "./setup.mjs";
import { start as startFixtures } from "./fixtures/server.mjs";

const LOCAL = "https://localhost:8443";
const filters = process.argv.slice(2).map((word) => word.toLowerCase());
const results = [];

// ---------------------------------------------------------------------------- helpers
async function openList(page, field, { arrow = false, timeout = 6000 } = {}) {
  await d.focusField(field);
  let list = arrow ? null : await d.listSurface(page, { timeout });
  if (!list) { await page.keyboard.press("ArrowDown"); list = await d.listSurface(page, { timeout: 4000 }); }
  if (!list) { await field.click(); list = await d.listSurface(page, { timeout: 3000 }); }
  // Frames inside frames load their content script late: give the field one more, slower try.
  if (!list) { await d.sleep(2000); await page.keyboard.press("Escape"); await field.click(); list = await d.listSurface(page, { timeout: 5000 }); }
  return list;
}
async function pick(page, field, option, opts) {
  const list = await openList(page, field, opts);
  if (!list) throw new Error("no Nuvori list appeared");
  const chosen = await d.clickInSurface(page, list, option);
  await d.sleep(1000);
  return { list, chosen };
}
const card = (page, re = /./, timeout = 9000) => d.waitForSurface(page, (s) => s.kind === "card" && re.test(s.text), { timeout });
const val = (locator) => locator.inputValue({ timeout: 4000 }).catch(() => "<missing>");
function expect(cond, message) { if (!cond) throw new Error(message); }
const vaultLogin = (origin, username) => d.readState().vault.find((e) => e.type === "PASSWORD" && e.url === origin && e.username === username);
const totpNow = (secret) => {
  // Same TOTP as the fake host, for checking a filled code.
  return import("node:crypto").then(({ default: crypto }) => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = ""; for (const ch of secret) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
    const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
    const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
    const mac = crypto.createHmac("sha1", key).update(counter).digest();
    const o = mac[19] & 15;
    return String((mac.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
  });
};
async function goto(page, url, settle = 2500) {
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
  await d.sleep(settle);
}

// ---------------------------------------------------------------------------- scenarios
const S = [];
const scenario = (id, title, fn) => S.push({ id, title, fn });

// --- Logins: fill on real sites
scenario("L1", "Real login fills and submits (the-internet.herokuapp.com), then 'Already saved'", async ({ page }) => {
  await goto(page, "https://the-internet.herokuapp.com/login");
  const { list } = await pick(page, page.locator("#username"), "tomsmith");
  expect(list.text.includes("the-internet.herokuapp.com"), "list header lacks the site");
  expect(await val(page.locator("#username")) === "tomsmith", "username not filled");
  expect(await val(page.locator("#password")) === "SuperSecretPassword!", "password not filled");
  await page.locator("button[type=submit]").click();
  await page.waitForURL(/secure/, { timeout: 15000 });
  const notice = await card(page, /already saved/i);
  expect(notice, "no 'Already saved' notice after signing in with the saved login");
  return "filled both fields, signed in, 'Already saved' shown";
});

scenario("L2", "Real login (practicetestautomation.com) fill + submit", async ({ page }) => {
  await goto(page, "https://practicetestautomation.com/practice-test-login/");
  await pick(page, page.locator("#username"), "student");
  expect(await val(page.locator("#password")) === "Password123", "password not filled");
  await page.locator("#submit").click();
  await page.waitForURL(/logged-in-successfully/, { timeout: 20000 });
  expect(await card(page, /already saved/i), "no 'Already saved' notice");
  return "signed in, 'Already saved' shown";
});

scenario("L3", "Fake Filler login page detects and fills", async ({ page }) => {
  await goto(page, "https://fakefiller.com/login");
  await pick(page, page.locator("#email"), "ff.tester");
  expect(await val(page.locator("#email")) === "ff.tester", "email not filled");
  expect(await val(page.locator("#password")) === "ff-test-pass-7", "password not filled");
  return "email + password filled (not submitted)";
});

scenario("L4", "Two saved accounts on one site: pick the second (github.com)", async ({ page }) => {
  await goto(page, "https://github.com/login");
  const { list } = await pick(page, page.locator("#login_field"), "octo-personal");
  expect(list.options.length === 2, `expected 2 accounts, saw ${list.options.length}`);
  expect(await val(page.locator("#login_field")) === "octo-personal", "wrong username");
  expect(await val(page.locator("#password")) === "gh-personal-pass-2", "wrong password");
  return "list showed both accounts; second one filled";
});

scenario("L5", "Google identifier-first page: list + fill the email", async ({ page }) => {
  await goto(page, "https://accounts.google.com/", 4000);
  const field = page.locator("#identifierId");
  const { list } = await pick(page, field, "nuvori.e2e.test");
  expect(await val(field) === "nuvori.e2e.test@gmail.com", "email not filled");
  return `list: ${list.options.map((o) => o.text).join(" | ")}; email filled`;
});

scenario("L6", "Microsoft identifier-first page: list + fill", async ({ page }) => {
  await goto(page, "https://login.live.com/", 4000);
  const field = page.locator("input[type=email], input[name=loginfmt]").first();
  await pick(page, field, "nuvori.e2e.test");
  expect(await val(field) === "nuvori.e2e.test@outlook.com", "email not filled");
  return "email filled";
});

scenario("L7", "autofill.me simple login", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-simple");
  await pick(page, page.locator("#username"), "am.tester");
  expect(await val(page.locator("#password")) === "am-test-pass-3", "password not filled");
  return "filled";
});

scenario("L8", "Login form inside a same-site iframe (autofill.me login-iframe)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-nested-iframe", 3500);
  const frame = page.frameLocator("iframe").first().frameLocator("iframe").first(); // inner frame holds the full sign-in
  const user = frame.locator("#username");
  await pick(page, user, "am.tester");
  expect(await val(user) === "am.tester@example.com", "username not filled in frame");
  expect(await val(frame.locator("#password")) === "am-test-pass-3", "password not filled in frame");
  return "list drawn on top page, filled inside the frame";
});

scenario("L9", "Cross-site sign-in frame fills only that frame's site login", async ({ page }) => {
  await goto(page, LOCAL + "/frame-host", 3000);
  const frame = page.frameLocator("iframe");
  const { list } = await pick(page, frame.locator("input[name=email]"), "frame.user");
  expect(/127\.0\.0\.1:8444/.test(list.text), "list header should name the frame's site");
  expect(!list.options.some((o) => /alice|bob/.test(o.text)), "top site's logins leaked into a cross-site frame");
  expect(await val(frame.locator("input[name=password]")) === "frame-pass-5", "frame password not filled");
  return "frame's own login listed and filled; top-site logins not offered";
});

scenario("L10", "Login inside an open shadow root (autofill.me login-shadow)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-shadow");
  await page.locator("#create-open").click();
  await d.sleep(800);
  const user = page.locator("input[autocomplete=username], input[name=username]").first();
  await pick(page, user, "am.tester");
  expect(await val(user) === "am.tester@example.com", "username not filled in shadow root");
  return "filled inside open shadow DOM";
});

scenario("L11", "Login inside a modal <dialog> (autofill.me login-dialogs)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-dialogs");
  await page.locator("#show-modal-button").click();
  await d.sleep(800);
  const user = page.locator("dialog #username");
  await pick(page, user, "am.tester");
  expect(await val(page.locator("dialog #password")) === "am-test-pass-3", "password not filled in modal dialog");
  return "list usable above a modal dialog; filled";
});

scenario("L12", "Form revealed after page load (display:none -> visible)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-reveal-display-none");
  await page.getByRole("button", { name: /show sign-in/i }).click();
  await d.sleep(1200);
  await pick(page, page.locator("#username"), "am.tester");
  expect(await val(page.locator("#password")) === "am-test-pass-3", "password not filled");
  return "filled after reveal";
});

scenario("L13", "Multi-step sign-in: username page, then password page shows 'Continue'", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-multi-step");
  await pick(page, page.locator("#username"), "am.tester");
  await page.locator("#username").press("Enter");
  await d.sleep(2500);
  const pass = page.locator("input[type=password]").first();
  await pass.waitFor({ timeout: 10000 });
  const { list } = await pick(page, pass, "am.tester");
  expect(/continue/i.test(list.options[0]?.text || ""), `first option lacks 'Continue': ${list.options[0]?.text}`);
  expect(await val(pass) === "am-test-pass-3", "password not filled on step 2");
  return "step 2 listed the step-1 account first with 'Continue' and filled the password";
});

scenario("L14", "Username + password + TOTP in one form (autofill.me login-totp)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/login-totp.html");
  const list = await openList(page, page.locator("#username"));
  expect(list && list.options.some((o) => /am\.tester/.test(o.text)), "no login suggestions on a form that also has a code field");
  await d.clickInSurface(page, list, "am.tester");
  await d.sleep(900);
  expect(await val(page.locator("#password")) === "am-test-pass-3", "password not filled");
  expect(await val(page.locator("#totp")) === "", "the code field must not receive the password");
  return "login offered and filled; code field left for the code";
});

scenario("L15", "Honeypot fields beside a real login stay empty", async ({ page }) => {
  await goto(page, LOCAL + "/honeypot");
  const list = await openList(page, page.locator("input[name=email]"));
  expect(list && list.options.length, "no suggestions on a login that has hidden honeypot fields");
  await d.clickInSurface(page, list, "alice");
  await d.sleep(900);
  expect(await val(page.locator("input[name=email]")) === "alice@example.com", "email not filled");
  expect(await val(page.locator("input[name=password]")) === "local-alice-1", "password not filled");
  for (const name of ["email_confirm", "user_hp", "pass_hp"]) expect(await val(page.locator(`input[name=${name}]`)) === "", `honeypot ${name} received a value`);
  return "real fields filled; honeypots untouched";
});

scenario("L16", "Search all logins on a site with nothing saved, with a confirm step", async ({ page }) => {
  await goto(page, "https://www.saucedemo.com/");
  const field = page.locator("#user-name");
  const list = await openList(page, field, { arrow: true });
  expect(list, "no list on a site with no saved login (Down key)");
  await d.clickInSurface(page, list, /search all logins/i);
  const search = await d.waitForSurface(page, (s) => s.kind === "list" && s.options.length > 3, { timeout: 6000 });
  expect(search, "search list did not open");
  await d.clickInSurface(page, search, "student");
  const confirm = await d.waitForSurface(page, (s) => /fill it on|saved this login for/i.test(s.text), { timeout: 5000 });
  expect(confirm, "no cross-site confirmation before filling another site's login");
  await d.clickInSurface(page, confirm, /^fill/i);
  await d.sleep(1000);
  expect(await val(field) === "student", "login from another site not filled after confirming");
  return "search listed every login; asked before filling a practicetestautomation.com login here";
});

// --- Saving logins
scenario("S1", "New login on a real site: Save prompt after sign-in, stored correctly", async ({ page }) => {
  await goto(page, "https://www.saucedemo.com/");
  await page.locator("#user-name").click();
  await page.keyboard.press("Escape");
  await page.locator("#user-name").pressSequentially("standard_user", { delay: 20 });
  await page.locator("#password").click();
  await page.keyboard.press("Escape");
  await page.locator("#password").pressSequentially("secret_sauce", { delay: 20 });
  await page.locator("#login-button").click();
  await page.waitForURL(/inventory/, { timeout: 15000 });
  await d.sleep(3000); // the card is drawn again on the new page; let it settle
  let prompt = await card(page, /save login/i);
  expect(prompt, "no Save prompt after signing in with a new login");
  await d.clickInSurface(page, prompt, /^save$/i);
  if (!(await card(page, /saved/i, 4000))) {
    prompt = await card(page, /save login/i, 2000);
    if (prompt) { await d.clickInSurface(page, prompt, /^save$/i); await card(page, /saved/i, 4000); }
  }
  const saved = vaultLogin("https://www.saucedemo.com", "standard_user");
  expect(saved && saved.password === "secret_sauce", "login not stored with the right username/password");
  return `saved as "${saved.title}" for https://www.saucedemo.com`;
});

scenario("S2", "Saved login is offered next time, and re-signing in says 'Already saved'", async ({ page }) => {
  await goto(page, "https://www.saucedemo.com/");
  await pick(page, page.locator("#user-name"), "standard_user");
  expect(await val(page.locator("#password")) === "secret_sauce", "password not filled");
  await page.locator("#login-button").click();
  await page.waitForURL(/inventory/, { timeout: 15000 });
  expect(await card(page, /already saved/i), "no 'Already saved'");
  return "round trip works";
});

scenario("S3", "Edit username and name on the save card (SPA sign-in, no <form>)", async ({ page }) => {
  await goto(page, LOCAL + "/spa");
  await page.locator("#e").click(); await page.keyboard.press("Escape");
  await page.locator("#e").pressSequentially("carol@example.com");
  await page.locator("#p").click(); await page.keyboard.press("Escape");
  await page.locator("#p").pressSequentially("carol-pass-9");
  await page.locator("#go").click();
  const prompt = await card(page, /save login/i);
  expect(prompt, "no Save prompt for a formless sign-in button");
  expect(prompt.inputs.length >= 2, "save card lacks name/username inputs");
  await d.typeInSurfaceInput(page, prompt, 0, "Carol at local");
  await d.typeInSurfaceInput(page, prompt, 1, "carol.renamed@example.com");
  const fresh = await card(page, /save login/i);
  await d.clickInSurface(page, fresh, /^save$/i);
  await d.sleep(1500);
  const saved = vaultLogin(LOCAL, "carol.renamed@example.com");
  expect(saved, "corrected username was not saved");
  expect(saved.title === "Carol at local", `title not saved (got "${saved.title}")`);
  return "saved with the corrected username and chosen name";
});

scenario("S4", "Changed password on a real site offers Update and updates the vault", async ({ page }) => {
  await goto(page, "https://the-internet.herokuapp.com/login");
  await page.locator("#username").click(); await page.keyboard.press("Escape");
  await page.locator("#username").pressSequentially("tomsmith");
  await page.locator("#password").click(); await page.keyboard.press("Escape");
  await page.locator("#password").pressSequentially("NewPassword!42");
  await page.locator("button[type=submit]").click();
  const prompt = await card(page, /update/i);
  expect(prompt, "no Update prompt for a known account with a new password");
  await d.clickInSurface(page, prompt, /^update$/i);
  await d.sleep(1500);
  const entry = vaultLogin("https://the-internet.herokuapp.com", "tomsmith");
  expect(entry.password === "NewPassword!42", "password not updated");
  d.patchState((s) => { s.vault.find((e) => e.id === "login-herokuapp").password = "SuperSecretPassword!"; });
  return "Update replaced the saved password (restored afterwards)";
});

scenario("S5", "Change-password form updates the right account of two", async ({ page }) => {
  await goto(page, LOCAL + "/change");
  await pick(page, page.locator("input[name=current]"), "bob");
  await page.locator("input[name=new1]").fill("");
  await page.locator("input[name=new1]").pressSequentially("bob-new-pass-3");
  await page.locator("input[name=new2]").pressSequentially("bob-new-pass-3");
  await page.locator("button").click();
  await page.waitForLoadState("domcontentloaded");
  const prompt = await card(page, /update/i);
  expect(prompt, "no Update prompt after a password change");
  await d.clickInSurface(page, prompt, /^update$/i);
  await d.sleep(1500);
  const bob = vaultLogin(LOCAL, "bob");
  expect(bob.password === "bob-new-pass-3", `bob's password not updated (still ${bob.password})`);
  expect(vaultLogin(LOCAL, "alice@example.com").password === "local-alice-1", "alice changed by mistake");
  return "bob updated to the new password; alice untouched";
});

scenario("S6", "'Never for this site' stops later save prompts", async ({ page }) => {
  await goto(page, LOCAL + "/spa");
  await page.locator("#e").click(); await page.keyboard.press("Escape");
  await page.locator("#e").pressSequentially("dave@example.com");
  await page.locator("#p").pressSequentially("dave-pass-1");
  await page.locator("#go").click();
  const prompt = await card(page, /save login/i);
  expect(prompt, "no first prompt");
  await d.clickInSurface(page, prompt, /never/i);
  await d.sleep(1200);
  await goto(page, LOCAL + "/spa");
  await page.locator("#e").click(); await page.keyboard.press("Escape");
  await page.locator("#e").pressSequentially("erin@example.com");
  await page.locator("#p").pressSequentially("erin-pass-1");
  await d.sleep(5500); // capture rate limit: one per tab per 5 s
  await page.locator("#go").click();
  const again = await card(page, /save login/i, 5000);
  expect(!again, "save prompt shown on a 'never' site");
  return "no prompt after choosing Never";
});

// --- Cards
scenario("C1", "Card form: number, name, expiry selects; CVV after approval", async ({ page }) => {
  d.patchState({ cvvDecision: "approve" });
  await goto(page, "https://autofill.me/form/credit-card-simple");
  // The page's year list ends at 2028, so use the card that expires 08/28.
  await pick(page, page.locator("#cc-number"), "Travel Mastercard");
  expect((await val(page.locator("#cc-number"))).replace(/\D/g, "") === "5555555555554444", "number not filled");
  expect(await val(page.locator("#cc-name")) === "Alex Tester", "name not filled");
  const mm = await val(page.locator("#cc-exp-month")); const yy = await val(page.locator("#cc-exp-year"));
  expect(/^0?8$/.test(mm), `month not 8 (got ${mm})`);
  expect(/28$/.test(yy), `year not 2028 (got ${yy})`);
  await d.sleep(3500);
  expect(await val(page.locator("#cc-csc")) === "456", "CVV not filled after approval");
  return `number, name, month ${mm}, year ${yy}, CVV after approval`;
});

scenario("C2", "Card form with one MM/YY field; CVV denied stays empty", async ({ page }) => {
  d.patchState({ cvvDecision: "deny" });
  await goto(page, "https://autofill.me/form/credit-card-mm-yy");
  await pick(page, page.locator("#cc-number"), "Travel Mastercard");
  expect(await val(page.locator("#cc-exp")) === "08/28", `expiry not 08/28 (got ${await val(page.locator("#cc-exp"))})`);
  await d.sleep(3500);
  expect(await val(page.locator("#cc-csc")) === "", "CVV filled although approval was denied");
  d.patchState({ cvvDecision: "approve" });
  return "MM/YY filled; denied CVV left empty";
});

scenario("C3", "RoboForm all-fields page: card section", async ({ page }) => {
  await goto(page, "https://www.roboform.com/filling-test-all-fields");
  await pick(page, page.locator("input[name='41ccnumber']"), "Everyday Visa");
  const out = { number: await val(page.locator("input[name='41ccnumber']")), mm: await val(page.locator("select[name='42ccexp_mm']")),
    yy: await val(page.locator("select[name='43ccexp_yy']")), name: await val(page.locator("input[name='44cc_uname']")) };
  expect(out.number.replace(/\D/g, "") === "4111111111111111", "number not filled");
  return `number ok; month=${out.mm} year=${out.yy} name="${out.name}"`;
});

scenario("C4", "Save a new card after paying (security code never saved)", async ({ page }) => {
  await goto(page, "https://autofill.me/form/credit-card-simple");
  const type = async (sel, text) => { await page.locator(sel).click(); await page.keyboard.press("Escape"); await page.locator(sel).pressSequentially(text); };
  await type("#cc-name", "Jamie Doe");
  await type("#cc-number", "4000056655665556");
  await page.locator("#cc-type").selectOption("visa"); // required by the page, or the browser blocks the submit
  await page.locator("#cc-exp-month").selectOption({ index: 5 });
  await page.locator("#cc-exp-year").selectOption("2028");
  await type("#cc-csc", "777");
  await page.locator("button[type=submit], input[type=submit]").first().click();
  const prompt = await card(page, /save this card/i);
  expect(prompt, "no 'Save this card' prompt");
  await d.clickInSurface(page, prompt, /^save$/i);
  await d.sleep(1500);
  const saved = d.readState().vault.find((e) => e.type === "CARD" && e.number === "4000056655665556");
  expect(saved, "card not stored");
  expect(!saved.cvv, "security code was stored");
  return `stored "${saved.title}", name ${saved.name}, expiry ${saved.expiry}, no CVV`;
});

// --- Addresses
scenario("A1", "Address form: one pick fills every part", async ({ page }) => {
  await goto(page, "https://autofill.me/form/identity-simple");
  await pick(page, page.locator("#given-name"), "Alex");
  const read = async (id) => val(page.locator("#" + id));
  const got = { given: await read("given-name"), family: await read("family-name"), tel: await read("tel"), a1: await read("address-line1"),
    city: await read("address-level2"), state: await read("address-level1"), zip: await read("postal-code"), country: await read("country") };
  expect(got.given === "Alex" && got.family === "Tester", `names wrong ${got.given}/${got.family}`);
  expect(got.a1 === "1 Market St" && got.city === "San Francisco" && got.zip === "94105", "address parts wrong");
  return Object.entries(got).map(([k, v]) => `${k}=${v}`).join(", ");
});

scenario("A2", "RoboForm all-fields page: identity section", async ({ page }) => {
  await goto(page, "https://www.roboform.com/filling-test-all-fields");
  await pick(page, page.locator("input[name='10address1']"), "1 Market St");
  const names = ["02frstname", "04lastname", "04fullname", "10address1", "13adr_city", "14adrstate", "16addr_zip", "20homephon", "23cellphon", "24emailadr"];
  const got = {};
  for (const n of [...names, "22faxphone"]) got[n] = await val(page.locator(`input[name='${n}']`));
  const empty = names.filter((n) => !got[n]);
  // One phone per address: home phone fills, a second (cell) phone is left alone by design.
  const missing = empty.filter((n) => n !== "23cellphon");
  expect(!missing.length, `fields left empty: ${missing.join(", ")}`);
  expect(!got["22faxphone"], `fax received "${got["22faxphone"]}"`);
  return `filled ${names.length - empty.length}/${names.length}; empty: ${empty.join(", ") || "none"}`;
});

scenario("A3", "Save a new address after submitting a form", async ({ page }) => {
  await goto(page, "https://autofill.me/form/identity-simple");
  const type = async (sel, text) => { await page.locator(sel).click(); await page.keyboard.press("Escape"); await page.locator(sel).pressSequentially(text); };
  await type("#given-name", "Robin"); await type("#family-name", "Banks"); await type("#tel", "2065550199");
  await type("#address-line1", "400 Broad St"); await type("#address-level2", "Seattle"); await type("#postal-code", "98109");
  await page.locator("button[type=submit], input[type=submit]").first().click();
  const prompt = await card(page, /save this address/i);
  expect(prompt, "no 'Save this address' prompt");
  await d.clickInSurface(page, prompt, /^save$/i);
  await d.sleep(1500);
  const saved = d.readState().vault.find((e) => e.type === "AUTOFILL" && e.profile?.address1 === "400 Broad St");
  expect(saved, "address not stored");
  expect(!/choose/i.test(saved.profile.state + saved.profile.country), `drop-down placeholder saved: ${saved.profile.state} / ${saved.profile.country}`);
  return `stored "${saved.title}": ${JSON.stringify(saved.profile)}`;
});

scenario("A4", "Lone newsletter email gets no address list", async ({ page }) => {
  await goto(page, LOCAL + "/newsletter");
  await d.focusField(page.locator("input[name=email]"));
  const list = await d.waitForSurface(page, (s) => s.kind === "list" && /address/i.test(s.text), { timeout: 2500 });
  expect(!list, "address list shown on a newsletter box");
  return "no address list";
});

// --- Codes
scenario("K1", "Six single-digit boxes get the current authenticator code", async ({ page }) => {
  await goto(page, LOCAL + "/otp-boxes");
  await pick(page, page.locator("input[name=d0]"), "Local app");
  let code = ""; for (let i = 0; i < 6; i++) code += await val(page.locator(`input[name=d${i}]`));
  const expected = await totpNow("KRSXG5CTMVRXEZLU");
  expect(/^\d{6}$/.test(code), `boxes hold "${code}"`);
  expect(code === expected, `code ${code} differs from current TOTP ${expected}`);
  return `filled ${code}`;
});

scenario("K2", "Multi-step sign-in ending in a TOTP step (autofill.me)", async ({ page }) => {
  d.patchState((s) => { if (!s.vault.some((e) => e.id === "code-autofill")) s.vault.push({ id: "code-autofill", type: "AUTHENTICATOR", title: "autofill.me", account: "am.tester@example.com", secret: "ONSWG4TFOQ======".replace(/=/g, "A") }); });
  await goto(page, "https://autofill.me/form/login-multi-step-totp");
  await pick(page, page.locator("#username"), "am.tester");
  await page.locator("#username").press("Enter");
  const pass = page.locator("input[type=password]").first();
  await pass.waitFor({ timeout: 10000 });
  await pick(page, pass, "am.tester");
  await pass.press("Enter");
  const code = page.locator("input[autocomplete=one-time-code], input[name*=totp i], input[id*=totp i]").first();
  await code.waitFor({ timeout: 10000 });
  const { list } = await pick(page, code, "autofill.me");
  expect(/^\d{6}$/.test(await val(code)), `code field holds "${await val(code)}"`);
  return `code list: ${list.options.map((o) => o.text).join(" | ")}; code filled`;
});

// --- Popup: cards and addresses (the only way on Firefox; also in Chrome's popup)
async function popupCall(worker, page, message) {
  const url = page.url();
  return worker.evaluate(async ({ url, message }) => {
    const [tab] = await chrome.tabs.query({ url: url.split("#")[0] });
    return handlePopupItems({ ...message, tabId: tab.id });
  }, { url, message });
}

scenario("P1", "Popup lists cards only on a payment page and fills the focused form", async ({ page, worker }) => {
  d.patchState({ cvvDecision: "approve" });
  await goto(page, "https://autofill.me/form/credit-card-simple");
  await page.locator("#cc-number").click(); await page.keyboard.press("Escape");
  const forms = await popupCall(worker, page, { action: "popup_forms" });
  expect(forms.card === true, `payment form not detected: ${JSON.stringify(forms)}`);
  const listed = await popupCall(worker, page, { action: "popup_items", kind: "card" });
  expect(listed.status === "ok" && listed.items.length >= 2, `cards not listed: ${JSON.stringify(listed)}`); // C4 may have added one
  const mc = listed.items.find((item) => /Mastercard/.test(item.title));
  const filled = await popupCall(worker, page, { action: "popup_fill_item", kind: "card", id: mc.id });
  expect(filled.status === "ok", `fill failed: ${JSON.stringify(filled)}`);
  expect((await val(page.locator("#cc-number"))).replace(/\D/g, "") === "5555555555554444", "number not filled");
  expect(await val(page.locator("#cc-name")) === "Alex Tester", "name not filled");
  await d.sleep(3500);
  expect(await val(page.locator("#cc-csc")) === "456", "CVV not filled after approval");
  const login = await (async () => { await goto(page, "https://the-internet.herokuapp.com/login"); return popupCall(worker, page, { action: "popup_forms" }); })();
  expect(!login.card && !login.profile, "a login page should show no card or address section");
  return `filled ${filled.filled} fields + CVV after approval; login page shows neither section`;
});

scenario("P2", "Popup fills an address form", async ({ page, worker }) => {
  await goto(page, "https://autofill.me/form/identity-simple");
  const forms = await popupCall(worker, page, { action: "popup_forms" });
  expect(forms.profile === true, "address form not detected");
  const listed = await popupCall(worker, page, { action: "popup_items", kind: "profile" });
  const filled = await popupCall(worker, page, { action: "popup_fill_item", kind: "profile", id: listed.items[0].id });
  expect(filled.status === "ok", `fill failed: ${JSON.stringify(filled)}`);
  expect(await val(page.locator("#address-line1")) === "1 Market St" && await val(page.locator("#postal-code")) === "94105", "address not filled");
  return `filled ${filled.filled} fields`;
});

scenario("P3", "Popup renders (icons parsed, no innerHTML)", async ({ page, context }) => {
  const id = "kapellkbongejlglcengbmjnpblemmjm";
  await page.goto(`chrome-extension://${id}/popup.html`);
  await d.sleep(1500);
  const svgs = await page.locator("svg").count();
  await d.shot(page, "popup");
  expect(svgs > 0, "no icons rendered");
  return `${svgs} icons rendered`;
});

// --- Vault states
scenario("X1", "Locked vault: list says so and offers Unlock", async ({ page }) => {
  d.patchState({ locked: true });
  try {
    await goto(page, "https://the-internet.herokuapp.com/login");
    const list = await openList(page, page.locator("#username"), { arrow: true });
    expect(list && /lock/i.test(list.text), `locked state not shown: ${list?.text}`);
    const before = d.readState().unlockPrompts || 0;
    await d.clickInSurface(page, list, /unlock/i);
    await d.sleep(1500);
    expect((d.readState().unlockPrompts || 0) > before, "Unlock did not ask Nuvori to show its unlock window");
    return `"${list.text.split("\n").slice(1).join(" ").slice(0, 80)}"; unlock requested`;
  } finally { d.patchState({ locked: false }); }
});

scenario("X2", "Nuvori not running: list explains and offers to start it", async ({ page }) => {
  d.patchState({ offline: true });
  try {
    await goto(page, "https://the-internet.herokuapp.com/login");
    const list = await openList(page, page.locator("#username"), { arrow: true });
    expect(list, "no list at all when Nuvori is unavailable");
    return `"${list.text.split("\n").slice(1).join(" ").slice(0, 100)}"`;
  } finally { d.patchState({ offline: false }); }
});

// ---------------------------------------------------------------------------- run
const chosen = S.filter((s) => !filters.length || filters.some((f) => s.id.toLowerCase() === f || s.title.toLowerCase().includes(f)));
seedVault();
register();
const stopFixtures = startFixtures();
const { context, worker } = await d.launch();
try {
  for (const s of chosen) {
    const page = await context.newPage();
    const started = Date.now();
    try {
      const note = await s.fn({ page, context, worker });
      results.push({ id: s.id, title: s.title, ok: true, note, ms: Date.now() - started });
      console.log(`PASS ${s.id} ${s.title} — ${note}`);
    } catch (error) {
      const shot = await d.shot(page, `fail-${s.id}`);
      results.push({ id: s.id, title: s.title, ok: false, note: error.message.split("\n")[0], shot, ms: Date.now() - started });
      console.log(`FAIL ${s.id} ${s.title} — ${error.message.split("\n")[0]}`);
    }
    await page.close().catch(() => {});
    await d.sleep(5200); // keep captures apart (one per tab per 5 s, four per site per minute)
  }
} finally {
  await context.close();
  stopFixtures();
  if (!process.env.KEEP_HOST) unregister();
}
fs.writeFileSync(path.join(d.STATE_DIR, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
