import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const signinsSource = readFileSync(new URL("./signins.js", import.meta.url), "utf8");
const context = vm.createContext({ URL, URLSearchParams, setTimeout, clearTimeout });
vm.runInContext(signinsSource, context);
const S = context.NuvoriSignIns;
const plain = (value) => JSON.parse(JSON.stringify(value));

// ---------------------------------------------------------------------------
// Recorded URL sequences. Each step is what the background feeds the tracker from the browser's
// events: webRequest requests and redirects, finished page loads, closed tabs and page reports.
// Shapes follow real flows; client ids, codes and states are synthetic.

function play(steps) {
  const tracker = S.createTracker();
  let at = 1_000_000;
  const found = [];
  for (const step of steps) {
    at += step.after ?? 200;
    const [kind, details] = step.step;
    const result = tracker[kind]({ ...details, at });
    if (kind === "committed" && result) {
      const settled = tracker.settle({ tabId: details.tabId, at: at + S.SETTLE_MS });
      if (settled) found.push(plain(settled));
    } else if (result && typeof result === "object" && "provider" in result && "origin" in result) found.push(plain(result));
  }
  return { found, tracker };
}

const req = (tabId, url, extra = {}) => ({ step: ["request", { tabId, url, ...extra }] });
const redirect = (tabId, url, redirectUrl) => ({ step: ["redirect", { tabId, url, redirectUrl }] });
const loaded = (tabId, url, homeUrl) => ({ step: ["committed", { tabId, url, homeUrl }] });
const account = (tabId, url, value, extra = {}) => ({ step: ["account", { tabId, url, account: value, ...extra }] });
const click = (tabId, provider) => ({ step: ["click", { tabId, provider }] });
const closed = (tabId, homeUrl) => ({ step: ["closed", { tabId, homeUrl }] });
const settle = (tabId) => ({ step: ["settle", { tabId }], after: S.SETTLE_MS + 10 });

test("GitHub: an app already authorized redirects at once; the click and the return are enough", () => {
  const { found } = play([
    click(7, "github"),
    req(7, "https://example.com/auth/github", { initiator: "https://example.com", startUrl: "https://example.com/login" }),
    req(7, "https://github.com/login/oauth/authorize?client_id=Iv1.abc&redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgithub%2Fcallback&scope=user%3Aemail&state=s1",
      { initiator: "https://example.com", startUrl: "https://example.com/login" }),
    redirect(7, "https://github.com/login/oauth/authorize?client_id=Iv1.abc", "https://example.com/auth/github/callback?code=c0de&state=s1"),
    req(7, "https://example.com/auth/github/callback?code=c0de&state=s1", { initiator: "https://example.com" }),
    loaded(7, "https://example.com/dashboard"),
  ]);
  assert.deepEqual(found, [{ tabId: 7, provider: "github", origin: "https://example.com", account: "", providerTabId: 7,
    providerOrigin: "https://github.com", evidence: "click" }]);
});

test("GitHub: the authorize page's signed-in user is the account; Authorize posts back from github.com", () => {
  const { found } = play([
    req(3, "https://github.com/login/oauth/authorize?client_id=Iv1.abc&redirect_uri=https%3A%2F%2Fapp.example.dev%2Fcb", { initiator: "https://app.example.dev", startUrl: "https://app.example.dev/" }),
    account(3, "https://github.com/login/oauth/authorize?client_id=Iv1.abc", "octocat"),
    account(3, "https://github.com/login/oauth/authorize", "", { chosen: true }),
    req(3, "https://github.com/login/oauth/authorize", { initiator: "https://github.com" }),
    redirect(3, "https://github.com/login/oauth/authorize", "https://app.example.dev/cb?code=1&state=2"),
    loaded(3, "https://app.example.dev/projects"),
  ]);
  assert.equal(found.length, 1);
  assert.equal(found[0].account, "octocat");
  assert.equal(found[0].evidence, "scope", "no scope asked for is a sign-in");
});

test("Google: a popup from the site, the account picked in the chooser, the opener's page is the site", () => {
  const { found } = play([
    click(1, "google"),
    req(2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=1.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fapp.example.org%2Foauth%2Fcallback&response_type=code&scope=openid%20email%20profile",
      { initiator: "https://app.example.org", startUrl: "https://app.example.org/signin", homeTabId: 1 }),
    req(2, "https://accounts.google.com/v3/signin/accountchooser?continue=x", { initiator: "https://accounts.google.com" }),
    account(2, "https://accounts.google.com/v3/signin/accountchooser", "Jamie.Doe@gmail.com", { chosen: true }),
    req(2, "https://accounts.youtube.com/accounts/SetSID", { initiator: "https://accounts.google.com" }),
    redirect(2, "https://accounts.google.com/signin/oauth/consent?authuser=0", "https://app.example.org/oauth/callback?code=4%2F0Ab&scope=email"),
    loaded(2, "https://app.example.org/oauth/callback?code=4%2F0Ab", "https://app.example.org/home"),
  ]);
  assert.deepEqual(found.map(({ tabId, provider, origin, account: who }) => ({ tabId, provider, origin, account: who })),
    [{ tabId: 1, provider: "google", origin: "https://app.example.org", account: "Jamie.Doe@gmail.com" }]);
});

test("Google Identity Services popup (storagerelay) finishes when the popup closes after a choice", () => {
  const start = req(2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fwww.example.com%3Fid%3Dauth123&response_type=permission%20id_token&scope=openid%20email%20profile",
    { initiator: "https://www.example.com", startUrl: "https://www.example.com/", homeTabId: 1 });
  const chosen = play([start, account(2, "https://accounts.google.com/o/oauth2/v2/auth", "me@example.com", { chosen: true }), closed(2, "https://www.example.com/")]);
  assert.equal(chosen.found[0].origin, "https://www.example.com");
  assert.equal(chosen.found[0].account, "me@example.com");
  // Closed without a choice: the user gave up.
  assert.deepEqual(play([start, closed(2, "https://www.example.com/")]).found, []);
  // "Cancel" in the chooser.
  assert.deepEqual(play([start, account(2, "https://accounts.google.com/x", "", { chosen: true, cancel: true }), closed(2, "https://www.example.com/")]).found, []);
});

test("Google One Tap: the chooser frame on the site's own page", () => {
  const { found } = play([
    req(4, "https://accounts.google.com/gsi/select?client_id=1.apps.googleusercontent.com&ux_mode=popup&ui_mode=card&origin=https%3A%2F%2Fnews.example",
      { type: "sub_frame", initiator: "https://news.example", startUrl: "https://news.example/article" }),
    account(4, "https://accounts.google.com/gsi/select", "reader@gmail.com", { chosen: true, homeUrl: "https://news.example/article" }),
    settle(4),
  ]);
  assert.deepEqual(found.map((entry) => [entry.provider, entry.origin, entry.account]), [["google", "https://news.example", "reader@gmail.com"]]);
});

test("Apple: form_post back to the site, with the Hide My Email relay address as the account", () => {
  const { found } = play([
    click(5, "apple"),
    req(5, "https://appleid.apple.com/auth/authorize?client_id=com.shop.web&redirect_uri=https%3A%2F%2Fshop.example%2Fapple%2Fcallback&response_type=code%20id_token&response_mode=form_post&scope=name%20email",
      { initiator: "https://shop.example", startUrl: "https://shop.example/login" }),
    account(5, "https://appleid.apple.com/auth/authorize", "x7k2m9qp4z@privaterelay.appleid.com", { chosen: true }),
    req(5, "https://shop.example/apple/callback", { initiator: "https://appleid.apple.com" }),
    loaded(5, "https://shop.example/account"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.provider, entry.origin, entry.account]), [["apple", "https://shop.example", "x7k2m9qp4z@privaterelay.appleid.com"]]);
});

test("Microsoft, Facebook, X, LinkedIn, Discord, Amazon and Slack: authorize, answer, landing", () => {
  const flows = [
    ["microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=c&redirect_uri=https%3A%2F%2Fportal.contoso.example%2Fsignin-oidc&response_mode=form_post&scope=openid%20profile%20offline_access%20User.Read",
      [req(9, "https://login.live.com/oauth20_authorize.srf?client_id=c", { initiator: "https://login.microsoftonline.com" }), req(9, "https://portal.contoso.example/signin-oidc", { initiator: "https://login.microsoftonline.com" })],
      "https://portal.contoso.example"],
    ["facebook", "https://www.facebook.com/v19.0/dialog/oauth?client_id=1&redirect_uri=https%3A%2F%2Fexample.net%2Ffb&scope=email%2Cpublic_profile&state=s",
      [redirect(9, "https://www.facebook.com/v19.0/dialog/oauth/confirm", "https://example.net/fb?code=AQ&state=s")], "https://example.net"],
    ["x", "https://x.com/i/oauth2/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fexample.io%2Fx&scope=users.read%20tweet.read&state=s&code_challenge=c",
      [redirect(9, "https://x.com/i/oauth2/authorize", "https://example.io/x?state=s&code=c")], "https://example.io"],
    ["linkedin", "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fjobs.example%2Fli&scope=openid%20profile%20email",
      [redirect(9, "https://www.linkedin.com/oauth/v2/login-success", "https://jobs.example/li?code=c")], "https://jobs.example"],
    ["discord", "https://discord.com/oauth2/authorize?client_id=1&redirect_uri=https%3A%2F%2Fbot.example%2Fcb&response_type=code&scope=identify%20email",
      [redirect(9, "https://discord.com/api/v9/oauth2/authorize", "https://bot.example/cb?code=c")], "https://bot.example"],
    ["amazon", "https://www.amazon.com/ap/oa?client_id=amzn1&scope=profile&response_type=code&redirect_uri=https%3A%2F%2Fskills.example%2Famazon",
      [redirect(9, "https://www.amazon.com/ap/oa", "https://skills.example/amazon?code=c")], "https://skills.example"],
    ["slack", "https://slack.com/openid/connect/authorize?response_type=code&scope=openid%20email%20profile&client_id=1&redirect_uri=https%3A%2F%2Ftools.example%2Fslack",
      [redirect(9, "https://acme.slack.com/openid/connect/authorize", "https://tools.example/slack?code=c")], "https://tools.example"],
  ];
  for (const [provider, authorize, answer, origin] of flows) {
    const start = new URL(origin).origin;
    const { found } = play([req(9, authorize, { initiator: start, startUrl: `${start}/login` }), ...answer, loaded(9, `${start}/home`)]);
    assert.deepEqual(found.map((entry) => [entry.provider, entry.origin]), [[provider, origin]], provider);
  }
});

test("X with OAuth 1.0a names no redirect and no scope: the site page and the return still identify it", () => {
  const { found } = play([
    click(2, "x"),
    req(2, "https://api.twitter.com/oauth/authenticate?oauth_token=abc", { initiator: "https://forum.example", startUrl: "https://forum.example/login" }),
    redirect(2, "https://api.twitter.com/oauth/authenticate?oauth_token=abc", "https://forum.example/auth/twitter/callback?oauth_token=abc&oauth_verifier=v"),
    loaded(2, "https://forum.example/"),
  ]);
  assert.equal(found[0].provider, "x");
});

test("negatives: cancel, integrations, the provider's own site, leaving, look-alike hosts, frames and stale flows", () => {
  const github = "https://github.com/login/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fexample.com%2Fcb";
  const begin = (extra = {}) => req(1, github, { initiator: "https://example.com", startUrl: "https://example.com/login", ...extra });
  // The user cancelled on the consent page.
  assert.deepEqual(play([begin(), redirect(1, github, "https://example.com/cb?error=access_denied&state=s"), loaded(1, "https://example.com/login?error=1")]).found, []);
  assert.deepEqual(play([begin(), redirect(1, github, "https://example.com/cb#error=access_denied"), loaded(1, "https://example.com/")]).found, []);
  // "Connect your Google Calendar": API scopes and no sign-in button click.
  const calendar = "https://accounts.google.com/o/oauth2/v2/auth?client_id=c&redirect_uri=https%3A%2F%2Fcal.example%2Fg&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcalendar";
  const integration = [req(1, calendar, { initiator: "https://cal.example", startUrl: "https://cal.example/settings" }),
    redirect(1, calendar, "https://cal.example/g?code=c"), loaded(1, "https://cal.example/settings")];
  assert.deepEqual(play(integration).found, []);
  // The same with a "Continue with Google" click is a sign-in.
  assert.equal(play([click(1, "google"), ...integration]).found.length, 1);
  // "Add to Slack" installs an app; it is not a sign-in at all.
  assert.equal(S.parseAuthorize("https://slack.com/oauth/v2/authorize?client_id=1&scope=chat:write,commands"), null);
  assert.ok(S.parseAuthorize("https://slack.com/oauth/v2/authorize?client_id=1&user_scope=identity.basic,identity.email"));
  // Started on the provider's own site (YouTube with Google, a GitHub page with GitHub), or landing there.
  const youtube = "https://accounts.google.com/o/oauth2/v2/auth?client_id=c&redirect_uri=https%3A%2F%2Fwww.youtube.com%2Fsignin";
  assert.deepEqual(play([req(1, youtube, { initiator: "https://www.youtube.com", startUrl: "https://www.youtube.com/" }),
    redirect(1, youtube, "https://www.youtube.com/signin?code=c"), loaded(1, "https://www.youtube.com/")]).found, []);
  assert.deepEqual(play([req(1, github, { initiator: "https://gist.github.com", startUrl: "https://gist.github.com/" }),
    redirect(1, github, "https://gist.github.com/auth?code=c"), loaded(1, "https://gist.github.com/")]).found, []);
  assert.deepEqual(play([begin(), redirect(1, github, "https://github.com/settings/apps?code=c")]).found, []);
  // Typed into the address bar: no page started it.
  assert.deepEqual(play([req(1, github, { startUrl: "about:blank" }), redirect(1, github, "https://example.com/cb?code=c"), loaded(1, "https://example.com/")]).found, []);
  // Back to the site without the provider's answer (the Back button).
  const back = play([begin(), req(1, "https://example.com/login"), loaded(1, "https://example.com/login")]);
  assert.deepEqual(back.found, []);
  assert.equal(back.tracker.active(), 0);
  // Look-alike hosts and plain HTTP are not authorize endpoints.
  for (const url of ["https://github.com.evil.example/login/oauth/authorize?client_id=c", "https://evil.example/o/oauth2/v2/auth?client_id=c",
    "https://accounts.google.com.evil.example/o/oauth2/v2/auth", "http://github.com/login/oauth/authorize", "https://github.com/login?return_to=x",
    "https://notfacebook.com/dialog/oauth", "https://www.amazon.evil/ap/oa"]) {
    assert.equal(S.parseAuthorize(url), null, url);
  }
  // A provider page in a site's frame is never a flow, except Google One Tap.
  assert.deepEqual(play([req(1, github, { type: "sub_frame", initiator: "https://example.com", startUrl: "https://example.com/" }),
    redirect(1, github, "https://example.com/cb?code=c"), loaded(1, "https://example.com/")]).found, []);
  // A popup closed before the provider answered.
  assert.deepEqual(play([req(2, github, { initiator: "https://example.com", startUrl: "https://example.com/", homeTabId: 1 }), closed(2, "https://example.com/")]).found, []);
  // Ten minutes on the consent page: forgotten.
  assert.deepEqual(play([begin(), { ...redirect(1, github, "https://example.com/cb?code=c"), after: 11 * 60 * 1000 }, loaded(1, "https://example.com/")]).found, []);
  // A page that navigates on before settling: the last page counts.
  const tracker = S.createTracker();
  tracker.request({ tabId: 1, url: github, initiator: "https://example.com", startUrl: "https://example.com/", at: 1 });
  tracker.redirect({ tabId: 1, url: github, redirectUrl: "https://broker.example/cb?code=c", at: 2 });
  tracker.committed({ tabId: 1, url: "https://broker.example/cb", at: 3 });
  assert.equal(tracker.settle({ tabId: 1, at: 4 }), null, "too soon");
  tracker.committed({ tabId: 1, url: "https://app.example.com/", at: 1000 });
  assert.equal(tracker.settle({ tabId: 1, at: 1000 + S.SETTLE_MS }).origin, "https://app.example.com");
});

test("the tracker survives a worker restart through its JSON", () => {
  const first = S.createTracker();
  first.click({ tabId: 1, provider: "github", at: 1 });
  first.request({ tabId: 1, url: "https://github.com/login/oauth/authorize?client_id=c", initiator: "https://example.com", startUrl: "https://example.com/", at: 2 });
  const second = S.createTracker(JSON.parse(JSON.stringify(first.toJSON())));
  second.redirect({ tabId: 1, url: "https://github.com/login/oauth/authorize", redirectUrl: "https://example.com/cb?code=1", at: 3 });
  second.committed({ tabId: 1, url: "https://example.com/", at: 4 });
  assert.equal(second.settle({ tabId: 1, at: 4 + S.SETTLE_MS }).evidence, "click");
  // An unknown provider id from a page never counts.
  second.click({ tabId: 2, provider: "myspace", at: 5 });
  assert.equal(JSON.stringify(second.toJSON()).includes("myspace"), false);
});

test("button text names the provider in common wordings and languages, and nothing else", () => {
  const cases = [
    ["Continue with GitHub", "github"], ["Sign in with Google", "google"], ["Log in with Apple", "apple"], ["Sign up with Microsoft", "microsoft"],
    ["Login with Facebook", "facebook"], ["Continue with X", "x"], ["Sign in with Twitter", "x"], ["Sign in with LinkedIn", "linkedin"],
    ["Login via Discord", "discord"], ["Login with Amazon", "amazon"], ["Sign in with Slack", "slack"], ["Mit Google anmelden", "google"],
    ["Continuer avec Apple", "apple"], ["Continuar con Facebook", "facebook"], ["GitHub", "github"], ["  Google  ", "google"],
    ["Continue with Google Workspace", "google"], ["Sign in with Microsoft account", "microsoft"],
  ];
  for (const [text, provider] of cases) assert.equal(S.providerOfText(text), provider, text);
  for (const text of ["x", "X", "Close", "Sign in", "Google Drive files", "Share on Facebook page", "Continue with email",
    "Use your Google account to sign up for our newsletter that comes out every week", "Applesauce recipes", "github-actions bot"]) {
    assert.equal(S.providerOfText(text), null, text);
  }
});

test("accounts: an email or a user name only, read from what the provider shows", () => {
  assert.equal(S.cleanAccount(" octocat "), "octocat");
  assert.equal(S.cleanAccount("@jack"), "@jack");
  assert.equal(S.cleanAccount("x7k2m9qp4z@privaterelay.appleid.com"), "x7k2m9qp4z@privaterelay.appleid.com");
  for (const bad of ["", "Jamie Doe", "a‮b", "line\nbreak", "a".repeat(300), "<script>", 5, null]) assert.equal(S.cleanAccount(bad), "", String(bad));
  assert.equal(S.oneEmail("Choose an account\nJamie Doe\njamie@example.com\nUse another account"), "jamie@example.com");
  assert.equal(S.oneEmail("a@example.com b@example.com"), "", "two addresses: not knowable");
  assert.equal(S.signedInAs("Signed in as octocat. Not you?"), "octocat");
  assert.equal(S.signedInAs("Logged in as: someone@example.org"), "someone@example.org");
  assert.equal(S.isErrorAnswer("https://a.example/cb?error=access_denied"), true);
  assert.equal(S.isErrorAnswer("https://a.example/cb?code=1&error=x"), false);
});

/** A tiny DOM stand-in: nodes with attributes, text and a parent. */
function fakePage(nodes, bodyText = "") {
  const all = nodes.map((node) => ({ attrs: {}, text: "", ...node }));
  return {
    query: (selector) => all.filter((node) => node.matches?.includes(selector) || selector.split(",").some((part) => node.matches?.includes(part.trim()))),
    within: () => [],
    attr: (node, name) => node?.attrs?.[name] || "",
    text: (node) => (node === "body" ? bodyText : node?.text || ""),
    parent: (node) => node?.parent || null,
    isElement: (node) => Boolean(node && typeof node === "object"),
    matches: (node, selector) => selector.split(",").some((part) => node.matches?.includes(part.trim())),
    body: () => "body",
  };
}

test("Apple: the selected email option is the account, the relay address when Hide My Email is chosen", () => {
  const relayRow = { text: "Hide My Email\nForward To: x7k2m9qp4z@privaterelay.appleid.com" };
  const shareRow = { text: "Share My Email\njamie@icloud.com" };
  const relayRadio = { matches: ["input[type='radio']:checked"], parent: relayRow };
  const page = fakePage([relayRadio, { matches: [], parent: shareRow }], `${shareRow.text}\n${relayRow.text}`);
  assert.equal(S.accountFromPage("apple", page), "x7k2m9qp4z@privaterelay.appleid.com");
  const sharePage = fakePage([{ matches: ["[role='radio'][aria-checked='true']"], parent: shareRow }], `${shareRow.text}\n${relayRow.text}`);
  assert.equal(S.accountFromPage("apple", sharePage), "jamie@icloud.com");
  // No selection to read: only a relay address shown alone counts.
  assert.equal(S.accountFromPage("apple", fakePage([], "Continue with x7k2m9qp4z@privaterelay.appleid.com")), "x7k2m9qp4z@privaterelay.appleid.com");
  assert.equal(S.accountFromPage("apple", fakePage([], `${shareRow.text}\n${relayRow.text}`)), "");
});

test("GitHub reads its signed-in user; Google reads the chosen account; a click on a tile picks it", () => {
  assert.equal(S.accountFromPage("github", fakePage([{ matches: ["meta[name='user-login']"], attrs: { content: "octocat" } }])), "octocat");
  assert.equal(S.accountFromPage("google", fakePage([{ matches: ["[data-email]"], attrs: { "data-email": "me@gmail.com" } }])), "me@gmail.com");
  assert.equal(S.accountFromPage("discord", fakePage([], "Signed in as wumpus  Not you?")), "wumpus");
  const tile = { matches: ["li"], attrs: { "data-identifier": "other@gmail.com" } };
  assert.equal(S.accountFromClick([{ matches: ["div"], text: "Other Person" }, tile], fakePage([tile])), "other@gmail.com");
  assert.equal(S.providerOfPage("github.com", "/login/oauth/authorize"), "github");
  assert.equal(S.providerOfPage("github.com", "/torvalds/linux"), null, "ordinary GitHub pages are left alone");
  assert.equal(S.providerOfPage("appleid.apple.com", "/auth/authorize"), "apple");
  assert.equal(S.providerOfPage("example.com", "/login"), null);
});

test("every provider has a mark from the shipped set: six CC0 paths and four letter tiles", () => {
  const ids = S.PROVIDERS.map((provider) => provider.id);
  assert.deepEqual(plain(ids), ["google", "apple", "microsoft", "github", "facebook", "x", "linkedin", "discord", "amazon", "slack"]);
  const marks = readFileSync(new URL("../src/lib/sign-in-marks.json", import.meta.url), "utf8");
  assert.deepEqual(plain(S.MARKS), JSON.parse(marks).marks, "the extension and the app ship the same marks");
  assert.deepEqual(plain(ids.filter((id) => S.MARKS[id].path)), ["google", "apple", "github", "facebook", "x", "discord"]);
  for (const id of ids) assert.match(S.MARKS[id].hex, /^[0-9A-F]{6}$/);
});

// ---------------------------------------------------------------------------
// The background worker with signins.js: browser events in, a prompt out, then Save.

function area(data) {
  return {
    get: async (keys) => {
      const list = keys == null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((key) => key in data).map((key) => [key, structuredClone(data[key])]));
    },
    set: async (value) => Object.assign(data, structuredClone(value)),
  };
}

// Like the app: the site is the host without "www." (the real app uses the registrable domain).
const siteOf = (origin) => { try { return new URL(origin).hostname.replace(/^www\./, ""); } catch { return "example.com"; } };

async function worker({ features = ["sign_in_methods"], methods = [], tabs = {}, windows = {}, storage = { changed: false } } = {}) {
  const local = {};
  const session = {};
  const requests = [];
  const sent = [];
  const listeners = { request: [], redirect: [], updated: [], removed: [], created: [], message: null };
  const timers = [];
  const clock = { now: 1_700_000_000_000 };
  class FakeDate extends Date { static now() { return clock.now; } }
  const stored = [...methods];
  const chrome = {
    storage: { local: area(local), session: area(session), onChanged: { addListener() {} } },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {}, setTitle: async () => {}, openPopup: async () => {} },
    scripting: { executeScript: async () => [] },
    webRequest: {
      onBeforeRequest: { addListener: (callback, filter) => listeners.request.push({ callback, filter }) },
      onBeforeRedirect: { addListener: (callback, filter) => listeners.redirect.push({ callback, filter }) },
    },
    // Popup windows (window.open with features) have their own window id and type "popup".
    windows: {
      get: async (id) => ({ id, type: windows[id] || "normal" }),
      getLastFocused: async () => ({ id: Number(Object.keys(windows).find((id) => windows[id] === "normal") ?? 1), type: "normal" }),
    },
    tabs: {
      sendMessage: async (tabId, message, options) => {
        sent.push({ tabId, message: structuredClone(message), options });
        return message.action === "signin_changed" ? { status: "ok", changed: storage.changed === true } : { status: "ok" };
      },
      query: async (filter = {}) => Object.entries(tabs).map(([id, tab]) => ({ id: Number(id), ...tab }))
        .filter((tab) => (filter.active === undefined || tab.active === filter.active) && (filter.windowId === undefined || tab.windowId === filter.windowId)),
      onCreated: { addListener: (callback) => listeners.created.push(callback) },
      get: async (id) => { if (!tabs[id]) throw new Error("no tab"); return { id, ...tabs[id] }; },
      onActivated: { addListener() {} },
      onUpdated: { addListener: (callback) => listeners.updated.push(callback) },
      onRemoved: { addListener: (callback) => listeners.removed.push(callback) },
    },
    alarms: { create: async () => {}, onAlarm: { addListener() {} } },
    runtime: {
      onMessage: { addListener: (callback) => { listeners.message = callback; } },
      onStartup: { addListener() {} },
      sendNativeMessage: async (_host, request) => {
        requests.push(structuredClone(request));
        if (request.action === "status") return { status: "ok", features };
        if (request.action === "query_sign_ins") return { status: "ok", signIns: { site: siteOf(request.origin), methods: stored } };
        if (request.action === "record_sign_in") {
          stored.unshift({ provider: request.signIn.provider, account: request.signIn.account || "", lastUsedAt: 1, useCount: 1 });
          return { status: "saved", signIns: { site: siteOf(request.origin), methods: stored } };
        }
        return { status: "ok", credentials: [] };
      },
    },
  };
  const sandbox = vm.createContext({ chrome, URL, URLSearchParams, Date: FakeDate, setTimeout: (callback) => { timers.push(callback); return timers.length; },
    clearTimeout() {}, crypto: { randomUUID: () => `id-${requests.length}-${sent.length}` } });
  vm.runInContext(signinsSource, sandbox);
  vm.runInContext(readFileSync(new URL("./background.js", import.meta.url), "utf8"), sandbox);
  const flush = async () => { for (let index = 0; index < 20; index++) await new Promise(setImmediate); };
  await flush();
  const fire = async (list, details) => { for (const { callback } of list) callback(details); await flush(); };
  return {
    local, requests, sent, clock, tabs, listeners,
    request: (details) => fire(listeners.request.filter(({ filter }) => filter.types.includes(details.type || "main_frame")), { type: "main_frame", ...details }),
    redirect: (details) => fire(listeners.redirect, { type: "main_frame", ...details }),
    updated: async (tabId, change = { status: "complete" }) => { for (const callback of listeners.updated) callback(tabId, change, { id: tabId, ...tabs[tabId] }); await flush(); },
    created: async (tabId) => { for (const callback of listeners.created) callback({ id: tabId, ...tabs[tabId] }); await flush(); },
    removed: async (tabId) => { const tab = tabs[tabId]; delete tabs[tabId]; for (const callback of listeners.removed) callback(tabId, {}); await flush(); void tab; },
    storage,
    timers: async () => { clock.now += 3000; for (const callback of timers.splice(0)) callback(); await flush(); },
    send: (message, sender) => new Promise((resolve) => { if (!listeners.message(message, sender, resolve)) resolve({ status: "rejected" }); }),
  };
}

const githubAuthorize = "https://github.com/login/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=read%3Auser";
async function signInOnExample(state, { account = "octocat" } = {}) {
  state.tabs[1] = { url: "https://example.com/login", incognito: state.tabs[1]?.incognito === true };
  await state.send({ action: "signin_click", provider: "github" }, { tab: { id: 1, url: "https://example.com/login" }, frameId: 0, url: "https://example.com/login" });
  await state.request({ tabId: 1, url: githubAuthorize, initiator: "https://example.com" });
  if (account) await state.send({ action: "signin_account", account }, { tab: { id: 1, url: githubAuthorize }, frameId: 0, url: githubAuthorize });
  await state.redirect({ tabId: 1, url: githubAuthorize, redirectUrl: "https://example.com/cb?code=c" });
  state.tabs[1].url = "https://example.com/home";
  await state.updated(1);
  await state.timers();
}

test("background: a detected GitHub sign-in asks once on the site's page, then Save remembers the edited account", async () => {
  const state = await worker();
  await signInOnExample(state);
  const shown = state.sent.find((entry) => entry.message.action === "show_prompt");
  assert.deepEqual(shown.message.prompt, { id: shown.message.prompt.id, kind: "signin", provider: "github", providerName: "GitHub", host: "example.com", account: "octocat", locked: false });
  assert.equal(shown.tabId, 1);
  // The page asks again after loading (inline_pending), on any page of the site in that tab.
  const page = { tab: { id: 1 }, frameId: 0, url: "https://www.example.com/home" };
  const pending = await state.send({ action: "inline_pending" }, page);
  assert.equal(pending.prompt.kind, "signin");
  assert.equal((await state.send({ action: "inline_pending" }, { tab: { id: 1 }, frameId: 0, url: "https://other.example/" })).status, "none");
  const saved = await state.send({ action: "inline_approve", id: pending.prompt.id, decision: "save", account: " OctoCat​ " }, page);
  assert.equal(saved.status, "remembered");
  const record = state.requests.find((request) => request.action === "record_sign_in");
  assert.deepEqual(record.signIn, { provider: "github", account: "OctoCat" });
  assert.equal(record.origin, "https://example.com");
  assert.equal(JSON.stringify(state.requests).includes("code=c"), false, "no URL or code reaches the app");
  // The next sign-in with the same account is remembered quietly.
  state.sent.length = 0;
  await signInOnExample(state, { account: "octocat" });
  assert.equal(state.sent.some((entry) => entry.message.action === "show_prompt"), false);
  assert.equal(state.requests.filter((request) => request.action === "record_sign_in").length, 2);
  // Reminders for the page and the popup.
  const reminders = await state.send({ action: "signin_reminders" }, page);
  assert.deepEqual(plain(reminders.methods.map((method) => [method.provider, method.account])), [["github", "octocat"], ["github", "OctoCat"]]);
});

test("background: Never for this site, private windows, and an app without the feature stay quiet", async () => {
  const never = await worker();
  await signInOnExample(never);
  const page = { tab: { id: 1 }, frameId: 0, url: "https://example.com/home" };
  const pending = await never.send({ action: "inline_pending" }, page);
  assert.equal((await never.send({ action: "inline_approve", id: pending.prompt.id, decision: "never" }, page)).status, "never_signin");
  assert.deepEqual(never.local.neverSignIn, ["example.com"]);
  never.sent.length = 0;
  await signInOnExample(never, { account: "hubot" });
  assert.equal(never.sent.length, 0);

  const incognito = await worker();
  incognito.tabs[1] = { url: "https://example.com/login", incognito: true };
  await signInOnExample(incognito);
  assert.equal(incognito.sent.length, 0);
  assert.equal(incognito.requests.some((request) => request.action.includes("sign_in")), false);

  const old = await worker({ features: ["login_title"] });
  await signInOnExample(old);
  assert.equal(old.sent.length, 0);
  assert.equal(old.requests.some((request) => request.action.includes("sign_in")), false);
  assert.equal((await old.send({ action: "signin_reminders" }, page)).status, "unsupported");
});

test("background: an authorize request that redirects at once is still followed (no race with the redirect)", async () => {
  const state = await worker();
  state.tabs[1] = { url: "https://example.com/login" };
  await state.send({ action: "signin_click", provider: "github" }, { tab: { id: 1, url: "https://example.com/login" }, frameId: 0, url: "https://example.com/login" });
  // The browser fires both events before the worker's queue has run once.
  for (const { callback, filter } of state.listeners.request) if (filter.urls.some((url) => url.startsWith("https://github.com/"))) callback({ tabId: 1, type: "main_frame", url: githubAuthorize, initiator: "https://example.com" });
  for (const { callback } of state.listeners.redirect) callback({ tabId: 1, type: "main_frame", url: githubAuthorize, redirectUrl: "https://example.com/cb?code=c" });
  await new Promise((resolve) => setTimeout(resolve, 20));
  state.tabs[1].url = "https://example.com/home";
  await state.updated(1);
  await state.timers();
  assert.equal(state.sent.filter((entry) => entry.message.action === "show_prompt").length, 1);
});

// ---------------------------------------------------------------------------
// Popup sign-ins: recorded URL sequences. The opener is linked when the popup opens (`opened`, from
// openerTabId or, where the browser gives none, a guess), and a popup that answers by postMessage and closes by
// itself waits for the opener to take the answer.

const opened = (tabId, homeTabId) => ({ step: ["opened", { tabId, homeTabId }] });
const homeChanged = (tabId, url) => ({ step: ["homeChanged", { tabId, url }] });

test("Google GIS button popup (Brave, no FedCM): /gsi/select, the chooser, a choice, the popup closes itself", () => {
  const { found } = play([
    click(1, "google"), // the click in the GIS button frame on the site
    opened(2, 1),
    req(2, "https://accounts.google.com/gsi/select?client_id=1.apps.googleusercontent.com&ux_mode=popup&ui_mode=card&as=abc&channel_id=ch1&origin=https%3A%2F%2Fwww.seedr.example",
      { initiator: "https://www.seedr.example", startUrl: "https://www.seedr.example/" }),
    req(2, "https://accounts.google.com/v3/signin/accountchooser?client_id=1.apps.googleusercontent.com&continue=https%3A%2F%2Faccounts.google.com%2Fgsi%2Fselect%3Fclient_id%3D1&flowName=GeneralOAuthLite",
      { initiator: "https://www.seedr.example" }),
    account(2, "https://accounts.google.com/v3/signin/accountchooser", "jamie@gmail.com", { chosen: true }),
    closed(2, "https://www.seedr.example/"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.tabId, entry.provider, entry.origin, entry.account, entry.evidence]),
    [[1, "google", "https://www.seedr.example", "jamie@gmail.com", "click"]]);
});

test("Google OAuth popup that starts at the v3 account chooser (client_id, scope, storagerelay in continue)", () => {
  const chooser = "https://accounts.google.com/v3/signin/accountchooser?client_id=9.apps.googleusercontent.com&scope=openid%20email%20profile"
    + "&continue=" + encodeURIComponent("https://accounts.google.com/o/oauth2/v2/auth?client_id=9&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fwww.seedr.example%3Fid%3Dauth1&scope=openid%20email")
    + "&service=lso&o2v=2&flowName=GeneralOAuthFlow";
  const auth = S.parseAuthorize(chooser);
  assert.equal(auth.provider, "google");
  assert.equal(auth.message, true, "storagerelay in continue answers by postMessage");
  assert.equal(auth.redirectOrigin, "https://www.seedr.example");
  // Google's own sign-ins carry no client_id: not a sign-in to another site.
  assert.equal(S.parseAuthorize("https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com&service=mail"), null);
  const { found } = play([opened(4, 3), req(4, chooser, { initiator: "https://www.seedr.example" }),
    account(4, chooser, "pat@gmail.com", { chosen: true }), closed(4, "https://www.seedr.example/files")]);
  assert.deepEqual(found.map((entry) => [entry.tabId, entry.origin, entry.account]), [[3, "https://www.seedr.example", "pat@gmail.com"]]);
});

test("a popup that closes by itself with no choice seen: the opener's next navigation within 20 s is the answer", () => {
  const start = [opened(2, 1), req(2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fclaude.example%3Fid%3Dauth9&response_type=permission%20id_token&scope=openid%20email%20profile",
    { initiator: "https://claude.example" }), closed(2, "https://claude.example/login")];
  const { found, tracker } = play([...start, homeChanged(1, "https://claude.example/new")]);
  assert.equal(found.length, 0, "it settles first");
  const flow = tracker.flowOf(2);
  assert.equal(flow.phase, "returned");
  assert.deepEqual(plain(tracker.settle({ tabId: 2, at: flow.landedAt + S.SETTLE_MS })), { tabId: 1, provider: "google", origin: "https://claude.example",
    account: "", providerTabId: 2, providerOrigin: "https://accounts.google.com", evidence: "scope" });
  // Nothing happened on the opener within 20 seconds: the user closed the popup.
  const late = play([...start, { ...homeChanged(1, "https://claude.example/new"), after: S.POPUP_RETURN_MS + 1000 }]);
  assert.equal(late.tracker.flowOf(2), null);
  // A popup the user cancelled in, or a redirect-mode popup closed on the provider, never waits.
  assert.equal(play([...start.slice(0, 2), account(2, "https://accounts.google.com/x", "", { chosen: true, cancel: true }), closed(2, "https://claude.example/login")]).tracker.flowOf(2), null);
  const redirectMode = play([opened(2, 1), req(2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=https%3A%2F%2Fclaude.example%2Fcb&scope=openid", { initiator: "https://claude.example" }),
    closed(2, "https://claude.example/login")]);
  assert.equal(redirectMode.tracker.flowOf(2), null);
  // The opener going to the provider itself is not the answer.
  const toProvider = play([...start, homeChanged(1, "https://accounts.google.com/")]);
  assert.equal(toProvider.tracker.flowOf(2).phase, "awaiting");
});

test("a self-closing popup whose opener takes the answer a moment before the popup is reported closed", () => {
  const authorize = req(2, "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fclaude.example%3Fid%3Dauth9&response_type=permission%20id_token&scope=openid%20email%20profile",
    { initiator: "https://claude.example" });
  const moved = (url, after) => ({ step: ["homeMoved", { tabId: 1, url }], after });
  const { tracker } = play([opened(2, 1), authorize, moved("https://claude.example/new", 600), { ...closed(2, "https://claude.example/new"), after: 50 }]);
  const flow = tracker.flowOf(2);
  assert.equal(flow.phase, "returned", "the move just before the close is the answer");
  assert.equal(flow.landing, "https://claude.example/new");
  assert.equal(plain(tracker.settle({ tabId: 2, at: flow.landedAt + S.SETTLE_MS })).origin, "https://claude.example");
  // A move long before the close (the user browsed while the popup sat open) is not the answer.
  const stale = play([opened(2, 1), authorize, moved("https://claude.example/other", 600), { ...closed(2, "https://claude.example/other"), after: 5000 }]);
  assert.equal(stale.tracker.flowOf(2).phase, "awaiting");
  // A move to the provider, or with no popup open, notes nothing.
  assert.equal(play([opened(2, 1), authorize]).tracker.homeMoved({ tabId: 1, url: "https://accounts.google.com/x", at: 1_000_500 }), false);
  assert.equal(S.createTracker().homeMoved({ tabId: 1, url: "https://claude.example/new", at: 1 }), false);
});

test("Microsoft MSAL loginPopup: the popup returns to the site's blank page and closes at once", () => {
  const { found } = play([
    click(1, "microsoft"),
    opened(2, 1),
    req(2, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=c&scope=openid%20profile%20offline_access&redirect_uri=https%3A%2F%2Fapp.contoso.example%2Fblank.html&response_mode=fragment&response_type=code",
      { initiator: "https://app.contoso.example" }),
    account(2, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "sam@contoso.example"),
    req(2, "https://login.microsoftonline.com/common/login", { initiator: "https://login.microsoftonline.com" }),
    redirect(2, "https://login.microsoftonline.com/common/login", "https://app.contoso.example/blank.html#code=0.A&state=s"),
    loaded(2, "https://app.contoso.example/blank.html", "https://app.contoso.example/inbox"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.tabId, entry.provider, entry.origin, entry.account]), [[1, "microsoft", "https://app.contoso.example", "sam@contoso.example"]]);
  // The popup closes before the landing settles: the opener's page still counts.
  const quick = play([
    opened(2, 1),
    req(2, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=c&scope=openid%20profile&redirect_uri=https%3A%2F%2Fapp.contoso.example%2Fblank.html",
      { initiator: "https://app.contoso.example" }),
    redirect(2, "https://login.microsoftonline.com/common/login", "https://app.contoso.example/blank.html#code=0.A"),
    closed(2, "https://app.contoso.example/inbox"),
  ]);
  assert.deepEqual(quick.found.map((entry) => [entry.tabId, entry.origin]), [[1, "https://app.contoso.example"]]);
});

test("broker popup (Firebase signInWithPopup): the handler page first, Google, back to the handler, then the site", () => {
  const { found } = play([
    click(1, "google"),
    opened(2, 1), // linked when the popup opened at the handler, before any provider URL
    req(2, "https://shop-prod.firebaseapp.com/__/auth/handler?apiKey=k&appName=%5BDEFAULT%5D&authType=signInViaPopup&providerId=google.com", { initiator: "https://shop.example" }),
    req(2, "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Fshop-prod.firebaseapp.com%2F__%2Fauth%2Fhandler&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email%20profile",
      { initiator: "https://shop-prod.firebaseapp.com" }),
    account(2, "https://accounts.google.com/o/oauth2/auth/oauthchooseaccount", "lee@gmail.com", { chosen: true }),
    redirect(2, "https://accounts.google.com/signin/oauth/consent", "https://shop-prod.firebaseapp.com/__/auth/handler?state=s&code=4%2F0A"),
    loaded(2, "https://shop-prod.firebaseapp.com/__/auth/handler?state=s&code=4%2F0A", "https://shop.example/account"),
    closed(2, "https://shop.example/account"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.tabId, entry.origin, entry.account]), [[1, "https://shop.example", "lee@gmail.com"]]);
});

test("broker in the same tab (Auth0 Universal Login, as a store's own login service may be): the site after the broker counts", () => {
  const authorize = "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=1&redirect_uri=https%3A%2F%2Fstore-login.us.auth0.com%2Flogin%2Fcallback&scope=email%20profile%20openid";
  const { found } = play([
    req(1, "https://store-login.us.auth0.com/u/login?state=s", { initiator: "https://www.store.example" }),
    click(1, "google"), // "Continue with Google" on the broker's page
    req(1, authorize, { initiator: "https://store-login.us.auth0.com", startUrl: "https://store-login.us.auth0.com/u/login" }),
    account(1, "https://accounts.google.com/v3/signin/accountchooser", "kim@gmail.com", { chosen: true }),
    redirect(1, "https://accounts.google.com/signin/oauth/consent", "https://store-login.us.auth0.com/login/callback?code=4%2F0A&state=s"),
    loaded(1, "https://store-login.us.auth0.com/login/callback"), // the broker: wait for the next page
    loaded(1, "https://www.store.example/account"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.origin, entry.account, entry.evidence]), [["https://www.store.example", "kim@gmail.com", "click"]]);
  for (const url of ["https://x.us.auth0.com/", "https://a.okta.com/", "https://p.firebaseapp.com/", "https://auth.shop.example/__/auth/handler", "https://t.auth.us-east-1.amazoncognito.com/"]) {
    assert.equal(S.isBroker(url), true, url);
  }
  assert.equal(S.isBroker("https://www.store.example/"), false);
});

test("a store's own subdomain login service (login.account.store.example) hands back to the store", () => {
  const authorize = "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=https%3A%2F%2Flogin.account.store.example%2Fsso%2Fgoogle&scope=openid%20email%20profile";
  const { found } = play([
    click(1, "google"),
    req(1, authorize, { initiator: "https://login.account.store.example", startUrl: "https://login.account.store.example/sso/authorize" }),
    redirect(1, authorize, "https://login.account.store.example/sso/google?code=c"),
    loaded(1, "https://www.store.example/"),
  ]);
  assert.deepEqual(found.map((entry) => entry.origin), ["https://www.store.example"]);
});

test("Google's last hop from accounts.youtube.com (SetSID) is still the answer", () => {
  const authorize = "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid";
  const { found } = play([
    req(1, authorize, { initiator: "https://app.example", startUrl: "https://app.example/login" }),
    redirect(1, "https://accounts.google.com/signin/oauth/consent", "https://accounts.youtube.com/accounts/SetSID?continue=x"),
    redirect(1, "https://accounts.youtube.com/accounts/SetSID?continue=x", "https://app.example/cb?code=c"),
    loaded(1, "https://app.example/home"),
  ]);
  assert.equal(found[0]?.origin, "https://app.example");
});

test("popup links: opened() survives a worker restart; a click is recent for 30 s only", () => {
  const first = S.createTracker();
  first.click({ tabId: 7, provider: "google", at: 1000 });
  first.opened({ tabId: 8, homeTabId: 7, at: 1100 });
  const second = S.createTracker(JSON.parse(JSON.stringify(first.toJSON())));
  assert.equal(second.homeOf(8), 7);
  assert.equal(second.recentClick({ at: 20_000, except: 8 }), 7);
  assert.equal(second.recentClick({ at: 40_000, except: 8 }), null);
  second.closed({ tabId: 7, at: 2000 });
  assert.equal(second.homeOf(8), null, "the opener closed: the link goes");
});

// ---------------------------------------------------------------------------
// The background worker: popups without openerTabId (Firefox across windows, or opened with noopener).

const seedr = "https://www.seedr.example/";
const gsiSelect = "https://accounts.google.com/gsi/select?client_id=1.apps.googleusercontent.com&ux_mode=popup&ui_mode=card&channel_id=c&origin=https%3A%2F%2Fwww.seedr.example";
const gsiButtonFrame = "https://accounts.google.com/gsi/button?theme=outline&size=large&client_id=1.apps.googleusercontent.com";

async function popupWorker(extra = {}) {
  const state = await worker({ windows: { 10: "normal", 20: "popup" }, ...extra });
  state.tabs[1] = { url: seedr, windowId: 10, active: true };
  return state;
}

test("background: a GIS button popup with no openerTabId is linked to the clicked tab and asks there, with the chosen account", async () => {
  const state = await popupWorker();
  // The click lands in Google's button frame on the site.
  await state.send({ action: "signin_click", provider: "google", frame: "button" }, { tab: { id: 1, url: seedr }, frameId: 3, url: gsiButtonFrame });
  state.tabs[2] = { url: "", pendingUrl: gsiSelect, windowId: 20 }; // no openerTabId: a popup window
  await state.created(2);
  await state.request({ tabId: 2, url: gsiSelect, initiator: "https://www.seedr.example" });
  assert.ok(state.sent.some((entry) => entry.tabId === 1 && entry.message.action === "signin_watch"), "the opener notes its storage keys");
  state.tabs[2].url = "https://accounts.google.com/v3/signin/accountchooser?client_id=1";
  await state.send({ action: "signin_account", account: "jamie@gmail.com", chosen: true }, { tab: { id: 2, url: state.tabs[2].url }, frameId: 0, url: state.tabs[2].url });
  await state.removed(2);
  const shown = state.sent.find((entry) => entry.message.action === "show_prompt");
  assert.equal(shown?.tabId, 1);
  assert.equal(shown.message.prompt.provider, "google");
  assert.equal(shown.message.prompt.account, "jamie@gmail.com");
});

test("background: without a click, the active tab of the focused window is the opener only when it is the site that started it", async () => {
  const state = await popupWorker();
  state.tabs[5] = { url: "https://news.example/", windowId: 10, active: false };
  state.tabs[2] = { url: "about:blank", windowId: 20 };
  await state.request({ tabId: 2, url: gsiSelect, initiator: "https://www.seedr.example" });
  assert.equal(state.sent.find((entry) => entry.message.action === "signin_watch")?.tabId, 1);
  const other = await popupWorker();
  other.tabs[2] = { url: "about:blank", windowId: 20 };
  await other.request({ tabId: 2, url: gsiSelect, initiator: "https://elsewhere.example" });
  assert.equal(other.sent.some((entry) => entry.message.action === "signin_watch"), false, "a site in no tab: no opener is guessed");
});

test("background: a popup opened before any provider URL (broker) is linked on tabs.onCreated", async () => {
  const state = await popupWorker();
  await state.send({ action: "signin_click", provider: "google" }, { tab: { id: 1, url: seedr }, frameId: 0, url: seedr });
  state.tabs[2] = { url: "", pendingUrl: "https://seedr-prod.firebaseapp.com/__/auth/handler?providerId=google.com", windowId: 20 };
  await state.created(2);
  state.tabs[2].url = "https://seedr-prod.firebaseapp.com/__/auth/handler?providerId=google.com";
  const authorize = "https://accounts.google.com/o/oauth2/auth?client_id=1&redirect_uri=https%3A%2F%2Fseedr-prod.firebaseapp.com%2F__%2Fauth%2Fhandler&scope=openid%20email%20profile";
  await state.request({ tabId: 2, url: authorize, initiator: "https://seedr-prod.firebaseapp.com" });
  await state.redirect({ tabId: 2, url: authorize, redirectUrl: "https://seedr-prod.firebaseapp.com/__/auth/handler?code=c" });
  state.tabs[2].url = "https://seedr-prod.firebaseapp.com/__/auth/handler?code=c";
  await state.updated(2);
  await state.removed(2);
  const shown = state.sent.find((entry) => entry.message.action === "show_prompt");
  assert.equal(shown?.tabId, 1, "asked on the site, never on the broker");
});

test("background: a self-closing popup counts once the opener navigates (pushState) or stores a new key, not otherwise", async () => {
  const storagerelay = "https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=storagerelay%3A%2F%2Fhttps%2Fwww.seedr.example%3Fid%3Dauth1&scope=openid%20email%20profile";
  const begin = async (state) => {
    state.tabs[2] = { url: "about:blank", windowId: 20 };
    await state.created(2);
    await state.request({ tabId: 2, url: storagerelay, initiator: "https://www.seedr.example" });
    await state.removed(2);
  };
  const navigated = await popupWorker();
  await begin(navigated);
  navigated.tabs[1].url = "https://www.seedr.example/files";
  await navigated.updated(1, { url: "https://www.seedr.example/files" });
  await navigated.timers();
  await navigated.timers();
  assert.equal(navigated.sent.filter((entry) => entry.message.action === "show_prompt").length, 1);

  const stored = await popupWorker({ storage: { changed: true } });
  await begin(stored);
  await stored.timers(); // the opener is asked whether a new storage key appeared
  await stored.timers(); // then the landing settles
  assert.ok(stored.sent.some((entry) => entry.message.action === "signin_changed"));
  assert.equal(stored.sent.filter((entry) => entry.message.action === "show_prompt").length, 1);

  const nothing = await popupWorker();
  await begin(nothing);
  await nothing.timers();
  await nothing.timers();
  assert.equal(nothing.sent.some((entry) => entry.message.action === "show_prompt"), false, "closed and nothing happened: the user gave up");
});

test("background: a click reported from a frame counts only from the provider's own button frame or a site frame", async () => {
  const state = await popupWorker();
  const fromFrame = (url, provider = "google") => state.send({ action: "signin_click", provider }, { tab: { id: 1, url: seedr }, frameId: 4, url });
  assert.equal((await fromFrame(gsiButtonFrame)).status, "ok");
  assert.equal((await fromFrame(gsiButtonFrame, "apple")).status, "ignored", "Google's button frame never reports another provider");
  assert.equal((await fromFrame("https://accounts.google.com/v3/signin/identifier?client_id=1")).status, "ignored", "a provider's sign-in page is not a site");
  assert.equal((await fromFrame("https://login.store.example/embedded")).status, "ok", "a site's own login frame");
});

// ---------------------------------------------------------------------------
// Account extraction from provider page markup (synthetic HTML; the shapes of real pages, no real data).

/** A small HTML parser and the `api` signins.js reads pages through (selectors: tag, #id, .class, [attr], [attr='v'], :checked). */
function htmlPage(html) {
  const root = { tag: "#root", attrs: {}, children: [], parent: null };
  let node = root;
  const VOID = new Set(["meta", "input", "img", "br", "hr", "link"]);
  for (const token of html.match(/<!--[\s\S]*?-->|<\/?[a-z][^>]*>|[^<]+/gi) || []) {
    if (token.startsWith("<!--")) continue;
    const close = /^<\/([a-z0-9]+)/i.exec(token);
    if (close) {
      let at = node;
      while (at !== root && at.tag !== close[1].toLowerCase()) at = at.parent;
      if (at !== root) node = at.parent;
      continue;
    }
    const open = /^<([a-z0-9]+)([^>]*)>$/i.exec(token);
    if (!open) { node.children.push({ text: token.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">") }); continue; }
    const element = { tag: open[1].toLowerCase(), attrs: {}, children: [], parent: node };
    for (const match of open[2].matchAll(/([a-z0-9-:]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/gi)) element.attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? "";
    node.children.push(element);
    if (!VOID.has(element.tag)) node = element;
  }
  const elements = (from) => from.children.filter((child) => child.tag).flatMap((child) => [child, ...elements(child)]);
  // innerText: text nodes only (an input's value is never text), block elements on their own lines.
  const text = (from) => (from.text !== undefined ? from.text : from.tag === "script" || from.tag === "style" ? ""
    : from.children.map((child) => text(child) + (/^(div|li|p|h1|h2|small|ul)$/.test(child.tag || "") ? "\n" : "")).join(""));
  const one = (element, selector) => {
    const parts = /^([a-z0-9]*)((?:#[\w-]+|\.[\w-]+|\[[^\]]+\]|:checked)*)$/i.exec(selector.trim());
    if (!parts) throw new Error(`selector not supported here: ${selector}`);
    if (parts[1] && element.tag !== parts[1].toLowerCase()) return false;
    for (const [piece] of parts[2].matchAll(/#[\w-]+|\.[\w-]+|\[[^\]]+\]|:checked/g)) {
      if (piece === ":checked") { if (!("checked" in element.attrs)) return false; continue; }
      if (piece[0] === "#") { if (element.attrs.id !== piece.slice(1)) return false; continue; }
      if (piece[0] === ".") { if (!(element.attrs.class || "").split(/\s+/).includes(piece.slice(1))) return false; continue; }
      const [, name, value] = /^\[([\w-]+)(?:=['"]?([^'"]*)['"]?)?\]$/.exec(piece);
      if (!(name in element.attrs) || (value !== undefined && element.attrs[name] !== value)) return false;
    }
    return true;
  };
  const matches = (element, selector) => Boolean(element?.tag) && selector.split(",").some((part) => one(element, part));
  const api = {
    query: (selector) => elements(root).filter((element) => matches(element, selector)),
    within: (from, selector) => elements(from).filter((element) => matches(element, selector)),
    attr: (element, name) => element?.attrs?.[name] ?? "",
    text: (element) => text(element).replace(/\n+/g, "\n"),
    parent: (element) => (element?.parent && element.parent !== root ? element.parent : null),
    isElement: (element) => Boolean(element?.tag),
    matches,
    body: () => elements(root).find((element) => element.tag === "body") || root,
  };
  /** The event path of a click on the first element matching `selector`: it, then its ancestors. */
  const pathTo = (selector) => { const path = []; for (let at = api.query(selector)[0]; at && at !== root; at = at.parent) path.push(at); return path; };
  return { api, pathTo };
}

const GOOGLE_CHOOSER = `<html><body><div class="card"><h1>Choose an account</h1><div>to continue to <a href="#">seedr.example</a></div>
  <ul>
    <li><div role="link" tabindex="0" data-identifier="jamie@gmail.com" data-authuser="0"><div><img alt=""></div>
      <div><div class="name">Jamie Doe</div><div data-email="jamie@gmail.com">jamie@gmail.com</div></div></div></li>
    <li><div role="link" tabindex="0" data-identifier="jamie.work@example.org" data-authuser="1"><div><img alt=""></div>
      <div><div class="name" id="work-name">Jamie (Work)</div><div data-email="jamie.work@example.org">jamie.work@example.org</div></div></div></li>
    <li><div role="link" tabindex="0" id="other"><div>Use another account</div></div></li>
  </ul></div></body></html>`;

test("Google: the chooser names no account until a tile is picked; the picked tile's address is the account", () => {
  const { api, pathTo } = htmlPage(GOOGLE_CHOOSER);
  assert.equal(S.accountFromPage("google", api), "", "two accounts listed: not knowable before the click");
  assert.equal(S.accountFromClick(pathTo("#work-name"), api), "jamie.work@example.org");
  assert.equal(S.accountFromClick(pathTo("#other"), api), "", "Use another account names none");
});

test("Google: the password step's identity chip, the consent page and a chooser with one account", () => {
  const password = htmlPage(`<body><h1>Welcome</h1><div id="identifierChip"><div><img alt=""></div><div data-profile-identifier="">jamie@gmail.com</div></div>
    <form><input type="password" name="Passwd" value="never-read-this"><div>Show password</div></form></body>`);
  assert.equal(S.accountFromPage("google", password.api), "jamie@gmail.com");
  const consent = htmlPage(`<body><h1>Sign in to seedr.example</h1><div><div>Jamie Doe</div><div>jamie@gmail.com</div></div>
    <p>By continuing, Google will share your name, email address, language preference, and profile picture with seedr.example.</p>
    <button>Cancel</button><button>Continue</button></body>`);
  assert.equal(S.accountFromPage("google", consent.api), "jamie@gmail.com");
  const single = htmlPage(`<body><div>Choose an account</div><div role="link" data-identifier="pat@gmail.com"><div>Pat</div><div>pat@gmail.com</div></div></body>`);
  assert.equal(S.accountFromPage("google", single.api), "pat@gmail.com");
  // An address typed into the identifier field is an input's value, never read.
  const typed = htmlPage(`<body><h1>Sign in</h1><input type="email" value="typed@example.com"><button>Next</button></body>`);
  assert.equal(S.accountFromPage("google", typed.api), "");
});

test("Microsoft: Pick an account tiles, the identity banner on the password and Approve steps, and Stay signed in", () => {
  const pick = htmlPage(`<body><div id="loginHeader">Pick an account</div><div id="tilesHolder">
    <div class="table" role="button" tabindex="0" data-test-id="sam@contoso.example"><div class="table-row"><div class="table-cell"><div id="sam-name">Sam Rivera</div><small>sam@contoso.example</small><div>Signed in</div></div></div></div>
    <div class="table" role="button" tabindex="0" data-test-id="sam.personal@outlook.example"><div class="table-cell"><div>Sam</div><small>sam.personal@outlook.example</small></div></div>
    <div class="table" role="button" id="otherTile" data-test-id="otherTile"><div>Use another account</div></div></div></body>`);
  assert.equal(S.accountFromPage("microsoft", pick.api), "");
  assert.equal(S.accountFromClick(pick.pathTo("#sam-name"), pick.api), "sam@contoso.example");
  assert.equal(S.accountFromClick(pick.pathTo("#otherTile"), pick.api), "", "data-test-id='otherTile' is not an account");
  const approve = htmlPage(`<body><div class="identityBanner"><button aria-label="Back">Back</button><div id="displayName" class="identity" title="sam@contoso.example">sam@contoso.example</div></div>
    <div id="idDiv_SAOTCAS_Title">Approve sign in request</div><div>Open your Authenticator app, and enter the number shown to sign in.</div><div>42</div></body>`);
  assert.equal(S.accountFromPage("microsoft", approve.api), "sam@contoso.example");
  const stay = htmlPage(`<body><div data-testid="identityBanner"><div>sam.personal@outlook.example</div></div><div>Stay signed in?</div><input type="submit" value="Yes"></body>`);
  assert.equal(S.accountFromPage("microsoft", stay.api), "sam.personal@outlook.example");
  assert.equal(S.providerOfPage("account.live.com", "/Consent/Update"), "microsoft", "the personal account consent page");
});

test("watchPage: a single-page step re-reports the account when it appears, Enter on a tile picks it, GIS button frames report the click", () => {
  // Microsoft's password step appears without a page load: the account is reported when it shows.
  const sent = [];
  let changed = null;
  const first = htmlPage(`<body><div id="step">Sign in</div></body>`);
  const api = { ...first.api, observe: (callback) => { changed = callback; } };
  S.watchPage({ send: async (message) => sent.push(message), listen: () => {}, doc: {}, api, hostname: "login.microsoftonline.com", pathname: "/common/oauth2/v2.0/authorize", inFrame: false });
  assert.equal(typeof changed, "function", "the page is watched for changes");
  Object.assign(api, htmlPage(`<body><div id="displayName">sam@contoso.example</div><div>Enter password</div></body>`).api, { observe: api.observe });
  changed();
  assert.deepEqual(plain(sent.at(-1)), { action: "signin_account", account: "sam@contoso.example" });
  // Keyboard: Enter on a focused account tile is a choice like a click.
  const chooser = htmlPage(GOOGLE_CHOOSER);
  const googleSent = [];
  const handlers = {};
  S.watchPage({ send: async (message) => googleSent.push(message), listen: (_doc, type, callback) => { (handlers[type] ||= []).push(callback); }, doc: {},
    api: chooser.api, hostname: "accounts.google.com", pathname: "/v3/signin/accountchooser", inFrame: false });
  const tile = chooser.pathTo("[data-identifier='jamie.work@example.org']");
  for (const callback of handlers.keydown) callback({ isTrusted: true, type: "keydown", key: "a", composedPath: () => tile });
  assert.equal(googleSent.length, 0, "other keys pick nothing");
  for (const callback of handlers.keydown) callback({ isTrusted: true, type: "keydown", key: "Enter", composedPath: () => tile });
  assert.deepEqual(plain(googleSent.at(-1)), { action: "signin_account", account: "jamie.work@example.org", chosen: true, cancel: false });
  // Google's GIS button frame on a site reports the click for the site's tab.
  const frameSent = [];
  const frameHandlers = {};
  S.watchPage({ send: async (message) => frameSent.push(message), listen: (_doc, type, callback) => { (frameHandlers[type] ||= []).push(callback); }, doc: {},
    api: htmlPage("<body><div role='button'>Sign in with Google</div></body>").api, hostname: "accounts.google.com", pathname: "/gsi/button", inFrame: true });
  for (const callback of frameHandlers.click) callback({ isTrusted: true, type: "click", composedPath: () => [] });
  for (const callback of frameHandlers.click) callback({ isTrusted: false, type: "click", composedPath: () => [] });
  assert.deepEqual(plain(frameSent), [{ action: "signin_click", provider: "google", frame: "button" }]);
});

test("Google Identity Services in redirect mode: the page goes to /gsi/select, the choice posts back to login_uri", () => {
  const select = "https://accounts.google.com/gsi/select?client_id=1.apps.googleusercontent.com&ux_mode=redirect&login_uri=https%3A%2F%2Fclaude.example%2Flogin%2Fgoogle";
  const { found } = play([
    click(1, "google"),
    req(1, select, { initiator: "https://claude.example", startUrl: "https://claude.example/login" }),
    req(1, "https://accounts.google.com/v3/signin/accountchooser?client_id=1.apps.googleusercontent.com&continue=" + encodeURIComponent(select), { initiator: "https://claude.example" }),
    account(1, "https://accounts.google.com/v3/signin/accountchooser", "jamie@gmail.com", { chosen: true, homeUrl: "https://accounts.google.com/v3/signin/accountchooser" }),
    req(1, "https://claude.example/login/google", { initiator: "https://accounts.google.com" }), // the form POST
    loaded(1, "https://claude.example/new"),
  ]);
  assert.deepEqual(found.map((entry) => [entry.origin, entry.account]), [["https://claude.example", "jamie@gmail.com"]]);
});

test("background: a blank new tab in a normal window is never linked to another tab on creation", async () => {
  const state = await popupWorker();
  state.tabs[3] = { url: "", pendingUrl: "", windowId: 10, openerTabId: 1 };
  await state.created(3);
  state.tabs[3].url = "https://other.example/login";
  const github = "https://github.com/login/oauth/authorize?client_id=c&redirect_uri=https%3A%2F%2Fother.example%2Fcb&scope=read%3Auser";
  await state.request({ tabId: 3, url: github, initiator: "https://other.example" });
  assert.equal(state.sent.some((entry) => entry.message.action === "signin_watch"), false, "its sign-in is its own");
});
