import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const signinsSource = readFileSync(new URL("./signins.js", import.meta.url), "utf8");
const context = vm.createContext({ URL, URLSearchParams });
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

async function worker({ features = ["sign_in_methods"], methods = [], tabs = {} } = {}) {
  const local = {};
  const session = {};
  const requests = [];
  const sent = [];
  const listeners = { request: [], redirect: [], updated: [], removed: [], message: null };
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
    windows: { get: async () => ({ type: "normal" }) },
    tabs: {
      sendMessage: async (tabId, message, options) => { sent.push({ tabId, message: structuredClone(message), options }); return { status: "ok" }; },
      query: async () => [],
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
        if (request.action === "query_sign_ins") return { status: "ok", signIns: { site: "example.com", methods: stored } };
        if (request.action === "record_sign_in") {
          stored.unshift({ provider: request.signIn.provider, account: request.signIn.account || "", lastUsedAt: 1, useCount: 1 });
          return { status: "saved", signIns: { site: "example.com", methods: stored } };
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
    updated: async (tabId) => { for (const callback of listeners.updated) callback(tabId, { status: "complete" }, { id: tabId, ...tabs[tabId] }); await flush(); },
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
