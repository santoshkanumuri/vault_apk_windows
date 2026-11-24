// Run with `npm test`. Node strips the TypeScript types of signIns.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { accountProblem, accountsOf, forLogin, groupBySite, providerName, providersOf, searchHost, siteMatches } from "./signIns.ts";

const row = (id, site, provider, account, lastUsedAt) => ({ id, site, provider, account, firstUsedAt: 1, lastUsedAt, useCount: 1 });
const items = [
  row("a", "example.com", "github", "octocat", 50),
  row("b", "example.com", "google", "me@example.com", 90),
  row("c", "bbc.co.uk", "google", "Me@Example.com", 10),
  row("d", "alice.github.io", "github", "", 70),
];

test("groups by site, most recent first, with each site's methods most recent first", () => {
  const groups = groupBySite(items);
  assert.deepEqual(groups.map((group) => [group.site, group.methods.map((method) => method.id)]),
    [["example.com", ["b", "a"]], ["alice.github.io", ["d"]], ["bbc.co.uk", ["c"]]]);
});

test("filters by provider, by account (ignoring case, or not known) and by site", () => {
  assert.deepEqual(groupBySite(items, { provider: "google" }).map((group) => group.site), ["example.com", "bbc.co.uk"]);
  assert.deepEqual(groupBySite(items, { account: "ME@example.com" }).map((group) => group.site), ["example.com", "bbc.co.uk"]);
  assert.deepEqual(groupBySite(items, { account: "\u0000none" }).map((group) => group.site), ["alice.github.io"]);
  assert.deepEqual(groupBySite(items, { provider: "github", account: "octocat" }).map((group) => group.methods.length), [1]);
});

test("the search box matches a site like logins match pages: the site, any page of it, or part of its name", () => {
  assert.equal(searchHost(" https://WWW.Example.com:443/login?x "), "example.com");
  assert.ok(siteMatches("example.com", "login.example.com"));
  assert.ok(siteMatches("example.com", "https://app.example.com/path"));
  assert.ok(siteMatches("example.com", "examp"));
  assert.ok(siteMatches("bbc.co.uk", "news.bbc.co.uk"));
  assert.ok(!siteMatches("example.com", "notexample.org"));
  assert.ok(!siteMatches("alice.github.io", "bob.github.io"), "another user's site under a public suffix");
  assert.ok(siteMatches("example.com", "  "));
});

test("filter choices, login links, names and account checks", () => {
  assert.deepEqual(accountsOf(items), ["me@example.com", "octocat"]);
  assert.deepEqual(providersOf(items), ["google", "github"]);
  assert.equal(providerName("linkedin"), "LinkedIn");
  assert.equal(providerName("unknown"), "unknown");
  const state = { enabled: true, items, logins: { "example.com": ["login-1"], "bbc.co.uk": ["login-2"] } };
  assert.deepEqual(forLogin(state, "login-1").map((method) => method.id), ["b", "a"]);
  assert.deepEqual(forLogin(state, "nope"), []);
  assert.equal(accountProblem("octocat"), null);
  assert.equal(accountProblem("a".repeat(257)) !== null, true);
  assert.equal(accountProblem("a‮b") !== null, true);
});
