import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const context = vm.createContext({ URL });
vm.runInContext(readFileSync(new URL("./loginsearch.js", import.meta.url), "utf8"), context);
const S = context.NuvoriLoginSearch;
const ids = (found) => Array.from(found.results, (login) => login.id);

const LOGINS = [
  { id: "1", title: "GitHub", username: "octocat", site: "github.com", selectionToken: "a" },
  { id: "2", title: "Work mail", username: "alice@corp.example", site: "mail.corp.example", selectionToken: "b" },
  { id: "3", title: "Personal mail", username: "alice@example.com", site: "www.example.com", selectionToken: "c" },
  { id: "4", title: "Router", username: "admin", site: "", selectionToken: "d" },
  { id: "5", title: "No token", username: "alice", site: "x.test" },
];

test("queries are words, and a pasted URL becomes its host", () => {
  assert.deepEqual(Array.from(S.queryWords("  Alice   MAIL ")), ["alice", "mail"]);
  assert.deepEqual(Array.from(S.queryWords("https://www.GitHub.com/login?next=/")), ["github.com"]);
  assert.deepEqual(Array.from(S.queryWords("https://user@host.test:8443/x")), ["host.test"]);
  assert.deepEqual(Array.from(S.queryWords("")), []);
  assert.equal(S.queryWords("a".repeat(500))[0].length, S.MAX_QUERY);
});

test("search matches site, name and username, every word, best first", () => {
  assert.deepEqual(ids(S.search(LOGINS, "mail")), ["2", "3"]);
  assert.deepEqual(ids(S.search(LOGINS, "alice")), ["3", "2"]);
  assert.deepEqual(ids(S.search(LOGINS, "alice corp")), ["2"]);
  assert.deepEqual(ids(S.search(LOGINS, "octo")), ["1"]);
  assert.deepEqual(ids(S.search(LOGINS, "https://github.com/settings")), ["1"]);
  assert.deepEqual(ids(S.search(LOGINS, "example.com")), ["3"]);
  assert.deepEqual(ids(S.search(LOGINS, "admin")), ["4"]);
  assert.deepEqual(ids(S.search(LOGINS, "corp")), ["2"], "a site part counts");
  assert.deepEqual(ids(S.search(LOGINS, "nothing")), []);
  assert.deepEqual(ids(S.search(LOGINS, "")), []);
});

test("search skips logins it can't fill and caps the list", () => {
  assert.deepEqual(ids(S.search(LOGINS, "x.test")), [], "no selection token, not listed");
  const many = Array.from({ length: 60 }, (_, index) => ({ id: `id${index}`, title: `Shop ${index}`, username: "u", site: `shop${index}.test`, selectionToken: "t" }));
  const found = S.search(many, "shop");
  assert.equal(found.results.length, S.MAX_RESULTS);
  assert.equal(found.total, 60);
  assert.deepEqual(S.search(null, "x").results.length, 0);
});

test("a site ranks above a name or username that only contains the word", () => {
  const logins = [
    { id: "contains", title: "My amazon wishlist", username: "x", site: "lists.test", selectionToken: "t" },
    { id: "site", title: "Shopping", username: "y", site: "www.amazon.com", selectionToken: "t" },
  ];
  assert.deepEqual(ids(S.search(logins, "amazon")), ["site", "contains"]);
});

test("same site means the same host, or a domain and its www name", () => {
  assert.equal(S.sameSite("example.com", "https://www.example.com"), true);
  assert.equal(S.sameSite("www.example.com", "https://example.com"), true);
  assert.equal(S.sameSite("Example.com", "https://example.com:8443"), true);
  assert.equal(S.sameSite("mail.example.com", "https://mail.example.com"), true);
  assert.equal(S.sameSite("mail.example.com", "https://example.com"), false);
  assert.equal(S.sameSite("example.com", "https://login.example.com"), false);
  assert.equal(S.sameSite("example.com", "https://example.com.evil.test"), false);
  assert.equal(S.sameSite("example.com", "https://examp1e.com"), false);
  assert.equal(S.sameSite("", "https://example.com"), false);
  assert.equal(S.sameSite("example.com", "not a url"), false);
  assert.equal(S.hostOf("https://www.example.com/x"), "example.com");
});
