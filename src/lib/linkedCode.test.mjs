// Run with `npm test`. Node strips the TypeScript types of entries.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { codeLabel, codesToLink, linkedCode } from "./linkedCode.ts";

const item = (draft) => ({ id: "x", type: "PASSWORD", title: "", primaryValue: "", linkedAuthenticatorId: "", favorite: false, ...draft });
const code = (id, title, account = "", favorite = false) => item({ id, type: "AUTHENTICATOR", title, primaryValue: account, favorite });

test("the picker lists codes only, favorites first, then by name", () => {
  const entries = [
    code("c2", "GitHub", "octocat"),
    item({ id: "p1", title: "Mail" }),
    code("c3", "bank", "me@example.com"),
    code("c1", "AWS root", "ops@example.com", true),
    item({ id: "k1", type: "CARD", title: "Travel" }),
  ];
  assert.deepEqual(codesToLink(entries).map((entry) => entry.id), ["c1", "c3", "c2"]);
  assert.deepEqual(codesToLink([item({ id: "p1", title: "Mail" })]), []);
});

test("a login shows its linked code, and nothing when the link cannot be followed", () => {
  const github = code("c1", "GitHub", "octocat");
  const login = item({ id: "p1", title: "GitHub", linkedAuthenticatorId: "c1" });
  const entries = [github, login];
  assert.equal(linkedCode(login, entries), github);
  // A code that was deleted, a link to something that is not a code, and no link at all.
  assert.equal(linkedCode(login, [login]), null);
  assert.equal(linkedCode(item({ id: "p2", linkedAuthenticatorId: "p1" }), entries), null);
  assert.equal(linkedCode(item({ id: "p3" }), entries), null);
  // Only a login carries a link, so a card with one shows no code.
  assert.equal(linkedCode(item({ id: "k1", type: "CARD", linkedAuthenticatorId: "c1" }), entries), null);
});

test("a code reads as its name and account", () => {
  assert.equal(codeLabel(code("c1", "GitHub", "octocat")), "GitHub · octocat");
  assert.equal(codeLabel(code("c1", " GitHub ", "  ")), "GitHub");
  assert.equal(codeLabel(code("c1", "", "octocat")), "Untitled · octocat");
});
