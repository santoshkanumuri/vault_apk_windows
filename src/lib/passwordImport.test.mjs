// Run with `npm test`. Node strips the TypeScript types of passwordImport.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { importChoices, importResult, itemLabel, mappingValid, matchesFilter, reviewCounts } from "./passwordImport.ts";

const review = {
  kind: "review", rows: 6, duplicateRows: 1, new: 2, alreadySaved: 1, passwordDiffers: 1, ambiguous: 1, token: "t",
  items: [
    { row: 0, title: "Mail", username: "me", status: "new" },
    { row: 1, title: "Shop", username: "me", status: "new" },
    { row: 2, title: "Bank", username: "me", status: "alreadySaved" },
    { row: 3, title: "Forum", username: "me", status: "passwordDiffers" },
    { row: 4, title: "Work", username: "me", status: "ambiguous" },
  ],
};

test("the column choice needs website, username and password, each column once", () => {
  const mapping = { title: null, website: "site", username: "login", password: "secret", notes: null };
  assert.equal(mappingValid(mapping), true);
  assert.equal(mappingValid({ ...mapping, password: null }), false);
  assert.equal(mappingValid({ ...mapping, notes: "site" }), false, "an optional column can't repeat a required one");
  assert.equal(mappingValid({ ...mapping, title: "name", notes: "comments" }), true);
});

test("filters show what Android's chips show", () => {
  assert.deepEqual(review.items.filter((item) => matchesFilter("needsDecision", item.status)).map((item) => item.row), [3, 4]);
  assert.deepEqual(review.items.filter((item) => matchesFilter("new", item.status)).map((item) => item.row), [0, 1]);
  assert.equal(review.items.filter((item) => matchesFilter("all", item.status)).length, 5);
});

test("the heading counts each kind and leaves out empty extras", () => {
  assert.equal(reviewCounts(review), "2 new · 1 already saved · 1 password changes · 1 ambiguous · 1 repeated export rows consolidated");
  assert.equal(reviewCounts({ ...review, ambiguous: 0, duplicateRows: 0 }), "2 new · 1 already saved · 1 password changes");
  assert.equal(itemLabel(review.items[0]), "Mail · me");
});

test("choices send unticked new logins and chosen imported passwords only", () => {
  assert.deepEqual(importChoices(review, new Set([1, 3]), new Set([3, 0])), { token: "t", skipNew: [1], useImported: [3] });
  assert.deepEqual(importChoices(review, new Set(), new Set()), { token: "t", skipNew: [], useImported: [] });
});

test("the result reads as Android's", () => {
  assert.equal(importResult({ added: 1, updated: 2, skippedExact: 1, skippedConflicts: 1, duplicateRows: 2 }),
    "Added 1 login and updated 2. Skipped 3 duplicates and 1 incoming password change. Delete the readable export file after checking your logins.");
});
