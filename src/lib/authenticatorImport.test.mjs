// Run with `npm test`. Node strips the TypeScript types of authenticatorImport.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { alreadyRead, importResult, isOneAuthExport, reviewHeading, reviewLabel } from "./authenticatorImport.ts";

test("only a oneauth_04 export asks for its password", () => {
  assert.equal(isOneAuthExport('{"format":"oneauth_04","nonce":1}'), true);
  assert.equal(isOneAuthExport('{"format":"oneauth_03"}'), false);
  assert.equal(isOneAuthExport("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"), false);
  assert.equal(isOneAuthExport('["oneauth_04"]'), false);
});

test("the heading counts QR pages only for a batch of more than one", () => {
  const review = (pages, expected) => ({ pages, expected, items: [], new: 0, alreadySaved: 0, conflicts: 0 });
  assert.equal(reviewHeading(review(1, 1)), "Accounts to import");
  assert.equal(reviewHeading(review(1, 3)), "1 of 3 QR pages scanned");
});

test("each account shows its name, account and status as on Android", () => {
  assert.equal(reviewLabel({ issuer: "GitHub", account: "me", status: "new" }), "GitHub · me · New");
  assert.equal(reviewLabel({ issuer: " ", account: "me", status: "alreadySaved" }), "me · me · Already saved");
  assert.equal(reviewLabel({ issuer: "Mail", account: "me", status: "conflict" }), "Mail · me · Different setup key, skipped");
});

test("the result reads like Android's and warns about skipped conflicts", () => {
  assert.deepEqual(importResult({ added: 2, alreadySaved: 1, conflicts: 0 }),
    { message: "Imported 2 authenticator accounts. 1 already saved. 0 conflicts skipped.", tone: "success" });
  assert.deepEqual(importResult({ added: 1, alreadySaved: 0, conflicts: 1 }),
    { message: "Imported 1 authenticator account. 0 already saved. 1 conflict skipped.", tone: "warning" });
  assert.equal(importResult({ added: 0, alreadySaved: 3, conflicts: 0 }).tone, "info");
});

test("a page read twice is noticed", () => {
  const sources = [{ kind: "qr", text: "otpauth-migration://offline?data=AA" }];
  assert.equal(alreadyRead(sources, { kind: "qr", text: "otpauth-migration://offline?data=AA" }), true);
  assert.equal(alreadyRead(sources, { kind: "text", text: "otpauth-migration://offline?data=AA" }), false);
});
