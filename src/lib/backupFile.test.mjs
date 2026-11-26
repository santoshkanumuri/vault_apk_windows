// Run with `npm test`. Node strips the TypeScript types of backupFile.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { backupContents, localDate, restoredMessage } from "./backupFile.ts";

test("the suggested date is the local calendar date", () => {
  assert.equal(localDate(new Date(2026, 10, 5, 23, 59)), "2026-11-05");
  assert.equal(localDate(new Date(2027, 0, 1, 0, 0)), "2027-01-01");
});

test("the review says what the backup holds, as Android does", () => {
  assert.equal(backupContents({ items: 12, codes: 2, folders: 3, photos: 1, passkeys: 4 }),
    "The backup has 12 items, including 2 authenticators. It also has 3 folders, 1 photo and 4 passkeys.");
  assert.equal(backupContents({ items: 1, codes: 1, folders: 0, photos: 2, passkeys: 0 }),
    "The backup has 1 item, including 1 authenticator. It also has 2 photos.");
  assert.equal(backupContents({ items: 0, codes: 0, folders: 0, photos: 0, passkeys: 0 }), "The backup has 0 items.");
  assert.equal(backupContents({ items: 5, codes: 0, folders: 1, photos: 0, passkeys: 1 }), "The backup has 5 items. It also has 1 folder and 1 passkey.");
});

test("a vault that locked to finish the restore says so", () => {
  assert.equal(restoredMessage({ items: 3 }, true), "Restored 3 items from the backup.");
  assert.equal(restoredMessage({ items: 1 }, false), "Restored 1 item from the backup. Unlock Nuvori to finish.");
});
