// Run with `npm test`. Node strips the TypeScript types of startFresh.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { lastUsedText, lockedView, startFreshConfirmed, START_FRESH_WORD } from "./startFresh.ts";

test("only the exact word RESET confirms starting fresh", () => {
  assert.equal(START_FRESH_WORD, "RESET");
  assert.equal(startFreshConfirmed("RESET"), true);
  for (const typed of ["", "reset", "Reset", " RESET", "RESET ", "RESE", "RESET!"]) {
    assert.equal(startFreshConfirmed(typed), false, JSON.stringify(typed));
  }
});

test("a vault from an earlier install opens on Welcome back, the plain unlock otherwise", () => {
  const earlier = { vaultState: "locked", welcomeBack: true };
  assert.equal(lockedView(earlier, ""), "welcome");
  assert.equal(lockedView(earlier, "unlock"), "unlock", "Unlock it");
  assert.equal(lockedView(earlier, "choices"), "choices");
  const same = { vaultState: "locked", welcomeBack: false };
  assert.equal(lockedView(same, ""), "unlock");
  assert.equal(lockedView(same, "choices"), "choices", "Forgot the password or starting over?");
  assert.equal(lockedView({ vaultState: "locked" }, ""), "unlock", "an older backend without the field");
  // After "Start fresh" the vault is gone, whatever was picked: set up a new one.
  assert.equal(lockedView({ vaultState: "notConfigured", welcomeBack: false }, "choices"), "create");
  assert.equal(lockedView({ vaultState: "notConfigured", welcomeBack: true }, ""), "create");
});

test("the last-used line reads a file time as plain words", () => {
  const now = Date.UTC(2026, 10, 24, 12, 0, 0);
  const hour = 3_600_000;
  assert.equal(lastUsedText(now - 10_000, now), "Last used just now");
  assert.equal(lastUsedText(now - 3 * hour, now), "Last used 3 h ago");
  assert.equal(lastUsedText(now - 26 * hour, now), "Last used yesterday");
  assert.equal(lastUsedText(now - 4 * 24 * hour, now), "Last used 4 days ago");
  assert.match(lastUsedText(Date.UTC(2025, 2, 12, 12), now), /^Last used on .*2025/);
  assert.equal(lastUsedText(0, now), "");
  assert.equal(lastUsedText(undefined, now), "");
});
