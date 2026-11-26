// Run with `npm test`. Node strips the TypeScript types of helloWindow.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { capInterval, confirmsFirst, DAY_MS, helloLockScreen, MASTER_PASSWORD_INTERVALS, WEEK_MS } from "./helloWindow.ts";

test("the choices match Android and hello_window.rs", () => {
  assert.deepEqual([...MASTER_PASSWORD_INTERVALS], [0, 86_400_000, 604_800_000]);
});

test("the lock screen offers Windows Hello only inside the window", () => {
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: "ready" }, true), { button: true, notice: "" });
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: "password" }, true), { button: false, notice: "password" });
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: "everyUnlock" }, true), { button: false, notice: "everyUnlock" });
  // Off, or Windows Hello not working on this PC now: nothing to explain.
  assert.deepEqual(helloLockScreen({ helloEnabled: false, helloUnlock: "off" }, true), { button: false, notice: "" });
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: "ready" }, false), { button: false, notice: "" });
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: "password" }, false), { button: false, notice: "" });
  // A state this build doesn't know never shows the button.
  assert.deepEqual(helloLockScreen({ helloEnabled: true, helloUnlock: /** @type {any} */ ("later") }, true), { button: false, notice: "" });
  // An older backend without the field: as before.
  assert.deepEqual(helloLockScreen({ helloEnabled: true }, true), { button: true, notice: "" });
});

test("values outside the three choices are capped like Android", () => {
  assert.equal(capInterval(0), 0);
  assert.equal(capInterval(DAY_MS), DAY_MS);
  assert.equal(capInterval(WEEK_MS), WEEK_MS);
  assert.equal(capInterval(2_592_000_000), WEEK_MS);
  assert.equal(capInterval(3_600_000), DAY_MS);
  assert.equal(capInterval(-1), 0);
  assert.equal(capInterval(null), DAY_MS);
  assert.equal(capInterval(undefined), DAY_MS);
  assert.equal(capInterval(Number.NaN), DAY_MS);
});

test("only moving to 1 week asks first", () => {
  assert.equal(confirmsFirst(DAY_MS, WEEK_MS), true);
  assert.equal(confirmsFirst(0, WEEK_MS), true);
  assert.equal(confirmsFirst(WEEK_MS, WEEK_MS), false);
  assert.equal(confirmsFirst(WEEK_MS, DAY_MS), false);
  assert.equal(confirmsFirst(DAY_MS, 0), false);
  assert.equal(confirmsFirst(WEEK_MS, 0), false);
});
