import test from "node:test";
import assert from "node:assert/strict";
import { cardExpiryKind, cardLastFour } from "./cardExpiry.ts";

const now = new Date(2026, 10, 25, 12, 0).getTime(); // 25 November 2026, noon, this PC's time

test("a card is valid to the end of its expiry month", () => {
  assert.equal(cardExpiryKind("11/26", now), "warning");
  assert.equal(cardExpiryKind("10/26", now), "error");
  const lastMoment = new Date(2026, 10, 30, 23, 59, 59, 999).getTime();
  assert.equal(cardExpiryKind("11/26", lastMoment), "warning");
  assert.equal(cardExpiryKind("11/26", lastMoment + 1), "error");
});

test("cards expiring within 90 days are warnings, as on Android", () => {
  assert.equal(cardExpiryKind("12/26", now), "warning");
  assert.equal(cardExpiryKind("1/27", now), "warning");
  assert.equal(cardExpiryKind("02/27", now), null); // ends 28 February, 95 days away
  assert.equal(cardExpiryKind("03/27", now), null);
  const ninetyDaysBefore = new Date(2027, 1, 28, 23, 59, 59, 999).getTime() - 90 * 86_400_000;
  assert.equal(cardExpiryKind("02/27", ninetyDaysBefore), "warning");
  assert.equal(cardExpiryKind("02/27", ninetyDaysBefore - 1), null);
});

test("the expiry reads as Android reads it", () => {
  assert.equal(cardExpiryKind(" 12-26 ", now), "warning");
  assert.equal(cardExpiryKind("12 26", now), "warning");
  assert.equal(cardExpiryKind("12/2026", now), "warning");
  assert.equal(cardExpiryKind("8/2029", now), null);
  assert.equal(cardExpiryKind("08/29", now), null);
  assert.equal(cardExpiryKind("12/99", now), null);
  assert.equal(cardExpiryKind("12/1999", now), "error");
  for (const unreadable of ["", "0829", "13/26", "0/26", "Dec/26", "12/", "12//26", "1.5/26", "12/26x"]) {
    assert.equal(cardExpiryKind(unreadable, now), null, unreadable);
  }
});

test("a card shows its last four digits", () => {
  assert.equal(cardLastFour("4111 1111 1111 1234"), "1234");
  assert.equal(cardLastFour("378282246310005"), "0005");
  assert.equal(cardLastFour(""), "");
});
