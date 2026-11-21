// Run with `npm test`. Node strips the TypeScript types of siteIcons.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBuiltinMap, findIcon, glyphColor, hostOf, lookupKeys, needsBorder, relativeLuminance } from "./siteIcons.ts";

test("hostOf accepts urls and bare hosts", () => {
  assert.equal(hostOf("github.com"), "github.com");
  assert.equal(hostOf("https://github.com:443/login?x"), "github.com");
  assert.equal(hostOf("HTTP://User:pw@Accounts.Google.com./a#b"), "accounts.google.com");
  assert.equal(hostOf("github.com/login"), "github.com");
});

test("hostOf rejects hosts that have no icon", () => {
  for (const value of ["192.168.1.1", "http://10.0.0.1:8080/x", "localhost", "https://localhost:3000", "intranet", "android://abc@com.example.app", "", undefined, "[::1]", "ftp://x.com"]) {
    assert.equal(hostOf(value), "", String(value));
  }
});

test("lookupKeys walks the suffixes down to two labels", () => {
  assert.deepEqual(lookupKeys("accounts.google.com"), ["accounts.google.com", "google.com"]);
  assert.deepEqual(lookupKeys("www.bbc.co.uk"), ["www.bbc.co.uk", "bbc.co.uk", "co.uk"]);
  assert.deepEqual(lookupKeys(""), []);
});

test("findIcon picks the registrable domain, never the public suffix", () => {
  const map = new Map([["google.com", "G"], ["bbc.co.uk", "B"]]);
  assert.equal(findIcon(map, "https://accounts.google.com/signin"), "G");
  assert.equal(findIcon(map, "www.bbc.co.uk"), "B");
  assert.equal(findIcon(map, "other.co.uk"), undefined);
  assert.equal(findIcon(map, "192.168.1.1"), undefined);
  assert.equal(findIcon(map, "android://x@google.com"), undefined);
  assert.equal(findIcon(null, "google.com"), undefined);
});

test("luminance and glyph contrast", () => {
  assert.equal(relativeLuminance("FFFFFF"), 1);
  assert.equal(relativeLuminance("#000000"), 0);
  assert.equal(glyphColor("181717"), "#FFFFFF");
  assert.equal(glyphColor("F7DF1E"), "#111111");
  assert.equal(needsBorder("FFFFFF"), true);
  assert.equal(needsBorder("181717"), false);
});

test("buildBuiltinMap maps domains to icons", () => {
  const map = buildBuiltinMap({ icons: [["GitHub", "181717", "M0 0"]], domains: { "github.com": 0, "bad.com": 5 } });
  assert.deepEqual(map.get("github.com"), { title: "GitHub", hex: "181717", path: "M0 0" });
  assert.equal(map.has("bad.com"), false);
});
