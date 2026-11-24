// Run with `npm test`. Node strips the TypeScript types of siteIcons.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { brandKey, buildBrandDomains, buildBuiltinMap, codeSite, findIcon, glyphColor, hostOf, iconHints, lookupKeys, needsBorder, relativeLuminance } from "./siteIcons.ts";

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

test("brandKey and buildBrandDomains match issuer names to a domain", () => {
  assert.equal(brandKey("Amazon Web Services"), "amazonwebservices");
  assert.equal(brandKey(" GitHub "), "github");
  assert.equal(brandKey(undefined), "");
  const brands = buildBrandDomains({ icons: [["GitHub", "181717", "M0 0"], ["Google", "4285F4", "M1 1"]], domains: { "github.com": 0, "github.io": 0, "google.com": 1 } });
  assert.equal(brands.get("github"), "github.com", "the first domain of a brand wins");
  assert.equal(brands.get("google"), "google.com");
});

test("codeSite prefers the linked login, then a host issuer, then one same-title login", () => {
  const code = { id: "c1", type: "AUTHENTICATOR", title: "GitHub", tertiaryValue: "" };
  const linked = { id: "l1", type: "PASSWORD", title: "Work", tertiaryValue: "https://github.example.org", linkedAuthenticatorId: "c1" };
  const sameTitle = { id: "l2", type: "PASSWORD", title: "github", tertiaryValue: "https://github.com/login", linkedAuthenticatorId: "" };
  assert.equal(codeSite(code, [sameTitle, linked, code]), "https://github.example.org");
  assert.equal(codeSite(code, [sameTitle, code]), "https://github.com/login");
  assert.equal(codeSite({ ...code, title: "accounts.example.com" }, []), "accounts.example.com");
  // Two logins named "GitHub" on different hosts: no guess.
  const other = { ...sameTitle, id: "l3", tertiaryValue: "https://gitlab.com" };
  assert.equal(codeSite(code, [sameTitle, other]), undefined);
  assert.equal(codeSite({ ...code, title: "My bank" }, [sameTitle]), undefined);
});

test("iconHints gives logins their website and codes a site and a brand", () => {
  const login = { id: "l", type: "PASSWORD", title: "Mail", tertiaryValue: "mail.example.com" };
  const code = { id: "c", type: "AUTHENTICATOR", title: "Dropbox", tertiaryValue: "" };
  assert.deepEqual(iconHints(login, []), { site: "mail.example.com" });
  assert.deepEqual(iconHints(code, [login]), { site: undefined, brand: "Dropbox" });
  assert.deepEqual(iconHints({ id: "n", type: "CARD", title: "Visa", tertiaryValue: "" }, []), {});
});
