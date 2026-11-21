// Run with `npm test`. Node strips the TypeScript types of autoType.ts on load.
import { test } from "node:test";
import assert from "node:assert/strict";
import { rankForWindow, siteName, siteWords, windowScore } from "./autoType.ts";

const login = (title, url = "", id = title) => ({ id, type: "PASSWORD", title, tertiaryValue: url });

test("the site name is the label before the top-level domain", () => {
  assert.equal(siteName("https://www.skechers.com/login/"), "skechers");
  assert.equal(siteName("account.activedirectory.windowsazure.com"), "windowsazure");
  assert.equal(siteName("https://www.bbc.co.uk/signin"), "bbc");
  assert.equal(siteName("https://my.abc.com.au"), "abc");
  assert.equal(siteName("192.168.1.1"), "");
  assert.equal(siteName(""), "");
});

test("site words leave out generic labels like account and login", () => {
  assert.deepEqual(siteWords("https://accounts.google.com/signin"), ["google"]);
  assert.deepEqual(siteWords("https://www.github.com/login"), ["github"]);
  assert.deepEqual(siteWords("vpn.example.co"), ["example", "vpn"]);
  assert.deepEqual(siteWords("https://outlook.office.com/mail"), ["office", "outlook"]);
  assert.deepEqual(siteWords("account.lenovo.com"), ["lenovo"]);
  assert.deepEqual(siteWords(""), []);
});

test("a login matches by its title, its website, or the app's name", () => {
  assert.equal(windowScore(login("Microsoft Teams"), "Sign in to your account | Microsoft Teams", "ms-teams.exe"), 3);
  assert.equal(windowScore(login("Work", "https://github.com"), "GitHub Desktop", "GitHubDesktop.exe"), 2);
  assert.equal(windowScore(login("Mail", "https://outlook.office.com"), "Outlook", "olk.exe"), 1);
  assert.equal(windowScore(login("Steam account"), "Sign in", "steam.exe"), 1);
  assert.equal(windowScore(login("Bank", "https://bank.example"), "Notepad", "notepad.exe"), 0);
  assert.equal(windowScore({ id: "c", type: "CARD", title: "Notepad" }, "Notepad", "notepad.exe"), 0, "only logins are typed");
  // Two letters are too short to count as a title match.
  assert.equal(windowScore(login("Go"), "Google Chrome", "chrome.exe"), 0);
});

test("generic words and the browser's name never make a match", () => {
  const skechers = "Log in or Create Your Skechers Plus Account - Brave";
  // These all fit before: "account" was matched as part of the title.
  for (const url of ["account.activedirectory.windowsazure.com", "account.bcbstx.com", "account.humana.com", "account.jetbrains.com", "account.lenovo.com"]) {
    assert.equal(windowScore(login(url, url), skechers, "brave.exe"), 0, url);
  }
  assert.equal(windowScore(login("Account"), skechers, "brave.exe"), 0, "one generic word is not a name");
  assert.equal(windowScore(login("Brave sync", "https://brave.com"), skechers, "brave.exe"), 0, "the browser suffix is not the page");
  // A word inside another word is not a match: "plus" is not in "Skechers Plus" as a site.
  assert.equal(windowScore(login("Google", "https://plusnet.com"), skechers, "brave.exe"), 0);
});

test("the right login is first for the Skechers sign-in window", () => {
  const entries = [
    login("account.activedirectory.windowsazure.com", "account.activedirectory.windowsazure.com"),
    login("account.jetbrains.com", "account.jetbrains.com"),
    login("skechers.com", "https://www.skechers.com/login/"),
    login("Bank", "https://bank.example"),
  ];
  const ranked = rankForWindow(entries, "Log in or Create Your Skechers Plus Account - Brave", "brave.exe");
  assert.deepEqual(ranked.filter((item) => item.score > 0).map((item) => item.entry.title), ["skechers.com"]);
  assert.equal(ranked[0].entry.title, "skechers.com");
});

test("ranking puts matches first and keeps every login available", () => {
  const ranked = rankForWindow([login("Bank"), login("Zoom", "https://zoom.us"), login("Mail", "https://mail.example.org"), { id: "c", type: "CARD", title: "Zoom card" }],
    "Zoom Workplace - Sign in", "Zoom.exe");
  assert.deepEqual(ranked.map((item) => [item.entry.title, item.score]), [["Zoom", 3], ["Bank", 0], ["Mail", 0]]);
});
