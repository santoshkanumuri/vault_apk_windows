// Prepares the fake native host for Playwright's Chromium only:
//   node setup.mjs          seed the test vault, write the host launcher + manifest, register it
//   node setup.mjs --remove remove the registry entry (leaves Chrome, Edge and Brave untouched)
// The key is HKCU\Software\Chromium\NativeMessagingHosts, which branded Chrome, Edge and Brave never read.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const HOST_NAME = "com.nuvori.desktop";
const KEY = `HKCU\\Software\\Chromium\\NativeMessagingHosts\\${HOST_NAME}`;
const EXTENSION_ID = "kapellkbongejlglcengbmjnpblemmjm"; // fixed by the manifest "key"
export const STATE_DIR = path.join(here, ".state");

export function seedVault(overrides = {}) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const vault = [
    // Real public test logins (published on the sites themselves).
    { id: "login-herokuapp", type: "PASSWORD", title: "The Internet (test)", username: "tomsmith", password: "SuperSecretPassword!", url: "https://the-internet.herokuapp.com" },
    { id: "login-practice", type: "PASSWORD", title: "Practice Test Automation", username: "student", password: "Password123", url: "https://practicetestautomation.com" },
    // Fake accounts for detection-only sites (never submitted anywhere real).
    { id: "login-google", type: "PASSWORD", title: "Google", username: "nuvori.e2e.test@gmail.com", password: "not-a-real-password-1", url: "https://accounts.google.com" },
    { id: "login-github-1", type: "PASSWORD", title: "GitHub work", username: "dev@example.com", password: "gh-work-pass-1", url: "https://github.com" },
    { id: "login-github-2", type: "PASSWORD", title: "GitHub personal", username: "octo-personal", password: "gh-personal-pass-2", url: "https://github.com" },
    { id: "login-roboform", type: "PASSWORD", title: "RoboForm test", username: "rf.tester@example.com", password: "rf-test-pass-9", url: "https://www.roboform.com" },
    { id: "login-fakefiller", type: "PASSWORD", title: "Fake Filler test", username: "ff.tester", password: "ff-test-pass-7", url: "https://fakefiller.com" },
    { id: "login-autofillme", type: "PASSWORD", title: "autofill.me test", username: "am.tester@example.com", password: "am-test-pass-3", url: "https://autofill.me" },
    { id: "login-local-a", type: "PASSWORD", title: "Local app", username: "alice@example.com", password: "local-alice-1", url: "https://localhost:8443" },
    { id: "login-local-b", type: "PASSWORD", title: "Local app (bob)", username: "bob", password: "local-bob-2", url: "https://localhost:8443" },
    { id: "login-frame", type: "PASSWORD", title: "Frame site", username: "frame.user@example.com", password: "frame-pass-5", url: "https://127.0.0.1:8444" },
    { id: "login-microsoft", type: "PASSWORD", title: "Microsoft", username: "nuvori.e2e.test@outlook.com", password: "not-a-real-password-2", url: "https://login.live.com" },
    { id: "card-visa", type: "CARD", title: "Everyday Visa", number: "4111111111111111", name: "Alex Tester", expiry: "12/29", cvv: "123", network: "Visa", color: 0xff2e7034 },
    { id: "card-mc", type: "CARD", title: "Travel Mastercard", number: "5555555555554444", name: "Alex Tester", expiry: "08/28", cvv: "456", network: "Mastercard", color: 0xff244a77 },
    { id: "profile-home", type: "AUTOFILL", title: "Home", profile: { name: "Alex Tester", email: "alex.tester@example.com", phone: "+1 415 555 0134",
      address1: "1 Market St", address2: "", unit: "Apt 5", city: "San Francisco", state: "CA", postalCode: "94105", country: "United States" } },
    { id: "code-github", type: "AUTHENTICATOR", title: "GitHub", account: "dev@example.com", secret: "JBSWY3DPEHPK3PXP" },
    { id: "code-google", type: "AUTHENTICATOR", title: "Google", account: "nuvori.e2e.test@gmail.com", secret: "GEZDGNBVGY3TQOJQ" },
    { id: "code-local", type: "AUTHENTICATOR", title: "Local app", account: "alice@example.com", secret: "KRSXG5CTMVRXEZLU" },
    { id: "code-aws", type: "AUTHENTICATOR", title: "AWS root", account: "root", secret: "MFRGGZDFMZTWQ2LK" },
  ];
  const state = { locked: false, offline: false, autoUnlockOnPrompt: false, cvvDecision: "approve",
    appearance: { accent: "green", surface: "sage" }, vault, grants: {}, fills: [], events: [], ...overrides };
  fs.writeFileSync(path.join(STATE_DIR, "vault.json"), JSON.stringify(state, null, 2));
  fs.writeFileSync(path.join(STATE_DIR, "host-log.jsonl"), "");
  try { fs.rmdirSync(path.join(STATE_DIR, "lock")); } catch {}
}

export function register() {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const launcher = path.join(STATE_DIR, "host.bat");
  const script = path.join(here, "fake-host", "host.mjs");
  fs.writeFileSync(launcher, `@echo off\r\n"${process.execPath}" "${script}" %*\r\n`);
  const manifest = path.join(STATE_DIR, `${HOST_NAME}.json`);
  fs.writeFileSync(manifest, JSON.stringify({ name: HOST_NAME, description: "Nuvori fake host (e2e)", path: launcher, type: "stdio",
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`] }, null, 2));
  execFileSync("reg", ["add", KEY, "/ve", "/t", "REG_SZ", "/d", manifest, "/f"], { stdio: "ignore" });
}

export function unregister() {
  try { execFileSync("reg", ["delete", KEY, "/f"], { stdio: "ignore" }); } catch { /* already gone */ }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--remove")) { unregister(); console.log("removed", KEY); }
  else { seedVault(); register(); console.log("registered", KEY); }
}
