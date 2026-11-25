# End-to-end tests for the browser extension

These tests drive the real extension in a real browser, on real websites and on local pages, against a **fake native host** that stands in for Nuvori for Windows. Your own vault is never used, and no test data reaches it or your other devices.

## What runs

| Part | File | What it does |
| --- | --- | --- |
| Fake native host | `fake-host/host.mjs` | Answers protocol 2 like the native host plus the app: matching, save, update, cards with a CVV approval, addresses, TOTP codes, locked and offline states. It keeps its state in `.state/vault.json` and logs each request's shape to `.state/host-log.jsonl`, never a password. |
| Setup | `setup.mjs` | Seeds the test vault and registers the fake host under `HKCU\Software\Chromium\NativeMessagingHosts` only. Chrome, Edge and Brave don't read that key. `--remove` deletes it. |
| Local pages | `fixtures/server.mjs` | HTTPS pages on `https://localhost:8443` and `https://127.0.0.1:8444`: a cross-site sign-in frame, honeypots, a change-password form, an SPA sign-in, a PIN, a checkout, 6 code boxes and a newsletter box. |
| Chrome suite | `run.mjs` | 37 scenarios: logins, saving and updating, cards, addresses, codes, the popup's card and address fill, and the locked and not-running states. |
| Sign-in methods | `signins.mjs` | 5 scenarios on synthetic local pages: Google's GIS button popup, a popup that closes by itself, GIS redirect mode, a Microsoft popup with a single-page step, and a Firebase-style broker popup; also typing into the "Remember…?" card (the page sees no key) and one-click Save. The browser maps `accounts.google.com`, `login.microsoftonline.com` and `*.nuvori-e2e.test` to a local server (`--host-resolver-rules`), so nothing real is contacted. Its certificate needs those names: add `DNS:accounts.google.com,DNS:login.microsoftonline.com,DNS:*.nuvori-e2e.test` to the `subjectAltName` below. `NUVORI_EXTENSION` runs it against another unpacked copy. |
| Firefox smoke | `firefox-smoke.mjs` | Installs the Firefox package as a temporary add-on in Playwright's Firefox, registers the fake host under `HKCU\Software\Mozilla\NativeMessagingHosts`, and checks the Firefox behaviour. It removes the key afterwards. |
| Host check | `tools/host-caller-check.cjs` | Runs the real `nuvori-native-host.exe` against a throwaway `LOCALAPPDATA` and checks which Chrome and Firefox callers it accepts. |

Nuvori draws its list and cards in a closed shadow root. The Chrome driver (`lib/driver.mjs`) reads them through the DevTools protocol and clicks real mouse coordinates, so the extension's own guards stay on: a trusted event, the 400 ms delay, IntersectionObserver v2 and the hit test.

## Run

From this folder:

```powershell
npm install
openssl req -x509 -newkey rsa:2048 -nodes -keyout .state/key.pem -out .state/cert.pem -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
node run.mjs                 # all Chrome scenarios
node run.mjs L8 card         # scenarios whose id or title matches
$env:HEADED=1; node run.mjs  # watch it

# Firefox: build and unpack the package first
..\..\scripts\package-extension.ps1 -Firefox -Destination $env:TEMP\nuvori-ff
Expand-Archive $env:TEMP\nuvori-ff\Nuvori_extension_*_firefox.zip .state\ff-src -Force
npx playwright install firefox
node firefox-smoke.mjs .state\ff-src

# Native host caller check (after cargo build --bin nuvori-native-host)
node tools\host-caller-check.cjs ..\..\src-tauri\target\debug\nuvori-native-host.exe
```

The Chrome suite uses Playwright's Chromium. Set `NUVORI_CHROMIUM` to point at another Chromium build. Branded Chrome no longer loads unpacked extensions from the command line.

Results go to `.state/results.json`, and screenshots of failures to `.state/shots/`. The real sites can change their pages; a failure there is a lead to check, not proof of a bug.
