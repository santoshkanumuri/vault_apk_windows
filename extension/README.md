# Nuvori browser extension

Manifest V3 extension for Chrome, Brave and Edge (Chromium 127+). It fills and saves logins held by Nuvori for Windows through the native messaging host `com.nuvori.desktop` (protocol version 2). The extension never receives the master password, the vault key, or the vault. It only gets account metadata for the exact HTTPS origin, plus one selected login after you choose it.

## What it does

- **Suggestions in the page.** Focus a sign-in field and a small Nuvori list opens under it with the saved logins for this exact origin (title and username). Pick one with the mouse, or with ↓ then Enter, and Nuvori fills the username and password. It never submits the form. Esc closes the list and keeps your cursor in the field. Click the field or press ↓ to reopen it. If the vault is locked or Windows can't be reached, the list says so. A site with no saved login gets no list on focus; click the field or press ↓ to see that state. Every list has **Don't suggest on this site**.
- **Two-step sign-ins.** Many sites ask for the account name on one page and the password or a code on the next. Nuvori remembers the account name used in the tab (filled from the list, or typed and submitted on the first page) for that site for 10 minutes, in memory only. On the next page that login is first in the list with a **Continue** tag, its authenticator code is first among the codes, and a password page with no account field is saved under that name (the save card still lets you correct it).
- **Cards, addresses and authenticator codes.** The same list appears on other forms, with a label that says what it holds:
  - **Cards** on payment forms (card number, name, expiry as one field or month/year drop-downs, split number boxes). Number, name and expiry fill with one click. When the form has a security-code field and the card has a saved code, Nuvori opens a small **Fill security code?** window. The code fills only after Windows Hello or the master password. Declining or waiting 2 minutes leaves the field empty.
  - **Addresses** on address and contact forms (name or first/last name, email, phone, street, flat or unit, city, state, postal code, country), from the app's contact profiles. A lone email box (a newsletter, say) gets nothing.
  - **Authenticator codes** on two-step sign-in fields (`one-time-code`, names such as `otp` or `totp`, labels such as "code from your authenticator app", and rows of 4 to 8 single-digit boxes). Codes whose service names the site, or whose account is a login saved for it, come first; **Show all codes** lists the rest. A code field without authenticator wording (often an SMS code) shows the list only when something matches. The extension gets the current code, never the setup key.
  - Detection reads `autocomplete`, the field's name, id, placeholder, `aria-label` and label text.
  - **Forms inside frames** (many hosted payment forms): the script in the frame draws nothing. It reports the focused card, address or code field, and the list opens on the top page next to that frame. The chosen item goes only to that frame; a card also goes to other frames of the same origin, so split number and expiry frames both fill. A card's security code is not filled in a frame. Logins are never filled in a frame.
- **Save and update prompts.** After you submit a sign-in form, a card in the top-right offers **Save** (new account) or **Update** (same username, different password). If the login is already saved, a brief "Already saved" card appears instead. The save card lets you correct the username before saving ("login_edit"). After a payment or address form is submitted, a similar card offers **Save this card** or **Save this address**, with an editable name. A card is saved without its security code. It needs a Luhn-valid number; an address needs a street plus a city or postal code. If Nuvori is locked, Save opens its unlock window and the card waits. The password is always masked. If the vault is locked, Save keeps the login encrypted and finishes after you unlock. The card comes back on the next page of the same site in the same tab for 2 minutes, because most sign-ins navigate away. **Never for this site** stops save prompts there.
- **Unlock when the browser starts.** When the browser starts and Nuvori is locked or not running, the extension asks Nuvori to show its small **Unlock Nuvori** window. If Nuvori isn't running, the native host starts it in the background first. You type the master password (or use Windows Hello) in that Nuvori window, never in the browser. Nuvori then stays in the Windows tray, so filling keeps working after you close its windows. Turn this off in Settings ("Ask to unlock when the browser starts"). The popup's **Unlock Nuvori** button and the in-page **Unlock Nuvori** / **Start Nuvori** buttons do the same on demand.
- **Popup.** Shows a connection chip (Connected · Unlocked / Locked / Not connected / Checking…) with setup steps when needed. It has three tabs:
  - **This site:** Fill, copy username, copy password, "Save this page's login", and **Authenticator codes** for the site with **Copy code**.
  - **Pending:** encrypted logins waiting for Save, Update or Discard.
  - **Settings:** theme, in-page suggestions on/off, ask to unlock when the browser starts, cards, addresses and codes on/off, offer to save cards and addresses, "Never save" and "Don't suggest" site lists, and diagnostics (last 20 events: action, status, site host and time only), with a connection test.
- **Badge.** Green number: saved logins for this site. Amber `!`: a capture needs review. Amber `L`: locked. Empty: not connected.
- **Use Nuvori instead of the browser's password manager** (Settings, off by default).
  - Turning it on asks for the optional `privacy` permission at that moment, so installing Nuvori shows no extra warning.
  - It then sets `chrome.privacy.services.passwordSavingEnabled` to `false`, so the browser stops offering "Save password?". A second switch also turns off address and card autofill (`autofillAddressEnabled`, `autofillCreditCardEnabled`).
  - Before changing anything, Nuvori reads each setting's `levelOfControl`. If policy (`not_controllable`) or another extension (`controlled_by_other_extensions`) controls it, the popup says so and changes nothing.
  - The header shows "Browser saving: off (Nuvori)" while Nuvori controls the setting. Each change is logged in diagnostics, with no secrets.
  - Turning the switch off clears Nuvori's value, which gives the setting back to the browser. The permission is kept, so the next turn-on doesn't prompt again.
  - There is no uninstall hook. The browser itself returns these settings to their previous state when the extension is removed or disabled, because extension-controlled settings don't outlive the extension.
  - **Limit:** passwords already saved in the browser still appear in the browser's own suggestions, and extensions can't hide them. To stop them, export the passwords from `chrome://password-manager/settings` (Brave: `brave://password-manager/settings`, Edge: `edge://wallet/passwords`). Import the file into Nuvori on your phone, delete the file, then delete the passwords from the browser. The popup opens that page directly only on Chrome; elsewhere it shows the address to paste.

## Security model

- **Origins come from the browser.** The background worker takes the site origin from `sender.url` (frame 0, HTTPS only, and `sender.origin` must agree), never from a message. Subframes, HTTP pages and extension pages can't use the page actions.
- **Tokens stay in the background.** The one-use selection tokens from `query_credentials` stay in the service worker. The page gets `{ id, title, username }` only. Results are cached per tab and origin for about 12 seconds (about 4 seconds for locked or offline) so focusing fields doesn't hammer the host. An expired token is refreshed once for the same account. The password goes back only to the requesting tab's frame 0, and only if that tab still shows the same origin. Filling only a username never returns the password.
- **Page scripts can't act for you.** The page can't message the extension, and every Nuvori control lives in a closed shadow root. An action needs all of the following:
  - a trusted event (`isTrusted`);
  - UI visible for at least 400 ms without moving or being restyled;
  - a fresh IntersectionObserver v2 report that the UI is fully visible. Without one, nothing activates; there is no fallback.
  - a hit test that finds Nuvori's UI: at the pointer for mouse clicks, at the control's center for keyboard use.

  Focus moving into the list or onto a card button starts a new 400 ms delay for keyboard activation. Only Enter chooses an account, never Space. Any other popover or dialog opening or closing (`beforetoggle`/`toggle`, a dialog's `open` attribute) and any fullscreen change reset the delay and wait for a new visibility report. The host element uses inline `all: initial` and `!important` styles, a MutationObserver puts them back if the page changes them, and it sits in the top layer (`popover="manual"`). New buttons, such as Update after an expired approval, start a new delay.
- **Named elements can't trick the script.** Pages can override `document` and form properties with named elements, such as `<img name="elementFromPoint">` or `<form name="body">`. The content script therefore copies the real methods and getters from the DOM prototypes when it starts (`elementFromPoint`, `documentElement`, `body`, `activeElement`, `visibilityState`, `querySelector(All)`, `createElement`, `addEventListener`, and others) and always calls them with `.call`.
- **Only visible fields are filled.** Nuvori fills enabled, same-document fields in the top frame. A field must not be hidden by `display`, `visibility` or near-zero opacity (including ancestors). It must be on screen and pass a hit test; an off-screen field is scrolled into view (`block: "nearest"`) and tested again. If no visible field remains, no password is requested. The value is set through the native setter, followed by `input` and `change` events, so React and Vue forms update. The password variable is cleared after filling.
- **The page can only touch its own prompt.** The pending prompt is bound to tab + origin. `inline_approve` acts only on that tab's item, only from that origin, only within 2 minutes, and only for a decision that fits the item's state:
  - Save and Never: new accounts only;
  - Update: a reviewed replacement only;
  - Not now: either.

  Queue management (`update_pending`, `approve_pending`, `remove_pending`, `queue_login`, …) still needs the popup.
- **Captures need a real gesture, and few are allowed.** A page can submit a form from script (`form.requestSubmit()`), and that submit event is trusted. Each capture path (submit, a sign-in button outside a form, and Enter) therefore also needs live user activation (`navigator.userActivation.isActive`). Each key press or click allows at most one capture. The background then allows one capture per tab every 5 seconds and four per site per minute, before any host call. This keeps a page from using Save / Update / Already saved as a way to test usernames and passwords. A page can still learn one outcome per real user gesture, by watching whether a card appears and how big it is.
- **Passwords are never stored in plain text, and unapproved captures never touch disk.** Captures are sealed by the native host (`seal_login`, DPAPI) before anything is stored. A capture you haven't answered lives only in `chrome.storage.session` (memory, not readable by content scripts) and expires with its 2-minute prompt. `chrome.storage.local` holds only logins you approved: Save or Update while the vault is locked or offline, or the popup's manual save. Unapproved items left in local storage by older versions are dropped. One site can hold at most 3 unanswered captures and 5 approved waiting logins (20 in total), so it can't crowd out other sites. The username shown on the card is in session storage too. New captures never save without approval. Password replacements use single-use update tokens and are never retried automatically: a stale approval goes back for review. An Update chosen while locked is kept without its token, and the popup reviews it again before replacing.
- **Diagnostics hold no secrets.** They record action, status, site host and time only. No usernames, titles, passwords or tokens.
- **Clipboard clearing is best effort.** Copy password writes to the clipboard. About 30 seconds later an offscreen document overwrites the clipboard. That clear doesn't happen if the browser closes first, so the popup doesn't promise it.

Field detection follows the Android app's form classifier (`fields.js`):

- autocomplete tokens are case-insensitive, and section, shipping, billing and webauthn qualifiers are ignored;
- hidden and `cc-*` fields never count;
- with several credential forms, the focused one wins;
- it recognizes sign-in, registration, current+new and change shapes;
- ambiguous password pairs are skipped;
- a lone password uses the preceding plain input as its username;
- one-time-code screens get no login suggestions.

## Native protocol (version 2)

- `status` reports `ok`, `locked` or `desktop_unavailable`. Newer hosts also list `features`. The background caches the list for 5 minutes and refreshes it on every status ping. Older hosts reject unknown request fields, so the extension sends a new field only when its feature is listed:
  - `status_no_origin`: status pings send `origin: ""`. Older hosts get the reserved `https://status.nuvori.invalid`.
  - `login_title`: the save card and the popup's save review show an editable **Name**.
    - It is prefilled with the site's declared name (`og:site_name`, used only as a hint) or its host, and the card always shows the real host next to it.
    - It goes to the host as `title`: on `commit_login` for in-page saves, or on `seal_login` for the popup's manual save.
    - Control characters and Unicode format characters (zero-width, bidi overrides such as U+202E) are removed, and the length is capped at 256 characters. Titles never appear in diagnostics.
    - The page can't read the field's value, but keys typed into it pass through the page's capture-phase key listeners. A name isn't a secret, so that's acceptable; don't type secrets there.
  - `password_only`: a sign-in form with no account field can be saved with an empty username. The card shows "No username". A numeric PIN, or a change or sign-up form with no account field, is still never captured.
  - `multi_update`: when several saved accounts match, the card and the Pending tab list them (title and username), and Update stays disabled until you pick one. Each choice carries its own one-use token, which stays in the background.
  - `unlock_prompt`: the extension may send `unlock_prompt` (empty origin, no other fields). A running app shows its unlock window if the vault is locked and answers `locked` or `ok`. When the app isn't reachable, the host starts the installed `nuvori.exe --background`, which opens only the unlock window, and answers `starting`. The host lists this feature even when the app is unreachable.
  - `cards`, `profiles`, `codes`: `query_items` with `kind` (`card`, `profile` or `code`; codes may add `all: true`) lists `{ id, title, username, selectionToken }`, where `username` is a display line such as "Visa · •••• 1111". `fill_item` with `kind`, `credentialId` and the one-use token returns `item`. A card never includes its security code; it carries a one-use `cvvToken` instead. `request_cvv` opens the approval window and answers `pending`. `fill_cvv` answers `pending`, `denied`, `selection_expired`, or `ok` with only the code. Tokens are bound to their kind, so a card token can't release a login.
  - `save_details`: `seal_details` (the host encrypts a captured `card` or `profile` with DPAPI, never with a security code), `review_details` (`needs_save` or `already_saved`) and `commit_details` (an optional `title`) save a new card or address. They never change an existing item.
  - `login_edit`: `commit_login` may carry a corrected `username`.
- `query_credentials` returns `{ id, title, username, selectionToken }` for the exact origin.
- `fill_credential` takes `credentialId` and a one-use `selectionToken`. It returns the selected `{ id, username, password }`, or `selection_expired`.
- `seal_login` encrypts a login for the origin in the native host, without needing the app.
- `review_login` checks a sealed login without changing the vault. It returns `needs_save`, `already_saved`, or `account_exists`; `account_exists` comes with update tokens: one per matching account with `multi_update`, otherwise only when exactly one matches.
- `commit_login` saves a new account. It never replaces a password.
- `update_login` replaces a password. It needs the update token bound to the account, the origin and the saved-password fingerprint.

Permissions: `nativeMessaging`, `storage`, `alarms`, `scripting` (the popup's fill and manual review), `clipboardWrite` and `offscreen` (copy and best-effort clear), plus HTTPS host access. `privacy` is optional and asked for only when you turn on "Use Nuvori instead of the browser's password manager". `activeTab` isn't needed, because the HTTPS host permission already covers the active tab. Without it the popup can't read a non-HTTPS tab's URL, which it never uses.

## Install from the Chrome Web Store

Install **Nuvori Password Fill** (item ID `lpohaakdindhljdhpofnfmggbfllgdil`) from the Chrome Web Store in Chrome or Brave. In Edge, first allow extensions from other stores. Nuvori for Windows 2.2.1 or later trusts this ID. See [publishing](../docs/CHROME-WEB-STORE.md).

## Load for local development

1. Open `chrome://extensions` or `brave://extensions` and enable Developer mode.
2. Choose **Load unpacked** and select this `extension` directory. The `key` in `manifest.json` fixes the extension ID to `kapellkbongejlglcengbmjnpblemmjm` in every folder.
3. An installed Nuvori (2.1.8 or later) registers the native host for Chrome, Edge and Brave when it starts, or from **Settings > Browser extension > Connect**. It allows the fixed ID, the store ID (from 2.2.1) and any ID registered earlier. A development build does not register itself; run `browser-host/register-native-host.ps1 -HostExecutable .\src-tauri\target\release\nuvori-native-host.exe` (Chrome and Brave).
4. Open and unlock Nuvori for Windows, then visit an HTTPS sign-in page.

After updating, reload the extension and refresh open pages so the new content script runs. Saved logins match only when their **Website URL** has the same HTTPS origin as the tab, including subdomain and port.

## Passkeys

The extension doesn't intercept WebAuthn. Sites keep using the browser's or the operating system's passkey provider. Any future support must sign only after a click in Nuvori. It must validate the origin and RP ID on Windows and bind a one-use approval to the credential, origin, RP ID and challenge.

## Checks

`npm test` runs the extension tests: background message handlers, field classification, the content script with a fake DOM, and the popup. Run `npm run build` and `cargo test --manifest-path src-tauri/Cargo.toml` from the project root for the app.
