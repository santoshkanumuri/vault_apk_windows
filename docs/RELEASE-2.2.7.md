# Nuvori 2.2.7

Windows version 2.2.7. Browser extension version 0.7.6. Pairs with Android 2.2.7 (version code 65). Windows 2.2.5 and 2.2.6 were not published (2.2.6 was a preview build): this release takes the phone's version number so both match.

## Browser extension 0.7.6: fills where the browser's own password manager fills

- **Sign-in boxes inside frames.** Many sites put the login form in a frame (seedr.cc's **Login** box, say). The list now opens next to the field, as on any other page. Logins are matched to the frame's own site, like the browser's password manager does. The login goes only into that frame, never to the page around it.
- **Frames inside frames, and frames a page builds by script** (`about:blank`, `srcdoc`) work too.
- **Saving from a frame.** A login you submit inside a frame is saved for the frame's site. The save card shows on the page.
- **Web-component forms.** A username and a password in different shadow roots (one custom element per field) fill together.
- **Search all logins.** Every list has **Search all logins**. A site with no saved login offers it too: click the field again, or press Down. Type to find any login by name, account or site. A login saved for this site fills at once. One saved for another site asks first: "Nuvori saved this login for seedr.cc. Fill it on example.com?" Nothing in the vault changes.
- **Fixed: cards and codes inside frames.** Since extension 0.6, payment frames reported their field, but the page could not find the frame. The `chrome.runtime.getFrameId` call it used does not exist in content scripts in current Edge. A frame now names itself to its parent window with a one-time code instead.
- **Address rows show what they fill.** Like the browser's own Autofill, each address shows the value the focused field receives ("alice@example.com" in an email field, "78701" in a ZIP field), with the address's name and two more of its values below. This works in frames too. With an older desktop app, rows show the name and summary as before.
- **Email boxes in address forms.** An email box can also be the first step of a sign-in. When no login is saved for the site, it now offers your addresses instead of nothing.
- **Fixed:** "Show all codes" no longer shows on login lists.
- Card suggestions show each card in its own color, with a chip and its last four digits (from 0.7.4 and 0.7.5, which were not released).
- Needs Nuvori for Windows 2.2.7 for **Search all logins**. With an older desktop app, the search says to update; everything else works.

## Desktop app: every login for the browser

- New browser feature `all_logins`. The extension may list every login (`query_credentials` with `all`), with the site each one is saved for.
- A login chosen from that list fills only on the page it was listed for, once, within 30 seconds. Its token can never update a login. Matched listings keep releasing only matching logins.
- Address listings (`query_items` for profiles) now carry each address's values in `preview`, so the extension can show them in its rows. Card and code listings never do.

## Cards wallet

- The Cards page shows your cards as a wallet of card faces in their own colors. Each face shows the name, credit or debit, a chip, the network logo, the cardholder, the expiry, and only the last four digits of the number.
- Hover a card to copy its number or security code. Switch to **List** for the compact view.
- A card's page shows the same face larger. Its number and security code stay hidden until you choose **Show**.
- The network comes from the number when the Network field is empty, with the same rules as the phone.

## Any card color

- The fixed list of card colors is now a full picker: a live card preview, a saturation and brightness square, a hue slider, and an exact `#RRGGBB` field.
- **On your other cards** shows the colors you already use, for one-tap reuse.
- The color is stored in the same field as before, so it syncs with the phone and older versions show it.

## Sync when Nuvori opens

- When the Nuvori window comes to the front (Start menu, tray, or switching back to it), Nuvori checks paired devices on this Wi-Fi and Google Drive once. You no longer need to click **Sync now**.
- It runs also when automatic sync is off. A locked vault syncs right after you unlock.
- Opening it again within a minute does not start another check.
- Turn it off with **Sync when Nuvori opens** on the Sync page. It is on by default.

## Other changes

- Google Drive sync ignores the Android app's Google Drive backup files (`nvbak1.<backup ID>.<time>`).
- Payment-network marks have a third-party notice in the README and `docs/licenses/`.

## Checks

- **Rust:** 222 unit tests passed (4 network and emulator tests ignored), plus 44 native-host tests. New tests:
  - every login listed with its site, filled once on that page only, never on another page, never as an update;
  - `all` accepted on login listings only;
  - the card color in the browser listing;
  - address values in address listings only.
- **Extension:** 135 tests passed. New tests:
  - address rows with the focused field's value, the fallback for an older desktop app, and addresses in an email box with no saved login;
  - address values passed on as text parts only, and a frame's field part forwarded for addresses only;
  - frame logins matched to the frame's own site, and filled only into that frame;
  - nothing released after the frame moved to another site;
  - the one-time code that finds the frame element, also through a middle frame;
  - script-built frames;
  - saving from a frame;
  - "Search all logins" with its confirmation, and the older-desktop-app case.
- **Real browser:** headless Edge 157 with the built extension (a fake desktop app) and real mouse and keyboard input. 12 of 12 passed:
  - an address form whose email and ZIP rows show "alice@example.com" and "78701", and the same in another site's frame;
  - a top-level form, a same-site frame, another site's frame, a frame inside a frame, a script-built frame, and fields in separate shadow roots;
  - "Search all logins" with its confirmation, and the save card for a login typed in a frame;
  - the live seedr.cc **Login** box, filled inside its frame;
  - the live USCIS sign-in page.
- `named_pipe_releases_only_one_selected_password_and_locks` fails now and then, as in 2.2.3 and 2.2.4. It is a timing race in the test (`os error 995` after the vault locks). It passes when run again, and it does not touch the changed code.
- **Versions and signatures:**
  - `nuvori.exe`, the MSI and the setup EXE report version 2.2.7.
  - Both MSIX packages carry version 2.2.7.0: the test package `Nuvori.Desktop.Test`, signed by `CN=Nuvori Test` (the same certificate as `Nuvori-Test.cer`), and the unsigned Store package `SantoshKanumuri.Nuvori`.
  - Both extension zips carry version 0.7.6 and contain no test files. Only the local zip has the `key` field.
- **Not run:**
  - The extension with the real desktop app: the bench used a fake one.
  - A click-through of the new Cards wallet in the installed app.

  Check both before publishing.

## Files

In `artifacts/release-2.2.7/`, with `SHA256SUMS.txt`:

- `Nuvori_2.2.7_x64-setup.exe` and `Nuvori_2.2.7_x64_en-US.msi` for direct installs.
- `Nuvori_2.2.7.0_x64_store.msix` for Partner Center upload.
- `Nuvori_2.2.7.0_x64.msix` and `Nuvori-Test.cer` for a local MSIX test (`scripts\install-test-msix.ps1`).
- `Nuvori_extension_0.7.6_chrome_web_store.zip` for the Chrome Web Store, and `Nuvori_extension_0.7.6.zip` to load unpacked.
- The Android phone 2.2.7 and watch 2.1.2 APK, AAB and R8 mapping files.
