# Nuvori 2.3.1

Windows version 2.3.1. Browser extension version 0.7.9. Pairs with Android 2.3.4 (version code 75).

**Update every device in a sync group together.** The new sync features turn on only when every device announces them; until then a group keeps the 2.3.0 behaviour.

## Rich notes

Notes get a formatting toolbar and keyboard shortcuts: bold, italic, underline, strikethrough, inline code, text and highlight colors, links, headings, bulleted, numbered and check lists, quotes, code blocks, dividers and tables. The format is shared with Android (`docs/RICH-NOTES-PLAN.md`, tested against `docs/rich-notes/fixtures.json` in both repositories) and travels in the existing note fields, so the sync format doesn't change.

Before this version, an edit on Windows removed a note's formatting. 2.3.1 keeps it.

## Sign-in methods

The browser extension notices when you sign in to a site with Google, Apple, Microsoft, GitHub, Facebook, X, LinkedIn, Discord, Amazon or Slack. It asks first, then remembers the provider and the account the provider showed. Next time, the sign-in page shows "Last time: GitHub · name", and a click outlines the matching button (it never clicks it). The new **Sign-ins** page lists them with filters. They sync to the phone. Turn it off in **Settings > Browser extension**.

Detection needs the extension's new `webRequest` permission. Chrome shows no install warning for it.

## Extension popup search

The extension popup can search every login by site, name or username. It gets names, usernames and sites, never passwords, and filling a login saved for another site needs a second confirmation.

## Sync

The same protocol upgrades as Android 2.3.4: website icons sync, checkpoint enrollment, history cleanup on the PC and in Google Drive, key rotation when a device is removed, "Mark as lost" and joining a new group without duplicates, and rejoining after leaving. A PC that joins a group with items no longer duplicates them: exact copies merge, and differing copies go to **Recently deleted** with a "Needs review" badge. A removed PC keeps changes it hadn't applied in **Recently deleted**, with a "Removed" badge.

## Security

- **Auto-lock runs in the background service** (review H-03), so it works with no window open and also on Windows session lock and sleep.
- **Browser pipe connections** are accepted only from Nuvori's own programs (M-05).
- **Login and code lists are never given to page scripts across sites,** in every browser (M-06). Related logins are offered only between a bare domain and its `www.` name (L-21).
- **Copied secrets** stay out of Windows clipboard history and the cloud clipboard (L-17).
- The source-tree pairing helper is used only in debug builds (L-19).

## Welcome back and start fresh

- After a reinstall, Nuvori notices the vault left by the earlier install and asks: **Unlock it** (old master password, everything kept) or **Start fresh on this PC** (deletes this PC's vault and device identity after you type RESET, then goes to creating a vault and pairing with the phone). Neither choice touches the phone or other devices.
- The unlock screen has **Forgot the password or starting over?** with the same choices, so nobody is stuck with a forgotten password.
- A PC that was removed from its group, or left it, gets a new device identity and can pair again.

## One sync status for Wi-Fi and Google Drive

- **Devices & sync** and **Home** count a sync over either Wi-Fi or Google Drive. When Wi-Fi can't reach a device but Google Drive keeps it in step, the status says **Up to date**, with a quiet note about Wi-Fi.
- Each device shows **Up to date** when its signed progress shows it applied this PC's latest changes, or **Waiting for …** with when it was last heard from. **Waiting** counts changes no device has confirmed yet.
- An error shows only when both ways fail, or a device stays silent.

## Interface

- The sidebar footer is pinned so **Lock** stays reachable. Toasts show over dialogs. Arrow keys work in segmented controls, focus rings show in menus and search, and click targets are at least 32 px.
- Helium and Comet are detected as browsers. Codes show site logos. The KeePass import has a styled file button.
- **Store app icon:** the taskbar and Start show the padlock without an accent-colored plate behind it (unplated icons and `resources.pri` in the package).
- Clearer wording and stronger control borders. All on-screen text is in `src/strings.ts`.
- Unproven Wi-Fi sync connections are limited, and a pairing QR outlasts a stranger's connection attempt (L-20).
- Signed releases: when code signing is set up, Nuvori trusts only programs signed with its own certificates (M-07). Without signing set up, builds work as before.

## Checks

- `cargo test --lib`: 391 pass. One test (`named_pipe_releases_only_one_selected_password_and_locks`) fails only when the installed Nuvori is running on the same PC, because both use the same pipe name. `npm test`: 258 pass. `npx tsc --noEmit`: clean.
- The installers and both MSIX packages were built from `main` at this version.

## Downloads

`artifacts/Nuvori_2.3.1_x64-setup.exe`, `Nuvori_2.3.1_x64_en-US.msi`, `msix/Nuvori_2.3.1.0_x64.msix` (test certificate), `msix/Nuvori_2.3.1.0_x64_store.msix` (for Partner Center), and the extension packages `Nuvori_extension_0.7.9.zip`, `_chrome_web_store.zip` and `_firefox.zip`. Checksums: `artifacts/SHA256SUMS-2.3.1.txt`.

## Store listings to update

- Chrome Web Store: add the `webRequest` justification (detecting which sign-in provider a site sent you to), and replace "makes no network requests" with the website icon fetch (see `docs/CHROME-WEB-STORE.md`).
- Firefox Add-ons: the same two changes (see `docs/FIREFOX-ADD-ONS.md`).
- Microsoft Store: the listing names only Chrome, Edge and Brave for the extension.
