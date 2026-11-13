# Nuvori 2.2.0

Windows version 2.2.0. Browser extension version 0.7.2: the same code as 0.7.1, plus icons for the Chrome Web Store (see [Chrome Web Store](CHROME-WEB-STORE.md)). Same Wi-Fi sync, autofill and passkey behavior as 2.1.9. Pairs with Android 2.2.0 (version code 58), the first phone version with Google Drive sync.

## Sync through Google Drive

- The **Sync** page has a new card: **Sync when your devices are apart**. It syncs your devices through your own Google Drive when they are not on the same Wi-Fi.
- It is optional. Wi-Fi sync works as before, with or without it.
- Select **Connect Google Drive** and sign in to Google in your browser. Then connect the same Google account on your phone under **Settings > Devices & sync**.
- Nuvori asks for one permission: its own hidden app folder in your Google Drive. It cannot see or change your other files.
- Every change and photo is encrypted on the device before it is uploaded. Google cannot read your items. Google can see how many files there are, their sizes and times.
- Devices check Google Drive while unlocked: soon after a change, about every minute, and on **Sync now**. There is no push.
- First pairing still happens on the same Wi-Fi.
- **Disconnect** stops Google Drive sync on this PC. The encrypted files stay in your Google Drive for your other devices.
- If Google stops accepting the sign-in, the card shows **Sign in again**. Nothing is lost.

See [Cloud sync through Google Drive](CLOUD-SYNC.md) for the full description, what Google can see, and the limits.

## What stays the same

- Pairing, Wi-Fi sync, conflicts, photo sync and device removal work as in 2.1.9.
- The vault, its location and its master password do not change.
- Nuvori has no server. Google Drive sync uses your own Google account.
- A build without the Google sign-in setup shows "Google Drive sync is not set up in this build of Nuvori". Wi-Fi sync works as usual.

## Updating from 2.1.9

1. Quit Nuvori from the tray icon.
2. Run the 2.2.0 package of the same type you installed before (MSI or setup EXE). The vault is kept.
3. For the Store build test, install `Nuvori_2.2.0.0_x64.msix` with `scripts\install-test-msix.ps1`.
4. Open Nuvori from the Start menu and unlock it.
5. Open **Sync** and check that the Google Drive card shows **Connect Google Drive**.

## Before the build (for the developer)

- Create `src-tauri/cloud-oauth.json` with the Windows OAuth client, or set `NUVORI_GOOGLE_CLIENT_ID` and `NUVORI_GOOGLE_CLIENT_SECRET`. See [the developer setup](CLOUD-SYNC.md#for-the-developer-one-time-google-cloud-setup). Without it, the card says that Google Drive sync is not set up in this build.
- Publish the Google OAuth consent screen to production. In the testing state, the Google sign-in expires after 7 days.
- Push the updated privacy policy (`card_app/docs/privacy-policy.html`) before you publish the consent screen. Google's review reads it.

## Checks

- 187 Rust unit tests passed (4 network and emulator tests ignored), 43 browser host tests and 121 extension tests passed. The frontend type check and the release build passed.
- The packaged app holds the Google OAuth client from `cloud-oauth.json`. The setup EXE, the MSI and the Store test package `Nuvori_2.2.0.0_x64.msix` were built. The Store package is signed with the local test certificate.
- New tests: the `nv1` file names and envelope against the shared vectors, names from other groups and malformed names, two PCs that sync changes and photos through an in-memory Google Drive, forged and misnamed files, a long history in bounded files, a signed removal found on the drive, the sign-in address and its single scope, the sign-in answer from the browser, and Google error answers.
- The `nv1` test vectors in `src-tauri/fixtures/cloud-sync-v1.json` match an independent Python implementation (names) and Node.js `crypto` (AES-256-GCM envelope).
- Not run: a live Google sign-in, any real Google Drive call, and sync between Windows and Android through Google Drive. Check these with the real OAuth clients before release.
