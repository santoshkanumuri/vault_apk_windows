# Nuvori for Windows

Nuvori for Windows is the desktop companion for the Android vault. Version 2.2.1 uses Tauri 2, React, TypeScript, and Rust. See [release notes](docs/RELEASE-2.2.1.md).

This repository is still in development. The desktop app creates, unlocks, and locks a SQLCipher vault. It can create, edit, and delete cards, logins, authenticator codes, security questions, contact autofill profiles, notes, and folders. It can add, view, and delete local entry photos, and list and delete stored passkeys. Each local entry change commits an Android-compatible encrypted, signed operation and device head in the same database transaction. Existing local notes are added to that history once on unlock. Rust can verify and durably stage bounded batches of signed incoming changes, and apply received entries, folders, and passkeys after authentication. Windows accepts the managing Android phone's QR through a PC camera or its copied setup link. When the PC cannot reach the phone, Windows can show a QR for the managing phone to scan and then accept the phone's connection. Both paths verify the pairing code and master password, ask for matching-code approval, and import the encrypted vault copy while preserving existing Windows items. The new reverse connection path needs a live phone-to-PC test. Paired devices can exchange later edits over an authenticated LAN connection. Windows supports automatic discovery, incoming and outgoing sync, photo transfer, and conflict review while the vault is unlocked. A group supports six mobile devices and two Windows PCs. Separate physical computers and phones still need a full network test.

Android currently requires an empty joining Android vault. Windows can keep its local items when joining the Android vault. Do not clear or replace either vault to force pairing.

The managing Android phone controls invitations and membership. After enrollment, neither device should overwrite the other's later edits by authority alone. Each keeps its own encrypted copy; signed changes sync in both directions after pairing. Concurrent changes are retained as conflicts without overwriting local items. Conflicts can be reviewed and resolved in either app.

In Windows Sync, **Stop sharing** leaves the group on this PC and keeps its local items, notes, folders, passkeys, and photos. Windows rebuilds independent change history under a new vault ID. If Android still lists this PC, remove it there too. **Reset vault** requires the Windows master password and typed confirmation, then deletes this PC's vault and device identity. Neither action removes data from other devices.

The Chrome and Brave extension can request a matching login from the unlocked Windows vault through the Native Messaging host. Nuvori registers the host for Chrome, Edge and Brave by itself; see [extension/README.md](extension/README.md). The extension shows matching-account counts on HTTPS pages, offers a sign-in shortcut, and queues encrypted captures for explicit save or update approval. It has Accounts, Save login, and Pending views with system, light, and dark themes. A live Brave fill was confirmed on Seedr before this update; the new suggestion and update flows have automated coverage and still need live extension validation. The Rust core validates Android passkey key material and signs WebAuthn assertions, but passkey creation and use are not connected to the extension yet. The Microsoft Store build (MSIX) is a Windows passkey provider instead: it signs in with synced passkeys in every browser and app, and **Settings > Security > Passkeys in Windows** shows whether Windows has it turned on. See [distribution](docs/DISTRIBUTION.md#test-the-store-build-msix). Contact profile filling is also pending.

The extension also fills cards, addresses and authenticator codes, and offers to save new cards and addresses after a form is submitted. A card's security code fills only after you approve it in a small Nuvori window with Windows Hello or the master password. See [extension/README.md](extension/README.md).

Nuvori keeps running in the Windows tray when you close its window, so browser filling keeps working. Use the tray icon to open Nuvori, lock the vault, or quit. When the browser starts, the extension asks Nuvori to show a small **Unlock Nuvori** window. If Nuvori isn't running, the browser host starts it in the background (`nuvori.exe --background`) with only that window. Starting Nuvori again while it runs brings the existing window forward instead of opening a second copy.

Windows Hello is optional. Unlock with the master password, then open More and confirm that password once to enable Hello. Later unlocks can use the Windows PIN, face, or fingerprint. The master password remains the recovery path. Windows protects a copy of the vault key for the signed-in Windows account using DPAPI, and the app asks Windows Hello before opening that copy. This is a convenience unlock: another process already running as the same Windows user may be able to decrypt the DPAPI copy without the app's Hello prompt. Turn off Hello in More to remove that copy. Reset vault removes it too.

## Why Tauri

- React can reproduce Nuvori's existing black, green, and soft-surface design without forcing the Android UI into Windows-native controls.
- Rust is a suitable home for portable cryptography, sync reconciliation, and the browser host. The Android app can call the same core later through a narrow JNI boundary.
- Tauri uses the installed WebView2 runtime on Windows instead of bundling a browser engine.
- Tauri capabilities let the UI call only the Rust commands explicitly registered by the app.

React Native for Windows was considered. It makes more sense when the mobile app already uses React Native. Nuvori uses Kotlin and Jetpack Compose, and React Native Windows still requires C++ for new-architecture native modules. It would not share meaningful code with the Android app.

## Install or distribute

Download `Nuvori_2.2.1_x64-setup.exe` from this repository's **Releases** page and run it on a 64-bit Windows PC. Recipients do not need npm or development tools. See the [installation and distribution guide](docs/DISTRIBUTION.md) for the MSI, checksums, and future builds.

The browser extension **Nuvori Password Fill** comes from the Chrome Web Store. See [extension/README.md](extension/README.md).

## Run the project

Prerequisites:

- Node.js 22 or newer
- Rust stable 1.88 or newer with the MSVC toolchain
- Microsoft C++ Build Tools with "Desktop development with C++"
- WebView2 Runtime
- .NET 8 SDK for the pairing helper
- A C compiler and Perl for the vendored SQLCipher/OpenSSL build. The resulting installer includes the crypto library in the application binary.

```powershell
npm install
npm run build
npm test
npm run prepare:pairing
. .\scripts\ensure-perl.ps1
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

Google Drive sync needs `src-tauri/cloud-oauth.json` with the Google OAuth client. The file is not in Git. Without it, the app builds and shows "Google Drive sync is not set up in this build". See [the developer setup](docs/CLOUD-SYNC.md#for-the-developer-one-time-google-cloud-setup).

`npm run tauri dev` and `npm run package:windows` find Perl on `PATH` or at `%LOCALAPPDATA%\NuvoriBuildTools\Perl\perl\bin`. If neither is present, install Strawberry Perl. Direct `cargo` commands still need Perl on `PATH`.

To build the Windows installer with the self-contained J-PAKE helper and browser Native Messaging host, run `npm run package:windows`. Both executables are included in the installer. Pairing and LAN change exchange are available. For later edits, enable device sync on Android and automatic sync in Windows. Paired devices find one another on the local network. Use Sync now to check immediately; an IP address is optional connection help. Automatic sync runs only while this vault is unlocked. After a failure it retries with backoff (15 s doubling to 5 min, with jitter) and shows the reason, attempt count, and next retry in Windows Sync. Large vaults sync in bounded batches; one Sync now reconnects until both sides are caught up, and an interrupted pass resumes from the saved frontier. Photos travel both ways as encrypted blobs, with integrity checks, and resume after an interruption. Concurrent edits become conflicts that you resolve in the app, and every device converges on the choice. Leaving the group notifies the managing phone, and a PC removed by the phone learns about it the next time it syncs. Windows advertises and discovers the same LAN service as Android and accepts authenticated peer connections. The app keeps an in-memory activity log (last 500 events, never secrets or item titles) and reports browser host registration and recent extension requests.

Paired devices that are not on the same Wi-Fi can also sync through the user's own Google Drive. This is optional and works next to Wi-Fi sync. Nuvori uses only a hidden app folder, and every change is encrypted before upload. First pairing still happens on the same Wi-Fi. See [cloud sync through Google Drive](docs/CLOUD-SYNC.md).

For networks where the phone can reach the PC but the PC cannot reach the phone, unlock Windows Sync, enter the Android vault master password, and choose **Show QR for phone to scan**. On the managing Android phone, open Android devices and tap **Scan Windows QR if the PC cannot reach this phone**. Both devices confirm the same code. The QR expires after two minutes. This requires an Android build with the reverse pairing option.

The frontend can run without Rust for UI work:

```powershell
npm run dev
```

## Project map

```text
src/                         React interface
src-tauri/src/sync.rs        Versioned change records and chain validation
src-tauri/src/change_store.rs Atomic local operations and tombstones
src-tauri/src/wire.rs        Android-compatible encrypted frame format
src-tauri/src/payload.rs     Android-compatible encrypted change payloads
src-tauri/src/passkeys.rs    Passkey key validation and assertion signing
src-tauri/src/pairing.rs     Android wire-v2 J-PAKE handshake adapter
src-tauri/src/membership.rs  Signed device membership history verifier
src-tauri/src/snapshot.rs    Authenticated enrollment metadata reader
src-tauri/src/portable_backup.rs Windows logical backup body parser
src-tauri/src/snapshot_import.rs Atomic enrollment import and local item migration
src-tauri/src/enrollment.rs  Windows joiner for Android QR and reverse listener for phone scans
src-tauri/src/migration_inventory.rs Validated local item inventory for migration
src-tauri/src/progress.rs    Received and applied sync frontiers
src-tauri/src/lan_sync.rs    Paired LAN exchange, batching, timeouts, retry state
src-tauri/src/activity.rs    In-memory activity log for the UI (500 events)
src-tauri/src/photo_blobs.rs Android-compatible encrypted photo blobs
src-tauri/src/conflicts.rs   Conflict listing and signed resolution
src-tauri/src/membership_exit.rs Leave requests and removal notices (SPEC3)
src-tauri/src/incoming_apply.rs Received entry, folder, passkey, and photo delete/cover materialization
src-tauri/src/vault.rs       SQLCipher database and password-wrapped local key
src-tauri/src/browser.rs     Browser-to-client protocol types
src-tauri/src/browser_ipc.rs Named-pipe server, request stats, host registration check
src-tauri/src/desktop.rs     Single instance, tray icon, background start, unlock and card-code windows
src-tauri/src/totp.rs        Authenticator codes (RFC 6238) for browser filling
src-tauri/src/bin/           Native Messaging host process
src-tauri/src/cloud_sync.rs  Google Drive sync format and pass
src-tauri/src/google_drive.rs Google sign-in and Drive calls
extension/                   Chrome and Brave extension and host setup
pairing-helper/              Bouncy Castle .NET J-PAKE process and Java interop test
docs/                        Cloud sync, distribution, Chrome Web Store, release notes
store-assets/                Chrome Web Store screenshots and promo images
```

## Non-negotiable security rules

- The browser extension never receives the master key, vault key, or full vault.
- Being on the same Wi-Fi never grants trust. Users pair devices explicitly.
- Sync moves authenticated operations, not a live SQLite database file.
- Deletions are durable tombstone operations so another device cannot resurrect an item.
- The app must preserve concurrent conflicts for review instead of silently choosing a winner.
- Local secret changes stay in the encrypted vault until an authenticated peer path is connected.

