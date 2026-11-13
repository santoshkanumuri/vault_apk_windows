# Cloud sync through Google Drive

Nuvori can sync your devices through your own Google Drive. Use it when your devices are not on the same Wi-Fi.

- It is optional. Wi-Fi sync works with or without it.
- It works next to Wi-Fi sync. Each sync pass tries the devices on this Wi-Fi first, then Google Drive. The pass succeeds when one of the two works (`src-tauri/src/lib.rs`, `SyncController::pass`).
- Nuvori has no server. Your Google Drive only carries the encrypted changes between your devices.
- It needs Windows 2.2.0 and Android 2.2.0 or newer. Both use the same file format, `nv1`.

This document has five parts:

1. [For users](#for-users)
2. [What Google can and cannot see](#what-google-can-and-cannot-see)
3. [Format `nv1` reference](#format-nv1-reference)
4. [For the developer: one-time Google Cloud setup](#for-the-developer-one-time-google-cloud-setup)
5. [Verification status](#verification-status)

## For users

### Before you start

- Pair this PC with your phone on the same Wi-Fi first. The Google Drive card shows on the Sync page only after pairing.
- Unlock the vault. Google Drive sync runs only while the vault is unlocked.
- Use one Google account for all your devices. Each device must sign in to the same account.

If the card says "Google Drive sync is not set up in this build of Nuvori", this copy of Nuvori has no Google sign-in. Wi-Fi sync works as usual.

### Turn it on in Windows

1. Open the **Sync** page in Nuvori.
2. Find the card **Sync when your devices are apart**.
3. Select **Connect Google Drive**. Your browser opens Google's sign-in page.
4. Choose your Google account.
5. Allow Nuvori to use its own app folder. This is the only permission Nuvori asks for.
6. Wait for the browser page **Google Drive is connected**. Close that tab.
7. Go back to Nuvori. The card now shows your Google account.

Notes:

- You have 5 minutes to finish the sign-in in the browser. After that, Nuvori stops waiting.
- To stop the sign-in, select **Cancel** on the card. Nothing changes.
- When you cancel in the browser, the page says **Sign-in was canceled**. Nothing is connected.
- After a good sign-in, Nuvori starts a sync pass right away. This uploads this PC's changes for your other devices.

### Turn it on on the phone

You need Nuvori 2.2.0 or newer on the phone.

1. Unlock Nuvori on the phone.
2. Open **Settings > Devices & sync**.
3. Find the card **Sync when your devices are apart**. It shows only after the phone is paired.
4. Tap **Connect Google Drive**. Android shows Google's account screen.
5. Choose the same Google account that you use on this PC, and allow access.
6. The card now shows **Google Drive** and your account.

The phone checks Google Drive when you unlock it, about every minute while Nuvori is open, and on **Sync now**. It uploads its own changes right after each change. It does not check while Nuvori is closed. Unlike Windows, the phone checks Google Drive also when Wi-Fi sync is off.

### When devices sync

Google Drive does not tell a device about new files. Each device checks Google Drive by itself while its vault is unlocked:

- about 2 seconds after a change on this PC,
- about every minute when nothing changes,
- when you select **Sync now**.

The automatic checks run only when **Sync automatically** is on in the Sync page. With it off, Windows checks Google Drive only when you select **Sync now**. After a failure, automatic sync waits longer between tries (15 seconds, up to 5 minutes).

### What the card shows

The chip in the corner of the card shows the state (`src/pages/sync/Cloud.tsx`, `cloudIndicator`):

| Chip | Meaning |
| --- | --- |
| **Off** | Google Drive is not connected on this PC. |
| **Waiting for sign-in** | The browser sign-in is open. Finish it or select **Cancel**. |
| **Starting** | Google Drive is connected. No sync pass through Google Drive has finished yet. |
| **On** | Google Drive is connected, and the last sync pass through Google Drive finished. |
| **Needs attention** | The last sync pass through Google Drive failed. The card shows the reason. |
| **Sign in again** | Google does not accept the saved sign-in. See [Sign in again](#sign-in-again). |

When Google Drive is connected, the card also shows:

- the Google account,
- **Last Drive sync**: the time of the last finished sync pass through Google Drive, or "Not yet",
- **Stored in your Drive**: "Encrypted changes only".

A sync pass that stops at a work limit (see [Limits](#limits)) does not update **Last Drive sync**. The next pass continues.

### Messages

When a sync pass through Google Drive fails, the card shows one of these fixed sentences (`src-tauri/src/cloud_sync.rs`, `CloudError::message`). They never contain file names or account data.

| Message | Cause | What to do |
| --- | --- | --- |
| Can't reach Google Drive. Check the internet connection. | No connection to Google. | Check the internet connection. |
| Your Google Drive is full. Free some space, then sync again. | The Google storage of the account is full. | Free some space in the Google account. |
| A sync file is gone from Google Drive. Sync will check again. | A file was deleted from Google Drive. | Nothing. The next full listing finds the files again. |
| Google Drive is busy. Sync will retry soon. | Google asked Nuvori to slow down, or Google had an error. | Nothing. Sync retries. |
| Google Drive sync failed. Sync will retry. | Any other error. | Nothing. If it stays, open the activity log. |
| Google Drive needs you to sign in again. | Google does not accept the saved sign-in. | See [Sign in again](#sign-in-again). |

### Sign in again

The card shows **Google needs you to sign in again** when Google refuses the saved sign-in. Google does this when:

- you removed Nuvori's access in your Google account, or
- the sign-in expired.

Nothing is lost. Wi-Fi sync keeps working. To fix it:

1. Select **Sign in** in the yellow banner on the card.
2. Finish the sign-in in the browser, as in [Turn it on in Windows](#turn-it-on-in-windows).
3. Choose the same Google account as before. Another account has a different app folder, so your other devices do not see its files.

### Disconnect

1. Select **Disconnect** on the card.
2. Read the message and select **Disconnect** again.

Disconnect does these things:

- This PC stops syncing through Google Drive. Wi-Fi sync keeps working.
- Nuvori deletes the saved sign-in from this PC.
- Nuvori asks Google to end this PC's access. If Google cannot be reached, the local sign-in is still deleted.
- The encrypted files stay in your Google Drive for your other devices.

### Delete everything from Google Drive

Nuvori does not delete its files from Google Drive. To delete them all:

1. Open Google Drive in a web browser.
2. Open the Drive settings, then the page that manages apps.
3. Find Nuvori and choose the option to delete its hidden app data.

Do this only when no device uses Google Drive sync anymore. Otherwise the next sync pass uploads the files again. The exact Google menu names can change. Follow the Google Drive settings as they are today.

## What Google can and cannot see

Nuvori asks Google for one permission: `https://www.googleapis.com/auth/drive.appdata`. This gives Nuvori a hidden app folder in your Google Drive. Nuvori cannot see or change your other Google Drive files. The sign-in token stays in the encrypted vault database on the PC. It is readable only while the vault is unlocked.

### What Google cannot see

- **Your items.** Every change and every photo is encrypted with the sync group's content key before it leaves the device. Google never gets that key.
- **IDs and times inside the files.** Each file is encrypted a second time with a key that only the sync group knows. Entry IDs, device IDs and change times stay inside that encryption.
- **Who the devices are.** File names use short opaque tags, not device IDs or the vault ID.

### What Google can see

| Google sees | Where it comes from |
| --- | --- |
| Your Google account, and that it uses Nuvori | The sign-in |
| The number of files, their sizes, and when each file was written | Google Drive keeps this for every file |
| The tag of the sync group (the same in every file name) | File names |
| A tag per device. Google can group the files of one device, but cannot tell which device it is | Change and progress file names |
| The change numbers of each device. For example, `000000000001.000000000256` shows changes 1 to 256 of one device | Change file names |
| The number of membership events, and the first 16 hex characters of the membership head hash | Membership file names |
| The SHA-256 hash of each encrypted photo, and the photo size (the photo plus 28 bytes) | Photo file names and sizes |
| When a device last reported its progress | The progress file is the only file that Nuvori overwrites |

### What Google can do

Google stores the files, so Google can delete them, keep them back, or send old copies. This delays sync. It cannot forge a change or alter a change:

- Every change is signed by the device that made it, and is part of a hash chain. Each device checks these signatures and chains, as in Wi-Fi sync.
- The device membership list is a signed chain. A device adopts a longer list only when every event in it is signed correctly.
- Each file is sealed with AES-256-GCM, and the seal includes the file name. A file under a wrong name, or a changed file, does not open. Nuvori ignores it.
- A photo must match the SHA-256 hash and size in its signed change.

### Limits

Read these limits before you depend on Google Drive sync:

- **No push.** Devices check Google Drive by themselves. See [When devices sync](#when-devices-sync).
- **First pairing needs the same Wi-Fi.** Google Drive carries changes only between devices that are already in the sync group.
- **One Google account.** Every device must use the same Google account. Each account has its own hidden app folder.
- **A removed device can still read old files.** Suppose you remove a device from the sync group. If that device still has the Google sign-in and the old keys, it can still download and open the files. The other devices refuse its new changes. To stop it reading, also remove that device's access in your Google account. This can end the sign-in on your other devices too. Then use **Sign in again** on each device you keep.
- **The folder grows slowly.** Nuvori does not clean up old files yet. Every change file and photo stays. The files use storage in your Google account.
- **To delete everything**, see [Delete everything from Google Drive](#delete-everything-from-google-drive).

## Format `nv1` reference

This part is for developers. The Windows source is `src-tauri/src/cloud_sync.rs` (the module `lan_sync::cloud`) and `src-tauri/src/google_drive.rs`. The Android implementation must match it byte for byte. The shared test vectors are in `src-tauri/fixtures/cloud-sync-v1.json`.

### Keys

All keys come from the sync group's existing secrets (`sync_group_state`). Cloud sync adds no new secret.

```text
transport secret (32 bytes) + vault ID
        |
        |  HMAC-SHA256(transport secret, "nuvori-cloud-v1:" + vaultId)
        v
   cloud key (32 bytes)
        |-- HMAC-SHA256(cloud key, "tag"), first 8 bytes, hex        --> <group>
        |-- HMAC-SHA256(cloud key, "device:" + deviceId), 8 bytes hex --> <device>
        '-- AES-256-GCM key for the envelope
```

- The transport secret must be exactly 32 bytes. Otherwise `CloudKeys::derive` fails.
- The content key (32 bytes) encrypts change payloads and photo blobs. Cloud sync does not change that encryption.

### File names

All files are in the Google Drive `appDataFolder`. Every name starts with `nv1.<group>.`.

| Kind | Name | Fields |
| --- | --- | --- |
| Membership | `nv1.<group>.m.<count>.<head16>` | `<count>`: number of membership events, 10 digits, at least 1. `<head16>`: first 16 hex characters of the head hash. |
| Changes | `nv1.<group>.o.<device>.<first>.<last>` | `<first>` and `<last>`: sequence numbers of the author's changes, 12 digits each. `first` is at least 1, and `last` is at least `first`. |
| Progress | `nv1.<group>.p.<device>` | One file per device. |
| Photo blob | `nv1.<group>.b.<sha256>` | `<sha256>`: 64 lowercase hex characters, the hash of the encrypted blob. |

- Numbers are zero padded. Hex is lowercase.
- `<device>` in a change file is the tag of the author, not of the device that uploaded it.
- A name with another prefix, another kind, or a wrong field length is ignored (`CloudKeys::parse`).

Example from the test vectors (`cloud-sync-v1.json`):

```text
transport secret  0102030405...1f20
vault ID          7d0e7f0a-3b56-4a57-9a0e-2f6f1c5f0b11
device ID         0f6c1a52-9d1e-4c3b-8a77-5e2d9b4c6a10
prefix            nv1.e1e6ddbe30652114.
device tag        5755ee97f9749a2d
changes 7 to 42   nv1.e1e6ddbe30652114.o.5755ee97f9749a2d.000000000007.000000000042
```

### Envelope

Membership, change and progress files are sealed. Photo blobs are not.

```text
"NVC1" (4 bytes) || nonce (12 random bytes) || AES-256-GCM(cloud key, plaintext, AAD = file name)
```

- The AAD is the full file name as UTF-8 bytes. This binds the content to its name.
- The GCM tag is 16 bytes, at the end of the ciphertext. A sealed file is at least 4 + 12 + 16 bytes.
- A file that does not open is ignored (`CloudKeys::open` returns `None`).

### File contents

Contents after the envelope is opened:

| Kind | Content |
| --- | --- |
| Membership | JSON array of the signed membership events, the same events as in Wi-Fi sync. |
| Changes | JSON array of changes by one author, in sequence order. Each change is in its Wi-Fi wire form. The array has exactly `last - first + 1` items. |
| Progress | JSON object `{"deviceId": ..., "updatedAt": <milliseconds>, "progress": <sync progress>}`. |
| Photo blob | The blob as stored on the device: nonce (12 bytes) and ciphertext with tag. No envelope. The blob is already encrypted under a key derived from the content key, and its name is its hash. |

Every file is written once and never changed. The only exception is the progress file. Any device may upload any author's changes that Google Drive lacks. So a device that never connects to Google Drive still reaches it through one that does. Two devices that upload the same range make a harmless duplicate.

### Limits

All constants are in `src-tauri/src/cloud_sync.rs`, except where the table says otherwise.

| Constant | Value | Use |
| --- | --- | --- |
| `UPLOAD_OPERATIONS` | 256 | Most changes in one uploaded change file. |
| `UPLOAD_BYTES` | 2 MiB | Most bytes of changes in one uploaded change file. |
| `DOWNLOAD_OPERATIONS` | 1024 | Most changes in a downloaded change file. A larger file is ignored. |
| `DOWNLOAD_BYTES` | 16 MiB | Largest downloaded change file. |
| `MEMBERSHIP_BYTES` | 1,000,064 bytes | Largest downloaded membership file. |
| `PROGRESS_BYTES` | 200,000 bytes | Largest downloaded progress file. |
| `UPLOAD_FILES_PER_PASS` | 64 | Most change files uploaded in one pass. |
| `PHOTOS_PER_PASS` | 32 | Most photos downloaded, and most photos uploaded, in one pass. |
| `LIST_OVERLAP` | 10 minutes | A partial listing starts this long before the newest file seen, to cover clock differences at Google. |
| Longer membership histories tried | 3 per pass | `run`, step 2. |
| `CLOUD_FULL_LISTING` (`lib.rs`) | 6 hours | After this time, the next pass lists the whole folder. |
| `SINGLE_REQUEST_BYTES` (`google_drive.rs`) | 4 MiB | A larger upload uses a resumable upload. |
| `SIGN_IN_WAIT` (`google_drive.rs`) | 5 minutes | Time to finish the browser sign-in. |
| List stop (`google_drive.rs`) | 200,000 files | A listing stops after this many files. |
| Photo size | photo + 28 bytes, at most 128 MiB + 28 (`photo_blobs.rs`) | A downloaded photo must have the exact size from its signed change. |

When a pass stops at a work limit, it saves its place, and the next pass continues. Such a pass does not set **Last Drive sync**.

### The sync pass

`lan_sync::cloud::run` does one pass. It holds no vault lock during a network call.

0. **Load.** Read the sync group state and derive the keys. Verify the signed membership. This PC must be an active member. Otherwise the pass stops with "This PC is no longer in the sync group. Pair again."
1. **List.** List the files in `appDataFolder` that are not in the trash.
   - A full pass lists all files. A pass is full on **Sync now**, on the first pass, and when the last full listing is older than 6 hours.
   - Other passes list only files changed after the newest file seen, minus 10 minutes.
   - Keep only names with this group's prefix that parse. Save the file list.
2. **Membership.** Compare the membership files with the local history.
   - Try up to 3 files with more events than the local history, longest first. Download, open and merge each one. The merge accepts only a correctly signed history.
   - When the accepted history removes this PC, this PC leaves the group, as with a removal notice over Wi-Fi. The message is "This PC was removed from the sync group. Your items stay on this PC."
   - Otherwise store the longer history and use it for the rest of the pass.
   - When no file has the local event count, upload the local history.
3. **Download changes.** For each other author in the membership:
   - Find the file that starts at or before the next needed change and reaches furthest.
   - Download it, open it, and check the item count.
   - Check each change: the author and sequence must match, and the change must pass the same checks as over Wi-Fi (signature and hash chain).
   - At the first bad change, keep the changes before it and stop using that file.
   - When a file is gone from Google Drive, mark the pass as not complete.
   - Then apply the received changes.
4. **Upload changes.** For every author whose changes this PC holds:
   - Active members: all changes. Removed members: only up to their removal cutoff. Others: none.
   - Find how far Google Drive already holds the author's changes without a gap, from change 1.
   - Upload the next changes in files of at most 256 changes and 2 MiB, at most 64 files per pass.
5. **Photos.**
   - Download photos that this PC waits for and that Google Drive has with the right size. Check the size and the SHA-256 hash. At most 32.
   - Upload photos that this PC holds and that Google Drive lacks. At most 32.
6. **Progress.**
   - Apply waiting changes. Write this PC's progress file when the progress changed or the file is missing. Nuvori overwrites the existing file.
   - Read the progress files of the other active members from this pass's listing. The `deviceId` inside must match the device tag. The progress goes through the same check as over Wi-Fi, and Nuvori records when that device was last seen.
7. **Save.** Save the file list and the listing position. When the pass is complete, save the time as **Last Drive sync**.

After a pass, the sync message on the Sync page is one of these (`lib.rs`, `sync_summary`):

- "Synced through Google Drive. Sent N changes and received M." when no device answered on Wi-Fi.
- "Sent N changes and received M, over Wi-Fi (K devices) and Google Drive." when both worked.

### Sign-in and Google Drive calls

Sign-in uses OAuth for installed apps (`google_drive.rs`, `sign_in`):

1. Nuvori opens a listener on `127.0.0.1` on a free port.
2. Nuvori opens the system browser at Google's sign-in page. The request has the scope `drive.appdata`, PKCE (`S256`), a random `state`, `access_type=offline` and `prompt=consent`.
3. Google sends the browser back to `http://127.0.0.1:<port>`. Nuvori accepts only a `GET` with a `code` and the same `state`. Any other request gets a 404.
4. Nuvori exchanges the code for tokens and reads the account's email address from the Drive `about` call.
5. Nuvori saves the email address and the refresh token in the encrypted vault database.

Google Drive calls:

| Operation | Google Drive call |
| --- | --- |
| List | `GET drive/v3/files`, `spaces=appDataFolder`, `pageSize=1000`, `q=trashed = false` (plus `and modifiedTime > '<time>'` for a partial listing) |
| Download | `GET drive/v3/files/<id>?alt=media`, stopped when it is larger than the limit |
| Upload, up to 4 MiB | `POST upload/drive/v3/files?uploadType=multipart`, parent `appDataFolder` |
| Upload, larger | `POST upload/drive/v3/files?uploadType=resumable`, then one `PUT` to the upload address |
| Replace (progress file only) | `PATCH upload/drive/v3/files/<id>?uploadType=media` |
| Account | `GET drive/v3/about?fields=user(emailAddress)` |
| Disconnect | `POST oauth2.googleapis.com/revoke` (best effort) |

Network timeouts: 15 seconds to connect, 60 seconds to read or write. An expired access token is renewed once per request.

Google answers map to these errors (`classify`):

| Google answer | Error |
| --- | --- |
| 401, or 400 with `invalid_grant` | Sign in again |
| 403 with `storageQuotaExceeded` | Drive full |
| 403 with `rateLimitExceeded` or `userRateLimitExceeded` | Busy |
| 404 | File gone |
| 429, or 500 to 599 | Busy |
| No connection | Offline |
| Other | Failed |

## For the developer: one-time Google Cloud setup

Google Drive sync needs one Google Cloud project with one OAuth client for Windows and one Android OAuth client per signing key.

The scope class and the 7-day limit below come from Google's documentation. I could not check the current console wording or every verification rule. The steps describe the goal of each step. Follow the Google Cloud console as it is today.

### 1. Create one Google Cloud project

- Create one project for Nuvori. Use this project for Windows and for Android.
- Why one project: the hidden app folder belongs to the project. A Windows client and an Android client in two projects see two different folders. Then the devices never see each other's files.

### 2. Enable the Google Drive API

- Enable the Google Drive API in that project. Without it, every Google Drive call fails.

### 3. Configure the OAuth consent screen

- Set the app name, a support email and the developer contact.
- Add only one scope: `https://www.googleapis.com/auth/drive.appdata`. The code asks for nothing else (`google_drive.rs`, `SCOPE`).
- Google's Drive scope list names `drive.appdata` as a non-sensitive scope. So it does not need the review for sensitive or restricted scopes.
- While an External project is in the testing state, only listed test users can sign in. Google's refresh tokens for it expire after 7 days. The card then shows **Sign in again** every week.
- Publish the consent screen to production before real use. Google may still ask for brand verification (app name, logo and domains).

### 4. Create the Windows client

1. Create an OAuth client of type **Desktop app**.
2. Copy its client ID and client secret.
3. Create the file `src-tauri/cloud-oauth.json` with this content:

```json
{
  "googleClientId": "<client ID>.apps.googleusercontent.com",
  "googleClientSecret": "<client secret>"
}
```

4. Build Nuvori as usual (`npm run tauri dev` or `npm run package:windows`).
5. Open the Sync page on a paired PC. The card must show **Connect Google Drive**, not "not set up in this build".

Notes (`src-tauri/build.rs`):

- `src-tauri/cloud-oauth.json` is in `.gitignore`. Do not commit it.
- The environment variables `NUVORI_GOOGLE_CLIENT_ID` and `NUVORI_GOOGLE_CLIENT_SECRET` replace the file. When both a variable and the file are present, the variable wins.
- Without an ID and a secret, the app still builds. The card then says that Google Drive sync is not set up in this build.
- The build compiles the ID and the secret into the app. Google treats a desktop client's secret as not confidential. PKCE protects the sign-in.

### 5. Create the Android clients

1. In the same project, create an OAuth client of type **Android**.
2. Enter the Android application ID as the package name.
3. Enter the SHA-1 fingerprint of the signing certificate.
4. Create one Android client for each signing key, as in the table.

| Build | Package name (application ID) | SHA-1 of the signing certificate |
| --- | --- | --- |
| Debug | `com.application.private_vault.debug` | The debug key on the developer PC. Read it as shown below. |
| Release (the key that signs the APK today) | `com.application.private_vault` | `37:02:B3:B5:C2:FD:FB:5A:7A:62:89:AE:AB:E7:F8:FD:BA:B3:E6:2C` |
| Install from Google Play | `com.application.private_vault` | The Play app signing key. Copy it from Play Console, App integrity. |

About the package name:

- The Android OAuth client uses the application ID, not the Kotlin package name.
- In `card_app/app/build.gradle.kts`, `applicationId` is `com.application.private_vault`. The debug build type adds `applicationIdSuffix = ".debug"`.
- The Kotlin namespace `com.privatevault.app` is not the application ID. Do not use it here.

About the release SHA-1:

- The SHA-1 above was read from the signed 2.1.6 APK with `apksigner`.
- The SHA-256 of the same certificate is `c88756b1…a6db79d9`. It is the same as in the Android 2.1.6 release notes.
- If a later release uses another key, add a client for that key too.

To read the debug SHA-1, run this on the developer PC:

```powershell
keytool -list -v -keystore $env:USERPROFILE\.android\debug.keystore -alias androiddebugkey -storepass android
```

In `cmd.exe`, write the path as `%USERPROFILE%\.android\debug.keystore`.

To read the SHA-1 of a signed release APK, use `apksigner verify --print-certs <file>.apk`. Do not use `keytool -printcert -jarfile` for it. An APK signed only with signature scheme v2 or later has no JAR signature, so `keytool` finds no certificate.

With Google Play App Signing, Google signs the installed app with its own key. So the third client, with the Play app signing key's SHA-1, is needed for every install from Google Play.

## Verification status

### Automated tests

These tests pass on Windows. A filtered run on 2026-11-12 (`cargo test --lib -- cloud google_drive background_`) ran 12 tests, all passed.

In `src-tauri/src/cloud_sync.rs`, with a Google Drive replacement in memory (`MemoryDrive`):

| Test | What it checks |
| --- | --- |
| `names_and_envelope_match_the_shared_vectors` | The cloud key, prefix, device tag, all four file names and the sealed envelope match `fixtures/cloud-sync-v1.json`. A wrong file name and another group's key cannot open the envelope. |
| `names_parse_back_and_foreign_names_are_ignored` | Each name parses back. Foreign names are ignored: another file, another group, `first` after `last`, change 0, unpadded numbers, membership count 0, uppercase hex, unknown kind. The coverage stops at a gap. |
| `two_pcs_sync_changes_and_photos_through_the_drive` | Two PCs exchange notes, an entry, a photo and the phone's changes (relayed by one PC). An idle pass moves nothing and lists only changed files. No file name or file content shows the vault ID, device IDs or titles. Each PC reads the other's progress. |
| `forged_reordered_and_foreign_files_change_nothing` | A forged signature, a real file under a wrong name, another group's file, garbage, and a file after a gap change nothing. The real file is then accepted. |
| `a_long_history_uploads_in_bounded_files_and_downloads_in_order` | 300 phone changes upload as files 1 to 256 and 257 to 300. The other PC receives all of them in order. |
| `a_signed_removal_on_the_drive_makes_this_pc_leave` | A forged removal is not adopted. A signed removal makes the removed PC leave and keep its items. The other PC adopts the same history. |

In `src-tauri/src/google_drive.rs`, without network:

| Test | What it checks |
| --- | --- |
| `the_sign_in_address_asks_only_for_the_app_folder` | The sign-in address asks only for `drive.appdata`, and uses PKCE `S256`, `response_type=code` and `access_type=offline`. |
| `only_the_real_redirect_is_read_as_the_sign_in_answer` | Only a `GET` with a code and a state counts as the answer. A Google error is read as an error. Other requests are ignored. |
| `google_answers_map_to_what_the_user_can_do` | Google answers map to the errors in [Sign-in and Google Drive calls](#sign-in-and-google-drive-calls). |
| `a_new_file_goes_into_the_app_folder_and_drive_numbers_are_read` | The upload body puts a new file in `appDataFolder`. The size that Google sends as a string is read as a number. |

In `src-tauri/src/lib.rs`, `background_sync_retries_without_busy_polling` and `background_backoff_waits_for_the_retry_deadline` check the timing of automatic sync. They cover Wi-Fi and Google Drive together.

### Independent check of the format

- The values in `src-tauri/fixtures/cloud-sync-v1.json` were checked against an independent Python implementation (the standard `hmac` and `hashlib` modules). The cloud key, prefix, device tag and all four file names match.
- The sealed envelope was checked with Node.js `crypto` (AES-256-GCM). It matches `sealedHex`. With the progress file name as AAD, the envelope does not open.
- The Android app passes the same vectors (`CloudSyncFormatTest` reads its copy, `app/src/test/resources/cloud-sync-v1.json`). Its sync pass is tested with an in-memory Google Drive in `CloudSyncPassTest`.

### Not run yet

- No live Google sign-in. No real Google Drive call. The tests use the in-memory replacement only.
- No sync between Windows and Android through a real Google Drive.
- No test of the 7-day expiry in the testing state, of revoking access in the Google account, or of a full Google Drive.
- No resumable upload (photos larger than 4 MiB) against Google.
- `src-tauri/cloud-oauth.json` is local to the developer PC and is not in Git. A build without it shows "not set up in this build".
