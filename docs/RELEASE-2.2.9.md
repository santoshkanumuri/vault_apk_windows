# Nuvori 2.2.9

Windows version 2.2.9. Browser extension version 0.7.7. Pairs with Android 2.2.9 (version code 67).

## Passkey mark on logins

A login that also has a passkey for the same account now says so, so you can see at a glance that a passkey sign-in is possible.

- **Logins list (desktop app):** a green fingerprint next to the title, beside the favorite star.
- **Browser suggestions:** a green **Passkey** tag on the row, next to **Same site** or **Continue** when those show. **Search all logins** shows it too.
- **Toolbar popup:** the same **Passkey** tag on the account row, before **Fill**.
- **Android 2.2.9** shows the same mark in its vault list and keyboard suggestions.

The same account means:

- the usernames are the same, ignoring case and outer spaces; and
- the passkey's site (RP ID) is the login's website host or a parent domain of it, by the WebAuthn rule. A website saved without `https://` counts, and so do the sites linked to the login on Android.

Example: a passkey for `github.com` with username `dev@example.com` marks a login for `https://github.com/login` or `gist.github.com` with that username. It does not mark `work@example.com`, `notgithub.com` or `http://github.com`.

The mark is only a hint. It never changes what fills or what signs in.

### Desktop app

- Login listings (`query_credentials`, also with `all`) carry `"passkey": true` on a marked login. The field is left out otherwise, so older extensions see no change. It is a response field only, so it needs no entry in the browser feature list.
- New app command `passkey_login_ids` for the list. If it fails, the lists still load without the mark.

### Extension 0.7.7

- Shows the **Passkey** tag when the desktop app sends the mark. With desktop 2.2.8, no tag shows and everything else works.
- Only the value `true` counts.

## Checks

- **Rust:** 224 unit tests passed (4 network and emulator tests ignored), plus 45 native-host tests. New tests:
  - the passkey rule: same account only, an RP ID that is a child of the site or a public suffix never matches, no username or website gives no mark;
  - the vault marks a login for the site, a subdomain, a bare host and an origin linked on Android, and not another account, another site, a look-alike or `http://`;
  - `"passkey": true` reaches the extension when set, and is left out otherwise.
- **Extension:** 136 tests passed. New tests: the mark passes through only as `true`, also in **Search all logins**; the row shows **Passkey** next to **Same site**.
- **Frontend:** `tsc --noEmit` passed.
- **Packages:** `nuvori.exe` reports 2.2.9. Both MSIX packages carry version 2.2.9.0 with the test and Store identities. The test MSIX is signed with the same `CN=Nuvori Test` certificate as 2.2.8. Both extension zips report 0.7.7 and hold no test files. Only the plain zip keeps the `key` field.
- Not run: the mark in a real browser or in the installed app, and the installers on a separate PC.
