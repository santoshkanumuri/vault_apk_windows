# Design: new keys after a device is removed

Status: design, not implemented. Applies to Windows and Android together.

## The problem

A removed device must not read anything the group writes after its removal. Today it can, if it keeps its copy of the keys.

What exists today (verified in the code):

| Key | How it is made | After a REMOVE |
| --- | --- | --- |
| Root secret `R` (32 bytes) | Random, at pairing. Stored in `sync_group_state.transport_secret` (Windows) and `TransportMirror.transportSecret` (Android). | Unchanged |
| Transport secret of epoch `N` | `N = 1`: `R`. `N > 1`: HMAC-SHA256(`R`, `nuvori-transport-epoch-v1:<vaultId>:<N>`) (`membership_exit::transport_epoch_secret`, Android `TransportEpochs.secret`) | The epoch goes up, but anyone with `R` computes the new secret |
| Content key `K` | Random, at pairing. Payload keys and photo blob keys come from it (`payload::derive_key`, `photo_blobs::blob_key`). | Unchanged |
| Cloud key | HMAC-SHA256(`R`, `nuvori-cloud-v1:<vaultId>`) (`cloud_sync::CloudKeys::derive`) | Unchanged |

So a removed device that kept `R` and `K` can still:

- read every new change and photo, over Wi-Fi relays or from Google Drive,
- pass the Wi-Fi proof of every later epoch,
- read every new Google Drive file.

The signed device list still stops it from **writing**: every device refuses its new changes. This design stops it from **reading**.

## Goals

1. After a REMOVE, new changes, photos, Wi-Fi proofs and Google Drive files use keys the removed device cannot compute.
2. Every remaining device can still read all old items and history.
3. No server. The managing device makes the new keys. Wi-Fi and Google Drive carry them.
4. Old builds keep working until every device is updated. The new behavior starts only when every remaining device supports it.

Not a goal: hiding what the removed device already had before its removal.

## Design

### 1. An encryption key for each device

Each device already has an Ed25519 identity key. Its seed is a software key on both apps (Android: wrapped by the Keystore in `AndroidDeviceIdentityStore`; Windows: in the identity store).

- Derive an X25519 key pair from the same seed: private key = HKDF-SHA256(ikm = seed, salt = empty, info = `nuvori-device-x25519-v1`), clamped as X25519 requires.
- The device signs a **key statement** with its Ed25519 key: `{vaultId, deviceId, x25519Public}` with signing bytes `nuvori-device-key-v1\n<vaultId>\n<deviceId>\n<x25519 public, base64url>`.
- Anyone can check the statement against the Ed25519 key in the signed device list. The device list format does not change.
- Statements travel in the Wi-Fi handshake and as Google Drive files `nv1.<group>.k.<device>`.
- Libraries: Android Tink (already a dependency) has X25519 and HKDF. Windows adds `x25519-dalek` and `hkdf`, from the same family as `ed25519-dalek`.

### 2. New random keys at each REMOVE

When the managing device signs a REMOVE that starts epoch `N+1`:

1. It makes a random transport secret `S(N+1)` and a random content key `K(N+1)`, 32 bytes each.
2. For each remaining active device `d` with a valid key statement, it makes one **key package**:
   - an ephemeral X25519 key pair `e`,
   - shared = X25519(`e`, `d.x25519Public`),
   - wrap key = HKDF-SHA256(shared, info = `nuvori-epoch-key-v1:<vaultId>:<N+1>:<deviceId>`),
   - package = `e.public` || AES-256-GCM(wrap key, `S(N+1)` || `K(N+1)`, AAD = `<vaultId>:<N+1>:<deviceId>`).
3. It signs the set of packages with its Ed25519 key, bound to the REMOVE event hash.
4. The packages travel next to the REMOVE: in the Wi-Fi membership exchange, and as Google Drive files `nv1.<group>.e.<epoch>.<device>`.

A device that gets its package checks the manager signature and the binding to the REMOVE, opens its package, and stores `S(N+1)` and `K(N+1)` next to the older keys. The removed device has no package, so it cannot open anything.

### 3. Using the epoch keys

- **Wi-Fi proof:** epoch `N+1` uses `S(N+1)` instead of the HMAC derivation.
- **Changes:** a new payload format records the content key epoch. New changes use `K(current)`. Old changes keep their key and stay readable, because devices keep all old `K`.
- **Photos:** the same, with the content key epoch recorded in the signed photo change.
- **Google Drive:** cloud key = HMAC-SHA256(`S(N)`, `nuvori-cloud-v1:<vaultId>`). The group tag in file names changes with the epoch, so files of each epoch have their own prefix. Devices list the prefixes of the epochs they hold.
- **Leave requests (`l.` files):** sealed with the leaving device's current epoch cloud key, as today.

### 4. Turning it on safely

- Both apps announce a feature `epochKeys1` in the sync handshake, as they do for the removal cutoff.
- The managing device makes random keys only when every remaining active device has announced `epochKeys1` and has a valid key statement. Otherwise it keeps the old HMAC derivation, and the Remove dialog says which device needs an update for a full key change.
- A device that missed several epochs gets one package per missed epoch, in order.

### 5. What does not change

- The device list format and its signatures.
- How changes are signed and chained.
- Pairing (it still hands over `R` and `K` of the current epoch, plus the epoch keys).

## Work and tests

| Part | Windows | Android |
| --- | --- | --- |
| X25519 key from the seed, key statements | new | new |
| Key packages: make (manager), open (member) | open only (Windows is never the manager) | make and open |
| Epoch key store and the `epochKeys1` feature | new | new |
| Payload and photo format with a key epoch | new | new |
| Wi-Fi proof and Google Drive names per epoch | change | change |
| Shared test values (`fixtures/epoch-keys-v1.json`) | check | check |

Tests to write first, on both apps, against the same fixture:

- the X25519 key and key statement from a fixed seed,
- one key package made from fixed ephemeral and device keys, opened by the right device, refused by any other,
- a payload encrypted with `K(2)` that a device with only `K(1)` cannot read,
- an old build in the group: no random keys are made, and the dialog names the device.

This is the largest protocol change since pairing. Build it as its own release on both apps, after a live test of 2.2.3.

## Pairing through Google Drive (the step after this one)

This builds on the device encryption keys above. Both devices sign in to the same Google account and meet in the hidden app folder. They run the same J-PAKE exchange and compare the same code as over Wi-Fi, but through files. The vault copy is then sealed to the new device's X25519 key. Write its design after this one is implemented.
