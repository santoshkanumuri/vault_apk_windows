//! Protocol `master-password-v1`: every device in a sync group keeps the managing device's master
//! password (Android `MasterPasswordRules`). Shared test vectors: `fixtures/master-password-v1.json`
//! (Android `scripts/sync-vectors/master_password.py`, which also states the rules in full).
//!
//! When the managing phone changes its master password while it shares the vault, it writes a signed
//! `master_password` change under the vault ID: a password check. The check proves that a typed
//! password is the new one without holding it: an Argon2id key of the password (64 MiB, the vault's
//! own settings) and an HMAC of the vault ID and the check's epoch under that key. Guessing the
//! password from it costs one Argon2id run per guess, as guessing it from a backup file does, and it
//! travels only inside the group's end-to-end encrypted sync changes. The password itself never
//! leaves the phone.
//!
//! A device that holds a newer check than it switched to asks for the new password after unlock,
//! tests it against the check, wraps its own vault key under it and writes a `master_password` change
//! under its own device ID, `{"switchedEpoch": E}`. Until then it still opens with its old password,
//! and its sync waits. A check that any other device writes is never used: the author must have been
//! the managing device once the membership event the check names applied. Windows never manages, so
//! this PC only reads checks and writes its own switches.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const FEATURE: &str = "master-password-v1";
pub const ENTITY_TYPE: &str = "master_password";

const LABEL: &str = "nuvori-master-password-check-v1";
const MEMORY_KIB: u32 = 65_536;
const PARALLELISM: u32 = 1;
const MIN_ITERATIONS: u32 = 3;
const MAX_ITERATIONS: u32 = 64;
/// Epochs and sequences stay below 2^53, so that every platform reads them exactly.
const MAX_NUMBER: u64 = (1 << 53) - 1;

/// A password check from the managing device. `Debug` shows the epoch and the membership sequence only.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordCheck {
    pub epoch: u64,
    pub membership_sequence: u64,
    salt: [u8; 16],
    iterations: u32,
    check: [u8; 32],
}

impl std::fmt::Debug for PasswordCheck {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordCheck")
            .field("epoch", &self.epoch)
            .field("membership_sequence", &self.membership_sequence)
            .finish_non_exhaustive()
    }
}

impl PasswordCheck {
    /// True when `password` is the master password this check was made from, for this vault. Takes one
    /// Argon2id run (64 MiB, up to about a second); the tags are compared in constant time.
    pub fn matches(&self, vault_id: &str, password: &str) -> bool {
        keyed(vault_id, password, &self.salt, self.iterations, self.epoch)
            .is_some_and(|mac| mac.verify_slice(&self.check).is_ok())
    }

    /// The check in a change payload, or `None` when the payload breaks the protocol: exactly the seven
    /// keys, whole numbers in range, the fixed Argon2id memory and lanes, canonical padded base64.
    pub fn parse(payload: &Value) -> Option<Self> {
        let object = payload.as_object()?;
        if object.len() != 7
            || object.get("memoryKib")?.as_u64()? != u64::from(MEMORY_KIB)
            || object.get("parallelism")?.as_u64()? != u64::from(PARALLELISM)
        {
            return None;
        }
        let iterations = u32::try_from(object.get("iterations")?.as_u64()?).ok()?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return None;
        }
        Some(Self {
            epoch: number(object, "epoch")?,
            membership_sequence: number(object, "membershipSequence")?,
            salt: bytes(object, "salt")?,
            iterations,
            check: bytes(object, "check")?,
        })
    }

    /// The managing device's side, which only tests use here: Windows never manages.
    #[cfg(test)]
    fn create(vault_id: &str, password: &str, epoch: u64, membership_sequence: u64, salt: [u8; 16], iterations: u32) -> Self {
        let check = keyed(vault_id, password, &salt, iterations, epoch).unwrap().finalize().into_bytes().into();
        Self { epoch, membership_sequence, salt, iterations, check }
    }

    #[cfg(test)]
    fn to_payload(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "membershipSequence": self.membership_sequence,
            "salt": STANDARD.encode(self.salt),
            "memoryKib": MEMORY_KIB,
            "iterations": self.iterations,
            "parallelism": PARALLELISM,
            "check": STANDARD.encode(self.check),
        })
    }
}

/// HMAC-SHA256 under Argon2id(password), fed "nuvori-master-password-check-v1\n<vaultId>\n<epoch>".
fn keyed(vault_id: &str, password: &str, salt: &[u8; 16], iterations: u32, epoch: u64) -> Option<Hmac<Sha256>> {
    let params = Params::new(MEMORY_KIB, iterations, PARALLELISM, Some(32)).ok()?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .ok()?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*key).ok()?;
    mac.update(format!("{LABEL}\n{vault_id}\n{epoch}").as_bytes());
    Some(mac)
}

fn number(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key)?.as_u64().filter(|value| (1..=MAX_NUMBER).contains(value))
}

fn bytes<const N: usize>(object: &Map<String, Value>, key: &str) -> Option<[u8; N]> {
    let text = object.get(key)?.as_str()?;
    let decoded = STANDARD.decode(text).ok()?;
    // STANDARD already wants canonical padding and zero unused bits; the round trip makes it plain.
    if STANDARD.encode(&decoded) != text {
        return None;
    }
    decoded.try_into().ok()
}

/// The payload of this PC's switch to check `epoch`.
pub fn switched_payload(epoch: u64) -> Value {
    json!({ "switchedEpoch": epoch })
}

fn parse_switched(payload: &Value) -> Option<u64> {
    let object = payload.as_object()?;
    if object.len() != 1 {
        return None;
    }
    number(object, "switchedEpoch")
}

/// What one `master_password` change says.
#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    /// Under the vault ID: a password check. Whether its author may write one is decided by [current].
    Check(PasswordCheck),
    /// Under the author's own device ID: the author switched to this check epoch.
    Switched(u64),
}

/// The record a change holds, or `None` when the change is invalid: a delete, an entity ID that is
/// neither the vault ID nor the author's own device ID, or a payload of the wrong shape for its ID.
pub fn read(vault_id: &str, author: &str, entity_id: &str, upsert: bool, payload: &Value) -> Option<Record> {
    if !upsert {
        return None;
    }
    if entity_id == vault_id {
        PasswordCheck::parse(payload).map(Record::Check)
    } else if entity_id == author {
        parse_switched(payload).map(Record::Switched)
    } else {
        None
    }
}

/// A password check held here, with its author and change hash.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub author: String,
    pub hash: String,
    pub check: PasswordCheck,
}

/// The check every device must hold: the highest epoch, then the highest membership sequence, then
/// the highest change hash, among the checks whose membership sequence is within `head` and whose
/// author was the managing device once that membership event applied (`manager_after`). Checks of
/// any other device are ignored, so a former manager's check from before a transfer still counts
/// and one it wrote afterwards does not.
pub fn current(candidates: Vec<Candidate>, head: u64, manager_after: impl Fn(u64) -> Option<String>) -> Option<Candidate> {
    candidates
        .into_iter()
        .filter(|candidate| {
            let sequence = candidate.check.membership_sequence;
            (1..=head).contains(&sequence) && manager_after(sequence).as_deref() == Some(candidate.author.as_str())
        })
        .max_by(|a, b| {
            (a.check.epoch, a.check.membership_sequence, a.hash.as_bytes())
                .cmp(&(b.check.epoch, b.check.membership_sequence, b.hash.as_bytes()))
        })
}

/// True when `device_id` holds the password of `current`: it wrote the check, it switched to that
/// epoch or a later one, or its newest ADD (or GENESIS) membership event came after the check, so its
/// pairing already proved the password.
pub fn satisfied(device_id: &str, current: &Candidate, switched_epoch: Option<u64>, added_at: Option<u64>) -> bool {
    device_id == current.author
        || switched_epoch.is_some_and(|epoch| epoch >= current.check.epoch)
        || added_at.is_some_and(|sequence| sequence > current.check.membership_sequence)
}

/// A check this device still has to switch to, with the vault ID its check is bound to.
#[derive(Clone, Debug)]
pub struct PendingSwitch {
    pub vault_id: String,
    pub current: Candidate,
}

impl PendingSwitch {
    /// True when `password` is the managing device's new master password. One Argon2id run.
    pub fn matches(&self, password: &str) -> bool {
        self.current.check.matches(&self.vault_id, password)
    }
}

/// What a membership event means for this protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Genesis,
    Add,
    Transfer,
    Other,
}

/// The managing device once each membership event applied: entry `i` is the manager after event
/// `i + 1`. GENESIS makes its subject the manager and TRANSFER hands the role to its subject. The
/// events are a verified history (`membership::verify`), so every prefix of it is valid too.
pub fn managers_after(steps: &[(Step, &str)]) -> Vec<String> {
    let mut manager = String::new();
    steps
        .iter()
        .map(|(step, subject)| {
            if matches!(step, Step::Genesis | Step::Transfer) {
                manager = (*subject).to_owned();
            }
            manager.clone()
        })
        .collect()
}

/// The sequence of `device_id`'s newest GENESIS or ADD event, if any.
pub fn added_at(steps: &[(Step, &str)], device_id: &str) -> Option<u64> {
    steps
        .iter()
        .zip(1_u64..)
        .filter(|((step, subject), _)| matches!(step, Step::Genesis | Step::Add) && *subject == device_id)
        .map(|(_, sequence)| sequence)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../fixtures/master-password-v1.json")).unwrap()
    }

    fn text(value: &Value) -> &str {
        value.as_str().unwrap()
    }

    #[test]
    fn the_shared_vectors_describe_this_protocol() {
        let vectors = vectors();
        assert_eq!(vectors["feature"], FEATURE);
        assert_eq!(vectors["entityType"], ENTITY_TYPE);
        assert_eq!(vectors["label"], LABEL);
        assert_eq!(vectors["memoryKib"], MEMORY_KIB);
        assert_eq!(vectors["minIterations"], MIN_ITERATIONS);
        assert_eq!(vectors["maxIterations"], MAX_ITERATIONS);
    }

    #[test]
    fn a_check_matches_only_its_password_vault_and_epoch() {
        for case in vectors()["checks"].as_array().unwrap() {
            let name = text(&case["name"]);
            let check = PasswordCheck::parse(&case["payload"]).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(hex::encode(check.check), text(&case["checkHex"]), "{name}");
            for variant in case["variants"].as_array().unwrap() {
                let mut tested = check.clone();
                tested.epoch = variant["epoch"].as_u64().unwrap();
                assert_eq!(
                    tested.matches(text(&variant["vaultId"]), text(&variant["password"])),
                    variant["matches"].as_bool().unwrap(),
                    "{name}: {variant}"
                );
            }
        }
    }

    #[test]
    fn a_check_this_side_makes_is_the_one_in_the_vectors() {
        for case in vectors()["checks"].as_array().unwrap() {
            let parsed = PasswordCheck::parse(&case["payload"]).unwrap();
            let made = PasswordCheck::create(text(&case["vaultId"]), text(&case["password"]), parsed.epoch,
                parsed.membership_sequence, parsed.salt, parsed.iterations);
            assert_eq!(made, parsed, "{}", case["name"]);
            assert_eq!(made.to_payload(), case["payload"], "{}", case["name"]);
        }
    }

    #[test]
    fn payloads_outside_the_protocol_are_refused() {
        let vectors = vectors();
        for payload in vectors["payloads"]["check"]["valid"].as_array().unwrap() {
            let check = PasswordCheck::parse(payload).unwrap_or_else(|| panic!("{payload}"));
            assert_eq!(check.to_payload(), *payload);
        }
        for payload in vectors["payloads"]["check"]["invalid"].as_array().unwrap() {
            assert_eq!(PasswordCheck::parse(payload), None, "{payload}");
        }
        for payload in vectors["payloads"]["switched"]["valid"].as_array().unwrap() {
            let epoch = parse_switched(payload).unwrap_or_else(|| panic!("{payload}"));
            assert_eq!(switched_payload(epoch), *payload);
        }
        for payload in vectors["payloads"]["switched"]["invalid"].as_array().unwrap() {
            assert_eq!(parse_switched(payload), None, "{payload}");
        }
    }

    #[test]
    fn a_change_is_a_check_under_the_vault_id_and_a_switch_under_its_own_device_id() {
        for case in vectors()["records"].as_array().unwrap() {
            let record = read(text(&case["vaultId"]), text(&case["author"]), text(&case["entityId"]),
                case["kind"] == "upsert", &case["payload"]);
            let kind = match record {
                Some(Record::Check(_)) => "check",
                Some(Record::Switched(_)) => "switched",
                None => "invalid",
            };
            assert_eq!(kind, text(&case["expected"]), "{}", case["name"]);
        }
    }

    fn candidate(value: &Value) -> Candidate {
        Candidate {
            author: text(&value["author"]).to_owned(),
            hash: value["hash"].as_str().unwrap_or("hash").to_owned(),
            check: PasswordCheck {
                epoch: value["epoch"].as_u64().unwrap(),
                membership_sequence: value["membershipSequence"].as_u64().unwrap(),
                salt: [0; 16],
                iterations: MIN_ITERATIONS,
                check: [0; 32],
            },
        }
    }

    #[test]
    fn the_current_check_comes_from_the_manager_of_its_time() {
        for case in vectors()["current"].as_array().unwrap() {
            let managers: Vec<String> = case["managers"].as_array().unwrap().iter().map(|m| text(m).to_owned()).collect();
            let candidates = case["candidates"].as_array().unwrap().iter().map(candidate).collect();
            let chosen = current(candidates, case["head"].as_u64().unwrap(), |sequence| {
                managers.get(usize::try_from(sequence).ok()?.checked_sub(1)?).cloned()
            });
            assert_eq!(chosen.map(|c| c.hash), case["expected"].as_str().map(str::to_owned), "{}", case["name"]);
        }
    }

    #[test]
    fn a_device_holds_the_password_once_it_switched_or_joined_after() {
        for case in vectors()["satisfied"].as_array().unwrap() {
            assert_eq!(
                satisfied(text(&case["device"]), &candidate(&case["current"]), case["switchedEpoch"].as_u64(),
                    case["addedAt"].as_u64()),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn debug_output_leaves_out_the_salt_and_the_check() {
        let check = PasswordCheck { epoch: 2, membership_sequence: 3, salt: [0xAB; 16], iterations: 3, check: [0xCD; 32] };
        let shown = format!("{check:?}");
        assert!(shown.contains("epoch: 2") && !shown.contains("171") && !shown.contains("205"), "{shown}");
    }
    #[test]
    fn the_manager_moves_only_with_genesis_and_transfer() {
        let steps = [(Step::Genesis, "phone-a"), (Step::Add, "pc"), (Step::Other, "pc"), (Step::Add, "tablet"),
            (Step::Transfer, "phone-b"), (Step::Add, "laptop")];
        assert_eq!(managers_after(&steps), ["phone-a", "phone-a", "phone-a", "phone-a", "phone-b", "phone-b"]);
        assert_eq!(added_at(&steps, "phone-a"), Some(1));
        assert_eq!(added_at(&steps, "pc"), Some(2));
        assert_eq!(added_at(&steps, "laptop"), Some(6));
        // A transfer does not add its subject.
        assert_eq!(added_at(&steps, "phone-b"), None);
        assert!(managers_after(&[]).is_empty());
    }

    #[test]
    fn a_pending_switch_tests_the_password_against_its_own_vault() {
        let case = &vectors()["checks"][0];
        let check = PasswordCheck::parse(&case["payload"]).unwrap();
        let pending = PendingSwitch {
            vault_id: text(&case["vaultId"]).to_owned(),
            current: Candidate { author: "phone".to_owned(), hash: "h".to_owned(), check },
        };
        assert!(pending.matches(text(&case["password"])));
        assert!(!pending.matches("not the password"));
    }
}
