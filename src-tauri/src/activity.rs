//! In-memory activity log for the UI. It lives only for the process lifetime and keeps
//! at most `CAPACITY` events. Callers must pass display-safe messages: never secrets,
//! usernames, item titles, setup links, pairing codes, or full URLs (a site host is fine).

use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

pub const CAPACITY: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Success,
    Warning,
    Error,
    Progress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Vault,
    Items,
    Sync,
    Pairing,
    Browser,
    Security,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEvent {
    pub id: u64,
    /// Unix time in milliseconds.
    pub at: u64,
    pub level: Level,
    pub category: Category,
    pub message: String,
}

struct Inner {
    next_id: u64,
    events: VecDeque<ActivityEvent>,
}

pub struct ActivityLog {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl ActivityLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner {
                next_id: 1,
                events: VecDeque::with_capacity(capacity.clamp(1, CAPACITY)),
            }),
        }
    }

    pub fn record(&self, level: Level, category: Category, message: impl Into<String>) {
        self.push(level, category, message.into(), None);
    }

    /// Like `record`, but refreshes the newest event instead of adding a duplicate when the
    /// same message was logged within `window`. Used for chatty sources such as browser lookups.
    pub fn record_coalesced(
        &self,
        level: Level,
        category: Category,
        message: impl Into<String>,
        window: Duration,
    ) {
        self.push(level, category, message.into(), Some(window));
    }

    fn push(&self, level: Level, category: Category, message: String, window: Option<Duration>) {
        let at = now_millis();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if let Some(window) = window
            && let Some(last) = inner.events.back_mut()
            && last.message == message
            && last.category == category
            && last.level == level
            && at.saturating_sub(last.at) <= window.as_millis() as u64
        {
            last.at = at;
            return;
        }
        let id = inner.next_id;
        inner.next_id += 1;
        while inner.events.len() >= self.capacity {
            inner.events.pop_front();
        }
        inner.events.push_back(ActivityEvent {
            id,
            at,
            level,
            category,
            message,
        });
    }

    /// Newest first. `None` or a limit above the capacity returns every kept event.
    pub fn recent(&self, limit: Option<usize>) -> Vec<ActivityEvent> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let limit = limit.unwrap_or(self.capacity).min(self.capacity);
        inner.events.iter().rev().take(limit).cloned().collect()
    }

    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.events.clear();
        }
    }
}

pub fn global() -> &'static ActivityLog {
    static LOG: OnceLock<ActivityLog> = OnceLock::new();
    LOG.get_or_init(|| ActivityLog::new(CAPACITY))
}

pub fn log(level: Level, category: Category, message: impl Into<String>) {
    global().record(level, category, message);
}

static DIAGNOSTICS_FILE: OnceLock<std::path::PathBuf> = OnceLock::new();
const DIAGNOSTICS_LIMIT: u64 = 256 * 1024;

/// Sets the file that keeps internal error details across restarts. Called once at startup.
#[allow(dead_code)]
pub fn set_diagnostics_file(path: std::path::PathBuf) {
    let _ = DIAGNOSTICS_FILE.set(path);
}

/// Records the detail behind an error the UI shows only as a generic message. Details come
/// from database, file, and parser errors, which carry no vault contents; they are still
/// stripped of control characters and capped.
#[allow(dead_code)]
pub fn diagnostic(category: Category, context: &str, detail: impl std::fmt::Display) {
    let detail: String = detail.to_string().chars().filter(|c| !c.is_control()).take(300).collect();
    let message = format!("{context}: {detail}");
    log(Level::Error, category, message.clone());
    let Some(path) = DIAGNOSTICS_FILE.get() else {
        return;
    };
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > DIAGNOSTICS_LIMIT) {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = writeln!(file, "{} {message}", now_millis());
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Display name for an Android entry type, safe for the activity log.
pub fn entry_kind(entry_type: &str) -> &'static str {
    match entry_type {
        "CARD" => "card",
        "PASSWORD" => "login",
        "AUTHENTICATOR" => "authenticator code",
        "QUESTION" => "security question",
        "AUTOFILL" => "autofill profile",
        "NOTE" => "note",
        _ => "item",
    }
}

/// "Saved a new login" / "Updated a card". Only the type is used, never item content.
pub fn item_saved_message(entry_type: &str, created: bool) -> String {
    let kind = entry_kind(entry_type);
    if created {
        format!("Added {} {kind}", article(kind))
    } else {
        format!("Updated {} {kind}", article(kind))
    }
}

pub fn item_deleted_message(entry_type: &str) -> String {
    let kind = entry_kind(entry_type);
    format!("Deleted {} {kind}", article(kind))
}

fn article(kind: &str) -> &'static str {
    if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    }
}

/// Reduces a canonical origin or URL to its host for browser events.
pub fn origin_host(origin: &str) -> String {
    url::Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .filter(|host| !host.is_empty() && host.len() <= 253)
        .unwrap_or_else(|| "a site".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_newest_first() {
        let log = ActivityLog::new(CAPACITY);
        for index in 0..(CAPACITY + 25) {
            log.record(Level::Info, Category::Vault, format!("event {index}"));
        }
        let events = log.recent(None);
        assert_eq!(events.len(), CAPACITY);
        assert_eq!(events[0].message, format!("event {}", CAPACITY + 24));
        assert_eq!(events[CAPACITY - 1].message, "event 25");
        assert!(events.windows(2).all(|pair| pair[0].id > pair[1].id));
        assert!(events.windows(2).all(|pair| pair[0].at >= pair[1].at));
        let limited = log.recent(Some(3));
        assert_eq!(limited.len(), 3);
        assert_eq!(limited[0].id, events[0].id);
        assert_eq!(log.recent(Some(10_000)).len(), CAPACITY);
        log.clear();
        assert!(log.recent(None).is_empty());
        log.record(Level::Success, Category::Sync, "after clear");
        assert_eq!(log.recent(None)[0].id, CAPACITY as u64 + 26);
    }

    #[test]
    fn coalesces_repeated_messages_only_within_window() {
        let log = ActivityLog::new(10);
        log.record_coalesced(Level::Info, Category::Browser, "Looked up logins for a.com", Duration::from_secs(60));
        log.record_coalesced(Level::Info, Category::Browser, "Looked up logins for a.com", Duration::from_secs(60));
        assert_eq!(log.recent(None).len(), 1);
        log.record_coalesced(Level::Info, Category::Browser, "Looked up logins for b.com", Duration::from_secs(60));
        log.record_coalesced(Level::Info, Category::Browser, "Looked up logins for b.com", Duration::ZERO);
        assert_eq!(log.recent(None).len(), 2);
    }

    #[test]
    fn serializes_the_ui_contract_shape() {
        let log = ActivityLog::new(4);
        log.record(Level::Progress, Category::Pairing, "Pairing started");
        let value = serde_json::to_value(&log.recent(Some(1))[0]).unwrap();
        assert_eq!(value["level"], "progress");
        assert_eq!(value["category"], "pairing");
        assert_eq!(value["message"], "Pairing started");
        assert!(value["id"].is_u64() && value["at"].is_u64());
    }

    #[test]
    fn item_messages_name_only_the_type_and_hosts_drop_paths() {
        assert_eq!(item_saved_message("PASSWORD", true), "Added a login");
        assert_eq!(item_saved_message("AUTHENTICATOR", false), "Updated an authenticator code");
        assert_eq!(item_deleted_message("AUTOFILL"), "Deleted an autofill profile");
        assert_eq!(origin_host("https://github.com"), "github.com");
        assert_eq!(origin_host("https://user:pw@accounts.example.com/login?x=1"), "accounts.example.com");
        assert_eq!(origin_host("not a url"), "a site");
    }
}
