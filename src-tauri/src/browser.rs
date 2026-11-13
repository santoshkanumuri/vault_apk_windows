use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const BROWSER_PROTOCOL_VERSION: u16 = 2;

/// Optional protocol additions this host and app understand. `status` responses list them in
/// `features`; an extension sends the matching new fields only when the feature is listed,
/// because requests use `deny_unknown_fields` and older builds reject unknown fields.
pub const BROWSER_FEATURES: [&str; 11] = [
    "status_no_origin", "login_title", "password_only", "multi_update", "unlock_prompt",
    "cards", "profiles", "codes", "save_details", "login_edit", "related_logins",
];

/// Longest login title accepted from the extension, in characters.
pub const MAX_LOGIN_TITLE_CHARS: usize = 256;
/// Android `newLoginTitle` keeps at most this many characters.
const SAVED_TITLE_CHARS: usize = 200;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRequest {
    pub version: u16,
    pub request_id: String,
    pub action: BrowserAction,
    pub origin: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default)]
    pub selection_token: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub sealed_login: Option<String>,
    /// "login_title": optional name for a new login on `seal_login` and `commit_login`, or for
    /// a new card or address on `commit_details`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// "cards", "profiles", "codes": the item type for `query_items`, `fill_item`, `request_cvv`
    /// and `fill_cvv`, and for a `seal_details` capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ItemKind>,
    /// "codes": list every code instead of only those that match the site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>,
    /// "save_details": a card captured from a submitted form (`seal_details` only, never a CVV).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardDetails>,
    /// "save_details": an address or contact profile captured from a submitted form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDetails>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAction {
    #[default]
    Status,
    QueryCredentials,
    FillCredential,
    SealLogin,
    CommitLogin,
    UpdateLogin,
    ReviewLogin,
    /// "unlock_prompt": show the small unlock window if the vault is locked. The native host
    /// starts the app in the background first when it isn't running. No origin or fields.
    UnlockPrompt,
    /// A second app launch asks the running app to show its main window. Never sent by the
    /// extension; the native host rejects it.
    ShowApp,
    /// "cards" / "profiles" / "codes": list items of `kind` with one-use selection tokens.
    QueryItems,
    /// Release one listed item. A card comes without its security code.
    FillItem,
    /// Ask the user, in a Nuvori window, to release a card's security code.
    RequestCvv,
    /// The security code once the user approved it; `pending` until then.
    FillCvv,
    /// "save_details": the native host encrypts a captured card or address (DPAPI).
    SealDetails,
    /// Is a sealed card or address already in the vault?
    ReviewDetails,
    /// Save a sealed card or address as a new item. Never changes an existing one.
    CommitDetails,
    /// "hand_over": the Microsoft Store build asks a running installer-build copy to close so
    /// that it can run instead. Never sent by the extension; the native host rejects it, and
    /// the app accepts it only from a process of the recorded Store package.
    HandOver,
}

impl BrowserAction {
    /// Actions that only open an app window: no origin, no credential fields, no vault access.
    pub fn is_window_request(&self) -> bool {
        matches!(self, Self::UnlockPrompt | Self::ShowApp)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingLogin {
    pub version: u16,
    pub origin: String,
    pub username: String,
    pub password: String,
    pub created_at: i64,
    /// Absent in logins sealed before "login_title"; they still open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl Drop for PendingLogin {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialChoice {
    pub id: String,
    pub title: String,
    pub username: String,
    pub selection_token: String,
    /// "related_logins": saved for another page of the same site (same registrable domain).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub related: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedCredential {
    pub id: String,
    pub username: String,
    pub password: String,
}

/// Which kind of vault item a browser request is about.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Card,
    Profile,
    Code,
}

/// Card fields as the extension sees them. `fill_item` never includes `cvv`; `fill_cvv` returns
/// only `cvv`. Captures never carry one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardDetails {
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub name: String,
    /// "MM/YY".
    #[serde(default)]
    pub expiry: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvv: String,
    #[serde(default)]
    pub network: String,
}

impl CardDetails {
    /// A card with only these fields set (`Drop` rules out struct-update syntax).
    pub fn with(number: &str, expiry: &str, cvv: &str) -> Self {
        let mut card = Self::default();
        card.number = number.to_owned();
        card.expiry = expiry.to_owned();
        card.cvv = cvv.to_owned();
        card
    }
}

impl Drop for CardDetails {
    fn drop(&mut self) {
        self.number.zeroize();
        self.cvv.zeroize();
    }
}

/// The app's contact profile (an "AUTOFILL" item), field for field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDetails {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address1: String,
    #[serde(default)]
    pub address2: String,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
}

impl ProfileDetails {
    pub fn fields(&self) -> [&String; 10] {
        [&self.name, &self.email, &self.phone, &self.address1, &self.address2, &self.unit,
            &self.city, &self.state, &self.postal_code, &self.country]
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeValue {
    pub value: String,
    pub seconds_left: u64,
}

impl Drop for CodeValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// One released item (`fill_item`, `fill_cvv`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilledItem {
    pub id: String,
    pub kind: ItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CardDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<CodeValue>,
    /// A card with a saved security code: the one-use token for `request_cvv` / `fill_cvv`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvv_token: Option<String>,
}

/// A captured card or address, sealed by the native host until the user saves it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingDetails {
    pub version: u16,
    pub origin: String,
    pub kind: ItemKind,
    #[serde(default)]
    pub card: Option<CardDetails>,
    #[serde(default)]
    pub profile: Option<ProfileDetails>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserResponse {
    pub version: u16,
    pub request_id: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<CredentialChoice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<SelectedCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_login: Option<String>,
    /// Present on `status` responses only. See `BROWSER_FEATURES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    /// `fill_item` and `fill_cvv`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<FilledItem>,
}

impl BrowserResponse {
    pub fn unavailable(request_id: String) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            status: "desktop_unavailable".to_owned(),
            message: "Unlock Nuvori for Windows to use browser filling.".to_owned(),
            credentials: None,
            credential: None,
            sealed_login: None,
            features: None, item: None,
        }
    }

    /// Adds the feature list; used on every `status` response.
    pub fn with_features(mut self) -> Self {
        self.features = Some(BROWSER_FEATURES.iter().map(|feature| (*feature).to_owned()).collect());
        self
    }

    pub fn invalid(request_id: String, message: &'static str) -> Self {
        Self {
            version: BROWSER_PROTOCOL_VERSION,
            request_id,
            status: "invalid_request".to_owned(),
            message: message.to_owned(),
            credentials: None,
            credential: None,
            sealed_login: None,
            features: None, item: None,
        }
    }
}

/// A requested login title is at most 256 characters with no control characters.
/// Whitespace-only is allowed and means "use the default".
pub fn valid_login_title(title: &str) -> bool {
    title.chars().count() <= MAX_LOGIN_TITLE_CHARS
        && !title.chars().any(|c| c.is_control() || is_format_char(c))
}

/// Unicode general category Cf (format characters), e.g. bidi overrides like U+202E that can
/// make a saved name display differently from what it contains.
pub fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Mirrors Android `newLoginTitle(requested, default)` with the browser default
/// `origin.removePrefix("https://")`: trim, keep 200 characters, trim the end, else the default.
pub fn new_login_title(requested: Option<&str>, origin: &str) -> String {
    requested
        .map(|title| {
            title
                .trim()
                .chars()
                .take(SAVED_TITLE_CHARS)
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| origin.strip_prefix("https://").unwrap_or(origin).to_owned())
}

/// Card number digits only.
pub fn card_digits(number: &str) -> String {
    number.chars().filter(char::is_ascii_digit).collect()
}

/// The Luhn checksum every payment card number carries.
pub fn luhn_valid(digits: &str) -> bool {
    if !(12..=19).contains(&digits.len()) || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = digits.bytes().rev().enumerate().map(|(index, byte)| {
        let digit = u32::from(byte - b'0');
        if index % 2 == 1 { if digit * 2 > 9 { digit * 2 - 9 } else { digit * 2 } } else { digit }
    }).sum();
    sum % 10 == 0
}

/// "MM/YY" from "MM/YY", "MM/YYYY", "MMYY" or "M / YY"; `None` otherwise.
pub fn normalize_expiry(value: &str) -> Option<String> {
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    let separated = value.contains('/') || value.contains('-');
    let (month, year) = if separated {
        let mut parts = value.split(['/', '-']).map(|part| part.trim());
        let month = parts.next()?;
        let year = parts.next()?;
        if parts.next().is_some() || !month.bytes().all(|b| b.is_ascii_digit()) || !year.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        (month.to_owned(), year.to_owned())
    } else if digits.len() == 4 || digits.len() == 6 {
        (digits[..2].to_owned(), digits[2..].to_owned())
    } else {
        return None;
    };
    let month: u32 = month.parse().ok().filter(|month| (1..=12).contains(month))?;
    let year = match year.len() { 2 => year, 4 if year.starts_with("20") => year[2..].to_owned(), _ => return None };
    Some(format!("{month:02}/{year}"))
}

/// The card network a number belongs to, for display and the saved item's "Network".
pub fn card_network(digits: &str) -> &'static str {
    let prefix = |length: usize| digits.get(..length).and_then(|part| part.parse::<u32>().ok()).unwrap_or(0);
    match (prefix(1), prefix(2), prefix(3), prefix(4)) {
        (4, ..) => "Visa",
        (_, 34 | 37, ..) => "American Express",
        (_, 51..=55, ..) | (.., 2221..=2720) => "Mastercard",
        (_, 60 | 81 | 82, ..) if prefix(4) != 6011 => "RuPay",
        (_, _, 508, _) => "RuPay",
        (.., 6011) | (_, 65, ..) | (_, _, 644..=649, _) => "Discover",
        (.., 3528..=3589) => "JCB",
        (_, 36 | 38, ..) | (_, _, 300..=305, _) => "Diners Club",
        _ => "",
    }
}

fn clean_text(value: &str, max_chars: usize) -> bool {
    value.chars().count() <= max_chars && !value.chars().any(|c| c.is_control() || is_format_char(c))
}

/// A card captured from a page: a Luhn-valid number, a valid or empty expiry, and never a CVV.
pub fn valid_card_capture(card: &CardDetails) -> bool {
    let digits = card_digits(&card.number);
    digits == card.number && luhn_valid(&digits) && card.cvv.is_empty()
        && clean_text(&card.name, 200) && clean_text(&card.network, 40)
        && (card.expiry.is_empty() || normalize_expiry(&card.expiry).as_deref() == Some(card.expiry.as_str()))
}

/// An address or contact captured from a page: short plain-text fields, at least one filled.
pub fn valid_profile_capture(profile: &ProfileDetails) -> bool {
    profile.fields().iter().all(|field| clean_text(field, 256))
        && profile.fields().iter().any(|field| !field.trim().is_empty())
}

/// A browser-captured username: empty for a password-only form ("password_only"),
/// otherwise not blank and at most 1024 bytes.
pub fn valid_capture_username(username: &str) -> bool {
    username.len() <= 1024 && (username.is_empty() || !username.trim().is_empty())
}

/// Accept only the canonical HTTPS origin shape emitted by `URL.origin`.
/// The caller must still compare the whole value to the stored origin exactly.
pub fn canonical_https_origin(value: &str) -> Option<String> {
    let origin = stored_login_origin(value)?;
    (origin == value).then_some(origin)
}

/// Check WebAuthn's RP ID rule against a canonical HTTPS origin.
/// RP IDs may be the origin host or a registrable parent domain, never a public suffix or IP.
pub fn rp_id_matches_origin(rp_id: &str, origin: &str) -> bool {
    if rp_id.is_empty()
        || rp_id.len() > 253
        || rp_id != rp_id.to_ascii_lowercase()
        || rp_id.ends_with('.')
        || rp_id.contains(['/', ':', '@'])
        || rp_id.parse::<std::net::IpAddr>().is_ok()
        || (rp_id != "localhost" && psl::domain(rp_id.as_bytes()).is_none())
    {
        return false;
    }
    let Some(origin) = canonical_https_origin(origin) else {
        return false;
    };
    let Ok(parsed) = url::Url::parse(&origin) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

pub fn stored_login_origin(login_url: &str) -> Option<String> {
    let parsed = url::Url::parse(login_url).ok()?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?;
    if !valid_host(host) {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn valid_host(host: &str) -> bool {
    let address = host.trim_start_matches('[').trim_end_matches(']');
    if address.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// The registrable domain of an HTTPS origin ("https://login.example.co.uk" -> "example.co.uk"),
/// or `None` for an IP address or a host that is itself a public suffix.
fn registrable_site(origin: &str) -> Option<String> {
    let parsed = url::Url::parse(origin).ok()?;
    let host = match parsed.host()? {
        url::Host::Domain(domain) => domain.to_ascii_lowercase(),
        _ => return None,
    };
    psl::domain_str(&host).map(str::to_owned)
}

/// A login saved for another page of the same site: both HTTPS, a different origin, and the same
/// registrable domain. Sites under a public suffix (`a.github.io`, `b.github.io`) are different.
pub fn login_url_same_site(login_url: &str, request_origin: &str) -> bool {
    let (Some(request), Some(stored)) = (canonical_https_origin(request_origin), stored_login_origin(login_url)) else {
        return false;
    };
    request != stored && registrable_site(&request).is_some_and(|site| registrable_site(&stored).as_deref() == Some(site.as_str()))
}

pub fn login_url_matches_origin(login_url: &str, request_origin: &str) -> bool {
    let request = canonical_https_origin(request_origin);
    let stored = stored_login_origin(login_url);
    request.is_some() && request == stored
}

pub fn is_extension_origin(value: &str) -> bool {
    let Some((scheme, id)) = value.split_once("-extension://") else {
        return false;
    };
    scheme == "chrome" && id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_https_origins() {
        assert!(canonical_https_origin("https://example.com").is_some());
        assert!(canonical_https_origin("https://login.example.com:8443").is_some());
        assert!(canonical_https_origin("https://[2001:db8::1]").is_some());
    }

    #[test]
    fn rejects_non_origins_and_non_https_sites() {
        for value in [
            "http://example.com",
            "https://example.com/",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com?next=/",
            "https://example.com#fragment",
            "https://example..com",
            "https://example.com\\@evil.test",
        ] {
            assert!(canonical_https_origin(value).is_none(), "accepted {value}");
        }
    }

    #[test]
    fn stored_login_matching_uses_the_exact_canonical_origin() {
        assert!(login_url_matches_origin(
            "https://example.com/login?next=%2Faccount",
            "https://example.com"
        ));
        assert!(!login_url_matches_origin(
            "https://sub.example.com/login",
            "https://example.com"
        ));
        assert!(!login_url_matches_origin(
            "https://example.com.evil.test/login",
            "https://example.com"
        ));
        assert!(!login_url_matches_origin(
            "https://user:password@example.com/login",
            "https://example.com"
        ));
        assert!(!login_url_matches_origin(
            "http://example.com/login",
            "https://example.com"
        ));
        assert!(!login_url_matches_origin(
            "https://example.com/login",
            "https://EXAMPLE.com"
        ));
    }

    #[test]
    fn extension_origin_must_have_a_chromium_extension_id() {
        assert!(is_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!is_extension_origin("https://example.com"));
        assert!(!is_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(!is_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop?x"
        ));
    }

    #[test]
    fn rp_id_must_be_origin_host_or_registrable_parent() {
        assert!(rp_id_matches_origin(
            "example.com",
            "https://login.example.com"
        ));
        assert!(rp_id_matches_origin(
            "login.example.com",
            "https://login.example.com"
        ));
        for (rp_id, origin) in [
            ("com", "https://login.example.com"),
            ("example.com.evil.test", "https://example.com"),
            ("EXAMPLE.com", "https://example.com"),
            ("127.0.0.1", "https://127.0.0.1"),
            ("example.com", "http://example.com"),
        ] {
            assert!(
                !rp_id_matches_origin(rp_id, origin),
                "accepted {rp_id} for {origin}"
            );
        }
    }

    #[test]
    fn requests_reject_unknown_fields_and_require_origin() {
        let request: BrowserRequest = serde_json::from_str(
            r#"{"version":2,"requestId":"r1","action":"query_credentials","origin":"https://example.com"}"#,
        )
        .unwrap();
        assert!(matches!(request.action, BrowserAction::QueryCredentials));
        assert!(request.credential_id.is_none());
        assert!(request.selection_token.is_none());

        assert!(serde_json::from_str::<BrowserRequest>(
            r#"{"version":2,"requestId":"r1","action":"query_credentials","origin":"https://example.com","secrets":true}"#,
        )
        .is_err());
        assert!(
            serde_json::from_str::<BrowserRequest>(
                r#"{"version":2,"requestId":"r1","action":"query_credentials"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn candidates_and_fill_payloads_are_separate_types() {
        let choices = vec![CredentialChoice {
            id: "record-1".to_owned(),
            title: "Work".to_owned(),
            username: "user@example.com".to_owned(),
            selection_token: "one-time-token".to_owned(), related: false
        }];
        let json = serde_json::to_value(choices).unwrap();
        assert!(json[0].get("password").is_none());

        let secret = SelectedCredential {
            id: "record-1".to_owned(),
            username: "user@example.com".to_owned(),
            password: "selected-secret".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(secret).unwrap()["password"],
            "selected-secret"
        );
    }
}

#[cfg(test)]
mod protocol_addition_tests {
    use super::*;

    #[test]
    fn old_requests_and_sealed_logins_still_parse() {
        let request: BrowserRequest = serde_json::from_str(
            r#"{"version":2,"requestId":"r","action":"commit_login","origin":"https://a.example","sealedLogin":"x"}"#,
        )
        .unwrap();
        assert!(request.title.is_none());
        let pending: PendingLogin = serde_json::from_str(
            r#"{"version":1,"origin":"https://a.example","username":"u","password":"p","createdAt":1}"#,
        )
        .unwrap();
        assert!(pending.title.is_none());
        assert!(!serde_json::to_string(&pending).unwrap().contains("title"));
        assert!(serde_json::from_str::<BrowserRequest>(
            r#"{"version":2,"requestId":"r","action":"status","origin":"","surprise":1}"#
        )
        .is_err());
    }

    #[test]
    fn titles_follow_android_new_login_title() {
        assert_eq!(new_login_title(None, "https://github.com"), "github.com");
        assert_eq!(new_login_title(Some("   "), "https://github.com:8443"), "github.com:8443");
        assert_eq!(new_login_title(Some("  Work GitHub  "), "https://github.com"), "Work GitHub");
        let long = format!("{}  tail", "a".repeat(199));
        assert_eq!(new_login_title(Some(&long), "https://x.example"), "a".repeat(199));
        assert!(valid_login_title(&"é".repeat(256)));
        assert!(!valid_login_title(&"a".repeat(257)));
        assert!(!valid_login_title("Bank\nLogin"));
        assert!(!valid_login_title("Tab\tName"));
        assert!(!valid_login_title("Bank\u{202E}moc.evil"), "bidi overrides are rejected");
        assert!(!valid_login_title("Zero\u{200B}width"));
        assert!(!valid_login_title("\u{FEFF}Mail"));
        assert!(valid_login_title("Café ☕ 日本"));
    }

    #[test]
    fn card_numbers_expiry_and_networks() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("41111111111"));
        assert_eq!(card_digits("4111 1111-1111 1111"), "4111111111111111");
        assert_eq!(normalize_expiry("7/27").as_deref(), Some("07/27"));
        assert_eq!(normalize_expiry("12/2029").as_deref(), Some("12/29"));
        assert_eq!(normalize_expiry("1229").as_deref(), Some("12/29"));
        assert_eq!(normalize_expiry("13/29"), None);
        assert_eq!(normalize_expiry("12/1999"), None);
        assert_eq!(card_network("4111111111111111"), "Visa");
        assert_eq!(card_network("5500000000000004"), "Mastercard");
        assert_eq!(card_network("2223000048400011"), "Mastercard");
        assert_eq!(card_network("378282246310005"), "American Express");
        assert_eq!(card_network("6011111111111117"), "Discover");
        assert_eq!(card_network("6070000000000000"), "RuPay");
    }

    #[test]
    fn captured_cards_and_profiles_are_checked() {
        let card = CardDetails::with;
        assert!(valid_card_capture(&card("4111111111111111", "12/29", "")));
        assert!(valid_card_capture(&card("4111111111111111", "", "")));
        assert!(!valid_card_capture(&card("4111111111111111", "12/29", "123")), "never a CVV");
        assert!(!valid_card_capture(&card("4111 1111 1111 1111", "12/29", "")), "digits only");
        assert!(!valid_card_capture(&card("4111111111111112", "12/29", "")));
        assert!(!valid_card_capture(&card("4111111111111111", "12/2029", "")), "normalized expiry only");
        assert!(valid_profile_capture(&ProfileDetails { email: "a@example.com".into(), ..Default::default() }));
        assert!(!valid_profile_capture(&ProfileDetails::default()));
        assert!(!valid_profile_capture(&ProfileDetails { name: "A\u{202E}B".into(), ..Default::default() }));
        let json = r#"{"name":"A","postalCode":"560001","country":"India"}"#;
        assert_eq!(serde_json::from_str::<ProfileDetails>(json).unwrap().postal_code, "560001");
        assert!(serde_json::from_str::<ProfileDetails>(r#"{"cvv":"1"}"#).is_err());
    }

    #[test]
    fn capture_usernames_allow_empty_but_not_blank() {
        assert!(valid_capture_username(""));
        assert!(valid_capture_username("alice"));
        assert!(!valid_capture_username("   "));
        assert!(!valid_capture_username(&"a".repeat(1025)));
    }

    #[test]
    fn status_responses_list_every_feature() {
        let response = BrowserResponse::unavailable("r".into()).with_features();
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["features"], serde_json::json!(["status_no_origin", "login_title", "password_only", "multi_update", "unlock_prompt",
            "cards", "profiles", "codes", "save_details", "login_edit", "related_logins"]));
        assert!(serde_json::to_value(BrowserResponse::unavailable("r".into())).unwrap().get("features").is_none());
    }

    #[test]
    fn related_logins_share_the_registrable_domain_but_never_a_public_suffix() {
        assert!(login_url_same_site("https://login.example.com", "https://www.example.com"));
        assert!(login_url_same_site("https://example.co.uk/sign-in", "https://accounts.example.co.uk"));
        assert!(!login_url_same_site("https://www.example.com", "https://www.example.com"), "the same origin is an exact match, not a related one");
        assert!(!login_url_same_site("https://a.github.io", "https://b.github.io"), "github.io is a public suffix");
        assert!(!login_url_same_site("https://example.com", "https://example.com.evil.test"));
        assert!(!login_url_same_site("http://login.example.com", "https://www.example.com"));
        assert!(!login_url_same_site("https://192.168.1.2", "https://192.168.1.3"));
    }
}
