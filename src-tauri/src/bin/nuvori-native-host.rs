use serde_json::from_slice;
use std::io::{self, Read, Write};

#[path = "../activity.rs"]
#[allow(dead_code)]
mod activity;
#[path = "../browser.rs"]
#[allow(dead_code)]
mod browser;
#[path = "../browser_ipc.rs"]
#[allow(dead_code)]
mod browser_ipc;
#[path = "../dpapi.rs"]
mod dpapi;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use browser::{BROWSER_PROTOCOL_VERSION, BrowserRequest, BrowserResponse, ItemKind, PendingDetails, PendingLogin};
use browser_ipc::{BrowserIpcError, send_to_app};
use zeroize::{Zeroize, Zeroizing};

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("Nuvori native host stopped: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let caller = std::env::args().nth(1).unwrap_or_default();
    if !is_registered_extension_origin(&caller) {
        return Err("native host caller is not an extension origin".into());
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    while let Some(mut message) = read_message(&mut reader)? {
        let parsed = from_slice::<BrowserRequest>(&message);
        message.zeroize();
        let response = match parsed {
            Ok(request) => handle(request),
            Err(_) => BrowserResponse::invalid(String::new(), "Malformed JSON request."),
        };
        write_message(&mut writer, &serde_json::to_vec(&response)?)?;
    }

    Ok(())
}

fn handle(request: BrowserRequest) -> BrowserResponse {
    if request.version != BROWSER_PROTOCOL_VERSION {
        let mut response = BrowserResponse::invalid(request.request_id, "Unsupported protocol version.");
        response.message = format!(
            "Unsupported protocol version: extension {}, native host {}.",
            request.version, BROWSER_PROTOCOL_VERSION
        );
        return response;
    }
    if let Err(message) = validate(&request) {
        return BrowserResponse::invalid(request.request_id, message);
    }
    match request.action {
        browser::BrowserAction::SealLogin => seal_login(request)
            .unwrap_or_else(|_| BrowserResponse::invalid(String::new(), "Could not encrypt this login.")),
        browser::BrowserAction::UnlockPrompt => unlock_prompt(request),
        browser::BrowserAction::SealDetails => seal_details(request)
            .unwrap_or_else(|_| BrowserResponse::invalid(String::new(), "Could not encrypt these details.")),
        browser::BrowserAction::RequestCvv => {
            // The approval window should come to the front, as the unlock window does.
            allow_foreground();
            let request_id = request.request_id.clone();
            send_to_app(&request).unwrap_or_else(|_| BrowserResponse::unavailable(request_id))
        }
        browser::BrowserAction::Status => {
            let request_id = request.request_id.clone();
            // Forward the app's own feature list unchanged; an older app without one advertises
            // nothing. When the app is unreachable, only report what this host handles alone.
            send_to_app(&request).unwrap_or_else(|_| unreachable_status(request_id))
        }
        _ => send_to_app(&request)
            .unwrap_or_else(|_| BrowserResponse::unavailable(request.request_id)),
    }
}

/// The host accepts an empty status origin and starts the app for "unlock_prompt" itself, so
/// those are the features it can promise without the app. The rest depend on the app's list.
fn unreachable_status(request_id: String) -> BrowserResponse {
    let mut response = BrowserResponse::unavailable(request_id);
    response.features = Some(vec!["status_no_origin".to_owned(), "unlock_prompt".to_owned()]);
    response
}

/// "unlock_prompt": a running app shows its unlock window if locked. Otherwise start the
/// installed app in the background, which opens only that window.
fn allow_foreground() {
    // The browser launched this host, so let the app's window come to the front.
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(
            windows::Win32::UI::WindowsAndMessaging::ASFW_ANY,
        );
    }
}

fn unlock_prompt(request: BrowserRequest) -> BrowserResponse {
    allow_foreground();
    let request_id = request.request_id.clone();
    match send_to_app(&request) {
        Ok(response) => response,
        // Something else holds the pipe name; starting Nuvori would not help.
        Err(BrowserIpcError::UntrustedServer) => BrowserResponse::unavailable(request_id),
        Err(_) => match launch_app() {
            Ok(()) => BrowserResponse {
                version: BROWSER_PROTOCOL_VERSION,
                request_id,
                status: "starting".to_owned(),
                message: "Nuvori is starting. Enter your master password in the Nuvori window.".to_owned(),
                credentials: None,
                credential: None,
                sealed_login: None,
                features: None, item: None,
            },
            Err(_) => BrowserResponse::unavailable(request_id),
        },
    }
}

fn launch_app() -> io::Result<()> {
    use std::os::windows::{io::AsRawHandle, process::CommandExt};
    use std::process::{Command, Stdio};
    use windows::Win32::Foundation::{HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, SetHandleInformation};
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    let app = browser_ipc::installed_app_image()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Nuvori is not installed"))?;
    // The browser's message pipes must not stay open in the app after this host exits.
    for handle in [io::stdin().as_raw_handle(), io::stdout().as_raw_handle(), io::stderr().as_raw_handle()] {
        unsafe {
            let _ = SetHandleInformation(HANDLE(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        }
    }
    let spawn = |flags: u32| {
        let mut command = Command::new(&app);
        command
            .arg("--background")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags);
        if let Some(directory) = app.parent() {
            command.current_dir(directory);
        }
        command.spawn()
    };
    // Leave the browser's job so closing the browser does not close Nuvori. Some jobs forbid
    // that; the app then still starts, inside the job.
    spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP))
        .map(drop)
}

/// Shape checks before anything reaches the desktop app. The app checks again.
fn validate(request: &BrowserRequest) -> Result<(), &'static str> {
    use browser::BrowserAction as Action;
    let status = matches!(request.action, Action::Status);
    let unlock = matches!(request.action, Action::UnlockPrompt);
    // "status_no_origin": only a status ping may leave the origin empty. "unlock_prompt" never has one.
    if unlock {
        if !request.origin.is_empty() {
            return Err("The browser request is incomplete.");
        }
    } else if browser::canonical_https_origin(&request.origin).is_none() && !(status && request.origin.is_empty()) {
        return Err("Only HTTPS site origins are allowed.");
    }
    // "login_title": a name only accompanies a captured login, its commit, or a details commit.
    if let Some(title) = &request.title
        && (!matches!(request.action, Action::SealLogin | Action::CommitLogin | Action::CommitDetails) || !browser::valid_login_title(title))
    {
        return Err("The browser request is incomplete.");
    }
    // Item kinds, "all" and captured fields belong to their own actions only.
    let item_action = matches!(request.action, Action::QueryItems | Action::FillItem | Action::RequestCvv | Action::FillCvv);
    let sealing_details = matches!(request.action, Action::SealDetails);
    if (request.kind.is_some() && !item_action && !sealing_details)
        || ((item_action || sealing_details) && request.kind.is_none())
        || (request.all.is_some() && !(matches!(request.action, Action::QueryItems) && request.kind == Some(ItemKind::Code)))
        || ((request.card.is_some() || request.profile.is_some()) && !sealing_details)
    {
        return Err("The browser request is incomplete.");
    }
    let no_secrets = |request: &BrowserRequest| request.username.is_none() && request.password.is_none() && request.sealed_login.is_none();
    let sealed_ok = |sealed: &Option<String>| sealed.as_ref().is_some_and(|sealed| !sealed.is_empty() && sealed.len() <= 32768);
    let action_is_valid = match request.action {
        Action::QueryItems => {
            request.credential_id.is_none() && request.selection_token.is_none() && no_secrets(request)
        }
        Action::FillItem | Action::RequestCvv | Action::FillCvv => {
            request.credential_id.as_deref().is_some_and(|id| !id.is_empty() && id.len() <= 256)
                && request.selection_token.as_deref().is_some_and(|token| !token.is_empty() && token.len() <= 512)
                && no_secrets(request)
                && (matches!(request.action, Action::FillItem) || request.kind == Some(ItemKind::Card))
        }
        Action::SealDetails => {
            request.credential_id.is_none() && request.selection_token.is_none() && no_secrets(request)
                && match request.kind {
                    Some(ItemKind::Card) => request.profile.is_none() && request.card.as_ref().is_some_and(browser::valid_card_capture),
                    Some(ItemKind::Profile) => request.card.is_none() && request.profile.as_ref().is_some_and(browser::valid_profile_capture),
                    _ => false,
                }
        }
        Action::ReviewDetails | Action::CommitDetails => {
            request.credential_id.is_none() && request.selection_token.is_none()
                && request.username.is_none() && request.password.is_none()
                && sealed_ok(&request.sealed_login)
        }
        Action::Status | Action::QueryCredentials | Action::UnlockPrompt => {
            request.credential_id.is_none() && request.selection_token.is_none()
                && request.username.is_none() && request.password.is_none()
                && request.sealed_login.is_none()
        }
        Action::FillCredential => {
            request.credential_id.as_deref().is_some_and(|id| !id.is_empty() && id.len() <= 256)
                && request.selection_token.as_deref().is_some_and(|token| !token.is_empty() && token.len() <= 512)
                && request.username.is_none() && request.password.is_none()
                && request.sealed_login.is_none()
        }
        Action::SealLogin => {
            request.credential_id.is_none() && request.selection_token.is_none()
                && request.sealed_login.is_none()
                // "password_only": an empty username is allowed, a blank one is not.
                && request.username.as_deref().is_some_and(browser::valid_capture_username)
                && request.password.as_ref().is_some_and(|password| !password.is_empty() && password.len() <= 4096)
        }
        Action::CommitLogin | Action::ReviewLogin => {
            request.credential_id.is_none() && request.selection_token.is_none()
                // "login_edit": a save may correct the captured username.
                && request.username.as_deref().is_none_or(|username| {
                    matches!(request.action, Action::CommitLogin) && browser::valid_capture_username(username)
                })
                && request.password.is_none()
                && sealed_ok(&request.sealed_login)
        }
        Action::UpdateLogin => {
            request.username.is_none() && request.password.is_none()
                && request.credential_id.as_ref().is_some_and(|id| !id.is_empty() && id.len() <= 256)
                && request.selection_token.as_ref().is_some_and(|token| token.len() == 64)
                && sealed_ok(&request.sealed_login)
        }
        // Only a second app launch sends these, never the extension.
        Action::ShowApp | Action::HandOver => false,
    };
    if !action_is_valid || request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err("The browser request is incomplete.");
    }
    Ok(())
}

fn seal_login(mut request: BrowserRequest) -> Result<BrowserResponse, Box<dyn std::error::Error>> {
    let mut password = Zeroizing::new(request.password.take().ok_or("Missing password")?);
    let login = PendingLogin {
        version: 1,
        origin: request.origin,
        username: request.username.take().ok_or("Missing username")?,
        password: std::mem::take(&mut *password),
        created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        title: request.title.take().filter(|title| !title.trim().is_empty()),
    };
    let mut bytes = Zeroizing::new(serde_json::to_vec(&login)?);
    password.zeroize();
    let sealed = URL_SAFE_NO_PAD.encode(dpapi::protect(&bytes, "Nuvori pending browser login")?);
    bytes.zeroize();
    Ok(BrowserResponse {
        version: BROWSER_PROTOCOL_VERSION,
        request_id: request.request_id,
        status: "sealed".to_owned(),
        message: String::new(),
        credentials: None,
        credential: None,
        sealed_login: Some(sealed), features: None, item: None,
    })
}

/// "save_details": encrypt a captured card or address for this site, without the app.
fn seal_details(mut request: BrowserRequest) -> Result<BrowserResponse, Box<dyn std::error::Error>> {
    let details = PendingDetails {
        version: 1,
        origin: request.origin,
        kind: request.kind.ok_or("Missing kind")?,
        card: request.card.take(),
        profile: request.profile.take(),
        created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    let mut bytes = Zeroizing::new(serde_json::to_vec(&details)?);
    drop(details);
    let sealed = URL_SAFE_NO_PAD.encode(dpapi::protect(&bytes, "Nuvori pending browser details")?);
    bytes.zeroize();
    Ok(BrowserResponse {
        version: BROWSER_PROTOCOL_VERSION,
        request_id: request.request_id,
        status: "sealed".to_owned(),
        message: String::new(),
        credentials: None,
        credential: None,
        sealed_login: Some(sealed), features: None, item: None,
    })
}

fn is_registered_extension_origin(value: &str) -> bool {
    let origin = value.strip_suffix('/').unwrap_or(value);
    if !is_extension_origin(origin) {
        return false;
    }
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let manifest_path = std::path::PathBuf::from(local_app_data)
        .join("Nuvori")
        .join("BrowserHost")
        .join("com.nuvori.desktop.json");
    let Ok(manifest) = std::fs::read(manifest_path) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_slice::<NativeHostManifest>(&manifest) else {
        return false;
    };
    manifest
        .allowed_origins
        .iter()
        .any(|allowed| allowed.strip_suffix('/') == Some(origin))
}

fn is_extension_origin(value: &str) -> bool {
    browser::is_extension_origin(value)
}

#[derive(serde::Deserialize)]
struct NativeHostManifest {
    allowed_origins: Vec<String>,
}

fn read_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0_u8; 4];
    match reader.read_exact(&mut length_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let length = u32::from_le_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid message length",
        ));
    }

    let mut message = vec![0_u8; length];
    reader.read_exact(&mut message)?;
    Ok(Some(message))
}

fn write_message(writer: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let length = u32::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message is too large"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(message)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_extension_origins() {
        assert!(browser::is_extension_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(!browser::is_extension_origin(
            "moz-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
    }

    #[test]
    fn rejects_non_extension_callers() {
        assert!(!browser::is_extension_origin("https://example.com"));
        assert!(!browser::is_extension_origin(""));
    }

    #[test]
    fn registered_extension_origin_requires_exact_manifest_match() {
        let allowed = ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"];
        let matches = |caller: &str| {
            let caller = caller.strip_suffix('/').unwrap_or(caller);
            allowed
                .iter()
                .any(|origin| origin.strip_suffix('/') == Some(caller))
        };
        assert!(matches(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        ));
        assert!(matches(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        ));
        assert!(!matches(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop//"
        ));
        assert!(!matches(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnopx"
        ));
    }

    #[test]
    fn reads_a_framed_message() {
        let payload = br#"{"version":1}"#;
        let mut framed = Vec::from((payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(payload);

        assert_eq!(
            read_message(&mut framed.as_slice()).unwrap(),
            Some(payload.to_vec())
        );
    }

    fn parse(json: &str) -> BrowserRequest {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn status_may_omit_the_origin_but_other_actions_may_not() {
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"status","origin":""}"#)).is_ok());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"status","origin":"https://status.nuvori.invalid"}"#)).is_ok());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"query_credentials","origin":""}"#)).is_err());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"status","origin":"http://a.example"}"#)).is_err());
    }

    #[test]
    fn unlock_prompt_has_no_origin_or_fields_and_show_app_is_refused() {
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"unlock_prompt","origin":""}"#)).is_ok());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"unlock_prompt","origin":"https://a.example"}"#)).is_err());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"unlock_prompt","origin":"","username":"u"}"#)).is_err());
        assert!(validate(&parse(r#"{"version":2,"requestId":"r","action":"show_app","origin":""}"#)).is_err());
    }

    #[test]
    fn item_requests_need_their_kind_and_only_their_fields() {
        let ok = |json: &str| validate(&parse(json)).is_ok();
        assert!(ok(r#"{"version":2,"requestId":"r","action":"query_items","origin":"https://a.example","kind":"card"}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"query_items","origin":"https://a.example","kind":"code","all":true}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"query_items","origin":"https://a.example","kind":"card","all":true}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"query_items","origin":"https://a.example"}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"query_credentials","origin":"https://a.example","kind":"card"}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"fill_item","origin":"https://a.example","kind":"profile","credentialId":"i","selectionToken":"t"}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"request_cvv","origin":"https://a.example","kind":"profile","credentialId":"i","selectionToken":"t"}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"seal_details","origin":"https://a.example","kind":"card","card":{"number":"4111111111111111","expiry":"12/29"}}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"seal_details","origin":"https://a.example","kind":"card","card":{"number":"4111111111111111","cvv":"123"}}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"seal_details","origin":"https://a.example","kind":"profile","card":{"number":"4111111111111111"}}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"seal_details","origin":"https://a.example","kind":"profile","profile":{"city":"Pune"}}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"query_credentials","origin":"https://a.example","profile":{"city":"Pune"}}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"commit_login","origin":"https://a.example","sealedLogin":"x","username":"fixed"}"#));
        assert!(!ok(r#"{"version":2,"requestId":"r","action":"review_login","origin":"https://a.example","sealedLogin":"x","username":"fixed"}"#));
        assert!(ok(r#"{"version":2,"requestId":"r","action":"commit_details","origin":"https://a.example","sealedLogin":"x","title":"Home"}"#));
    }

    #[test]
    fn sealed_details_open_only_as_details() {
        let request = parse(r#"{"version":2,"requestId":"r","action":"seal_details","origin":"https://a.example","kind":"card","card":{"number":"4111111111111111","expiry":"12/29","name":"A"}}"#);
        let sealed = seal_details(request).unwrap().sealed_login.unwrap();
        let bytes = dpapi::unprotect(&URL_SAFE_NO_PAD.decode(sealed).unwrap()).unwrap();
        let details: PendingDetails = serde_json::from_slice(&bytes).unwrap();
        assert_eq!((details.origin.as_str(), details.card.as_ref().unwrap().number.as_str()), ("https://a.example", "4111111111111111"));
        assert!(serde_json::from_slice::<PendingLogin>(&bytes).is_err(), "a sealed card is never a login");
    }

    #[test]
    fn seal_accepts_password_only_and_bounded_titles() {
        let seal = |username: &str, title: &str| parse(&format!(
            r#"{{"version":2,"requestId":"r","action":"seal_login","origin":"https://a.example","username":{},"password":"p"{}}}"#,
            serde_json::to_string(username).unwrap(),
            if title.is_empty() { String::new() } else { format!(r#","title":{}"#, serde_json::to_string(title).unwrap()) }
        ));
        assert!(validate(&seal("", "")).is_ok());
        assert!(validate(&seal("alice", "Work")).is_ok());
        assert!(validate(&seal("   ", "")).is_err());
        assert!(validate(&seal("alice", &"t".repeat(257))).is_err());
        assert!(validate(&seal("alice", "a\u{1}b")).is_err());
        let titled_commit = parse(r#"{"version":2,"requestId":"r","action":"commit_login","origin":"https://a.example","sealedLogin":"x","title":"Mine"}"#);
        assert!(validate(&titled_commit).is_ok());
        let titled_review = parse(r#"{"version":2,"requestId":"r","action":"review_login","origin":"https://a.example","sealedLogin":"x","title":"Mine"}"#);
        assert!(validate(&titled_review).is_err());
    }

    #[test]
    fn sealed_login_keeps_its_title_and_opens_without_one() {
        let request = parse(r#"{"version":2,"requestId":"r","action":"seal_login","origin":"https://a.example","username":"","password":"p","title":"  Home router "}"#);
        let response = seal_login(request).unwrap();
        let bytes = dpapi::unprotect(&URL_SAFE_NO_PAD.decode(response.sealed_login.unwrap()).unwrap()).unwrap();
        let pending: PendingLogin = serde_json::from_slice(&bytes).unwrap();
        assert_eq!((pending.username.as_str(), pending.title.as_deref()), ("", Some("  Home router ")));
        let request = parse(r#"{"version":2,"requestId":"r","action":"seal_login","origin":"https://a.example","username":"u","password":"p","title":"   "}"#);
        let bytes = dpapi::unprotect(&URL_SAFE_NO_PAD.decode(seal_login(request).unwrap().sealed_login.unwrap()).unwrap()).unwrap();
        assert!(!String::from_utf8(bytes.to_vec()).unwrap().contains("title"));
    }

    #[test]
    fn unreachable_app_advertises_only_host_features() {
        let response = unreachable_status("r".into());
        assert_eq!(response.status, "desktop_unavailable");
        assert_eq!(response.features, Some(vec!["status_no_origin".to_owned(), "unlock_prompt".to_owned()]));
    }
}
