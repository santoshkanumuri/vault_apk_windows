//! Google Drive for cloud sync: sign-in and the four drive operations `CloudStore` needs.
//!
//! Sign-in is OAuth for installed apps: the system browser opens Google's page, and Google
//! sends the result to a loopback address that only this PC can reach. PKCE ties that result to
//! this sign-in attempt. Nuvori asks for one permission, `drive.appdata`: a hidden folder that
//! only Nuvori can read. It cannot see any other file in the user's Drive.
//!
//! Nuvori has no server. The refresh token stays in the encrypted vault database on this PC.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::lan_sync::cloud::{CloudError, CloudFile, CloudStore};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const UPLOAD_URL: &str = "https://www.googleapis.com/upload/drive/v3/files";
const ABOUT_URL: &str = "https://www.googleapis.com/drive/v3/about";
const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";
const FILE_FIELDS: &str = "id,name,size,modifiedTime";
/// A file up to this size goes up in one request; a larger one uses a resumable upload.
const SINGLE_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
/// How long the user has to finish the sign-in in the browser.
const SIGN_IN_WAIT: Duration = Duration::from_secs(5 * 60);

type Cloud<T> = Result<T, CloudError>;

/// The OAuth client this build was made with, or `None` when cloud sync is not set up.
pub fn client() -> Option<(&'static str, &'static str)> {
    let (id, secret) = (env!("NUVORI_GOOGLE_CLIENT_ID"), env!("NUVORI_GOOGLE_CLIENT_SECRET"));
    (!id.is_empty() && !secret.is_empty()).then_some((id, secret))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .timeout_write(Duration::from_secs(60))
        .user_agent("Nuvori")
        .build()
}

fn failure(error: ureq::Error) -> CloudError {
    match error {
        ureq::Error::Transport(_) => CloudError::Offline,
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            classify(code, &body)
        }
    }
}

/// Maps a Google error answer to what the user can do about it.
fn classify(code: u16, body: &str) -> CloudError {
    match code {
        401 => CloudError::Auth,
        400 if body.contains("invalid_grant") => CloudError::Auth,
        403 if body.contains("storageQuotaExceeded") => CloudError::Quota,
        403 if body.contains("ateLimitExceeded") => CloudError::Busy,
        404 => CloudError::NotFound,
        429 | 500..=599 => CloudError::Busy,
        code => CloudError::Other(format!("HTTP {code}")),
    }
}

fn percent(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

fn random_token() -> Cloud<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| CloudError::Other(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn sign_in_url(client_id: &str, redirect: &str, challenge: &str, state: &str) -> String {
    format!(
        "{AUTH_URL}?client_id={}&redirect_uri={}&response_type=code&scope={}&code_challenge={challenge}&code_challenge_method=S256&state={state}&access_type=offline&prompt=consent",
        percent(client_id),
        percent(redirect),
        percent(SCOPE),
    )
}

/// The `code` and `state` of the browser's request to the loopback address, or the error Google sent.
fn redirect_answer(request_line: &str) -> Option<Result<(String, String), String>> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let query = target.strip_prefix("/?")?;
    let mut pairs: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    if let Some(error) = pairs.remove("error") {
        return Some(Err(error));
    }
    Some(Ok((pairs.remove("code")?, pairs.remove("state")?)))
}

fn browser_page(title: &str, text: &str) -> String {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Nuvori</title><style>body{{font:16px system-ui,sans-serif;background:#0d0f0e;color:#e8ece9;display:grid;place-items:center;height:100vh;margin:0}}main{{max-width:26rem;padding:2rem;text-align:center}}h1{{font-size:1.4rem}}p{{color:#a9b3ad}}</style></head><body><main><h1>{title}</h1><p>{text}</p></main></body></html>"
    );
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}", body.len())
}

fn answer(mut stream: TcpStream, response: &str) {
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// A finished sign-in: the token that renews access, and the account's email address.
pub struct SignedIn {
    pub refresh_token: Zeroizing<String>,
    pub account: String,
}

/// Signs in through the system browser. `open` gets the Google address to show. Returns
/// `Ok(None)` when `cancel` is set or the user does not finish in time.
pub fn sign_in(cancel: &AtomicBool, open: impl FnOnce(&str) -> bool) -> Cloud<Option<SignedIn>> {
    let (client_id, client_secret) = client().ok_or_else(|| CloudError::Other("not set up".into()))?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| CloudError::Other(error.to_string()))?;
    listener.set_nonblocking(true).map_err(|error| CloudError::Other(error.to_string()))?;
    let port = listener.local_addr().map_err(|error| CloudError::Other(error.to_string()))?.port();
    let redirect = format!("http://127.0.0.1:{port}");
    let (verifier, state) = (random_token()?, random_token()?);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if !open(&sign_in_url(client_id, &redirect, &challenge, &state)) {
        return Err(CloudError::Other("the browser did not open".into()));
    }
    let deadline = Instant::now() + SIGN_IN_WAIT;
    let code = loop {
        if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Ok(None);
        }
        let Ok((mut stream, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(150));
            continue;
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut buffer = [0u8; 8192];
        let read = stream.read(&mut buffer).unwrap_or(0);
        let request = String::from_utf8_lossy(&buffer[..read]);
        match redirect_answer(request.lines().next().unwrap_or_default()) {
            Some(Ok((code, returned))) if returned == state => {
                answer(stream, &browser_page("Google Drive is connected", "You can close this tab and go back to Nuvori."));
                break code;
            }
            Some(Err(_)) => {
                answer(stream, &browser_page("Sign-in was canceled", "Nothing was connected. You can close this tab and try again in Nuvori."));
                return Ok(None);
            }
            // Another request (a favicon, or a page that guessed the port): not the sign-in.
            _ => answer(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        }
    };
    let agent = agent();
    let tokens: serde_json::Value = agent
        .post(TOKEN_URL)
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", &redirect),
            ("code_verifier", &verifier),
        ])
        .map_err(failure)?
        .into_json()
        .map_err(|error| CloudError::Other(error.to_string()))?;
    let refresh_token = Zeroizing::new(tokens["refresh_token"].as_str().ok_or(CloudError::Auth)?.to_owned());
    let mut drive = GoogleDrive::new(refresh_token.clone());
    drive.access = tokens["access_token"].as_str().map(|token| {
        (Zeroizing::new(token.to_owned()), Instant::now() + Duration::from_secs(tokens["expires_in"].as_u64().unwrap_or(3600).saturating_sub(60)))
    });
    let account = drive.account()?;
    Ok(Some(SignedIn { refresh_token, account }))
}

/// Tells Google to end this PC's access. Best effort; the local token is deleted either way.
pub fn revoke(refresh_token: &str) {
    let _ = agent().post(REVOKE_URL).send_form(&[("token", refresh_token)]);
}

pub struct GoogleDrive {
    agent: ureq::Agent,
    refresh_token: Zeroizing<String>,
    access: Option<(Zeroizing<String>, Instant)>,
}

fn parse_file(json: &serde_json::Value) -> Option<CloudFile> {
    Some(CloudFile {
        id: json["id"].as_str()?.to_owned(),
        name: json["name"].as_str()?.to_owned(),
        // The Drive API sends 64-bit numbers as strings.
        size: json["size"].as_str().and_then(|size| size.parse().ok()).or_else(|| json["size"].as_u64()).unwrap_or(0),
        modified: json["modifiedTime"].as_str()?.to_owned(),
    })
}

fn file_from(response: ureq::Response) -> Cloud<CloudFile> {
    let json: serde_json::Value = response.into_json().map_err(|error| CloudError::Other(error.to_string()))?;
    parse_file(&json).ok_or_else(|| CloudError::Other("unexpected answer".into()))
}

/// `multipart/related` body for a new file in the app folder.
fn multipart(boundary: &str, name: &str, content: &[u8]) -> Vec<u8> {
    let metadata = serde_json::json!({"name": name, "parents": ["appDataFolder"]}).to_string();
    let mut body = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
    body
}

impl GoogleDrive {
    pub fn new(refresh_token: Zeroizing<String>) -> Self {
        Self { agent: agent(), refresh_token, access: None }
    }

    fn token(&mut self) -> Cloud<String> {
        if let Some((token, until)) = &self.access
            && Instant::now() < *until
        {
            return Ok(token.to_string());
        }
        let (client_id, client_secret) = client().ok_or_else(|| CloudError::Other("not set up".into()))?;
        let tokens: serde_json::Value = self
            .agent
            .post(TOKEN_URL)
            .send_form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", self.refresh_token.as_str()),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .map_err(failure)?
            .into_json()
            .map_err(|error| CloudError::Other(error.to_string()))?;
        let token = tokens["access_token"].as_str().ok_or(CloudError::Auth)?.to_owned();
        let lifetime = tokens["expires_in"].as_u64().unwrap_or(3600).saturating_sub(60);
        self.access = Some((Zeroizing::new(token.clone()), Instant::now() + Duration::from_secs(lifetime)));
        Ok(token)
    }

    /// Runs a request with the access token. An expired token is renewed once.
    fn send(&mut self, request: &mut dyn FnMut(&ureq::Agent, &str) -> Result<ureq::Response, ureq::Error>) -> Cloud<ureq::Response> {
        let token = self.token()?;
        match request(&self.agent, &format!("Bearer {token}")) {
            Err(ureq::Error::Status(401, _)) => {
                self.access = None;
                let token = self.token()?;
                request(&self.agent, &format!("Bearer {token}")).map_err(failure)
            }
            other => other.map_err(failure),
        }
    }

    /// The email address of the signed-in Google account.
    pub fn account(&mut self) -> Cloud<String> {
        let json: serde_json::Value = self
            .send(&mut |agent, bearer| agent.get(ABOUT_URL).query("fields", "user(emailAddress)").set("Authorization", bearer).call())?
            .into_json()
            .map_err(|error| CloudError::Other(error.to_string()))?;
        Ok(json["user"]["emailAddress"].as_str().unwrap_or("Google account").to_owned())
    }
}

impl CloudStore for GoogleDrive {
    fn list(&mut self, modified_after: Option<&str>) -> Cloud<Vec<CloudFile>> {
        let query = match modified_after {
            Some(after) => format!("trashed = false and modifiedTime > '{}'", after.replace('\'', "")),
            None => "trashed = false".to_owned(),
        };
        let fields = format!("nextPageToken,files({FILE_FIELDS})");
        let (mut files, mut page) = (Vec::new(), String::new());
        loop {
            let json: serde_json::Value = self
                .send(&mut |agent, bearer| {
                    let mut request = agent
                        .get(FILES_URL)
                        .query("spaces", "appDataFolder")
                        .query("pageSize", "1000")
                        .query("q", &query)
                        .query("fields", &fields)
                        .set("Authorization", bearer);
                    if !page.is_empty() {
                        request = request.query("pageToken", &page);
                    }
                    request.call()
                })?
                .into_json()
                .map_err(|error| CloudError::Other(error.to_string()))?;
            files.extend(json["files"].as_array().into_iter().flatten().filter_map(parse_file));
            match json["nextPageToken"].as_str() {
                // A folder this large means something is wrong; stop instead of listing forever.
                Some(next) if files.len() < 200_000 => page = next.to_owned(),
                _ => return Ok(files),
            }
        }
    }

    fn download(&mut self, id: &str, max_bytes: u64, sink: &mut dyn FnMut(&[u8]) -> Cloud<()>) -> Cloud<()> {
        let url = format!("{FILES_URL}/{}", percent(id));
        let response = self.send(&mut |agent, bearer| agent.get(&url).query("alt", "media").set("Authorization", bearer).call())?;
        let mut reader = response.into_reader();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = reader.read(&mut buffer).map_err(|_| CloudError::Offline)?;
            if count == 0 {
                return Ok(());
            }
            total += count as u64;
            if total > max_bytes {
                return Err(CloudError::Other("file larger than expected".into()));
            }
            sink(&buffer[..count])?;
        }
    }

    fn upload(&mut self, name: &str, size: u64, content: &mut dyn Read) -> Cloud<CloudFile> {
        if size <= SINGLE_REQUEST_BYTES {
            let mut bytes = Vec::with_capacity(size as usize);
            content.read_to_end(&mut bytes).map_err(|error| CloudError::Other(error.to_string()))?;
            let boundary = format!("nuvori-{}", uuid::Uuid::new_v4().simple());
            let body = multipart(&boundary, name, &bytes);
            let content_type = format!("multipart/related; boundary={boundary}");
            return file_from(self.send(&mut |agent, bearer| {
                agent
                    .post(UPLOAD_URL)
                    .query("uploadType", "multipart")
                    .query("fields", FILE_FIELDS)
                    .set("Authorization", bearer)
                    .set("Content-Type", &content_type)
                    .send_bytes(&body)
            })?);
        }
        // Resumable upload: ask for an upload address, then send the bytes there in one stream.
        let metadata = serde_json::json!({"name": name, "parents": ["appDataFolder"]}).to_string();
        let length = size.to_string();
        let session = self.send(&mut |agent, bearer| {
            agent
                .post(UPLOAD_URL)
                .query("uploadType", "resumable")
                .query("fields", FILE_FIELDS)
                .set("Authorization", bearer)
                .set("Content-Type", "application/json; charset=UTF-8")
                .set("X-Upload-Content-Type", "application/octet-stream")
                .set("X-Upload-Content-Length", &length)
                .send_string(&metadata)
        })?;
        let location = session.header("Location").ok_or_else(|| CloudError::Other("no upload address".into()))?.to_owned();
        // The upload address carries its own authorization and a stream cannot be sent twice.
        let response = self
            .agent
            .put(&location)
            .set("Content-Length", &length)
            .set("Content-Type", "application/octet-stream")
            .send(content.take(size))
            .map_err(failure)?;
        file_from(response)
    }

    fn replace(&mut self, id: &str, content: &[u8]) -> Cloud<CloudFile> {
        let url = format!("{UPLOAD_URL}/{}", percent(id));
        file_from(self.send(&mut |agent, bearer| {
            agent
                .request("PATCH", &url)
                .query("uploadType", "media")
                .query("fields", FILE_FIELDS)
                .set("Authorization", bearer)
                .set("Content-Type", "application/octet-stream")
                .send_bytes(content)
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sign_in_address_asks_only_for_the_app_folder() {
        let url = sign_in_url("client.apps.example", "http://127.0.0.1:5123", "challenge", "state-1");
        let query: std::collections::HashMap<String, String> =
            url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
        assert_eq!(query["scope"], "https://www.googleapis.com/auth/drive.appdata", "no access to the user's other files");
        assert_eq!(query["redirect_uri"], "http://127.0.0.1:5123");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["access_type"], "offline");
        assert_eq!((query["client_id"].as_str(), query["state"].as_str()), ("client.apps.example", "state-1"));
        assert!(url.starts_with("https://accounts.google.com/"));
    }

    #[test]
    fn only_the_real_redirect_is_read_as_the_sign_in_answer() {
        assert_eq!(redirect_answer("GET /?state=s%2D1&code=4%2Fabc&scope=x HTTP/1.1"), Some(Ok(("4/abc".into(), "s-1".into()))));
        assert_eq!(redirect_answer("GET /?error=access_denied&state=s HTTP/1.1"), Some(Err("access_denied".into())));
        for line in ["GET /favicon.ico HTTP/1.1", "GET / HTTP/1.1", "GET /?code=only HTTP/1.1", "POST /?code=a&state=b HTTP/1.1", ""] {
            assert_eq!(redirect_answer(line), None, "{line}");
        }
    }

    #[test]
    fn google_answers_map_to_what_the_user_can_do() {
        assert_eq!(classify(401, ""), CloudError::Auth);
        assert_eq!(classify(400, r#"{"error":"invalid_grant"}"#), CloudError::Auth, "access was revoked in the Google account");
        assert_eq!(classify(403, r#"{"error":{"errors":[{"reason":"storageQuotaExceeded"}]}}"#), CloudError::Quota);
        assert_eq!(classify(403, r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#), CloudError::Busy);
        assert_eq!(classify(404, ""), CloudError::NotFound);
        assert_eq!(classify(429, ""), CloudError::Busy);
        assert_eq!(classify(503, ""), CloudError::Busy);
        assert!(matches!(classify(400, "bad request"), CloudError::Other(_)));
    }

    #[test]
    fn a_new_file_goes_into_the_app_folder_and_drive_numbers_are_read() {
        let body = String::from_utf8(multipart("b1", "nv1.tag.p.device", b"sealed")).unwrap();
        assert_eq!(body, "--b1\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"name\":\"nv1.tag.p.device\",\"parents\":[\"appDataFolder\"]}\r\n--b1\r\nContent-Type: application/octet-stream\r\n\r\nsealed\r\n--b1--");
        let file = parse_file(&serde_json::json!({"id": "f1", "name": "n", "size": "1234", "modifiedTime": "2026-11-12T10:00:00.000Z"})).unwrap();
        assert_eq!(file, CloudFile { id: "f1".into(), name: "n".into(), size: 1234, modified: "2026-11-12T10:00:00.000Z".into() });
        assert!(parse_file(&serde_json::json!({"name": "n"})).is_none());
    }
}
