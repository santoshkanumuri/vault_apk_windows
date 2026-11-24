fn main() {
    // Cloud sync signs in with a Google OAuth client of type "Desktop app". Its ID and secret come
    // from `cloud-oauth.json` next to this file (not in git) or from the environment. Without
    // them the app builds, and the Sync page says that cloud sync is not set up in this build.
    // A desktop client's "secret" is not confidential (Google documents this); PKCE protects the
    // sign-in.
    println!("cargo:rerun-if-changed=cloud-oauth.json");
    let file: Option<serde_json::Value> =
        std::fs::read_to_string("cloud-oauth.json").ok().and_then(|text| serde_json::from_str(&text).ok());
    for (variable, field) in [("NUVORI_GOOGLE_CLIENT_ID", "googleClientId"), ("NUVORI_GOOGLE_CLIENT_SECRET", "googleClientSecret")] {
        println!("cargo:rerun-if-env-changed={variable}");
        let value = std::env::var(variable)
            .ok()
            .or_else(|| file.as_ref().and_then(|json| json[field].as_str().map(str::to_owned)))
            .unwrap_or_default();
        println!("cargo:rustc-env={variable}={}", value.trim());
    }
    // Security review M-07: the SHA-256 hashes of the certificates that sign Nuvori's programs
    // (comma separated) and/or the publisher name (NUVORI_SIGNER_NAME). Set by
    // scripts/build-windows.ps1 when code signing is configured; a build without them keeps the
    // path checks alone. A malformed list stops the build instead of quietly
    // trusting nothing (see src/signer.rs).
    println!("cargo:rerun-if-env-changed=NUVORI_SIGNER_SHA256");
    println!("cargo:rerun-if-env-changed=NUVORI_SIGNER_NAME");
    if let Ok(list) = std::env::var("NUVORI_SIGNER_SHA256") {
        for entry in list.split([',', ';', '\n']).map(str::trim).filter(|entry| !entry.is_empty()) {
            let digits: String = entry.chars().filter(|c| !matches!(c, ':' | ' ' | '\t')).collect();
            assert!(
                digits.len() == 64 && digits.chars().all(|c| c.is_ascii_hexdigit()),
                "NUVORI_SIGNER_SHA256 holds something that is not a SHA-256 certificate hash: {entry}"
            );
        }
    }
    tauri_build::build()
}
