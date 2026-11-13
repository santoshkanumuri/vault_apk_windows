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
    tauri_build::build()
}
