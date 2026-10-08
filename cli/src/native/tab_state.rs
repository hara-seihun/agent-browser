//! Explicit, private, expiring per-tab sessionStorage capsules. Context-wide
//! cookies/localStorage are intentionally not copied: they cannot be isolated
//! to one exact origin/tab. Loading installs a top-level, exact-origin bootstrap
//! on a fresh blank target before application scripts execute.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use super::cdp::client::CdpClient;
use super::state::StorageEntry;

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum PersonContext {
    Standalone,
    Person { id: String },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TabState {
    version: u8,
    uid: u32,
    person: PersonContext,
    account: String,
    origin: String,
    expires_at: u64,
    session_storage: Vec<StorageEntry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TabStateError {
    Unsupported,
    InvalidScope,
    InvalidExpiry,
    Missing,
    UnsafeFile,
    InvalidState,
    WrongOwner,
    WrongAccount,
    WrongOrigin,
    Expired,
    Empty,
    Capture,
    Install,
    Write,
}

impl TabStateError {
    pub fn message(&self) -> String {
        let code = match self {
            Self::Unsupported => "unsupported",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidExpiry => "invalid_expiry",
            Self::Missing => "missing",
            Self::UnsafeFile => "unsafe_file",
            Self::InvalidState => "invalid_state",
            Self::WrongOwner => "wrong_owner",
            Self::WrongAccount => "wrong_account",
            Self::WrongOrigin => "wrong_origin",
            Self::Expired => "expired",
            Self::Empty => "empty",
            Self::Capture => "capture_failed",
            Self::Install => "install_failed",
            Self::Write => "write_failed",
        };
        format!("tab_state_{code}: authorized clean-tab state unavailable")
    }
}

fn now() -> Result<u64, TabStateError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_millis() as u64)
        .map_err(|_| TabStateError::InvalidExpiry)
}

fn person() -> Result<PersonContext, TabStateError> {
    match std::env::var("PI_KENAN_MEMORY_PERSON") {
        Ok(id) if !id.trim().is_empty() => Ok(PersonContext::Person { id }),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => Err(TabStateError::WrongOwner),
        Err(std::env::VarError::NotPresent) => Ok(PersonContext::Standalone),
    }
}

pub fn validate_scope(account: &str, origin: &str) -> Result<(), TabStateError> {
    if account.trim().is_empty() || account.len() > 256 || account.chars().any(char::is_control) {
        return Err(TabStateError::InvalidScope);
    }
    let parsed = url::Url::parse(origin).map_err(|_| TabStateError::InvalidScope)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.origin().ascii_serialization() != origin
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TabStateError::InvalidScope);
    }
    Ok(())
}

#[cfg(unix)]
fn uid() -> Result<u32, TabStateError> {
    Ok(unsafe { libc::geteuid() })
}
#[cfg(not(unix))]
fn uid() -> Result<u32, TabStateError> {
    Err(TabStateError::Unsupported)
}

#[cfg(unix)]
fn private_file(path: &str, create: bool) -> Result<File, TabStateError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create {
        options.write(true).create_new(true).mode(0o600);
    } else {
        options.read(true);
    }
    let file = options.open(path).map_err(|e| {
        if !create && e.kind() == std::io::ErrorKind::NotFound {
            TabStateError::Missing
        } else {
            TabStateError::UnsafeFile
        }
    })?;
    let meta = file.metadata().map_err(|_| TabStateError::UnsafeFile)?;
    if !meta.is_file() || meta.uid() != uid()? || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(TabStateError::UnsafeFile);
    }
    Ok(file)
}
#[cfg(not(unix))]
fn private_file(_path: &str, _create: bool) -> Result<File, TabStateError> {
    Err(TabStateError::Unsupported)
}

fn validate_capsule(state: &TabState, account: &str, origin: &str) -> Result<(), TabStateError> {
    validate_scope(account, origin)?;
    if state.version != 1 {
        return Err(TabStateError::InvalidState);
    }
    if state.uid != uid()? || state.person != person()? {
        return Err(TabStateError::WrongOwner);
    }
    if state.account != account {
        return Err(TabStateError::WrongAccount);
    }
    if state.origin != origin {
        return Err(TabStateError::WrongOrigin);
    }
    if state.expires_at <= now()? {
        return Err(TabStateError::Expired);
    }
    if state.session_storage.is_empty() {
        return Err(TabStateError::Empty);
    }
    let mut names = HashSet::new();
    if state.session_storage.iter().any(|e| !names.insert(&e.name)) {
        return Err(TabStateError::InvalidState);
    }
    Ok(())
}

/// Capture only the selected top-level origin's sessionStorage. The caller must
/// first apply the sticky sensitive-tab guard. Values never appear in responses.
pub async fn save(
    client: &CdpClient,
    session: &str,
    path: &str,
    account: &str,
    origin: &str,
    ttl_seconds: u64,
) -> Result<Value, TabStateError> {
    validate_scope(account, origin)?;
    if ttl_seconds == 0 || ttl_seconds > 86400 {
        return Err(TabStateError::InvalidExpiry);
    }
    let result = client.send_command("Runtime.evaluate", Some(json!({
        "expression": "(() => ({origin:location.origin, entries:Object.entries(sessionStorage).map(([name,value])=>({name,value}))}))()",
        "returnByValue": true
    })), Some(session)).await.map_err(|_| TabStateError::Capture)?;
    if result.get("exceptionDetails").is_some() {
        return Err(TabStateError::Capture);
    }
    let data = &result["result"]["value"];
    if data["origin"].as_str() != Some(origin) {
        return Err(TabStateError::WrongOrigin);
    }
    let capsule = TabState {
        version: 1,
        uid: uid()?,
        person: person()?,
        account: account.into(),
        origin: origin.into(),
        expires_at: now()?
            .checked_add(ttl_seconds * 1000)
            .ok_or(TabStateError::InvalidExpiry)?,
        session_storage: serde_json::from_value(data["entries"].clone())
            .map_err(|_| TabStateError::Capture)?,
    };
    validate_capsule(&capsule, account, origin)?;
    let bytes = serde_json::to_vec(&capsule).map_err(|_| TabStateError::InvalidState)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(TabStateError::InvalidState);
    }
    let mut file = private_file(path, true)?;
    if file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(TabStateError::Write);
    }
    Ok(
        json!({"saved":true,"path":path,"account":account,"origin":origin,"expiresAt":capsule.expires_at,"entries":capsule.session_storage.len(),"scope":"tab-session-storage"}),
    )
}

fn read(path: &str, account: &str, origin: &str) -> Result<TabState, TabStateError> {
    validate_scope(account, origin)?;
    let mut bytes = Vec::new();
    private_file(path, false)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TabStateError::UnsafeFile)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(TabStateError::InvalidState);
    }
    let capsule: TabState =
        serde_json::from_slice(&bytes).map_err(|_| TabStateError::InvalidState)?;
    validate_capsule(&capsule, account, origin)?;
    Ok(capsule)
}

fn bootstrap(capsule: &TabState) -> Result<String, TabStateError> {
    let data = serde_json::to_string(&json!({"origin":capsule.origin,"expiresAt":capsule.expires_at,"sessionStorage":capsule.session_storage})).map_err(|_| TabStateError::InvalidState)?;
    Ok(format!(
        r#"(() => {{
        const state = {data};
        if (window !== window.top || location.origin !== state.origin || Date.now() >= state.expiresAt) return;
        for (const entry of state.sessionStorage) {{
            if (sessionStorage.getItem(entry.name) === null) sessionStorage.setItem(entry.name, entry.value);
        }}
    }})()"#
    ))
}

/// Install into a blank target, not the browser or any other target. The caller
/// checks blankness, complete sensitive inventory and duplicate installation.
pub async fn load(
    client: &CdpClient,
    session: &str,
    path: &str,
    account: &str,
    origin: &str,
) -> Result<Value, TabStateError> {
    let capsule = read(path, account, origin)?;
    let installed = client
        .send_command(
            "Page.addScriptToEvaluateOnNewDocument",
            Some(json!({"source":bootstrap(&capsule)?})),
            Some(session),
        )
        .await
        .map_err(|_| TabStateError::Install)?;
    if installed["identifier"].as_str().is_none_or(str::is_empty) {
        return Err(TabStateError::Install);
    }
    Ok(
        json!({"loaded":true,"path":path,"account":account,"origin":origin,"expiresAt":capsule.expires_at,"entries":capsule.session_storage.len(),"scope":"tab-session-storage","startup":"armed"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn exact_scope_and_typed_refusals() {
        let _env = crate::test_utils::EnvGuard::new(&["PI_KENAN_MEMORY_PERSON"]);
        for origin in [
            "https://example.com/",
            "https://user@example.com",
            "https://example.com/path",
            "file:///tmp/test",
            "https://example.com?x",
        ] {
            assert_eq!(
                validate_scope("own", origin),
                Err(TabStateError::InvalidScope)
            );
        }
        assert!(validate_scope("own", "https://example.com:8443").is_ok());
        let mut capsule = TabState {
            version: 1,
            uid: uid().unwrap(),
            person: person().unwrap(),
            account: "own".into(),
            origin: "https://example.com".into(),
            expires_at: now().unwrap() + 60000,
            session_storage: vec![StorageEntry {
                name: "synthetic".into(),
                value: "fixture-only".into(),
            }],
        };
        assert_eq!(
            validate_capsule(&capsule, "other", &capsule.origin),
            Err(TabStateError::WrongAccount)
        );
        assert_eq!(
            validate_capsule(&capsule, "own", "https://example.com:8443"),
            Err(TabStateError::WrongOrigin)
        );
        capsule.uid += 1;
        assert_eq!(
            validate_capsule(&capsule, "own", &capsule.origin),
            Err(TabStateError::WrongOwner)
        );
        capsule.uid -= 1;
        capsule.expires_at = 0;
        assert_eq!(
            validate_capsule(&capsule, "own", &capsule.origin),
            Err(TabStateError::Expired)
        );
    }
    #[cfg(unix)]
    #[test]
    fn private_file_refuses_permissions_symlinks_and_overwrite() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capsule");
        let path = path.to_str().unwrap();
        private_file(path, true).unwrap();
        assert!(private_file(path, true).is_err());
        let hardlink = dir.path().join("hardlink");
        std::fs::hard_link(path, &hardlink).unwrap();
        assert!(private_file(path, false).is_err());
        std::fs::remove_file(hardlink).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(path, false).is_err());
        let link = dir.path().join("link");
        symlink(path, &link).unwrap();
        assert!(private_file(link.to_str().unwrap(), false).is_err());
        assert_eq!(
            read(
                dir.path().join("absent").to_str().unwrap(),
                "own",
                "https://example.com"
            )
            .err(),
            Some(TabStateError::Missing)
        );
    }
}
