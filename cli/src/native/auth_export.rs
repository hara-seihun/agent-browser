//! A daemon-private read into an exclusive file owned by the daemon's UID.
//! Only path and byte count leave this boundary. No navigation or replay occurs.
use super::actions::DaemonState;
use super::auth_fill::{bind_location, FieldLocation};
use super::element::{resolve_element_object_id, RefMap};
use serde_json::{json, Value};
use tokio::time::Instant;

const INVALID: &str = "auth_export_invalid_request: explicit CSS selector, target, frame and absolute output are required";
const BINDING: &str =
    "auth_export_binding_changed: pinned target, frame, document or field changed; not replayed";
const FIELD: &str = "auth_export_field_unavailable: selector must identify one visible input, textarea or text-only element";
const PAGE: &str = "auth_export_page_error: private read failed; no value returned";

/// Reconstruct setup failures as metadata, never preserve foreign error text.
pub(crate) fn public_error(message: &str) -> &'static str {
    match message.split(':').next() {
        Some("auth_export_card_number_invalid") => "auth_export_card_number_invalid: pinned number field must contain 12..19 digits",
        Some("auth_export_card_cvv_invalid") => "auth_export_card_cvv_invalid: pinned CVC field must contain 3..4 digits",
        Some("auth_export_card_expiry_invalid") => "auth_export_card_expiry_invalid: expiry must be YYYY-MM, MM/YY or MM/YYYY",
        Some("auth_export_card_invalid") => "auth_export_card_invalid: item, cardholder, expiry and unique CSS number/CVC selectors are required",
        Some("auth_export_vault_uncertain") => "auth_export_vault_uncertain: vault create did not acknowledge success; inspect the item before another attempt; never replay",
        Some("auth_export_invalid_request") => INVALID,
        Some("auth_export_binding_changed") => BINDING,
        Some("auth_export_field_unavailable") => FIELD,
        Some("auth_export_page_error") => PAGE,
        Some("auth_export_capture_active") => "auth_export_capture_active: stop recording, tracing, streaming and network capture before private read",
        Some("auth_export_timeout") => "auth_export_timeout: private export deadline expired; dispatched effects may have settled; never replay",
        Some("auth_export_path_invalid") => "auth_export_path_invalid: absolute nonsymlink path and own-UID private 0700 parent are required",
        Some("auth_export_path_exists") => "auth_export_path_exists: output already exists; not overwritten or replayed",
        Some("auth_export_write_failed") => "auth_export_write_failed: exclusive private file could not be published; not replayed",
        Some("auth_export_commit_uncertain") => "auth_export_commit_uncertain: exclusive file may be published; inspect the requested path, never replay",
        Some("auth_export_unsupported") => "auth_export_unsupported: exclusive private export requires a nonroot Linux daemon",
        _ => "auth_export_setup_failed: private export could not begin; check session and policy; no value returned",
    }
}

/// Export one unique field in the selected live document without exposing its value.
/// The output parent must be a nonsymlink private 0700 directory owned by this UID.
pub async fn handle_auth_export(
    cmd: &Value,
    state: &mut DaemonState,
    deadline: Instant,
) -> Result<Value, String> {
    if cmd.get("destination").and_then(Value::as_str) == Some("proton-card") {
        return save_card(cmd, state, deadline).await;
    }
    let output = cmd.get("output").and_then(Value::as_str).ok_or(INVALID)?;
    let sink = ExclusiveSink::prepare(output)?;
    let value = read_private_field(cmd, state, deadline).await?;
    sink.publish(&value)
}

/// Only native private consumers receive these bytes; normal command responses never do.
async fn read_private_field(
    cmd: &Value,
    state: &mut DaemonState,
    deadline: Instant,
) -> Result<String, String> {
    let field = |name: &str| {
        cmd.get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or(INVALID)
    };
    let selector = field("selector")?;
    let index = cmd.get("selectorIndex").and_then(Value::as_u64);
    let container = cmd["destination"] == "proton-card";
    if index.is_some_and(|i| i > 1000) {
        return Err(INVALID.into());
    }
    let location = FieldLocation {
        target: super::auth_fill::canonical_target(
            state,
            cmd.get("target").and_then(Value::as_str).unwrap_or(""),
        )
        .map_err(|_| BINDING)?,
        frame: super::auth_fill::canonical_frame(
            state,
            cmd.get("frame").and_then(Value::as_str).unwrap_or(""),
        )
        .map_err(|_| BINDING)?,
    };
    if selector.starts_with('@') || selector.starts_with("xpath=") || selector.starts_with("//") {
        return Err(INVALID.into());
    }
    if state.recording_state.active
        || state.tracing_state.active
        || state.screencasting
        || state.stream_server.is_some()
        || state.har_recording
        || state.request_tracking
    {
        return Err("auth_export_capture_active: stop recording, tracing, streaming and network capture before private read".into());
    }
    if Instant::now() >= deadline {
        return Err("auth_export_timeout: private export deadline expired; not replayed".into());
    }
    let bound = bind_location(state, &location).await.map_err(|_| BINDING)?;
    super::element::set_active_frame(if location.frame == "main" {
        None
    } else {
        Some(&location.frame)
    });
    let client = state.browser.as_ref().ok_or(BINDING)?.client.clone();
    let (mut object, session) = resolve_element_object_id(
        &client,
        &bound.session,
        &RefMap::new(),
        selector,
        &state.iframe_sessions,
    )
    .await
    .map_err(|_| FIELD)?;
    if session != bound.frame_session.as_deref().unwrap_or(&bound.session) {
        return Err(BINDING.into());
    }
    if let Some(index) = index {
        let selected = client.send_command("Runtime.callFunctionOn", Some(json!({
            "objectId":object,"functionDeclaration":"function(selector,index){return this.ownerDocument.querySelectorAll(selector)[index] || null}",
            "arguments":[{"value":selector},{"value":index}],"returnByValue":false
        })),Some(&session)).await.map_err(|_| PAGE)?;
        object = selected["result"]["objectId"]
            .as_str()
            .ok_or(FIELD)?
            .to_owned();
    }
    let group = client
        .object_group(vec![session.clone()])
        .await
        .map_err(|_| PAGE)?;
    let pinned = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(json!({
                "objectId":object, "functionDeclaration":PIN_FIELD,
                "arguments":[{"value":selector},{"value":index},{"value":container}], "objectGroup":group.name, "returnByValue":false
            })),
            Some(&session),
        )
        .await
        .map_err(|_| PAGE)?;
    if pinned.get("exceptionDetails").is_some() {
        return Err(FIELD.into());
    }
    let document = pinned["result"]["objectId"].as_str().ok_or(FIELD)?;
    let described = client
        .send_command(
            "DOM.describeNode",
            Some(json!({"objectId":object,"depth":if container {-1} else {1}})),
            Some(&session),
        )
        .await
        .map_err(|_| PAGE)?;
    let backend = described["node"]["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(PAGE)?;
    let is_text = match described["node"]["nodeName"].as_str().ok_or(PAGE)? {
        "INPUT" | "TEXTAREA" => false,
        _ => true,
    };
    let mut text_backends = vec![backend];
    fn collect_nodes(node: &Value, ids: &mut Vec<i64>) {
        if let Some(children) = node["children"].as_array() {
            for child in children {
                if let Some(id) = child["backendNodeId"].as_i64().filter(|id| *id > 0) {
                    ids.push(id);
                }
                collect_nodes(child, ids);
            }
        }
    }
    if is_text {
        collect_nodes(&described["node"], &mut text_backends);
    }
    if bind_location(state, &location).await.map_err(|_| BINDING)? != bound {
        return Err(BINDING.into());
    }
    let read = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(json!({
                "objectId":object, "functionDeclaration":READ_FIELD,
                "arguments":[{"objectId":document},{"value":selector},{"value":index},{"value":container}], "returnByValue":true
            })),
            Some(&session),
        )
        .await
        .map_err(|_| PAGE)?;
    if read.get("exceptionDetails").is_some() {
        return Err(PAGE.into());
    }
    let result = &read["result"]["value"];
    let value = result["value"].as_str().filter(|s| !s.is_empty());
    // Even an unexpected page mutation after the read cannot turn the returned
    // private bytes into later normal output: register before final validation.
    if let Some(value) = value {
        let known = state
            .sensitive_observations
            .entry(bound.session.clone())
            .or_default();
        if is_text {
            for backend in text_backends {
                known.remember_private_text(&session, backend, value);
            }
        } else {
            known.remember_private_value(&session, backend, "credential", value);
        }
    }
    match result["status"].as_str() {
        Some("changed") => return Err(BINDING.into()),
        Some("unavailable") => return Err(FIELD.into()),
        Some("read") if value.is_some() => {}
        _ => return Err(PAGE.into()),
    }
    if bind_location(state, &location).await.map_err(|_| BINDING)? != bound {
        return Err(BINDING.into());
    }
    group.finish();
    client.settle_object_cleanup().await.map_err(|_| PAGE)?;
    if Instant::now() >= deadline {
        return Err("auth_export_timeout: private export deadline expired; not replayed".into());
    }
    Ok(value.ok_or(PAGE)?.to_owned())
}

/// Fixed Proton consumer: private values go only into stdin, never argv, files or output.
async fn save_card(
    cmd: &Value,
    state: &mut DaemonState,
    deadline: Instant,
) -> Result<Value, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    const INVALID_CARD: &str = "auth_export_card_invalid: item, cardholder, expiry and unique CSS number/CVC selectors are required";
    const VAULT: &str = "auth_export_vault_uncertain: vault create did not acknowledge success; inspect the item before another attempt; never replay";
    // This consumer owns only Kenan's Agent vault, not other users' accounts.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 1000 {
        return Err(INVALID_CARD.into());
    }
    let required = |key: &str| {
        cmd.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or(INVALID_CARD)
    };
    let item = required("item")?;
    let holder = required("cardholderName")?;
    let expiry_selector = cmd.get("expirationSelector").and_then(Value::as_str);
    if expiry_selector.is_some() == cmd.get("expirationDate").is_some() {
        return Err(INVALID_CARD.into());
    }
    let number_selector = required("numberSelector")?;
    let cvv_selector = required("cvvSelector")?;
    if item.len() > 256
        || holder.len() > 256
        || (number_selector == cvv_selector && cmd["numberIndex"] == cmd["cvvIndex"])
    {
        return Err(INVALID_CARD.into());
    }
    let location = FieldLocation {
        target: super::auth_fill::canonical_target(state, required("target")?)
            .map_err(|_| BINDING)?,
        frame: super::auth_fill::canonical_frame(state, required("frame")?).map_err(|_| BINDING)?,
    };
    let original = bind_location(state, &location).await.map_err(|_| BINDING)?;
    let mut read_cmd = cmd.clone();
    read_cmd["selector"] = json!(number_selector);
    read_cmd["selectorIndex"] = cmd["numberIndex"].clone();
    let number_raw = read_private_field(&read_cmd, state, deadline).await?;
    read_cmd["selector"] = json!(cvv_selector);
    read_cmd["selectorIndex"] = cmd["cvvIndex"].clone();
    let cvv_raw = read_private_field(&read_cmd, state, deadline).await?;
    let expiry_raw = if let Some(selector) = expiry_selector {
        read_cmd["selector"] = json!(selector);
        read_cmd["selectorIndex"] = cmd["expirationIndex"].clone();
        read_private_field(&read_cmd, state, deadline).await?
    } else {
        required("expirationDate")?.to_owned()
    };
    let compact: String = expiry_raw.chars().filter(|c| !c.is_whitespace()).collect();
    let expiry = if compact.len() == 7
        && compact.as_bytes()[4] == b'-'
        && compact
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || b.is_ascii_digit())
    {
        compact
    } else {
        let parts: Vec<_> = compact.split('/').collect();
        if parts.len() != 2
            || parts[0].len() != 2
            || !parts[0].bytes().all(|b| b.is_ascii_digit())
            || ![2, 4].contains(&parts[1].len())
            || !parts[1].bytes().all(|b| b.is_ascii_digit())
        {
            return Err("auth_export_card_expiry_invalid: invalid private expiry".into());
        }
        format!(
            "{}{}-{}",
            if parts[1].len() == 2 { "20" } else { "" },
            parts[1],
            parts[0]
        )
    };
    if !expiry[5..]
        .parse::<u8>()
        .ok()
        .is_some_and(|m| (1..=12).contains(&m))
    {
        return Err("auth_export_card_expiry_invalid: invalid private expiry".into());
    }
    if bind_location(state, &location).await.map_err(|_| BINDING)? != original {
        return Err(BINDING.into());
    }
    // Dedicated card buttons can include copy-icon text and Unicode spacing.
    let number: String = number_raw.chars().filter(char::is_ascii_digit).collect();
    let cvv: String = cvv_raw.chars().filter(char::is_ascii_digit).collect();
    if !(12..=19).contains(&number.len()) {
        return Err("auth_export_card_number_invalid: invalid private number".into());
    }
    if !(3..=4).contains(&cvv.len()) {
        return Err("auth_export_card_cvv_invalid: invalid private CVC".into());
    }
    // Register normalized forms as well as exactly what the page displayed.
    state
        .sensitive_observations
        .entry(original.session.clone())
        .or_default()
        .remember_private_value(&original.session, 0, "credential", &number);
    state
        .sensitive_observations
        .entry(original.session.clone())
        .or_default()
        .remember_private_value(&original.session, 0, "credential", &cvv);
    let template = json!({"title":item,"cardholder_name":holder,"number":number,
        "cvv":cvv,"expiration_date":expiry});
    if Instant::now() >= deadline {
        return Err("auth_export_timeout: private operation expired; never replay".into());
    }
    let mut child = tokio::process::Command::new("/home/kenan/tools/pass-cli/main")
        .args([
            "item",
            "create",
            "credit-card",
            "--vault-name",
            "Agent",
            "--from-template",
            "-",
        ])
        .env(
            "PROTON_PASS_AGENT_REASON",
            "Save the authorized browser-created virtual card directly to Agent vault",
        )
        .env("PASS_CLI_NO_CACHE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| VAULT)?;
    let mut stdin = child.stdin.take().ok_or(VAULT)?;
    stdin
        .write_all(template.to_string().as_bytes())
        .await
        .map_err(|_| VAULT)?;
    stdin.shutdown().await.map_err(|_| VAULT)?;
    drop(stdin);
    let status = child.wait().await.map_err(|_| VAULT)?;
    if !status.success() {
        return Err(VAULT.into());
    }
    Ok(json!({"saved":true,"vault":"Agent","item":item}))
}

const PIN_FIELD: &str = r#"function(selector,index,container) {
    const d=this.ownerDocument;
    const matches=d.querySelectorAll(selector);
    if (!this.isConnected || (index===null ? matches.length!==1 || matches[0]!==this : matches[index]!==this) || !this.getClientRects().length) return null;
    if (!['INPUT','TEXTAREA'].includes(this.tagName) && this.children.length!==0 && !(container && this.tagName==='BUTTON')) return null;
    return d;
}"#;
const READ_FIELD: &str = r#"function(document, selector,index,container) {
    const valid=()=>{const m=document.querySelectorAll(selector); return this.isConnected && this.ownerDocument===document && this.getClientRects().length && (index===null ? m.length===1 && m[0]===this : m[index]===this)};
    if (!valid()) return {status:'changed'};
    const control=['INPUT','TEXTAREA'].includes(this.tagName);
    if (!control && this.children.length!==0 && !(container && this.tagName==='BUTTON')) return {status:'unavailable'};
    const value=control ? this.value : this.textContent;
    if (typeof value!=='string' || value.length===0) return {status:'unavailable'};
    if (!valid()) return {status:'changed',value};
    return {status:'read',value};
}"#;

#[cfg(target_os = "linux")]
mod sink {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    const PATH_ERROR: &str = "auth_export_path_invalid: absolute nonsymlink path and own-UID private 0700 parent are required";
    const EXISTS: &str =
        "auth_export_path_exists: output already exists; not overwritten or replayed";
    const WRITE: &str =
        "auth_export_write_failed: exclusive private file could not be published; not replayed";

    pub(crate) struct ExclusiveSink {
        path: String,
        parent: File,
        leaf: CString,
    }

    fn cstring(s: &std::ffi::OsStr) -> Result<CString, String> {
        use std::os::unix::ffi::OsStrExt;
        CString::new(s.as_bytes()).map_err(|_| PATH_ERROR.into())
    }
    fn open_parent(path: &str) -> Result<(File, CString), String> {
        let path = Path::new(path);
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().ends_with(b"/") {
            return Err(PATH_ERROR.into());
        }
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(PATH_ERROR.into());
        }
        let names = parts
            .map(|part| match part {
                Component::Normal(name) => cstring(name),
                _ => Err(PATH_ERROR.into()),
            })
            .collect::<Result<Vec<_>, String>>()?;
        // components() normalizes internal dots; reject them instead of accepting aliases.
        if path
            .as_os_str()
            .as_encoded_bytes()
            .split(|c| *c == b'/')
            .skip(1)
            .any(|s| s == b"." || s == b".." || s.is_empty())
        {
            return Err(PATH_ERROR.into());
        }
        let (leaf, directories) = names.split_last().ok_or(PATH_ERROR)?;
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(PATH_ERROR.into());
        }
        let mut current = unsafe { File::from_raw_fd(fd) };
        for name in directories {
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(PATH_ERROR.into());
            }
            current = unsafe { File::from_raw_fd(fd) };
        }
        let metadata = current.metadata().map_err(|_| PATH_ERROR)?;
        let uid = unsafe { libc::geteuid() };
        if uid == 0 || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(PATH_ERROR.into());
        }
        Ok((current, leaf.clone()))
    }
    fn require_absent(parent: &File, leaf: &CString) -> Result<(), String> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Err(EXISTS.into());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(PATH_ERROR.into());
        }
        Ok(())
    }
    struct Temporary<'a> {
        parent: &'a File,
        name: CString,
        active: bool,
    }
    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            if self.active {
                unsafe {
                    libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }
    impl ExclusiveSink {
        pub(crate) fn prepare(path: &str) -> Result<Self, String> {
            let (parent, leaf) = open_parent(path)?;
            require_absent(&parent, &leaf)?;
            Ok(Self {
                path: path.into(),
                parent,
                leaf,
            })
        }
        pub(crate) fn publish(self, value: &str) -> Result<Value, String> {
            if value.is_empty() {
                return Err(FIELD.into());
            }
            let (live, _) = open_parent(&self.path)?;
            let a = self.parent.metadata().map_err(|_| PATH_ERROR)?;
            let b = live.metadata().map_err(|_| PATH_ERROR)?;
            if a.dev() != b.dev() || a.ino() != b.ino() {
                return Err(PATH_ERROR.into());
            }
            require_absent(&self.parent, &self.leaf)?;
            let name = CString::new(format!(".private-export-{}", uuid::Uuid::new_v4()))
                .map_err(|_| WRITE)?;
            let fd = unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(WRITE.into());
            }
            let mut temporary = Temporary {
                parent: &self.parent,
                name,
                active: true,
            };
            let mut file = unsafe { File::from_raw_fd(fd) };
            // Force exact mode regardless of the caller's umask.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(WRITE.into());
            }
            file.write_all(value.as_bytes()).map_err(|_| WRITE)?;
            file.sync_all().map_err(|_| WRITE)?;
            let rc = unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    temporary.name.as_ptr(),
                    self.parent.as_raw_fd(),
                    self.leaf.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if rc != 0 {
                return Err(
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                        EXISTS
                    } else {
                        WRITE
                    }
                    .into(),
                );
            }
            temporary.active = false;
            let (committed,_) = open_parent(&self.path).map_err(|_| "auth_export_commit_uncertain: output parent association changed after publication; never replay")?;
            let c=committed.metadata().map_err(|_| "auth_export_commit_uncertain: output parent identity unavailable after publication; never replay")?;
            if a.dev() != c.dev() || a.ino() != c.ino() {
                return Err("auth_export_commit_uncertain: output parent association changed after publication; never replay".into());
            }
            self.parent.sync_all().map_err(|_| "auth_export_commit_uncertain: exclusive file published but directory sync failed; inspect receipt path, never replay")?;
            Ok(json!({"path":self.path,"byteCount":value.len()}))
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use sink::ExclusiveSink;
#[cfg(not(target_os = "linux"))]
pub(crate) struct ExclusiveSink;
#[cfg(not(target_os = "linux"))]
impl ExclusiveSink {
    pub(crate) fn prepare(_: &str) -> Result<Self, String> {
        Err("auth_export_unsupported: exclusive private export requires Linux".into())
    }
    pub(crate) fn publish(self, _: &str) -> Result<Value, String> {
        Err("auth_export_unsupported: exclusive private export requires Linux".into())
    }
}
