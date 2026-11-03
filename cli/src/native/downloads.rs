//! Move the actual Chrome download to the caller's filesystem, including over remote CDP.
//! Never replay a download URL: it may represent a POST, a blob or a one-time link.
use super::browser::BrowserManager;
use super::cdp::client::CdpClient;
use super::cdp::types::CdpEvent;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;

pub struct Download {
    pub destination: PathBuf,
    directory: String,
    frames: HashSet<String>,
    events: broadcast::Receiver<CdpEvent>,
}

impl Download {
    /// Subscribe before the triggering click, and keep local paths off a remote browser.
    pub async fn prepare(mgr: &BrowserManager, path: &str) -> Result<Self, String> {
        let raw = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path);
        let parent = raw.parent().ok_or("Invalid download path: no parent")?;
        std::fs::create_dir_all(parent).map_err(|e| format!("Create download directory: {e}"))?;
        let destination = parent.canonicalize().map_err(|e| e.to_string())?.join(
            raw.file_name()
                .ok_or("Invalid download path: no filename")?,
        );
        let directory = if mgr.is_cdp_connection() {
            format!("/tmp/agent-browser-download-{}", uuid::Uuid::new_v4())
        } else {
            destination.parent().unwrap().to_string_lossy().into_owned()
        };
        let tree = mgr
            .client
            .send_command_no_params("Page.getFrameTree", Some(mgr.active_session_id()?))
            .await?;
        fn collect(tree: &Value, frames: &mut HashSet<String>) {
            if let Some(id) = tree["frame"]["id"].as_str() {
                frames.insert(id.to_owned());
            }
            if let Some(children) = tree["childFrames"].as_array() {
                for child in children {
                    collect(child, frames);
                }
            }
        }
        let mut frames = HashSet::new();
        collect(&tree["frameTree"], &mut frames);
        if frames.is_empty() {
            return Err("download_frame_missing: cannot identify the initiating tab".into());
        }
        let events = mgr.client.subscribe();
        mgr.set_download_behavior(&directory).await?;
        Ok(Self {
            destination,
            directory,
            frames,
            events,
        })
    }

    pub async fn finish(mut self, mgr: &BrowserManager, timeout_ms: u64) -> Result<Value, String> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        let mut guid = None;
        let mut filename = None;
        let (source, bytes) = loop {
            let event = match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Ok(event)) => event,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => return Err("download_events_lost: cannot identify the completed file; the click was not repeated".into()),
                Ok(Err(_)) => return Err("Download event stream closed".into()),
                Err(_) => return Err("Timeout waiting for download; the click was not repeated".into()),
            };
            if event.method == "Browser.downloadWillBegin" {
                if !event.params["frameId"]
                    .as_str()
                    .is_some_and(|f| self.frames.contains(f))
                {
                    continue;
                }
                if guid.is_none() {
                    guid = event.params["guid"].as_str().map(str::to_owned);
                    filename = event.params["suggestedFilename"]
                        .as_str()
                        .map(str::to_owned);
                }
            }
            // Page.downloadProgress can precede the browser event, without its actual
            // filePath when a provider overrides the directory. Browser events were
            // explicitly enabled in prepare; only those describe the completed file.
            if event.method != "Browser.downloadProgress"
                || guid.is_none()
                || event.params["guid"].as_str() != guid.as_deref()
            {
                continue;
            }
            match event.params["state"].as_str() {
                Some("canceled") => return Err("Download was canceled".into()),
                Some("completed") => {
                    // Providers may override setDownloadBehavior. The completion path is authoritative.
                    let source = event.params["filePath"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            format!("{}/{}", self.directory, guid.as_deref().unwrap())
                        });
                    break (
                        source,
                        event.params["totalBytes"].as_f64().map(|n| n as u64),
                    );
                }
                _ => {}
            }
        };
        if mgr.is_cdp_connection() {
            copy_remote(&mgr.client, &source, &self.destination, bytes).await?;
        } else {
            // Chrome's completed event means its file has been closed. Do not accept a stale destination.
            let source = Path::new(&source);
            let size = std::fs::metadata(source)
                .map_err(|e| format!("Read completed download: {e}"))?
                .len();
            if bytes.is_some_and(|n| n != size) {
                return Err("download_size_mismatch: completed file size differs".into());
            }
            if source != self.destination {
                std::fs::rename(source, &self.destination)
                    .map_err(|e| format!("Save download: {e}"))?;
            }
        }
        Ok(json!({ "path": self.destination, "filename": filename }))
    }
}

/// A partial transfer never becomes the requested file, and interruption removes its private staging file.
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn evaluate(client: &CdpClient, sid: &str, expression: String) -> Result<Value, String> {
    let value = client
        .send_command(
            "Runtime.evaluate",
            Some(json!({
                "expression": expression, "awaitPromise": true, "returnByValue": true,
            })),
            Some(sid),
        )
        .await?;
    if value.get("exceptionDetails").is_some() {
        return Err(
            "remote_download_read_failed: browser could not read its completed download".into(),
        );
    }
    value["result"]
        .get("value")
        .cloned()
        .ok_or_else(|| "remote_download_read_failed: missing result".into())
}

async fn copy_remote(
    client: &std::sync::Arc<CdpClient>,
    source: &str,
    destination: &Path,
    expected: Option<u64>,
) -> Result<(), String> {
    // A new blank tab has no application scripts or opener. Never expose the file input to the website.
    let target = client
        .send_command(
            "Target.createTarget",
            Some(json!({"url":"about:blank", "background":true})),
            None,
        )
        .await?;
    let target = target["targetId"]
        .as_str()
        .ok_or("Missing transfer target")?
        .to_owned();
    struct TransferTab {
        client: std::sync::Arc<CdpClient>,
        target: String,
        closed: bool,
    }
    impl Drop for TransferTab {
        fn drop(&mut self) {
            if !self.closed {
                let client = self.client.clone();
                let target = self.target.clone();
                tokio::spawn(async move {
                    let _ = client
                        .send_command("Target.closeTarget", Some(json!({"targetId":target})), None)
                        .await;
                });
            }
        }
    }
    let mut tab = TransferTab {
        client: client.clone(),
        target: target.clone(),
        closed: false,
    };
    let result: Result<(), String> = async {
        let attached = client.send_command("Target.attachToTarget", Some(json!({"targetId":target,"flatten":true})), None).await?;
        let sid = attached["sessionId"].as_str().ok_or("Missing transfer session")?;
        client.send_command_no_params("Runtime.runIfWaitingForDebugger", Some(sid)).await?;
        evaluate(client, sid, "document.body.appendChild(document.createElement('input')).type='file'".into()).await?;
        let doc = client.send_command_no_params("DOM.getDocument", Some(sid)).await?;
        let input = client.send_command("DOM.querySelector", Some(json!({"nodeId":doc["root"]["nodeId"],"selector":"input"})), Some(sid)).await?;
        client.send_command("DOM.setFileInputFiles", Some(json!({"nodeId":input["nodeId"],"files":[source]})), Some(sid)).await?;
        let size = evaluate(client, sid, "document.querySelector('input').files[0].size".into()).await?
            .as_u64().ok_or("remote_download_read_failed: missing file size")?;
        if expected.is_some_and(|n| n != size) { return Err("download_size_mismatch: remote file size differs".into()); }
        let staging = Staging(destination.with_file_name(format!(".agent-browser-{}.part", uuid::Uuid::new_v4())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staging.0).map_err(|e| format!("Create local download: {e}"))?;
        const CHUNK: u64 = 256 * 1024;
        for offset in (0..size).step_by(CHUNK as usize) {
            let end = (offset + CHUNK).min(size);
            let encoded = evaluate(client, sid, format!(
                "new Promise((resolve,reject)=>{{const r=new FileReader();r.onload=()=>resolve(r.result.split(',')[1]);r.onerror=()=>reject(r.error);r.readAsDataURL(document.querySelector('input').files[0].slice({offset},{end}));}})"
            )).await?;
            let bytes = STANDARD.decode(encoded.as_str().ok_or("Invalid remote download chunk")?).map_err(|e| e.to_string())?;
            if bytes.len() as u64 != end - offset { return Err("download_size_mismatch: incomplete transfer chunk".into()); }
            file.write_all(&bytes).map_err(|e| format!("Write local download: {e}"))?;
        }
        file.sync_all().map_err(|e| format!("Flush local download: {e}"))?;
        std::fs::rename(&staging.0, destination).map_err(|e| format!("Save local download: {e}"))?;
        Ok(())
    }.await;
    let closed = client
        .send_command("Target.closeTarget", Some(json!({"targetId":target})), None)
        .await;
    tab.closed = closed.is_ok();
    result?;
    closed.map_err(|e| {
        format!("Download saved locally, but closing its temporary transfer tab failed: {e}")
    })?;
    Ok(())
}
