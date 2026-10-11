//! Native form-control observation boundary. Known values are retained only in
//! daemon memory for the tab's protection state, never serialized or saved to disk.
//! Observation responses are protected before output or artifact publication.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures_util::{stream::FuturesUnordered, StreamExt};
use serde_json::{json, Value};

use super::cdp::client::CdpClient;

pub const UNSUPPORTED: &str = "SENSITIVE_OUTPUT_UNSUPPORTED";

const AUTOCOMPLETE: &[(&str, &str)] = &[
    ("cc-number", "cc-number"),
    ("cc-exp", "cc-exp"),
    ("cc-exp-month", "cc-exp-month"),
    ("cc-exp-year", "cc-exp-year"),
    ("cc-csc", "cc-csc"),
    ("current-password", "password"),
    ("new-password", "password"),
    ("one-time-code", "one-time-code"),
];
const IDENTIFIERS: &[(&str, &[&str])] = &[
    (
        "cc-number",
        &[
            "cardnumber",
            "creditcardnumber",
            "ccnumber",
            "cardno",
            "ccnum",
        ],
    ),
    (
        "cc-exp-month",
        &["expmonth", "expirymonth", "expirationmonth", "ccexpmonth"],
    ),
    (
        "cc-exp-year",
        &["expyear", "expiryyear", "expirationyear", "ccexpyear"],
    ),
    (
        "cc-exp",
        &[
            "expdate",
            "expirydate",
            "expirationdate",
            "cardexpiry",
            "cardexpiration",
            "ccexp",
            "expiry",
            "expiration",
        ],
    ),
    (
        "cc-csc",
        &[
            "cvc",
            "cvv",
            "cvv2",
            "cvc2",
            "securitycode",
            "cardsecuritycode",
            "cccsc",
            "cardcvc",
            "cardcvv",
        ],
    ),
    (
        "password",
        &["password", "currentpassword", "newpassword", "passwd"],
    ),
    (
        "one-time-code",
        &["onetimecode", "otp", "otpcode", "verificationcode"],
    ),
];

pub fn marker(kind: &str) -> String {
    format!("[redacted: {kind}]")
}

fn normalize(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn classify(attributes: &HashMap<String, String>) -> Option<&'static str> {
    if attributes
        .get("type")
        .is_some_and(|s| s.eq_ignore_ascii_case("password"))
    {
        return Some("password");
    }
    if let Some(autocomplete) = attributes.get("autocomplete") {
        for token in autocomplete.split_whitespace() {
            if let Some((_, kind)) = AUTOCOMPLETE
                .iter()
                .find(|(a, _)| token.eq_ignore_ascii_case(a))
            {
                return Some(kind);
            }
        }
        if autocomplete
            .split_whitespace()
            .any(|s| s.eq_ignore_ascii_case("cc-name"))
        {
            return None;
        }
    }
    for key in ["name", "id"] {
        if let Some(value) = attributes.get(key) {
            let normalized = normalize(value);
            for (kind, names) in IDENTIFIERS {
                if names.iter().any(|name| normalized.contains(name)) {
                    return Some(kind);
                }
            }
        }
    }
    None
}

/// Generated from the same classifier tables as CDP node classification.
/// Used inside synchronous getters and eval's execution-time DOM guard.
pub fn classifier_js() -> String {
    format!(
        r#"const kindOf = el => {{
      if (!el || !['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)) return null;
      if ((el.getAttribute('type') || '').toLowerCase() === 'password') return 'password';
      const tokens = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
      const autos = {};
      for (const token of tokens) if (autos[token]) return autos[token];
      if (tokens.includes('cc-name')) return null;
      const rules = {};
      for (const key of ['name', 'id']) {{
        const name = (el.getAttribute(key) || '').toLowerCase().replace(/[^a-z0-9]/g, '');
        for (const [kind, names] of rules) if (names.some(n => name.includes(n))) return kind;
      }}
      return null;
    }};"#,
        serde_json::to_string(&AUTOCOMPLETE.iter().copied().collect::<HashMap<_, _>>()).unwrap(),
        serde_json::to_string(IDENTIFIERS).unwrap(),
    )
}

/// A safe DOM projection, executed before returning any value to CDP. Live form
/// values and attributes are untouched, including fields needed for submission.
pub fn getter_js(operation: &str, attribute: Option<&str>) -> String {
    let read = match operation {
        "value" => "return this.value || '';".to_string(),
        "text" => "return this.innerText || this.textContent || '';".to_string(),
        "innertext" => "return this.innerText || '';".to_string(),
        "html" => {
            "const clone = this.cloneNode(true); sanitize(this, clone); return clone.innerHTML;"
                .to_string()
        }
        "attribute" => format!(
            "return this.getAttribute({});",
            json!(attribute.expect("attribute getter requires attribute"))
        ),
        _ => unreachable!("unknown protected getter"),
    };
    format!(
        r#"function() {{
      {}
      const kind = kindOf(this);
      if (kind) return '[redacted: ' + kind + ']';
      const sanitize = (original, clone) => {{
        const k = kindOf(original);
        if (k) {{
          const m = '[redacted: ' + k + ']';
          for (const a of Array.from(clone.attributes)) {{
            if (!['type','name','id','autocomplete'].includes(a.name)) clone.setAttribute(a.name, m);
          }}
          clone.setAttribute('value', m);
          if (clone.tagName !== 'INPUT') clone.textContent = m;
          return;
        }}
        for (let i = 0; i < original.childNodes.length; i++) sanitize(original.childNodes[i], clone.childNodes[i]);
      }};
      {}
    }}"#,
        classifier_js(),
        read
    )
}

/// Checks in the same synchronous execution turn as user code, before it runs.
/// Cross-origin and closed-root checks are performed by the CDP inventory too.
pub fn guarded_eval(script: &str) -> String {
    format!(
        r#"(() => {{
      {}
      const scan = root => {{
        for (const el of root.querySelectorAll('*')) {{
          if (kindOf(el)) throw new Error('SENSITIVE_OUTPUT_UNSUPPORTED: eval on sensitive document');
          if (el.shadowRoot) scan(el.shadowRoot);
          if (el.tagName === 'IFRAME' && el.contentDocument) scan(el.contentDocument);
        }}
      }};
      scan(document);
      return (0, eval)({});
    }})()"#,
        classifier_js(),
        json!(script)
    )
}

#[derive(Default)]
pub struct Observation {
    pub(crate) frame_sessions: HashSet<String>,
    pub controls: HashMap<(String, i64), String>,
    secrets: Vec<(String, String)>,
}

impl Observation {
    pub fn has_sensitive(&self) -> bool {
        !self.controls.is_empty()
    }

    pub fn remember_private_value(&mut self, session: &str, backend: i64, kind: &str, value: &str) {
        let redacted = marker(kind);
        self.controls
            .insert((session.to_owned(), backend), redacted.clone());
        if !value.is_empty() {
            self.secrets.push((value.to_owned(), redacted));
            self.secrets
                .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
            self.secrets.dedup_by(|a, b| a.0 == b.0);
        }
    }

    pub fn protect_text(&self, text: &str) -> String {
        // Single pass over the ORIGINAL string: replacement markers are never
        // themselves re-redacted (important for short expiry and CVC values).
        let mut out = String::new();
        let mut start = 0;
        while start < text.len() {
            if text[start..].starts_with("[redacted: ") {
                if let Some(end) = text[start..].find(']') {
                    let kind = &text[start + 11..start + end];
                    if kind == "credential" || AUTOCOMPLETE.iter().any(|(_, k)| *k == kind) {
                        out.push_str(&text[start..start + end + 1]);
                        start += end + 1;
                        continue;
                    }
                }
            }
            if let Some((secret, marker)) = self
                .secrets
                .iter()
                .find(|(s, _)| text[start..].starts_with(s))
            {
                out.push_str(marker);
                start += secret.len();
            } else {
                let ch = text[start..].chars().next().unwrap();
                out.push(ch);
                start += ch.len_utf8();
            }
        }
        out
    }

    pub fn protect(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.protect_text(text),
            Value::Array(values) => values.iter_mut().for_each(|v| self.protect(v)),
            Value::Object(values) => {
                let original = std::mem::take(values);
                for (key, mut value) in original {
                    self.protect(&mut value);
                    values.insert(self.protect_text(&key), value);
                }
            }
            _ => {}
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.frame_sessions = other.frame_sessions;
        self.controls.extend(other.controls);
        self.secrets.extend(other.secrets);
        self.secrets
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        self.secrets.dedup_by(|a, b| a.0 == b.0);
    }
}

struct Control {
    session: String,
    backend: i64,
    kind: &'static str,
}

fn collect_nodes(
    node: &Value,
    session: &str,
    controls: &mut Vec<Control>,
    seen: &mut HashSet<i64>,
) {
    if let Some(backend) = node.get("backendNodeId").and_then(Value::as_i64) {
        if seen.insert(backend)
            && node
                .get("nodeName")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s, "INPUT" | "TEXTAREA" | "SELECT"))
        {
            let mut attrs = HashMap::new();
            if let Some(attributes) = node.get("attributes").and_then(Value::as_array) {
                for pair in attributes.chunks_exact(2) {
                    if let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) {
                        attrs.insert(k.to_string(), v.to_string());
                    }
                }
            }
            if let Some(kind) = classify(&attrs) {
                controls.push(Control {
                    session: session.to_string(),
                    backend,
                    kind,
                });
            }
        }
    }
    for key in ["children", "shadowRoots", "pseudoElements"] {
        if let Some(children) = node.get(key).and_then(Value::as_array) {
            for child in children {
                collect_nodes(child, session, controls, seen);
            }
        }
    }
    for key in ["contentDocument", "templateContent"] {
        if let Some(doc) = node.get(key) {
            collect_nodes(doc, session, controls, seen);
        }
    }
}

fn collect_document_frames(
    node: &Value,
    session: &str,
    frames: &mut HashMap<String, String>,
    owners: &mut HashSet<String>,
) {
    if matches!(
        node.get("nodeName").and_then(Value::as_str),
        Some("IFRAME" | "FRAME")
    ) {
        if let Some(frame) = node.get("frameId").and_then(Value::as_str) {
            owners.insert(frame.to_owned());
        }
    }
    if let Some(document) = node
        .get("contentDocument")
        .filter(|value| value.is_object())
    {
        if let Some(frame) = document
            .get("frameId")
            .and_then(Value::as_str)
            .or_else(|| node.get("frameId").and_then(Value::as_str))
        {
            frames.insert(frame.to_owned(), session.to_owned());
        }
        collect_document_frames(document, session, frames, owners);
    }
    for key in ["children", "shadowRoots", "pseudoElements"] {
        if let Some(children) = node.get(key).and_then(Value::as_array) {
            for child in children {
                collect_document_frames(child, session, frames, owners);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct CoverageGap {
    pub missing_owners: Vec<String>,
    pub mismatched_frames: Vec<(String, String, Option<String>)>,
    covered: HashMap<String, String>,
    attached: HashMap<String, String>,
}

impl CoverageGap {
    /// Only represented but uncached frames may request attachment recovery.
    pub(crate) fn unattached_frames(&self) -> HashSet<String> {
        self.missing_owners
            .iter()
            .chain(self.mismatched_frames.iter().map(|(frame, _, _)| frame))
            .filter(|frame| !self.attached.contains_key(*frame))
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub(crate) enum InventoryError {
    Unavailable(String),
    Coverage(CoverageGap),
}

impl From<String> for InventoryError {
    fn from(message: String) -> Self {
        Self::Unavailable(message)
    }
}

impl InventoryError {
    pub(crate) fn into_message(self) -> String {
        match self {
            Self::Unavailable(message) => message,
            Self::Coverage(gap) => format!(
                "{UNSUPPORTED}: frame document coverage unavailable: {}",
                json!({ "missingOwnerFrameIds": gap.missing_owners, "mismatchedFrameSessions": gap.mismatched_frames, "coveredFrameSessions": gap.covered, "attachedFrameSessions": gap.attached })
            ),
        }
    }
}

fn collect_tree_frames(
    tree: &Value,
    parent_session: &str,
    iframe_sessions: &HashMap<String, String>,
    frames: &mut HashMap<String, String>,
) -> Result<(), InventoryError> {
    let frame = tree["frame"]["id"]
        .as_str()
        .ok_or_else(|| format!("{UNSUPPORTED}: frame tree ID unavailable"))?;
    let session = iframe_sessions
        .get(frame)
        .map(String::as_str)
        .unwrap_or(parent_session);
    frames.insert(frame.to_owned(), session.to_owned());
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            collect_tree_frames(child, session, iframe_sessions, frames)?;
        }
    }
    Ok(())
}

/// Fail closed on incomplete frame inventory or an unreadable sensitive control.
/// Validate document coverage through pierced DOM, without executing renderer
/// JavaScript or creating worlds in newly attached, debugger-paused frames.
pub async fn observe(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Observation, String> {
    observe_inventory(client, top_session, iframe_sessions)
        .await
        .map_err(InventoryError::into_message)
}

struct InventoryDocument {
    session: String,
    tree: Value,
    root: Value,
    backend: i64,
}

async fn inventory_document(
    client: &CdpClient,
    session: String,
    expected_frame: Option<String>,
) -> Result<InventoryDocument, InventoryError> {
    let live = client
        .send_command_no_params("Page.getFrameTree", Some(&session))
        .await
        .map_err(|_| format!("{UNSUPPORTED}: frame session unavailable"))?;
    let root_frame = live["frameTree"]["frame"]["id"]
        .as_str()
        .ok_or_else(|| format!("{UNSUPPORTED}: frame inventory unavailable"))?;
    if expected_frame
        .as_deref()
        .is_some_and(|frame| frame != root_frame)
    {
        return Err(format!("{UNSUPPORTED}: frame session association changed").into());
    }
    let document = client
        .send_command(
            "DOM.getDocument",
            Some(json!({ "depth": -1, "pierce": true })),
            Some(&session),
        )
        .await
        .map_err(|_| format!("{UNSUPPORTED}: pierced DOM unavailable"))?;
    let root = document
        .get("root")
        .filter(|root| root["nodeName"] == "#document")
        .ok_or_else(|| format!("{UNSUPPORTED}: DOM root unavailable"))?;
    let backend = root["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or_else(|| format!("{UNSUPPORTED}: document identity unavailable"))?;
    if root["frameId"]
        .as_str()
        .is_some_and(|frame| frame != root_frame)
    {
        return Err(format!("{UNSUPPORTED}: document frame association changed").into());
    }
    Ok(InventoryDocument {
        session,
        tree: live["frameTree"].clone(),
        root: root.clone(),
        backend,
    })
}

async fn inventory_control(
    client: &CdpClient,
    control: &Control,
    object_group: &str,
) -> Result<Vec<String>, InventoryError> {
    let resolved = client
        .send_command(
            "DOM.resolveNode",
            Some(json!({ "backendNodeId": control.backend, "objectGroup": object_group })),
            Some(&control.session),
        )
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive control unavailable"))?;
    let object = resolved["object"]["objectId"]
        .as_str()
        .ok_or_else(|| format!("{UNSUPPORTED}: sensitive control handle unavailable"))?;
    let values = async {
        let values = client.send_command("Runtime.callFunctionOn", Some(json!({
            "objectId": object,
            "functionDeclaration": "function() { return [String(this.value || ''), this.getAttribute('value') || '', this.tagName === 'TEXTAREA' ? this.textContent : '']; }",
            "returnByValue": true,
        })), Some(&control.session)).await.map_err(|_| format!("{UNSUPPORTED}: sensitive control observation failed"))?;
        if values.get("exceptionDetails").is_some() {
            return Err(format!("{UNSUPPORTED}: sensitive control observation failed").into());
        }
        values["result"]["value"]
            .as_array()
            .ok_or_else(|| format!("{UNSUPPORTED}: sensitive control values unavailable"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{UNSUPPORTED}: invalid control observation").into())
            })
            .collect::<Result<Vec<String>, InventoryError>>()
    }
    .await;
    client
        .send_command(
            "Runtime.releaseObject",
            Some(json!({ "objectId": object })),
            Some(&control.session),
        )
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive observation cleanup failed"))?;
    values
}

async fn validate_inventory_document(
    client: &CdpClient,
    document: &InventoryDocument,
) -> Result<(), InventoryError> {
    let (live, root) = tokio::join!(
        client.send_command_no_params("Page.getFrameTree", Some(&document.session)),
        client.send_command(
            "DOM.getDocument",
            Some(json!({ "depth": 0, "pierce": true })),
            Some(&document.session),
        )
    );
    let live = live.map_err(|_| format!("{UNSUPPORTED}: frame session unavailable"))?;
    let root = root.map_err(|_| format!("{UNSUPPORTED}: pierced DOM unavailable"))?;
    if live["frameTree"] != document.tree
        || root["root"]["backendNodeId"].as_i64() != Some(document.backend)
        || root["root"]["nodeName"] != "#document"
        || root["root"]["frameId"]
            .as_str()
            .is_some_and(|frame| Some(frame) != document.tree["frame"]["id"].as_str())
    {
        return Err(format!("{UNSUPPORTED}: observed document changed").into());
    }
    Ok(())
}

/// Follow only frame-tree claims and pierced-DOM owners of this tab. An OOPIF
/// may be absent from its parent's frame tree while its DOM owner is present.
/// Independent represented sessions and sensitive controls are observed concurrently,
/// with tree and document identities rechecked before admitting the complete result.
/// Renderer groups register connection-owned cancellation cleanup before resolve;
/// cancellation cannot dispatch further value reads or abandon remote handles.
/// Cached sessions from unrelated tabs are not evidence of membership.
pub(crate) async fn observe_inventory(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Observation, InventoryError> {
    client
        .settle_object_cleanup()
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
    let mut frames = HashMap::new();
    let mut covered = HashMap::new();
    let mut owners = HashSet::new();
    let mut controls = Vec::new();
    let mut sessions = FuturesUnordered::new();
    sessions.push(inventory_document(client, top_session.to_owned(), None));
    let mut documents = Vec::new();
    let mut visited = HashSet::from([top_session.to_owned()]);
    while let Some(document) = sessions.next().await {
        let document = document?;
        let session = &document.session;
        let root_frame = document.tree["frame"]["id"].as_str().unwrap();
        collect_tree_frames(&document.tree, session, iframe_sessions, &mut frames)?;
        covered.insert(root_frame.to_owned(), session.clone());
        collect_document_frames(&document.root, session, &mut covered, &mut owners);
        collect_nodes(&document.root, session, &mut controls, &mut HashSet::new());
        for frame in frames.keys().chain(owners.iter()) {
            if let Some(sid) = iframe_sessions.get(frame) {
                if visited.insert(sid.clone()) {
                    sessions.push(inventory_document(client, sid.clone(), Some(frame.clone())));
                }
            }
        }
        documents.push(document);
    }
    let mut missing_owners: Vec<_> = owners
        .iter()
        .filter(|frame| !covered.contains_key(*frame))
        .cloned()
        .collect();
    let mut mismatched_frames: Vec<_> = frames
        .iter()
        .filter(|(frame, session)| covered.get(*frame) != Some(*session))
        .map(|(frame, session)| (frame.clone(), session.clone(), covered.get(frame).cloned()))
        .collect();
    if !missing_owners.is_empty() || !mismatched_frames.is_empty() {
        missing_owners.sort();
        mismatched_frames.sort();
        return Err(InventoryError::Coverage(CoverageGap {
            missing_owners,
            mismatched_frames,
            covered,
            attached: iframe_sessions.clone(),
        }));
    }
    let mut observation = Observation {
        frame_sessions: visited
            .into_iter()
            .filter(|session| session != top_session)
            .collect(),
        ..Observation::default()
    };
    let control_sessions: HashSet<_> = controls
        .iter()
        .map(|control| control.session.clone())
        .collect();
    let object_group = client
        .object_group(control_sessions.into_iter().collect())
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
    let values = futures_util::future::join_all(
        controls
            .iter()
            .map(|control| inventory_control(client, control, &object_group.name)),
    )
    .await;
    for (control, values) in controls.iter().zip(values) {
        let redacted = marker(control.kind);
        observation
            .controls
            .insert((control.session.clone(), control.backend), redacted.clone());
        for value in values? {
            if !value.is_empty() {
                observation.secrets.push((value, redacted.clone()));
            }
        }
    }
    for validation in futures_util::future::join_all(
        documents
            .iter()
            .map(|document| validate_inventory_document(client, document)),
    )
    .await
    {
        validation?;
    }
    object_group.finish();
    client
        .settle_object_cleanup()
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
    observation
        .secrets
        .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
    observation.secrets.dedup_by(|a, b| a.0 == b.0);
    Ok(observation)
}

pub async fn require_public(
    client: &Arc<CdpClient>,
    session: &str,
    frames: &HashMap<String, String>,
) -> Result<(), String> {
    if observe(client, session, frames).await?.has_sensitive() {
        Err(format!("{UNSUPPORTED}: sensitive form controls present"))
    } else {
        Ok(())
    }
}

pub fn always_denied(action: &str) -> bool {
    matches!(
        action,
        "recording_start"
            | "recording_restart"
            | "recording_stop"
            | "video_start"
            | "video_stop"
            | "trace_start"
            | "trace_stop"
            | "profiler_start"
            | "profiler_stop"
            | "har_start"
            | "har_stop"
            | "screencast_start"
            | "screencast_stop"
            | "stream_enable"
            | "inspect"
            | "expose"
            | "addinitscript"
    )
}

pub fn guarded(action: &str, cmd: &Value) -> bool {
    matches!(
        action,
        "evaluate"
            | "evalhandle"
            | "addscript"
            | "waitforfunction"
            | "screenshot"
            | "pdf"
            | "diff_screenshot"
            | "download"
            | "waitfordownload"
            | "react_tree"
            | "react_inspect"
            | "react_suspense"
            | "a11y"
            | "webmcp_invoke"
            | "webmcp_result"
            | "console"
            | "errors"
            | "requests"
            | "request_detail"
            | "responsebody"
            | "clipboard"
            | "storage_get"
            | "cookies_get"
            | "state_save"
            | "state_save_tab"
            | "state_load_tab"
            | "state_show"
    ) || (action == "wait" && cmd.get("expression").is_some())
        || (action == "read" && cmd.get("url").is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn payment_inventory_needs_no_isolated_world() {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut world_requests = 0;
            while let Some(Ok(message)) = socket.next().await {
                if message.is_close() {
                    break;
                }
                if !message.is_text() {
                    continue;
                }
                let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let session = request["sessionId"].as_str().unwrap_or("");
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" if session == "top-session" => {
                        json!({"frameTree":{"frame":{"id":"top"},"childFrames":[{"frame":{"id":"payment", "parentId":"top"}}]}})
                    }
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"payment", "parentId":"top"}}})
                    }
                    "DOM.getDocument" if session == "top-session" => {
                        json!({"root":{"nodeName":"#document", "backendNodeId":100, "children":[{"nodeName":"IFRAME", "frameId":"payment"}]}})
                    }
                    "DOM.getDocument" => {
                        json!({"root":{"nodeName":"#document", "backendNodeId":101, "children":[{"nodeName":"INPUT", "backendNodeId":1, "attributes":["autocomplete","cc-number"]}]}})
                    }
                    "DOM.resolveNode" => json!({"object":{"objectId":"synthetic-card"}}),
                    "Runtime.callFunctionOn" => {
                        json!({"result":{"value":["4242424242424242", "", ""]}})
                    }
                    "Runtime.releaseObject" | "Runtime.releaseObjectGroup" => json!({}),
                    "Page.createIsolatedWorld" => {
                        world_requests += 1;
                        let reply = json!({"id":request["id"], "error":{"code":-32000,"message":"Frame observation unavailable while target transitions"}});
                        socket
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                reply.to_string().into(),
                            ))
                            .await
                            .unwrap();
                        continue;
                    }
                    method => panic!("Unexpected observation command {method}"),
                };
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"], "result":result})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            world_requests
        });
        let client = Arc::new(
            CdpClient::connect(&format!("ws://{address}"))
                .await
                .unwrap(),
        );
        let observed = observe(
            &client,
            "top-session",
            &HashMap::from([("payment".into(), "payment-session".into())]),
        )
        .await
        .unwrap();
        assert!(observed.has_sensitive());
        assert_eq!(
            observed.protect_text("4242424242424242"),
            "[redacted: cc-number]"
        );
        client.close().await;
        assert_eq!(server.await.unwrap(), 0);
    }

    #[test]
    fn private_values_are_sticky_and_marker_safe() {
        let mut observed = Observation::default();
        observed.remember_private_value("frame-session", 17, "credential", "Synthetic-123");
        assert!(observed.has_sensitive());
        assert_eq!(
            observed.controls[&("frame-session".into(), 17)],
            "[redacted: credential]"
        );
        assert_eq!(
            observed.protect_text("Synthetic-123 [redacted: credential]"),
            "[redacted: credential] [redacted: credential]"
        );
    }

    #[test]
    fn pierced_document_coverage_keeps_unattached_frames_uncovered() {
        let node = json!({"children":[
            {"nodeName":"IFRAME", "frameId":"same", "contentDocument":{"frameId":"same", "children":[
                {"nodeName":"IFRAME", "frameId":"remote"}
            ]}},
            {"nodeName":"FRAME", "frameId":"other", "contentDocument":{"children":[]}},
            {"nodeName":"IFRAME", "frameId":"null-document-id", "contentDocument":{"frameId":null,"children":[]}},
            {"nodeName":"IFRAME", "frameId":"missing-document", "contentDocument":null}
        ]});
        let mut covered = HashMap::new();
        let mut owners = HashSet::new();
        collect_document_frames(&node, "top-session", &mut covered, &mut owners);
        assert_eq!(covered["same"], "top-session");
        assert_eq!(covered["other"], "top-session");
        assert_eq!(covered["null-document-id"], "top-session");
        assert!(owners.contains("remote"));
        assert!(!covered.contains_key("remote"));
        assert!(!covered.contains_key("missing-document"));
    }

    #[test]
    fn sensitive_classifier_and_markers() {
        for (token, kind) in AUTOCOMPLETE {
            assert_eq!(
                classify(&HashMap::from([(
                    "autocomplete".into(),
                    format!("section-payment {token}")
                )])),
                Some(*kind)
            );
        }
        for (name, kind) in [
            ("cardnumber", "cc-number"),
            ("exp-date", "cc-exp"),
            ("cvc", "cc-csc"),
            ("cvv", "cc-csc"),
            ("securitycode", "cc-csc"),
        ] {
            assert_eq!(
                classify(&HashMap::from([("id".into(), name.into())])),
                Some(kind)
            );
        }
        assert_eq!(
            classify(&HashMap::from([("autocomplete".into(), "cc-name".into())])),
            None
        );
        assert_eq!(
            classify(&HashMap::from([
                ("type".into(), "password".into()),
                ("autocomplete".into(), "cc-name".into())
            ])),
            Some("password")
        );
        let obs = Observation {
            frame_sessions: HashSet::new(),
            controls: HashMap::new(),
            secrets: vec![
                ("4242424242424242".into(), marker("cc-number")),
                ("12".into(), marker("cc-exp-month")),
            ],
        };
        assert_eq!(
            obs.protect_text("4242424242424242 12 test"),
            "[redacted: cc-number] [redacted: cc-exp-month] test"
        );
    }
}
