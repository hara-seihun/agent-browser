//! Native form-control observation boundary. Known values are retained only in
//! daemon memory for the tab's protection state, never serialized or saved to disk.
//! Observation responses are protected before output or artifact publication.
use std::collections::{HashMap, HashSet};

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
    pub controls: HashMap<(String, i64), String>,
    secrets: Vec<(String, String)>,
}

impl Observation {
    pub fn has_sensitive(&self) -> bool {
        !self.controls.is_empty()
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
                    if AUTOCOMPLETE.iter().any(|(_, k)| *k == kind) {
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

/// Fail closed on incomplete frame inventory or an unreadable sensitive control.
/// CDP's pierced DOM includes closed shadow roots and same-process documents;
/// target-local DOM queries cover cross-origin out-of-process iframes.
pub async fn observe(
    client: &CdpClient,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Observation, String> {
    let (_, frames) = super::a11y::collect_frame_sessions(client, top_session, iframe_sessions)
        .await
        .map_err(|_| format!("{UNSUPPORTED}: frame inventory unavailable"))?;
    let mut sessions = HashSet::new();
    for frame in &frames {
        // Validates the frame/session association even for children omitted by
        // an unattached OOPIF. Failure is not permission to omit that frame.
        client.send_command("Page.createIsolatedWorld", Some(json!({ "frameId": frame.frame_id, "worldName": "agent-browser-sensitive-observation" })), Some(&frame.session_id)).await
            .map_err(|_| format!("{UNSUPPORTED}: frame observation unavailable"))?;
        sessions.insert(frame.session_id.clone());
    }
    let mut controls = Vec::new();
    for session in sessions {
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
            .ok_or_else(|| format!("{UNSUPPORTED}: DOM root unavailable"))?;
        collect_nodes(root, &session, &mut controls, &mut HashSet::new());
    }
    let mut observation = Observation::default();
    for control in controls {
        let redacted = marker(control.kind);
        observation
            .controls
            .insert((control.session.clone(), control.backend), redacted.clone());
        let resolved = client.send_command("DOM.resolveNode", Some(json!({ "backendNodeId": control.backend, "objectGroup": "agent-browser-sensitive" })), Some(&control.session)).await
            .map_err(|_| format!("{UNSUPPORTED}: sensitive control unavailable"))?;
        let object = resolved
            .get("object")
            .and_then(|v| v.get("objectId"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{UNSUPPORTED}: sensitive control handle unavailable"))?;
        let values = client.send_command("Runtime.callFunctionOn", Some(json!({
            "objectId": object,
            "functionDeclaration": "function() { return [String(this.value || ''), this.getAttribute('value') || '', this.tagName === 'TEXTAREA' ? this.textContent : '']; }",
            "returnByValue": true,
        })), Some(&control.session)).await.map_err(|_| format!("{UNSUPPORTED}: sensitive control observation failed"))?;
        if values.get("exceptionDetails").is_some() {
            return Err(format!(
                "{UNSUPPORTED}: sensitive control observation failed"
            ));
        }
        let values = values
            .get("result")
            .and_then(|v| v.get("value"))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{UNSUPPORTED}: sensitive control values unavailable"))?;
        for value in values {
            let value = value
                .as_str()
                .ok_or_else(|| format!("{UNSUPPORTED}: invalid control observation"))?;
            if !value.is_empty() {
                observation
                    .secrets
                    .push((value.to_string(), redacted.clone()));
            }
        }
        client
            .send_command(
                "Runtime.releaseObject",
                Some(json!({ "objectId": object })),
                Some(&control.session),
            )
            .await
            .map_err(|_| format!("{UNSUPPORTED}: sensitive observation cleanup failed"))?;
    }
    observation
        .secrets
        .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
    observation.secrets.dedup_by(|a, b| a.0 == b.0);
    Ok(observation)
}

pub async fn require_public(
    client: &CdpClient,
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
            | "state_show"
    ) || (action == "wait" && cmd.get("expression").is_some())
        || (action == "read" && cmd.get("url").is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
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
