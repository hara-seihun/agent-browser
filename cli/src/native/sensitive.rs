//! Native form-control observation boundary. Known values are retained only in
//! daemon memory for the tab's protection state, never serialized or saved to disk.
//! Observation responses are protected before output or artifact publication.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use futures_util::{stream::FuturesUnordered, StreamExt};
use serde_json::{json, Value};

use super::cdp::client::CdpClient;
use super::observation_progress::{DeadlineDiagnostic, Phase};

pub const UNSUPPORTED: &str = "SENSITIVE_OUTPUT_UNSUPPORTED";
pub const MIN_SECRET_CHARS: usize = 3;

fn useful_secret(value: &str) -> bool {
    // Private text inventories include layout-only descendants. Keep those nodes
    // scoped, but never let their indentation become a global credential match.
    !value.trim().is_empty()
        && value.chars().take(MIN_SECRET_CHARS).count() == MIN_SECRET_CHARS
}

// Always-private token families are credentials even without a nearby label.
// The boolean selects URL-safe base64 characters rather than alphanumerics.
// Publishable pk_ keys deliberately remain ordinary public text. Keep the same
// table in Rust response filtering and generated execution-time DOM guards.
const PRIVATE_TOKEN_PATTERNS: &[(&str, usize, bool)] = &[
    ("sk_test_", 8, false),
    ("sk_live_", 8, false),
    ("rk_test_", 8, false),
    ("rk_live_", 8, false),
    ("whsec_", 8, false),
    ("bu_", 20, true),
];

fn private_token_length(text: &str) -> Option<usize> {
    PRIVATE_TOKEN_PATTERNS.iter().find_map(|(prefix, minimum, url_safe)| {
        let rest = text.strip_prefix(prefix)?;
        let length = rest.bytes().take_while(|byte| {
            byte.is_ascii_alphanumeric() || (*url_safe && matches!(*byte, b'_' | b'-'))
        }).count();
        (length >= *minimum).then_some(prefix.len() + length)
    })
}

fn has_private_token(text: &str) -> bool {
    text.char_indices()
        .any(|(start, _)| private_token_length(&text[start..]).is_some())
}

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
        &[
            "onetimecode",
            "otp",
            "otpcode",
            "verificationcode",
            "enteryourcode",
        ],
    ),
    (
        "recovery-code",
        &["recoverycode", "backupcode", "2farecovery"],
    ),
];

// Some contact forms use new-password to suppress browser autofill on names
// and email addresses. Only ignore that token with positive contact semantics;
// password controls, credential hints and privately filled controls stay private.
const CONTACT_HINTS: &[&str] = &[
    "name",
    "fullname",
    "fullnameoptional",
    "firstname",
    "lastname",
    "givenname",
    "familyname",
    "recipientname",
    "contactname",
    "email",
    "emailaddress",
    "recipientemail",
    "contactemail",
];
const FIELD_HINT_KEYS: &[&str] = &["name", "id", "aria-label", "placeholder", "label"];

// Password recovery describes the workflow, not the contents of its email input.
// Strip that phrase before inferring a secret from a name: "forgotpassword"
// also contains "otp". Explicit autocomplete, remaining secret hints and
// remembered private-fill node identities still take precedence.
const PASSWORD_RECOVERY_HINTS: &[&str] = &[
    "forgotpassword",
    "forgottenpassword",
    "resetpassword",
    "passwordreset",
    "recoverpassword",
    "passwordrecovery",
];

fn field_hint(attributes: &HashMap<String, String>, value: &str) -> String {
    let mut hint = normalize(value);
    if attributes
        .get("type")
        .is_some_and(|kind| kind.eq_ignore_ascii_case("email"))
    {
        for workflow in PASSWORD_RECOVERY_HINTS {
            hint = hint.replace(workflow, "");
        }
    }
    hint
}

fn contact_field(attributes: &HashMap<String, String>) -> bool {
    let hints: Vec<_> = FIELD_HINT_KEYS
        .iter()
        .filter_map(|key| attributes.get(*key))
        .flat_map(|value| value.lines())
        .map(|value| field_hint(attributes, value))
        .collect();
    if hints.iter().any(|hint| {
        api_text_label(hint)
            || IDENTIFIERS
                .iter()
                .any(|(_, names)| names.iter().any(|name| hint.contains(name)))
    }) {
        return false;
    }
    attributes
        .get("type")
        .is_some_and(|kind| kind.eq_ignore_ascii_case("email"))
        || hints
            .iter()
            .any(|hint| CONTACT_HINTS.contains(&hint.as_str()))
}

const OTP_HINTS: &[&str] = &[
    "otp",
    "code",
    "token",
    "pin",
    "passcode",
    "2fa",
    "mfa",
    "verif",
    "sms",
    "authenticator",
];
const OTP_TYPES: &[&str] = &["", "text", "number"];

// These names identify displayed credentials, including OAuth authorization codes,
// not arbitrary UUIDs or source-code blocks elsewhere on a page.
const API_TEXT_LABELS: &[&str] = &[
    "apikey",
    "apisecret",
    "secretkey",
    "accesskey",
    "clientsecret",
    "accesstoken",
    "authtoken",
    "bearertoken",
    "privatetoken",
    "accesskeyid",
    "secretaccesskey",
    "scwsecretkey",
    "scwaccesskey",
    "authcode",
    "authorizationcode",
    "authorisationcode",
    "oauthcode",
    "oauthauthorizationcode",
    "oauthauthorisationcode",
    "oauth2authorizationcode",
    "yourauthorizationcode",
    "backupcode",
    "backupcodes",
    "recoverycode",
    "recoverycodes",
    "emergencybackupcode",
    "saveyourbackupcode",
    "saveyourrecoverycode",
];

fn api_text_label(text: &str) -> bool {
    if text.len() > 64 {
        return false;
    }
    let label = normalize(text);
    API_TEXT_LABELS.contains(&label.as_str())
}

fn api_labeled_value(text: &str) -> Option<&str> {
    let text = text.trim().strip_prefix("export ").unwrap_or(text.trim());
    text.char_indices().take(64).find_map(|(offset, ch)| {
        if !(ch.is_whitespace() || ch == ':' || ch == '=') || !api_text_label(&text[..offset]) {
            return None;
        }
        let value = text[offset..]
            .trim_start_matches(|ch: char| ch.is_whitespace() || ch == ':' || ch == '=');
        api_value(value).then_some(value)
    })
}

// Bound work per element even on very broad or deeply nested pages.
fn api_node_label(node: &Value) -> bool {
    fn read(node: &Value, text: &mut String) -> bool {
        let value = node["nodeValue"].as_str().unwrap_or("");
        if text.len() + value.len() > 64 {
            return false;
        }
        text.push_str(value);
        node["children"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|child| read(child, text))
    }
    let mut text = String::new();
    read(node, &mut text) && api_text_label(&text)
}

fn api_value(text: &str) -> bool {
    let text = text.trim();
    text.len() >= 8
        && text.len() <= 512
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-/.+=".contains(&b))
        && text.bytes().any(|b| b.is_ascii_alphanumeric())
}

// Find the smallest field containing one exact API label and a displayed token.
// Text nodes are bound to their containing element for screenshot geometry.
// Completed fields never donate their values to an ancestor's unrelated label.
fn api_display_nodes(root: &Value) -> HashSet<i64> {
    fn walk(
        node: &Value,
        parent: Option<i64>,
        found: &mut HashSet<i64>,
    ) -> (usize, Vec<(i64, usize)>) {
        let backend = node["backendNodeId"].as_i64().or(parent);
        if matches!(node["nodeName"].as_str(), Some("SCRIPT" | "STYLE")) {
            return (0, Vec::new());
        }
        if node["nodeName"] == "#text" {
            let text = node["nodeValue"].as_str().unwrap_or("");
            if has_private_token(text) {
                if let Some(parent) = parent {
                    found.insert(parent);
                }
                // This is a complete credential, not a label for sibling values.
                return (0, Vec::new());
            }
            if text.lines().any(|line| api_labeled_value(line).is_some()) {
                if let Some(parent) = parent {
                    found.insert(parent);
                }
                return (0, Vec::new());
            }
            return (
                usize::from(api_text_label(text)),
                parent
                    .filter(|_| api_value(text))
                    .map(|id| vec![(id, 0)])
                    .unwrap_or_default(),
            );
        }
        if api_node_label(node) {
            return (1, Vec::new());
        }
        let mut labels = 0;
        let mut values = Vec::new();
        for child in node["children"].as_array().into_iter().flatten() {
            let (count, candidates) = walk(child, backend, found);
            labels += count;
            values.extend(
                candidates
                    .into_iter()
                    .filter_map(|(id, depth)| (depth < 4).then_some((id, depth + 1))),
            );
        }
        if labels == 1 && !values.is_empty() {
            found.extend(values.drain(..).map(|(id, _)| id));
            labels = 0;
        }
        for key in ["shadowRoots", "pseudoElements"] {
            for child in node[key].as_array().into_iter().flatten() {
                walk(child, None, found);
            }
        }
        for key in ["contentDocument", "templateContent"] {
            if let Some(child) = node.get(key) {
                walk(child, None, found);
            }
        }
        (labels, values)
    }
    // A recovery-code dialog often separates its heading from a deeply nested
    // list. Protect list items as a group, regardless of token shape or depth.
    fn recovery_dialogs(node: &Value, found: &mut HashSet<i64>) {
        fn attrs(node: &Value) -> HashMap<String, String> {
            node["attributes"].as_array().into_iter().flatten().collect::<Vec<_>>()
                .chunks_exact(2).filter_map(|pair| Some((pair[0].as_str()?.to_ascii_lowercase(), pair[1].as_str()?.to_ascii_lowercase()))).collect()
        }
        fn heading(node: &Value) -> bool {
            let name = node["nodeName"].as_str().unwrap_or("");
            let a = attrs(node);
            let is_heading = matches!(name, "H1" | "H2" | "H3" | "H4" | "H5" | "H6") || a.get("role").is_some_and(|r| r == "heading");
            fn text(node: &Value, out: &mut String) {
                if let Some(t) = node["nodeValue"].as_str() { out.push_str(t); }
                for child in node["children"].as_array().into_iter().flatten() { text(child, out); }
            }
            if is_heading {
                let mut value = String::new(); text(node, &mut value);
                let value = normalize(&value);
                if value.contains("backupcode") || value.contains("recoverycode") { return true; }
            }
            node["children"].as_array().into_iter().flatten().any(heading)
        }
        fn items(node: &Value, found: &mut HashSet<i64>) {
            let a = attrs(node);
            if node["nodeName"] == "LI" || a.get("role").is_some_and(|r| r == "listitem") {
                if let Some(id) = node["backendNodeId"].as_i64() { found.insert(id); }
            }
            for child in node["children"].as_array().into_iter().flatten() { items(child, found); }
        }
        let a = attrs(node);
        if (node["nodeName"] == "DIALOG" || a.get("role").is_some_and(|r| r == "dialog" || r == "alertdialog")) && heading(node) { items(node, found); }
        for key in ["children", "shadowRoots", "pseudoElements"] {
            for child in node[key].as_array().into_iter().flatten() { recovery_dialogs(child, found); }
        }
        for key in ["contentDocument", "templateContent"] { if let Some(child) = node.get(key) { recovery_dialogs(child, found); } }
    }
    let mut found = HashSet::new();
    walk(root, None, &mut found);
    recovery_dialogs(root, &mut found);
    found
}

// Explicit private page text is protected even when it is not a form control.
const PRIVATE_TEXT_LABELS: &[&str] = &[
    "totpsecret",
    "otpsecret",
    "authenticatorsecret",
    "authenticatorseed",
    "totpseed",
    "otpseed",
    "twofactorsecret",
    "2fasecret",
    "mfasecret",
];

fn private_text(attributes: &HashMap<String, String>) -> bool {
    attributes.values().any(|value| has_private_token(value))
        || attributes
            .get("data-private")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
        || attributes.get("aria-label").is_some_and(|label| {
            let label = normalize(label);
            PRIVATE_TEXT_LABELS.iter().any(|hint| label.contains(hint))
        })
        || ["aria-label", "title", "id", "name"]
            .iter()
            .filter_map(|key| attributes.get(*key))
            .any(|label| api_text_label(label))
        || attributes
            .get("class")
            .is_some_and(|classes| classes.split_whitespace().any(api_text_label))
}

/// `autocomplete="one-time-code"` alone does not make a field a one-time code:
/// some forms put it on every field. It protects only a single-line input that
/// is code-shaped (short maxlength, numeric inputmode or pattern, or a code-like
/// name, id, aria-label or placeholder).
fn otp_shaped(attributes: &HashMap<String, String>) -> bool {
    if attributes
        .get("tagname")
        .is_some_and(|t| !t.eq_ignore_ascii_case("input"))
    {
        return false;
    }
    let kind = attributes
        .get("type")
        .map(|t| t.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !OTP_TYPES.contains(&kind.as_str()) {
        return false;
    }
    if attributes
        .get("maxlength")
        .and_then(|m| m.trim().parse::<i64>().ok())
        .is_some_and(|m| (1..=12).contains(&m))
    {
        return true;
    }
    if kind == "number"
        || attributes.contains_key("pattern")
        || attributes
            .get("inputmode")
            .is_some_and(|m| m.eq_ignore_ascii_case("numeric"))
    {
        return true;
    }
    ["name", "id", "aria-label", "placeholder"]
        .iter()
        .filter_map(|key| attributes.get(*key))
        .any(|value| {
            let normalized = normalize(value);
            OTP_HINTS.iter().any(|hint| normalized.contains(hint))
        })
}

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
                if token.eq_ignore_ascii_case("new-password") && contact_field(attributes) {
                    continue;
                }
                if *kind != "one-time-code" || otp_shaped(attributes) {
                    return Some(kind);
                }
            }
        }
        if autocomplete
            .split_whitespace()
            .any(|s| s.eq_ignore_ascii_case("cc-name"))
        {
            return None;
        }
    }
    for key in ["name", "id", "aria-label", "placeholder", "label"] {
        if let Some(value) = attributes.get(key) {
            let normalized = field_hint(attributes, value);
            if api_text_label(&normalized) {
                return Some("credential");
            }
            if matches!(normalized.as_str(), "mmyy" | "mmyyyy") {
                return Some("cc-exp");
            }
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
        r#"const apiLabels = {};
    const privateTokenPatterns = {};
    const privateToken = text => privateTokenPatterns.some(([prefix, minimum, urlSafe]) => {{
      let at = -1;
      while ((at = text.indexOf(prefix, at + 1)) !== -1) {{
        const rest = text.slice(at + prefix.length);
        const token = rest.match(urlSafe ? /^[A-Za-z0-9_-]+/ : /^[A-Za-z0-9]+/);
        if (token && token[0].length >= minimum) return true;
      }}
      return false;
    }});
    const apiLabel = text => {{
      if (!text || text.length > 64) return false;
      const label = text.toLowerCase().replace(/[^a-z0-9]/g, '');
      return apiLabels.includes(label);
    }};
    const apiValue = text => /^[a-z0-9_\-/.+=]{{8,512}}$/i.test(text) && /[a-z0-9]/i.test(text);
    const apiLabeledValue = text => {{
      text = text.trim().replace(/^export /, '');
      for (let i = 0; i < Math.min(64, text.length); i++) {{
        if (/[\s:=]/.test(text[i]) && apiLabel(text.slice(0, i)) && apiValue(text.slice(i).replace(/^[\s:=]+/, ''))) return true;
      }}
      return false;
    }};
    const apiNodeLabel = node => {{
      let text = '';
      const read = node => {{
        const value = node.nodeValue || '';
        if (text.length + value.length > 64) return false;
        text += value;
        return Array.from(node.childNodes).every(read);
      }};
      return read(node) && apiLabel(text);
    }};
    const apiRoots = new WeakMap();
    const apiDisplay = el => {{
      const root = el.getRootNode();
      if (!apiRoots.has(root)) {{
        const found = new Set();
        const walk = node => {{
          if (node.nodeType === 1 && ['SCRIPT','STYLE'].includes(node.tagName)) return [0, []];
          if (node.nodeType === 3) {{
            const text = (node.textContent || '').trim();
            if (privateToken(text)) {{
              if (node.parentElement) found.add(node.parentElement);
              return [0, []];
            }}
            if (text.split(/\r?\n/).some(apiLabeledValue)) {{
              if (node.parentElement) found.add(node.parentElement);
              return [0, []];
            }}
            return [apiLabel(text) ? 1 : 0,
              node.parentElement && apiValue(text) ? [[node.parentElement, 0]] : []];
          }}
          if (apiNodeLabel(node)) return [1, []];
          let labels = 0, values = [];
          for (const child of node.childNodes) {{
            const [count, candidates] = walk(child);
            labels += count;
            values.push(...candidates.filter(([, depth]) => depth < 4).map(([el, depth]) => [el, depth + 1]));
          }}
          if (labels === 1 && values.length) {{
            for (const [el] of values) found.add(el);
            values = [];
            labels = 0;
          }}
          return [labels, values];
        }};
        walk(root);
        for (const dialog of root.querySelectorAll('dialog,[role="dialog"],[role="alertdialog"]')) {{
          const headings = dialog.querySelectorAll('h1,h2,h3,h4,h5,h6,[role="heading"]');
          if (Array.from(headings).some(h => /(?:backup|recovery)code/.test((h.textContent || '').toLowerCase().replace(/[^a-z0-9]/g, '')))) {{
            for (const item of dialog.querySelectorAll('li,[role="listitem"]')) found.add(item);
          }}
        }}
        apiRoots.set(root, found);
      }}
      return apiRoots.get(root).has(el);
    }};
    const privateText = el => Array.from(el.attributes).some(a => privateToken(a.value))
      || (el.getAttribute('data-private') || '').trim().toLowerCase() === 'true'
      || {}.some(hint => (el.getAttribute('aria-label') || '').toLowerCase().replace(/[^a-z0-9]/g, '').includes(hint))
      || ['aria-label', 'title', 'id', 'name'].some(key => apiLabel(el.getAttribute(key)))
      || (el.getAttribute('class') || '').split(/\s+/).some(apiLabel)
      || apiLabel((el.getAttribute('aria-labelledby') || '').split(/\s+/).map(id => el.getRootNode().getElementById(id)?.textContent || '').join(' '))
      || apiDisplay(el);
    const kindOf = el => {{
      if (!el || el.nodeType !== 1) return null;
      for (let parent = el; parent; parent = parent.parentElement || parent.getRootNode().host) {{
        if (privateText(parent)) return 'credential';
      }}
      if (!['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) && !el.isContentEditable) return null;
      if ((el.getAttribute('type') || '').toLowerCase() === 'password') return 'password';
      const root = el.getRootNode();
      const labels = Array.from(el.labels || []).map(label => label.textContent || '');
      if (el.isContentEditable && el.id) {{
        for (const label of root.querySelectorAll('label[for]')) {{
          if (label.htmlFor === el.id) labels.push(label.textContent || '');
        }}
      }}
      const wrapping = el.closest('label');
      if (wrapping) labels.push(wrapping.textContent || '');
      for (const id of (el.getAttribute('aria-labelledby') || '').split(/\s+/)) {{
        if (id) labels.push(root.getElementById(id)?.textContent || '');
      }}
      const hints = ['name', 'id', 'aria-label', 'placeholder'].map(key => el.getAttribute(key) || '').concat(labels);
      const rules = {};
      const contactHints = {};
      const recoveryHints = {};
      const fieldHint = hint => {{
        const name = hint.toLowerCase().replace(/[^a-z0-9]/g, '');
        return (el.getAttribute('type') || '').toLowerCase() === 'email'
          ? recoveryHints.reduce((text, workflow) => text.replaceAll(workflow, ''), name) : name;
      }};
      const contactField = ((el.getAttribute('type') || '').toLowerCase() === 'email'
        || hints.some(hint => contactHints.includes(fieldHint(hint))))
        && !hints.some(hint => {{
          const name = fieldHint(hint);
          return apiLabel(name) || rules.some(([, names]) => names.some(n => name.includes(n)));
        }});
      const tokens = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
      const autos = {};
      const otpShaped = () => {{
        if (el.tagName !== 'INPUT') return false;
        const type = (el.getAttribute('type') || '').trim().toLowerCase();
        if (!['', 'text', 'number'].includes(type)) return false;
        const max = parseInt((el.getAttribute('maxlength') || '').trim(), 10);
        if (max >= 1 && max <= 12) return true;
        if (type === 'number' || el.hasAttribute('pattern') || (el.getAttribute('inputmode') || '').toLowerCase() === 'numeric') return true;
        return ['name', 'id', 'aria-label', 'placeholder'].some(key => {{
          const name = (el.getAttribute(key) || '').toLowerCase().replace(/[^a-z0-9]/g, '');
          return {}.some(hint => name.includes(hint));
        }});
      }};
      for (const token of tokens) {{
        if (token === 'new-password' && contactField) continue;
        if (autos[token] && (autos[token] !== 'one-time-code' || otpShaped())) return autos[token];
      }}
      if (tokens.includes('cc-name')) return null;
      for (const hint of hints) {{
        const name = fieldHint(hint);
        if (apiLabel(name)) return 'credential';
        if (['mmyy', 'mmyyyy'].includes(name)) return 'cc-exp';
        for (const [kind, names] of rules) {{
          if (names.some(n => name.includes(n))) return kind;
        }}
      }}
      return null;
    }};"#,
        serde_json::to_string(API_TEXT_LABELS).unwrap(),
        serde_json::to_string(PRIVATE_TOKEN_PATTERNS).unwrap(),
        serde_json::to_string(PRIVATE_TEXT_LABELS).unwrap(),
        serde_json::to_string(IDENTIFIERS).unwrap(),
        serde_json::to_string(CONTACT_HINTS).unwrap(),
        serde_json::to_string(PASSWORD_RECOVERY_HINTS).unwrap(),
        serde_json::to_string(&AUTOCOMPLETE.iter().copied().collect::<HashMap<_, _>>()).unwrap(),
        serde_json::to_string(OTP_HINTS).unwrap(),
    )
}

/// A safe DOM projection, executed before returning any value to CDP. Rendered
/// text uses native innerText as its whitespace/visibility authority and masks
/// only mapped control spans. An unmappable span returns a typed refusal. Live
/// DOM, form values and attributes are untouched, including submission fields.
/// Non-value control metadata used to discover selectors for private fills.
/// The command still inventories the complete tab and redacts remembered values.
pub fn selector_metadata_attribute(attribute: &str) -> bool {
    matches!(
        attribute,
        "id" | "class" | "type" | "name" | "autocomplete" | "aria-label" | "aria-labelledby"
    )
}

pub fn getter_js(operation: &str, attribute: Option<&str>) -> String {
    if operation == "attribute" && attribute.is_some_and(selector_metadata_attribute) {
        return format!(
            "function() {{ return this.getAttribute({}); }}",
            json!(attribute.unwrap())
        );
    }
    let read = match operation {
        "value" => "return this.value || '';".to_string(),
        "text" => "return safeText(this, true);".to_string(),
        "innertext" => "return safeText(this, true);".to_string(),
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
      // Keep short select/contenteditable text protection scoped to its DOM subtree.
      // Public subtrees keep their native text; no short-value global substitution.
      const protectedAncestors = new Set();
      if (['text', 'innertext'].includes({})) {{
        for (const el of this.querySelectorAll('*')) {{
          if (kindOf(el)) {{
            for (let parent = el.parentElement; parent && this.contains(parent); parent = parent.parentElement) {{
              if (protectedAncestors.has(parent)) break;
              protectedAncestors.add(parent);
            }}
          }}
        }}
      }}
      const mappingError = () => {{
        throw new Error('SENSITIVE_OUTPUT_UNSUPPORTED: protected rendered text mapping unavailable');
      }};
      const nativeText = el => {{
        if (typeof el.innerText !== 'string') mappingError();
        return el.innerText;
      }};
      const safeText = (el, visible) => {{
        const k = kindOf(el);
        if (k) return '[redacted: ' + k + ']';
        const source = nativeText(el);
        if (!protectedAncestors.has(el)) return source;
        const rendered = visible && (getComputedStyle(el).display === 'contents' || el.getClientRects().length > 0);
        if (!rendered) mappingError();
        let cursor = 0;
        const edits = [];
        for (const child of el.childNodes) {{
          let original, projected;
          if (child.nodeType === 3) {{
            if (rendered && getComputedStyle(el).visibility !== 'visible') continue;
            original = child.textContent || '';
            if (rendered) {{
              const transform = getComputedStyle(el).textTransform;
              if (transform === 'uppercase') original = original.toLocaleUpperCase(el.lang || undefined);
              else if (transform === 'lowercase') original = original.toLocaleLowerCase(el.lang || undefined);
            }}
            projected = original;
          }} else if (child.nodeType === 1) {{
            if (rendered && getComputedStyle(child).display === 'none') continue;
            original = nativeText(child);
            projected = safeText(child, rendered);
          }} else continue;
          const core = original.trim();
          if (!core) continue;
          let start = source.indexOf(core, cursor);
          let end = start + core.length;
          // Whitespace-only gaps are native block/table/BR boundaries. Public
          // text nodes may have collapsed whitespace; never regenerate that text.
          if (start < cursor || !/^\s*$/.test(source.slice(cursor, start))) {{
            if (projected !== original) mappingError();
            const escaped = core.split(/\s+/).map(part => part.replace(/[.*+?^${{}}()|[\]\\]/g, '\\$&')).join('\\s+');
            const match = source.slice(cursor).match(new RegExp('^(\\s*)(' + escaped + ')'));
            if (!match) mappingError();
            start = cursor + match[1].length;
            end = start + match[2].length;
          }}
          if (projected !== original) edits.push([start, end, projected.trim()]);
          cursor = end;
        }}
        if (!/^\s*$/.test(source.slice(cursor))) mappingError();
        // Apply disjoint, DOM-ordered spans to the original browser-rendered text.
        // All characters outside the protected spans remain byte-for-byte native.
        let result = '', offset = 0;
        for (const [start, end, text] of edits) {{
          result += source.slice(offset, start) + text;
          offset = end;
        }}
        return result + source.slice(offset);
      }};
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
        json!(operation),
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

#[derive(Clone, Default)]
pub struct Observation {
    pub(crate) frame_sessions: HashSet<String>,
    pub controls: HashMap<(String, i64), String>,
    pub(crate) private_text_nodes: HashSet<(String, i64)>,
    // Complete current DOM membership, not just classified controls. Private-fill
    // controls retain protection while alive even if their attributes change.
    live_nodes: Option<HashSet<(String, i64)>>,
    secrets: Vec<(String, String)>,
    expiry_echoes: Vec<(String, String)>,
}

impl Observation {
    pub fn has_sensitive(&self) -> bool {
        !self.controls.is_empty()
    }

    pub fn remember_private_value(&mut self, session: &str, backend: i64, kind: &str, value: &str) {
        let redacted = marker(kind);
        self.controls
            .insert((session.to_owned(), backend), redacted.clone());
        if kind == "cc-exp" {
            self.remember_expiry_echo(value, &redacted);
        }
        if useful_secret(value) {
            // Exported text may include indentation outside the credential. Keep
            // the exact value private and protect its unpadded echo as well.
            self.secrets.push((value.to_owned(), redacted.clone()));
            let trimmed = value.trim();
            if trimmed != value && useful_secret(trimmed) {
                self.secrets.push((trimmed.to_owned(), redacted));
            }
            self.secrets
                .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
            self.secrets.dedup_by(|a, b| a.0 == b.0);
        }
    }

    /// A known combined expiry may be echoed with whitespace outside its control.
    /// Month/year fragments never enter this global matcher.
    fn remember_expiry_echo(&mut self, value: &str, redacted: &str) {
        let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
        let bytes = compact.as_bytes();
        if matches!(bytes.len(), 5 | 7)
            && bytes[2] == b'/'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 2 || b.is_ascii_digit())
            && matches!(compact[..2].parse::<u8>(), Ok(1..=12))
        {
            let pair = (compact, redacted.to_owned());
            if !self.expiry_echoes.contains(&pair) {
                self.expiry_echoes.push(pair);
            }
        }
    }

    pub(crate) fn remember_private_expiry_value(
        &mut self,
        session: &str,
        backend: i64,
        value: &str,
    ) {
        self.remember_private_value(session, backend, "credential", value);
        self.remember_expiry_echo(value, &marker("credential"));
    }

    /// Text-only exported fields protect AX names/descendants as well as values.
    pub(crate) fn remember_private_text(&mut self, session: &str, backend: i64, value: &str) {
        self.remember_private_value(session, backend, "credential", value);
        self.private_text_nodes
            .insert((session.to_owned(), backend));
    }

    /// Retires only global fragments; scoped control protection is unchanged.
    /// Reports counts by character length, never values or value-derived hashes.
    pub fn prune_secret_fragments(&mut self) -> BTreeMap<usize, usize> {
        let mut removed = BTreeMap::new();
        self.secrets.retain(|(value, _)| {
            if useful_secret(value) {
                true
            } else {
                *removed.entry(value.chars().count()).or_insert(0) += 1;
                false
            }
        });
        removed
    }

    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    pub fn protect_text(&self, text: &str) -> String {
        // Single pass over the ORIGINAL string: replacement markers are never
        // themselves re-redacted (important for short expiry and CVC values).
        // Skip the remembered-value search at positions whose first byte cannot
        // match any secret. This is only a rejection prefilter: candidates still
        // use exact, longest-first string matching and the same usefulness check.
        let mut secret_initials = [false; 256];
        for (secret, _) in &self.secrets {
            if let Some(first) = secret.as_bytes().first() {
                secret_initials[*first as usize] = true;
            }
        }
        let mut public_ids = public_social_id_spans(text);
        public_ids.extend(cdp_browser_id_spans(text));
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
            let remembered = if secret_initials[text.as_bytes()[start] as usize] {
                self.secrets
                    .iter()
                    // Most candidates do not match. Only classify a secret after
                    // its cheap byte-prefix comparison succeeds.
                    .find(|(s, _)| text[start..].starts_with(s) && useful_secret(s))
            } else {
                None
            };
            if let Some((secret, marker)) = remembered {
                out.push_str(marker);
                start += secret.len();
            } else if let Some(length) = private_token_length(&text[start..]) {
                out.push_str(&marker("credential"));
                start += length;
            } else if let Some((length, marker)) =
                self.expiry_echoes.iter().find_map(|(expiry, marker)| {
                    expiry_echo_length(&text[start..], expiry).map(|length| (length, marker))
                })
            {
                out.push_str(marker);
                start += length;
            } else if let Some(length) = text.as_bytes()[start]
                .is_ascii_digit()
                .then(|| payment_number_length(&text[start..]))
                .flatten()
                .filter(|_| start == 0 || !text.as_bytes()[start - 1].is_ascii_digit())
                .filter(|_| !public_ids.iter().any(|&(lo, hi)| lo <= start && start < hi))
            {
                out.push_str("[redacted: cc-number]");
                start += length;
            } else {
                let ch = text[start..].chars().next().unwrap();
                out.push(ch);
                start += ch.len_utf8();
            }
        }
        out
    }

    /// A scoped payment control may expose a short month/year in its name.
    /// Replace only the value span, preserving its useful action/field label.
    pub(crate) fn protect_control_name(&self, text: &str, redacted: &str) -> String {
        let Some(kind) = redacted
            .strip_prefix("[redacted: ")
            .and_then(|s| s.strip_suffix(']'))
        else {
            return self.protect_text(text);
        };
        let mut out = String::new();
        let mut offset = 0;
        for (start, end) in display_payment_spans(text, kind) {
            out.push_str(&text[offset..start]);
            out.push_str(redacted);
            offset = end;
        }
        out.push_str(&text[offset..]);
        self.protect_text(&out)
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

    /// Retain protection for live nodes and remembered values. Detached login
    /// fields in a single-page app must not make its later inbox sensitive.
    pub(crate) fn inherit_private(&mut self, known: &Self) {
        let live = |key: &&(String, i64)| {
            self.live_nodes
                .as_ref()
                .is_none_or(|nodes| nodes.contains(*key))
        };
        self.controls.extend(
            known
                .controls
                .iter()
                .filter(|(key, _)| live(key))
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        self.private_text_nodes
            .extend(known.private_text_nodes.iter().filter(live).cloned());
        self.secrets.extend(known.secrets.clone());
        self.expiry_echoes.extend(known.expiry_echoes.clone());
        self.expiry_echoes.sort();
        self.expiry_echoes.dedup();
        self.prune_secret_fragments();
        self.secrets
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        self.secrets.dedup_by(|a, b| a.0 == b.0);
    }

    /// The page loaded a new document. Controls and text nodes are pinned by
    /// backend node id, which a new document reuses (after a cross-process
    /// navigation ids restart), so keeping them redacted whole unrelated pages
    /// (2026-10-31: every name on the next site read "[redacted: credential]").
    /// Remembered values still protect any echo of them on the new page.
    pub(crate) fn forget_document_controls(&mut self) {
        self.controls.clear();
        self.private_text_nodes.clear();
    }

    pub fn merge(&mut self, mut other: Self) {
        other.inherit_private(self);
        *self = other;
    }
}

fn expiry_echo_length(text: &str, expiry: &str) -> Option<usize> {
    let mut chars = text.char_indices().peekable();
    let mut end = 0;
    for (index, expected) in expiry.chars().enumerate() {
        if index > 0 {
            while chars.peek().is_some_and(|(_, ch)| ch.is_whitespace()) {
                chars.next();
            }
        }
        let (offset, actual) = chars.next()?;
        if actual != expected {
            return None;
        }
        end = offset + actual.len_utf8();
    }
    if chars.peek().is_some_and(|(_, ch)| ch.is_ascii_digit()) {
        return None;
    }
    Some(end)
}

/// Only the numeric path component of a recognized public social permalink is
/// exempt from the generic payment-number guess. Known secret matching still
/// runs at every character, and scoped payment controls remain protected.
fn public_social_id_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for (offset, _) in text.match_indices("https://") {
        if text[..offset].chars().next_back().is_some_and(|ch| {
            !ch.is_whitespace() && !matches!(ch, '\'' | '"' | '(' | '[' | '{' | '<' | '=' | ':')
        }) {
            continue;
        }
        let rest = &text[offset + "https://".len()..];
        let Some((host, path)) = rest.split_once('/') else {
            continue;
        };
        let id = match host {
            "x.com" | "www.x.com" | "twitter.com" | "www.twitter.com" => {
                let Some((user, path)) = path.split_once('/') else {
                    continue;
                };
                if user.is_empty()
                    || user.len() > 15
                    || !user.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    continue;
                }
                path.strip_prefix("status/")
            }
            "linkedin.com" | "www.linkedin.com" => {
                path.strip_prefix("feed/update/urn:li:activity:")
            }
            _ => None,
        };
        let Some(id) = id else { continue };
        if let Some(span) = public_numeric_id_span(text, id) {
            spans.push(span);
        }
    }
    // data-urn on LinkedIn cards exposes the public activity identifier before
    // the page renders a permalink. Do not treat arbitrary URL paths as URNs.
    for (offset, _) in text.match_indices("urn:li:activity:") {
        if text[..offset].chars().next_back().is_some_and(|ch| {
            !ch.is_whitespace() && !matches!(ch, '\'' | '"' | '(' | '[' | '{' | '<' | '=' | ':')
        }) {
            continue;
        }
        if let Some(span) = public_numeric_id_span(text, &text[offset + "urn:li:activity:".len()..])
        {
            spans.push(span);
        }
    }
    // LinkedIn uses this exact test-id prefix for a reaction facepile. Keep
    // the boundary narrow; arbitrary text ending in a URN is not metadata.
    let prefix = "ReactionFacepileCollection-urn:li:activity:";
    for (offset, _) in text.match_indices(prefix) {
        if text[..offset].chars().next_back().is_some_and(|ch| {
            !ch.is_whitespace() && !matches!(ch, '\'' | '"' | '(' | '[' | '{' | '<' | '=' | ':')
        }) {
            continue;
        }
        if let Some(span) = public_numeric_id_span(text, &text[offset + prefix.len()..]) {
            spans.push(span);
        }
    }
    spans
}

/// Chrome's browser UUID is connection metadata, not a payment number. Exempt
/// only its canonical UUID path component, never URL credentials or query data.
/// Known secrets are still matched before this generic-number exception.
fn cdp_browser_id_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for scheme in ["ws://", "wss://"] {
        for (offset, _) in text.match_indices(scheme) {
            if text[..offset].chars().next_back().is_some_and(|ch| {
                !ch.is_whitespace() && !matches!(ch, '\'' | '"' | '(' | '[' | '{' | '<' | '=' | ':')
            }) {
                continue;
            }
            let candidate = &text[offset..];
            let end = candidate
                .find(|ch: char| {
                    ch.is_whitespace()
                        || matches!(ch, '\'' | '"' | ')' | ']' | '}' | '<' | '>' | ',' | ';')
                })
                .unwrap_or(candidate.len());
            let Ok(url) = url::Url::parse(&candidate[..end]) else {
                continue;
            };
            if url.host_str().is_none() {
                continue;
            }
            let Some(id) = url.path().strip_prefix("/devtools/browser/") else {
                continue;
            };
            if id.len() != 36
                || !id.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
            {
                continue;
            }
            // Locate the literal path, not an occurrence in userinfo or query.
            let authority_end = scheme.len()
                + candidate[scheme.len()..end]
                    .find('/')
                    .unwrap_or(end - scheme.len());
            let start = offset + authority_end + "/devtools/browser/".len();
            if text.get(start..start + id.len()) == Some(id) {
                spans.push((start, start + id.len()));
            }
        }
    }
    spans
}

fn public_numeric_id_span(text: &str, id: &str) -> Option<(usize, usize)> {
    let length = id.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=20).contains(&length)
        || id[length..].chars().next().is_some_and(|ch| {
            !ch.is_whitespace()
                && !matches!(
                    ch,
                    '/' | '?' | '#' | '\'' | '"' | ')' | ']' | '}' | '<' | '>' | ',' | ';' | '.'
                )
        })
    {
        return None;
    }
    let start = text.len() - id.len();
    Some((start, start + length))
}

/// Full payment numbers are private even when a site renders them as ordinary
/// text or copy-button names rather than form values. Do not require a checksum:
/// a mistyped or provider-specific number still must not be published.
fn payment_number_length(text: &str) -> Option<usize> {
    let mut digits = 0;
    let mut end = 0;
    for (offset, ch) in text.char_indices() {
        if ch.is_ascii_digit() {
            digits += 1;
            end = offset + 1;
        } else if digits > 0 && (ch.is_whitespace() || matches!(ch, '-' | '‐' | '‑' | '–')) {
            continue;
        } else {
            break;
        }
    }
    (digits >= 13).then_some(end)
}

/// Short payment values need an explicit payment label; unlike full numbers,
/// arbitrary dates and three-digit public text are not globally secret.
fn display_payment_spans(text: &str, kind: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let ch = text[start..].chars().next().unwrap();
        if !ch.is_ascii_digit() {
            start += ch.len_utf8();
            continue;
        }
        let length = if kind == "cc-number" {
            payment_number_length(&text[start..])
        } else {
            let mut digits = 0;
            let mut end = 0;
            let mut slash = false;
            for (offset, ch) in text[start..].char_indices() {
                if ch.is_ascii_digit() {
                    digits += 1;
                    end = offset + 1;
                } else if kind == "cc-exp" && (ch.is_whitespace() || ch == '/') {
                    slash |= ch == '/';
                } else {
                    break;
                }
            }
            match kind {
                "cc-csc" if matches!(digits, 3 | 4) => Some(end),
                "cc-exp" if slash && matches!(digits, 4 | 6) => Some(end),
                "cc-exp-month" if matches!(digits, 1 | 2) => Some(end),
                "cc-exp-year" if matches!(digits, 2 | 4) => Some(end),
                _ => None,
            }
        };
        if let Some(length) = length {
            spans.push((start, start + length));
            start += length;
        } else {
            // Consume the whole digit run: never match a private-looking suffix
            // of a longer public identifier.
            start += text[start..].bytes().take_while(u8::is_ascii_digit).count();
        }
    }
    spans
}

fn display_button(node: &Value) -> bool {
    node["nodeName"] == "BUTTON"
        || node_attributes(node)
            .get("role")
            .is_some_and(|role| role == "button")
}

fn button_counts(node: &Value, counts: &mut HashMap<usize, usize>) -> usize {
    let count = usize::from(display_button(node))
        + node["children"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|child| button_counts(child, counts))
            .sum::<usize>();
    counts.insert(node as *const Value as usize, count);
    count
}

struct Control {
    session: String,
    backend: i64,
    kind: &'static str,
    display: bool,
    text: bool,
}

fn node_attributes(node: &Value) -> HashMap<String, String> {
    match node["attributes"].as_array() {
        Some(attributes) => attributes
            .chunks_exact(2)
            .filter_map(|pair| Some((pair[0].as_str()?.to_owned(), pair[1].as_str()?.to_owned())))
            .collect(),
        None => HashMap::new(),
    }
}

fn node_text(node: &Value) -> String {
    let mut text = node["nodeValue"].as_str().unwrap_or("").to_owned();
    for child in node["children"].as_array().into_iter().flatten() {
        text.push_str(&node_text(child));
    }
    text
}

/// Label identities are scoped to each document/shadow root, like DOM label lookup.
fn collect_nodes(
    node: &Value,
    session: &str,
    controls: &mut Vec<Control>,
    seen: &mut HashSet<i64>,
) {
    fn labels<'a>(
        node: &'a Value,
        ids: &mut HashMap<String, &'a Value>,
        targets: &mut HashMap<String, String>,
    ) {
        let attrs = node_attributes(node);
        if let Some(id) = attrs.get("id") {
            ids.insert(id.clone(), node);
        }
        if node["nodeName"] == "LABEL" {
            if let Some(target) = attrs.get("for") {
                targets
                    .entry(target.clone())
                    .or_default()
                    .push_str(&format!("\n{}", node_text(node)));
            }
        }
        for key in ["children", "pseudoElements"] {
            for child in node[key].as_array().into_iter().flatten() {
                labels(child, ids, targets);
            }
        }
    }
    fn walk(
        node: &Value,
        session: &str,
        controls: &mut Vec<Control>,
        seen: &mut HashSet<i64>,
        ids: &HashMap<String, &Value>,
        targets: &HashMap<String, String>,
        inherited: &str,
        parent_editable: bool,
        payment_label: &str,
        button_counts: &HashMap<usize, usize>,
        api_nodes: &HashSet<i64>,
    ) {
        let mut attrs = node_attributes(node);
        let editable = match attrs
            .get("contenteditable")
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
        {
            Some("" | "true" | "plaintext-only") => true,
            Some("false") => false,
            _ => parent_editable,
        };
        let wrapping = if node["nodeName"] == "LABEL" {
            node_text(node)
        } else {
            inherited.to_owned()
        };
        let mut label = wrapping.clone();
        if let Some(text) = attrs.get("id").and_then(|id| targets.get(id)) {
            label.push('\n');
            label.push_str(text);
        }
        if let Some(references) = attrs.get("aria-labelledby") {
            for id in references.split_whitespace() {
                if let Some(text) = ids.get(id) {
                    label.push('\n');
                    label.push_str(&node_text(text));
                }
            }
        }
        let display = display_button(node);
        let text = private_text(&attrs)
            || node["backendNodeId"]
                .as_i64()
                .is_some_and(|id| api_nodes.contains(&id))
            || api_text_label(&label);
        if display {
            label.push_str(payment_label);
            label.push_str(&node_text(node));
            if let Some(title) = attrs.get("title") {
                label.push_str(title);
            }
        }
        attrs.insert("label".into(), label);
        if let Some(backend) = node["backendNodeId"].as_i64() {
            if seen.insert(backend)
                && (text
                    || display
                    || (editable
                        && node["nodeName"]
                            .as_str()
                            .is_some_and(|name| !name.starts_with('#')))
                    || matches!(
                        node["nodeName"].as_str(),
                        Some("INPUT" | "TEXTAREA" | "SELECT")
                    ))
            {
                if let Some(name) = node["nodeName"].as_str() {
                    attrs.insert("tagname".into(), name.to_owned());
                }
                if let Some(kind) = text
                    .then_some("credential")
                    .or_else(|| classify(&attrs))
                    .or_else(|| {
                        (display
                            && !display_payment_spans(&node_text(node), "cc-number").is_empty())
                        .then_some("cc-number")
                    })
                    .filter(|kind| {
                        text || !display
                            || !display_payment_spans(
                                &format!(
                                    "{} {}",
                                    node_text(node),
                                    attrs.get("aria-label").map(String::as_str).unwrap_or("")
                                ),
                                kind,
                            )
                            .is_empty()
                    })
                {
                    controls.push(Control {
                        session: session.to_owned(),
                        backend,
                        kind,
                        display: display && !text,
                        text,
                    });
                }
            }
        }
        // A single copy button's surrounding field text supplies its label.
        // Never borrow labels from a container holding several payment fields.
        let field_label =
            if !display && button_counts.get(&(node as *const Value as usize)) == Some(&1) {
                let local = node_text(node);
                if classify(&HashMap::from([("label".into(), local.clone())])).is_some() {
                    local
                } else {
                    payment_label.to_owned()
                }
            } else {
                payment_label.to_owned()
            };
        for key in ["children", "pseudoElements"] {
            for child in node[key].as_array().into_iter().flatten() {
                walk(
                    child,
                    session,
                    controls,
                    seen,
                    ids,
                    targets,
                    &wrapping,
                    editable,
                    &field_label,
                    button_counts,
                    api_nodes,
                );
            }
        }
        for root in node["shadowRoots"].as_array().into_iter().flatten() {
            collect_nodes(root, session, controls, seen);
        }
        if let Some(root) = node.get("contentDocument") {
            collect_nodes(root, session, controls, seen);
        }
        if let Some(root) = node.get("templateContent") {
            // Inert template descendants belong to a separate document. Chrome
            // cannot resolve their backend IDs in the live document, but the
            // owning template element can safely expose its content for private
            // inventory. Never publish a partial inventory of those descendants.
            let mut nested = Vec::new();
            collect_nodes(root, session, &mut nested, &mut HashSet::new());
            if !nested.is_empty() {
                // An absent owner identity must fail resolution, never silently
                // drop a sensitive subtree from the inventory.
                let backend = node["backendNodeId"].as_i64().unwrap_or(0);
                controls.push(Control {
                    session: session.to_owned(), backend, kind: "credential",
                    display: false, text: true,
                });
            }
        }
    }
    let mut ids = HashMap::new();
    let mut targets = HashMap::new();
    labels(node, &mut ids, &mut targets);
    let mut counts = HashMap::new();
    button_counts(node, &mut counts);
    walk(
        node,
        session,
        controls,
        seen,
        &ids,
        &targets,
        "",
        false,
        "",
        &counts,
        &api_display_nodes(node),
    );
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
    Changed(DocumentChange),
    Deadline(DeadlineDiagnostic),
}

#[derive(Debug)]
pub(crate) enum DocumentChange {
    FrameBindings,
    BackendIdentity,
    PiercedSubtree,
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
            Self::Deadline(diagnostic) => diagnostic.into_message(),
            Self::Changed(change) => format!(
                "{UNSUPPORTED}: observed document changed: {}",
                match change {
                    DocumentChange::FrameBindings => "frame bindings",
                    DocumentChange::BackendIdentity => "DOM backend identity",
                    DocumentChange::PiercedSubtree => "pierced DOM subtree",
                }
            ),
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

pub(crate) struct InventoryContext {
    pub(crate) document_frames: HashMap<String, String>,
    pub(crate) cursor_nodes: HashMap<String, HashMap<String, i64>>,
    pub(crate) frame_paths: HashMap<String, HashMap<String, i64>>,
    pub(crate) dialog_roots: HashMap<String, HashSet<i64>>,
    pub(crate) top_frame: String,
    frame_roots: HashMap<String, Option<i64>>,
    pub(crate) frames: HashMap<String, String>,
    pub(crate) owners: HashMap<(String, i64), String>,
    pub(crate) hrefs: HashMap<(String, i64), Result<String, String>>,
}

fn collect_snapshot_context(
    node: &Value,
    session: &str,
    context: &mut InventoryContext,
    inherited_base: Option<&url::Url>,
    document_frame: Option<&str>,
) -> Result<(), String> {
    let document_base = if node["nodeName"] == "#document" {
        node["baseURL"]
            .as_str()
            .or_else(|| node["documentURL"].as_str())
            .and_then(|base| url::Url::parse(base).ok())
    } else {
        None
    };
    let base = document_base.as_ref().or(inherited_base);
    if node["nodeName"] == "#document" {
        if let Some(frame) = node["frameId"].as_str().or(document_frame) {
            let dialogs = dialog_roots(node);
            if !dialogs.is_empty() {
                context
                    .frame_paths
                    .insert(frame.to_owned(), cursor_node_paths(node)?);
                context.dialog_roots.insert(frame.to_owned(), dialogs);
            }
            context.frame_roots.insert(
                frame.to_owned(),
                node["nodeId"].as_i64().filter(|id| *id > 0),
            );
        }
    }
    if let Some(backend) = node["backendNodeId"].as_i64() {
        if matches!(node["nodeName"].as_str(), Some("IFRAME" | "FRAME")) {
            if let Some(frame) = node["contentDocument"]["frameId"]
                .as_str()
                .or_else(|| node["frameId"].as_str())
            {
                context
                    .owners
                    .insert((session.to_owned(), backend), frame.to_owned());
            }
        }
        if let Some(attrs) = node["attributes"].as_array() {
            for pair in attrs.chunks_exact(2) {
                if pair[0] == "href" {
                    if let Some(href) = pair[1].as_str() {
                        let resolved = url::Url::parse(href)
                            .or_else(|_| {
                                base.ok_or(url::ParseError::RelativeUrlWithoutBase)?
                                    .join(href)
                            })
                            .map(|url| url.to_string())
                            .map_err(|_| "Link document base unavailable".to_owned());
                        context
                            .hrefs
                            .insert((session.to_owned(), backend), resolved);
                    }
                }
            }
        }
    }
    for key in ["children", "shadowRoots", "pseudoElements"] {
        if let Some(children) = node[key].as_array() {
            for child in children {
                collect_snapshot_context(child, session, context, base, None)?;
            }
        }
    }
    if let Some(document) = node.get("contentDocument") {
        collect_snapshot_context(document, session, context, None, node["frameId"].as_str())?;
    }
    Ok(())
}

fn dialog_roots(root: &Value) -> HashSet<i64> {
    fn walk(node: &Value, found: &mut HashSet<i64>) {
        let attributes = node_attributes(node);
        if matches!(
            attributes.get("role").map(String::as_str),
            Some("dialog" | "alertdialog")
        ) || attributes
            .get("aria-modal")
            .is_some_and(|value| value == "true")
            || node["nodeName"] == "DIALOG"
        {
            if let Some(backend) = node["backendNodeId"].as_i64() {
                found.insert(backend);
            }
        }
        for key in ["children", "shadowRoots"] {
            for child in node[key].as_array().into_iter().flatten() {
                walk(child, found);
            }
        }
    }
    let mut found = HashSet::new();
    walk(root, &mut found);
    found
}

fn cursor_node_paths(root: &Value) -> Result<HashMap<String, i64>, String> {
    fn walk(node: &Value, parent: &str, paths: &mut HashMap<String, i64>) -> Result<(), String> {
        // Renderer projections can enter open roots only. The privacy inventory
        // separately includes closed and user-agent roots as well.
        for shadow in node["shadowRoots"].as_array().into_iter().flatten() {
            if shadow["shadowRootType"] == "open" {
                walk(shadow, &format!("{parent} >>> "), paths)?;
            }
        }
        let Some(children) = node["children"].as_array() else {
            return Ok(());
        };
        // Element position is unique even when namespaces or casing differ.
        // CDP nodeName can be STYLE and style for siblings with one localName.
        // Use the same element-only positions as both renderer projections.
        let mut index = 0;
        for child in children {
            let Some(name) = child["nodeName"].as_str() else {
                continue;
            };
            let element = match child["nodeType"].as_i64() {
                Some(kind) => kind == 1,
                None => !name.starts_with('#'),
            };
            if !element {
                continue;
            }
            index += 1;
            let component = format!("*:nth-child({index})");
            let path = if parent.is_empty() || parent.ends_with(" >>> ") {
                format!("{parent}{component}")
            } else {
                format!("{parent} > {component}")
            };
            if let Some(backend) = child["backendNodeId"].as_i64().filter(|id| *id > 0) {
                if paths.insert(path.clone(), backend).is_some() {
                    return Err("Ambiguous cursor element path".into());
                }
            }
            walk(child, &path, paths)?;
        }
        Ok(())
    }
    let mut paths = HashMap::new();
    walk(root, "", &mut paths)?;
    Ok(paths)
}

impl InventoryContext {
    pub(crate) fn frame_node(&self, frame: &str) -> Result<i64, String> {
        self.frame_roots
            .get(frame)
            .copied()
            .flatten()
            .ok_or_else(|| format!("{UNSUPPORTED}: frame DOM root identity unavailable"))
    }
}

/// Collect protected output inside the inventory's document-identity span.
/// A changed document discards both the output and its control observation.
/// Capture guards use the one-shot observer instead of admitting older captures.
pub(crate) async fn observe_with_continuation<T, F, Fut>(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
    continuation: &mut InventoryContinuation,
    collect: F,
) -> Result<(Observation, T), InventoryError>
where
    F: FnMut(InventoryContext) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    observe_inventory_with(client, top_session, iframe_sessions, continuation, collect).await
}

#[derive(Debug, PartialEq, Eq)]
struct FrameBinding {
    loader: String,
    parent: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct FrameBindings {
    root: String,
    members: BTreeMap<String, FrameBinding>,
}

fn frame_bindings(tree: &Value) -> Result<FrameBindings, InventoryError> {
    fn collect(
        tree: &Value,
        parent: Option<&str>,
        members: &mut BTreeMap<String, FrameBinding>,
    ) -> Result<String, InventoryError> {
        let frame = tree["frame"]
            .as_object()
            .ok_or_else(|| format!("{UNSUPPORTED}: frame binding unavailable"))?;
        let id = frame
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| format!("{UNSUPPORTED}: frame binding ID unavailable"))?;
        let loader = frame
            .get("loaderId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{UNSUPPORTED}: frame loader identity unavailable"))?;
        let reported_parent = frame
            .get("parentId")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| format!("{UNSUPPORTED}: frame parent identity unavailable"))
            })
            .transpose()?;
        if parent.is_some() && reported_parent.is_some() && parent != reported_parent {
            return Err(format!("{UNSUPPORTED}: frame parent association changed").into());
        }
        let binding = FrameBinding {
            loader: loader.to_owned(),
            parent: parent.or(reported_parent).map(str::to_owned),
        };
        if members.insert(id.to_owned(), binding).is_some() {
            return Err(format!("{UNSUPPORTED}: duplicate frame binding").into());
        }
        if let Some(children) = tree.get("childFrames") {
            let children = children
                .as_array()
                .ok_or_else(|| format!("{UNSUPPORTED}: frame membership unavailable"))?;
            for child in children {
                collect(child, Some(id), members)?;
            }
        }
        Ok(id.to_owned())
    }
    let mut members = BTreeMap::new();
    let root = collect(tree, None, &mut members)?;
    Ok(FrameBindings { root, members })
}

/// Kept only while one command attaches missing frames. Successful observations,
/// navigation and other failures drop it; no tree is reused by a later command.
#[derive(Default)]
pub(crate) struct InventoryContinuation {
    documents: HashMap<String, InventoryDocument>,
}

struct InventoryDocument {
    revision: u64,
    session: String,
    tree: Value,
    bindings: FrameBindings,
    root: Value,
    backend: i64,
}

/// Chrome converts every protocol response through CBOR with a 300-level
/// nesting limit, two levels per element, so a pierced tree deeper than about
/// 147 elements (long Gmail threads) cannot be read in one response. Read it in
/// layers: a node reporting children it did not include is described again from
/// there, and the description is spliced in, until no such node remains.
pub(crate) const PIERCE_LAYER_DEPTH: i64 = 120;

#[derive(Clone, Copy)]
enum TreeStep {
    Child(usize),
    Shadow(usize),
    Content,
    Template,
}

fn truncated_nodes(root: &Value) -> Vec<(Vec<TreeStep>, i64)> {
    // Steps are kept as a parent-linked list so the walk stays linear in nodes.
    let mut steps: Vec<(usize, TreeStep)> = Vec::new();
    let mut found = Vec::new();
    let mut stack = vec![(root, usize::MAX)];
    while let Some((node, at)) = stack.pop() {
        let reported = node["childNodeCount"].as_u64().unwrap_or(0);
        if reported > 0 && node.get("children").is_none() {
            if let Some(backend) = node["backendNodeId"].as_i64() {
                let mut path = Vec::new();
                let mut cursor = at;
                while cursor != usize::MAX {
                    let (parent, step) = steps[cursor];
                    path.push(step);
                    cursor = parent;
                }
                path.reverse();
                found.push((path, backend));
            }
        }
        let mut next: Vec<(&Value, TreeStep)> = Vec::new();
        if let Some(items) = node["children"].as_array() {
            next.extend(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| (item, TreeStep::Child(i))),
            );
        }
        if let Some(items) = node["shadowRoots"].as_array() {
            next.extend(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| (item, TreeStep::Shadow(i))),
            );
        }
        if let Some(item) = node.get("contentDocument").filter(|item| item.is_object()) {
            next.push((item, TreeStep::Content));
        }
        if let Some(item) = node.get("templateContent").filter(|item| item.is_object()) {
            next.push((item, TreeStep::Template));
        }
        for (item, step) in next {
            steps.push((at, step));
            stack.push((item, steps.len() - 1));
        }
    }
    found
}

fn node_at<'a>(mut node: &'a mut Value, path: &[TreeStep]) -> Option<&'a mut Value> {
    for step in path {
        node = match step {
            TreeStep::Child(index) => node.get_mut("children")?.get_mut(*index)?,
            TreeStep::Shadow(index) => node.get_mut("shadowRoots")?.get_mut(*index)?,
            TreeStep::Content => node.get_mut("contentDocument")?,
            TreeStep::Template => node.get_mut("templateContent")?,
        };
    }
    Some(node)
}

async fn pierced_document(client: &CdpClient, session: &str) -> Result<Value, InventoryError> {
    let unavailable = || InventoryError::from(format!("{UNSUPPORTED}: pierced DOM unavailable"));
    let mut document = client
        .send_command(
            "DOM.getDocument",
            Some(json!({ "depth": PIERCE_LAYER_DEPTH, "pierce": true })),
            Some(session),
        )
        .await
        .map_err(|_| unavailable())?;
    loop {
        let pending = truncated_nodes(&document["root"]);
        if pending.is_empty() {
            return Ok(document);
        }
        let described = futures_util::future::join_all(pending.iter().map(|(_, backend)| {
            client.send_command(
                "DOM.describeNode",
                Some(json!({ "backendNodeId": backend, "depth": PIERCE_LAYER_DEPTH, "pierce": true })),
                Some(session),
            )
        }))
        .await;
        for ((path, backend), described) in pending.into_iter().zip(described) {
            let described =
                described.map_err(|_| InventoryError::Changed(DocumentChange::PiercedSubtree))?;
            let mut subtree = described.get("node").cloned().ok_or_else(unavailable)?;
            if subtree["backendNodeId"].as_i64() != Some(backend)
                || subtree.get("children").is_none()
            {
                return Err(InventoryError::Changed(DocumentChange::PiercedSubtree));
            }
            let node = node_at(&mut document["root"], &path).ok_or_else(unavailable)?;
            let fields = node.as_object_mut().ok_or_else(unavailable)?;
            let described = subtree.as_object_mut().ok_or_else(unavailable)?;
            for field in [
                "children",
                "shadowRoots",
                "contentDocument",
                "templateContent",
                "pseudoElements",
            ] {
                if let Some(value) = described.remove(field) {
                    fields.insert(field.to_owned(), value);
                }
            }
        }
    }
}

async fn inventory_document(
    client: &CdpClient,
    session: String,
    expected_frame: Option<String>,
) -> Result<InventoryDocument, InventoryError> {
    // Both reads bind to this exact session. Final binding/backend validation
    // rejects transitions crossing their independent response spans.
    let revision = client.dom_revision(&session);
    let (live, document) = tokio::join!(
        client.observation_progress.track(
            Phase::InitialFrameTree,
            client.send_command_no_params("Page.getFrameTree", Some(&session))
        ),
        client
            .observation_progress
            .track(Phase::InitialDocument, pierced_document(client, &session))
    );
    let live = live.map_err(|_| format!("{UNSUPPORTED}: frame session unavailable"))?;
    let bindings = frame_bindings(&live["frameTree"])?;
    let root_frame = bindings.root.as_str();
    if expected_frame
        .as_deref()
        .is_some_and(|frame| frame != root_frame)
    {
        return Err(format!("{UNSUPPORTED}: frame session association changed").into());
    }
    let document = document?;
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
        revision,
        session,
        tree: live["frameTree"].clone(),
        bindings,
        root: root.clone(),
        backend,
    })
}

async fn inventory_document_continued(
    client: &CdpClient,
    session: String,
    expected_frame: Option<String>,
    retained: Option<InventoryDocument>,
) -> Result<InventoryDocument, InventoryError> {
    if let Some(document) = retained {
        if client.dom_revision(&session) == document.revision {
            // A recovered attachment must still belong to the same live document.
            // Check again afterwards: DOM mutation events can arrive during validation.
            client
                .observation_progress
                .track(
                    Phase::FinalValidation,
                    validate_inventory_document(client, &document),
                )
                .await?;
            if client.dom_revision(&session) == document.revision
                && expected_frame
                    .as_deref()
                    .is_none_or(|frame| frame == document.bindings.root)
            {
                return Ok(document);
            }
        }
    }
    inventory_document(client, session, expected_frame).await
}

async fn inventory_control(
    client: &CdpClient,
    control: &Control,
    object_group: &str,
) -> Result<Vec<String>, InventoryError> {
    let resolved = client
        .observation_progress
        .track(
            Phase::ControlResolve,
            client.send_command(
                "DOM.resolveNode",
                Some(json!({ "backendNodeId": control.backend, "objectGroup": object_group })),
                Some(&control.session),
            ),
        )
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive control unavailable"))?;
    let object = resolved["object"]["objectId"]
        .as_str()
        .ok_or_else(|| format!("{UNSUPPORTED}: sensitive control handle unavailable"))?;
    let values = async {
        let values = client.observation_progress.track(Phase::ControlValues,
            client.send_command("Runtime.callFunctionOn", Some(json!({
                "objectId": object,
                "functionDeclaration": if control.text {
                    // Keep both rendered text and individual fragments private, including
                    // short descendants whose AX parent may be omitted by Chrome.
                    r#"function(patterns) {
                        const privateToken = text => patterns.some(([prefix, minimum, urlSafe]) => {
                            let at = -1;
                            while ((at = text.indexOf(prefix, at + 1)) !== -1) {
                                const rest = text.slice(at + prefix.length);
                                const token = rest.match(urlSafe ? /^[A-Za-z0-9_-]+/ : /^[A-Za-z0-9]+/);
                                if (token && token[0].length >= minimum) return true;
                            }
                            return false;
                        });
                        const values = [this.textContent || '', this.innerText || '', String(this.value || '')];
                        const scan = node => {
                            if (node.nodeType === 3) values.push(node.textContent || '');
                            if (node.nodeType === 1) {
                                if ('value' in node) values.push(String(node.value || ''));
                                // Attributes can be the only full copy of a displayed
                                // credential; retain them privately to protect echoes.
                                for (const attr of node.attributes) {
                                    if (privateToken(attr.value)) values.push(attr.value);
                                }
                                if (node.shadowRoot) scan(node.shadowRoot);
                                if (node.content) scan(node.content);
                            }
                            for (const child of node.childNodes) scan(child);
                        };
                        scan(this.content || this);
                        return values;
                    }"#
                } else if control.display {
                    "function() { return [this.textContent || '', this.getAttribute('aria-label') || '']; }"
                } else {
                    "function() { return [String(this.value || ''), this.getAttribute('value') || '', (this.tagName === 'TEXTAREA' || this.isContentEditable) ? this.textContent : '']; }"
                },
                "arguments": [{"value": PRIVATE_TOKEN_PATTERNS}],
                "returnByValue": true,
            })), Some(&control.session)),
        ).await.map_err(|_| format!("{UNSUPPORTED}: sensitive control observation failed"))?;
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
        .observation_progress
        .track(
            Phase::ControlRelease,
            client.send_command(
                "Runtime.releaseObject",
                Some(json!({ "objectId": object })),
                Some(&control.session),
            ),
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
    if frame_bindings(&live["frameTree"])? != document.bindings {
        return Err(InventoryError::Changed(DocumentChange::FrameBindings));
    }
    if root["root"]["nodeName"] != "#document" {
        return Err(format!("{UNSUPPORTED}: DOM root unavailable").into());
    }
    if root["root"]["frameId"]
        .as_str()
        .is_some_and(|frame| frame != document.bindings.root)
    {
        return Err(format!("{UNSUPPORTED}: document frame association changed").into());
    }
    let backend = root["root"]["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or_else(|| format!("{UNSUPPORTED}: document identity unavailable"))?;
    if backend != document.backend {
        return Err(InventoryError::Changed(DocumentChange::BackendIdentity));
    }
    Ok(())
}

/// Follow only frame-tree claims and pierced-DOM owners of this tab. An OOPIF
/// may be absent from its parent's frame tree while its DOM owner is present.
/// Initial frame metadata and pierced DOM reads overlap within each exact session.
/// Each bound document starts its control reads while deeper represented documents
/// are still being discovered. Complete coverage and final frame/loader/parent/member/
/// backend validation remain required before any observation or output is published.
/// Volatile metadata and sibling ordering are not identity. Changed observations
/// are discarded for whole-batch reinventory by the deadline-owning caller.
/// Renderer groups register connection-owned cancellation cleanup before resolve;
/// cancellation cannot dispatch further value reads or abandon remote handles.
/// Cached sessions from unrelated tabs are not evidence of membership.
pub(crate) async fn observe_inventory(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Observation, InventoryError> {
    observe_inventory_continued(
        client,
        top_session,
        iframe_sessions,
        &mut InventoryContinuation::default(),
    )
    .await
}

pub(crate) async fn observe_inventory_continued(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
    continuation: &mut InventoryContinuation,
) -> Result<Observation, InventoryError> {
    observe_inventory_with(
        client,
        top_session,
        iframe_sessions,
        continuation,
        |_| async { Ok(()) },
    )
    .await
    .map(|(observation, ())| observation)
}

async fn observe_inventory_with<T, F, Fut>(
    client: &Arc<CdpClient>,
    top_session: &str,
    iframe_sessions: &HashMap<String, String>,
    continuation: &mut InventoryContinuation,
    mut collect: F,
) -> Result<(Observation, T), InventoryError>
where
    F: FnMut(InventoryContext) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    // Taking ownership empties the continuation on every exit except Coverage.
    let mut retained = std::mem::take(&mut continuation.documents);
    client.observation_progress.attempt();
    client
        .observation_progress
        .track(Phase::ObjectCleanup, client.settle_object_cleanup())
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
    let mut frames = HashMap::new();
    let mut covered = HashMap::new();
    let mut owners = HashSet::new();
    let mut control_reads = FuturesUnordered::new();
    let mut control_results = Vec::new();
    let mut object_groups = Vec::new();
    let mut sessions = FuturesUnordered::new();
    sessions.push(inventory_document_continued(
        client,
        top_session.to_owned(),
        None,
        retained.remove(top_session),
    ));
    let mut documents = Vec::new();
    let mut visited = HashSet::from([top_session.to_owned()]);
    while !sessions.is_empty() {
        let document = tokio::select! {
            document = sessions.next() => document.expect("pending document")?,
            values = control_reads.next(), if !control_reads.is_empty() => {
                control_results.push(values.expect("pending control"));
                continue;
            }
        };
        let session = &document.session;
        let root_frame = document.bindings.root.as_str();
        collect_tree_frames(&document.tree, session, iframe_sessions, &mut frames)?;
        covered.insert(root_frame.to_owned(), session.clone());
        collect_document_frames(&document.root, session, &mut covered, &mut owners);
        for frame in frames.keys().chain(owners.iter()) {
            if let Some(sid) = iframe_sessions.get(frame) {
                if visited.insert(sid.clone()) {
                    sessions.push(inventory_document_continued(
                        client,
                        sid.clone(),
                        Some(frame.clone()),
                        retained.remove(sid),
                    ));
                }
            }
        }
        let mut controls = Vec::new();
        collect_nodes(&document.root, session, &mut controls, &mut HashSet::new());
        if !controls.is_empty() {
            let group = client
                .object_group(vec![session.clone()])
                .await
                .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
            for control in controls {
                let name = group.name.clone();
                control_reads.push(async move {
                    let values = client
                        .observation_progress
                        .track(Phase::Controls, inventory_control(client, &control, &name))
                        .await;
                    (control, values)
                });
            }
            object_groups.push(group);
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
        continuation.documents = documents
            .into_iter()
            .map(|document| (document.session.clone(), document))
            .collect();
        return Err(InventoryError::Coverage(CoverageGap {
            missing_owners,
            mismatched_frames,
            covered,
            attached: iframe_sessions.clone(),
        }));
    }
    fn collect_live_nodes(
        node: &Value,
        session: &str,
        nodes: &mut HashSet<(String, i64)>,
        private_nodes: &mut HashSet<(String, i64)>,
        inherited_private: bool,
        api_nodes: &HashSet<i64>,
    ) {
        let private = inherited_private
            || private_text(&node_attributes(node))
            || node["backendNodeId"]
                .as_i64()
                .is_some_and(|id| api_nodes.contains(&id));
        if let Some(backend) = node["backendNodeId"].as_i64() {
            let key = (session.to_owned(), backend);
            nodes.insert(key.clone());
            if private {
                private_nodes.insert(key);
            }
        }
        for key in ["children", "shadowRoots", "pseudoElements"] {
            for child in node[key].as_array().into_iter().flatten() {
                collect_live_nodes(child, session, nodes, private_nodes, private, api_nodes);
            }
        }
        for key in ["contentDocument", "templateContent"] {
            if let Some(child) = node.get(key) {
                collect_live_nodes(child, session, nodes, private_nodes, private, api_nodes);
            }
        }
    }
    let mut live_nodes = HashSet::new();
    let mut private_text_nodes = HashSet::new();
    for document in &documents {
        collect_live_nodes(
            &document.root,
            &document.session,
            &mut live_nodes,
            &mut private_text_nodes,
            false,
            &api_display_nodes(&document.root),
        );
    }
    let mut observation = Observation {
        live_nodes: Some(live_nodes),
        private_text_nodes,
        frame_sessions: visited
            .into_iter()
            .filter(|session| session != top_session)
            .collect(),
        ..Observation::default()
    };
    let mut context = InventoryContext {
        document_frames: documents.iter().map(|document| (document.session.clone(), document.bindings.root.clone())).collect(),
        frame_paths: HashMap::new(),
        dialog_roots: HashMap::new(),
        cursor_nodes: documents
            .iter()
            .map(|document| {
                cursor_node_paths(&document.root).map(|paths| (document.session.clone(), paths))
            })
            .collect::<Result<_, _>>()?,
        top_frame: documents
            .iter()
            .find(|document| document.session == top_session)
            .expect("top document observed")
            .bindings
            .root
            .clone(),
        frame_roots: documents
            .iter()
            .map(|document| {
                (
                    document.bindings.root.clone(),
                    document.root["nodeId"].as_i64().filter(|id| *id > 0),
                )
            })
            .collect(),
        frames: covered,
        owners: HashMap::new(),
        hrefs: HashMap::new(),
    };
    for document in &documents {
        collect_snapshot_context(
            &document.root,
            &document.session,
            &mut context,
            None,
            Some(&document.bindings.root),
        )?;
    }
    let (values, collected) = tokio::join!(control_reads.collect::<Vec<_>>(), collect(context),);
    control_results.extend(values);
    for (control, values) in control_results {
        let redacted = marker(control.kind);
        observation
            .controls
            .insert((control.session.clone(), control.backend), redacted.clone());
        for value in values? {
            if control.display {
                for (start, end) in display_payment_spans(&value, control.kind) {
                    observation.remember_private_value(
                        &control.session,
                        control.backend,
                        control.kind,
                        &value[start..end],
                    );
                }
            } else {
                observation.remember_private_value(
                    &control.session,
                    control.backend,
                    control.kind,
                    &value,
                );
                if control.text {
                    for token in value.lines().filter_map(api_labeled_value) {
                        observation.remember_private_value(
                            &control.session,
                            control.backend,
                            "credential",
                            token,
                        );
                    }
                }
            }
        }
    }

    for validation in futures_util::future::join_all(documents.iter().map(|document| {
        client.observation_progress.track(
            Phase::FinalValidation,
            validate_inventory_document(client, document),
        )
    }))
    .await
    {
        validation?;
    }
    for group in object_groups {
        group.finish();
    }
    client
        .observation_progress
        .track(Phase::ObjectCleanup, client.settle_object_cleanup())
        .await
        .map_err(|_| format!("{UNSUPPORTED}: sensitive object cleanup unavailable"))?;
    observation
        .secrets
        .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
    observation.secrets.dedup_by(|a, b| a.0 == b.0);
    Ok((observation, collected?))
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

/// Commands whose responses carry no page content. When the protected
/// inventory cannot be taken they still run, protected by what earlier
/// observations remember, and report the incomplete observation alongside.
pub fn content_free(action: &str, cmd: &Value) -> bool {
    matches!(
        action,
        "download"
            | "waitfordownload"
            | "navigate"
            | "url"
            | "title"
            | "back"
            | "forward"
            | "reload"
            | "click"
            | "dblclick"
            | "type"
            | "press"
            | "hover"
            | "scroll"
            | "scrollintoview"
            | "check"
            | "uncheck"
            | "focus"
            | "mouse"
            | "keyboard"
            | "wheel"
            | "keydown"
            | "keyup"
            | "mousemove"
            | "mousedown"
            | "mouseup"
            | "inserttext"
            | "tab_list"
            | "viewport"
            | "bringtofront"
            | "isvisible"
            | "isenabled"
            | "ischecked"
            | "count"
            | "boundingbox"
            | "waitforurl"
            | "waitforloadstate"
            | "frame"
            | "mainframe"
            | "dialog"
    ) || (action == "wait" && cmd.get("expression").is_none())
}

/// Input and download acknowledgements contain selectors/keys, static status or
/// completed-file metadata, never page text or control values. They do not need
/// a post-dispatch page inventory. Fill retains its preflight inventory and
/// target classification before editing, but returns only the selector/status.
/// Downloads transfer only the browser-created file, not a DOM export, and must
/// not fail after saving due to a page observation.
/// In particular, a click may navigate away or start a payment POST;
/// renderer observation must not turn its successful dispatch into a timeout.
/// A new-tab click also returns a page-derived href, so it still needs protection.
pub fn input_acknowledgement(action: &str, cmd: &Value) -> bool {
    matches!(
        action,
        "fill"
            | "download"
            | "waitfordownload"
            | "click"
            | "dblclick"
            | "press"
            | "hover"
            | "scroll"
            | "scrollintoview"
            | "check"
            | "uncheck"
            | "focus"
            | "mousemove"
            | "mousedown"
            | "mouseup"
            | "keydown"
            | "keyup"
            | "wheel"
    ) && !cmd.get("newTab").and_then(Value::as_bool).unwrap_or(false)
}

/// Plain screenshots paint every identified sensitive control black instead
/// of refusing. Annotated captures still need a protected snapshot.
pub fn masked_screenshot(action: &str, cmd: &Value) -> bool {
    action == "screenshot"
        && !cmd
            .get("annotate")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

pub fn guarded(action: &str, cmd: &Value) -> bool {
    matches!(
        action,
        "fill"
            | "evaluate"
            | "evalhandle"
            | "addscript"
            | "waitforfunction"
            | "pdf"
            | "diff_screenshot"
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
        || (action == "screenshot" && !masked_screenshot(action, cmd))
        || (action == "read" && cmd.get("url").is_none())
}

#[cfg(test)]
mod tests {
    #[test]
    fn linkedin_facepile_id_is_public_but_cards_and_remembered_secrets_are_not() {
        use super::*;
        let id = "7526753488295477248";
        let value = format!("ReactionFacepileCollection-urn:li:activity:{id}");
        let observed = Observation::default();
        assert_eq!(observed.protect_text(&value), value);
        assert_eq!(observed.protect_text(&format!("x{value}")), "xReactionFacepileCollection-urn:li:activity:[redacted: cc-number]");
        assert_eq!(observed.protect_text("Card 4242424242424242"), "Card [redacted: cc-number]");
        assert_eq!(observed.protect_control_name(&value, "[redacted: cc-number]"), "ReactionFacepileCollection-urn:li:activity:[redacted: cc-number]");
        let mut known = Observation::default();
        known.secrets.push((id.to_string(), marker("cc-number")));
        assert_eq!(known.protect_text(&value), "ReactionFacepileCollection-urn:li:activity:[redacted: cc-number]");
    }

    #[test]
    fn browser_use_tokens_are_always_private_and_url_safe() {
        use super::*;
        let secret = format!("bu_{}", "Ab_9-".repeat(9));
        assert!(has_private_token(&secret));
        assert!(!has_private_token(&format!("bu_{}", "x".repeat(19))));
        assert!(has_private_token(&format!("bu_{}", "x".repeat(20))));
        assert!(!has_private_token("pk_test_public_1234567890"));
        assert!(has_private_token("sk_test_12345678"));
        let observed = Observation::default();
        assert_eq!(observed.protect_text(&format!("é[{secret}]!")), "é[[redacted: credential]]!");
        let root = json!({"nodeName":"DIV", "backendNodeId":1, "children":[
            {"nodeName":"DIV", "backendNodeId":2, "children":[
                {"nodeName":"#text", "nodeValue":secret}
            ]}
        ]});
        assert_eq!(api_display_nodes(&root), HashSet::from([2]));
        assert!(private_text(&HashMap::from([("data-key".into(), secret)])));
    }

    #[test]
    fn recovery_dialog_protects_deep_list_items_only() {
        use super::*;
        let root = json!({"nodeName":"DIV","backendNodeId":1,"children":[
          {"nodeName":"DIV","backendNodeId":2,"attributes":["role","dialog"],"children":[
            {"nodeName":"H2","backendNodeId":3,"children":[{"nodeName":"#text","nodeValue":"Save your backup codes"}]},
            {"nodeName":"DIV","backendNodeId":4,"children":[{"nodeName":"DIV","backendNodeId":5,"children":[
              {"nodeName":"UL","backendNodeId":6,"children":[
                {"nodeName":"LI","backendNodeId":7,"children":[{"nodeName":"SPAN","backendNodeId":8,"children":[{"nodeName":"#text","nodeValue":"dummy-code-one"}]}]},
                {"nodeName":"LI","backendNodeId":9,"children":[{"nodeName":"#text","nodeValue":"dummy-code-two"}]}
              ]}
            ]}]}
          ]},
          {"nodeName":"LI","backendNodeId":10,"children":[{"nodeName":"#text","nodeValue":"public-item"}]}
        ]});
        let found = api_display_nodes(&root);
        assert!(found.contains(&7) && found.contains(&9));
        assert!(!found.contains(&10));
    }

    #[test]
    fn secret_fragments_never_poison_metadata_and_cleanup_preserves_full_values() {
        use super::*;
        let mut observed = Observation::default();
        for (index, value) in ["O", "2", "12", "é", "界", "123", "OF29AB8CD"]
            .iter()
            .enumerate()
        {
            observed.remember_private_value("synthetic", index as i64 + 1, "credential", value);
        }
        assert_eq!(observed.controls.len(), 7);
        assert_eq!(observed.secret_count(), 2);
        assert_eq!(
            observed.protect_text("OpenAI https://fixture.test/e12 @e2"),
            "OpenAI https://fixture.test/e12 @e2"
        );
        assert_eq!(
            observed.protect_text("OF29AB8CD 123"),
            "[redacted: credential] [redacted: credential]"
        );
        observed.secrets.extend([
            ("O".into(), marker("credential")),
            ("12".into(), marker("credential")),
            ("界".into(), marker("credential")),
        ]);
        assert_eq!(observed.protect_text("OpenAI @e12"), "OpenAI @e12");
        let removed = observed.prune_secret_fragments();
        assert_eq!(removed, BTreeMap::from([(1, 2), (2, 1)]));
        assert_eq!(observed.secret_count(), 2);
        assert_eq!(observed.controls.len(), 7);
        assert!(observed.prune_secret_fragments().is_empty());
        assert_eq!(observed.protect_text("OF29AB8CD"), marker("credential"));
        let mut incoming = Observation::default();
        incoming.secrets.push(("2".into(), marker("credential")));
        observed.secrets.push(("O".into(), marker("credential")));
        observed.merge(incoming);
        assert_eq!(observed.secret_count(), 2);
    }

    #[test]
    fn remembered_prefix_prefilter_keeps_unicode_longest_matches_and_token_families() {
        let mut observed = Observation::default();
        for (backend, kind, value) in [
            (1, "credential", "secret"),
            (2, "password", "secret-tail"),
            (3, "credential", "é界abc"),
            (4, "password", "🔑abc"),
        ] {
            observed.remember_private_value("session", backend, kind, value);
        }
        // Legacy short and empty fragments are still excluded, even if their
        // first byte matches. Global token rules do not depend on this index.
        observed.secrets.extend([
            ("".into(), marker("credential")),
            ("x".into(), marker("credential")),
        ]);
        assert_eq!(
            observed.protect_text("x secret-tail secret é界abc 🔑abc bu_01234567890123456789"),
            "x [redacted: password] [redacted: credential] [redacted: credential] [redacted: password] [redacted: credential]"
        );
        assert_eq!(observed.protect_text("plain text 界🔑"), "plain text 界🔑");
    }

    #[test]
    fn expiry_echo_whitespace_and_split_fragments() {
        let mut known = Observation::default();
        known.remember_private_expiry_value("synthetic", 1, "12/34");
        for value in ["12/34", "12 / 34", "12\u{a0}/\u{2009}34"] {
            assert_eq!(
                known.protect_text(&format!("Echo {value}")),
                "Echo [redacted: credential]"
            );
        }
        let mut split = Observation::default();
        split.remember_private_value("synthetic", 2, "cc-exp-month", "12");
        split.remember_private_value("synthetic", 3, "cc-exp-year", "34");
        assert_eq!(
            split.protect_text("Open @e12: 12 items and 34 rows"),
            "Open @e12: 12 items and 34 rows"
        );
        assert_eq!(
            split.controls[&("synthetic".into(), 2)],
            marker("cc-exp-month")
        );
        assert_eq!(
            split.controls[&("synthetic".into(), 3)],
            marker("cc-exp-year")
        );
        split.frame_sessions.insert("current".into());
        known.frame_sessions.insert("retired".into());
        split.inherit_private(&known);
        assert_eq!(split.frame_sessions, HashSet::from(["current".into()]));
        assert_eq!(split.protect_text("12 / 34"), marker("credential"));
        assert_eq!(split.protect_text("12 / 340"), "12 / 340");
    }

    #[test]
    fn expiry_labels_and_structural_scope() {
        let root = json!({"nodeName":"#document","children":[
            {"nodeName":"LABEL","attributes":["for","slot"],"children":[{"nodeName":"#text","nodeValue":"Expiration date"}]},
            {"nodeName":"INPUT","backendNodeId":1,"attributes":["id","slot"]},
            {"nodeName":"INPUT","backendNodeId":2,"attributes":["aria-label","Expiry date"]},
            {"nodeName":"INPUT","backendNodeId":3,"attributes":["placeholder","MM / YY"]},
            {"nodeName":"LABEL","children":[{"nodeName":"#text","nodeValue":"Expiry month"},{"nodeName":"SELECT","backendNodeId":4}]},
            {"nodeName":"SPAN","attributes":["id","year-label"],"children":[{"nodeName":"#text","nodeValue":"Expiration year"}]},
            {"nodeName":"SELECT","backendNodeId":5,"attributes":["aria-labelledby","year-label"]},
            {"nodeName":"INPUT","backendNodeId":6,"attributes":["autocomplete","cc-name","aria-label","Card number"]},
            {"nodeName":"DIV","shadowRoots":[{"nodeName":"#document-fragment","children":[{"nodeName":"INPUT","backendNodeId":7,"attributes":["id","slot"]}]}]},
            {"nodeName":"INPUT","backendNodeId":8,"attributes":["aria-label","Ordinary date"]},
            {"nodeName":"DIV","backendNodeId":9,"attributes":["contenteditable","true","aria-label","Expiration date"],"children":[{"nodeName":"#text","backendNodeId":10,"nodeValue":"12/34"}]},
            {"nodeName":"LABEL","children":[{"nodeName":"#text","backendNodeId":11,"nodeValue":"Expiration date"},{"nodeName":"DIV","backendNodeId":12,"attributes":["contenteditable","true"],"children":[{"nodeName":"#text","backendNodeId":13,"nodeValue":"12/34"}]}]}
        ]});
        let mut controls = Vec::new();
        collect_nodes(&root, "synthetic", &mut controls, &mut HashSet::new());
        assert_eq!(
            controls
                .iter()
                .map(|control| (control.backend, control.kind))
                .collect::<Vec<_>>(),
            vec![
                (1, "cc-exp"),
                (2, "cc-exp"),
                (3, "cc-exp"),
                (4, "cc-exp-month"),
                (5, "cc-exp-year"),
                (9, "cc-exp"),
                (12, "cc-exp")
            ]
        );
    }

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
                        json!({"frameTree":{"frame":{"id":"top","loaderId":"top-document"},"childFrames":[{"frame":{"id":"payment", "parentId":"top","loaderId":"payment-document"}}]}})
                    }
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"payment", "parentId":"top","loaderId":"payment-document"}}})
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

    #[tokio::test]
    async fn delayed_initial_pair_preserves_coverage_association_and_changed_errors() {
        use super::super::lifecycle_fixture::SyntheticCdp;
        for case in [
            "coverage",
            "session",
            "document",
            "backend",
            "binding",
            "unreadable",
        ] {
            let mut fixture = SyntheticCdp::connect().await;
            let client = fixture.manager.client.clone();
            let session = fixture.manager.active_session_id().unwrap().to_owned();
            {
                let mut inventory = fixture.frame_inventory.lock().unwrap();
                inventory.reply_delays.insert(
                    "Page.getFrameTree".into(),
                    std::time::Duration::from_millis(30),
                );
                inventory.reply_delays.insert(
                    "DOM.getDocument".into(),
                    std::time::Duration::from_millis(10),
                );
                inventory.documents.insert("synthetic-top".into(), json!({"root":{
                    "nodeName":"#document", "frameId":"synthetic-top", "backendNodeId":1000,
                    "children":[{"nodeName":"INPUT","backendNodeId":11,"attributes":["autocomplete","cc-number"]}]
                }}));
                match case {
                    "coverage" => {
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["children"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"nodeName":"IFRAME","frameId":"missing-frame"}));
                    }
                    "session" => {
                        inventory
                            .session_roots
                            .insert("misbound-session".into(), "wrong-frame".into());
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["children"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"nodeName":"IFRAME","frameId":"expected-frame"}));
                    }
                    "document" => {
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["frameId"] =
                            json!("wrong-frame");
                    }
                    "backend" => {
                        inventory.changed_documents.insert("synthetic-top".into());
                    }
                    "binding" => {
                        inventory.changed_frame_trees.insert(
                            "synthetic-top".into(),
                            json!({"frameTree":{
                                "frame":{"id":"synthetic-top","loaderId":"next-document"}
                            }}),
                        );
                    }
                    "unreadable" => {
                        inventory.unreadable.insert("synthetic-top".into());
                    }
                    _ => unreachable!(),
                }
            }
            let frames = if case == "session" {
                HashMap::from([("expected-frame".into(), "misbound-session".into())])
            } else {
                HashMap::new()
            };
            let error = observe_inventory(&client, &session, &frames)
                .await
                .err()
                .unwrap();
            match (case, &error) {
                ("coverage", InventoryError::Coverage(gap)) => {
                    assert_eq!(gap.missing_owners, ["missing-frame"])
                }
                ("backend", InventoryError::Changed(DocumentChange::BackendIdentity)) => (),
                ("binding", InventoryError::Changed(DocumentChange::FrameBindings)) => (),
                ("session" | "document" | "unreadable", InventoryError::Unavailable(_)) => (),
                _ => panic!("unexpected {case} error: {error:?}"),
            }
            let message = error.into_message();
            assert!(!message.contains("Synthetic-"));
            if case == "session" {
                assert!(message.contains("frame session association changed"));
            }
            if case == "document" {
                assert!(message.contains("document frame association changed"));
            }
            if case == "unreadable" {
                assert!(message.contains("pierced DOM unavailable"));
            }
            client.settle_object_cleanup().await.unwrap();
            assert!(fixture.frame_inventory.lock().unwrap().objects.is_empty());
            assert_eq!(client.object_cleanup_len().await, 0);
            assert_eq!(client.pending_len().await, 0);
            while let Ok(command) = fixture.commands.try_recv() {
                let method = command["method"].as_str().unwrap();
                assert!(!method.starts_with("Input.") && method != "Page.navigate");
                if matches!(case, "coverage" | "document" | "unreadable") {
                    assert_ne!(method, "Runtime.callFunctionOn");
                }
                if matches!(method, "DOM.resolveNode" | "Runtime.callFunctionOn") {
                    assert_eq!(command["sessionId"], session);
                }
            }
            client.close().await;
            fixture.server.await.unwrap();
        }
    }

    #[test]
    fn test_protected_inventory_frame_bindings_preserve_all_identity_distinctions() {
        let tree = json!({"frame":{"id":"top","loaderId":"top-document"},"childFrames":[
            {"frame":{"id":"a","loaderId":"document-a","parentId":"top"}},
            {"frame":{"id":"b","loaderId":"document-b","parentId":"top"}}
        ]});
        let binding = frame_bindings(&tree).unwrap();
        let mut reordered = tree.clone();
        reordered["frame"]["name"] = json!("changed-name");
        reordered["frame"]["urlFragment"] = json!("#changed-fragment");
        reordered["childFrames"].as_array_mut().unwrap().reverse();
        assert_eq!(frame_bindings(&reordered).unwrap(), binding);
        for path in [vec!["frame", "loaderId"], vec!["frame", "parentId"]] {
            let mut changed = tree.clone();
            changed[path[0]][path[1]] = json!("changed-identity");
            assert_ne!(frame_bindings(&changed).unwrap(), binding);
        }
        let mut changed_root = tree.clone();
        changed_root["frame"]["id"] = json!("next-root");
        for child in changed_root["childFrames"].as_array_mut().unwrap() {
            child["frame"]["parentId"] = json!("next-root");
        }
        assert_ne!(frame_bindings(&changed_root).unwrap(), binding);
        let mut changed = tree.clone();
        changed["childFrames"][0]["frame"]["loaderId"] = json!("next-child-document");
        assert_ne!(frame_bindings(&changed).unwrap(), binding);
        let mut removed = tree.clone();
        removed["childFrames"].as_array_mut().unwrap().pop();
        assert_ne!(frame_bindings(&removed).unwrap(), binding);
        let mut added = tree.clone();
        added["childFrames"]
            .as_array_mut()
            .unwrap()
            .push(json!({"frame":{"id":"c","loaderId":"document-c","parentId":"top"}}));
        assert_ne!(frame_bindings(&added).unwrap(), binding);
        let mut reparented = tree.clone();
        reparented["childFrames"][0]["frame"]["parentId"] = json!("unrelated-parent");
        assert!(frame_bindings(&reparented).is_err());
        for invalid in [
            json!({"frame":{"id":"top"}}),
            json!({"frame":{"id":"top","loaderId":null}}),
            json!({"frame":{"id":"top","loaderId":"document","parentId":5}}),
            json!({"frame":{"id":"top","loaderId":"document"},"childFrames":null}),
            json!({"frame":{"id":"top","loaderId":"document"},"childFrames":[{"frame":{"id":"top","loaderId":"document"}}]}),
        ] {
            assert!(frame_bindings(&invalid).is_err());
        }
    }

    #[test]
    fn test_protected_inventory_cursor_paths_preserve_element_identity_and_document_scope() {
        let root = json!({"nodeName":"#document","children":[
            {"nodeName":"html","nodeType":10},
            {"nodeName":"HTML","nodeType":1,"localName":"html","backendNodeId":1,"children":[
                {"nodeName":"BODY","nodeType":1,"localName":"body","backendNodeId":2,"children":[
                    {"nodeName":"#text","nodeType":3},
                    {"nodeName":"DIV","nodeType":1,"localName":"div","backendNodeId":3},
                    {"nodeName":"SPAN","nodeType":1,"localName":"span","backendNodeId":4},
                    {"nodeName":"DIV","nodeType":1,"localName":"div","backendNodeId":5,
                        "shadowRoots":[{"nodeName":"#document-fragment","children":[{"nodeName":"DIV","backendNodeId":99}]}]},
                    {"nodeName":"IFRAME","nodeType":1,"localName":"iframe","backendNodeId":6,
                        "contentDocument":{"nodeName":"#document","children":[{"nodeName":"DIV","backendNodeId":100}]}}
                ]}
            ]}
        ]});
        let paths = cursor_node_paths(&root).unwrap();
        assert_eq!(paths.len(), 6);
        assert_eq!(paths["*:nth-child(1) > *:nth-child(1) > *:nth-child(1)"], 3);
        assert_eq!(paths["*:nth-child(1) > *:nth-child(1) > *:nth-child(3)"], 5);
        assert!(!paths.values().any(|id| matches!(id, 99 | 100)));
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
    fn one_time_code_autocomplete_protects_only_code_shaped_inputs() {
        let field = |pairs: &[(&str, &str)]| {
            let mut m: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            m.insert("autocomplete".into(), "one-time-code".into());
            m
        };
        let otc = Some("one-time-code");
        assert_eq!(
            classify(&field(&[("name", "company"), ("type", "text")])),
            None
        );
        assert_eq!(
            classify(&field(&[("type", "email"), ("name", "email")])),
            None
        );
        assert_eq!(
            classify(&field(&[("tagname", "TEXTAREA"), ("maxlength", "6")])),
            None
        );
        assert_eq!(
            classify(&field(&[("name", "message"), ("maxlength", "500")])),
            None
        );
        assert_eq!(classify(&field(&[("maxlength", "6")])), otc);
        assert_eq!(classify(&field(&[("inputmode", "numeric")])), otc);
        assert_eq!(classify(&field(&[("type", "number")])), otc);
        assert_eq!(classify(&field(&[("name", "sms_code")])), otc);
        assert_eq!(
            classify(&field(&[("placeholder", "Verification code")])),
            otc
        );
    }

    #[test]
    fn sensitive_classifier_and_markers() {
        for (token, kind) in AUTOCOMPLETE {
            assert_eq!(
                classify(&HashMap::from([
                    ("autocomplete".into(), format!("section-payment {token}")),
                    ("maxlength".into(), "6".into()),
                ])),
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
            live_nodes: None,
            controls: HashMap::new(),
            private_text_nodes: HashSet::new(),
            expiry_echoes: Vec::new(),
            secrets: vec![
                ("4242424242424242".into(), marker("cc-number")),
                ("12".into(), marker("cc-exp-month")),
            ],
        };
        assert_eq!(
            obs.protect_text("4242424242424242 12 test"),
            "[redacted: cc-number] 12 test"
        );
    }
}
