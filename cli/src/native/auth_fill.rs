//! One private field fill, bound to the caller's exact active target and frame.
//! The daemon owns the operation lock, deadline and disconnect cancellation.
//! No navigation, submit, focus-based insertion or replay occurs here.

use super::actions::DaemonState;
use super::element::{resolve_element_object_id, RefMap};
use crate::plugins::{resolve_credential_field_with_plugins, PluginConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use std::future::Future;
use tokio::time::Instant;

const INVALID: &str = "auth_fill_invalid_request: explicit provider, item, field, CSS selector, target and frame are required";
const BINDING: &str = "auth_fill_binding_changed: active target, selected frame or live document association changed; not replayed";
const PAGE: &str = "auth_fill_page_error: private field operation failed; dispatched effects may still settle; not replayed";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FillRequest {
    #[serde(rename = "credentialProvider")]
    provider: String,
    #[serde(rename = "credentialItem")]
    item: String,
    field: String,
    selector: String,
    target: String,
    frame: String,
    format: Option<String>,
}

fn request(cmd: &Value) -> Result<FillRequest, String> {
    // Envelope fields belong to the daemon, not the fill request.
    let mut fields = serde_json::Map::new();
    for key in [
        "credentialProvider",
        "credentialItem",
        "field",
        "selector",
        "target",
        "frame",
        "format",
    ] {
        if let Some(value) = cmd.get(key) {
            fields.insert(key.into(), value.clone());
        }
    }
    let req: FillRequest = serde_json::from_value(Value::Object(fields)).map_err(|_| INVALID)?;
    if [
        &req.provider,
        &req.item,
        &req.field,
        &req.selector,
        &req.target,
        &req.frame,
    ]
    .iter()
    .any(|v| v.trim().is_empty())
        || req.selector.starts_with('@')
        || req.format.as_deref().is_some_and(|f| f != "mm/yy")
        || (req.format.is_some() && req.field != "expiration_date")
    {
        return Err(INVALID.into());
    }
    Ok(req)
}

#[derive(Clone, PartialEq, Eq)]
struct Binding {
    session: String,
    frame_session: Option<String>,
    frame: String,
    loader: String,
    url: String,
}

fn find_frame<'a>(tree: &'a Value, id: &str) -> Option<&'a Value> {
    let frame = tree.get("frame")?;
    if frame.get("id").and_then(Value::as_str) == Some(id) {
        return Some(frame);
    }
    tree.get("childFrames")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|child| find_frame(child, id))
}

async fn bind(state: &DaemonState, req: &FillRequest) -> Result<Binding, String> {
    let mgr = state.browser.as_ref().ok_or(BINDING)?;
    let selected = if req.frame == "main" {
        None
    } else {
        Some(req.frame.as_str())
    };
    if mgr.active_target_id().map_err(|_| BINDING)? != req.target
        || state.active_frame_id.as_deref() != selected
    {
        return Err(BINDING.into());
    }
    let session = mgr.active_session_id().map_err(|_| BINDING)?.to_string();
    let target = mgr
        .client
        .send_command(
            "Target.getTargetInfo",
            Some(json!({"targetId": req.target})),
            None,
        )
        .await
        .map_err(|_| BINDING)?;
    if target["targetInfo"]["targetId"].as_str() != Some(req.target.as_str()) {
        return Err(BINDING.into());
    }
    let live = mgr
        .client
        .send_command_no_params("Page.getFrameTree", Some(&session))
        .await
        .map_err(|_| BINDING)?;
    let tree = live.get("frameTree").ok_or(BINDING)?;
    let root = tree.get("frame").ok_or(BINDING)?;
    let (frame_session, frame_value) = if req.frame == "main" {
        (None, root.clone())
    } else {
        let (_, frames) =
            super::a11y::collect_frame_sessions(&mgr.client, &session, &state.iframe_sessions)
                .await
                .map_err(|_| BINDING)?;
        let live_frame = frames
            .iter()
            .find(|frame| frame.frame_id == req.frame)
            .ok_or(BINDING)?;
        if let Some(sid) = state.iframe_sessions.get(&req.frame) {
            if live_frame.session_id != *sid {
                return Err(BINDING.into());
            }
            let owned = mgr
                .client
                .send_command_no_params("Page.getFrameTree", Some(sid))
                .await
                .map_err(|_| BINDING)?;
            let frame = owned
                .get("frameTree")
                .and_then(|tree| tree.get("frame"))
                .ok_or(BINDING)?;
            (Some(sid.clone()), frame.clone())
        } else {
            if live_frame.session_id != session {
                return Err(BINDING.into());
            }
            (None, find_frame(tree, &req.frame).ok_or(BINDING)?.clone())
        }
    };
    let frame = &frame_value;
    let frame_id = frame
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(BINDING)?;
    let loader = frame
        .get("loaderId")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(BINDING)?;
    let url = frame.get("url").and_then(Value::as_str).ok_or(BINDING)?;
    if req.frame != "main" && frame_id != req.frame {
        return Err(BINDING.into());
    }
    if let Some(sid) = &frame_session {
        // A cached OOPIF session is insufficient: it must still own this frame
        // in the active page's live tree, with the same committed document.
        let oopif = mgr
            .client
            .send_command_no_params("Page.getFrameTree", Some(sid))
            .await
            .map_err(|_| BINDING)?;
        let child = &oopif["frameTree"]["frame"];
        if child["id"].as_str() != Some(frame_id)
            || child["loaderId"].as_str() != Some(loader)
            || child["url"].as_str() != Some(url)
        {
            return Err(BINDING.into());
        }
    }
    Ok(Binding {
        session,
        frame_session,
        frame: frame_id.into(),
        loader: loader.into(),
        url: url.into(),
    })
}

/// Resolves a secret only after a live target/frame and editable input are pinned.
/// All plugin and page failures are metadata-only; foreign errors never escape.
/// Retention permits spaces/hyphens only for number and spaces only for expiry;
/// every other private field must retain its exact input representation. A pinned
/// complete segmented input may retain that representation collectively.
pub async fn handle_auth_fill(
    cmd: &Value,
    state: &mut DaemonState,
    deadline: Instant,
) -> Result<Value, String> {
    let req = request(cmd)?;
    if state.recording_state.active
        || state.tracing_state.active
        || state.screencasting
        || state.stream_server.is_some()
        || state.har_recording
        || state.request_tracking
    {
        return Err("auth_fill_capture_active: stop recording, tracing, streaming and network capture before private lookup".into());
    }
    let plugins = match cmd.get("plugins") {
        Some(value) => {
            serde_json::from_value::<Vec<PluginConfig>>(value.clone()).map_err(|_| INVALID)?
        }
        None => crate::plugins::plugins_from_env(),
    };
    fill_with_resolver(state, &req, deadline, |deadline| {
        resolve_credential_field_with_plugins(
            &req.provider,
            &plugins,
            &req.item,
            &req.field,
            req.format.as_deref(),
            deadline,
        )
    })
    .await
}

async fn fill_with_resolver<F, Fut>(
    state: &mut DaemonState,
    req: &FillRequest,
    deadline: Instant,
    resolve: F,
) -> Result<Value, String>
where
    F: FnOnce(Instant) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let bound = bind(state, req).await?;
    super::element::set_active_frame(if req.frame == "main" {
        None
    } else {
        Some(&req.frame)
    });
    let mgr = state.browser.as_ref().ok_or(BINDING)?;
    // An empty RefMap makes selector lookup incapable of following a stale ref.
    let (object, object_session) = resolve_element_object_id(
        &mgr.client,
        &bound.session,
        &RefMap::new(),
        &req.selector,
        &state.iframe_sessions,
    )
    .await
    .map_err(|_| {
        "auth_fill_input_unavailable: CSS selector did not resolve in the selected frame"
    })?;
    if object_session != bound.frame_session.as_deref().unwrap_or(&bound.session) {
        return Err(BINDING.into());
    }
    let probe = mgr.client.send_command("Runtime.callFunctionOn", Some(json!({
        "objectId": object,
        "functionDeclaration": "function() { if (!this.isConnected || !['INPUT','TEXTAREA'].includes(this.tagName) || (this.tagName === 'INPUT' && !['text','password','email','tel','url','search','number','date','month'].includes(this.type)) || this.matches(':disabled') || this.readOnly || !this.getClientRects().length) return null; return this.ownerDocument; }",
        "returnByValue": false
    })), Some(&object_session)).await.map_err(|_| PAGE)?;
    if probe.get("exceptionDetails").is_some() {
        return Err(PAGE.into());
    }
    let document = probe["result"]["objectId"]
        .as_str()
        .ok_or("auth_fill_input_unavailable: selected element is not a visible editable input")?
        .to_string();
    let node = mgr
        .client
        .send_command(
            "DOM.describeNode",
            Some(json!({"objectId": object})),
            Some(&object_session),
        )
        .await
        .map_err(|_| PAGE)?;
    let backend = node["node"]["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(PAGE)?;
    if bind(state, req).await? != bound {
        return Err(BINDING.into());
    }
    let value = resolve(deadline)
        .await
        .map_err(|_| "auth_fill_lookup_failed: credential field could not be resolved")?;
    if value.is_empty() {
        return Err("auth_fill_lookup_failed: credential field is empty".into());
    }
    if bind(state, req).await? != bound {
        return Err(BINDING.into());
    }
    let client = state.browser.as_ref().ok_or(BINDING)?.client.clone();
    let is_segment = node["node"]["attributes"].as_array().is_some_and(|attrs| {
        attrs
            .chunks_exact(2)
            .any(|pair| pair[0] == "maxlength" && pair[1] == "1")
    });
    let mut segments = None;
    let mut segment_group = None;
    let mut backends = vec![backend];
    let count = value.chars().count();
    if is_segment && (2..=32).contains(&count) {
        let group = client
            .object_group(vec![object_session.clone()])
            .await
            .map_err(|_| PAGE)?;
        let result = client
            .send_command(
                "Runtime.callFunctionOn",
                Some(json!({
                    "objectId": object,
                    "functionDeclaration": SEGMENT_GROUP,
                    "arguments": [{"value": count}],
                    "objectGroup": group.name,
                    "returnByValue": false
                })),
                Some(&object_session),
            )
            .await
            .map_err(|_| PAGE)?;
        if result.get("exceptionDetails").is_some() {
            return Err(PAGE.into());
        }
        if let Some(array) = result["result"]["objectId"].as_str() {
            let properties = client
                .send_command(
                    "Runtime.getProperties",
                    Some(json!({
                        "objectId": array, "ownProperties": true
                    })),
                    Some(&object_session),
                )
                .await
                .map_err(|_| PAGE)?;
            let entries = properties["result"].as_array().ok_or(PAGE)?;
            backends.clear();
            for index in 0..count {
                let name = index.to_string();
                let element = entries
                    .iter()
                    .find(|entry| entry["name"].as_str() == Some(&name))
                    .and_then(|entry| entry["value"]["objectId"].as_str())
                    .ok_or(PAGE)?;
                let described = client
                    .send_command(
                        "DOM.describeNode",
                        Some(json!({"objectId":element})),
                        Some(&object_session),
                    )
                    .await
                    .map_err(|_| PAGE)?;
                let id = described["node"]["backendNodeId"]
                    .as_i64()
                    .filter(|id| *id > 0)
                    .ok_or(PAGE)?;
                if backends.contains(&id) || (index == 0 && id != backend) {
                    return Err(PAGE.into());
                }
                backends.push(id);
            }
            segments = Some(array.to_owned());
        }
        segment_group = Some(group);
    }
    if bind(state, req).await? != bound {
        return Err(BINDING.into());
    }
    for id in backends {
        state
            .sensitive_observations
            .entry(bound.session.clone())
            .or_default()
            .remember_private_value(&object_session, id, "credential", &value);
    }
    let filled = client
        .client
        .send_command(
            "Runtime.callFunctionOn",
            Some(json!({
                "objectId": object,
                "functionDeclaration": PRIVATE_FILL,
                "arguments": [{"value": value}, {"objectId": document}, {"value": req.field},
                    match &segments { Some(array) => json!({"objectId":array}), None => json!({"value":null}) }],
                "returnByValue": true,
                "awaitPromise": true
            })),
            Some(&object_session),
        )
        .await
        .map_err(|_| PAGE)?;
    drop(segment_group);
    client.settle_object_cleanup().await.map_err(|_| PAGE)?;
    if filled.get("exceptionDetails").is_some() {
        return Err(PAGE.into());
    }
    // Page-visible masks are private too; only hand-built metadata leaves here.
    if let Some(rendered) = filled["result"]["value"]["redactionValue"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        state
            .sensitive_observations
            .entry(bound.session.clone())
            .or_default()
            .remember_private_value(&object_session, backend, "credential", rendered);
    } else if filled["result"]["value"]["status"].as_str() == Some("filled") {
        return Err(PAGE.into());
    }
    match filled["result"]["value"]["status"].as_str() {
        Some("filled") => Ok(
            json!({"filled": true, "target": req.target, "frame": req.frame, "field": req.field}),
        ),
        Some("detached") => {
            Err("auth_fill_input_changed: pinned input or document changed; not replayed".into())
        }
        Some("not_editable") => Err("auth_fill_not_editable: pinned input is not editable".into()),
        Some("invalid_value") => {
            Err("auth_fill_invalid_value: value is invalid for the pinned input".into())
        }
        Some("not_retained") => Err(
            "auth_fill_not_retained: input did not retain the private value; not replayed".into(),
        ),
        _ => Err(PAGE.into()),
    }
}

const SEGMENT_GROUP: &str = r#"function(count) {
    const eligible = el => el.tagName === 'INPUT' && el.maxLength === 1 &&
        el.type === this.type && el.form === this.form && el.isConnected &&
        !el.matches(':disabled') && !el.readOnly && el.getClientRects().length;
    for (let parent = this.parentElement; parent; parent = parent.parentElement) {
        const fields = Array.from(parent.querySelectorAll('input')).filter(eligible);
        if (fields.length < 2) continue;
        if (fields.length !== count || fields[0] !== this) return null;
        const editables = Array.from(parent.querySelectorAll('input,textarea,select')).filter(el =>
            el.getClientRects().length && !el.matches(':disabled') && !el.readOnly);
        if (editables.length !== fields.length) return null;
        fields.container = parent;
        return fields;
    }
    return null;
}"#;

const PRIVATE_FILL: &str = r#"async function(value, document, field, segments) {
    if (!this.isConnected || this.ownerDocument !== document) return {status:'detached'};
    if (this.matches(':disabled') || this.readOnly) return {status:'not_editable'};
    const view = document.defaultView;
    const input = this.tagName === 'INPUT';
    if (!input && this.tagName !== 'TEXTAREA') return {status:'not_editable'};
    const probe = document.createElement(input ? 'input' : 'textarea');
    if (input) probe.type = this.type;
    probe.value = value;
    if (!probe.value) return {status:'invalid_value'};
    const expected = probe.value;
    const validSegments = () => {
        if (!segments) return true;
        const current = Array.from(segments.container.querySelectorAll('input,textarea,select')).filter(el =>
            el.getClientRects().length && !el.matches(':disabled') && !el.readOnly);
        return segments[0] === this && segments.length === Array.from(expected).length &&
            current.length === segments.length && current.every((el, i) => el === segments[i]) &&
            segments.every(el => el.isConnected && el.ownerDocument === document &&
                el.tagName === 'INPUT' && el.maxLength === 1 && el.type === this.type && el.form === this.form);
    };
    if (!validSegments()) return {status:'detached'};
    const prototype = input ? view.HTMLInputElement.prototype : view.HTMLTextAreaElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
    setter.call(this, expected);
    this.dispatchEvent(new view.Event('input', {bubbles:true}));
    this.dispatchEvent(new view.Event('change', {bubbles:true}));
    await new Promise(resolve => view.setTimeout(resolve, 100));
    const rendered = segments ? segments.map(el => el.value).join('') : this.value;
    if (!this.isConnected || this.ownerDocument !== document || !validSegments()) return {status:'detached',redactionValue:rendered};
    const presentation = field === 'number' ? s => s.replace(/[ -]/g, '')
        : field === 'expiration_date' ? s => s.replace(/ /g, '') : s => s;
    const complete = !segments || segments.every(el => Array.from(el.value).length === 1);
    return {status:complete && presentation(rendered) === presentation(expected) ? 'filled' : 'not_retained',redactionValue:rendered};
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        state: DaemonState,
        generation: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fills: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        active_membership: std::sync::Arc<std::sync::atomic::AtomicBool>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn new() -> Self {
            use futures_util::{SinkExt, StreamExt};
            use std::sync::{
                atomic::{AtomicBool, AtomicUsize, Ordering},
                Arc,
            };
            use tokio_tungstenite::tungstenite::Message;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let generation = Arc::new(AtomicUsize::new(1));
            let fills = Arc::new(AtomicUsize::new(0));
            let active_membership = Arc::new(AtomicBool::new(true));
            let server_membership = active_membership.clone();
            let server_generation = generation.clone();
            let server_fills = fills.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let cmd: Value = serde_json::from_str(&text).unwrap();
                    let result = match cmd["method"].as_str().unwrap() {
                        "Target.getTargets" => {
                            json!({"targetInfos":[{"targetId":"page", "type":"page", "url":"https://fixture.test", "title":"fixture", "attached":false}]})
                        }
                        "Target.attachToTarget" => json!({"sessionId":"page-session"}),
                        "Target.getTargetInfo" => json!({"targetInfo":{"targetId":"page"}}),
                        "Page.getFrameTree" => {
                            let loader = format!("doc{}", server_generation.load(Ordering::SeqCst));
                            let active = server_membership.load(Ordering::SeqCst);
                            if cmd["sessionId"] == "child-session" {
                                json!({"frameTree":{"frame":{"id":"child", "parentId":if active {"root"} else {"background-root"}, "loaderId":loader, "url":"https://child.test"}}})
                            } else if active {
                                json!({"frameTree":{"frame":{"id":"root", "loaderId":"topdoc", "url":"https://fixture.test"}, "childFrames":[{"frame":{"id":"child", "parentId":"root", "loaderId":loader, "url":"https://child.test"}}]}})
                            } else {
                                json!({"frameTree":{"frame":{"id":"root", "loaderId":"topdoc", "url":"https://fixture.test"}}})
                            }
                        }
                        "Runtime.evaluate" => {
                            json!({"result":{"objectId":"input-object", "type":"object"}})
                        }
                        "DOM.describeNode" => json!({"node":{"backendNodeId":7}}),
                        "Runtime.callFunctionOn" => {
                            if cmd["params"]["functionDeclaration"] == PRIVATE_FILL {
                                assert_eq!(cmd["sessionId"], "child-session");
                                assert_eq!(
                                    cmd["params"]["arguments"][1]["objectId"],
                                    "document-object"
                                );
                                server_fills.fetch_add(1, Ordering::SeqCst);
                                json!({"result":{"value":{"status":"filled", "redactionValue":"synthetic-private-value"}}})
                            } else {
                                json!({"result":{"objectId":"document-object", "type":"object"}})
                            }
                        }
                        _ => json!({}),
                    };
                    if ws
                        .send(Message::Text(
                            json!({"id":cmd["id"],"result":result}).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let manager =
                super::super::browser::BrowserManager::connect_cdp(&format!("ws://{addr}"))
                    .await
                    .unwrap();
            let mut state = DaemonState::new();
            state.browser = Some(manager);
            state.active_frame_id = Some("child".into());
            state
                .iframe_sessions
                .insert("child".into(), "child-session".into());
            Self {
                state,
                generation,
                fills,
                active_membership,
                server,
            }
        }

        fn req() -> FillRequest {
            request(&json!({"credentialProvider":"fixture", "credentialItem":"Synthetic", "field":"number", "selector":"#card", "target":"page", "frame":"child"})).unwrap()
        }
    }

    #[tokio::test]
    async fn pinned_cross_origin_fill_is_metadata_only() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new().await;
        let secret = "synthetic-private-value";
        let result = fill_with_resolver(
            &mut fixture.state,
            &Fixture::req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { Ok(secret.to_string()) },
        )
        .await
        .unwrap();
        assert!(!result.to_string().contains(secret));
        assert_eq!(result["filled"], true);
        assert!(result.get("redactionValue").is_none());
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 1);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn changed_document_after_lookup_never_dispatches_fill() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new().await;
        let generation = fixture.generation.clone();
        let lookups = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver_lookups = lookups.clone();
        let error = fill_with_resolver(
            &mut fixture.state,
            &Fixture::req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async move {
                resolver_lookups.fetch_add(1, Ordering::SeqCst);
                generation.store(2, Ordering::SeqCst);
                Ok("synthetic-private-value".into())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error, BINDING);
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            1,
            "loader drift must be rejected after lookup, not before it"
        );
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn cached_iframe_on_other_page_never_looks_up() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new().await;
        fixture.active_membership.store(false, Ordering::SeqCst);
        let error = fill_with_resolver(
            &mut fixture.state,
            &Fixture::req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { panic!("cached OOPIF belonging to another page must not resolve secrets") },
        )
        .await
        .unwrap_err();
        assert_eq!(error, BINDING);
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn wrong_target_frame_or_association_never_looks_up() {
        let mut fixture = Fixture::new().await;
        for variant in 0..3 {
            let mut req = Fixture::req();
            match variant {
                0 => req.target = "wrong-page".into(),
                1 => req.frame = "main".into(),
                _ => {
                    fixture.state.active_frame_id = Some("absent".into());
                    req.frame = "absent".into();
                }
            }
            let error = fill_with_resolver(
                &mut fixture.state,
                &req,
                Instant::now() + std::time::Duration::from_secs(2),
                |_| async { panic!("lookup must not occur for invalid binding") },
            )
            .await
            .unwrap_err();
            assert_eq!(error, BINDING);
        }
        fixture.server.abort();
    }

    #[tokio::test]
    #[ignore = "requires installed Chrome; run serially"]
    async fn e2e_private_fill_cross_process_input_and_redaction() {
        use super::super::actions::{close_current_browser, execute_command};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _env =
            crate::test_utils::EnvGuard::new(&["AGENT_BROWSER_RESTORE", "AGENT_BROWSER_PLUGINS"]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let size = stream.read(&mut buffer).await.unwrap();
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    let body = if request.starts_with("GET /input ") {
                        "<label for='slot'>Private input</label><input id='slot'><script>document.querySelector('#slot').addEventListener('input',e=>{document.body.dataset.received=e.target.value})</script>".to_string()
                    } else {
                        format!(
                            "<iframe id='payment' src='http://localhost:{port}/input'></iframe>"
                        )
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        let mut state = DaemonState::new();
        let launch = execute_command(
            &json!({"id":"launch", "action":"launch", "args":["--site-per-process"]}),
            &mut state,
        )
        .await;
        assert_eq!(launch["success"], true, "{launch}");
        let navigate = execute_command(&json!({"id":"nav", "action":"navigate", "url":format!("http://127.0.0.1:{port}/"), "waitUntil":"load"}), &mut state).await;
        assert_eq!(navigate["success"], true, "{navigate}");
        let select = execute_command(
            &json!({"id":"frame", "action":"frame", "selector":"#payment"}),
            &mut state,
        )
        .await;
        assert_eq!(select["success"], true, "{select}");
        let frame = state.active_frame_id.clone().unwrap();
        let sid = state
            .iframe_sessions
            .get(&frame)
            .expect("fixture must be an attached cross-process frame")
            .clone();
        let target = state
            .browser
            .as_ref()
            .unwrap()
            .active_target_id()
            .unwrap()
            .to_string();
        let req = request(&json!({"credentialProvider":"fixture", "credentialItem":"Synthetic", "field":"password", "selector":"#slot", "target":target, "frame":frame})).unwrap();
        let secret = "synthetic-private-value";
        let result = fill_with_resolver(
            &mut state,
            &req,
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { Ok(secret.into()) },
        )
        .await
        .unwrap();
        assert!(!result.to_string().contains(secret));
        let actual = state.browser.as_ref().unwrap().evaluate_in_session(&sid, "document.querySelector('#slot').value === 'synthetic-private-value' && document.body.dataset.received === 'synthetic-private-value'", None).await.unwrap();
        assert_eq!(actual, json!(true));
        let getter = execute_command(
            &json!({"id":"get", "action":"inputvalue", "selector":"#slot"}),
            &mut state,
        )
        .await;
        assert_eq!(getter["success"], true, "{getter}");
        assert!(!getter.to_string().contains(secret));
        let snapshot = execute_command(
            &json!({"id":"snapshot", "action":"snapshot", "interactive":true}),
            &mut state,
        )
        .await;
        assert_eq!(snapshot["success"], true, "{snapshot}");
        assert!(!snapshot.to_string().contains(secret));
        let mut masked = req;
        for (field, mode, supplied, rendered) in [
            (
                "number",
                "number",
                "4242424242424242",
                "4242 4242 4242 4242",
            ),
            ("expiration_date", "expiry", "12/30", "12 / 30"),
            (
                "password",
                "password",
                "synthetic-private-value",
                "synthetic-private-value ",
            ),
        ] {
            state.browser.as_ref().unwrap().evaluate_in_session(&sid, &format!(
                "document.body.dataset.mask = '{mode}'; if (!window.maskInstalled) {{ window.maskInstalled=true; document.querySelector('#slot').addEventListener('input', e => {{ const mode=document.body.dataset.mask; if(mode==='number') e.target.value=e.target.value.replace(/[ -]/g,'').replace(/(.{{4}})/g,'$1 ').trim(); else if(mode==='expiry') e.target.value=e.target.value.replace(/ /g,'').replace('/',' / '); else if(mode==='password') e.target.value += ' '; }}); }} true"
            ), None).await.unwrap();
            masked.field = field.into();
            let result = fill_with_resolver(
                &mut state,
                &masked,
                Instant::now() + std::time::Duration::from_secs(2),
                |_| async { Ok(supplied.into()) },
            )
            .await;
            if field == "password" {
                assert!(result.unwrap_err().starts_with("auth_fill_not_retained:"));
            } else {
                assert_eq!(result.unwrap()["filled"], true);
            }
            let actual = state
                .browser
                .as_ref()
                .unwrap()
                .evaluate_in_session(
                    &sid,
                    &format!("document.querySelector('#slot').value === '{}'", rendered),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(actual, json!(true));
        }
        let mut drift = masked;
        drift.target = "different-target".into();
        assert_eq!(
            fill_with_resolver(
                &mut state,
                &drift,
                Instant::now() + std::time::Duration::from_secs(2),
                |_| async { panic!("no lookup after target drift") }
            )
            .await
            .unwrap_err(),
            BINDING
        );
        close_current_browser(&mut state).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires installed Chrome; run serially"]
    async fn e2e_private_fill_segmented_retention_redaction_and_rejection() {
        use super::super::actions::{close_current_browser, execute_command};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _env =
            crate::test_utils::EnvGuard::new(&["AGENT_BROWSER_RESTORE", "AGENT_BROWSER_PLUGINS"]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    stream.read(&mut buffer).await.unwrap();
                    let fields = (1..=9)
                        .map(|n| {
                            format!("<input maxlength='1' aria-label='Code character {n} of 9'>")
                        })
                        .collect::<String>();
                    let body = format!(
                        r#"<title>OpenAI</title><form><div id='code'>{fields}</div><button id='continue' disabled>Continue</button></form><output id='echo'></output><script>
                        const boxes = Array.from(document.querySelectorAll('input'));
                        window.inputCount=0; window.changeCount=0;
                        boxes[0].addEventListener('input', e => {{
                            window.inputCount++;
                            const chars = Array.from(e.target.value);
                            boxes.forEach((box,i) => box.value=chars[i] || '');
                            if (document.body.dataset.mode === 'reject') boxes[8].value='X';
                            if (document.body.dataset.mode === 'replace') boxes[8].replaceWith(boxes[8].cloneNode());
                            document.querySelector('#continue').disabled=boxes.some(box => !box.value);
                            document.querySelector('#echo').textContent=chars.join('');
                        }});
                        boxes[0].addEventListener('change', () => window.changeCount++);
                    </script>"#
                    );
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
                });
            }
        });
        let mut state = DaemonState::new();
        assert_eq!(
            execute_command(&json!({"id":"launch","action":"launch"}), &mut state).await["success"],
            true
        );
        let url = format!("http://127.0.0.1:{port}/e12?plain=OpenAI2");
        assert_eq!(
            execute_command(
                &json!({"id":"nav","action":"navigate","url":url,"waitUntil":"load"}),
                &mut state
            )
            .await["success"],
            true
        );
        let mgr = state.browser.as_ref().unwrap();
        let target = mgr.active_target_id().unwrap().to_owned();
        let sid = mgr.active_session_id().unwrap().to_owned();
        let req = request(&json!({"credentialProvider":"fixture","credentialItem":"Synthetic","field":"password","selector":"input[aria-label='Code character 1 of 9']","target":target,"frame":"main"})).unwrap();
        let secret = "OF29AB8CD";
        let result = fill_with_resolver(
            &mut state,
            &req,
            Instant::now() + std::time::Duration::from_secs(5),
            |_| async { Ok(secret.into()) },
        )
        .await
        .unwrap();
        assert_eq!(result["filled"], true);
        assert!(!result.to_string().contains(secret));
        let actual = state.browser.as_ref().unwrap().evaluate_in_session(&sid,
            "Array.from(document.querySelectorAll('input')).map(el=>el.value).join('') === 'OF29AB8CD' && !document.querySelector('#continue').disabled && window.inputCount===1 && window.changeCount===1", None).await.unwrap();
        assert_eq!(actual, json!(true));
        let known = &state.sensitive_observations[&sid];
        assert_eq!(known.controls.len(), 9);
        assert_eq!(known.secret_count(), 1);
        assert_eq!(known.protect_text("OpenAI @e12 @e2"), "OpenAI @e12 @e2");
        assert_eq!(known.protect_text(secret), "[redacted: credential]");
        for n in 1..=9 {
            let getter = execute_command(&json!({"id":"get","action":"inputvalue","selector":format!("input[aria-label='Code character {n} of 9']")}), &mut state).await;
            assert_eq!(getter["success"], true, "{getter}");
            assert_eq!(
                getter["data"]["value"], "[redacted: credential]",
                "{getter}"
            );
        }
        let snapshot = execute_command(
            &json!({"id":"snapshot","action":"snapshot","interactive":true}),
            &mut state,
        )
        .await;
        assert_eq!(snapshot["success"], true, "{snapshot}");
        assert!(!snapshot.to_string().contains(secret));
        assert!(snapshot.to_string().contains("Code character 2 of 9"));
        assert_eq!(state.sensitive_observations[&sid].secret_count(), 1);
        let metadata = execute_command(
            &json!({"id":"metadata","action":"session_info"}),
            &mut state,
        )
        .await;
        assert_eq!(
            metadata["data"]["sensitiveSecretMaintenance"]["retainedCount"],
            1
        );
        assert_eq!(
            metadata["data"]["sensitiveSecretMaintenance"]["removedByCharacterLength"],
            json!({})
        );
        for (mode, error) in [
            ("reject", "auth_fill_not_retained:"),
            ("replace", "auth_fill_input_changed:"),
        ] {
            state
                .browser
                .as_ref()
                .unwrap()
                .evaluate_in_session(&sid, &format!("document.body.dataset.mode='{mode}'"), None)
                .await
                .unwrap();
            let failure = fill_with_resolver(
                &mut state,
                &req,
                Instant::now() + std::time::Duration::from_secs(5),
                |_| async { Ok(secret.into()) },
            )
            .await
            .unwrap_err();
            assert!(failure.starts_with(error), "{failure}");
        }
        let actual = state
            .browser
            .as_ref()
            .unwrap()
            .evaluate_in_session(
                &sid,
                "window.inputCount===3 && window.changeCount===3",
                None,
            )
            .await
            .unwrap();
        assert_eq!(actual, json!(true));
        assert_eq!(
            state
                .browser
                .as_ref()
                .unwrap()
                .client
                .object_cleanup_len()
                .await,
            0
        );
        close_current_browser(&mut state).await.unwrap();
        server.abort();
    }

    #[test]
    fn rejects_missing_binding_and_unsafe_format() {
        let valid = json!({"credentialProvider":"fixture", "credentialItem":"Synthetic", "field":"number", "selector":"#card", "target":"page", "frame":"main"});
        assert!(request(&valid).is_ok());
        for key in [
            "credentialProvider",
            "credentialItem",
            "field",
            "selector",
            "target",
            "frame",
        ] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert_eq!(request(&missing).err().unwrap(), INVALID);
        }
        let mut formatted = valid;
        formatted["format"] = json!("mm/yy");
        assert!(request(&formatted).is_err());
        formatted["field"] = json!("expiration_date");
        assert!(request(&formatted).is_ok());
        formatted["selector"] = json!("@e1");
        assert!(request(&formatted).is_err());
    }

    #[test]
    fn frame_search_requires_live_membership() {
        let tree = json!({"frame":{"id":"main"},"childFrames":[{"frame":{"id":"child"}}]});
        assert_eq!(find_frame(&tree, "child").unwrap()["id"], "child");
        assert!(find_frame(&tree, "gone").is_none());
    }
}
