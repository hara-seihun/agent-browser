use std::collections::HashMap;

use serde_json::Value;

use super::cdp::client::CdpClient;
use super::cdp::types::*;

#[derive(Debug, Clone)]
pub struct RefEntry {
    pub backend_node_id: Option<i64>,
    pub role: String,
    pub name: String,
    pub nth: Option<usize>,
    pub selector: Option<String>,
    pub frame_id: Option<String>,
}

#[derive(Clone)]
pub struct RefMap {
    map: HashMap<String, RefEntry>,
    next_ref: usize,
}

impl RefMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_ref: 1,
        }
    }

    pub fn add(
        &mut self,
        ref_id: String,
        backend_node_id: Option<i64>,
        role: &str,
        name: &str,
        nth: Option<usize>,
    ) {
        self.add_with_frame(ref_id, backend_node_id, role, name, nth, None);
    }

    pub fn add_with_frame(
        &mut self,
        ref_id: String,
        backend_node_id: Option<i64>,
        role: &str,
        name: &str,
        nth: Option<usize>,
        frame_id: Option<&str>,
    ) {
        self.map.insert(
            ref_id,
            RefEntry {
                backend_node_id,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: None,
                frame_id: frame_id.map(|s| s.to_string()),
            },
        );
    }

    pub fn add_selector(
        &mut self,
        ref_id: String,
        selector: String,
        role: &str,
        name: &str,
        nth: Option<usize>,
    ) {
        self.map.insert(
            ref_id,
            RefEntry {
                backend_node_id: None,
                role: role.to_string(),
                name: name.to_string(),
                nth,
                selector: Some(selector),
                frame_id: None,
            },
        );
    }

    pub fn get(&self, ref_id: &str) -> Option<&RefEntry> {
        self.map.get(ref_id)
    }

    pub fn entries_sorted(&self) -> Vec<(String, RefEntry)> {
        let mut entries = self
            .map
            .iter()
            .map(|(ref_id, entry)| (ref_id.clone(), entry.clone()))
            .collect::<Vec<_>>();

        entries.sort_by_key(|(ref_id, _)| {
            ref_id
                .strip_prefix('e')
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(usize::MAX)
        });

        entries
    }

    pub fn remove(&mut self, ref_id: &str) {
        self.map.remove(ref_id);
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.next_ref = 1;
    }

    pub fn next_ref_num(&self) -> usize {
        self.next_ref
    }

    pub fn set_next_ref_num(&mut self, n: usize) {
        self.next_ref = n;
    }
}

pub fn parse_ref(input: &str) -> Option<String> {
    let trimmed = input.trim();

    if let Some(stripped) = trimmed.strip_prefix('@') {
        if stripped.starts_with('e') && stripped[1..].chars().all(|c| c.is_ascii_digit()) {
            return Some(stripped.to_string());
        }
    }

    if let Some(stripped) = trimmed.strip_prefix("ref=") {
        if stripped.starts_with('e') && stripped[1..].chars().all(|c| c.is_ascii_digit()) {
            return Some(stripped.to_string());
        }
    }

    if trimmed.starts_with('e')
        && trimmed.len() > 1
        && trimmed[1..].chars().all(|c| c.is_ascii_digit())
    {
        return Some(trimmed.to_string());
    }

    None
}

/// Mirror of DaemonState.active_frame_id, refreshed before every command
/// (commands are serialized by the daemon's state lock, so this cannot
/// race). It lets CSS-selector resolution honor `frame <sel>` without
/// threading a parameter through every interaction signature; snapshot refs
/// already carry their frame through the ref map.
static ACTIVE_FRAME: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

pub fn set_active_frame(frame_id: Option<&str>) {
    *ACTIVE_FRAME
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap() = frame_id.map(String::from);
}

fn active_frame() -> Option<String> {
    ACTIVE_FRAME.get().and_then(|m| m.lock().unwrap().clone())
}

/// Object handle for the <iframe> element that owns a frame, resolved on the
/// parent session. Works for same-process frames where no dedicated CDP
/// session exists.
pub(super) async fn frame_owner_object_id(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
) -> Result<String, String> {
    let owner = client
        .send_command(
            "DOM.getFrameOwner",
            Some(serde_json::json!({ "frameId": frame_id })),
            Some(session_id),
        )
        .await?;
    let backend_node_id = owner
        .get("backendNodeId")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| format!("Could not resolve the owner element of frame {}", frame_id))?;
    let result: DomResolveNodeResult = client
        .send_command_typed(
            "DOM.resolveNode",
            &DomResolveNodeParams {
                backend_node_id: Some(backend_node_id),
                node_id: None,
                object_group: Some("agent-browser".to_string()),
            },
            Some(session_id),
        )
        .await?;
    result
        .object
        .object_id
        .ok_or_else(|| format!("No objectId for the owner element of frame {}", frame_id))
}

/// Object handle for a same-process frame's own `document`, in that frame's
/// realm. Same process does not mean same origin: a sibling subdomain
/// (passport.example.com inside account.example.com) shares the process but
/// the parent's `owner.contentDocument` is null for it. CDP resolves the node
/// with privilege, and functions called on it compile in the frame's realm.
pub(super) async fn frame_document_object_id(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
) -> Result<String, String> {
    let owner = client
        .send_command(
            "DOM.getFrameOwner",
            Some(serde_json::json!({ "frameId": frame_id })),
            Some(session_id),
        )
        .await?;
    let backend_node_id = owner
        .get("backendNodeId")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| format!("Could not resolve the owner element of frame {}", frame_id))?;
    let described = client
        .send_command(
            "DOM.describeNode",
            Some(serde_json::json!({ "backendNodeId": backend_node_id, "depth": 0 })),
            Some(session_id),
        )
        .await?;
    let document = described["node"]["contentDocument"]["backendNodeId"]
        .as_i64()
        .ok_or_else(|| format!("Frame {} has no document yet", frame_id))?;
    let world = client.dom_world(session_id, Some(frame_id)).await?;
    let result: DomResolveNodeResult = client
        .send_command_typed(
            "DOM.resolveNode",
            &serde_json::json!({
                "backendNodeId": document, "objectGroup": "agent-browser",
                "executionContextId": world,
            }),
            Some(session_id),
        )
        .await?;
    result
        .object
        .object_id
        .ok_or_else(|| format!("No objectId for the document of frame {}", frame_id))
}

/// Find a selector inside a same-process iframe and return its center in
/// top-level viewport coordinates (input events dispatch in that space).
/// The element is found in the frame's own realm (it may be cross-origin), and
/// the frame's offset is added from the owner element in the parent's realm.
async fn resolve_center_in_same_process_frame(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
    selector: &str,
) -> Result<(f64, f64), String> {
    let document_object_id = frame_document_object_id(client, session_id, frame_id).await?;
    let owner_object_id = frame_owner_object_id(client, session_id, frame_id).await?;
    let find_expr = build_find_element_js_in("doc", selector);
    let function = format!(
        r#"function() {{
            const doc = this;
            const el = {find_expr};
            if (!el) return null;
            el.scrollIntoView({{ block: 'center', inline: 'nearest', behavior: 'instant' }});
            const rect = el.getBoundingClientRect();
            const win=el.ownerDocument.defaultView;
            const left=Math.max(0,rect.left), top=Math.max(0,rect.top);
            const right=Math.min(win.innerWidth,rect.right), bottom=Math.min(win.innerHeight,rect.bottom);
            const visible=right>left && bottom>top;
            const x = visible ? (left+right)/2 : rect.x + rect.width / 2;
            const y = visible ? (top+bottom)/2 : rect.y + rect.height / 2;
            const blockerAt = {BLOCKER_AT_JS};
            return {{ x: x, y: y, blocker: blockerAt(doc, el, x, y) }};
        }}"#,
    );
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": document_object_id,
                "functionDeclaration": function,
                "returnByValue": true,
            })),
            Some(session_id),
        )
        .await?;
    if result.get("exceptionDetails").is_some() {
        return Err(selector_evaluation_error());
    }
    let value = result.get("result").and_then(|r| r.get("value"));
    if let Some(blocker) = value
        .and_then(|v| v.get("blocker"))
        .and_then(|v| v.as_str())
    {
        return Err(intercepted_error(selector, blocker));
    }
    let x = value.and_then(|v| v.get("x")).and_then(|v| v.as_f64());
    let y = value.and_then(|v| v.get("y")).and_then(|v| v.as_f64());
    let (Some(x), Some(y)) = (x, y) else {
        return Err(format!(
            "Element not found in the selected frame: {}",
            selector
        ));
    };
    // The frame's offset in top-level viewport space, from the parent's realm.
    let offset = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": owner_object_id,
                "functionDeclaration": r#"function() {
                    let x = 0, y = 0, owner = this;
                    while (owner) {
                        const r = owner.getBoundingClientRect();
                        x += r.x + owner.clientLeft;
                        y += r.y + owner.clientTop;
                        owner = owner.ownerDocument.defaultView.frameElement;
                    }
                    return { x: x, y: y };
                }"#,
                "returnByValue": true,
            })),
            Some(session_id),
        )
        .await?;
    let offset = offset.get("result").and_then(|r| r.get("value"));
    match (
        offset.and_then(|v| v.get("x")).and_then(|v| v.as_f64()),
        offset.and_then(|v| v.get("y")).and_then(|v| v.as_f64()),
    ) {
        (Some(dx), Some(dy)) => Ok((x + dx, y + dy)),
        _ => Err(format!("Could not place frame {} in the viewport", frame_id)),
    }
}

/// Find a selector inside a same-process iframe and return its object handle.
async fn resolve_object_in_same_process_frame(
    client: &CdpClient,
    session_id: &str,
    frame_id: &str,
    selector: &str,
) -> Result<String, String> {
    let document_object_id = frame_document_object_id(client, session_id, frame_id).await?;
    let find_expr = build_find_element_js_in("doc", selector);
    let function = format!("function() {{ const doc = this; return {find_expr}; }}");
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": document_object_id,
                "functionDeclaration": function,
                "returnByValue": false,
            })),
            Some(session_id),
        )
        .await?;
    if result.get("exceptionDetails").is_some() {
        return Err(selector_evaluation_error());
    }
    result
        .get("result")
        .and_then(|r| r.get("objectId"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("Element not found in the selected frame: {}", selector))
}

pub async fn resolve_element_center(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(f64, f64, String), String> {
    if let Some(ref_id) = parse_ref(selector_or_ref) {
        let entry = ref_map
            .get(&ref_id)
            .ok_or_else(|| format!("Unknown ref: {}", ref_id))?;

        let effective_session_id =
            resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions);

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            scroll_node_into_view(client, effective_session_id, backend_node_id).await;
            let result: Result<DomGetBoxModelResult, String> = client
                .send_command_typed(
                    "DOM.getBoxModel",
                    &DomGetBoxModelParams {
                        backend_node_id: Some(backend_node_id),
                        node_id: None,
                        object_id: None,
                    },
                    Some(effective_session_id),
                )
                .await;

            if let Ok(r) = result {
                let (x, y) = box_model_center(&r.model);
                let (x, y) = resolve_unobstructed_point(
                    client,
                    effective_session_id,
                    backend_node_id,
                    selector_or_ref,
                    x,
                    y,
                )
                .await?;
                return Ok((x, y, effective_session_id.to_string()));
            }
            // backend_node_id is stale; re-query the accessibility tree below
        }

        // Fallback: re-query the accessibility tree to find a fresh node by role/name
        let fresh_id = find_node_id_by_role_name(
            client,
            session_id,
            &entry.role,
            &entry.name,
            entry.nth,
            entry.frame_id.as_deref(),
            iframe_sessions,
        )
        .await?;
        scroll_node_into_view(client, effective_session_id, fresh_id).await;
        let result: DomGetBoxModelResult = client
            .send_command_typed(
                "DOM.getBoxModel",
                &DomGetBoxModelParams {
                    backend_node_id: Some(fresh_id),
                    node_id: None,
                    object_id: None,
                },
                Some(effective_session_id),
            )
            .await?;
        let (x, y) = box_model_center(&result.model);
        let (x, y) = resolve_unobstructed_point(
            client,
            effective_session_id,
            fresh_id,
            selector_or_ref,
            x,
            y,
        )
        .await?;
        return Ok((x, y, effective_session_id.to_string()));
    }

    // CSS selector: honor an active `frame <sel>` selection.
    if let Some(frame_id) = active_frame() {
        // Cross-process iframe: its dedicated session's main frame IS the
        // iframe, so plain document-rooted resolution works there.
        if let Some(frame_session) = iframe_sessions.get(&frame_id) {
            let (x, y) = resolve_by_selector(client, frame_session, selector_or_ref).await?;
            return Ok((x, y, frame_session.clone()));
        }
        let (x, y) =
            resolve_center_in_same_process_frame(client, session_id, &frame_id, selector_or_ref)
                .await?;
        return Ok((x, y, session_id.to_string()));
    }
    let (x, y) = resolve_by_selector(client, session_id, selector_or_ref).await?;
    Ok((x, y, session_id.to_string()))
}

/// A document anchor remains measurable even when a checkbox itself is hidden.
/// Its DOM rectangle and CDP box locate the document in the input session.
async fn document_viewport_anchor(
    client: &CdpClient,
    session_id: &str,
    object_id: &str,
) -> Result<(String, BoxModel), String> {
    let root = client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
        "objectId":object_id,
        "functionDeclaration":"function() { return this.ownerDocument.documentElement; }",
        "objectGroup":"agent-browser",
        "returnByValue":false,
    })), Some(session_id)).await?;
    let root_id = root["result"]["objectId"].as_str()
        .ok_or("click_state_unavailable: frame document unavailable before dispatch")?.to_string();
    let model: DomGetBoxModelResult = client.send_command_typed(
        "DOM.getBoxModel",
        &DomGetBoxModelParams { object_id: Some(root_id.clone()), backend_node_id: None, node_id: None },
        Some(session_id),
    ).await?;
    Ok((root_id, model.model))
}

/// Native checkboxes often have a clipped, offscreen input and a painted label.
/// Pick an actually hit-testable part of the input or its associated label before
/// any pointer event. Never activate with JavaScript or retry a dispatched click.
/// Top-document targets need one synchronous point/overlay/disabled check,
/// not serial CDP box-model and document-anchor reads. Framed targets keep the
/// existing coordinate conversion path; the caller still revalidates identity.
pub(super) async fn fast_click_point(
    client: &CdpClient, session: &str, object: &str, target: &str,
) -> Result<Option<(f64, f64)>, String> {
    let function = include_str!("click_point.js")
        .replace("CHECKBOX_POINT", include_str!("checkbox_point.js"))
        .replace("BLOCKER_AT", BLOCKER_AT_JS)
        .replace("CLICK_GUARD", include_str!("click_guard.js"));
    let result = client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
        "objectId": object, "functionDeclaration": function, "returnByValue": true,
    })), Some(session)).await.map_err(|_| "click_state_unavailable: click point unavailable before dispatch")?;
    if result.get("exceptionDetails").is_some() {
        return Err("click_state_unavailable: click point unavailable before dispatch".into());
    }
    let value = &result["result"]["value"];
    if value["framed"] == true { return Ok(None); }
    if let Some(blocker) = value["blocker"].as_str() {
        return Err(intercepted_error(target, blocker));
    }
    if let Some(error) = value["error"].as_str() {
        return Err(match error {
            "disabled" => "click_disabled: target or containing control is disabled; no pointer events dispatched",
            "changed" => "click_target_changed: pinned click target detached before dispatch",
            _ => "click_not_hittable: target has no unobstructed activation point; no pointer events dispatched",
        }.into());
    }
    match (value["x"].as_f64(), value["y"].as_f64()) {
        (Some(x), Some(y)) => Ok(Some((x,y))),
        _ => Err("click_state_unavailable: click point unavailable before dispatch".into()),
    }
}

pub(super) async fn resolve_checkbox_point(
    client: &CdpClient,
    session_id: &str,
    object_id: &str,
    selector: &str,
) -> Result<Option<(f64, f64)>, String> {
    let result = client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
        "objectId": object_id,
        "functionDeclaration": include_str!("checkbox_point.js"),
        "returnByValue": true,
    })), Some(session_id)).await?;
    if result.get("exceptionDetails").is_some() {
        return Err("click_state_unavailable: checkbox hit testing failed before dispatch".into());
    }
    let value = &result["result"]["value"];
    if value.is_null() { return Ok(None); }
    let (Some(mut x), Some(mut y)) = (value["x"].as_f64(), value["y"].as_f64()) else {
        return Err("click_not_hittable: checkbox and associated labels have no unobstructed activation point; no pointer events dispatched".into());
    };
    // DOM rectangles are local to the element's document. CDP box models
    // already include every same-process frame offset in the input session's
    // CSS viewport, even across origins where window.frameElement is null.
    let (anchor, model) = document_viewport_anchor(client, session_id, object_id).await?;
    let placed = client.send_command("Runtime.callFunctionOn", Some(serde_json::json!({
        "objectId":anchor,
        "functionDeclaration": r#"function(x,y,border) {
            const r=this.getBoundingClientRect();
            const xs=[border[0],border[2],border[4],border[6]];
            const ys=[border[1],border[3],border[5],border[7]];
            const left=Math.min(...xs), top=Math.min(...ys);
            const sx=r.width ? (Math.max(...xs)-left)/r.width : 1;
            const sy=r.height ? (Math.max(...ys)-top)/r.height : sx;
            return {x:left+(x-r.left)*sx, y:top+(y-r.top)*sy};
        }"#,
        "arguments":[{"value":x},{"value":y},{"value":model.border}],
        "returnByValue":true,
    })), Some(session_id)).await?;
    (x,y) = match (placed["result"]["value"]["x"].as_f64(), placed["result"]["value"]["y"].as_f64()) {
        (Some(x),Some(y)) => (x,y),
        _ => return Err("click_state_unavailable: checkbox frame coordinates unavailable before dispatch".into()),
    };
    let described = client.send_command("DOM.describeNode", Some(serde_json::json!({
        "objectId":object_id, "depth":0,
    })), Some(session_id)).await?;
    let backend_id = described["node"]["backendNodeId"].as_i64()
        .ok_or("click_state_unavailable: checkbox node unavailable before dispatch")?;
    let (x, y) = resolve_unobstructed_point(client, session_id, backend_id, selector, x, y).await?;
    Ok(Some((x, y)))
}

/// Return a viewport-visible click point for a ref-resolved node, refusing
/// unrelated covering elements before dispatch. If node resolution fails, the
/// caller retains its original box-model point.
async fn resolve_unobstructed_point(
    client: &CdpClient,
    session_id: &str,
    backend_node_id: i64,
    target: &str,
    x: f64,
    y: f64,
) -> Result<(f64, f64), String> {
    let resolved: Result<DomResolveNodeResult, String> = client
        .send_command_typed(
            "DOM.resolveNode",
            &DomResolveNodeParams {
                backend_node_id: Some(backend_node_id),
                node_id: None,
                object_group: Some("agent-browser".to_string()),
            },
            Some(session_id),
        )
        .await;
    let Ok(resolved) = resolved else {
        return Ok((x, y));
    };
    let Some(object_id) = resolved.object.object_id else {
        return Ok((x, y));
    };
    let (anchor, model) = document_viewport_anchor(client, session_id, &object_id).await?;
    // Hit testing uses document-local CSS pixels, unlike CDP's session-relative
    // input coordinates. Cross-origin same-process frames cannot find their
    // parent through frameElement, so derive the conversion from the live node.
    let function = format!(
        r#"function(x, y, border, anchor) {{
            let inputX=x, inputY=y;
            const r=anchor.getBoundingClientRect();
            const xs=[border[0],border[2],border[4],border[6]];
            const ys=[border[1],border[3],border[5],border[7]];
            const left=Math.min(...xs), top=Math.min(...ys);
            const width=Math.max(...xs)-left, height=Math.max(...ys)-top;
            const sx=width && r.width ? r.width/width : 1;
            const sy=height && r.height ? r.height/height : sx;
            x=r.left+(x-left)*sx;
            y=r.top+(y-top)*sy;
            let topDoc = this.ownerDocument || document;
            const win=topDoc.defaultView;
            // Scrolling cannot put the center of a tall dropdown option (or
            // any oversized element) inside a smaller iframe. Use the center
            // of its visible intersection instead, before checking blockers.
            if (x < 0 || y < 0 || x >= win.innerWidth || y >= win.innerHeight) {{
                const rect=this.getBoundingClientRect();
                const l=Math.max(0,rect.left), t=Math.max(0,rect.top);
                const rr=Math.min(win.innerWidth,rect.right), b=Math.min(win.innerHeight,rect.bottom);
                if (rr > l && b > t) {{
                    x=(l+rr)/2; y=(t+b)/2;
                    inputX=left+(x-r.left)/sx;
                    inputY=top+(y-r.top)/sy;
                }}
            }}
            while (topDoc.defaultView && topDoc.defaultView.frameElement) {{
                const owner=topDoc.defaultView.frameElement;
                const rect=owner.getBoundingClientRect();
                x+=rect.left+owner.clientLeft; y+=rect.top+owner.clientTop;
                topDoc = owner.ownerDocument;
            }}
            const blockerAt = {BLOCKER_AT_JS};
            return {{blocker:blockerAt(topDoc, this, x, y), x:inputX, y:inputY}};
        }}"#,
    );
    let result = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": object_id,
                "functionDeclaration": function,
                "arguments": [{ "value": x }, { "value": y }, { "value": model.border }, { "objectId": anchor }],
                "returnByValue": true,
            })),
            Some(session_id),
        )
        .await;
    if let Ok(value) = result {
        if let Some(blocker) = value
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.get("blocker"))
            .and_then(|v| v.as_str())
        {
            return Err(intercepted_error(target, blocker));
        }
        if let (Some(x), Some(y)) = (
            value["result"]["value"]["x"].as_f64(),
            value["result"]["value"]["y"].as_f64(),
        ) {
            return Ok((x, y));
        }
    }
    Ok((x, y))
}

/// Coordinates from DOM.getBoxModel are viewport-relative, and input events
/// only land inside the viewport, so make sure the node is visible first.
/// Best effort: a node that cannot be scrolled (display:none, detached) will
/// fail in DOM.getBoxModel with a clearer error anyway.
async fn scroll_node_into_view(client: &CdpClient, session_id: &str, backend_node_id: i64) {
    let _ = client
        .send_command(
            "DOM.scrollIntoViewIfNeeded",
            Some(serde_json::json!({ "backendNodeId": backend_node_id })),
            Some(session_id),
        )
        .await;
}

async fn is_connected(client: &CdpClient, session_id: &str, object_id: &str) -> bool {
    client
        .send_command(
            "Runtime.callFunctionOn",
            Some(serde_json::json!({
                "objectId": object_id,
                "functionDeclaration": "function() { return this.isConnected; }",
                "returnByValue": true
            })),
            Some(session_id),
        )
        .await
        .is_ok_and(|r| r["result"]["value"] == true)
}

/// Refresh only a known ref in its original frame, before any click dispatch.
/// A vanished role/name or duplicate match is a refusal, never an ordinal guess.
pub(super) async fn click_ref_map(
    client: &CdpClient, session: &str, refs: &RefMap, selector: &str,
    frames: &HashMap<String, String>,
) -> Result<Option<RefMap>, String> {
    let Some(id) = parse_ref(selector) else { return Ok(None) };
    let entry = refs.get(&id).ok_or_else(|| format!("Unknown ref: {}", id))?;
    if entry.name.is_empty() || entry.selector.is_some() {
        return Err("ref_refresh_ambiguous: this detached ref has no unique accessibility name; run snapshot -i and choose a fresh ref; no pointer events dispatched".into());
    }
    let node = find_node_id_by_role_name(client, session, &entry.role, &entry.name, None, entry.frame_id.as_deref(), frames).await?;
    let mut fresh = refs.clone();
    fresh.map.get_mut(&id).unwrap().backend_node_id = Some(node);
    Ok(Some(fresh))
}

pub async fn resolve_element_object_id(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(String, String), String> {
    let (object, session, _) = resolve_element_object_id_report(client, session_id, ref_map, selector_or_ref, iframe_sessions).await?;
    Ok((object, session))
}

pub(super) async fn resolve_element_object_id_report(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(String, String, bool), String> {
    resolve_element_object_id_report_inner(client, session_id, ref_map, selector_or_ref, iframe_sessions, true).await
}

/// Click point acquisition checks connection before returning any coordinates,
/// and the dispatch boundary checks it again. Do not add a separate remote read.
pub(super) async fn resolve_click_object_id_report(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(String, String, bool), String> {
    resolve_element_object_id_report_inner(client, session_id, ref_map, selector_or_ref, iframe_sessions, false).await
}

async fn resolve_element_object_id_report_inner(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
    validate_connection: bool,
) -> Result<(String, String, bool), String> {
    if let Some(ref_id) = parse_ref(selector_or_ref) {
        let entry = ref_map
            .get(&ref_id)
            .ok_or_else(|| format!("Unknown ref: {}", ref_id))?;

        let effective_session_id =
            resolve_frame_session(entry.frame_id.as_deref(), session_id, iframe_sessions);

        // Try cached backend_node_id first (fast path)
        if let Some(backend_node_id) = entry.backend_node_id {
            let result: Result<DomResolveNodeResult, String> = client
                .send_command_typed(
                    "DOM.resolveNode",
                    &DomResolveNodeParams {
                        backend_node_id: Some(backend_node_id),
                        node_id: None,
                        object_group: Some("agent-browser".to_string()),
                    },
                    Some(effective_session_id),
                )
                .await;

            if let Ok(r) = result {
                if let Some(object_id) = r.object.object_id {
                    if !validate_connection || is_connected(client, effective_session_id, &object_id).await {
                        return Ok((object_id, effective_session_id.to_string(), false));
                    }
                }
            }
            // backend_node_id is stale (unresolvable, or resolves to a node the page
            // has detached); re-query the accessibility tree below
        }

        // Fallback: re-query the accessibility tree to find a fresh node by role/name
        let fresh_id = find_node_id_by_role_name(
            client,
            session_id,
            &entry.role,
            &entry.name,
            entry.nth,
            entry.frame_id.as_deref(),
            iframe_sessions,
        )
        .await?;
        let result: DomResolveNodeResult = client
            .send_command_typed(
                "DOM.resolveNode",
                &DomResolveNodeParams {
                    backend_node_id: Some(fresh_id),
                    node_id: None,
                    object_group: Some("agent-browser".to_string()),
                },
                Some(effective_session_id),
            )
            .await?;
        let object_id = result
            .object
            .object_id
            .ok_or_else(|| format!("No objectId for ref {}", ref_id))?;
        return Ok((object_id, effective_session_id.to_string(), true));
    }

    // Selector fallback (CSS or XPath): honor an active `frame <sel>` selection.
    if let Some(frame_id) = active_frame() {
        if let Some(frame_session) = iframe_sessions.get(&frame_id) {
            let js = build_find_element_js(selector_or_ref);
            let result: EvaluateResult = client
                .evaluate_dom(frame_session.as_str(), js, false)
                .await?;
            if result.exception_details.is_some() {
                return Err(selector_evaluation_error());
            }
            let object_id = result
                .result
                .object_id
                .ok_or_else(|| format!("Element not found: {}", selector_or_ref))?;
            return Ok((object_id, frame_session.clone(), false));
        }
        let object_id =
            resolve_object_in_same_process_frame(client, session_id, &frame_id, selector_or_ref)
                .await?;
        return Ok((object_id, session_id.to_string(), false));
    }

    let js = build_find_element_js(selector_or_ref);
    let result: EvaluateResult = client
        .evaluate_dom(session_id, js, false)
        .await?;

    if result.exception_details.is_some() {
        return Err(selector_evaluation_error());
    }
    let object_id = result
        .result
        .object_id
        .ok_or_else(|| format!("Element not found: {}", selector_or_ref))?;
    Ok((object_id, session_id.to_string(), false))
}

/// Determine which CDP session and parameters to use for an AX tree query.
/// Cross-origin iframes have a dedicated session (no frameId needed);
/// same-origin iframes use the parent session with a frameId parameter.
pub(super) fn resolve_ax_session<'a>(
    frame_id: Option<&str>,
    session_id: &'a str,
    iframe_sessions: &'a HashMap<String, String>,
) -> (serde_json::Value, &'a str) {
    if let Some(frame_id) = frame_id {
        if let Some(iframe_sid) = iframe_sessions.get(frame_id) {
            (serde_json::json!({}), iframe_sid.as_str())
        } else {
            (serde_json::json!({ "frameId": frame_id }), session_id)
        }
    } else {
        (serde_json::json!({}), session_id)
    }
}

/// Resolve the effective CDP session for an element's frame.
/// If the element's frame_id has a dedicated cross-origin iframe session, return it.
/// Otherwise, return the parent session.
fn resolve_frame_session<'a>(
    frame_id: Option<&str>,
    session_id: &'a str,
    iframe_sessions: &'a HashMap<String, String>,
) -> &'a str {
    frame_id
        .and_then(|fid| iframe_sessions.get(fid))
        .map(|s| s.as_str())
        .unwrap_or(session_id)
}

/// Re-query the accessibility tree to find a node matching role+name+nth,
/// returning its fresh backendDOMNodeId. This uses the same data source
/// (Accessibility.getFullAXTree) that built the ref map during snapshot,
/// so role/name matching is guaranteed to be consistent.
async fn find_node_id_by_role_name(
    client: &CdpClient,
    session_id: &str,
    role: &str,
    name: &str,
    nth: Option<usize>,
    frame_id: Option<&str>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<i64, String> {
    let (ax_params, effective_session_id) =
        resolve_ax_session(frame_id, session_id, iframe_sessions);
    let ax_tree: GetFullAXTreeResult = client
        .send_command_typed(
            "Accessibility.getFullAXTree",
            &ax_params,
            Some(effective_session_id),
        )
        .await?;

    let _ = nth; // An ordinal is not stable identity after DOM replacement.
    let matches: Vec<_> = ax_tree.nodes.iter().filter(|node|
        !node.ignored.unwrap_or(false) && extract_ax_string(&node.role) == role && extract_ax_string(&node.name) == name
    ).collect();
    match matches.as_slice() {
        [node] => node.backend_d_o_m_node_id.ok_or_else(|| "ref_refresh_unavailable: matching element has no backend node; run snapshot -i; no pointer events dispatched".into()),
        [] => Err("ref_refresh_missing: the old role/name is absent in a fresh accessibility snapshot of its original frame; run snapshot -i and choose a new ref; no pointer events dispatched".into()),
        _ => Err("ref_refresh_ambiguous: multiple elements now have the old role/name; run snapshot -i and choose a specific ref; no pointer events dispatched".into()),
    }
}

pub(super) fn extract_ax_string(value: &Option<AXValue>) -> String {
    match value {
        Some(v) => match &v.value {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            _ => String::new(),
        },
        None => String::new(),
    }
}

/// Build a JS expression that finds a DOM element by CSS selector or XPath.
fn build_find_element_js(selector: &str) -> String {
    build_find_element_js_in("document", selector)
}

/// Same as build_find_element_js but rooted at an arbitrary Document
/// expression (e.g. an iframe's contentDocument). CSS searches the selected
/// document first, then its nested open shadow roots; it never enters frames.
fn build_find_element_js_in(root: &str, selector: &str) -> String {
    if let Some(xpath) = selector.strip_prefix("xpath=") {
        format!(
            "{root}.evaluate({xpath}, {root}, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue",
            xpath = serde_json::to_string(xpath).unwrap_or_default(),
        )
    } else {
        format!(
            r#"(() => {{
                const direct = {root}.querySelector({selector});
                if (direct) return direct;
                const find = root => {{
                    for (const host of root.querySelectorAll('*')) {{
                        if (!host.shadowRoot) continue;
                        const match = host.shadowRoot.querySelector({selector}) || find(host.shadowRoot);
                        if (match) return match;
                    }}
                    return null;
                }};
                return find({root});
            }})()"#,
            selector = serde_json::to_string(selector).unwrap_or_default(),
        )
    }
}

/// Build a JS expression that counts matching DOM elements by CSS selector or XPath.
fn build_count_elements_js(selector: &str) -> String {
    if let Some(xpath) = selector.strip_prefix("xpath=") {
        format!(
            "document.evaluate({}, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotLength",
            serde_json::to_string(xpath).unwrap_or_default()
        )
    } else {
        format!(
            r#"(() => {{
                const count = root => {{
                    let total = root.querySelectorAll({selector}).length;
                    for (const host of root.querySelectorAll('*')) {{
                        if (host.shadowRoot) total += count(host.shadowRoot);
                    }}
                    return total;
                }};
                return count(document);
            }})()"#,
            selector = serde_json::to_string(selector).unwrap_or_default()
        )
    }
}

/// JS function source for `blockerAt(doc, el, x, y)`: returns a short
/// description of the element that would actually receive a click at (x, y)
/// when that element is unrelated to `el`, or null when the click would land
/// on `el` (or something that activates it). Relations that count as "lands
/// on el": shadow-including descendants, and
/// label/control association (custom checkboxes hide the input under a styled
/// sibling inside the same label).
const BLOCKER_AT_JS: &str = r#"(doc, el, x, y) => {
    // Descend from the given document through same-origin iframes so a point
    // over a frame resolves to the element inside it, in that frame's space.
    let d = doc, lx = x, ly = y;
    // Document hit tests return shadow hosts, not the painted inner element.
    // Descend each root before judging a host to be an unrelated overlay. Roots
    // on the target's ancestry also cover closed roots without accepting a host
    // blindly: an overlay inside that root must still refuse the click.
    const roots = new Map();
    for (let n = el; n;) {
        const root = n.getRootNode?.();
        if (!root?.host) break;
        roots.set(root.host, root); n = root.host;
    }
    let hit = d.elementFromPoint(lx, ly);
    const visited = new Set();
    while (hit && hit !== el && !visited.has(hit)) {
        visited.add(hit);
        const root = hit.shadowRoot || roots.get(hit);
        if (root?.elementFromPoint) {
            const inner = root.elementFromPoint(lx, ly);
            if (inner && inner !== hit) { hit = inner; continue; }
        }
        if ((hit.tagName === 'IFRAME' || hit.tagName === 'FRAME') && hit.contentDocument) {
            const r = hit.getBoundingClientRect();
            lx -= r.x + hit.clientLeft; ly -= r.y + hit.clientTop;
            d = hit.contentDocument;
            hit = d.elementFromPoint(lx, ly);
            continue;
        }
        break;
    }
    if (!hit) return "no element in viewport";
    if (hit === el) return null;
    const up = (n) => n.parentNode || n.host || (n.getRootNode && n.getRootNode().host) || null;
    for (let n = hit; n; n = up(n)) { if (n === el) return null; }
    const hitLabel = hit.closest ? hit.closest('label') : null;
    if (hitLabel && (hitLabel.control === el || hitLabel.contains(el))) return null;
    const elLabel = el.closest ? el.closest('label') : null;
    if (elLabel && elLabel.contains(hit)) return null;
    let desc = hit.tagName.toLowerCase();
    if (hit.id) desc += '#' + hit.id;
    else if (typeof hit.className === 'string' && hit.className.trim())
        desc += '.' + hit.className.trim().split(/\s+/).slice(0, 2).join('.');
    if (!hit.id && hit.closest) {
        const anchored = hit.closest('[id]');
        if (anchored && anchored !== hit)
            desc += ' inside ' + anchored.tagName.toLowerCase() + '#' + anchored.id;
    }
    return desc;
}"#;

fn build_selector_js(selector: &str) -> String {
    let find_expr = build_find_element_js(selector);
    // A viewport rectangle can still be clipped by an overflow ancestor (for
    // example an option below a listbox's visible rows). Always ask the browser
    // to scroll every enclosing scroll container before measuring and hit-testing.
    // Center alignment also moves viewport-visible controls away from sticky footers.
    format!(
        r#"(() => {{
            const el = {find_expr};
            if (!el) return null;
            el.scrollIntoView({{ block: 'center', inline: 'nearest', behavior: 'instant' }});
            const rect = el.getBoundingClientRect();
            const win=el.ownerDocument.defaultView;
            const left=Math.max(0,rect.left), top=Math.max(0,rect.top);
            const right=Math.min(win.innerWidth,rect.right), bottom=Math.min(win.innerHeight,rect.bottom);
            const visible=right>left && bottom>top;
            const x = visible ? (left+right)/2 : rect.x + rect.width / 2;
            const y = visible ? (top+bottom)/2 : rect.y + rect.height / 2;
            const blockerAt = {BLOCKER_AT_JS};
            return {{ x: x, y: y, blocker: blockerAt(document, el, x, y) }};
        }})()"#,
    )
}

async fn resolve_by_selector(
    client: &CdpClient,
    session_id: &str,
    selector: &str,
) -> Result<(f64, f64), String> {
    let js = build_selector_js(selector);

    let result: EvaluateResult = client
        .evaluate_dom(session_id, js, true)
        .await?;

    if result.exception_details.is_some() {
        return Err(selector_evaluation_error());
    }
    let val = result.result.value.unwrap_or(Value::Null);
    if let Some(blocker) = val.get("blocker").and_then(|v| v.as_str()) {
        return Err(intercepted_error(selector, blocker));
    }
    let x = val.get("x").and_then(|v| v.as_f64());
    let y = val.get("y").and_then(|v| v.as_f64());

    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(format!("Element not found: {}", selector)),
    }
}

fn selector_evaluation_error() -> String {
    "selector_invalid: selector evaluation failed; use native CSS or xpath= selectors, or find role/text for text matching (Playwright :text-is is not CSS)".into()
}

fn intercepted_error(target: &str, blocker: &str) -> String {
    format!(
        "Element '{}' is covered by <{}> at its click point, so the input would land on that element instead. Dismiss or interact with the covering element first (it is often a dialog, banner, or sticky header).",
        target, blocker
    )
}

fn box_model_center(model: &BoxModel) -> (f64, f64) {
    // content quad: [x1,y1, x2,y2, x3,y3, x4,y4]
    if model.content.len() >= 8 {
        let x = (model.content[0] + model.content[2] + model.content[4] + model.content[6]) / 4.0;
        let y = (model.content[1] + model.content[3] + model.content[5] + model.content[7]) / 4.0;
        (x, y)
    } else {
        (0.0, 0.0)
    }
}

pub async fn get_element_text(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: super::sensitive::getter_js("text", None),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_attribute(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    attribute: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: super::sensitive::getter_js("attribute", Some(attribute)),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result.result.value.unwrap_or(Value::Null))
}

pub async fn is_element_visible(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    const rect = this.getBoundingClientRect();
                    const style = window.getComputedStyle(this);
                    return rect.width > 0 && rect.height > 0 &&
                           style.visibility !== 'hidden' &&
                           style.display !== 'none' &&
                           parseFloat(style.opacity) > 0;
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

pub async fn is_element_enabled(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { return !this.disabled; }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(true))
}

pub async fn is_element_checked(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    // Mirrors Playwright's getChecked() with follow-label retargeting:
    // 1. If element is a native checkbox/radio input, return .checked
    // 2. If element has an ARIA checked role, return aria-checked
    // 3. Follow label → input association (label.control)
    // 4. Check for nested checkbox/radio input as last resort
    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    var el = this;
                    // Native checkbox/radio input
                    var tag = el.tagName && el.tagName.toUpperCase();
                    if (tag === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio')) {
                        return el.checked;
                    }
                    // ARIA role-based checked state
                    var role = el.getAttribute && el.getAttribute('role');
                    var ariaCheckedRoles = ['checkbox','radio','switch','menuitemcheckbox','menuitemradio','option','treeitem'];
                    if (role && ariaCheckedRoles.indexOf(role) !== -1) {
                        return el.getAttribute('aria-checked') === 'true';
                    }
                    // Follow label association (Playwright follow-label retarget)
                    var label = el;
                    if (tag !== 'LABEL') {
                        label = el.closest && el.closest('label');
                    }
                    if (label && label.tagName && label.tagName.toUpperCase() === 'LABEL' && label.control) {
                        var ctrl = label.control;
                        if (ctrl.type === 'checkbox' || ctrl.type === 'radio') {
                            return ctrl.checked;
                        }
                    }
                    // Check for nested native input
                    var input = el.querySelector && el.querySelector('input[type="checkbox"], input[type="radio"]');
                    if (input) return input.checked;
                    return false;
                }"#.to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

pub async fn get_element_inner_text(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: super::sensitive::getter_js("innertext", None),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_inner_html(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: super::sensitive::getter_js("html", None),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn get_element_input_value(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<String, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: super::sensitive::getter_js("value", None),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result
        .result
        .value
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default())
}

pub async fn set_element_value(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    value: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let js = format!(
        "function() {{ this.value = {}; this.dispatchEvent(new Event('input', {{bubbles: true}})); this.dispatchEvent(new Event('change', {{bubbles: true}})); }}",
        serde_json::to_string(value).unwrap_or_default()
    );

    client
        .send_command_typed::<_, EvaluateResult>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn get_element_bounding_box(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    const r = this.getBoundingClientRect();
                    return { x: r.x, y: r.y, width: r.width, height: r.height };
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    result
        .result
        .value
        .ok_or_else(|| format!("Could not get bounding box for: {}", selector_or_ref))
}

/// Counts in the frame selected with `frame`, like every other selector command.
pub async fn get_element_count(
    client: &CdpClient,
    session_id: &str,
    selector: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<i64, String> {
    let js = build_count_elements_js(selector);
    let frame = active_frame();
    if let Some(frame_id) = frame.as_deref().filter(|f| !iframe_sessions.contains_key(*f)) {
        let document = frame_document_object_id(client, session_id, frame_id).await?;
        let result = client
            .send_command(
                "Runtime.callFunctionOn",
                Some(serde_json::json!({
                    "objectId": document,
                    "functionDeclaration": format!("function() {{ const document = this; return {js}; }}"),
                    "returnByValue": true,
                })),
                Some(session_id),
            )
            .await?;
        return Ok(result["result"]["value"].as_i64().unwrap_or(0));
    }
    let session_id = frame
        .as_deref()
        .and_then(|f| iframe_sessions.get(f))
        .map(String::as_str)
        .unwrap_or(session_id);

    let result: EvaluateResult = client
        .evaluate_dom(session_id, js, true)
        .await?;

    Ok(result.result.value.and_then(|v| v.as_i64()).unwrap_or(0))
}

pub async fn get_element_styles(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    properties: Option<Vec<String>>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Value, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let js = match properties {
        Some(props) => {
            let props_json = serde_json::to_string(&props).unwrap_or("[]".to_string());
            format!(
                r#"function() {{
                    const s = window.getComputedStyle(this);
                    const props = {};
                    const result = {{}};
                    for (const p of props) result[p] = s.getPropertyValue(p);
                    return result;
                }}"#,
                props_json
            )
        }
        None => r#"function() {
                    const s = window.getComputedStyle(this);
                    const result = {};
                    for (let i = 0; i < s.length; i++) {
                        const p = s[i];
                        result[p] = s.getPropertyValue(p);
                    }
                    return result;
                }"#
        .to_string(),
    };

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(result.result.value.unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ref_at_prefix() {
        assert_eq!(parse_ref("@e1"), Some("e1".to_string()));
        assert_eq!(parse_ref("@e123"), Some("e123".to_string()));
    }

    #[test]
    fn test_parse_ref_equals_prefix() {
        assert_eq!(parse_ref("ref=e1"), Some("e1".to_string()));
    }

    #[test]
    fn test_parse_ref_bare() {
        assert_eq!(parse_ref("e1"), Some("e1".to_string()));
        assert_eq!(parse_ref("e42"), Some("e42".to_string()));
    }

    #[test]
    fn test_parse_ref_invalid() {
        assert_eq!(parse_ref("button"), None);
        assert_eq!(parse_ref("e"), None);
        assert_eq!(parse_ref("1"), None);
        assert_eq!(parse_ref(""), None);
    }

    #[test]
    fn test_ref_map_basic() {
        let mut map = RefMap::new();
        map.add("e1".to_string(), Some(42), "button", "Submit", None);
        assert!(map.get("e1").is_some());
        assert_eq!(map.get("e1").unwrap().role, "button");
        assert!(map.get("e2").is_none());
    }

    #[test]
    fn test_ref_map_clear_resets_ref_numbering() {
        let mut map = RefMap::new();
        map.add("e1".to_string(), Some(42), "button", "Submit", None);
        map.set_next_ref_num(2);

        map.clear();

        assert!(map.get("e1").is_none());
        assert_eq!(map.next_ref_num(), 1);
    }

    #[test]
    fn test_build_selector_js_css() {
        let js = build_selector_js("#submit-btn");
        assert!(js.contains("document.querySelector(\"#submit-btn\")"));
        assert!(!js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_selector_js_xpath() {
        let js = build_selector_js("xpath=//button[@id='ok']");
        assert!(js.contains("document.evaluate(\"//button[@id='ok']\", document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null)"));
        assert!(!js.contains("document.querySelector"));
    }

    #[test]
    fn test_build_selector_js_xpath_empty() {
        let js = build_selector_js("xpath=");
        assert!(js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_selector_js_not_xpath_prefix() {
        // "xpath" without "=" should be treated as CSS selector
        let js = build_selector_js("xpath//div");
        assert!(js.contains("document.querySelector"));
    }

    #[test]
    fn test_build_count_elements_js_css() {
        let js = build_count_elements_js(".item");
        assert!(js.contains("document.querySelectorAll(\".item\").length"));
        assert!(!js.contains("document.evaluate"));
    }

    #[test]
    fn test_build_count_elements_js_xpath() {
        let js = build_count_elements_js("xpath=//li");
        assert!(js.contains("document.evaluate(\"//li\", document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null).snapshotLength"));
        assert!(!js.contains("querySelectorAll"));
    }

    #[test]
    fn test_box_model_center() {
        let model = BoxModel {
            content: vec![10.0, 20.0, 110.0, 20.0, 110.0, 60.0, 10.0, 60.0],
            padding: vec![],
            border: vec![],
            margin: vec![],
            width: 100,
            height: 40,
        };
        let (x, y) = box_model_center(&model);
        assert!((x - 60.0).abs() < 0.01);
        assert!((y - 40.0).abs() < 0.01);
    }

    // -----------------------------------------------------------------------
    // resolve_frame_session tests (Issue #925)
    // Cross-origin iframe elements must resolve to the dedicated session.
    // -----------------------------------------------------------------------

    #[test]
    fn test_cross_origin_element_uses_dedicated_session() {
        let mut iframe_sessions = HashMap::new();
        iframe_sessions.insert(
            "cross-origin-frame".to_string(),
            "iframe-session".to_string(),
        );

        let session = resolve_frame_session(
            Some("cross-origin-frame"),
            "parent-session",
            &iframe_sessions,
        );

        assert_eq!(session, "iframe-session");
    }

    #[test]
    fn test_same_origin_element_uses_parent_session() {
        let iframe_sessions = HashMap::new();

        let session = resolve_frame_session(
            Some("same-origin-frame"),
            "parent-session",
            &iframe_sessions,
        );

        assert_eq!(session, "parent-session");
    }

    #[test]
    fn test_main_frame_element_uses_parent_session() {
        let iframe_sessions = HashMap::new();

        let session = resolve_frame_session(None, "parent-session", &iframe_sessions);

        assert_eq!(session, "parent-session");
    }
}
