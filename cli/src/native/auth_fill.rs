//! One private field fill, bound to the caller's exact active target and frame.
//! The daemon owns the operation lock, deadline and disconnect cancellation.
//! Generic fills do not navigate, submit, insert by focus or replay.
//! The closed WORK provider additionally owns identifier readiness and explicit submit.

use super::actions::DaemonState;
use super::element::{resolve_element_object_id, RefMap};
use crate::plugins::{resolve_credential_field_with_plugins, PluginConfig};
use serde::{Deserialize, Serialize};
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
pub(crate) struct Binding {
    pub(crate) session: String,
    pub(crate) frame_session: Option<String>,
    pub(crate) frame: String,
    pub(crate) loader: String,
    pub(crate) url: String,
}

pub(crate) struct FieldLocation {
    pub(crate) target: String,
    pub(crate) frame: String,
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
    bind_location(
        state,
        &FieldLocation {
            target: req.target.clone(),
            frame: req.frame.clone(),
        },
    )
    .await
}

pub(crate) async fn bind_location(
    state: &DaemonState,
    req: &FieldLocation,
) -> Result<Binding, String> {
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
    let mut req = request(cmd)?;
    if req.provider == "converge-work-password-v5" && req.field == "identifier" {
        return work_identifier_readiness(state, &req, deadline).await;
    }
    let work_password = req.provider == "converge-work-password-v5";
    if work_password {
        if req.item != "projects/sara-experiments/secrets/shared-google-workspace-kenan-password-global/versions/5" || req.field != "password" || req.selector != r#"input[type="password"][name="Passwd"]"# || req.target != "owned-work-main" || req.frame != "main" || req.format.is_some() { return Err(INVALID.into()); }
        if state.active_frame_id.is_some() {
            return Err(BINDING.into());
        }
        req.target = state
            .browser
            .as_ref()
            .ok_or(BINDING)?
            .active_target_id()
            .map_err(|_| BINDING)?
            .to_string();
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum WorkReason {
    DocumentBinding,
    AccountMismatch,
    PasswordControlUnavailable,
    AmbiguousPasswordControls,
    MixedLoginControls,
    AccountEvidenceMissing,
    PasswordControlIdentity,
    PasswordNextUnavailable,
    FormBinding,
    FormAction,
    SubmitOverride,
    FormTarget,
    ChallengeRoute,
    ChallengeForm,
    IdentifierControlUnavailable,
    IdentifierControlAmbiguous,
    IdentifierNextUnavailable,
    PinnedMutation,
    BindingChanged,
    IdentifierValueChanged,
    TransitionOrder,
    AlreadyDispatched,
    PolicyException,
    PolicyExpired,
    PolicyDisposed,
    ReadinessNotReached,
    RequestPolicy,
    TargetUnavailable,
    NativeBinding,
    NativeEvaluation,
    NativeProtocol,
    ReadinessTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkStep {
    IdentifierReady,
    IdentifierFilled,
    NextDispatched,
    PasswordReady,
    ChallengeReady,
    Waiting(WorkReason),
    Refused(WorkReason),
    Unknown(WorkReason),
}

impl WorkStep {
    fn public(self) -> Value {
        match self {
            Self::PasswordReady => {
                json!({"kind":"work-readiness", "state":"password-ready", "authentication":"not-established"})
            }
            Self::ChallengeReady => {
                json!({"kind":"work-readiness", "state":"challenge-ready", "authentication":"not-established"})
            }
            Self::Refused(reason) => {
                json!({"kind":"work-readiness", "state":"refused", "authentication":"not-established", "reason":reason})
            }
            Self::Unknown(reason) => {
                json!({"kind":"work-readiness", "state":"unknown", "authentication":"not-established", "reason":reason})
            }
            Self::IdentifierReady
            | Self::IdentifierFilled
            | Self::NextDispatched
            | Self::Waiting(_) => Self::Unknown(WorkReason::NativeProtocol).public(),
        }
    }

    fn decode(value: &Value) -> Result<Self, WorkReason> {
        let object = value.as_object().ok_or(WorkReason::NativeProtocol)?;
        match (value["state"].as_str(), object.len()) {
            (Some("identifier-ready"), 1) => Ok(Self::IdentifierReady),
            (Some("identifier-filled"), 1) => Ok(Self::IdentifierFilled),
            (Some("next-dispatched"), 1) => Ok(Self::NextDispatched),
            (Some("password-ready"), 1) => Ok(Self::PasswordReady),
            (Some("challenge-ready"), 1) => Ok(Self::ChallengeReady),
            (Some("waiting"), 2) => {
                let reason = serde_json::from_value::<WorkReason>(value["reason"].clone())
                    .map_err(|_| WorkReason::NativeProtocol)?;
                match reason {
                    WorkReason::PasswordControlUnavailable | WorkReason::ReadinessNotReached => {
                        Ok(Self::Waiting(reason))
                    }
                    _ => Err(WorkReason::NativeProtocol),
                }
            }
            (Some("refused"), 2) | (Some("unknown"), 2) => {
                let reason = serde_json::from_value::<WorkReason>(value["reason"].clone())
                    .map_err(|_| WorkReason::NativeProtocol)?;
                if value["state"] == "refused" {
                    Ok(Self::Refused(reason))
                } else {
                    Ok(Self::Unknown(reason))
                }
            }
            _ => Err(WorkReason::NativeProtocol),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WorkControlClass {
    Identifier,
    Password,
    Challenge,
    Mixed,
    Ambiguous,
    None,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WorkIdentityPresence {
    Missing,
    Own,
    Foreign,
    Conflicting,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorkDiagnostic {
    control_class: WorkControlClass,
    identity: WorkIdentityPresence,
    marker_present: bool,
    identifier_present: bool,
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkObservation {
    phase: &'static str,
    policy_sha256: &'static str,
    #[serde(flatten)]
    diagnostic: WorkDiagnostic,
}

struct WorkPage {
    bound: Binding,
    object: String,
    _group: super::cdp::client::RemoteObjectGroup,
}

async fn work_bound(state: &DaemonState, location: &FieldLocation) -> Result<Binding, WorkReason> {
    if state.active_frame_id.is_some() || location.frame != "main" {
        return Err(WorkReason::NativeBinding);
    }
    let bound = bind_location(state, location)
        .await
        .map_err(|_| WorkReason::NativeBinding)?;
    let url = url::Url::parse(&bound.url).map_err(|_| WorkReason::NativeBinding)?;
    if url.origin().ascii_serialization() != "https://accounts.google.com"
        || !url.username().is_empty()
        || url.password().is_some()
        || bound.frame_session.is_some()
    {
        return Err(WorkReason::NativeBinding);
    }
    Ok(bound)
}

async fn work_page(state: &DaemonState, location: &FieldLocation) -> Result<WorkPage, WorkReason> {
    let bound = work_bound(state, location).await?;
    let client = &state
        .browser
        .as_ref()
        .ok_or(WorkReason::TargetUnavailable)?
        .client;
    let group = client
        .object_group(vec![bound.session.clone()])
        .await
        .map_err(|_| WorkReason::NativeEvaluation)?;
    let probe = client
        .send_command(
            "Runtime.evaluate",
            Some(json!({
                "expression":format!("({})()", include_str!("work_readiness.js")),
                "objectGroup":group.name, "returnByValue":false,
            })),
            Some(&bound.session),
        )
        .await
        .map_err(|_| WorkReason::NativeEvaluation)?;
    if probe.get("exceptionDetails").is_some() {
        return Err(WorkReason::NativeEvaluation);
    }
    if work_bound(state, location).await? != bound {
        return Err(WorkReason::NativeBinding);
    }
    let object = probe["result"]["objectId"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or(WorkReason::NativeProtocol)?
        .to_string();
    Ok(WorkPage {
        bound,
        object,
        _group: group,
    })
}

async fn work_step(
    state: &DaemonState,
    location: &FieldLocation,
    page: &WorkPage,
    method: &str,
    observation: &mut Option<WorkObservation>,
) -> Result<WorkStep, WorkReason> {
    if work_bound(state, location).await? != page.bound {
        return Err(WorkReason::NativeBinding);
    }
    if method != "dispose" {
        *observation = None;
    }
    let declaration = match method {
        "inspect" => "function() { const step = this.inspect(); return {step, diagnostic:this.diagnostic()}; }",
        "fillIdentifier" => "async function() { const step = await this.fillIdentifier(); return {step, diagnostic:this.diagnostic()}; }",
        "clickNext" => "function() { const step = this.clickNext(); return {step, diagnostic:this.diagnostic()}; }",
        "readiness" => "function() { const step = this.readiness(); return {step, diagnostic:this.diagnostic()}; }",
        "dispose" => "function() { return this.dispose(); }",
        _ => return Err(WorkReason::NativeProtocol),
    };
    let value = state.browser.as_ref().ok_or(WorkReason::TargetUnavailable)?.client.send_command("Runtime.callFunctionOn", Some(json!({
        "objectId":page.object,"functionDeclaration":declaration,"returnByValue":true,"awaitPromise":true,
    })), Some(&page.bound.session)).await.map_err(|_| WorkReason::NativeEvaluation)?;
    if value.get("exceptionDetails").is_some() {
        return Err(WorkReason::NativeEvaluation);
    }
    if method != "clickNext" && work_bound(state, location).await? != page.bound {
        return Err(WorkReason::NativeBinding);
    }
    if method == "dispose" {
        return WorkStep::decode(&value["result"]["value"]);
    }
    let reply = &value["result"]["value"];
    if reply.as_object().map(|o| o.len()) != Some(2) || reply.get("diagnostic").is_none() {
        return Err(WorkReason::NativeProtocol);
    }
    let result = WorkStep::decode(&reply["step"])?;
    *observation = if reply["diagnostic"].is_null() {
        None
    } else {
        let diagnostic: WorkDiagnostic = serde_json::from_value(reply["diagnostic"].clone())
            .map_err(|_| WorkReason::NativeProtocol)?;
        Some(WorkObservation {
            phase: match method {
                "inspect" => "initial",
                "fillIdentifier" => "fill-identifier",
                "clickNext" => "click-next",
                "readiness" => "post-next",
                _ => return Err(WorkReason::NativeProtocol),
            },
            policy_sha256: "6986d57dc8d0fdf906cc7709232f68bada8efdd4601eab0b33fc42fb84a183f8",
            diagnostic,
        })
    };

    Ok(result)
}

async fn work_backend(
    state: &DaemonState,
    location: &FieldLocation,
    page: &WorkPage,
) -> Result<i64, WorkReason> {
    if work_bound(state, location).await? != page.bound {
        return Err(WorkReason::NativeBinding);
    }
    let client = &state
        .browser
        .as_ref()
        .ok_or(WorkReason::TargetUnavailable)?
        .client;
    let node = client.send_command("Runtime.callFunctionOn", Some(json!({
        "objectId":page.object,"functionDeclaration":"function() { return this.identifierNode(); }",
        "returnByValue":false,
    })), Some(&page.bound.session)).await.map_err(|_| WorkReason::NativeEvaluation)?;
    if node.get("exceptionDetails").is_some() {
        return Err(WorkReason::NativeEvaluation);
    }
    let object = node["result"]["objectId"]
        .as_str()
        .ok_or(WorkReason::NativeProtocol)?;
    let description = client
        .send_command(
            "DOM.describeNode",
            Some(json!({"objectId":object})),
            Some(&page.bound.session),
        )
        .await
        .map_err(|_| WorkReason::NativeEvaluation)?;
    if work_bound(state, location).await? != page.bound {
        return Err(WorkReason::NativeBinding);
    }
    description["node"]["backendNodeId"]
        .as_i64()
        .filter(|id| *id > 0)
        .ok_or(WorkReason::NativeProtocol)
}

async fn work_observe(
    state: &DaemonState,
    location: &FieldLocation,
    page: &WorkPage,
    method: &str,
    deadline: Instant,
    after_next: bool,
    observation: &mut Option<WorkObservation>,
) -> Result<WorkStep, WorkReason> {
    let end = deadline.min(Instant::now() + std::time::Duration::from_secs(2));
    loop {
        let step = work_step(state, location, page, method, observation).await?;
        let reason = match step {
            WorkStep::Waiting(reason) => reason,
            WorkStep::Unknown(WorkReason::ReadinessNotReached) if after_next => {
                WorkReason::ReadinessTimeout
            }
            terminal => return Ok(terminal),
        };
        if Instant::now() >= end {
            work_step(state, location, page, "dispose", observation).await?;
            return Ok(if after_next {
                WorkStep::Unknown(reason)
            } else {
                WorkStep::Refused(reason)
            });
        }
        tokio::time::sleep_until(end.min(Instant::now() + std::time::Duration::from_millis(25)))
            .await;
    }
}

async fn work_identifier_transition(
    state: &DaemonState,
    location: &FieldLocation,
    deadline: Instant,
    observation: &mut Option<WorkObservation>,
) -> Result<WorkStep, WorkReason> {
    let page = work_page(state, location).await?;
    match work_observe(
        state,
        location,
        &page,
        "inspect",
        deadline,
        false,
        observation,
    )
    .await?
    {
        terminal @ (WorkStep::PasswordReady
        | WorkStep::ChallengeReady
        | WorkStep::Refused(_)
        | WorkStep::Unknown(_)) => return Ok(terminal),
        WorkStep::IdentifierReady => {}
        WorkStep::IdentifierFilled | WorkStep::NextDispatched | WorkStep::Waiting(_) => {
            return Err(WorkReason::NativeProtocol)
        }
    }
    let backend = work_backend(state, location, &page).await?;
    match work_step(state, location, &page, "fillIdentifier", observation).await? {
        WorkStep::IdentifierFilled => {}
        terminal @ (WorkStep::Refused(_) | WorkStep::Unknown(_)) => return Ok(terminal),
        _ => return Err(WorkReason::NativeProtocol),
    }
    if work_backend(state, location, &page).await? != backend {
        return Err(WorkReason::NativeBinding);
    }
    match work_step(state, location, &page, "clickNext", observation).await? {
        WorkStep::NextDispatched => {}
        WorkStep::Refused(reason) | WorkStep::Unknown(reason) => {
            return Ok(WorkStep::Unknown(reason))
        }
        _ => return Err(WorkReason::NativeProtocol),
    }
    // Only the intended Next permits a new loader; pending observation keeps one pinned policy.
    let ready = work_page(state, location).await?;
    if ready.bound.session != page.bound.session || ready.bound.frame != page.bound.frame {
        return Err(WorkReason::NativeBinding);
    }
    match work_observe(
        state,
        location,
        &ready,
        "readiness",
        deadline,
        true,
        observation,
    )
    .await?
    {
        terminal @ (WorkStep::PasswordReady | WorkStep::ChallengeReady) => Ok(terminal),
        WorkStep::Refused(reason) | WorkStep::Unknown(reason) => Ok(WorkStep::Unknown(reason)),
        _ => Err(WorkReason::NativeProtocol),
    }
}

async fn work_identifier_readiness(
    state: &DaemonState,
    req: &FillRequest,
    deadline: Instant,
) -> Result<Value, String> {
    if req.item != "projects/sara-experiments/secrets/shared-google-workspace-kenan-password-global/versions/5"
        || req.selector != r#"input[type="email"]"# || req.target != "owned-work-main" || req.frame != "main"
        || req.format.is_some() || state.active_frame_id.is_some()
        || state.recording_state.active || state.tracing_state.active || state.screencasting
        || state.stream_server.is_some() || state.har_recording || state.request_tracking {
        return Ok(WorkStep::Refused(WorkReason::RequestPolicy).public());
    }
    let target = match state
        .browser
        .as_ref()
        .and_then(|mgr| mgr.active_target_id().ok())
    {
        Some(target) => target.to_owned(),
        None => return Ok(WorkStep::Refused(WorkReason::TargetUnavailable).public()),
    };
    let location = FieldLocation {
        target,
        frame: "main".into(),
    };
    if let Err(reason) = work_bound(state, &location).await {
        return Ok(WorkStep::Refused(reason).public());
    }
    let end = deadline
        .checked_sub(std::time::Duration::from_millis(100))
        .unwrap_or(deadline);
    let mut observation = None;
    let outcome = tokio::time::timeout_at(
        end,
        work_identifier_transition(state, &location, end, &mut observation),
    )
    .await;
    let result = match outcome {
        Ok(Ok(state)) => state,
        Ok(Err(reason)) => WorkStep::Unknown(reason),
        Err(_) => WorkStep::Unknown(WorkReason::ReadinessTimeout),
    };
    let mut public = result.public();
    if let Some(observation) = observation {
        public["diagnostic"] = serde_json::to_value(observation)
            .map_err(|_| "Native WORK diagnostic encoding failed".to_owned())?;
    }
    Ok(public)
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
    let work_password = req.provider == "converge-work-password-v5";
    if work_password {
        let url = url::Url::parse(&bound.url).map_err(|_| BINDING)?;
        if url.origin().ascii_serialization() != "https://accounts.google.com"
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(BINDING.into());
        }
    }
    let probe = mgr.client.send_command("Runtime.callFunctionOn", Some(json!({
        "objectId": object,
        "functionDeclaration": if work_password { WORK_PASSWORD_PROBE } else { "function() { if (!this.isConnected || !['INPUT','TEXTAREA'].includes(this.tagName) || (this.tagName === 'INPUT' && !['text','password','email','tel','url','search','number','date','month'].includes(this.type)) || this.matches(':disabled') || this.readOnly || !this.getClientRects().length) return null; return this.ownerDocument; }" },
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
        let observation = state
            .sensitive_observations
            .entry(bound.session.clone())
            .or_default();
        if req.field == "expiration_date" {
            observation.remember_private_expiry_value(&object_session, id, &value);
        } else {
            observation.remember_private_value(&object_session, id, "credential", &value);
        }
    }
    let filled = client
        .send_command(
            "Runtime.callFunctionOn",
            Some(json!({
                "objectId": object,
                "functionDeclaration": if work_password { WORK_PASSWORD_FILL } else { PRIVATE_FILL },
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
        let observation = state
            .sensitive_observations
            .entry(bound.session.clone())
            .or_default();
        if req.field == "expiration_date" {
            observation.remember_private_expiry_value(&object_session, backend, rendered);
        } else {
            observation.remember_private_value(&object_session, backend, "credential", rendered);
        }
    } else if filled["result"]["value"]["status"].as_str() == Some("filled") {
        return Err(PAGE.into());
    }
    match filled["result"]["value"]["status"].as_str() {
        Some("submitted") if work_password => Ok(
            json!({"submitted":true,"authentication":"not-established","target":req.target,"frame":req.frame,"field":req.field}),
        ),
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

const WORK_PASSWORD_PROBE: &str = r##"function(){return (function(){
 const doc=this.ownerDocument;
 if(!this.isConnected||this.tagName!=='INPUT'||this.type!=='password'||this.name!=='Passwd'||this.disabled||this.readOnly||!this.getClientRects().length)return null;
 if(!doc||doc.defaultView.location.origin!=='https://accounts.google.com'||doc.defaultView!==doc.defaultView.top)return null;
 const form=this.form;if(!form||!form.isConnected||form.method.toUpperCase()!=='POST')return null;
 let action;try{action=new URL(form.action,doc.baseURI);}catch{return null;}
 if(action.origin!=='https://accounts.google.com'||action.username||action.password)return null;
 const identities=Array.from(doc.querySelectorAll('[data-identifier]')).map(el=>el.getAttribute('data-identifier'));
 const hidden=Array.from(form.querySelectorAll('input[type="hidden"][name="identifier"]')).map(el=>el.value);
 const accounts=[...identities,...hidden].filter(value=>typeof value==='string'&&value.length>0);
 if(accounts.length===0||accounts.some(value=>value!=='kenan@liminal.co'))return null;
 const controls=Array.from(doc.querySelectorAll('input[type="password"][name="Passwd"]')).filter(el=>el.isConnected&&!el.disabled&&!el.readOnly&&el.getClientRects().length);
 if(controls.length!==1||controls[0]!==this)return null;
 const buttons=Array.from(doc.querySelectorAll('#passwordNext button')).filter(el=>el.isConnected&&!el.disabled&&el.getClientRects().length);
 if(buttons.length!==1)return null;
 const button=buttons[0];if(button.ownerDocument!==doc)return null;
 return {doc,form,button,action:action.href};
}).call(this);}"##;
const WORK_PASSWORD_FILL: &str = r##"async function(value,bound,field,segments){
 const inspect=function(){
 const doc=this.ownerDocument;
 if(!this.isConnected||this.tagName!=='INPUT'||this.type!=='password'||this.name!=='Passwd'||this.disabled||this.readOnly||!this.getClientRects().length)return null;
 if(!doc||doc.defaultView.location.origin!=='https://accounts.google.com'||doc.defaultView!==doc.defaultView.top)return null;
 const form=this.form;if(!form||!form.isConnected||form.method.toUpperCase()!=='POST')return null;
 let action;try{action=new URL(form.action,doc.baseURI);}catch{return null;}
 if(action.origin!=='https://accounts.google.com'||action.username||action.password)return null;
 const identities=Array.from(doc.querySelectorAll('[data-identifier]')).map(el=>el.getAttribute('data-identifier'));
 const hidden=Array.from(form.querySelectorAll('input[type="hidden"][name="identifier"]')).map(el=>el.value);
 const accounts=[...identities,...hidden].filter(value=>typeof value==='string'&&value.length>0);
 if(accounts.length===0||accounts.some(value=>value!=='kenan@liminal.co'))return null;
 const controls=Array.from(doc.querySelectorAll('input[type="password"][name="Passwd"]')).filter(el=>el.isConnected&&!el.disabled&&!el.readOnly&&el.getClientRects().length);
 if(controls.length!==1||controls[0]!==this)return null;
 const buttons=Array.from(doc.querySelectorAll('#passwordNext button')).filter(el=>el.isConnected&&!el.disabled&&el.getClientRects().length);
 if(buttons.length!==1)return null;
 const button=buttons[0];if(button.ownerDocument!==doc)return null;
 return {doc,form,button,action:action.href};
};
 const before=inspect.call(this);
 if(!bound||!before||before.doc!==bound.doc||before.form!==bound.form||before.button!==bound.button||before.action!==bound.action||field!=='password'||segments)return {status:'detached'};
 const document=bound.doc;
 const view=document.defaultView;
 const setter=Object.getOwnPropertyDescriptor(view.HTMLInputElement.prototype,'value').set;
 setter.call(this,value);
 this.dispatchEvent(new view.Event('input',{bubbles:true}));
 this.dispatchEvent(new view.Event('change',{bubbles:true}));
 await new Promise(resolve=>view.setTimeout(resolve,100));
 const rendered=this.value;
 const current=inspect.call(this);
 if(!current||current.doc!==before.doc||current.form!==before.form||current.button!==before.button||current.action!==before.action)return {status:'detached',redactionValue:rendered};
 if(rendered!==value)return {status:'not_retained',redactionValue:rendered};
 // Same pinned ordinary continuation, after exact retention and immediately
 // before native click. A lost reply is unknown, never replayable.
 current.button.click();
 return {status:'submitted',redactionValue:rendered};
}"##;

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

    #[test]
    fn work_readiness_reason_codec_is_closed_and_exact() {
        let abi: Value =
            serde_json::from_str(include_str!("../../../scripts/work-readiness-reasons.json"))
                .unwrap();
        assert_eq!(abi["reasons"].as_array().unwrap().len(), 32);
        for reason in abi["reasons"].as_array().unwrap() {
            for state in ["refused", "unknown"] {
                let page = json!({"state":state,"reason":reason});
                let step = WorkStep::decode(&page).unwrap();
                assert_eq!(
                    step.public(),
                    json!({"kind":"work-readiness","state":state,"authentication":"not-established","reason":reason})
                );
            }
        }
        for bad in [
            json!({"state":"refused"}),
            json!({"state":"unknown","reason":"not-reported"}),
            json!({"state":"refused","reason":"private-secret"}),
            json!({"state":"password-ready","reason":"account-mismatch"}),
            json!({"state":"refused","reason":"account-mismatch","url":"private"}),
            json!({"state":"unknown","reason":null}),
        ] {
            assert_eq!(WorkStep::decode(&bad), Err(WorkReason::NativeProtocol));
        }
    }

    struct Fixture {
        state: DaemonState,
        generation: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fills: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        active_membership: std::sync::Arc<std::sync::atomic::AtomicBool>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::new_work(false).await
        }
        async fn new_work(work: bool) -> Self {
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
                                json!({"frameTree":{"frame":{"id":"root", "loaderId":if work {format!("topdoc{}",server_generation.load(Ordering::SeqCst))}else{"topdoc".to_string()}, "url":if work {"https://accounts.google.com/v3/signin/challenge/pwd"}else{"https://fixture.test"}}, "childFrames":[{"frame":{"id":"child", "parentId":"root", "loaderId":loader, "url":"https://child.test"}}]}})
                            } else {
                                json!({"frameTree":{"frame":{"id":"root", "loaderId":if work {format!("topdoc{}",server_generation.load(Ordering::SeqCst))}else{"topdoc".to_string()}, "url":if work {"https://accounts.google.com/v3/signin/challenge/pwd"}else{"https://fixture.test"}}}})
                            }
                        }
                        "Runtime.evaluate" => {
                            json!({"result":{"objectId":"input-object", "type":"object"}})
                        }
                        "DOM.describeNode" => json!({"node":{"backendNodeId":7}}),
                        "Runtime.callFunctionOn" => {
                            if work && cmd["params"]["functionDeclaration"] == WORK_PASSWORD_FILL {
                                assert_eq!(cmd["sessionId"], "page-session");
                                server_fills.fetch_add(1, Ordering::SeqCst);
                                json!({"result":{"value":{"status":"submitted", "redactionValue":"synthetic-private-value"}}})
                            } else if cmd["params"]["functionDeclaration"] == PRIVATE_FILL {
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

    fn work_req() -> FillRequest {
        request(&json!({"credentialProvider":"converge-work-password-v5","credentialItem":"projects/sara-experiments/secrets/shared-google-workspace-kenan-password-global/versions/5","field":"password","selector":"input[type=\"password\"][name=\"Passwd\"]","target":"page","frame":"main"})).unwrap()
    }
    #[tokio::test]
    async fn work_password_native_submit_is_metadata_only() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new_work(true).await;
        fixture.state.active_frame_id = None;
        let result = fill_with_resolver(
            &mut fixture.state,
            &work_req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { Ok("synthetic-private-value".into()) },
        )
        .await
        .unwrap();
        assert_eq!(result["submitted"], true);
        assert_eq!(result["authentication"], "not-established");
        assert!(!result.to_string().contains("synthetic-private-value"));
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 1);
        fixture.server.abort();
    }
    #[tokio::test]
    async fn work_password_foreign_origin_refuses_before_lookup() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new().await;
        fixture.state.active_frame_id = None;
        let error = fill_with_resolver(
            &mut fixture.state,
            &work_req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { panic!("foreign origin must never resolve") },
        )
        .await
        .unwrap_err();
        assert_eq!(error, BINDING);
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
        fixture.server.abort();
    }
    #[tokio::test]
    async fn work_password_loader_change_after_lookup_refuses_fill_submit() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new_work(true).await;
        fixture.state.active_frame_id = None;
        let generation = fixture.generation.clone();
        let error = fill_with_resolver(
            &mut fixture.state,
            &work_req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async move {
                generation.store(2, Ordering::SeqCst);
                Ok("synthetic-private-value".into())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error, BINDING);
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
        fixture.server.abort();
    }
    #[tokio::test]
    async fn work_password_private_lookup_error_is_redacted() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new_work(true).await;
        fixture.state.active_frame_id = None;
        let error = fill_with_resolver(
            &mut fixture.state,
            &work_req(),
            Instant::now() + std::time::Duration::from_secs(2),
            |_| async { Err("synthetic-private-value".into()) },
        )
        .await
        .unwrap_err();
        assert!(!error.contains("synthetic-private-value"));
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
        fixture.server.abort();
    }
    #[tokio::test]
    async fn work_password_cancelled_lookup_never_fills_or_submits() {
        use std::sync::atomic::Ordering;
        let mut fixture = Fixture::new_work(true).await;
        fixture.state.active_frame_id = None;
        let req = work_req();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            fill_with_resolver(
                &mut fixture.state,
                &req,
                Instant::now() + std::time::Duration::from_secs(2),
                |_| async { std::future::pending::<Result<String, String>>().await },
            ),
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(fixture.fills.load(Ordering::SeqCst), 0);
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
        assert!(
            snapshot["data"]["snapshot"]
                .as_str()
                .unwrap()
                .matches("[redacted: credential]")
                .count()
                >= 9
        );
        for (action, selector, key) in [
            ("gettext", "#code", "text"),
            ("innertext", "#code", "text"),
            ("innerhtml", "#code", "html"),
            ("getattribute", "input", "value"),
        ] {
            let getter = execute_command(
                &json!({"id":"scoped","action":action,"selector":selector,"attribute":"value"}),
                &mut state,
            )
            .await;
            assert_eq!(getter["success"], true, "{getter}");
            assert_eq!(getter["data"][key], "[redacted: credential]", "{getter}");
        }
        for action in ["content", "read"] {
            let refused = execute_command(&json!({"id":"bulk","action":action}), &mut state).await;
            assert_eq!(refused["success"], false, "{refused}");
            assert!(
                refused["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("SENSITIVE_OUTPUT_UNSUPPORTED:"),
                "{refused}"
            );
        }
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
