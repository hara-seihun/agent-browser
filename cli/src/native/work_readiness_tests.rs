//! Public-dispatch protocol qualification, composed with scripts/work-readiness.test.mjs.
//! This fixture does not interpret JavaScript or prove DOM guard semantics. It checks
//! the exact maintained factory bytes and method calls, models ordered page replies,
//! and injects CDP transport/binding faults. The companion actual-policy JSDOM
//! tests must pass on the same source before the composition is called qualified.
//! Neither half alone establishes actual Chrome/CDP integrated execution.

use super::actions::{execute_command, DaemonState};
use super::browser::BrowserManager;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message;

const OWN_ORIGIN: &str = "https://accounts.google.com";
const PRIVATE_MARKER: &str = "synthetic-private-password-never-public";
const ITEM: &str =
    "projects/sara-experiments/secrets/shared-google-workspace-kenan-password-global/versions/5";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Password,
    Challenge,
    ExistingPassword,
    ExistingChallenge,
    ForeignAccount,
    ForeignOrigin,
    UrlCredentials,
    ForeignTarget,
    ForeignFrame,
    LoaderBeforeFill,
    LoaderBeforeClick,
    DocumentBeforeFill,
    ActionBeforeClick,
    ForeignReadiness,
    Ambiguous,
    MalformedReadiness,
    ExtraReadiness,
    ExceptionAfterClick,
    LostAck,
    PendingReadiness,
    InitialWaiting,
    InitialWaitingForever,
    InitialWaitingBindingChange,
    ReadinessWaiting,
    ReadinessWaitingForever,
    ReadinessWaitingBindingChange,
}

#[derive(Default)]
struct Trace {
    commands: Vec<Value>,
    factory: usize,
    inspect: usize,
    fills: usize,
    clicks: usize,
    readiness: usize,
    password_submits: usize,
    generic_fill_dispatches: usize,
    violations: Vec<String>,
}

struct Fixture {
    state: DaemonState,
    trace: Arc<Mutex<Trace>>,
    click_seen: Arc<Notify>,
    server: tokio::task::JoinHandle<()>,
    private: tempfile::TempDir,
    plugins: Value,
}

fn page_state(state: &str) -> Value {
    json!({"result":{"type":"object","value":{"step":{"state":state},"diagnostic":null}}})
}

fn page_failure(state: &str, reason: &str) -> Value {
    json!({"result":{"type":"object","value":{"step":{"state":state,"reason":reason},"diagnostic":null}}})
}

fn password_policy_constant(name: &str) -> &'static str {
    let source = include_str!("auth_fill.rs");
    let prefix = format!("const {name}: &str = r##\"");
    source
        .split_once(prefix.as_str())
        .expect("maintained password policy constant")
        .1
        .split_once("\"##;")
        .expect("password policy delimiter")
        .0
}

impl Fixture {
    async fn new(case: Case) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let server_trace = trace.clone();
        let click_seen = Arc::new(Notify::new());
        let server_click_seen = click_seen.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut generation = 1;
            while let Some(Ok(message)) = ws.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let cmd: Value = serde_json::from_str(&text).unwrap();
                let method = cmd["method"].as_str().unwrap();
                let mut hold = false;
                let result = {
                    let mut t = server_trace.lock().unwrap();
                    t.commands.push(cmd.clone());
                    let url = if case == Case::ForeignOrigin {
                        "https://accounts.google.com.evil.invalid/"
                    } else if case == Case::UrlCredentials {
                        "https://foreign@accounts.google.com/"
                    } else {
                        "https://accounts.google.com/v3/signin/identifier?synthetic-private-query"
                    };
                    match method {
                        "Target.getTargets" => {
                            json!({"targetInfos":[{"targetId":"page","type":"page","url":url,"title":"synthetic-private-title","attached":false}]})
                        }
                        "Target.attachToTarget" => json!({"sessionId":"page-session"}),
                        "Target.getTargetInfo" => {
                            json!({"targetInfo":{"targetId":if case == Case::ForeignTarget {"foreign-page"} else {"page"}}})
                        }
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"root","loaderId":format!("loader-{generation}"),"url":url}}})
                        }
                        "DOM.getDocument" => {
                            json!({"root":{"nodeId":1,"backendNodeId":100,"nodeType":9,"nodeName":"#document","documentURL":url,"children":[{"nodeId":2,"backendNodeId":7,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":["type","password","name","Passwd","autocomplete","current-password"]}]}})
                        }
                        "DOM.resolveNode" => {
                            json!({"object":{"type":"object","objectId":"protected-control"}})
                        }
                        "DOM.describeNode" => {
                            json!({"node":{"nodeId":2,"backendNodeId":7,"nodeType":1,"nodeName":"INPUT","attributes":["type","password","name","Passwd"]}})
                        }
                        "Runtime.evaluate" => {
                            let expression = cmd["params"]["expression"].as_str().unwrap();
                            if expression == format!("({})()", include_str!("work_readiness.js")) {
                                if cmd["params"]["returnByValue"] != false
                                    || !cmd["params"]["objectGroup"].is_string()
                                    || cmd["sessionId"] != "page-session"
                                {
                                    t.violations.push("factory must bind a private grouped object in the owned session".into());
                                }
                                t.factory += 1;
                                json!({"result":{"type":"object","objectId":"work-policy"}})
                            } else if expression.contains("querySelector") {
                                json!({"result":{"type":"object","objectId":"password-control"}})
                            } else if expression == "1" {
                                json!({"result":{"type":"number","value":1}})
                            } else if expression == "location.href" {
                                json!({"result":{"type":"string","value":url}})
                            } else {
                                t.violations
                                    .push(format!("unexpected Runtime.evaluate: {expression}"));
                                json!({"exceptionDetails":{"text":PRIVATE_MARKER}})
                            }
                        }
                        "Runtime.callFunctionOn" => {
                            let js = cmd["params"]["functionDeclaration"].as_str().unwrap();
                            if js == include_str!("fill.js") {
                                t.generic_fill_dispatches += 1;
                                t.violations.push(
                                    "generic fill dispatched before sensitive-tab refusal".into(),
                                );
                                json!({"exceptionDetails":{"text":PRIVATE_MARKER}})
                            } else if cmd["params"]["objectId"] == "work-policy" {
                                let node_method =
                                    js == "function() { return this.identifierNode(); }";
                                if cmd["sessionId"] != "page-session"
                                    || cmd["params"]["returnByValue"] != !node_method
                                {
                                    t.violations.push("policy method escaped owned session/private value contract".into());
                                }
                                match js {
                                    "function() { return this.identifierNode(); }" => {
                                        json!({"result":{"type":"object","objectId":"identifier-control"}})
                                    }
                                    "function() { const step = this.inspect(); return {step, diagnostic:this.diagnostic()}; }" => {
                                        t.inspect += 1;
                                        if t.factory != 1
                                            || (t.inspect != 1
                                                && !matches!(
                                                    case,
                                                    Case::InitialWaiting
                                                        | Case::InitialWaitingForever
                                                        | Case::InitialWaitingBindingChange
                                                ))
                                        {
                                            t.violations
                                                .push("inspect without one fresh factory".into());
                                        }
                                        if case == Case::LoaderBeforeFill {
                                            generation += 1;
                                        }
                                        match case {
                                            Case::InitialWaiting
                                            | Case::InitialWaitingForever
                                            | Case::InitialWaitingBindingChange => {
                                                if case == Case::InitialWaitingBindingChange
                                                    && t.inspect == 2
                                                {
                                                    generation += 1;
                                                }
                                                if case == Case::InitialWaiting && t.inspect >= 3 {
                                                    page_state("password-ready")
                                                } else {
                                                    page_failure(
                                                        "waiting",
                                                        "password-control-unavailable",
                                                    )
                                                }
                                            }
                                            Case::ExistingPassword => page_state("password-ready"),
                                            Case::ExistingChallenge => {
                                                page_state("challenge-ready")
                                            }
                                            Case::ForeignAccount => {
                                                page_failure("refused", "account-mismatch")
                                            }
                                            _ => page_state("identifier-ready"),
                                        }
                                    }
                                    "async function() { const step = await this.fillIdentifier(); return {step, diagnostic:this.diagnostic()}; }" => {
                                        t.fills += 1;
                                        if t.inspect != 1 || t.fills != 1 || t.clicks != 0 {
                                            t.violations.push(
                                                "identifier setter duplicated or out of order"
                                                    .into(),
                                            );
                                        }
                                        if case == Case::LoaderBeforeClick {
                                            generation += 1;
                                        }
                                        if case == Case::DocumentBeforeFill {
                                            page_failure("refused", "document-binding")
                                        } else {
                                            page_state("identifier-filled")
                                        }
                                    }
                                    "function() { const step = this.clickNext(); return {step, diagnostic:this.diagnostic()}; }" => {
                                        t.clicks += 1;
                                        if t.fills != 1 || t.clicks != 1 {
                                            t.violations.push(
                                                "Next duplicated or without retained identifier"
                                                    .into(),
                                            );
                                        }
                                        server_click_seen.notify_one();
                                        if case == Case::LostAck {
                                            hold = true;
                                        }
                                        if case == Case::ActionBeforeClick {
                                            page_failure("refused", "form-action")
                                        } else {
                                            generation += 1;
                                            page_state("next-dispatched")
                                        }
                                    }
                                    "function() { return this.dispose(); }" => {
                                        json!({"result":{"type":"object","value":{"state":"refused","reason":"policy-disposed"}}})
                                    }
                                    "function() { const step = this.readiness(); return {step, diagnostic:this.diagnostic()}; }" => {
                                        t.readiness += 1;
                                        if t.clicks != 1 {
                                            t.violations.push("readiness before one Next".into());
                                        }
                                        match case {
                                            Case::ReadinessWaiting
                                            | Case::ReadinessWaitingForever
                                            | Case::ReadinessWaitingBindingChange => {
                                                if case == Case::ReadinessWaitingBindingChange
                                                    && t.readiness == 2
                                                {
                                                    generation += 1;
                                                }
                                                if case == Case::ReadinessWaiting
                                                    && t.readiness >= 3
                                                {
                                                    page_state("password-ready")
                                                } else {
                                                    page_failure(
                                                        "waiting",
                                                        "password-control-unavailable",
                                                    )
                                                }
                                            }
                                            Case::Challenge => page_state("challenge-ready"),
                                            Case::ForeignReadiness => {
                                                page_failure("refused", "account-mismatch")
                                            }
                                            Case::Ambiguous => {
                                                page_failure("unknown", "readiness-not-reached")
                                            }
                                            Case::MalformedReadiness => {
                                                page_state("invented-ready")
                                            }
                                            Case::ExtraReadiness => {
                                                json!({"result":{"value":{"state":"password-ready","body":PRIVATE_MARKER}}})
                                            }
                                            Case::ExceptionAfterClick => {
                                                json!({"exceptionDetails":{"text":PRIVATE_MARKER}})
                                            }
                                            Case::PendingReadiness => {
                                                hold = true;
                                                page_failure("unknown", "readiness-not-reached")
                                            }
                                            _ => page_state("password-ready"),
                                        }
                                    }
                                    _ => {
                                        t.violations.push(format!("unknown policy method: {js}"));
                                        json!({"exceptionDetails":{"text":PRIVATE_MARKER}})
                                    }
                                }
                            } else if js == password_policy_constant("WORK_PASSWORD_PROBE") {
                                json!({"result":{"type":"object","objectId":"password-document"}})
                            } else if js == password_policy_constant("WORK_PASSWORD_FILL") {
                                if cmd["params"]["arguments"][0]["value"] != PRIVATE_MARKER
                                    || cmd["params"]["arguments"][1]["objectId"]
                                        != "password-document"
                                {
                                    t.violations.push("password submission lacks separate private lookup/document binding".into());
                                }
                                t.password_submits += 1;
                                json!({"result":{"value":{"status":"submitted","redactionValue":PRIVATE_MARKER}}})
                            } else if cmd["params"]["objectId"] == "protected-control"
                                && js.contains("String(this.value")
                            {
                                json!({"result":{"value":[PRIVATE_MARKER,"",""]}})
                            } else {
                                t.violations
                                    .push(format!("unexpected Runtime.callFunctionOn: {js}"));
                                json!({"exceptionDetails":{"text":PRIVATE_MARKER}})
                            }
                        }
                        "Browser.getVersion" => {
                            json!({"protocolVersion":"1.3","product":"Fixture/1","revision":"synthetic","userAgent":"Fixture","jsVersion":"1"})
                        }
                        "Runtime.enable"
                        | "Page.enable"
                        | "DOM.enable"
                        | "Network.enable"
                        | "Accessibility.enable"
                        | "WebMCP.enable"
                        | "Target.setAutoAttach"
                        | "Runtime.runIfWaitingForDebugger"
                        | "Page.setLifecycleEventsEnabled"
                        | "Runtime.releaseObjectGroup"
                        | "Runtime.releaseObject"
                        | "Target.setDiscoverTargets" => json!({}),
                        _ => {
                            t.violations
                                .push(format!("unexpected CDP method: {method}"));
                            json!({})
                        }
                    }
                };
                if !hold
                    && ws
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
        let browser = BrowserManager::connect_cdp(&format!("ws://{address}"))
            .await
            .unwrap();
        let mut state = DaemonState::new();
        state.browser = Some(browser);
        state.restore_save = "never".into();
        if case == Case::ForeignFrame {
            state.active_frame_id = Some("foreign-frame".into());
        }
        let private = tempfile::tempdir().unwrap();
        std::fs::write(private.path().join("provider-calls"), "").unwrap();
        let script = private.path().join("provider.sh");
        std::fs::write(&script, format!("cat >> \"$1\"\nprintf '\\n' >> \"$1\"\nprintf '%s' '{{\"protocol\":\"agent-browser.plugin.v1\",\"success\":true,\"value\":\"{PRIVATE_MARKER}\"}}'\n")).unwrap();
        let plugins = json!([{"name":"converge-work-password-v5","command":"/bin/sh","args":[script.to_str().unwrap(),private.path().join("provider-calls").to_str().unwrap()],"capabilities":["credential.read"]}]);
        Self {
            state,
            trace,
            click_seen,
            server,
            private,
            plugins,
        }
    }

    fn request(&self) -> Value {
        json!({"id":"work-identifier","action":"auth_fill","credentialProvider":"converge-work-password-v5","credentialItem":ITEM,"field":"identifier","selector":"input[type=\"email\"]","target":"owned-work-main","frame":"main","timeout":2500,"plugins":self.plugins})
    }

    async fn dispatch(&mut self, cmd: Value) -> Value {
        tokio::time::timeout(
            Duration::from_secs(4),
            execute_command(&cmd, &mut self.state),
        )
        .await
        .expect("public dispatcher must terminate")
    }

    fn provider_calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.private.path().join("provider-calls"))
            .unwrap()
            .lines()
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    fn assert_trace(&self, fills: usize, clicks: usize) {
        let t = self.trace.lock().unwrap();
        assert!(t.violations.is_empty(), "{:?}", t.violations);
        assert_eq!(
            t.generic_fill_dispatches, 0,
            "generic fill must refuse before page dispatch"
        );
        assert_eq!((t.fills, t.clicks), (fills, clicks));
        assert!(t.fills <= 1 && t.clicks <= 1);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn closed(reply: &Value, state: &str) {
    assert_eq!(reply["success"], true, "{reply}");
    let mut expected =
        json!({"kind":"work-readiness","state":state,"authentication":"not-established"});
    if matches!(state, "refused" | "unknown") {
        let abi: Value =
            serde_json::from_str(include_str!("../../../scripts/work-readiness-reasons.json"))
                .unwrap();
        assert!(
            abi["reasons"]
                .as_array()
                .unwrap()
                .contains(&reply["data"]["reason"]),
            "{reply}"
        );
        expected["reason"] = reply["data"]["reason"].clone();
    }
    if !reply["data"]["diagnostic"].is_null() {
        let diagnostic = &reply["data"]["diagnostic"];
        assert_eq!(diagnostic.as_object().unwrap().len(), 6);
        assert_eq!(diagnostic["policySha256"], "6986d57dc8d0fdf906cc7709232f68bada8efdd4601eab0b33fc42fb84a183f8");
        assert!(["initial", "fill-identifier", "click-next", "post-next"].contains(&diagnostic["phase"].as_str().unwrap()));
        assert!(["identifier", "password", "challenge", "mixed", "ambiguous", "none"].contains(&diagnostic["controlClass"].as_str().unwrap()));
        assert!(["missing", "own", "foreign", "conflicting"].contains(&diagnostic["identity"].as_str().unwrap()));
        assert!(diagnostic["markerPresent"].is_boolean() && diagnostic["identifierPresent"].is_boolean());
        expected["diagnostic"] = diagnostic.clone();
    }
    assert_eq!(reply["data"], expected, "{reply}");
    nonleak(reply);
}

fn nonleak(reply: &Value) {
    let text = reply.to_string();
    for marker in [
        PRIVATE_MARKER,
        "synthetic-private-query",
        "synthetic-private-title",
        "kenan@liminal.co",
        OWN_ORIGIN,
    ] {
        assert!(
            !text.contains(marker),
            "public metadata leaked fixture content: {reply}"
        );
    }
}

fn env_guard() -> crate::test_utils::EnvGuard<'static> {
    let names = [
        "AGENT_BROWSER_RESTORE",
        "AGENT_BROWSER_PLUGINS",
        "AGENT_BROWSER_POLICY",
        "AGENT_BROWSER_RESTORE_SAVE",
        "AGENT_BROWSER_WEBMCP",
        "AGENT_BROWSER_PROVIDER",
    ];
    let guard = crate::test_utils::EnvGuard::new(&names);
    for name in names {
        guard.remove(name);
    }
    guard
}

#[tokio::test]
async fn work_readiness_public_dispatch_closed_paths_do_not_resolve_provider() {
    let _env = env_guard();
    for (case, expected, fills, clicks) in [
        (Case::Password, "password-ready", 1, 1),
        (Case::Challenge, "challenge-ready", 1, 1),
        (Case::ExistingPassword, "password-ready", 0, 0),
        (Case::ExistingChallenge, "challenge-ready", 0, 0),
        (Case::ForeignAccount, "refused", 0, 0),
        (Case::DocumentBeforeFill, "refused", 1, 0),
        (Case::ActionBeforeClick, "unknown", 1, 1),
        (Case::ForeignReadiness, "unknown", 1, 1),
        (Case::Ambiguous, "unknown", 1, 1),
        (Case::MalformedReadiness, "unknown", 1, 1),
        (Case::ExtraReadiness, "unknown", 1, 1),
        (Case::ExceptionAfterClick, "unknown", 1, 1),
    ] {
        let mut f = Fixture::new(case).await;
        let command = f.request();
        let result = f.dispatch(command).await;
        closed(&result, expected);
        let reason = match case {
            Case::ForeignAccount | Case::ForeignReadiness => Some("account-mismatch"),
            Case::DocumentBeforeFill => Some("document-binding"),
            Case::ActionBeforeClick => Some("form-action"),
            Case::Ambiguous => Some("readiness-timeout"),
            Case::MalformedReadiness | Case::ExtraReadiness => Some("native-protocol"),
            Case::ExceptionAfterClick => Some("native-evaluation"),
            _ => None,
        };
        if let Some(reason) = reason {
            assert_eq!(result["data"]["reason"], reason, "{case:?}: {result}");
        }
        assert!(
            f.provider_calls().is_empty(),
            "identifier invoked provider: {case:?}"
        );
        f.assert_trace(fills, clicks);
    }
}

#[tokio::test]
async fn work_readiness_public_dispatch_binding_changes_never_advance() {
    let _env = env_guard();
    for (case, fills) in [
        (Case::ForeignOrigin, 0),
        (Case::UrlCredentials, 0),
        (Case::ForeignTarget, 0),
        (Case::ForeignFrame, 0),
        (Case::LoaderBeforeFill, 0),
        (Case::LoaderBeforeClick, 1),
    ] {
        let mut f = Fixture::new(case).await;
        let request = f.request();
        let result = f.dispatch(request).await;
        assert!(
            result["success"] == false
                || matches!(
                    result["data"]["state"].as_str(),
                    Some("refused" | "unknown")
                ),
            "{case:?}: {result}"
        );
        nonleak(&result);
        assert!(f.provider_calls().is_empty());
        f.assert_trace(fills, 0);
    }
}

#[tokio::test]
async fn work_readiness_public_dispatch_rejects_changed_or_missing_auth_tuple() {
    let _env = env_guard();
    for (key, value) in [
        ("credentialItem", json!("foreign-item")),
        ("field", json!("username")),
        ("selector", json!("#arbitrary")),
        ("target", json!("foreign-page")),
        ("frame", json!("child")),
        ("format", json!("mm/yy")),
        ("credentialProvider", json!("foreign-provider")),
        ("selector", Value::Null),
    ] {
        let mut f = Fixture::new(Case::Password).await;
        let mut request = f.request();
        request[key] = value;
        let result = f.dispatch(request).await;
        assert!(
            result["success"] == false || result["data"]["state"] == "refused",
            "{key}: {result}"
        );
        nonleak(&result);
        assert!(f.provider_calls().is_empty());
        f.assert_trace(0, 0);
    }
    for key in [
        "credentialProvider",
        "credentialItem",
        "field",
        "selector",
        "target",
        "frame",
        "timeout",
    ] {
        let mut f = Fixture::new(Case::Password).await;
        let mut request = f.request();
        request.as_object_mut().unwrap().remove(key);
        let result = f.dispatch(request).await;
        assert!(
            result["success"] == false || result["data"]["state"] == "refused",
            "missing {key}: {result}"
        );
        assert!(f.provider_calls().is_empty());
        f.assert_trace(0, 0);
    }
}

#[tokio::test]
async fn work_readiness_public_dispatch_capture_active_never_enters_policy() {
    let _env = env_guard();
    for capture in 0..5 {
        let mut f = Fixture::new(Case::Password).await;
        match capture {
            0 => f.state.recording_state.active = true,
            1 => f.state.tracing_state.active = true,
            2 => f.state.screencasting = true,
            3 => f.state.har_recording = true,
            4 => f.state.request_tracking = true,
            _ => unreachable!(),
        }
        let command = f.request();
        let result = f.dispatch(command).await;
        assert!(
            result["success"] == false || result["data"]["state"] == "refused",
            "{result}"
        );
        assert!(f.provider_calls().is_empty());
        assert_eq!(f.trace.lock().unwrap().factory, 0);
        f.assert_trace(0, 0);
    }
}

#[tokio::test]
async fn work_readiness_public_dispatch_sensitive_generic_fill_eval_still_refuse() {
    let _env = env_guard();
    let mut f = Fixture::new(Case::Password).await;
    for command in [
        json!({"id":"generic-fill","action":"fill","selector":"input[type=\"email\"]","value":"arbitrary-user"}),
        json!({"id":"generic-eval","action":"evaluate","script":"document.body.innerText"}),
    ] {
        let reply = f.dispatch(command).await;
        assert_eq!(
            f.trace.lock().unwrap().generic_fill_dispatches,
            0,
            "generic fill reached the page before refusal: {reply}"
        );
        assert_eq!(reply["success"], false, "{reply}");
        assert!(
            reply["error"]
                .as_str()
                .is_some_and(|message| message.starts_with("SENSITIVE_OUTPUT_UNSUPPORTED:")),
            "{reply}"
        );
        nonleak(&reply);
    }
    assert!(f.provider_calls().is_empty());
    f.assert_trace(0, 0);
    assert_eq!(f.trace.lock().unwrap().factory, 0);
}

#[tokio::test]
async fn work_readiness_public_dispatch_password_is_separate_one_lookup() {
    let _env = env_guard();
    let mut f = Fixture::new(Case::Password).await;
    let request = f.request();
    let reply = f.dispatch(request).await;
    closed(&reply, "password-ready");
    assert!(f.provider_calls().is_empty());
    assert_eq!(f.trace.lock().unwrap().password_submits, 0);
    let mut password = f.request();
    password["id"] = json!("separate-password-command");
    password["field"] = json!("password");
    password["selector"] = json!("input[type=\"password\"][name=\"Passwd\"]");
    let reply = f.dispatch(password).await;
    assert_eq!(reply["success"], true, "{reply}");
    assert_eq!(reply["data"]["submitted"], true, "{reply}");
    assert_eq!(reply["data"]["authentication"], "not-established");
    assert!(!reply.to_string().contains(PRIVATE_MARKER));
    let calls = f.provider_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["type"], "credential.field.resolve");
    assert_eq!(calls[0]["request"]["field"], "password");
    assert_eq!(calls[0]["request"]["itemRef"], ITEM);
    f.assert_trace(1, 1);
    assert_eq!(f.trace.lock().unwrap().password_submits, 1);
}

#[tokio::test]
async fn work_readiness_public_dispatch_timeout_cancel_and_lost_ack_do_not_replay() {
    let _env = env_guard();
    for case in [Case::LostAck, Case::PendingReadiness] {
        let mut f = Fixture::new(case).await;
        let mut command = f.request();
        command["timeout"] = json!(400);
        let reply = f.dispatch(command).await;
        assert!(
            reply["success"] == false || reply["data"]["state"] == "unknown",
            "{case:?}: {reply}"
        );
        nonleak(&reply);
        assert!(f.provider_calls().is_empty());
        f.assert_trace(1, 1);
    }
    let mut f = Fixture::new(Case::LostAck).await;
    let command = f.request();
    let notified = f.click_seen.clone();
    let cancelled = {
        let future = execute_command(&command, &mut f.state);
        tokio::pin!(future);
        tokio::select! {
            _ = notified.notified() => true,
            result = &mut future => panic!("lost ACK unexpectedly completed: {result}"),
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("public dispatcher never reached Next"),
        }
    };
    assert!(cancelled);
    assert!(f.provider_calls().is_empty());
    f.assert_trace(1, 1);
    // Drain already-written commands without invoking the original operation again.
    let reply = f
        .dispatch(json!({"id":"after-cancel","action":"session_info"}))
        .await;
    assert_eq!(reply["success"], true, "{reply}");
    f.assert_trace(1, 1);
}

#[tokio::test]
async fn work_readiness_public_dispatch_waits_on_one_pinned_policy_without_next_replay() {
    let _env = env_guard();
    for (case, expected, reason, factories, clicks) in [
        (Case::InitialWaiting, "password-ready", None, 1, 0),
        (
            Case::InitialWaitingForever,
            "refused",
            Some("password-control-unavailable"),
            1,
            0,
        ),
        (
            Case::InitialWaitingBindingChange,
            "unknown",
            Some("native-binding"),
            1,
            0,
        ),
        (Case::ReadinessWaiting, "password-ready", None, 2, 1),
        (
            Case::ReadinessWaitingForever,
            "unknown",
            Some("password-control-unavailable"),
            2,
            1,
        ),
        (
            Case::ReadinessWaitingBindingChange,
            "unknown",
            Some("native-binding"),
            2,
            1,
        ),
    ] {
        let mut f = Fixture::new(case).await;
        let request = f.request();
        let reply = f.dispatch(request).await;
        assert_eq!(reply["success"], true, "{case:?}: {reply}");
        assert_eq!(reply["data"]["state"], expected, "{case:?}: {reply}");
        assert_eq!(
            reply["data"]["reason"].as_str(),
            reason,
            "{case:?}: {reply}"
        );
        assert!(f.provider_calls().is_empty());
        nonleak(&reply);
        f.assert_trace(clicks, clicks);
        assert_eq!(
            f.trace.lock().unwrap().factory,
            factories,
            "pending must not rebind policy"
        );
    }
}
