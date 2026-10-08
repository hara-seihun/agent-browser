//! Disposable startup and isolation contract; synthetic auth only.
use super::actions::{execute_command, DaemonState};
use futures_util::FutureExt;
use serde_json::{json, Value};
use std::panic::AssertUnwindSafe;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn fixture() -> (String, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&bytes[..count]);
                let html = if request.starts_with("GET /sensitive ") {
                    "<input id='secret' type='password' value='synthetic-secret'><p>guarded</p>"
                        .to_string()
                } else {
                    "<script>window.startupAuthorized = sessionStorage.getItem('pi-remote-session:fixture') === 'synthetic-authorized';</script><p id='startup'></p><script>document.getElementById('startup').textContent=window.startupAuthorized?'authorized':'locked';</script>".to_string()
                };
                let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",html.len(),html);
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (origin, Server(task))
}

async fn command(state: &mut DaemonState, mut value: Value) -> Value {
    value["id"] = json!("tab-fixture");
    execute_command(&value, state).await
}
fn success(value: &Value) {
    assert_eq!(value["success"], true, "{value}");
}
fn error(value: &Value, code: &str) {
    assert_eq!(value["success"], false, "{value}");
    assert_eq!(value["code"], code, "{value}");
}
async fn launch(state: &mut DaemonState) {
    success(&command(state,json!({"action":"launch","engine":"chrome","headless":true,"args":["--no-sandbox","--disable-dev-shm-usage"]})).await);
}
async fn marker(state: &mut DaemonState, expected: &str) {
    let result = command(state, json!({"action":"gettext","selector":"#startup"})).await;
    success(&result);
    assert_eq!(result["data"]["text"], expected);
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires Chrome"]
async fn e2e_tab_state_startup_replacement_isolation_and_guards() {
    let vars = [
        "AGENT_BROWSER_CDP",
        "AGENT_BROWSER_AUTO_CONNECT",
        "AGENT_BROWSER_STATE",
        "AGENT_BROWSER_PROFILE",
        "AGENT_BROWSER_RESTORE",
        "AGENT_BROWSER_SESSION_NAME",
        "AGENT_BROWSER_ALLOWED_DOMAINS",
        "AGENT_BROWSER_EXECUTABLE_PATH",
        "AGENT_BROWSER_SOCKET_DIR",
        "AGENT_BROWSER_SESSION",
        "PI_KENAN_MEMORY_PERSON",
    ];
    let env = crate::test_utils::EnvGuard::new(&vars);
    for name in vars {
        env.remove(name);
    }
    let artifacts = tempfile::tempdir().unwrap();
    env.set(
        "AGENT_BROWSER_SOCKET_DIR",
        artifacts.path().to_str().unwrap(),
    );
    env.set("AGENT_BROWSER_SESSION", "tab-state-fixture");
    env.set("PI_KENAN_MEMORY_PERSON", "synthetic-person");
    let (origin, _server) = fixture().await;
    let (other_origin, _other_server) = fixture().await;
    let path = artifacts.path().join("capsule.json");
    let mut state = DaemonState::new();
    let result=AssertUnwindSafe(async {
        launch(&mut state).await;
        success(&command(&mut state,json!({"action":"navigate","url":origin})).await);
        marker(&mut state,"locked").await;
        error(&command(&mut state,json!({"action":"state_save_tab","path":path,"account":"fixture","origin":origin,"ttlSeconds":60})).await,"tab_state_empty");
        assert!(!path.exists());
        success(&command(&mut state,json!({"action":"evaluate","script":"sessionStorage.setItem('pi-remote-session:fixture','synthetic-authorized')"})).await);
        let saved=command(&mut state,json!({"action":"state_save_tab","path":path,"account":"fixture","origin":origin,"ttlSeconds":60})).await;
        success(&saved);
        assert!(!saved.to_string().contains("synthetic-authorized"));
        // Browser/worker replacement: no original renderer or daemon state survives.
        success(&command(&mut state,json!({"action":"close"})).await);
        state=DaemonState::new();
        launch(&mut state).await;
        let load=json!({"action":"state_load_tab","path":path,"account":"fixture","origin":origin});
        let mut bad=load.clone(); bad["account"]=json!("someone-else");
        error(&command(&mut state,bad).await,"tab_state_wrong_account");
        let mut bad=load.clone(); bad["origin"]=json!(other_origin);
        error(&command(&mut state,bad).await,"tab_state_wrong_origin");
        let mut bad=load.clone(); bad["path"]=json!(artifacts.path().join("absent"));
        error(&command(&mut state,bad).await,"tab_state_missing");
        env.set("PI_KENAN_MEMORY_PERSON","other-person");
        error(&command(&mut state,load.clone()).await,"tab_state_wrong_owner");
        env.set("PI_KENAN_MEMORY_PERSON","synthetic-person");
        success(&command(&mut state,load.clone()).await);
        error(&command(&mut state,load.clone()).await,"tab_state_already_armed");
        success(&command(&mut state,json!({"action":"navigate","url":origin})).await);
        marker(&mut state,"authorized").await;
        // Script gates exact scheme/host/port and top-level frame.
        success(&command(&mut state,json!({"action":"navigate","url":other_origin})).await);
        marker(&mut state,"locked").await;
        // A new target does not receive auth implicitly.
        success(&command(&mut state,json!({"action":"tab_new"})).await);
        success(&command(&mut state,json!({"action":"navigate","url":origin})).await);
        marker(&mut state,"locked").await;
        error(&command(&mut state,load.clone()).await,"tab_state_not_blank");
        success(&command(&mut state,json!({"action":"navigate","url":"about:blank"})).await);
        error(&command(&mut state,load.clone()).await,"tab_state_not_fresh");
        success(&command(&mut state,json!({"action":"tab_new"})).await);
        success(&command(&mut state,load.clone()).await);
        success(&command(&mut state,json!({"action":"navigate","url":origin})).await);
        marker(&mut state,"authorized").await;
        // An observed credential tab stays guarded, including after blank navigation.
        success(&command(&mut state,json!({"action":"navigate","url":format!("{origin}/sensitive")})).await);
        let snap=command(&mut state,json!({"action":"snapshot"})).await;
        success(&snap); assert!(!snap.to_string().contains("synthetic-secret"));
        for action in ["state_save_tab","state_load_tab","evaluate","screenshot","pdf"] {
            let out=artifacts.path().join(format!("refused-{action}"));
            let result=command(&mut state,json!({"action":action,"path":out,"account":"fixture","origin":origin,"ttlSeconds":60,"script":"btoa(document.querySelector('input').value)"})).await;
            assert_eq!(result["success"],false,"{result}");
            assert!(result["error"].as_str().unwrap().contains("SENSITIVE_OUTPUT_UNSUPPORTED"));
            assert!(!out.exists());
        }
        success(&command(&mut state,json!({"action":"navigate","url":"about:blank"})).await);
        let refusal=command(&mut state,load.clone()).await;
        assert_eq!(refusal["success"],false);
        assert!(refusal["error"].as_str().unwrap().contains("SENSITIVE_OUTPUT_UNSUPPORTED"));
        // Expiry refuses before installing on a fresh target.
        let mut capsule:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        capsule["expiresAt"]=json!(0);
        std::fs::write(&path,serde_json::to_vec(&capsule).unwrap()).unwrap();
        success(&command(&mut state,json!({"action":"tab_new"})).await);
        error(&command(&mut state,load).await,"tab_state_expired");
    }).catch_unwind().await;
    let closed = command(&mut state, json!({"action":"close"})).await;
    success(&closed);
    drop(state);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
