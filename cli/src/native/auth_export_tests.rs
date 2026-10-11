#![cfg(target_os = "linux")]

use super::actions::{close_current_browser, execute_command, DaemonState};
use super::auth_export::{handle_auth_export, ExclusiveSink};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use tokio::time::{Duration, Instant};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn path_string(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

fn receipt_contract(receipt: &Value, path: &Path, expected: &str) {
    assert!(
        receipt.as_object().unwrap().len() == 2,
        "receipt must contain only path and byteCount"
    );
    assert!(receipt["path"] == path_string(path), "receipt path differs");
    assert!(
        receipt["byteCount"].as_u64() == Some(expected.len() as u64),
        "receipt byte count differs"
    );
    assert!(
        !receipt.to_string().contains(expected),
        "private value escaped in receipt"
    );
    assert!(
        fs::read(path).unwrap() == expected.as_bytes(),
        "private sink bytes differ"
    );
    let metadata = fs::metadata(path).unwrap();
    assert!(
        metadata.mode() & 0o777 == 0o600,
        "private sink mode differs"
    );
    assert!(
        metadata.uid() == unsafe { libc::geteuid() },
        "private sink owner differs"
    );
    assert!(
        metadata.nlink() == 1,
        "private sink has unexpected hard links"
    );
}

fn refused(result: Result<Value, String>, prefix: &str, marker: &str) {
    assert!(result.is_err(), "unsafe export unexpectedly succeeded");
    let error = result.unwrap_err();
    assert!(!error.contains(marker), "private value escaped in error");
    assert!(error.starts_with(prefix), "unexpected typed export refusal");
}

#[test]
fn private_export_sink_exact_bytes_exclusive_and_uncertain_reply() {
    let dir = private_dir();
    let path = dir.path().join("receipt-lost");
    let marker = format!(
        "synthetic-{}-λ\nsecond line\r\n",
        dir.path().file_name().unwrap().to_str().unwrap()
    );
    let receipt = ExclusiveSink::prepare(&path_string(&path))
        .unwrap()
        .publish(&marker)
        .unwrap();
    receipt_contract(&receipt, &path, &marker);
    let before = fs::metadata(&path).unwrap();
    drop(receipt);
    assert!(
        ExclusiveSink::prepare(&path_string(&path)).is_err(),
        "lost response must not permit another publication"
    );
    let after = fs::metadata(&path).unwrap();
    assert!(
        before.ino() == after.ino() && before.len() == after.len(),
        "uncertain retry replaced output"
    );
    assert!(
        fs::read(&path).unwrap() == marker.as_bytes(),
        "uncertain retry changed bytes"
    );
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 1,
        "sink leaked a staging file"
    );
}

#[test]
fn private_export_sink_drop_conflict_and_symlink_cleanup() {
    let dir = private_dir();
    let path = dir.path().join("abandoned");
    drop(ExclusiveSink::prepare(&path_string(&path)).unwrap());
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 0,
        "abandoned sink leaked a file"
    );
    let pending = ExclusiveSink::prepare(&path_string(&path)).unwrap();
    fs::write(&path, b"existing sentinel").unwrap();
    let marker = "synthetic-conflict-value";
    refused(pending.publish(marker), "auth_export_path_exists:", marker);
    assert!(
        fs::read(&path).unwrap() == b"existing sentinel",
        "publication clobbered competing file"
    );
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 1,
        "failed publication leaked staging file"
    );

    let outside = private_dir();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, b"outside sentinel").unwrap();
    let alias = dir.path().join("alias");
    symlink(outside.path(), &alias).unwrap();
    assert!(
        ExclusiveSink::prepare(&path_string(&alias.join("escaped"))).is_err(),
        "symlink ancestor accepted"
    );
    let destination_link = dir.path().join("destination-link");
    symlink(&sentinel, &destination_link).unwrap();
    assert!(
        ExclusiveSink::prepare(&path_string(&destination_link)).is_err(),
        "symlink destination accepted"
    );
    assert!(
        !outside.path().join("escaped").exists(),
        "sink escaped through symlink"
    );
    assert!(
        fs::read(&sentinel).unwrap() == b"outside sentinel",
        "sink overwrote symlink target"
    );
}

#[test]
fn private_export_sink_requires_private_own_uid_parent() {
    let dir = private_dir();
    for mode in [0o755, 0o750, 0o770] {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            ExclusiveSink::prepare(&path_string(&dir.path().join("denied"))).is_err(),
            "nonprivate parent accepted"
        );
    }
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        ExclusiveSink::prepare("relative-private-export").is_err(),
        "relative destination accepted"
    );
    assert!(
        ExclusiveSink::prepare(&format!("{}/../escaped", dir.path().display())).is_err(),
        "parent traversal accepted"
    );
    assert!(
        ExclusiveSink::prepare("/root/synthetic-private-export-test").is_err(),
        "foreign UID parent accepted"
    );
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 0,
        "refusal created output"
    );
}

#[tokio::test]
#[ignore = "requires installed Chrome; run serially"]
async fn private_export_actual_chrome_exact_field_and_refusals() {
    const CHILD_DIR: &str = "AGENT_BROWSER_SYNTHETIC_EXPORT_CHILD_DIR";
    let child_dir = match std::env::var_os(CHILD_DIR) {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let fixture_dir = private_dir();
            let marker = format!(
                "synthetic-{}-λ\nsecond line",
                fixture_dir.path().file_name().unwrap().to_str().unwrap()
            );
            let seed = fixture_dir.path().join("seed");
            fs::write(&seed, marker.as_bytes()).unwrap();
            fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "native::auth_export_tests::private_export_actual_chrome_exact_field_and_refusals", "--ignored", "--nocapture", "--test-threads=1"])
                .env(CHILD_DIR, fixture_dir.path())
                .output().unwrap();
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(&marker),
                "private value escaped into fixture stdout"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(&marker),
                "private value escaped into fixture stderr"
            );
            assert!(output.status.success(), "private Chrome fixture child failed; inspect static typed test failure without dumping private output");
            return;
        }
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _env =
        crate::test_utils::EnvGuard::new(&["AGENT_BROWSER_RESTORE", "AGENT_BROWSER_PLUGINS"]);
    let dir = private_dir();
    let marker = fs::read_to_string(child_dir.join("seed")).unwrap();
    let body = format!("<title>Synthetic export fixture</title><textarea id='private' readonly>{marker}</textarea><input id='input' readonly value='synthetic-input'><output id='leaf'>synthetic-leaf</output><input id='editable' value='not-exportable'><div id='container'><span>not-a-leaf</span></div><textarea class='duplicate' readonly>first</textarea><textarea class='duplicate' readonly>second</textarea><textarea id='hidden' hidden readonly>hidden</textarea>");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(
        "{body}<iframe id='child-frame' src='http://localhost:{}/child'></iframe>",
        addr.port()
    );
    let child_body = format!("<textarea id='child' readonly>{marker}</textarea>");
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = body.clone();
            let child_body = child_body.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                if let Ok(size) = stream.read(&mut request).await {
                    let body = if request[..size].starts_with(b"GET /child ") {
                        child_body
                    } else {
                        body
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
        }
    });
    let mut state = DaemonState::new();
    let launch = execute_command(
        &json!({"id":"launch", "action":"launch", "args":["--site-per-process"]}),
        &mut state,
    )
    .await;
    assert!(launch["success"] == true, "synthetic browser launch failed");
    let navigation = execute_command(&json!({"id":"navigate", "action":"navigate", "url":format!("http://{addr}/"), "waitUntil":"load"}), &mut state).await;
    assert!(
        navigation["success"] == true,
        "synthetic fixture navigation failed"
    );
    let target = state
        .browser
        .as_ref()
        .unwrap()
        .active_target_id()
        .unwrap()
        .to_owned();
    let path = dir.path().join("private-output");
    let request = json!({"action":"auth_export", "selector":"#private", "target":target, "frame":"main", "output":path_string(&path)});
    let receipt = handle_auth_export(&request, &mut state, deadline())
        .await
        .unwrap();
    receipt_contract(&receipt, &path, &marker);
    let getter = execute_command(
        &json!({"id":"get", "action":"inputvalue", "selector":"#private"}),
        &mut state,
    )
    .await;
    assert!(
        !getter.to_string().contains(&marker),
        "exported value escaped through ordinary getter"
    );
    let snapshot = execute_command(
        &json!({"id":"snapshot", "action":"snapshot", "interactive":true}),
        &mut state,
    )
    .await;
    assert!(
        !snapshot.to_string().contains(&marker),
        "exported value escaped through snapshot"
    );
    refused(
        handle_auth_export(&request, &mut state, deadline()).await,
        "auth_export_path_exists:",
        &marker,
    );
    for (selector, expected) in [
        ("#input", "synthetic-input"),
        ("#leaf", "synthetic-leaf"),
        ("#editable", "not-exportable"),
    ] {
        let output = dir.path().join(selector.trim_start_matches('#'));
        let mut command = request.clone();
        command["selector"] = json!(selector);
        command["output"] = json!(path_string(&output));
        let receipt = handle_auth_export(&command, &mut state, deadline())
            .await
            .unwrap();
        receipt_contract(&receipt, &output, expected);
    }
    for selector in [".duplicate", "#missing", "#hidden", "#container"] {
        let output = dir.path().join("refused");
        let mut command = request.clone();
        command["selector"] = json!(selector);
        command["output"] = json!(path_string(&output));
        refused(
            handle_auth_export(&command, &mut state, deadline()).await,
            "auth_export_field_unavailable:",
            &marker,
        );
        assert!(!output.exists(), "field refusal published output");
        assert!(
            fs::read_dir(dir.path()).unwrap().count() == 4,
            "field refusal leaked staging file"
        );
    }
    for (key, invalid) in [("target", "stale-target"), ("frame", "stale-frame")] {
        let mut command = request.clone();
        command[key] = json!(invalid);
        command["output"] = json!(path_string(&dir.path().join("binding-refused")));
        refused(
            handle_auth_export(&command, &mut state, deadline()).await,
            "auth_export_binding_changed:",
            &marker,
        );
    }
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 4,
        "binding refusal leaked staging file"
    );
    let selected = execute_command(
        &json!({"id":"child", "action":"frame", "selector":"#child-frame"}),
        &mut state,
    )
    .await;
    assert!(
        selected["success"] == true,
        "synthetic child selection failed"
    );
    let frame = state.active_frame_id.clone().unwrap();
    assert!(
        state.iframe_sessions.contains_key(&frame),
        "fixture did not create cross-process child frame"
    );
    let output = dir.path().join("child-output");
    let child_request = json!({"action":"auth_export", "selector":"#child", "target":target, "frame":frame, "output":path_string(&output)});
    let receipt = handle_auth_export(&child_request, &mut state, deadline())
        .await
        .unwrap();
    receipt_contract(&receipt, &output, &marker);
    let getter = execute_command(
        &json!({"id":"child-get", "action":"inputvalue", "selector":"#child"}),
        &mut state,
    )
    .await;
    assert!(
        !getter.to_string().contains(&marker),
        "child value escaped through ordinary getter"
    );
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 5,
        "child export leaked staging file"
    );
    close_current_browser(&mut state).await.unwrap();
    server.abort();
}

#[test]
fn private_export_sink_replaced_parent_refuses_publication() {
    let dir = private_dir();
    let parent = dir.path().join("parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let output = parent.join("export");
    let pending = ExclusiveSink::prepare(&path_string(&output)).unwrap();
    let displaced = dir.path().join("displaced");
    fs::rename(&parent, &displaced).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    refused(
        pending.publish("synthetic-parent-race"),
        "auth_export_path_invalid:",
        "synthetic-parent-race",
    );
    assert!(
        fs::read_dir(&parent).unwrap().count() == 0,
        "replaced parent received output"
    );
    assert!(
        fs::read_dir(&displaced).unwrap().count() == 0,
        "displaced parent received output"
    );
}

struct CdpFixture {
    state: DaemonState,
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for CdpFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl CdpFixture {
    async fn new(mode: &'static str, marker: String) -> Self {
        use futures_util::{SinkExt, StreamExt};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let counted_reads = reads.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut generation = 1;
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let command: Value = serde_json::from_str(&text).unwrap();
                let result = match command["method"].as_str().unwrap() {
                    "Target.getTargets" => {
                        json!({"targetInfos":[{"targetId":"synthetic-page", "type":"page", "url":"http://synthetic.test/", "title":"Synthetic", "attached":false}]})
                    }
                    "Target.attachToTarget" => json!({"sessionId":"synthetic-session"}),
                    "Target.getTargetInfo" => json!({"targetInfo":{"targetId":"synthetic-page"}}),
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"synthetic-frame", "loaderId":format!("document-{generation}"), "url":"http://synthetic.test/"}}})
                    }
                    "Runtime.evaluate" => {
                        json!({"result":{"objectId":"synthetic-field", "type":"object"}})
                    }
                    "DOM.describeNode" => json!({"node":{"backendNodeId":71}}),
                    "Runtime.callFunctionOn"
                        if command["params"]["functionDeclaration"]
                            .as_str()
                            .is_some_and(|s| s.starts_with("function(document")) =>
                    {
                        counted_reads.fetch_add(1, Ordering::SeqCst);
                        if mode == "change-after-read" {
                            generation += 1;
                        }
                        if mode == "exception" {
                            json!({"exceptionDetails":{"text":marker}})
                        } else {
                            json!({"result":{"value":{"status":if mode == "field-replaced" {"changed"} else {"read"}, "value":marker}}})
                        }
                    }
                    "Runtime.callFunctionOn" => {
                        if mode == "change-after-pin" {
                            generation += 1;
                        }
                        json!({"result":{"objectId":"synthetic-document", "type":"object"}})
                    }
                    _ => json!({}),
                };
                if ws
                    .send(Message::Text(
                        json!({"id":command["id"], "result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let browser = super::browser::BrowserManager::connect_cdp(&format!("ws://{address}"))
            .await
            .unwrap();
        let mut state = DaemonState::new();
        state.browser = Some(browser);
        Self {
            state,
            reads,
            server,
        }
    }
}

#[tokio::test]
async fn private_export_document_change_exception_and_deadline_never_publish_or_replay() {
    use std::sync::atomic::Ordering;
    for (mode, prefix, expected_reads) in [
        ("change-after-pin", "auth_export_binding_changed:", 0),
        ("change-after-read", "auth_export_binding_changed:", 1),
        ("field-replaced", "auth_export_binding_changed:", 1),
        ("exception", "auth_export_page_error:", 1),
        ("expired", "auth_export_timeout:", 0),
    ] {
        let dir = private_dir();
        let marker = format!(
            "synthetic-private-{}",
            dir.path().file_name().unwrap().to_str().unwrap()
        );
        let mut fixture = CdpFixture::new(mode, marker.clone()).await;
        let output = dir.path().join("refused");
        let request = json!({"action":"auth_export", "selector":"#synthetic", "target":"synthetic-page", "frame":"main", "output":path_string(&output)});
        let end = if mode == "expired" {
            Instant::now() - Duration::from_secs(1)
        } else {
            deadline()
        };
        refused(
            handle_auth_export(&request, &mut fixture.state, end).await,
            prefix,
            &marker,
        );
        assert!(
            fixture.reads.load(Ordering::SeqCst) == expected_reads,
            "private read repeated or happened after stale pin"
        );
        assert!(
            fs::read_dir(dir.path()).unwrap().count() == 0,
            "refused read left private output or staging file"
        );
        if mode == "change-after-read" || mode == "field-replaced" {
            let protected = &fixture.state.sensitive_observations["synthetic-session"];
            assert!(
                !protected.protect_text(&marker).contains(&marker),
                "refused private read was not retained for redaction"
            );
        }
        fixture
            .state
            .browser
            .as_ref()
            .unwrap()
            .client
            .settle_object_cleanup()
            .await
            .unwrap();
        assert!(
            fixture
                .state
                .browser
                .as_ref()
                .unwrap()
                .client
                .object_cleanup_len()
                .await
                == 0,
            "refused private read leaked renderer cleanup"
        );
    }
}

#[test]
fn private_export_write_failure_cleans_temporary_and_emits_no_value() {
    const CHILD_DIR: &str = "AGENT_BROWSER_SYNTHETIC_EXPORT_WRITE_FAILURE_DIR";
    match std::env::var_os(CHILD_DIR) {
        None => {
            let dir = private_dir();
            let marker = format!(
                "synthetic-write-failure-{}",
                dir.path().file_name().unwrap().to_str().unwrap()
            );
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "native::auth_export_tests::private_export_write_failure_cleans_temporary_and_emits_no_value", "--nocapture", "--test-threads=1"])
                .env(CHILD_DIR, dir.path()).output().unwrap();
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(&marker),
                "failed write leaked value into stdout"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(&marker),
                "failed write leaked value into stderr"
            );
            assert!(
                output.status.success(),
                "isolated failed-write fixture failed"
            );
            assert!(
                fs::read_dir(dir.path()).unwrap().count() == 0,
                "write failure left output or staging file"
            );
        }
        Some(path) => {
            let dir = std::path::PathBuf::from(path);
            let marker = format!(
                "synthetic-write-failure-{}",
                dir.file_name().unwrap().to_str().unwrap()
            );
            let sink = ExclusiveSink::prepare(&path_string(&dir.join("must-not-publish"))).unwrap();
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert!(
                unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) } != libc::SIG_ERR,
                "could not ignore file size signal"
            );
            assert!(
                unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) } == 0,
                "could not constrain synthetic write"
            );
            refused(sink.publish(&marker), "auth_export_write_failed:", &marker);
            assert!(
                fs::read_dir(dir).unwrap().count() == 0,
                "failed write leaked staging file"
            );
        }
    }
}
