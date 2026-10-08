#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn session_info(response: Value) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(directory.path().join("synthetic.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(
        directory.path().join("synthetic.pid"),
        std::process::id().to_string(),
    )
    .unwrap();
    std::fs::write(directory.path().join("synthetic.version"), "0.37.1").unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("synthetic session socket failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["action"], "session_info");
        writeln!(stream, "{response}").unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_agent-browser"))
        .args(["--json", "--session", "synthetic", "session", "info"])
        .env("AGENT_BROWSER_SOCKET_DIR", directory.path())
        .env_remove("AGENT_BROWSER_NAMESPACE")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "session inventory CLI did not finish"
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn session_info_preserves_typed_daemon_failure() {
    for code in ["daemon_busy", "metadata_unavailable"] {
        let response = session_info(
            json!({"success":false,"code":code,"error":"Synthetic operation unavailable"}),
        );
        assert_eq!(response["success"], false);
        assert_eq!(response["code"], code);
        assert_eq!(response["error"], "Synthetic operation unavailable");
        assert!(response.get("runtimeError").is_none());
        assert!(response.get("data").is_none_or(Value::is_null));
    }
}

#[test]
fn session_info_keeps_confirmed_runtime_metadata() {
    let response =
        session_info(json!({"success":true,"data":{"restoreKey":null,"browserLaunched":true}}));
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["active"], true);
    assert_eq!(response["data"]["runtime"]["browserLaunched"], true);
    assert!(response["data"]["runtime"]["restoreKey"].is_null());
}
