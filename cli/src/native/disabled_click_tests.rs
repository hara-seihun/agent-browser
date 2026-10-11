//! Synthetic disabled-click admission. No live accounts or provider actions.
use super::actions::{close_current_browser, execute_command, DaemonState};
use serde_json::{json, Value};

#[tokio::test]
#[ignore = "requires installed Chrome; run serially"]
async fn disabled_click_native_routes_refuse_before_pointer_dispatch() {
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
                let _ = stream.read(&mut buffer).await;
                let body = r#"<title>Click fixture</title><button id='disabled' disabled>Create secret key</button><fieldset disabled><button id='fieldset'>Inherited disabled</button></fieldset><button id='aria' aria-disabled='true'>ARIA disabled</button><div aria-disabled='true'><button id='ancestor'>Ancestor disabled</button></div><button id='nested' disabled><span id='span'>Nested disabled</span></button><a id='link' href='#changed' aria-disabled='true'>Disabled link</a><button id='enabled'>Enabled</button><button id='false' aria-disabled='false'>ARIA false</button><script>
                window.pointerEvents=0; window.clicks=0;
                for(const name of ['pointermove','mousemove','pointerdown','mousedown','pointerup','mouseup']) document.addEventListener(name,()=>window.pointerEvents++,true);
                document.addEventListener('click',()=>window.clicks++,true);
                </script>"#;
                let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let mut state = DaemonState::new();
    assert_eq!(
        execute_command(&json!({"id":"launch","action":"launch"}), &mut state).await["success"],
        true
    );
    assert_eq!(execute_command(&json!({"id":"nav","action":"navigate","url":format!("http://127.0.0.1:{port}/"),"waitUntil":"load"}),&mut state).await["success"],true);
    for selector in [
        "#disabled",
        "#fieldset",
        "#aria",
        "#ancestor",
        "#span",
        "#link",
    ] {
        let reply = execute_command(
            &json!({"id":"disabled","action":"click","selector":selector}),
            &mut state,
        )
        .await;
        refusal(&reply);
    }
    let snapshot = execute_command(
        &json!({"id":"snap","action":"snapshot","interactive":true}),
        &mut state,
    )
    .await;
    assert_eq!(snapshot["success"], true);
    let reference = state
        .ref_map
        .entries_sorted()
        .into_iter()
        .find(|(_, entry)| entry.name == "Create secret key")
        .map(|(key, _)| format!("@{key}"))
        .unwrap();
    refusal(
        &execute_command(
            &json!({"id":"ref","action":"click","selector":reference}),
            &mut state,
        )
        .await,
    );
    refusal(
        &execute_command(
            &json!({"id":"double","action":"dblclick","selector":"#disabled"}),
            &mut state,
        )
        .await,
    );
    refusal(&execute_command(&json!({"id":"semantic","action":"getbyrole","role":"button","name":"Create secret key","subaction":"click"}),&mut state).await);
    refusal(
        &execute_command(
            &json!({"id":"new-tab","action":"click","selector":"#link","newTab":true}),
            &mut state,
        )
        .await,
    );
    let mgr = state.browser.as_ref().unwrap();
    assert_eq!(
        mgr.evaluate(
            "window.pointerEvents===0 && window.clicks===0 && location.hash===''",
            None
        )
        .await
        .unwrap(),
        json!(true)
    );
    for selector in ["#enabled", "#false"] {
        assert_eq!(
            execute_command(
                &json!({"id":"click","action":"click","selector":selector}),
                &mut state
            )
            .await["success"],
            true
        );
    }
    assert_eq!(
        state
            .browser
            .as_ref()
            .unwrap()
            .evaluate("window.clicks===2 && window.pointerEvents>0", None)
            .await
            .unwrap(),
        json!(true)
    );
    close_current_browser(&mut state).await.unwrap();
    server.abort();
}
fn refusal(reply: &Value) {
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["code"], "click_disabled", "{reply}");
    assert_eq!(reply["data"]["effectDispatched"], false, "{reply}");
    assert!(reply["data"].get("clicked").is_none(), "{reply}");
}

#[tokio::test]
async fn disabled_click_guard_rejects_unknown_state_without_input_commands() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    for (status, expected) in [
        ("enabled", None),
        ("disabled", Some("click_disabled:")),
        ("changed", Some("click_target_changed:")),
        ("unknown", Some("click_state_unavailable:")),
        ("exception", Some("click_state_unavailable:")),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let cmd: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(cmd["method"], "Runtime.callFunctionOn");
                assert_eq!(cmd["sessionId"], "owned-session");
                let result = if status == "exception" {
                    json!({"exceptionDetails":{"text":"foreign-page-message"}})
                } else {
                    json!({"result":{"value":status}})
                };
                ws.send(Message::Text(
                    json!({"id":cmd["id"],"result":result}).to_string(),
                ))
                .await
                .unwrap();
            }
        });
        let client = super::cdp::client::CdpClient::connect(&format!("ws://{address}"))
            .await
            .unwrap();
        let outcome =
            super::interaction::require_click_enabled(&client, "owned-session", "owned-object")
                .await;
        match expected {
            None => assert!(outcome.is_ok()),
            Some(prefix) => {
                let err = outcome.unwrap_err();
                assert!(err.starts_with(prefix));
                assert!(!err.contains("foreign-page-message"));
            }
        }
        client.close().await;
        server.await.unwrap();
    }
}
