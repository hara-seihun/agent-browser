use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::browser::BrowserManager;

pub(crate) struct SyntheticCdp {
    pub manager: BrowserManager,
    pub stalled: Arc<AtomicBool>,
    pub coverage_failures: Arc<AtomicUsize>,
    pub coverage_observations: Arc<AtomicUsize>,
    pub commands: mpsc::UnboundedReceiver<Value>,
    pub server: tokio::task::JoinHandle<()>,
}

impl SyntheticCdp {
    pub async fn connect() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stalled = Arc::new(AtomicBool::new(false));
        let stall_server = stalled.clone();
        let coverage_failures = Arc::new(AtomicUsize::new(0));
        let coverage_observations = Arc::new(AtomicUsize::new(0));
        let server_failures = coverage_failures.clone();
        let server_observations = coverage_observations.clone();
        let (tx, mut commands) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(text) => {
                        let command: Value = serde_json::from_str(&text).unwrap();
                        let _ = tx.send(command.clone());
                        if stall_server.load(Ordering::SeqCst) {
                            continue;
                        }
                        let result = match command["method"].as_str().unwrap() {
                            "Target.getTargets" => json!({"targetInfos": [{
                                "targetId": "synthetic-page", "type": "page", "url": "about:blank",
                                "title": "synthetic", "attached": false
                            }]}),
                            "Target.attachToTarget" => json!({"sessionId": "synthetic-session"}),
                            "Page.getFrameTree" => {
                                json!({"frameTree":{"frame":{"id":"synthetic-top"}}})
                            }
                            "DOM.getDocument" => {
                                server_observations.fetch_add(1, Ordering::SeqCst);
                                let missing = server_failures
                                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                        n.checked_sub(1)
                                    })
                                    .is_ok();
                                let children = if missing {
                                    vec![json!({"nodeName":"IFRAME","frameId":"pending-frame"})]
                                } else {
                                    vec![]
                                };
                                json!({"root":{"nodeName":"#document","children":children}})
                            }
                            "Runtime.evaluate" => json!({"result": {"type": "number", "value": 1}}),
                            _ => json!({}),
                        };
                        if ws
                            .send(Message::Text(
                                json!({"id": command["id"], "result": result}).to_string(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
        let manager = BrowserManager::connect_cdp(&format!("ws://{address}"))
            .await
            .unwrap();
        manager
            .client
            .send_command_no_params("Fixture.ready", None)
            .await
            .unwrap();
        while commands.try_recv().is_ok() {}
        Self {
            manager,
            stalled,
            coverage_failures,
            coverage_observations,
            commands,
            server,
        }
    }

    pub fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }
}
