use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::browser::BrowserManager;

pub(crate) struct SyntheticCdp {
    pub manager: BrowserManager,
    pub stalled: Arc<AtomicBool>,
    pub commands: mpsc::UnboundedReceiver<Value>,
    pub server: tokio::task::JoinHandle<()>,
}

impl SyntheticCdp {
    pub async fn connect() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stalled = Arc::new(AtomicBool::new(false));
        let stall_server = stalled.clone();
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
            commands,
            server,
        }
    }

    pub fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }
}
