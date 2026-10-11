use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::browser::BrowserManager;

#[derive(Default)]
pub(crate) struct FrameInventory {
    pub owners: Vec<String>,
    pub targets: Vec<(String, String)>,
    pub session_roots: HashMap<String, String>,
    pub documents: HashMap<String, Value>,
    pub unreadable: HashSet<String>,
    pub hold_method: Option<String>,
    held: Vec<Value>,
}

pub(crate) struct SyntheticCdp {
    pub manager: BrowserManager,
    pub stalled: Arc<AtomicBool>,
    pub coverage_failures: Arc<AtomicUsize>,
    pub coverage_observations: Arc<AtomicUsize>,
    pub frame_inventory: Arc<Mutex<FrameInventory>>,
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
        let frame_inventory = Arc::new(Mutex::new(FrameInventory::default()));
        let inventory_server = frame_inventory.clone();
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
                        let method = command["method"].as_str().unwrap();
                        let (response, released) = {
                            let mut inventory = inventory_server.lock().unwrap();
                            let session = command["sessionId"].as_str().unwrap_or("");
                            let root_frame = inventory
                                .session_roots
                                .get(session)
                                .cloned()
                                .unwrap_or_else(|| "synthetic-top".into());
                            let result = match method {
                                "Target.getTargets" => {
                                    let mut targets = vec![json!({
                                        "targetId": "synthetic-page", "type": "page", "url": "about:blank",
                                        "title": "synthetic", "attached": false
                                    })];
                                    targets.extend(inventory.targets.iter().map(|(id, kind)| json!({
                                        "targetId": id, "type": kind, "url": "https://fixture.invalid/frame",
                                        "title": "fixture", "attached": true
                                    })));
                                    json!({"targetInfos": targets})
                                }
                                "Target.attachToTarget" => {
                                    let target = command["params"]["targetId"].as_str().unwrap();
                                    if target == "synthetic-page" {
                                        json!({"sessionId": "synthetic-session"})
                                    } else {
                                        let sid = format!("synthetic-frame-{target}");
                                        inventory.session_roots.insert(sid.clone(), target.into());
                                        json!({"sessionId": sid})
                                    }
                                }
                                "Page.getFrameTree" => {
                                    // Kernel can omit the OOPIF from the parent's tree
                                    // and omit parentId from the OOPIF's own root.
                                    json!({"frameTree":{"frame":{"id":root_frame}}})
                                }
                                "DOM.getDocument" => {
                                    server_observations.fetch_add(1, Ordering::SeqCst);
                                    if let Some(document) = inventory.documents.get(&root_frame) {
                                        document.clone()
                                    } else {
                                        let missing = server_failures
                                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                                n.checked_sub(1)
                                            })
                                            .is_ok();
                                        let mut children = if missing {
                                            vec![
                                                json!({"nodeName":"IFRAME","frameId":"pending-frame"}),
                                            ]
                                        } else {
                                            vec![]
                                        };
                                        if root_frame == "synthetic-top" {
                                            children.extend(inventory.owners.iter().map(|frame| json!({"nodeName":"IFRAME","frameId":frame})));
                                        }
                                        json!({"root":{"nodeName":"#document","children":children}})
                                    }
                                }
                                "Runtime.evaluate" => {
                                    json!({"result": {"type": "number", "value": 1}})
                                }
                                _ => json!({}),
                            };
                            let response = if method == "DOM.getDocument"
                                && inventory.unreadable.contains(&root_frame)
                            {
                                json!({"id":command["id"],"error":{"code":-32000,"message":"fixture unreadable document"}})
                            } else {
                                json!({"id":command["id"],"result":result})
                            };
                            let released = if method == "Fixture.release" {
                                std::mem::take(&mut inventory.held)
                            } else {
                                vec![]
                            };
                            if inventory.hold_method.as_deref() == Some(method) {
                                inventory.held.push(response);
                                (None, released)
                            } else {
                                (Some(response), released)
                            }
                        };
                        for response in released {
                            if ws.send(Message::Text(response.to_string())).await.is_err() {
                                return;
                            }
                        }
                        let Some(response) = response else {
                            continue;
                        };
                        if ws.send(Message::Text(response.to_string())).await.is_err() {
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
            frame_inventory,
            commands,
            server,
        }
    }

    pub fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }
}
