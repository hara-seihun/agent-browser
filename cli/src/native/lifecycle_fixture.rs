use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{stream::FuturesUnordered, SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::browser::BrowserManager;

async fn delayed_reply(response: Value, delay: std::time::Duration) -> Value {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    response
}

#[derive(Default)]
pub(crate) struct FrameInventory {
    pub owners: Vec<String>,
    pub targets: Vec<(String, String)>,
    pub session_roots: HashMap<String, String>,
    pub documents: HashMap<String, Value>,
    pub frame_trees: HashMap<String, Value>,
    pub unreadable: HashSet<String>,
    pub hold_method: Option<String>,
    pub reply_delays: HashMap<String, std::time::Duration>,
    pub changed_documents: HashSet<String>,
    pub invalid_control: bool,
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
            stream.set_nodelay(true).unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut replies = FuturesUnordered::new();
            loop {
                let message = tokio::select! {
                    message = ws.next() => match message {
                        Some(Ok(message)) => message,
                        _ => break,
                    },
                    response = replies.next(), if !replies.is_empty() => {
                        let response: Value = response.unwrap();
                        if ws.send(Message::Text(response.to_string())).await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                match message {
                    Message::Text(text) => {
                        let command: Value = serde_json::from_str(&text).unwrap();
                        let _ = tx.send(command.clone());
                        if stall_server.load(Ordering::SeqCst) {
                            continue;
                        }
                        let method = command["method"].as_str().unwrap();
                        let (response, released, delay) = {
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
                                    inventory
                                        .frame_trees
                                        .get(&root_frame)
                                        .cloned()
                                        .unwrap_or_else(
                                            || json!({"frameTree":{"frame":{"id":root_frame}}}),
                                        )
                                }
                                "DOM.getDocument" => {
                                    let shallow = command["params"]["depth"] == 0;
                                    if !shallow {
                                        server_observations.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if shallow {
                                        let backend =
                                            if inventory.changed_documents.contains(&root_frame) {
                                                1001
                                            } else {
                                                1000
                                            };
                                        json!({"root":{"nodeName":"#document","backendNodeId":backend}})
                                    } else if let Some(document) =
                                        inventory.documents.get(&root_frame)
                                    {
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
                                "DOM.resolveNode" => {
                                    json!({"object":{"objectId":format!("{session}-{}", command["params"]["backendNodeId"])}})
                                }
                                "Runtime.callFunctionOn" => {
                                    if inventory.invalid_control {
                                        json!({"exceptionDetails":{"text":"synthetic control unavailable"}})
                                    } else {
                                        json!({"result":{"value":[format!("Synthetic-{}", command["params"]["objectId"].as_str().unwrap()), "", ""]}})
                                    }
                                }
                                "Runtime.evaluate" => {
                                    json!({"result": {"type": "number", "value": 1}})
                                }
                                _ => json!({}),
                            };
                            let mut result = result;
                            if method == "DOM.getDocument"
                                && result["root"]["backendNodeId"].is_null()
                            {
                                result["root"]["backendNodeId"] = json!(1000);
                            }
                            let delay = inventory
                                .reply_delays
                                .get(method)
                                .copied()
                                .unwrap_or(std::time::Duration::ZERO);
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
                                (None, released, delay)
                            } else {
                                (Some(response), released, delay)
                            }
                        };
                        for response in released.into_iter().chain(response) {
                            replies.push(delayed_reply(response, delay));
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
