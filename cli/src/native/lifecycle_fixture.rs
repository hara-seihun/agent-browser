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
    pub changed_frame_trees: HashMap<String, Value>,
    frame_tree_reads: HashMap<String, usize>,
    pub unreadable: HashSet<String>,
    pub hold_method: Option<String>,
    pub held_session_methods: HashSet<(String, String)>,
    pub hold_shallow_document: bool,
    pub reply_delays: HashMap<String, std::time::Duration>,
    pub document_reply_delays: HashMap<(String, i64), std::time::Duration>,
    pub changed_documents: HashSet<String>,
    pub replace_documents_once: HashSet<String>,
    document_backends: HashMap<String, i64>,
    pub invalid_control: bool,
    pub ax_generation_labels: bool,
    pub ax_new_owner: Option<String>,
    pub ax_trees: HashMap<String, Value>,
    pub unreadable_ax: HashSet<String>,
    pub cursor_frames: HashSet<String>,
    pub session_reply_delays: HashMap<(String, String), std::time::Duration>,
    pub objects: HashMap<(String, String), String>,
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
                                    let reads = inventory
                                        .frame_tree_reads
                                        .entry(root_frame.clone())
                                        .or_insert(0);
                                    *reads += 1;
                                    let changed = *reads > 1;
                                    if changed
                                        && inventory.changed_frame_trees.contains_key(&root_frame)
                                    {
                                        inventory.changed_frame_trees[&root_frame].clone()
                                    } else {
                                        inventory.frame_trees.get(&root_frame).cloned().unwrap_or_else(|| json!({"frameTree":{"frame":{"id":root_frame,"loaderId":format!("document-{root_frame}")}}}))
                                    }
                                }
                                "DOM.getDocument" => {
                                    let shallow = command["params"]["depth"] == 0;
                                    if !shallow {
                                        server_observations.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if shallow {
                                        let mut backend = inventory
                                            .document_backends
                                            .get(&root_frame)
                                            .copied()
                                            .unwrap_or(1000);
                                        if inventory.replace_documents_once.remove(&root_frame) {
                                            backend += 1;
                                            inventory
                                                .document_backends
                                                .insert(root_frame.clone(), backend);
                                            if let Some(document) =
                                                inventory.documents.get_mut(&root_frame)
                                            {
                                                document["root"]["backendNodeId"] = json!(backend);
                                            }
                                        }
                                        if inventory.changed_documents.contains(&root_frame) {
                                            backend += 1;
                                        }
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
                                    let object =
                                        format!("{session}-{}", command["params"]["backendNodeId"]);
                                    inventory.objects.insert(
                                        (session.into(), object.clone()),
                                        command["params"]["objectGroup"].as_str().unwrap().into(),
                                    );
                                    json!({"object":{"objectId":object}})
                                }
                                "Runtime.releaseObject" => {
                                    inventory.objects.remove(&(
                                        session.into(),
                                        command["params"]["objectId"].as_str().unwrap().into(),
                                    ));
                                    json!({})
                                }
                                "Runtime.releaseObjectGroup" => {
                                    let group = command["params"]["objectGroup"].as_str().unwrap();
                                    inventory.objects.retain(|(sid, _), owned_group| {
                                        sid != session || owned_group != group
                                    });
                                    json!({})
                                }
                                "Runtime.callFunctionOn" => {
                                    if inventory.invalid_control {
                                        json!({"exceptionDetails":{"text":"synthetic control unavailable"}})
                                    } else {
                                        json!({"result":{"value":[format!("Synthetic-{}", command["params"]["objectId"].as_str().unwrap()), "", ""]}})
                                    }
                                }
                                "Accessibility.getFullAXTree" => {
                                    let backend = inventory
                                        .document_backends
                                        .get(&root_frame)
                                        .copied()
                                        .unwrap_or(1000);
                                    if let Some(frame) = inventory.ax_new_owner.take() {
                                        inventory.owners.push(frame.clone());
                                        inventory
                                            .document_backends
                                            .insert(root_frame.clone(), backend + 1);
                                        if let Some(document) =
                                            inventory.documents.get_mut(&root_frame)
                                        {
                                            document["root"]["backendNodeId"] = json!(backend + 1);
                                            document["root"]["children"]
                                                .as_array_mut()
                                                .unwrap()
                                                .push(json!({"nodeName":"IFRAME","frameId":frame}));
                                        }
                                    }
                                    let frame = command["params"]["frameId"]
                                        .as_str()
                                        .unwrap_or(&root_frame);
                                    if let Some(tree) = inventory.ax_trees.get(frame) {
                                        tree.clone()
                                    } else if inventory.ax_generation_labels {
                                        json!({"nodes":[ {"nodeId":"heading","ignored":false,"role":{"type":"role","value":"heading"},"name":{"type":"computedString","value":format!("snapshot-{backend}")},"backendDOMNodeId":1100}]})
                                    } else {
                                        json!({"nodes":[]})
                                    }
                                }
                                "Runtime.evaluate"
                                    if command["params"]["expression"]
                                        .as_str()
                                        .is_some_and(|js| js.contains("var allElements")) =>
                                {
                                    let value = if inventory.cursor_frames.contains(&root_frame) {
                                        json!([{"selector":"html:nth-of-type(1) > body:nth-of-type(1) > div:nth-of-type(1)","text":format!("cursor-{root_frame}"),"tagName":"div","hasCursorPointer":true,"hasOnClick":false,"hasTabIndex":false,"isEditable":false}])
                                    } else {
                                        json!([])
                                    };
                                    json!({"result":{"type":"object","value":value}})
                                }
                                "DOM.querySelector" => json!({"nodeId":400}),
                                "DOM.describeNode" => {
                                    json!({"node":{"nodeId":400,"backendNodeId":400,"nodeName":"DIV"}})
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
                                result["root"]["backendNodeId"] = json!(inventory
                                    .document_backends
                                    .get(&root_frame)
                                    .copied()
                                    .unwrap_or(1000));
                            }
                            let document_delay = if method == "DOM.getDocument" {
                                command["params"]["depth"].as_i64().and_then(|depth| {
                                    inventory
                                        .document_reply_delays
                                        .get(&(session.to_owned(), depth))
                                })
                            } else {
                                None
                            };
                            let delay = document_delay
                                .or_else(|| {
                                    inventory
                                        .session_reply_delays
                                        .get(&(session.to_owned(), method.to_owned()))
                                })
                                .or_else(|| inventory.reply_delays.get(method))
                                .copied()
                                .unwrap_or(std::time::Duration::ZERO);
                            let response = if (method == "DOM.getDocument"
                                && inventory.unreadable.contains(&root_frame))
                                || (method == "Accessibility.getFullAXTree"
                                    && inventory.unreadable_ax.contains(
                                        command["params"]["frameId"]
                                            .as_str()
                                            .unwrap_or(&root_frame),
                                    )) {
                                json!({"id":command["id"],"error":{"code":-32000,"message":"fixture unreadable document"}})
                            } else {
                                json!({"id":command["id"],"result":result})
                            };
                            let released = if method == "Fixture.release" {
                                std::mem::take(&mut inventory.held)
                            } else {
                                vec![]
                            };
                            if inventory.hold_method.as_deref() == Some(method)
                                || inventory
                                    .held_session_methods
                                    .contains(&(session.to_owned(), method.to_owned()))
                                || (inventory.hold_shallow_document
                                    && method == "DOM.getDocument"
                                    && command["params"]["depth"] == 0)
                            {
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
