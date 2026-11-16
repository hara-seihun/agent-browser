use agent_browser_observation::*;
use std::collections::HashMap;
use serde_json::json;
    #[tokio::test]
    async fn delayed_initial_pair_preserves_coverage_association_and_changed_errors() {
        use super::lifecycle_fixture::SyntheticCdp;
        for case in [
            "coverage",
            "session",
            "document",
            "backend",
            "binding",
            "unreadable",
        ] {
            let mut fixture = SyntheticCdp::connect().await;
            let client = fixture.manager.client.clone();
            let session = fixture.manager.active_session_id().unwrap().to_owned();
            {
                let mut inventory = fixture.frame_inventory.lock().unwrap();
                inventory.reply_delays.insert(
                    "Page.getFrameTree".into(),
                    std::time::Duration::from_millis(30),
                );
                inventory.reply_delays.insert(
                    "DOM.getDocument".into(),
                    std::time::Duration::from_millis(10),
                );
                inventory.documents.insert("synthetic-top".into(), json!({"root":{
                    "nodeName":"#document", "frameId":"synthetic-top", "backendNodeId":1000,
                    "children":[{"nodeName":"INPUT","backendNodeId":11,"attributes":["autocomplete","cc-number"]}]
                }}));
                match case {
                    "coverage" => {
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["children"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"nodeName":"IFRAME","frameId":"missing-frame"}));
                    }
                    "session" => {
                        inventory
                            .session_roots
                            .insert("misbound-session".into(), "wrong-frame".into());
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["children"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({"nodeName":"IFRAME","frameId":"expected-frame"}));
                    }
                    "document" => {
                        inventory.documents.get_mut("synthetic-top").unwrap()["root"]["frameId"] =
                            json!("wrong-frame");
                    }
                    "backend" => {
                        inventory.changed_documents.insert("synthetic-top".into());
                    }
                    "binding" => {
                        inventory.changed_frame_trees.insert(
                            "synthetic-top".into(),
                            json!({"frameTree":{
                                "frame":{"id":"synthetic-top","loaderId":"next-document"}
                            }}),
                        );
                    }
                    "unreadable" => {
                        inventory.unreadable.insert("synthetic-top".into());
                    }
                    _ => unreachable!(),
                }
            }
            let frames = if case == "session" {
                HashMap::from([("expected-frame".into(), "misbound-session".into())])
            } else {
                HashMap::new()
            };
            let error = observe_inventory(&client, &session, &frames)
                .await
                .err()
                .unwrap();
            match (case, &error) {
                ("coverage", InventoryError::Coverage(gap)) => {
                    assert_eq!(gap.missing_owners, ["missing-frame"])
                }
                ("backend", InventoryError::Changed(DocumentChange::BackendIdentity)) => (),
                ("binding", InventoryError::Changed(DocumentChange::FrameBindings)) => (),
                ("session" | "document" | "unreadable", InventoryError::Unavailable(_)) => (),
                _ => panic!("unexpected {case} error: {error:?}"),
            }
            let message = error.into_message();
            assert!(!message.contains("Synthetic-"));
            if case == "session" {
                assert!(message.contains("frame session association changed"));
            }
            if case == "document" {
                assert!(message.contains("document frame association changed"));
            }
            if case == "unreadable" {
                assert!(message.contains("pierced DOM unavailable"));
            }
            client.settle_object_cleanup().await.unwrap();
            assert!(fixture.frame_inventory.lock().unwrap().objects.is_empty());
            assert_eq!(client.object_cleanup_len().await, 0);
            assert_eq!(client.pending_len().await, 0);
            while let Ok(command) = fixture.commands.try_recv() {
                let method = command["method"].as_str().unwrap();
                assert!(!method.starts_with("Input.") && method != "Page.navigate");
                if matches!(case, "coverage" | "document" | "unreadable") {
                    assert_ne!(method, "Runtime.callFunctionOn");
                }
                if matches!(method, "DOM.resolveNode" | "Runtime.callFunctionOn") {
                    assert_eq!(command["sessionId"], session);
                }
            }
            client.close().await;
            fixture.server.await.unwrap();
        }
    }

