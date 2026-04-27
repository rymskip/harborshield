use crate::database::{ContainerIdentifiers, DB, WaitingContainerRule};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_delete_waiting_rule() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");

    // Create database
    let db = Arc::new(Mutex::new(
        DB::builder()
            .db_path(&db_path)
            .build()
            .await
            .map_err(|e| e)
            .unwrap(),
    ));

    // Insert a source container
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertContainer(&ContainerIdentifiers {
                id: "source-container".to_string(),
                name: "source".to_string(),
            }))
            .await
            .unwrap();
    }

    // Production serializes waiting rule data via serde_json
    // (see handlers/crud.rs::add_waiting_rule). Mirror that here.
    let rule_data = serde_json::json!({
        "protocol": "tcp",
        "dst_ports": [80, 443],
        "log_prefix": "test-rule",
    });

    let serialized_rule = serde_json::to_vec(&rule_data).unwrap();

    // Insert waiting rule
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertWaitingRule(&WaitingContainerRule {
                src_container_id: "source-container".to_string(),
                dst_container_name: "target-container".to_string(),
                rule: serialized_rule.clone(),
            }))
            .await
            .unwrap();
    }

    // Verify waiting rule was stored
    {
        let db_lock = db.lock().await;
        use crate::database::{DbOp, DbOpResult};
        let result = db_lock
            .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
            .await
            .unwrap();

        if let DbOpResult::WaitingRules(waiting_rules) = result {
            assert_eq!(waiting_rules.len(), 1);
            assert_eq!(waiting_rules[0].src_container_id, "source-container");
            assert_eq!(waiting_rules[0].dst_container_name, "target-container");

            let parsed: serde_json::Value =
                serde_json::from_slice(&waiting_rules[0].rule).unwrap();
            assert_eq!(parsed["protocol"], "tcp");
            assert_eq!(parsed["dst_ports"], serde_json::json!([80, 443]));
            assert_eq!(parsed["log_prefix"], "test-rule");
        } else {
            panic!("Expected WaitingRules result");
        }
    }

    // Test deletion of waiting rule
    {
        let db_lock = db.lock().await;
        use crate::database::{DbOp, DbOpResult};
        db_lock
            .execute(&DbOp::DeleteWaitingRule {
                src_container_id: "source-container",
                dst_container_name: "target-container",
            })
            .await
            .unwrap();

        // Verify it was deleted
        let result = db_lock
            .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
            .await
            .unwrap();

        if let DbOpResult::WaitingRules(waiting_rules) = result {
            assert_eq!(waiting_rules.len(), 0);
        } else {
            panic!("Expected WaitingRules result");
        }
    }
}

/// Production stores waiting-rule data as serde_json bytes
/// (handlers/crud.rs::add_waiting_rule). Verify a round-trip through that format
/// preserves every field we care about.
#[test]
fn test_waiting_rule_serialization_roundtrip() {
    let original = serde_json::json!({
        "protocol": "udp",
        "dst_ports": [53, 123],
        "log_prefix": null,
    });

    let encoded = serde_json::to_vec(&original).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(original, decoded);
}

/// The waiting-rule blob is part of the `waiting_container_rules` PRIMARY KEY
/// (see migrations/20240101000001_initial_schema.sql), so its byte layout matters
/// for row identity. This test pins down two compatibility properties of the
/// serde_json format that production relies on:
///   1. Adding a new optional field is backward-compatible: an old reader that
///      doesn't know about the field can still parse the bytes.
///   2. Old bytes without the new field deserialize cleanly into a new schema
///      that uses #[serde(default)] for the added field.
#[test]
fn test_waiting_rule_serde_json_forward_compatibility() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct OldRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
    }
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct NewRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
        #[serde(default)]
        log_prefix: Option<String>,
    }

    // New writer -> old reader: extra field must be tolerated.
    let new_bytes = serde_json::to_vec(&NewRuleData {
        protocol: "tcp".into(),
        dst_ports: vec![80, 443],
        log_prefix: Some("hi".into()),
    })
    .unwrap();
    let as_old: OldRuleData = serde_json::from_slice(&new_bytes).unwrap();
    assert_eq!(as_old.protocol, "tcp");
    assert_eq!(as_old.dst_ports, vec![80, 443]);

    // Old writer -> new reader: missing optional field must default.
    let old_bytes = serde_json::to_vec(&serde_json::json!({
        "protocol": "tcp",
        "dst_ports": [22],
    }))
    .unwrap();
    let as_new: NewRuleData = serde_json::from_slice(&old_bytes).unwrap();
    assert_eq!(as_new.protocol, "tcp");
    assert_eq!(as_new.dst_ports, vec![22]);
    assert_eq!(as_new.log_prefix, None);
}

#[tokio::test]
async fn test_get_container_by_alias() {
    use crate::database::{ContainerAlias, DbOp, DbOpResult};

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(Mutex::new(
        DB::builder().db_path(&db_path).build().await.unwrap(),
    ));

    {
        let db_lock = db.lock().await;
        db_lock
            .execute(&DbOp::InsertContainer(&ContainerIdentifiers {
                id: "container123".to_string(),
                name: "test-container".to_string(),
            }))
            .await
            .unwrap();
        db_lock
            .execute(&DbOp::InsertContainerAlias(&ContainerAlias {
                container_id: "container123".to_string(),
                container_alias: "my-alias".to_string(),
            }))
            .await
            .unwrap();
    }

    let db_lock = db.lock().await;
    let result = db_lock
        .execute(&DbOp::GetContainerByAlias("my-alias"))
        .await
        .unwrap();
    match result {
        DbOpResult::ContainerIdentifiers(Some(c)) => {
            assert_eq!(c.id, "container123");
            assert_eq!(c.name, "test-container");
        }
        DbOpResult::ContainerIdentifiers(None) => panic!("alias did not resolve"),
        _ => panic!("Expected ContainerIdentifiers result"),
    }
}
