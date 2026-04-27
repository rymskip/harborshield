use crate::database::{ContainerIdentifiers, DB, WaitingContainerRule};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_delete_waiting_rule() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(DB::builder().db_path(&db_path).build().await.unwrap());

    // Insert a source container
    db.insert_container(&ContainerIdentifiers {
        id: "source-container".to_string(),
        name: "source".to_string(),
    })
    .await
    .unwrap();

    // Record the (src, dst) waiting edge.
    db.insert_waiting_rule(&WaitingContainerRule {
        src_container_id: "source-container".to_string(),
        dst_container_name: "target-container".to_string(),
    })
    .await
    .unwrap();

    let waiting_rules = db
        .get_waiting_rules_for_container("target-container")
        .await
        .unwrap();
    assert_eq!(waiting_rules.len(), 1);
    assert_eq!(waiting_rules[0].src_container_id, "source-container");
    assert_eq!(waiting_rules[0].dst_container_name, "target-container");

    db.delete_waiting_rule("source-container", "target-container")
        .await
        .unwrap();

    let waiting_rules = db
        .get_waiting_rules_for_container("target-container")
        .await
        .unwrap();
    assert!(waiting_rules.is_empty());
}

#[tokio::test]
async fn test_get_container_by_alias() {
    use crate::database::ContainerAlias;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(DB::builder().db_path(&db_path).build().await.unwrap());

    db.insert_container(&ContainerIdentifiers {
        id: "container123".to_string(),
        name: "test-container".to_string(),
    })
    .await
    .unwrap();
    db.insert_container_alias(&ContainerAlias {
        container_id: "container123".to_string(),
        container_alias: "my-alias".to_string(),
    })
    .await
    .unwrap();

    let resolved = db
        .get_container_by_alias("my-alias")
        .await
        .unwrap()
        .expect("alias did not resolve");
    assert_eq!(resolved.id, "container123");
    assert_eq!(resolved.name, "test-container");
}
