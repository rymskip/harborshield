use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tempfile::NamedTempFile;

use crate::database::{
    Addr, ContainerAlias, ContainerIdentifiers, DB, DbOpResult, EstContainer, WaitingContainerRule,
};

async fn setup_test_db() -> crate::Result<(NamedTempFile, DB)> {
    let temp_file = NamedTempFile::new().unwrap();
    let db = DB::builder().db_path(temp_file.path()).build().await?;
    Ok((temp_file, db))
}

#[tokio::test]
async fn test_init_database() {
    let (_temp, db) = setup_test_db().await.unwrap();
    // If we got here, database initialized successfully
    use crate::database::DbOp;
    let result = db.execute(&DbOp::ListContainers).await.unwrap();
    if let DbOpResult::Containers(containers) = result {
        assert!(containers.is_empty());
    } else {
        panic!("Expected Containers result");
    }
}

#[tokio::test]
async fn test_insert_and_get_container() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "test123".to_string(),
        name: "test-container".to_string(),
    };

    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let result = db.execute(&DbOp::GetContainer("test123")).await.unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, "test123");
        assert_eq!(retrieved.name, "test-container");
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_get_container_by_name() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "test456".to_string(),
        name: "named-container".to_string(),
    };

    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let result = db
        .execute(&DbOp::GetContainerByName("named-container"))
        .await
        .unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        let retrieved = retrieved.expect("container should be found by name");
        assert_eq!(retrieved.id, "test456");
        assert_eq!(retrieved.name, "named-container");
    } else {
        panic!("Expected ContainerIdentifiers result");
    }

    let missing = db
        .execute(&DbOp::GetContainerByName("does-not-exist"))
        .await
        .unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = missing {
        assert!(retrieved.is_none());
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_delete_container() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "test789".to_string(),
        name: "delete-me".to_string(),
    };

    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let result = db.execute(&DbOp::GetContainer("test789")).await.unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        assert!(retrieved.is_some());
    } else {
        panic!("Expected ContainerIdentifiers result");
    }

    db.execute(&DbOp::DeleteContainer("test789")).await.unwrap();

    let result = db.execute(&DbOp::GetContainer("test789")).await.unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        assert!(retrieved.is_none());
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_list_containers() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    for i in 0..3 {
        let container = ContainerIdentifiers {
            id: format!("id{}", i),
            name: format!("container{}", i),
        };
        db.execute(&DbOp::InsertContainer(&container))
            .await
            .unwrap();
    }

    let result = db.execute(&DbOp::ListContainers).await.unwrap();
    if let DbOpResult::Containers(containers) = result {
        assert_eq!(containers.len(), 3);
    } else {
        panic!("Expected Containers result");
    }
}

#[test]
fn test_ipv4_addr_conversion() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let container_id = "test".to_string();

    let addr = Addr::from_ip(ip, container_id.clone());
    assert_eq!(addr.addr, vec![192, 168, 1, 1]);
    assert_eq!(addr.container_id, container_id);

    let converted = addr.to_ip().unwrap();
    assert_eq!(converted, ip);
}

#[test]
fn test_ipv6_addr_conversion() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let container_id = "test".to_string();

    let addr = Addr::from_ip(ip, container_id.clone());
    assert_eq!(addr.addr.len(), 16);
    assert_eq!(addr.container_id, container_id);

    let converted = addr.to_ip().unwrap();
    assert_eq!(converted, ip);
}

#[tokio::test]
async fn test_insert_and_get_addrs() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "addr-test".to_string(),
        name: "addr-container".to_string(),
    };
    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let addr1 = Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        "addr-test".to_string(),
    );
    let addr2 = Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        "addr-test".to_string(),
    );

    db.execute(&DbOp::InsertAddr(&addr1)).await.unwrap();
    db.execute(&DbOp::InsertAddr(&addr2)).await.unwrap();

    let result = db
        .execute(&DbOp::GetAddrsByContainer("addr-test"))
        .await
        .unwrap();
    let addrs = match result {
        DbOpResult::Addrs(a) => a,
        _ => panic!("Expected Addrs result"),
    };
    assert_eq!(addrs.len(), 2);
    let mut ips: Vec<IpAddr> = addrs.iter().map(|a| a.to_ip().unwrap()).collect();
    ips.sort();
    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ]
    );
}

#[tokio::test]
async fn test_delete_addrs_by_container() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "addr-del-test".to_string(),
        name: "addr-del-container".to_string(),
    };
    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let addr = Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "addr-del-test".to_string(),
    );
    db.execute(&DbOp::InsertAddr(&addr)).await.unwrap();

    let pre = db
        .execute(&DbOp::GetAddrsByContainer("addr-del-test"))
        .await
        .unwrap();
    let pre_addrs = match pre {
        DbOpResult::Addrs(a) => a,
        _ => panic!("Expected Addrs result"),
    };
    assert_eq!(pre_addrs.len(), 1);

    db.execute(&DbOp::DeleteAddrsByContainer("addr-del-test"))
        .await
        .unwrap();

    let post = db
        .execute(&DbOp::GetAddrsByContainer("addr-del-test"))
        .await
        .unwrap();
    let post_addrs = match post {
        DbOpResult::Addrs(a) => a,
        _ => panic!("Expected Addrs result"),
    };
    assert!(post_addrs.is_empty());
}

#[tokio::test]
async fn test_container_aliases() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "alias-test".to_string(),
        name: "alias-container".to_string(),
    };
    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let alias = ContainerAlias {
        container_id: "alias-test".to_string(),
        container_alias: "my-alias".to_string(),
    };
    db.execute(&DbOp::InsertContainerAlias(&alias))
        .await
        .unwrap();

    let result = db
        .execute(&DbOp::GetContainerByAlias("my-alias"))
        .await
        .unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        let retrieved = retrieved.expect("alias should resolve to container");
        assert_eq!(retrieved.id, "alias-test");
    } else {
        panic!("Expected ContainerIdentifiers result");
    }

    db.execute(&DbOp::DeleteContainerAliases("alias-test"))
        .await
        .unwrap();

    let after = db
        .execute(&DbOp::GetContainerByAlias("my-alias"))
        .await
        .unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = after {
        assert!(retrieved.is_none(), "alias should be removed after delete");
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_established_containers() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    // Create two containers
    for (id, name) in [("src-id", "src"), ("dst-id", "dst")] {
        db.execute(&DbOp::InsertContainer(&ContainerIdentifiers {
            id: id.to_string(),
            name: name.to_string(),
        }))
        .await
        .unwrap();
    }

    let est = EstContainer {
        src_container_id: "src-id".to_string(),
        dst_container_id: "dst-id".to_string(),
    };
    db.execute(&DbOp::InsertEstContainer(&est)).await.unwrap();

    // Verify it was inserted (we'd need to add a query method to test properly)
    // For now, just test deletion
    db.execute(&DbOp::DeleteEstContainers("src-id"))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_waiting_rules() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "rule-test".to_string(),
        name: "rule-container".to_string(),
    };
    db.execute(&DbOp::InsertContainer(&container))
        .await
        .unwrap();

    let rule = WaitingContainerRule {
        src_container_id: "rule-test".to_string(),
        dst_container_name: "target-container".to_string(),
        rule: vec![1, 2, 3, 4], // Mock rule data
    };
    db.execute(&DbOp::InsertWaitingRule(&rule)).await.unwrap();

    let result = db
        .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
        .await
        .unwrap();
    if let DbOpResult::WaitingRules(rules) = result {
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].src_container_id, "rule-test");
        assert_eq!(rules[0].rule, vec![1, 2, 3, 4]);
    } else {
        panic!("Expected WaitingRules result");
    }

    db.execute(&DbOp::DeleteWaitingRules("rule-test"))
        .await
        .unwrap();

    let result = db
        .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
        .await
        .unwrap();
    if let DbOpResult::WaitingRules(rules) = result {
        assert!(rules.is_empty());
    } else {
        panic!("Expected WaitingRules result");
    }
}

#[tokio::test]
async fn test_transaction_commit() {
    let (_temp, mut db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "tx-test".to_string(),
        name: "tx-container".to_string(),
    };

    // Use transaction builder
    db.transaction()
        .execute_ops(&[DbOp::InsertContainer(&container)])
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();

    // Verify the container was persisted
    let result = db.execute(&DbOp::GetContainer("tx-test")).await.unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        assert!(retrieved.is_some());
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_transaction_rollback() {
    let (_temp, mut db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    let container = ContainerIdentifiers {
        id: "rollback-test".to_string(),
        name: "rollback-container".to_string(),
    };

    // Use transaction builder and rollback
    let _ = db
        .transaction()
        .execute_ops(&[DbOp::InsertContainer(&container)])
        .await
        .unwrap()
        .rollback()
        .await;

    // Verify the container was not persisted
    let result = db
        .execute(&DbOp::GetContainer("rollback-test"))
        .await
        .unwrap();
    if let DbOpResult::ContainerIdentifiers(retrieved) = result {
        assert!(retrieved.is_none());
    } else {
        panic!("Expected ContainerIdentifiers result");
    }
}

#[tokio::test]
async fn test_foreign_key_constraint() {
    let (_temp, db) = setup_test_db().await.unwrap();
    use crate::database::DbOp;

    // Try to insert an addr for a non-existent container
    let addr = Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        "non-existent".to_string(),
    );

    let result = db.execute(&DbOp::InsertAddr(&addr)).await;
    assert!(result.is_err());
}
