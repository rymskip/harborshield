use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tempfile::NamedTempFile;

use crate::database::{
    Addr, ContainerAlias, ContainerIdentifiers, DB, EstContainer, WaitingContainerRule, queries,
};

async fn setup_test_db() -> crate::Result<(NamedTempFile, DB)> {
    let temp_file = NamedTempFile::new().unwrap();
    let db = DB::builder().db_path(temp_file.path()).build().await?;
    Ok((temp_file, db))
}

#[tokio::test]
async fn test_init_database() {
    let (_temp, db) = setup_test_db().await.unwrap();
    assert!(db.list_containers().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_insert_and_get_container() {
    let (_temp, db) = setup_test_db().await.unwrap();

    let container = ContainerIdentifiers {
        id: "test123".to_string(),
        name: "test-container".to_string(),
    };
    db.insert_container(&container).await.unwrap();

    let retrieved = db.get_container("test123").await.unwrap().unwrap();
    assert_eq!(retrieved.id, "test123");
    assert_eq!(retrieved.name, "test-container");
}

#[tokio::test]
async fn test_get_container_by_name() {
    let (_temp, db) = setup_test_db().await.unwrap();

    let container = ContainerIdentifiers {
        id: "test456".to_string(),
        name: "named-container".to_string(),
    };
    db.insert_container(&container).await.unwrap();

    let retrieved = db
        .get_container_by_name("named-container")
        .await
        .unwrap()
        .expect("container should be found by name");
    assert_eq!(retrieved.id, "test456");
    assert_eq!(retrieved.name, "named-container");

    assert!(
        db.get_container_by_name("does-not-exist")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_delete_container() {
    let (_temp, db) = setup_test_db().await.unwrap();

    let container = ContainerIdentifiers {
        id: "test789".to_string(),
        name: "delete-me".to_string(),
    };
    db.insert_container(&container).await.unwrap();
    assert!(db.get_container("test789").await.unwrap().is_some());

    db.delete_container("test789").await.unwrap();
    assert!(db.get_container("test789").await.unwrap().is_none());
}

#[tokio::test]
async fn test_list_containers() {
    let (_temp, db) = setup_test_db().await.unwrap();

    for i in 0..3 {
        db.insert_container(&ContainerIdentifiers {
            id: format!("id{}", i),
            name: format!("container{}", i),
        })
        .await
        .unwrap();
    }

    assert_eq!(db.list_containers().await.unwrap().len(), 3);
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

    db.insert_container(&ContainerIdentifiers {
        id: "addr-test".to_string(),
        name: "addr-container".to_string(),
    })
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
    db.insert_addr(&addr1).await.unwrap();
    db.insert_addr(&addr2).await.unwrap();

    let addrs = db.get_addrs_by_container("addr-test").await.unwrap();
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

    db.insert_container(&ContainerIdentifiers {
        id: "addr-del-test".to_string(),
        name: "addr-del-container".to_string(),
    })
    .await
    .unwrap();
    db.insert_addr(&Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        "addr-del-test".to_string(),
    ))
    .await
    .unwrap();

    assert_eq!(
        db.get_addrs_by_container("addr-del-test")
            .await
            .unwrap()
            .len(),
        1
    );
    db.delete_addrs_by_container("addr-del-test").await.unwrap();
    assert!(
        db.get_addrs_by_container("addr-del-test")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_container_aliases() {
    let (_temp, db) = setup_test_db().await.unwrap();

    db.insert_container(&ContainerIdentifiers {
        id: "alias-test".to_string(),
        name: "alias-container".to_string(),
    })
    .await
    .unwrap();
    db.insert_container_alias(&ContainerAlias {
        container_id: "alias-test".to_string(),
        container_alias: "my-alias".to_string(),
    })
    .await
    .unwrap();

    let retrieved = db
        .get_container_by_alias("my-alias")
        .await
        .unwrap()
        .expect("alias should resolve to container");
    assert_eq!(retrieved.id, "alias-test");

    db.delete_container_aliases("alias-test").await.unwrap();
    assert!(
        db.get_container_by_alias("my-alias")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_established_containers() {
    let (_temp, db) = setup_test_db().await.unwrap();

    for (id, name) in [("src-id", "src"), ("dst-id", "dst")] {
        db.insert_container(&ContainerIdentifiers {
            id: id.to_string(),
            name: name.to_string(),
        })
        .await
        .unwrap();
    }

    db.insert_est_container(&EstContainer {
        src_container_id: "src-id".to_string(),
        dst_container_id: "dst-id".to_string(),
    })
    .await
    .unwrap();
    // No Get* method exists for est_containers; deletion exercises the path.
    db.delete_est_containers("src-id").await.unwrap();
}

#[tokio::test]
async fn test_waiting_rules() {
    let (_temp, db) = setup_test_db().await.unwrap();

    db.insert_container(&ContainerIdentifiers {
        id: "rule-test".to_string(),
        name: "rule-container".to_string(),
    })
    .await
    .unwrap();

    db.insert_waiting_rule(&WaitingContainerRule {
        src_container_id: "rule-test".to_string(),
        dst_container_name: "target-container".to_string(),
        rule: vec![1, 2, 3, 4],
    })
    .await
    .unwrap();

    let rules = db
        .get_waiting_rules_for_container("target-container")
        .await
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].src_container_id, "rule-test");
    assert_eq!(rules[0].rule, vec![1, 2, 3, 4]);

    db.delete_waiting_rules("rule-test").await.unwrap();
    assert!(
        db.get_waiting_rules_for_container("target-container")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_transaction_commit() {
    let (_temp, db) = setup_test_db().await.unwrap();

    let container = ContainerIdentifiers {
        id: "tx-test".to_string(),
        name: "tx-container".to_string(),
    };
    db.with_transaction(|tx| {
        let c = container.clone();
        Box::pin(async move { queries::insert_container_tx(tx, &c).await })
    })
    .await
    .unwrap();

    assert!(db.get_container("tx-test").await.unwrap().is_some());
}

#[tokio::test]
async fn test_transaction_rollback() {
    let (_temp, db) = setup_test_db().await.unwrap();

    let container = ContainerIdentifiers {
        id: "rollback-test".to_string(),
        name: "rollback-container".to_string(),
    };

    let res: crate::Result<()> = db
        .with_transaction(|tx| {
            let c = container.clone();
            Box::pin(async move {
                queries::insert_container_tx(tx, &c).await?;
                // Force a rollback by returning Err without committing.
                Err(crate::Error::Database("intentional rollback".into()))
            })
        })
        .await;
    assert!(res.is_err());

    assert!(db.get_container("rollback-test").await.unwrap().is_none());
}

#[tokio::test]
async fn test_foreign_key_constraint() {
    let (_temp, db) = setup_test_db().await.unwrap();

    // Try to insert an addr for a non-existent container
    let addr = Addr::from_ip(
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        "non-existent".to_string(),
    );
    assert!(db.insert_addr(&addr).await.is_err());
}
