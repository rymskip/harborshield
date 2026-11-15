use tempfile::TempDir;

use super::{ContainerIdentifiers, DB};

async fn open() -> (TempDir, DB) {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = DB::builder()
        .db_path(&dir.path().join("db.sqlite"))
        .build()
        .await
        .expect("open database");
    (dir, db)
}

fn container(id: &str, name: &str) -> ContainerIdentifiers {
    ContainerIdentifiers {
        id: id.to_owned(),
        name: name.to_owned(),
    }
}

#[tokio::test]
async fn upsert_inserts_then_renames() {
    let (_dir, db) = open().await;
    db.upsert_container(&container("a", "web"))
        .await
        .expect("insert");
    db.upsert_container(&container("a", "web-renamed"))
        .await
        .expect("rename");
    assert_eq!(
        db.list_containers().await.expect("list"),
        vec![container("a", "web-renamed")]
    );
}

#[tokio::test]
async fn upsert_reclaims_a_name_left_by_a_stale_row() {
    let (_dir, db) = open().await;
    db.upsert_container(&container("old", "web"))
        .await
        .expect("insert old");
    db.upsert_container(&container("new", "web"))
        .await
        .expect("insert new");
    assert_eq!(
        db.list_containers().await.expect("list"),
        vec![container("new", "web")]
    );
}

#[tokio::test]
async fn delete_of_a_missing_container_is_not_an_error() {
    let (_dir, db) = open().await;
    db.delete_container("absent").await.expect("delete");
    assert!(db.list_containers().await.expect("list").is_empty());
}

#[tokio::test]
async fn replace_keeps_exactly_the_given_set() {
    let (_dir, db) = open().await;
    db.upsert_container(&container("a", "stays"))
        .await
        .expect("insert a");
    db.upsert_container(&container("b", "goes"))
        .await
        .expect("insert b");
    db.replace_containers(&[container("a", "stays"), container("c", "arrives")])
        .await
        .expect("replace");
    assert_eq!(
        db.list_containers().await.expect("list"),
        vec![container("a", "stays"), container("c", "arrives")]
    );
}

#[tokio::test]
async fn delete_all_empties_the_table() {
    let (_dir, db) = open().await;
    db.upsert_container(&container("a", "one"))
        .await
        .expect("insert");
    db.delete_all_containers().await.expect("delete all");
    assert!(db.list_containers().await.expect("list").is_empty());
}

#[tokio::test]
async fn opening_an_unwritable_path_fails() {
    let result = DB::builder()
        .db_path(std::path::Path::new("/nonexistent-dir/db.sqlite"))
        .build()
        .await;
    assert!(result.is_err());
}
