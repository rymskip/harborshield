use std::sync::Arc;
use std::thread;

use super::{Container, Tracker};

fn container(id: &str, name: &str) -> Container {
    Container::builder()
        .id(id.to_owned())
        .name(name.to_owned())
        .maybe_config(None)
        .build()
}

#[test]
fn upsert_then_get() {
    let tracker = Tracker::default();
    tracker.upsert(container("a", "web"));
    assert_eq!(
        tracker.get("a").map(|found| found.name),
        Some("web".to_owned())
    );
    assert!(tracker.get("missing").is_none());
}

#[test]
fn upsert_replaces_an_existing_entry() {
    let tracker = Tracker::default();
    tracker.upsert(container("a", "web"));
    tracker.upsert(container("a", "renamed"));
    let snapshot = tracker.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot.first().map(|found| found.name.as_str()),
        Some("renamed")
    );
}

#[test]
fn remove_returns_what_was_tracked() {
    let tracker = Tracker::default();
    tracker.upsert(container("a", "web"));
    assert_eq!(
        tracker.remove("a").map(|found| found.id),
        Some("a".to_owned())
    );
    assert!(tracker.remove("a").is_none());
}

#[test]
fn snapshot_is_ordered_by_id() {
    let tracker = Tracker::default();
    for (id, name) in [("c", "three"), ("a", "one"), ("b", "two")] {
        tracker.upsert(container(id, name));
    }
    let ids: Vec<String> = tracker
        .snapshot()
        .into_iter()
        .map(|found| found.id)
        .collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
}

#[test]
fn replace_all_drops_everything_not_given() {
    let tracker = Tracker::default();
    tracker.upsert(container("old", "gone"));
    tracker.replace_all(vec![container("new", "here")]);
    let ids: Vec<String> = tracker
        .snapshot()
        .into_iter()
        .map(|found| found.id)
        .collect();
    assert_eq!(ids, vec!["new"]);
}

#[test]
fn clear_empties_the_tracker() {
    let tracker = Tracker::default();
    tracker.upsert(container("a", "web"));
    tracker.clear();
    assert!(tracker.snapshot().is_empty());
}

#[test]
fn clones_share_state_across_threads() {
    let tracker = Arc::new(Tracker::default());
    let handles: Vec<_> = (0..8)
        .map(|index| {
            let tracker = Arc::clone(&tracker);
            thread::spawn(move || tracker.upsert(container(&format!("id{index}"), "worker")))
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker thread");
    }
    assert_eq!(tracker.snapshot().len(), 8);
}

#[test]
fn a_panic_while_holding_the_lock_does_not_wedge_the_tracker() {
    let tracker = Arc::new(Tracker::default());
    let poisoner = Arc::clone(&tracker);
    let outcome = thread::spawn(move || {
        let _guard = poisoner.lock();
        panic!("poison the lock");
    })
    .join();
    assert!(outcome.is_err());
    tracker.upsert(container("a", "web"));
    assert!(tracker.get("a").is_some());
}
