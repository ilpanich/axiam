//! The SSF poll/hold buffer against the real datastore (T23.5.3, G-5, D-48,
//! schema v77's `ssf_event_buffer`).
//!
//! What the datastore decides rather than plain Rust: one row per `jti`, the
//! bound of 1 000 per stream with the **oldest** dropped, the seven-day
//! expiry and its sweep, and that an acknowledgement names exactly the rows of
//! one stream in one tenant.
//!
//! No assertion or panic message formats an event's subject.

use axiam_core::models::ssf::{
    POLL_BUFFER_MAX_EVENTS, POLL_BUFFER_RETENTION_DAYS, SsfEventType, SsfPendingEvent,
};
use axiam_core::repository::SsfEventBufferRepository;
use axiam_db::repository::SurrealSsfEventBufferRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn repo() -> (Surreal<Db>, SurrealSsfEventBufferRepository<Db>) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let repo = SurrealSsfEventBufferRepository::new(db.clone());
    (db, repo)
}

fn event(label: &str) -> SsfPendingEvent {
    SsfPendingEvent {
        jti: Uuid::new_v4().simple().to_string(),
        iat: Utc::now().timestamp(),
        event_uri: SsfEventType::AccountEnabled.uri().to_owned(),
        event: serde_json::json!({ "label": label }),
        sub_id: serde_json::json!({
            "format": "iss_sub",
            "iss": "https://iam.example.test",
            "sub": Uuid::new_v4().to_string(),
        }),
        txn: None,
    }
}

fn label(event: &SsfPendingEvent) -> String {
    event.event["label"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn events_come_back_oldest_first_and_only_for_their_stream() {
    let (_db, repo) = repo().await;
    let tenant = Uuid::new_v4();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let now = Utc::now();
    for (i, name) in ["first", "second", "third"].iter().enumerate() {
        repo.push(
            tenant,
            a,
            &event(name),
            now + Duration::milliseconds(i as i64),
        )
        .await
        .unwrap();
    }
    repo.push(tenant, b, &event("other stream"), now)
        .await
        .unwrap();

    let held = repo.list_oldest(tenant, a, 100, now).await.unwrap();
    let labels: Vec<String> = held.iter().map(label).collect();
    assert_eq!(labels, ["first", "second", "third"]);
    assert_eq!(repo.list_oldest(tenant, a, 2, now).await.unwrap().len(), 2);
    assert_eq!(
        repo.list_oldest(tenant, b, 100, now).await.unwrap().len(),
        1
    );
    // The event round-trips exactly, subject member included.
    assert_eq!(held[0].sub_id["format"], "iss_sub");
    // Another tenant sees none of it, with the right stream id.
    assert!(
        repo.list_oldest(Uuid::new_v4(), a, 100, now)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_jti_is_buffered_once() {
    let (_db, repo) = repo().await;
    let (tenant, stream) = (Uuid::new_v4(), Uuid::new_v4());
    let e = event("once");
    repo.push(tenant, stream, &e, Utc::now()).await.unwrap();
    repo.push(tenant, stream, &e, Utc::now()).await.unwrap();
    assert_eq!(repo.count(tenant, stream).await.unwrap(), 1);
}

/// D-48: at most 1 000 per stream; the oldest are dropped to admit the newest.
#[tokio::test]
async fn the_buffer_is_bounded_and_drops_the_oldest() {
    let (_db, repo) = repo().await;
    let (tenant, stream) = (Uuid::new_v4(), Uuid::new_v4());
    let other = Uuid::new_v4();
    let start = Utc::now();
    repo.push(tenant, other, &event("untouched"), start)
        .await
        .unwrap();
    for i in 0..=POLL_BUFFER_MAX_EVENTS {
        repo.push(
            tenant,
            stream,
            &event(&format!("e{i}")),
            start + Duration::milliseconds(i as i64),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        repo.count(tenant, stream).await.unwrap() as usize,
        POLL_BUFFER_MAX_EVENTS
    );
    let held = repo
        .list_oldest(tenant, stream, POLL_BUFFER_MAX_EVENTS + 10, start)
        .await
        .unwrap();
    assert_eq!(held.len(), POLL_BUFFER_MAX_EVENTS);
    // e0 was the oldest and is gone; e1 is now the oldest; the newest is held.
    assert_eq!(label(&held[0]), "e1");
    assert_eq!(
        label(held.last().unwrap()),
        format!("e{POLL_BUFFER_MAX_EVENTS}")
    );
    // Another stream's buffer is not trimmed by this one's overflow.
    assert_eq!(repo.count(tenant, other).await.unwrap(), 1);
}

/// D-48: seven days at most; the sweep removes what has expired and nothing
/// else.
#[tokio::test]
async fn expired_events_are_not_served_and_the_sweep_removes_them() {
    let (_db, repo) = repo().await;
    let (tenant, stream) = (Uuid::new_v4(), Uuid::new_v4());
    let now = Utc::now();
    let long_ago = now - Duration::days(POLL_BUFFER_RETENTION_DAYS + 1);
    repo.push(tenant, stream, &event("stale"), long_ago)
        .await
        .unwrap();
    repo.push(tenant, stream, &event("fresh"), now)
        .await
        .unwrap();

    let served = repo.list_oldest(tenant, stream, 100, now).await.unwrap();
    assert_eq!(served.iter().map(label).collect::<Vec<_>>(), ["fresh"]);
    assert_eq!(repo.count(tenant, stream).await.unwrap(), 2);

    assert_eq!(repo.delete_expired(now).await.unwrap(), 1);
    assert_eq!(repo.count(tenant, stream).await.unwrap(), 1);
    assert_eq!(repo.delete_expired(now).await.unwrap(), 0);

    // The retention is exactly seven days from the push.
    let expires_in = repo
        .list_oldest(
            tenant,
            stream,
            1,
            now + Duration::days(POLL_BUFFER_RETENTION_DAYS) - Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(expires_in.len(), 1);
    assert!(
        repo.list_oldest(
            tenant,
            stream,
            1,
            now + Duration::days(POLL_BUFFER_RETENTION_DAYS)
        )
        .await
        .unwrap()
        .is_empty()
    );
}

/// An acknowledgement deletes exactly the named rows of that stream.
#[tokio::test]
async fn delete_by_jti_removes_only_the_named_rows_of_this_stream() {
    let (_db, repo) = repo().await;
    let tenant = Uuid::new_v4();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let now = Utc::now();
    let kept = event("kept");
    let acked = event("acked");
    repo.push(tenant, a, &kept, now).await.unwrap();
    repo.push(tenant, a, &acked, now + Duration::milliseconds(1))
        .await
        .unwrap();
    // The same jti held by another stream (the index is per stream) and by
    // another tenant's stream.
    repo.push(tenant, b, &acked, now).await.unwrap();
    let foreign = Uuid::new_v4();
    repo.push(foreign, a, &acked, now).await.unwrap();

    assert_eq!(
        repo.delete_by_jti(tenant, a, &[acked.jti.clone(), "no-such-jti".into()])
            .await
            .unwrap(),
        1
    );
    assert_eq!(repo.delete_by_jti(tenant, a, &[]).await.unwrap(), 0);
    let left = repo.list_oldest(tenant, a, 100, now).await.unwrap();
    assert_eq!(left.iter().map(label).collect::<Vec<_>>(), ["kept"]);
    assert_eq!(repo.count(tenant, b).await.unwrap(), 1);
    assert_eq!(repo.count(foreign, a).await.unwrap(), 1);
    // A second acknowledgement of the same jti removes nothing.
    assert_eq!(
        repo.delete_by_jti(tenant, a, std::slice::from_ref(&acked.jti))
            .await
            .unwrap(),
        0
    );
}

/// W4 F4 (the `x IN $ids` pitfall T23.2.4 met on a compound unique index): an
/// acknowledgement naming many rows of one stream deletes every one of them,
/// whatever the planner does with `(tenant_id, stream_id, jti)`.
#[tokio::test]
async fn an_acknowledgement_naming_many_rows_deletes_every_one() {
    let (_db, repo) = repo().await;
    let tenant = Uuid::new_v4();
    let stream = Uuid::new_v4();
    let now = Utc::now();
    let held: Vec<SsfPendingEvent> = (0..6).map(|i| event(&format!("e{i}"))).collect();
    for (i, e) in held.iter().enumerate() {
        repo.push(tenant, stream, e, now + Duration::milliseconds(i as i64))
            .await
            .unwrap();
    }
    let acked: Vec<String> = held[..5].iter().map(|e| e.jti.clone()).collect();
    assert_eq!(repo.delete_by_jti(tenant, stream, &acked).await.unwrap(), 5);
    let left = repo.list_oldest(tenant, stream, 100, now).await.unwrap();
    assert_eq!(left.iter().map(label).collect::<Vec<_>>(), ["e5"]);
}
