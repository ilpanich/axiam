//! R111W1-01: `claim_owed_erasure_records` reads the pending deletion requests
//! once, not once per user row.
//!
//! The statement that finds an anonymized account with no marker whose request
//! is still pending used to carry the request subquery inside the `WHERE` of a
//! scan of `user`; SurrealDB ran it again for every row, and `account_deletion`
//! (every completed and cancelled request stays) has no index on `status`. The
//! cost was users × requests, paid by every replica on every cleanup tick.

use axiam_db::repository::SurrealAccountDeletionRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// 20 000 users beside 2 000 deletion requests, 5 of them pending. Of the
/// pending ones' accounts exactly one is anonymized without a marker; another
/// is anonymized with a fresh marker (not owed), the rest are still active. A
/// completed request's account is anonymized without a marker too, but its
/// request is no longer pending, so it is not owed.
#[tokio::test]
async fn the_owed_erasure_claim_reads_the_pending_requests_once() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let tenant = Uuid::new_v4().to_string();
    let owed = Uuid::new_v4().to_string();
    let marked = Uuid::new_v4().to_string();
    let done = Uuid::new_v4().to_string();
    let epoch = Utc::now();

    db.query(
        "FOR $n IN 0..20000 { \
             CREATE type::record('user', string::concat('bulk-', <string> $n)) SET \
                 tenant_id = $tenant, username = string::concat('u', <string> $n), \
                 email = string::concat('u', <string> $n, '@example.test'), \
                 password_hash = 'x', status = 'Active'; \
         }; \
         CREATE type::record('user', $owed) SET tenant_id = $tenant, \
             username = 'erased-owed', email = 'a@example.test', password_hash = 'x', \
             status = 'Anonymized'; \
         CREATE type::record('user', $marked) SET tenant_id = $tenant, \
             username = 'erased-marked', email = 'b@example.test', password_hash = 'x', \
             status = 'Anonymized', erasure_audit_pending = $now; \
         CREATE type::record('user', $done) SET tenant_id = $tenant, \
             username = 'erased-done', email = 'c@example.test', password_hash = 'x', \
             status = 'Anonymized'; \
         FOR $n IN 0..1995 { \
             CREATE account_deletion SET tenant_id = $tenant, \
                 user_id = string::concat('bulk-', <string> $n), \
                 cancel_token_hash = string::concat('t', <string> $n), \
                 scheduled_purge_at = $now, status = 'completed'; \
         }; \
         FOR $u IN [$owed, $marked, 'bulk-19990', 'bulk-19991', 'bulk-19992'] { \
             CREATE account_deletion SET tenant_id = $tenant, user_id = $u, \
                 cancel_token_hash = string::concat('p', $u), \
                 scheduled_purge_at = $now, status = 'pending'; \
         }; \
         CREATE account_deletion SET tenant_id = $tenant, user_id = $done, \
             cancel_token_hash = 'done', scheduled_purge_at = $now, status = 'completed';",
    )
    .bind(("tenant", tenant.clone()))
    .bind(("owed", owed.clone()))
    .bind(("marked", marked))
    .bind(("done", done))
    .bind(("now", epoch))
    .await
    .unwrap()
    .check()
    .unwrap();

    let repo = SurrealAccountDeletionRepository::new(db.clone());
    let started = std::time::Instant::now();
    let claimed = repo
        .claim_owed_erasure_records(Utc::now(), Duration::minutes(10))
        .await
        .unwrap();
    let took = started.elapsed();

    eprintln!("claim took {took:?}");
    assert_eq!(
        claimed.len(),
        1,
        "only the unmarked, pending account is owed"
    );
    assert_eq!(claimed[0].user_id, Uuid::parse_str(&owed).unwrap());
    assert_eq!(claimed[0].pseudonym, "erased-owed");
    assert!(
        took < std::time::Duration::from_secs(15),
        "the claim must read the pending requests once, not once per user: took {took:?}"
    );
}
