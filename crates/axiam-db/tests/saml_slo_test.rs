//! SAML single logout's two stores against the real datastore (T23.2.4, G-2,
//! schema v76): the participant record of D-37 and the logout run of D-38/D-39.
//!
//! What lives in the datastore rather than in plain Rust: the two unique
//! indexes of the participant record, the replay guard of a `LogoutRequest` `ID`
//! that must outlive the run's use, tenant isolation on every verb, the single
//! consume of an outbound request's `ID` on the X6 arbiter (raced on
//! `surrealkv`, the engine production runs — see `tests/common`), and the five
//! ways a row goes: its session, its SP, its tenant, its person and the sweeper.
//!
//! No assertion message in this file formats a `NameID`, a `SessionIndex` or a
//! request id.

mod common;

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_slo::{
    NewSamlLogoutRun, NewSamlSpSession, SamlLogoutInitiator, SamlLogoutPlan, SamlLogoutProgress,
    SamlSpSession,
};
use axiam_core::models::saml_sp::{
    AcsEndpoint, NameIdFormat, SamlBinding, SamlServiceProviderInput,
};
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SamlLogoutRunRepository, SamlServiceProviderRepository,
    SamlSpSessionRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSamlLogoutRunRepository,
    SurrealSamlServiceProviderRepository, SurrealSamlSpSessionRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn participants(db: &Surreal<Db>) -> SurrealSamlSpSessionRepository<Db> {
    SurrealSamlSpSessionRepository::new(db.clone())
}

fn runs(db: &Surreal<Db>) -> SurrealSamlLogoutRunRepository<Db> {
    SurrealSamlLogoutRunRepository::new(db.clone())
}

/// 32 CSPRNG-grade bytes, base64url without padding: what the endpoint mints.
fn index() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn digest() -> String {
    hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()))
}

fn new_row(tenant_id: Uuid, session_id: Uuid, user_id: Uuid, sp_id: Uuid) -> NewSamlSpSession {
    NewSamlSpSession {
        tenant_id,
        session_id,
        user_id,
        sp_id,
        sp_entity_id: format!("https://sp-{sp_id}.example.test/m"),
        name_id: format!("name-{}", Uuid::new_v4().simple()),
        name_id_format: PERSISTENT.into(),
        session_index: index(),
        expires_at: Utc::now() + Duration::hours(8),
    }
}

async fn count(db: &Surreal<Db>, query: &str, bind: (&'static str, String)) -> usize {
    #[derive(Debug, SurrealValue)]
    struct Count {
        n: usize,
    }
    let mut result = db.query(query).bind(bind).await.unwrap();
    let counted: Vec<Count> = result.take(0).unwrap();
    counted.first().map_or(0, |c| c.n)
}

async fn rows_of(db: &Surreal<Db>, table: &'static str, tenant: Uuid) -> usize {
    count(
        db,
        &format!("SELECT count() AS n FROM {table} WHERE tenant_id = $t GROUP ALL"),
        ("t", tenant.to_string()),
    )
    .await
}

// ---------------------------------------------------------------------------
// The participant record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_participant_row_round_trips_and_is_found_by_every_key() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, session, user, sp) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let input = new_row(tenant, session, user, sp);
    let row = repo.record(input.clone()).await.unwrap();
    assert_eq!(row.session_index, input.session_index);
    assert_eq!(row.name_id, input.name_id);
    assert_eq!(row.name_id_format, PERSISTENT);
    assert_eq!(
        (row.tenant_id, row.session_id, row.user_id, row.sp_id),
        (tenant, session, user, sp)
    );

    let by_index = repo
        .get_by_index(tenant, sp, &input.session_index)
        .await
        .unwrap()
        .expect("found by (tenant, sp, index)");
    assert_eq!(by_index.id, row.id);
    assert_eq!(repo.get(tenant, row.id).await.unwrap().unwrap().id, row.id);
    assert_eq!(
        repo.list_for_session(tenant, session).await.unwrap().len(),
        1
    );
    assert_eq!(
        repo.list_for_sp_name_id(tenant, sp, &input.name_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(repo.get_by_index(tenant, sp, "").await.unwrap().is_none());
    assert!(
        repo.list_for_sp_name_id(tenant, sp, "")
            .await
            .unwrap()
            .is_empty()
    );
}

/// D-37: a second sign-on to one SP in one session reuses the row — the
/// original index comes back and the asserted `NameID` is refreshed — and never
/// accumulates a second row (T-384).
#[tokio::test]
async fn a_second_sign_on_to_one_sp_in_one_session_keeps_the_first_index() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, session, user, sp) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let first = repo
        .record(new_row(tenant, session, user, sp))
        .await
        .unwrap();

    let mut again = new_row(tenant, session, user, sp);
    again.name_id = "refreshed-value".into();
    again.name_id_format = EMAIL.into();
    let second = repo.record(again.clone()).await.unwrap();

    assert_eq!(second.id, first.id, "the same row");
    assert_eq!(
        second.session_index, first.session_index,
        "the original index, not the candidate"
    );
    assert_ne!(again.session_index, second.session_index);
    assert_eq!(second.name_id, "refreshed-value");
    assert_eq!(second.name_id_format, EMAIL);
    assert_eq!(second.created_at, first.created_at);
    assert_eq!(
        repo.list_for_session(tenant, session).await.unwrap().len(),
        1
    );
}

/// D-37: the index is per SP — one session, two SPs, two rows, and each index
/// resolves for its own SP only.
#[tokio::test]
async fn an_index_resolves_for_its_own_sp_and_tenant_only() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, session, user) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (sp_a, sp_b) = (Uuid::new_v4(), Uuid::new_v4());
    let a = repo
        .record(new_row(tenant, session, user, sp_a))
        .await
        .unwrap();
    let b = repo
        .record(new_row(tenant, session, user, sp_b))
        .await
        .unwrap();
    assert_ne!(a.session_index, b.session_index);
    assert!(
        !a.session_index.contains(&session.to_string())
            && !b.session_index.contains(&session.to_string()),
        "no index is, or contains, the session id"
    );

    assert!(
        repo.get_by_index(tenant, sp_a, &b.session_index)
            .await
            .unwrap()
            .is_none(),
        "another SP's index is no key for this SP"
    );
    assert!(
        repo.get_by_index(Uuid::new_v4(), sp_a, &a.session_index)
            .await
            .unwrap()
            .is_none(),
        "another tenant's path finds nothing"
    );
    assert!(repo.get(Uuid::new_v4(), a.id).await.unwrap().is_none());
    assert!(
        repo.list_for_session(Uuid::new_v4(), session)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.list_for_session(tenant, session).await.unwrap().len(),
        2
    );
}

/// The datastore, not the application, refuses two rows with one index for one
/// SP, and an empty index.
#[tokio::test]
async fn the_two_unique_indexes_and_the_non_empty_assertion_hold_in_the_datastore() {
    let db = setup().await;
    let (tenant, user, sp) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let shared = index();
    let insert = |session: Uuid, sp: Uuid, idx: &str| {
        let q = format!(
            "CREATE type::record('saml_sp_session', $id) SET tenant_id = $t, session_id = $s, \
             user_id = $u, sp_id = $sp, sp_entity_id = 'e', name_id = 'n', \
             name_id_format = 'f', session_index = '{idx}', created_at = time::now(), \
             expires_at = time::now() + 1h, ended_at = NONE"
        );
        let db = db.clone();
        async move {
            db.query(q)
                .bind(("id", Uuid::new_v4().to_string()))
                .bind(("t", tenant.to_string()))
                .bind(("s", session.to_string()))
                .bind(("u", user.to_string()))
                .bind(("sp", sp.to_string()))
                .await
                .unwrap()
                .check()
        }
    };
    let session = Uuid::new_v4();
    insert(session, sp, &shared).await.unwrap();
    assert!(
        insert(session, sp, &index()).await.is_err(),
        "one row per (tenant, session, SP)"
    );
    assert!(
        insert(Uuid::new_v4(), sp, &shared).await.is_err(),
        "one row per (tenant, SP, index)"
    );
    insert(Uuid::new_v4(), Uuid::new_v4(), &shared)
        .await
        .expect("the same index at another SP is not a collision");
    assert!(
        insert(Uuid::new_v4(), Uuid::new_v4(), "").await.is_err(),
        "an empty index is refused by the datastore"
    );
}

/// Eight sign-ons racing to record one (session, SP) agree on one index and one
/// row, on the engine production runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_records_for_one_session_and_sp_agree_on_one_index() {
    const ROUNDS: usize = 20;
    const RACERS: usize = 8;
    let db = common::serialising_db().await;
    let repo = SurrealSamlSpSessionRepository::new(db.handle());
    let (tenant, user, sp) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    for round in 0..ROUNDS {
        let session = Uuid::new_v4();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let row = new_row(tenant, session, user, sp);
            set.spawn(async move {
                barrier.wait().await;
                repo.record(row).await
            });
        }
        let mut indexes = std::collections::BTreeSet::new();
        while let Some(joined) = set.join_next().await {
            let recorded = joined.unwrap().expect("every racer is told a row");
            indexes.insert(recorded.session_index);
        }
        assert_eq!(indexes.len(), 1, "one index for the pair (round {round})");
        assert_eq!(
            repo.list_for_session(tenant, session).await.unwrap().len(),
            1,
            "one row for the pair (round {round})"
        );
    }
}

#[tokio::test]
async fn list_for_sp_name_id_is_scoped_to_the_sp_and_the_name_id() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
    let (sp_a, sp_b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut one = new_row(tenant, Uuid::new_v4(), user, sp_a);
    one.name_id = "shared-name".into();
    let mut two = new_row(tenant, Uuid::new_v4(), user, sp_a);
    two.name_id = "shared-name".into();
    let mut elsewhere = new_row(tenant, Uuid::new_v4(), user, sp_b);
    elsewhere.name_id = "shared-name".into();
    let other_name = new_row(tenant, Uuid::new_v4(), user, sp_a);
    for row in [one, two, elsewhere, other_name] {
        repo.record(row).await.unwrap();
    }
    assert_eq!(
        repo.list_for_sp_name_id(tenant, sp_a, "shared-name")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        repo.list_for_sp_name_id(tenant, sp_b, "shared-name")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        repo.list_for_sp_name_id(Uuid::new_v4(), sp_a, "shared-name")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rows_are_deleted_by_session_and_by_user_and_only_in_their_tenant() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, other_tenant) = (Uuid::new_v4(), Uuid::new_v4());
    let (user, other_user) = (Uuid::new_v4(), Uuid::new_v4());
    let (s1, s2, s3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let sp = Uuid::new_v4();
    repo.record(new_row(tenant, s1, user, sp)).await.unwrap();
    repo.record(new_row(tenant, s1, user, Uuid::new_v4()))
        .await
        .unwrap();
    repo.record(new_row(tenant, s2, user, sp)).await.unwrap();
    repo.record(new_row(tenant, s3, other_user, sp))
        .await
        .unwrap();
    repo.record(new_row(other_tenant, s1, user, sp))
        .await
        .unwrap();

    assert_eq!(repo.delete_for_sessions(tenant, &[]).await.unwrap(), 0);
    assert_eq!(
        repo.delete_for_sessions(tenant, &[s1]).await.unwrap(),
        2,
        "both SPs' rows of session one"
    );
    assert_eq!(
        rows_of(&db, "saml_sp_session", other_tenant).await,
        1,
        "another tenant's row of the same session id stays"
    );
    assert_eq!(
        repo.delete_for_user(other_tenant, other_user)
            .await
            .unwrap(),
        0,
        "the person's rows are in their tenant"
    );
    assert_eq!(repo.delete_for_user(tenant, user).await.unwrap(), 1);
    assert_eq!(
        repo.list_for_session(tenant, s3).await.unwrap().len(),
        1,
        "another person's row stays"
    );
}

// ---------------------------------------------------------------------------
// The sweeper
// ---------------------------------------------------------------------------

async fn a_live_session(db: &Surreal<Db>, tenant_id: Uuid, user_id: Uuid) -> Uuid {
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::days(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
        })
        .await
        .unwrap()
        .id
}

/// D-37, T-384: swept once the session has expired or the session row is gone;
/// a row whose session is alive is not; a row a logout ended within one run
/// lifetime is not — the chain still needs it — and is after.
#[tokio::test]
async fn the_sweeper_removes_expired_rows_and_rows_of_sessions_that_are_gone() {
    let db = setup().await;
    let repo = participants(&db);
    let (tenant, user, sp) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

    let alive = a_live_session(&db, tenant, user).await;
    let kept = repo.record(new_row(tenant, alive, user, sp)).await.unwrap();

    let gone_session = Uuid::new_v4();
    repo.record(new_row(tenant, gone_session, user, sp))
        .await
        .unwrap();

    let expired_session = a_live_session(&db, tenant, user).await;
    let mut expired = new_row(tenant, expired_session, user, sp);
    expired.expires_at = Utc::now() - Duration::minutes(1);
    repo.record(expired).await.unwrap();

    // Gone, but a logout ended it just now: left alone for the chain.
    let ending = Uuid::new_v4();
    repo.record(new_row(tenant, ending, user, sp))
        .await
        .unwrap();
    repo.mark_ended(tenant, &[ending]).await.unwrap();

    // Gone, ended long ago: swept.
    let long_ago = Uuid::new_v4();
    repo.record(new_row(tenant, long_ago, user, sp))
        .await
        .unwrap();
    db.query(
        "UPDATE saml_sp_session SET ended_at = time::now() - 1h \
         WHERE session_id = $s",
    )
    .bind(("s", long_ago.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();

    assert_eq!(
        repo.cleanup_expired().await.unwrap(),
        3,
        "the gone, the expired and the long-ended"
    );
    let left: Vec<SamlSpSession> = {
        let mut all = repo.list_for_session(tenant, alive).await.unwrap();
        all.extend(repo.list_for_session(tenant, ending).await.unwrap());
        all
    };
    assert_eq!(
        left.len(),
        2,
        "the live session's row and the one in flight"
    );
    assert!(left.iter().any(|r| r.id == kept.id));
    assert_eq!(repo.cleanup_expired().await.unwrap(), 0, "idempotent");
}

// ---------------------------------------------------------------------------
// The logout run
// ---------------------------------------------------------------------------

fn request(tenant_id: Uuid, sp_id: Uuid, id: &str) -> NewSamlLogoutRun {
    NewSamlLogoutRun {
        tenant_id,
        initiator: SamlLogoutInitiator::ServiceProvider(sp_id),
        initiator_request_id: Some(id.to_owned()),
        initiator_relay_state: Some("relay".into()),
    }
}

/// D-38: a `LogoutRequest` `ID` is single-use per SP, for the row's whole life —
/// including after the chain finished.
#[tokio::test]
async fn a_request_id_is_single_use_per_sp_even_after_the_run_finished() {
    let db = setup().await;
    let repo = runs(&db);
    let (tenant, sp_a, sp_b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let run = repo.claim(request(tenant, sp_a, "_r1")).await.unwrap();
    assert_eq!(run.initiator_sp_id, Some(sp_a));
    assert_eq!(run.initiator_request_id.as_deref(), Some("_r1"));
    assert!(run.queue.is_empty() && run.user_id.is_none() && !run.partial);

    assert!(matches!(
        repo.claim(request(tenant, sp_a, "_r1")).await,
        Err(AxiamError::ReplayDetected)
    ));
    repo.finish(tenant, run.id, false, 0).await.unwrap();
    assert!(
        matches!(
            repo.claim(request(tenant, sp_a, "_r1")).await,
            Err(AxiamError::ReplayDetected)
        ),
        "a finished run still guards its request id"
    );
    repo.claim(request(tenant, sp_b, "_r1"))
        .await
        .expect("the same id from another SP is another request");
    repo.claim(request(Uuid::new_v4(), sp_a, "_r1"))
        .await
        .expect("and in another tenant");
    repo.claim(request(tenant, sp_a, "_r2")).await.unwrap();

    // An IdP-initiated run answers no request and replays nothing.
    for _ in 0..3 {
        repo.claim(NewSamlLogoutRun {
            tenant_id: tenant,
            initiator: SamlLogoutInitiator::Idp,
            initiator_request_id: None,
            initiator_relay_state: None,
        })
        .await
        .unwrap();
    }
    assert!(matches!(
        repo.claim(NewSamlLogoutRun {
            tenant_id: tenant,
            initiator: SamlLogoutInitiator::ServiceProvider(sp_a),
            initiator_request_id: None,
            initiator_relay_state: None,
        })
        .await,
        Err(AxiamError::Validation { .. })
    ));
}

#[tokio::test]
async fn a_run_is_planned_progressed_and_finished() {
    let db = setup().await;
    let repo = runs(&db);
    let (tenant, sp, user) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let run = repo.claim(request(tenant, sp, "_r1")).await.unwrap();

    let (row_a, row_b, session) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let planned = repo
        .plan(
            tenant,
            run.id,
            SamlLogoutPlan {
                user_id: user,
                queue: vec![row_a, row_b],
                session_ids: vec![session],
                partial: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(planned.user_id, Some(user));
    assert_eq!(planned.queue, vec![row_a, row_b]);
    assert_eq!(planned.session_ids, vec![session]);
    assert_eq!(planned.sessions_ended, 1);

    let sp_a = Uuid::new_v4();
    repo.progress(
        tenant,
        run.id,
        SamlLogoutProgress {
            queue: vec![row_b],
            outbound: Some((sp_a, digest())),
            partial: true,
            sps_told: 1,
        },
    )
    .await
    .unwrap();
    let moved = repo.get(tenant, run.id).await.unwrap().unwrap();
    assert_eq!(moved.queue, vec![row_b]);
    assert_eq!(moved.current_sp_id, Some(sp_a));
    assert!(moved.partial);
    assert_eq!(moved.sps_told, 1);
    assert!(
        repo.get(Uuid::new_v4(), run.id).await.unwrap().is_none(),
        "another tenant does not see the run"
    );

    repo.finish(tenant, run.id, true, 2).await.unwrap();
    let done = repo.get(tenant, run.id).await.unwrap().unwrap();
    assert!(done.queue.is_empty() && done.current_sp_id.is_none());
    assert_eq!((done.partial, done.sps_told), (true, 2));
}

/// T-383: the run holds the digest of the outbound `ID` and nothing it could be
/// rebuilt from, and no `NameID`.
#[tokio::test]
async fn the_run_holds_a_digest_of_the_outbound_id_and_no_name_id() {
    let db = setup().await;
    let repo = runs(&db);
    let (tenant, sp, user) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let run = repo.claim(request(tenant, sp, "_r1")).await.unwrap();
    let raw_id = format!("_{}", Uuid::new_v4().simple());
    let hash = hex::encode(Sha256::digest(raw_id.as_bytes()));
    repo.plan(
        tenant,
        run.id,
        SamlLogoutPlan {
            user_id: user,
            queue: vec![Uuid::new_v4()],
            session_ids: vec![Uuid::new_v4()],
            partial: false,
        },
    )
    .await
    .unwrap();
    repo.progress(
        tenant,
        run.id,
        SamlLogoutProgress {
            queue: Vec::new(),
            outbound: Some((Uuid::new_v4(), hash.clone())),
            partial: false,
            sps_told: 1,
        },
    )
    .await
    .unwrap();

    let mut result = db.query("SELECT * FROM saml_logout_run").await.unwrap();
    let rows: Vec<serde_json::Value> = result.take(0).unwrap();
    let text = serde_json::to_string(&rows).unwrap();
    assert!(text.contains(&hash), "the digest is what is stored");
    assert!(!text.contains(&raw_id), "the raw ID is not");
    assert!(!text.contains("name_id"), "no NameID column or value");

    // A hash that is not a SHA-256 hex digest is refused by the datastore.
    assert!(
        db.query("UPDATE saml_logout_run SET current_request_hash = 'short'")
            .await
            .unwrap()
            .check()
            .is_err()
    );
}

async fn running(db: &Surreal<Db>, tenant: Uuid, sp: Uuid, hash: &str) -> Uuid {
    let repo = runs(db);
    let run = repo
        .claim(request(
            tenant,
            sp,
            &format!("_{}", Uuid::new_v4().simple()),
        ))
        .await
        .unwrap();
    let target = Uuid::new_v4();
    repo.progress(
        tenant,
        run.id,
        SamlLogoutProgress {
            queue: vec![Uuid::new_v4()],
            outbound: Some((target, hash.to_owned())),
            partial: false,
            sps_told: 1,
        },
    )
    .await
    .unwrap();
    run.id
}

/// The response is consumed once, only from the SP the request went to, only in
/// its tenant, and not after it expired.
#[tokio::test]
async fn an_outbound_request_is_consumed_once_by_the_sp_it_went_to() {
    let db = setup().await;
    let repo = runs(&db);
    let (tenant, initiator) = (Uuid::new_v4(), Uuid::new_v4());
    let hash = digest();
    let run_id = running(&db, tenant, initiator, &hash).await;
    let target = repo
        .get(tenant, run_id)
        .await
        .unwrap()
        .unwrap()
        .current_sp_id
        .unwrap();

    assert!(
        repo.consume_response(tenant, &hash, Uuid::new_v4())
            .await
            .unwrap()
            .is_none(),
        "a foreign SP's answer consumes nothing"
    );
    assert!(
        repo.consume_response(Uuid::new_v4(), &hash, target)
            .await
            .unwrap()
            .is_none(),
        "another tenant's path consumes nothing"
    );
    assert!(
        repo.consume_response(tenant, "short", target)
            .await
            .unwrap()
            .is_none()
    );
    let won = repo
        .consume_response(tenant, &hash, target)
        .await
        .unwrap()
        .expect("the SP it went to consumes it");
    assert_eq!(won.id, run_id);
    assert_eq!(won.initiator_sp_id, Some(initiator));
    assert!(
        repo.consume_response(tenant, &hash, target)
            .await
            .unwrap()
            .is_none(),
        "a replayed InResponseTo is refused"
    );

    // Expired.
    let late_hash = digest();
    let late = running(&db, tenant, initiator, &late_hash).await;
    db.query("UPDATE saml_logout_run SET expires_at = time::now() - 1s WHERE meta::id(id) = $id")
        .bind(("id", late.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let late_target = repo
        .get(tenant, late)
        .await
        .unwrap()
        .unwrap()
        .current_sp_id
        .unwrap();
    assert!(
        repo.consume_response(tenant, &late_hash, late_target)
            .await
            .unwrap()
            .is_none()
    );
}

/// **Exactly one concurrent response wins**, on the engine production runs. A
/// failure is a regression in the arbiter, not flakiness: see
/// `permission_ticket_test::concurrent_redemptions_yield_exactly_one_winner`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_responses_yield_exactly_one_winner() {
    const ROUNDS: usize = 100;
    const RACERS: usize = 8;
    let db = common::serialising_db().await;
    let repo = SurrealSamlLogoutRunRepository::new(db.handle());
    let (tenant, initiator) = (Uuid::new_v4(), Uuid::new_v4());

    for round in 0..ROUNDS {
        let hash = digest();
        let run = repo
            .claim(request(tenant, initiator, &format!("_r{round}")))
            .await
            .unwrap();
        let target = Uuid::new_v4();
        repo.progress(
            tenant,
            run.id,
            SamlLogoutProgress {
                queue: Vec::new(),
                outbound: Some((target, hash.clone())),
                partial: false,
                sps_told: 1,
            },
        )
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let hash = hash.clone();
            set.spawn(async move {
                barrier.wait().await;
                repo.consume_response(tenant, &hash, target).await.unwrap()
            });
        }
        let mut winners = 0;
        while let Some(result) = set.join_next().await {
            if result.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one response may win (round {round})");
    }
}

#[tokio::test]
async fn expired_runs_are_swept_and_a_runs_user_rows_are_erased() {
    let db = setup().await;
    let repo = runs(&db);
    let (tenant, sp, user) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let old = repo.claim(request(tenant, sp, "_old")).await.unwrap();
    let fresh = repo.claim(request(tenant, sp, "_fresh")).await.unwrap();
    repo.plan(
        tenant,
        fresh.id,
        SamlLogoutPlan {
            user_id: user,
            queue: Vec::new(),
            session_ids: vec![Uuid::new_v4()],
            partial: false,
        },
    )
    .await
    .unwrap();
    db.query("UPDATE saml_logout_run SET expires_at = time::now() - 1s WHERE meta::id(id) = $id")
        .bind(("id", old.id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(repo.cleanup_expired().await.unwrap(), 1);
    assert!(repo.get(tenant, old.id).await.unwrap().is_none());
    assert!(repo.get(tenant, fresh.id).await.unwrap().is_some());

    assert_eq!(
        repo.delete_for_user(Uuid::new_v4(), user).await.unwrap(),
        0,
        "the person is in their tenant"
    );
    assert_eq!(repo.delete_for_user(tenant, user).await.unwrap(), 1);
    assert!(repo.get(tenant, fresh.id).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// The cascades
// ---------------------------------------------------------------------------

async fn tenant_in_org(db: &Surreal<Db>, slug: &str) -> (Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {slug}"),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();
    (org.id, tenant.id)
}

/// T-366, T-381: the tenant-delete transaction takes both tables with it, and
/// only its own rows.
#[tokio::test]
async fn deleting_a_tenant_removes_both_tables_rows_and_only_its_own() {
    let db = setup().await;
    let (_, doomed) = tenant_in_org(&db, "doomed").await;
    let (_, kept) = tenant_in_org(&db, "kept").await;
    for tenant in [doomed, kept] {
        participants(&db)
            .record(new_row(
                tenant,
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            ))
            .await
            .unwrap();
        runs(&db)
            .claim(request(tenant, Uuid::new_v4(), "_r"))
            .await
            .unwrap();
    }

    SurrealTenantRepository::new(db.clone())
        .delete(doomed)
        .await
        .unwrap();

    for table in ["saml_sp_session", "saml_logout_run"] {
        assert_eq!(rows_of(&db, table, doomed).await, 0, "{table}");
        assert_eq!(rows_of(&db, table, kept).await, 1, "{table}");
    }
}

fn minimal_sp(entity_id: &str) -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        enabled: true,
        display_name: "SP".into(),
        entity_id: entity_id.into(),
        acs_urls: vec![AcsEndpoint {
            url: "https://sp.example.test/acs".into(),
            binding: SamlBinding::HttpPost,
            index: 0,
            is_default: true,
        }],
        slo_url: None,
        slo_binding: None,
        name_id_format: NameIdFormat::Persistent,
        sign_responses: true,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
    }
}

#[tokio::test]
async fn deleting_an_sp_removes_its_participant_rows_and_only_its_own() {
    let db = setup().await;
    let sps = SurrealSamlServiceProviderRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let doomed = sps
        .create(tenant, minimal_sp("https://doomed.example.test/m"))
        .await
        .unwrap();
    let kept = sps
        .create(tenant, minimal_sp("https://kept.example.test/m"))
        .await
        .unwrap();
    let (session, user) = (Uuid::new_v4(), Uuid::new_v4());
    participants(&db)
        .record(new_row(tenant, session, user, doomed.id))
        .await
        .unwrap();
    participants(&db)
        .record(new_row(tenant, session, user, kept.id))
        .await
        .unwrap();

    sps.delete(tenant, doomed.id).await.unwrap();

    let left = participants(&db)
        .list_for_session(tenant, session)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].sp_id, kept.id, "the other SP's row stays");
}

/// T-381: both erasure paths — the administrator's `delete` and the Art. 17
/// `anonymize_user` — remove the rows naming the person, in their tenant only.
#[tokio::test]
async fn both_erasure_paths_remove_the_persons_rows() {
    let db = setup().await;
    let (_, tenant) = tenant_in_org(&db, "erasure").await;
    let users = SurrealUserRepository::new(db.clone());
    let mut people = Vec::new();
    for name in ["erased-by-delete", "erased-by-anonymize", "stays"] {
        let user = users
            .create(CreateUser {
                tenant_id: tenant,
                username: name.into(),
                email: format!("{name}@example.test"),
                password: axiam_test_support::test_password(),
                metadata: None,
            })
            .await
            .unwrap();
        people.push(user.id);
    }
    for user in &people {
        let session = Uuid::new_v4();
        participants(&db)
            .record(new_row(tenant, session, *user, Uuid::new_v4()))
            .await
            .unwrap();
        let run = runs(&db)
            .claim(request(
                tenant,
                Uuid::new_v4(),
                &format!("_{}", user.simple()),
            ))
            .await
            .unwrap();
        runs(&db)
            .plan(
                tenant,
                run.id,
                SamlLogoutPlan {
                    user_id: *user,
                    queue: Vec::new(),
                    session_ids: vec![session],
                    partial: false,
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(rows_of(&db, "saml_sp_session", tenant).await, 3);

    users.delete(tenant, people[0]).await.unwrap();
    assert_eq!(
        rows_of(&db, "saml_sp_session", tenant).await,
        2,
        "the administrator's delete took the person's participant row"
    );
    assert_eq!(rows_of(&db, "saml_logout_run", tenant).await, 2);

    users
        .anonymize_user(tenant, people[1], &digest(), "DELETED_USER_test")
        .await
        .unwrap();
    assert_eq!(
        rows_of(&db, "saml_sp_session", tenant).await,
        1,
        "the Art. 17 anonymisation took the other's"
    );
    assert_eq!(rows_of(&db, "saml_logout_run", tenant).await, 1);

    let remaining = participants(&db)
        .list_for_session(tenant, Uuid::new_v4())
        .await
        .unwrap();
    assert!(remaining.is_empty());
    let mut left = db
        .query("SELECT VALUE user_id FROM saml_sp_session")
        .await
        .unwrap();
    let left: Vec<String> = left.take(0).unwrap();
    assert_eq!(left, vec![people[2].to_string()]);
}
