//! **X7.2 (plan §4.3)** — the authentication evidence snapshotted on an
//! authorization code survives storage, on every read path, and a code written
//! before schema v55 reads as carrying none.
//!
//! The snapshot exists because the session a code was minted from may be a
//! different row, or no row at all, by the time the code is redeemed (refresh
//! rotation deletes and recreates it). A snapshot that did not round-trip, or
//! that came back as *something* for an old code, would be the token endpoint
//! asserting an `auth_time` or an `amr` nobody ever observed. Both read paths
//! (`get_by_hash` and the transactional `consume`) decode through different
//! row structs, so both are asserted: a decode that worked for one and not the
//! other would be found by a relying party.

use axiam_core::models::oauth2_client::CreateAuthorizationCode;
use axiam_core::models::session::Amr;
use axiam_core::repository::AuthorizationCodeRepository;
use axiam_db::repository::SurrealAuthorizationCodeRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const CLIENT: &str = "oa_evidence";
const REDIRECT: &str = "https://rp.example.com/callback";

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn code(
    tenant_id: Uuid,
    code_hash: &str,
    auth_time: Option<chrono::DateTime<Utc>>,
    acr: Option<&str>,
    amr: Vec<Amr>,
) -> CreateAuthorizationCode {
    CreateAuthorizationCode {
        tenant_id,
        client_id: CLIENT.into(),
        user_id: Uuid::new_v4(),
        code_hash: code_hash.into(),
        redirect_uri: REDIRECT.into(),
        scopes: vec!["openid".into()],
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        session_id: Some(Uuid::new_v4()),
        auth_time,
        acr: acr.map(str::to_owned),
        amr,
        dpop_jkt: None,
        requested_userinfo_claims: Vec::new(),
        resource: None,
        expires_at: Utc::now() + Duration::minutes(10),
    }
}

#[tokio::test]
async fn a_codes_evidence_snapshot_round_trips_through_create_lookup_and_consume() {
    let db = setup().await;
    let repo = SurrealAuthorizationCodeRepository::new(db);
    let tenant_id = Uuid::new_v4();
    let authenticated_at = Utc::now() - Duration::hours(5);
    let amr = vec![Amr::Pwd, Amr::Otp, Amr::Mfa];

    let created = repo
        .create(code(
            tenant_id,
            "hash-round-trip",
            Some(authenticated_at),
            Some("urn:axiam:acr:mfa"),
            amr.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(
        created.auth_time.map(|t| t.timestamp()),
        Some(authenticated_at.timestamp())
    );
    assert_eq!(created.acr.as_deref(), Some("urn:axiam:acr:mfa"));
    assert_eq!(created.amr, amr);

    let looked_up = repo
        .get_by_hash(tenant_id, "hash-round-trip", CLIENT, REDIRECT)
        .await
        .unwrap();
    assert_eq!(
        looked_up.auth_time.map(|t| t.timestamp()),
        Some(authenticated_at.timestamp()),
        "the snapshot is the authentication instant, not the code's own created_at"
    );
    assert_eq!(looked_up.acr.as_deref(), Some("urn:axiam:acr:mfa"));
    assert_eq!(looked_up.amr, amr, "order and content survive storage");

    let consumed = repo
        .consume(tenant_id, "hash-round-trip", CLIENT, REDIRECT)
        .await
        .unwrap();
    assert_eq!(
        consumed.auth_time.map(|t| t.timestamp()),
        Some(authenticated_at.timestamp())
    );
    assert_eq!(consumed.acr.as_deref(), Some("urn:axiam:acr:mfa"));
    assert_eq!(consumed.amr, amr);
}

/// A code with no evidence — a grant with no browser session behind it, or
/// every client on the `ignore` lane for `acr` — stores and returns *nothing*,
/// not a default that could be read as evidence.
#[tokio::test]
async fn a_code_with_no_evidence_reads_back_with_none() {
    let db = setup().await;
    let repo = SurrealAuthorizationCodeRepository::new(db);
    let tenant_id = Uuid::new_v4();

    repo.create(code(tenant_id, "hash-empty", None, None, vec![]))
        .await
        .unwrap();
    let got = repo
        .get_by_hash(tenant_id, "hash-empty", CLIENT, REDIRECT)
        .await
        .unwrap();
    assert!(got.auth_time.is_none());
    assert!(got.acr.is_none());
    assert!(got.amr.is_empty());
}

/// A code row written before schema v55 has no `auth_time`, `acr` or `amr`
/// column at all (v55 does not backfill). It must stay readable — a code that
/// was valid before the upgrade must redeem after it — and must decode to the
/// strict meaning: no authentication instant to assert, no class, no methods.
#[tokio::test]
async fn a_pre_v55_code_row_decodes_to_no_evidence_on_both_read_paths() {
    let db = setup().await;
    let tenant_id = Uuid::new_v4();

    // Written the way the pre-X7.2 repository wrote it.
    db.query(
        "CREATE type::record('oauth2_auth_code', $id) SET \
         tenant_id = $tenant_id, \
         client_id = $client_id, \
         user_id = $user_id, \
         code_hash = $code_hash, \
         redirect_uri = $redirect_uri, \
         scopes = ['openid'], \
         code_challenge = NONE, \
         code_challenge_method = NONE, \
         nonce = NONE, \
         session_id = NONE, \
         expires_at = $expires_at, \
         used = false",
    )
    .bind(("id", Uuid::new_v4().to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .bind(("client_id", CLIENT))
    .bind(("user_id", Uuid::new_v4().to_string()))
    .bind(("code_hash", "hash-legacy"))
    .bind(("redirect_uri", REDIRECT))
    .bind(("expires_at", Utc::now() + Duration::minutes(10)))
    .await
    .unwrap()
    .check()
    .unwrap();

    let repo = SurrealAuthorizationCodeRepository::new(db);
    let looked_up = repo
        .get_by_hash(tenant_id, "hash-legacy", CLIENT, REDIRECT)
        .await
        .expect("an old code must stay readable");
    assert!(looked_up.auth_time.is_none());
    assert!(looked_up.acr.is_none());
    assert!(
        looked_up.amr.is_empty(),
        "an absent amr is evidence of nothing"
    );

    let consumed = repo
        .consume(tenant_id, "hash-legacy", CLIENT, REDIRECT)
        .await
        .expect("an old code must still redeem");
    assert!(consumed.auth_time.is_none());
    assert!(consumed.acr.is_none());
    assert!(consumed.amr.is_empty());
}
