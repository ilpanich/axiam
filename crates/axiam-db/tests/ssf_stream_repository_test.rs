//! The SSF stream registry against the real datastore (T23.5.2, G-5, schema
//! v77).
//!
//! What lives in the datastore rather than in plain Rust: the round trip of
//! every column, the deployment-wide unique audience (D-47), tenant isolation
//! on every verb, the sealed push header (D-49), the atomic verification
//! interval, the delete cascade into the poll buffer and the tenant cascade.
//!
//! No credential literal appears here: the sealing key and every header value
//! are generated at run time, and no assertion message formats either.

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{SetOrgSettings, SetTenantOverride, system_defaults};
use axiam_core::models::ssf::{
    NewSsfStream, SecretChange, SsfDeliveryMethod, SsfEventType, SsfStatusActor, SsfStreamStatus,
    SsfStreamUpdate, SsfSubjectFormat,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, Pagination, SettingsRepository, SsfStreamRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealSsfStreamRepository,
    SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A sealing key generated once per test binary, never written down.
fn sealing() -> [u8; 32] {
    static SEALING: OnceLock<[u8; 32]> = OnceLock::new();
    *SEALING.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

/// A push credential value made at run time.
fn header_value() -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {}", Uuid::new_v4().simple()))
}

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>) -> SurrealSsfStreamRepository<Db> {
    SurrealSsfStreamRepository::new(db.clone(), Some(sealing()))
}

fn push_input(tenant_id: Uuid, audience: &str) -> NewSsfStream {
    NewSsfStream {
        tenant_id,
        receiver_client_id: "receiver-a".into(),
        audience: audience.into(),
        description: Some("Payroll receiver".into()),
        delivery_method: SsfDeliveryMethod::Push,
        endpoint_url: Some("https://rp.example.com/ssf/events".into()),
        authorization_header: Some(header_value()),
        events_allowed: vec![
            SsfEventType::AccountPurged,
            SsfEventType::SessionRevoked,
            SsfEventType::CredentialChange,
        ],
        events_requested: vec![SsfEventType::SessionRevoked, SsfEventType::AccountPurged],
        subject_format: SsfSubjectFormat::Email,
        status: SsfStreamStatus::Enabled,
        status_reason: None,
    }
}

fn poll_input(tenant_id: Uuid, audience: &str) -> NewSsfStream {
    NewSsfStream {
        tenant_id,
        receiver_client_id: "receiver-b".into(),
        audience: audience.into(),
        description: None,
        delivery_method: SsfDeliveryMethod::Poll,
        endpoint_url: None,
        authorization_header: None,
        events_allowed: SsfEventType::ALL.to_vec(),
        events_requested: SsfEventType::ALL.to_vec(),
        subject_format: SsfSubjectFormat::IssSub,
        status: SsfStreamStatus::Enabled,
        status_reason: None,
    }
}

#[tokio::test]
async fn create_round_trips_every_field_and_never_reads_the_header_back() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let input = push_input(tenant, "https://rp.example.com/aud-1");
    let created = repo.create(input.clone()).await.unwrap();

    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.receiver_client_id, "receiver-a");
    assert_eq!(created.audience, input.audience);
    assert_eq!(created.description.as_deref(), Some("Payroll receiver"));
    assert_eq!(created.delivery_method, SsfDeliveryMethod::Push);
    assert_eq!(created.endpoint_url, input.endpoint_url);
    assert!(created.authorization_header_set);
    // Stored in canonical order, deduplicated.
    assert_eq!(
        created.events_allowed,
        vec![
            SsfEventType::SessionRevoked,
            SsfEventType::CredentialChange,
            SsfEventType::AccountPurged
        ]
    );
    assert_eq!(
        created.events_requested,
        vec![SsfEventType::SessionRevoked, SsfEventType::AccountPurged]
    );
    assert_eq!(created.subject_format, SsfSubjectFormat::Email);
    assert_eq!(created.status, SsfStreamStatus::Enabled);
    assert_eq!(created.status_actor, SsfStatusActor::Admin);
    assert!(created.last_verification_at.is_none());

    let fetched = repo.get(tenant, created.id).await.unwrap();
    assert_eq!(fetched, created);

    // The single path to the plaintext gives it back.
    let header = input.authorization_header.clone().unwrap();
    let opened = repo
        .decrypt_authorization_header(tenant, created.id)
        .await
        .unwrap()
        .expect("a header is stored");
    assert!(
        opened.as_str() == header.as_str(),
        "the stored header opens"
    );

    // And the row holds ciphertext, never the value.
    let mut raw = db.query("SELECT * FROM ssf_stream").await.unwrap();
    let rows: Vec<serde_json::Value> = raw.take(0).unwrap_or_default();
    let text = serde_json::to_string(&rows).unwrap();
    assert!(
        !text.contains(header.as_str()),
        "the stored row must not contain the plaintext header"
    );
}

#[tokio::test]
async fn the_audience_is_unique_across_every_tenant() {
    let db = setup().await;
    let repo = repo(&db);
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    repo.create(poll_input(a, "https://shared.example/aud"))
        .await
        .unwrap();
    // Same tenant.
    match repo
        .create(poll_input(a, "https://shared.example/aud"))
        .await
    {
        Err(AxiamError::AlreadyExists { .. }) => {}
        other => panic!("expected AlreadyExists, got {:?}", other.map(|s| s.id)),
    }
    // Another tenant: still refused (D-47).
    match repo
        .create(poll_input(b, "https://shared.example/aud"))
        .await
    {
        Err(AxiamError::AlreadyExists { .. }) => {}
        other => panic!("expected AlreadyExists, got {:?}", other.map(|s| s.id)),
    }
    // An update onto another stream's audience is refused too.
    let other = repo
        .create(poll_input(b, "https://other.example/aud"))
        .await
        .unwrap();
    let mut update = SsfStreamUpdate::from_stream(&other);
    update.audience = "https://shared.example/aud".into();
    match repo.update(b, other.id, update).await {
        Err(AxiamError::AlreadyExists { .. }) => {}
        other => panic!("expected AlreadyExists, got {:?}", other.map(|s| s.id)),
    }
}

#[tokio::test]
async fn tenants_cannot_read_update_verify_open_or_delete_each_others_streams() {
    let db = setup().await;
    let repo = repo(&db);
    let owner = Uuid::new_v4();
    let intruder = Uuid::new_v4();
    let stream = repo
        .create(push_input(owner, "https://rp.example.com/aud-iso"))
        .await
        .unwrap();

    assert!(matches!(
        repo.get(intruder, stream.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.update(intruder, stream.id, SsfStreamUpdate::from_stream(&stream))
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.claim_verification(intruder, stream.id, Utc::now(), 60)
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.decrypt_authorization_header(intruder, stream.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.delete(intruder, stream.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(
        repo.list_for_receiver(intruder, "receiver-a")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.list_page(intruder, Pagination::default())
            .await
            .unwrap()
            .total,
        0
    );
    // Still there for its owner.
    assert_eq!(repo.get(owner, stream.id).await.unwrap().id, stream.id);
}

#[tokio::test]
async fn without_the_key_a_header_cannot_be_stored_and_everything_else_works() {
    let db = setup().await;
    let keyless = SurrealSsfStreamRepository::new(db.clone(), None);
    assert!(!keyless.has_encryption_key());
    let tenant = Uuid::new_v4();
    match keyless
        .create(push_input(tenant, "https://rp.example.com/aud-nokey"))
        .await
    {
        Err(AxiamError::ServiceUnavailable(message)) => {
            assert!(message.contains("AXIAM__AUTH__PKI_ENCRYPTION_KEY"));
        }
        other => panic!("expected ServiceUnavailable, got {:?}", other.map(|s| s.id)),
    }
    let mut no_header = push_input(tenant, "https://rp.example.com/aud-nokey");
    no_header.authorization_header = None;
    let created = keyless.create(no_header).await.unwrap();
    assert!(!created.authorization_header_set);
    assert_eq!(
        keyless
            .decrypt_authorization_header(tenant, created.id)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn an_update_keeps_replaces_or_clears_the_header() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let stream = repo
        .create(push_input(tenant, "https://rp.example.com/aud-upd"))
        .await
        .unwrap();
    let original = repo
        .decrypt_authorization_header(tenant, stream.id)
        .await
        .unwrap()
        .unwrap();

    // Keep: the description changes, the header does not.
    let mut keep = SsfStreamUpdate::from_stream(&stream);
    keep.description = Some("renamed".into());
    keep.status = SsfStreamStatus::Paused;
    keep.status_actor = SsfStatusActor::Receiver;
    keep.status_reason = Some("maintenance".into());
    let kept = repo.update(tenant, stream.id, keep).await.unwrap();
    assert_eq!(kept.description.as_deref(), Some("renamed"));
    assert_eq!(kept.status, SsfStreamStatus::Paused);
    assert_eq!(kept.status_actor, SsfStatusActor::Receiver);
    assert_eq!(kept.status_reason.as_deref(), Some("maintenance"));
    assert!(kept.authorization_header_set);
    let still = repo
        .decrypt_authorization_header(tenant, stream.id)
        .await
        .unwrap()
        .unwrap();
    assert!(still.as_str() == original.as_str(), "Keep keeps the header");

    // Set: a new value.
    let replacement = header_value();
    let mut set = SsfStreamUpdate::from_stream(&kept);
    set.authorization_header = SecretChange::Set(replacement.clone());
    let replaced = repo.update(tenant, stream.id, set).await.unwrap();
    let opened = repo
        .decrypt_authorization_header(tenant, stream.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        opened.as_str() == replacement.as_str(),
        "Set replaces the header"
    );

    // Clear: gone.
    let mut clear = SsfStreamUpdate::from_stream(&replaced);
    clear.authorization_header = SecretChange::Clear;
    let cleared = repo.update(tenant, stream.id, clear).await.unwrap();
    assert!(!cleared.authorization_header_set);
    assert_eq!(
        repo.decrypt_authorization_header(tenant, stream.id)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn list_for_event_skips_disabled_streams_and_unrequested_events() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let push = repo
        .create(push_input(tenant, "https://rp.example.com/aud-ev1"))
        .await
        .unwrap();
    let poll = repo
        .create(poll_input(tenant, "https://rp.example.com/aud-ev2"))
        .await
        .unwrap();
    let mut paused = poll_input(tenant, "https://rp.example.com/aud-ev3");
    paused.status = SsfStreamStatus::Paused;
    let paused = repo.create(paused).await.unwrap();
    let mut disabled = poll_input(tenant, "https://rp.example.com/aud-ev4");
    disabled.status = SsfStreamStatus::Disabled;
    repo.create(disabled).await.unwrap();
    // Another tenant's stream never shows up.
    repo.create(poll_input(Uuid::new_v4(), "https://rp.example.com/aud-ev5"))
        .await
        .unwrap();

    let ids = |streams: Vec<axiam_core::models::ssf::SsfStream>| {
        let mut ids: Vec<Uuid> = streams.into_iter().map(|s| s.id).collect();
        ids.sort();
        ids
    };
    let mut want = vec![push.id, poll.id, paused.id];
    want.sort();
    assert_eq!(
        ids(repo
            .list_for_event(tenant, SsfEventType::SessionRevoked)
            .await
            .unwrap()),
        want
    );
    // Allowed but not requested on the push stream.
    let mut want = vec![poll.id, paused.id];
    want.sort();
    assert_eq!(
        ids(repo
            .list_for_event(tenant, SsfEventType::CredentialChange)
            .await
            .unwrap()),
        want
    );
    assert_eq!(
        repo.list_for_receiver(tenant, "receiver-a")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_verification_is_claimed_once_per_interval() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let stream = repo
        .create(poll_input(tenant, "https://rp.example.com/aud-ver"))
        .await
        .unwrap();
    let now = Utc::now();
    assert!(
        repo.claim_verification(tenant, stream.id, now, 60)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .claim_verification(tenant, stream.id, now + Duration::seconds(30), 60)
            .await
            .unwrap()
    );
    assert!(
        repo.claim_verification(tenant, stream.id, now + Duration::seconds(61), 60)
            .await
            .unwrap()
    );
    assert!(
        repo.get(tenant, stream.id)
            .await
            .unwrap()
            .last_verification_at
            .is_some()
    );
}

async fn buffer_rows(db: &Surreal<Db>, stream_id: Uuid) -> usize {
    let mut result = db
        .query("SELECT count() AS n FROM ssf_event_buffer WHERE stream_id = $s GROUP ALL")
        .bind(("s", stream_id.to_string()))
        .await
        .unwrap();
    let rows: Vec<serde_json::Value> = result.take(0).unwrap_or_default();
    rows.first()
        .and_then(|r| r.get("n"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize
}

async fn buffer_one(db: &Surreal<Db>, tenant: Uuid, stream_id: Uuid) {
    db.query(
        "CREATE ssf_event_buffer SET tenant_id = $t, stream_id = $s, jti = $jti, \
         event_uri = $uri, pending_json = '{}', created_at = time::now(), \
         expires_at = time::now() + 7d",
    )
    .bind(("t", tenant.to_string()))
    .bind(("s", stream_id.to_string()))
    .bind(("jti", Uuid::new_v4().simple().to_string()))
    .bind(("uri", SsfEventType::AccountPurged.uri().to_owned()))
    .await
    .unwrap()
    .check()
    .unwrap();
}

#[tokio::test]
async fn the_buffer_holds_one_row_per_jti() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let stream = Uuid::new_v4();
    let jti = Uuid::new_v4().simple().to_string();
    let insert = || {
        db.query(
            "CREATE ssf_event_buffer SET tenant_id = $t, stream_id = $s, jti = $jti, \
             event_uri = 'x', pending_json = '{}', created_at = time::now(), \
             expires_at = time::now() + 7d",
        )
        .bind(("t", tenant.to_string()))
        .bind(("s", stream.to_string()))
        .bind(("jti", jti.clone()))
    };
    insert().await.unwrap().check().unwrap();
    assert!(
        insert().await.unwrap().check().is_err(),
        "a second row with the same jti must be refused by the datastore"
    );
    // A jti that is not 32 hex characters long is refused by the schema.
    let short = db
        .query(
            "CREATE ssf_event_buffer SET tenant_id = $t, stream_id = $s, jti = 'abc', \
             event_uri = 'x', pending_json = '{}', created_at = time::now(), \
             expires_at = time::now() + 7d",
        )
        .bind(("t", tenant.to_string()))
        .bind(("s", stream.to_string()))
        .await
        .unwrap()
        .check();
    assert!(short.is_err());
}

#[tokio::test]
async fn deleting_a_stream_removes_its_buffer_and_nothing_else() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let doomed = repo
        .create(poll_input(tenant, "https://rp.example.com/aud-del1"))
        .await
        .unwrap();
    let kept = repo
        .create(poll_input(tenant, "https://rp.example.com/aud-del2"))
        .await
        .unwrap();
    buffer_one(&db, tenant, doomed.id).await;
    buffer_one(&db, tenant, doomed.id).await;
    buffer_one(&db, tenant, kept.id).await;

    repo.delete(tenant, doomed.id).await.unwrap();
    assert!(matches!(
        repo.get(tenant, doomed.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(buffer_rows(&db, doomed.id).await, 0);
    assert_eq!(buffer_rows(&db, kept.id).await, 1);
    assert!(matches!(
        repo.delete(tenant, doomed.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    // The audience is free again.
    repo.create(poll_input(tenant, "https://rp.example.com/aud-del1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_tenant_delete_removes_its_streams_and_buffers() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let mk = |slug: String| CreateTenant {
        organization_id: org.id,
        name: slug.clone(),
        slug,
        metadata: None,
        kind: TenantKind::Standard,
    };
    let doomed = tenants
        .create(mk(format!("t-{}", Uuid::new_v4().simple())))
        .await
        .unwrap();
    let survivor = tenants
        .create(mk(format!("t-{}", Uuid::new_v4().simple())))
        .await
        .unwrap();
    let repo = repo(&db);
    let gone = repo
        .create(poll_input(doomed.id, "https://rp.example.com/aud-td1"))
        .await
        .unwrap();
    let stays = repo
        .create(poll_input(survivor.id, "https://rp.example.com/aud-td2"))
        .await
        .unwrap();
    buffer_one(&db, doomed.id, gone.id).await;
    buffer_one(&db, survivor.id, stays.id).await;

    tenants.delete(doomed.id).await.unwrap();

    assert!(matches!(
        repo.get(doomed.id, gone.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(buffer_rows(&db, gone.id).await, 0);
    assert_eq!(repo.get(survivor.id, stays.id).await.unwrap().id, stays.id);
    assert_eq!(buffer_rows(&db, stays.id).await, 1);
}

#[tokio::test]
async fn ssf_enabled_is_off_by_default_and_disable_only() {
    let db = setup().await;
    let settings = SurrealSettingsRepository::new(db.clone());
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: format!("t-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let (org_id, tenant_id) = (org.id, tenant.id);
    let unset = settings
        .get_effective_settings(org_id, tenant_id)
        .await
        .unwrap();
    assert!(!unset.oidc.ssf_enabled);

    settings
        .set_org_settings(
            org_id,
            SetOrgSettings {
                ssf_enabled: true,
                ..system_defaults()
            },
        )
        .await
        .unwrap();
    assert!(
        settings
            .get_effective_settings(org_id, tenant_id)
            .await
            .unwrap()
            .oidc
            .ssf_enabled
    );
    settings
        .set_tenant_override(
            tenant_id,
            SetTenantOverride {
                ssf_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        !settings
            .get_effective_settings(org_id, tenant_id)
            .await
            .unwrap()
            .oidc
            .ssf_enabled
    );
}

/// F4 W4 P23W4-01 (D-49, D-51, T-406): every write of a stream is
/// read-modify-write — a receiver's `PATCH`, `PUT` and status write, and an
/// administrator's replacement, all carry the whole configuration they read. A
/// write prepared from a read that another write has since overtaken must not
/// land: if it did, a receiver racing an administrator would put back the
/// status, the allowance, the binding or the subject format the administrator
/// had just changed — undoing a `disabled` that D-51 says only an administrator
/// may lift.
#[tokio::test]
async fn a_write_prepared_from_an_overtaken_read_does_not_land() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let stream = repo
        .create(push_input(tenant, "https://rp.example.com/aud-race"))
        .await
        .unwrap();
    // The receiver's read, before the administrator acts.
    let receivers_read = repo.get(tenant, stream.id).await.unwrap();

    // The administrator disables the stream and narrows it.
    let mut stop = SsfStreamUpdate::from_stream(&receivers_read);
    stop.status = SsfStreamStatus::Disabled;
    stop.status_actor = SsfStatusActor::Admin;
    stop.events_allowed = vec![SsfEventType::AccountPurged];
    stop.events_requested = vec![SsfEventType::AccountPurged];
    stop.subject_format = SsfSubjectFormat::IssSub;
    repo.update(tenant, stream.id, stop).await.unwrap();

    // The receiver's write, built from its earlier read, arrives after.
    let mut late = SsfStreamUpdate::from_stream(&receivers_read);
    late.description = Some("renamed by the receiver".into());
    let refused = repo.update(tenant, stream.id, late).await;
    assert!(
        matches!(refused, Err(AxiamError::Conflict { .. })),
        "a write from an overtaken read is refused as a conflict"
    );

    let now = repo.get(tenant, stream.id).await.unwrap();
    assert_eq!(now.status, SsfStreamStatus::Disabled, "still disabled");
    assert_eq!(now.status_actor, SsfStatusActor::Admin);
    assert_eq!(now.events_allowed, vec![SsfEventType::AccountPurged]);
    assert_eq!(now.subject_format, SsfSubjectFormat::IssSub);
    assert_eq!(now.description.as_deref(), Some("Payroll receiver"));

    // A write from a fresh read lands, and a missing stream is still NotFound.
    let mut fresh = SsfStreamUpdate::from_stream(&now);
    fresh.description = Some("renamed".into());
    assert_eq!(
        repo.update(tenant, stream.id, fresh.clone())
            .await
            .unwrap()
            .description
            .as_deref(),
        Some("renamed")
    );
    assert!(matches!(
        repo.update(tenant, Uuid::new_v4(), fresh).await,
        Err(AxiamError::NotFound { .. })
    ));
}
