//! SurrealDB implementation of [`SsfStreamRepository`] (G-5, T23.5.2, schema
//! v77).
//!
//! One row per registered SSF stream, tenant-scoped, with one deployment-wide
//! rule the datastore enforces: `idx_ssf_stream_audience` is UNIQUE on the
//! audience alone, so two streams of **any** two tenants never share a SET
//! `aud` (D-47), and a concurrent double registration is an `AlreadyExists`.
//!
//! # The push `Authorization` header
//!
//! Sealed with AES-256-GCM under `pki_encryption_key` — the key webhook secrets
//! use, since it protects the same class of value: a credential AXIAM presents
//! to a tenant-registered outbound endpoint — a fresh nonce per write, nonce and
//! ciphertext in their own columns. The key is **optional**: a repository built
//! without it refuses any write that sets a header (fail closed, naming the
//! key) and serves everything else. Every read projects [`PUBLIC_COLUMNS`], so
//! the ciphertext never leaves the datastore except through
//! [`SurrealSsfStreamRepository::decrypt_authorization_header`].

use axiam_auth::crypto::{decrypt_separate, encrypt_separate};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::ssf::{
    NewSsfStream, SecretChange, SsfDeliveryMethod, SsfEventType, SsfStatusActor, SsfStream,
    SsfStreamStatus, SsfStreamUpdate, SsfSubjectFormat,
};
use axiam_core::repository::{PaginatedResult, Pagination, SsfStreamRepository};
use axiam_core::secrets::{PKI_ENCRYPTION_KEY, env_var_name};
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, delete_existence_guard, map_delete_errors, paginate,
    parse_uuid, search_bind, search_filter, take_first_or_not_found,
};

const ENTITY: &str = "ssf_stream";

/// The key version written today, as `directory_config` and `email_config`
/// write theirs.
const SECRET_KEY_VERSION: i64 = 1;

/// Every non-secret column, projected explicitly: a read of this table never
/// hydrates `auth_header_ciphertext` or `auth_header_nonce`.
const PUBLIC_COLUMNS: &str = "meta::id(id) AS record_id, tenant_id, receiver_client_id, \
    audience, description, delivery_method, endpoint_url, \
    (auth_header_ciphertext != NONE) AS authorization_header_set, events_allowed, \
    events_requested, subject_format, status, status_reason, status_actor, \
    last_verification_at, created_at, updated_at";

#[derive(Debug, SurrealValue)]
struct StreamRow {
    record_id: String,
    tenant_id: String,
    receiver_client_id: String,
    audience: String,
    description: Option<String>,
    delivery_method: String,
    endpoint_url: Option<String>,
    authorization_header_set: bool,
    events_allowed: Vec<String>,
    events_requested: Vec<String>,
    subject_format: String,
    status: String,
    status_reason: Option<String>,
    status_actor: String,
    last_verification_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn events_from(raw: &[String], what: &str) -> Result<Vec<SsfEventType>, DbError> {
    raw.iter()
        .map(|uri| {
            SsfEventType::from_uri(uri).ok_or_else(|| {
                DbError::Serialization(format!("ssf_stream {what} holds an unknown event type"))
            })
        })
        .collect()
}

impl StreamRow {
    fn into_domain(self) -> Result<SsfStream, DbError> {
        let unknown =
            |what: &str| DbError::Serialization(format!("ssf_stream has an unknown {what}"));
        Ok(SsfStream {
            id: parse_uuid(&self.record_id, ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            receiver_client_id: self.receiver_client_id,
            audience: self.audience,
            description: self.description,
            delivery_method: SsfDeliveryMethod::from_wire(&self.delivery_method)
                .ok_or_else(|| unknown("delivery_method"))?,
            endpoint_url: self.endpoint_url,
            authorization_header_set: self.authorization_header_set,
            events_allowed: events_from(&self.events_allowed, "events_allowed")?,
            events_requested: events_from(&self.events_requested, "events_requested")?,
            subject_format: SsfSubjectFormat::from_wire(&self.subject_format)
                .ok_or_else(|| unknown("subject_format"))?,
            status: SsfStreamStatus::from_wire(&self.status).ok_or_else(|| unknown("status"))?,
            status_reason: self.status_reason,
            status_actor: SsfStatusActor::from_wire(&self.status_actor)
                .ok_or_else(|| unknown("status_actor"))?,
            last_verification_at: self.last_verification_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The two secret columns. Deliberately not `Debug`.
#[derive(SurrealValue)]
struct SecretRow {
    auth_header_ciphertext: Option<String>,
    auth_header_nonce: Option<String>,
}

/// The `SET` clause every write of the public columns shares.
const SET_CLAUSE: &str = "receiver_client_id = $receiver_client_id, audience = $audience, \
    description = $description, delivery_method = $delivery_method, \
    endpoint_url = $endpoint_url, events_allowed = $events_allowed, \
    events_requested = $events_requested, subject_format = $subject_format, \
    status = $status, status_reason = $status_reason, status_actor = $status_actor";

/// SurrealDB implementation of [`SsfStreamRepository`].
pub struct SurrealSsfStreamRepository<C: Connection> {
    db: DbHandle<C>,
    key: Option<[u8; 32]>,
}

impl<C: Connection> Clone for SurrealSsfStreamRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            key: self.key,
        }
    }
}

/// Redacting `Debug`: the key is the one thing in this struct worth protecting.
impl<C: Connection> std::fmt::Debug for SurrealSsfStreamRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealSsfStreamRepository")
            .field("key_configured", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

/// Encrypt the header, returning `(nonce_b64, ciphertext_b64)`. The error
/// carries no detail.
fn seal(key: &[u8; 32], header: &str) -> AxiamResult<(String, String)> {
    encrypt_separate(key, header.as_bytes())
        .map_err(|_| AxiamError::Crypto("the SSF push credential could not be encrypted".into()))
}

impl<C: Connection> SurrealSsfStreamRepository<C> {
    /// Build the repository. `key` is the 256-bit `pki_encryption_key`, or
    /// `None` when it is not configured: then a write that sets a push header
    /// is refused and everything else works.
    pub fn new(db: impl Into<DbHandle<C>>, key: Option<[u8; 32]>) -> Self {
        Self { db: db.into(), key }
    }

    /// Whether the encryption key is configured, for a route that must answer
    /// `503` before it validates a header it could not store.
    #[must_use]
    pub fn has_encryption_key(&self) -> bool {
        self.key.is_some()
    }

    fn missing_key_message() -> String {
        format!(
            "a push authorization header cannot be stored: {PKI_ENCRYPTION_KEY} ({}) is not \
             configured",
            env_var_name(PKI_ENCRYPTION_KEY)
        )
    }

    fn sealed(&self, header: &str) -> AxiamResult<(String, String)> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AxiamError::ServiceUnavailable(Self::missing_key_message()))?;
        seal(key, header)
    }

    async fn fetch(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<SsfStream>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM ssf_stream \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<StreamRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .transpose()
    }

    async fn select_many(
        &self,
        filter: &str,
        tenant_id: Uuid,
        extra: Vec<(&'static str, String)>,
    ) -> AxiamResult<Vec<SsfStream>> {
        let db = self.db.current();
        let mut query = db
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM ssf_stream \
                 WHERE tenant_id = $tenant_id{filter} ORDER BY created_at ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()));
        for (name, value) in extra {
            query = query.bind((name, value));
        }
        let mut result = query.await.map_err(DbError::from)?;
        let rows: Vec<StreamRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect()
    }
}

impl<C: Connection> SsfStreamRepository for SurrealSsfStreamRepository<C> {
    async fn create(&self, input: NewSsfStream) -> AxiamResult<SsfStream> {
        let sealed = match input.authorization_header.as_ref() {
            Some(header) => Some(self.sealed(header)?),
            None => None,
        };
        let (nonce, ciphertext) = match sealed {
            Some((n, c)) => (Some(n), Some(c)),
            None => (None, None),
        };
        let key_version = ciphertext.as_ref().map(|_| SECRET_KEY_VERSION);
        let id = new_id();
        let tenant_id = input.tenant_id;
        let result = self
            .db
            .current()
            .query(format!(
                "CREATE type::record('ssf_stream', $id) SET \
                 tenant_id = $tenant_id, {SET_CLAUSE}, \
                 auth_header_ciphertext = $ciphertext, auth_header_nonce = $nonce, \
                 secret_key_version = $key_version, last_verification_at = NONE, \
                 created_at = time::now(), updated_at = time::now()"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("receiver_client_id", input.receiver_client_id))
            .bind(("audience", input.audience))
            .bind(("description", input.description))
            .bind(("delivery_method", input.delivery_method.as_str().to_owned()))
            .bind(("endpoint_url", input.endpoint_url))
            .bind(("events_allowed", SsfEventType::uris(&input.events_allowed)))
            .bind((
                "events_requested",
                SsfEventType::uris(&input.events_requested),
            ))
            .bind(("subject_format", input.subject_format.as_str().to_owned()))
            .bind(("status", input.status.as_str().to_owned()))
            .bind(("status_reason", input.status_reason))
            .bind(("status_actor", SsfStatusActor::Admin.as_str().to_owned()))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", key_version))
            .await
            .map_err(DbError::from)?;
        // The deployment-wide unique index on `audience` is what makes a second
        // registration of the same audience, in any tenant, `AlreadyExists`.
        result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;
        self.get(tenant_id, id).await
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<SsfStream> {
        let found = self.fetch(tenant_id, id).await?;
        Ok(take_first_or_not_found(
            found.into_iter().collect(),
            ENTITY,
            &id.to_string(),
        )?)
    }

    async fn list_page(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<SsfStream>> {
        let search = search_filter(
            &pagination,
            &["audience", "receiver_client_id", "description"],
        );
        let search_term = search_bind(&pagination);
        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM ssf_stream \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {PUBLIC_COLUMNS} FROM ssf_stream \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY created_at ASC LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<StreamRow> = result.take(0).map_err(DbError::from)?;
        let items = rows
            .into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn list_for_receiver(
        &self,
        tenant_id: Uuid,
        receiver_client_id: &str,
    ) -> AxiamResult<Vec<SsfStream>> {
        self.select_many(
            " AND receiver_client_id = $receiver_client_id",
            tenant_id,
            vec![("receiver_client_id", receiver_client_id.to_owned())],
        )
        .await
    }

    async fn list_for_event(
        &self,
        tenant_id: Uuid,
        event: SsfEventType,
    ) -> AxiamResult<Vec<SsfStream>> {
        self.select_many(
            " AND status != 'disabled' AND $event IN events_allowed \
             AND $event IN events_requested",
            tenant_id,
            vec![("event", event.uri().to_owned())],
        )
        .await
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: SsfStreamUpdate,
    ) -> AxiamResult<SsfStream> {
        let (secret_clause, ciphertext, nonce) = match &update.authorization_header {
            SecretChange::Keep => ("", None, None),
            SecretChange::Set(header) => {
                let (n, c) = self.sealed(header)?;
                (
                    ", auth_header_ciphertext = $ciphertext, auth_header_nonce = $nonce, \
                     secret_key_version = $key_version",
                    Some(c),
                    Some(n),
                )
            }
            SecretChange::Clear => (
                ", auth_header_ciphertext = NONE, auth_header_nonce = NONE, \
                 secret_key_version = NONE",
                None,
                None,
            ),
        };
        // The tenant guard is in the `WHERE`, so another tenant's row matches
        // nothing and reads back as `NotFound`.
        let result = self
            .db
            .current()
            .query(format!(
                "UPDATE type::record('ssf_stream', $id) SET {SET_CLAUSE}{secret_clause}, \
                 updated_at = time::now() WHERE tenant_id = $tenant_id"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("receiver_client_id", update.receiver_client_id))
            .bind(("audience", update.audience))
            .bind(("description", update.description))
            .bind((
                "delivery_method",
                update.delivery_method.as_str().to_owned(),
            ))
            .bind(("endpoint_url", update.endpoint_url))
            .bind(("events_allowed", SsfEventType::uris(&update.events_allowed)))
            .bind((
                "events_requested",
                SsfEventType::uris(&update.events_requested),
            ))
            .bind(("subject_format", update.subject_format.as_str().to_owned()))
            .bind(("status", update.status.as_str().to_owned()))
            .bind(("status_reason", update.status_reason))
            .bind(("status_actor", update.status_actor.as_str().to_owned()))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("key_version", SECRET_KEY_VERSION))
            .await
            .map_err(DbError::from)?;
        result
            .check()
            .map_err(|e| classify_write_error(e, ENTITY))?;
        self.get(tenant_id, id).await
    }

    async fn claim_verification(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
        min_interval_secs: i64,
    ) -> AxiamResult<bool> {
        // Existence first, so "too soon" and "not yours" are told apart.
        self.get(tenant_id, id).await?;
        let cutoff = now - Duration::seconds(min_interval_secs);
        // The interval is the precondition of the write: two concurrent
        // requests cannot both pass it.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE type::record('ssf_stream', $id) SET last_verification_at = $now \
                 WHERE tenant_id = $tenant_id \
                   AND (last_verification_at = NONE OR last_verification_at <= $cutoff) \
                 RETURN meta::id(id) AS record_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("now", now))
            .bind(("cutoff", cutoff))
            .await
            .map_err(DbError::from)?;

        #[derive(SurrealValue)]
        struct IdRow {
            #[allow(dead_code)] // counted, never read
            record_id: String,
        }
        let rows: Vec<IdRow> = result.take(0).map_err(DbError::from)?;
        Ok(!rows.is_empty())
    }

    async fn decrypt_authorization_header(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<Option<Zeroizing<String>>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT auth_header_ciphertext, auth_header_nonce FROM ssf_stream \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SecretRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Err(DbError::NotFound {
                entity: ENTITY.into(),
                id: id.to_string(),
            }
            .into());
        };
        let (Some(ciphertext), Some(nonce)) = (row.auth_header_ciphertext, row.auth_header_nonce)
        else {
            return Ok(None);
        };
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AxiamError::ServiceUnavailable(Self::missing_key_message()))?;
        let plaintext = decrypt_separate(key, &nonce, &ciphertext).map_err(|_| {
            AxiamError::Crypto(
                "the SSF push credential could not be decrypted: the stored value does not \
                 match the configured pki_encryption_key"
                    .into(),
            )
        })?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            AxiamError::Crypto("the decrypted SSF push credential is not valid UTF-8".into())
        })?;
        Ok(Some(Zeroizing::new(text)))
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        // One transaction: the existence guard (a foreign or unknown id aborts
        // with `NotFound` before anything is removed), the stream's buffered
        // events, then the stream.
        let guard = delete_existence_guard(ENTITY);
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             DELETE ssf_event_buffer WHERE tenant_id = $tenant_id AND stream_id = $id; \
             DELETE type::record('ssf_stream', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        map_delete_errors(result.take_errors(), ENTITY, &id.to_string())?;
        Ok(())
    }
}
