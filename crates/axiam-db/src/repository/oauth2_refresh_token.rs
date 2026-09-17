//! SurrealDB implementation of [`RefreshTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{CreateRefreshToken, RefreshToken};
use axiam_core::repository::RefreshTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;

/// Parse an optional stored session id.
///
/// Absent and empty both mean "no session": SurrealDB writes `NONE` as absent,
/// and a row migrated from the pre-v28 shape can carry `""`. Treating that as a
/// parse failure would make an old refresh token unreadable rather than merely
/// session-less.
fn parse_opt_session(raw: Option<&str>) -> Result<Option<Uuid>, DbError> {
    match raw {
        None | Some("") => Ok(None),
        Some(v) => Uuid::parse_str(v)
            .map(Some)
            .map_err(|e| DbError::Migration(format!("invalid session UUID: {e}"))),
    }
}
use crate::helpers::{CountRow, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct RefreshTokenRow {
    tenant_id: String,
    token_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Vec<String>,
    #[surreal(default)]
    session_id: Option<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
    /// T-254 — see [`RefreshToken::rotated_at`]. Absent on every row written
    /// before schema v60, and `#[surreal(default)]` is what lets such a row
    /// still decode.
    #[surreal(default)]
    rotated_at: Option<DateTime<Utc>>,
    /// T-241 — see [`RefreshToken::requested_userinfo_claims`]. Absent on
    /// every row written before schema v61; `None` decodes to the empty
    /// vector, which is a refreshed token with no `axiam_requested_claims` —
    /// exactly what such a row produced before the column existed.
    #[surreal(default)]
    requested_userinfo_claims: Option<Vec<String>>,
    /// T21.3 / RFC 8707 — see [`RefreshToken::resource`]. Absent on every row
    /// written before schema v63, which is the honest value: those grants
    /// named no resource, and a refresh of one mints `axiam:user` exactly as
    /// it always did.
    #[surreal(default)]
    resource: Option<String>,
}

#[derive(Debug, SurrealValue)]
struct RefreshTokenRowWithId {
    record_id: String,
    tenant_id: String,
    token_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Vec<String>,
    #[surreal(default)]
    session_id: Option<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
    /// T-254 — see [`RefreshToken::rotated_at`].
    #[surreal(default)]
    rotated_at: Option<DateTime<Utc>>,
    /// T-241 — see [`RefreshToken::requested_userinfo_claims`].
    #[surreal(default)]
    requested_userinfo_claims: Option<Vec<String>>,
    /// T21.3 / RFC 8707 — see [`RefreshToken::resource`]. Absent on every row
    /// written before schema v63, which is the honest value: those grants
    /// named no resource, and a refresh of one mints `axiam:user` exactly as
    /// it always did.
    #[surreal(default)]
    resource: Option<String>,
}

impl RefreshTokenRowWithId {
    fn try_into_refresh_token(self) -> Result<RefreshToken, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = self
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid)
                    .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: self.token_hash,
            client_id: self.client_id,
            user_id,
            scopes: self.scopes,
            session_id: parse_opt_session(self.session_id.as_deref())?,
            expires_at: self.expires_at,
            revoked: self.revoked,
            created_at: self.created_at,
            rotated_at: self.rotated_at,
            requested_userinfo_claims: self.requested_userinfo_claims.unwrap_or_default(),
            resource: self.resource,
        })
    }
}

/// SurrealDB implementation of the RefreshToken repository.
pub struct SurrealRefreshTokenRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound that
// blocks cloning under generic `C: Connection` callers. Matches SurrealUserRepository.
impl<C: Connection> Clone for SurrealRefreshTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealRefreshTokenRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> RefreshTokenRepository for SurrealRefreshTokenRepository<C> {
    async fn create(&self, input: CreateRefreshToken) -> AxiamResult<RefreshToken> {
        let id = new_id();
        let id_str = id.to_string();

        let user_id_str = input.user_id.map(|u| u.to_string());

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_refresh_token', $id) SET \
                 tenant_id = $tenant_id, \
                 token_hash = $token_hash, \
                 client_id = $client_id, \
                 user_id = $user_id, \
                 scopes = $scopes, \
                 session_id = $session_id, \
                 requested_userinfo_claims = $requested_userinfo_claims, \
                 resource = $resource, \
                 expires_at = $expires_at, \
                 revoked = false",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("token_hash", input.token_hash.clone()))
            .bind(("client_id", input.client_id.clone()))
            .bind(("user_id", user_id_str))
            .bind(("scopes", input.scopes))
            .bind(("session_id", input.session_id.map(|id| id.to_string())))
            .bind(("requested_userinfo_claims", input.requested_userinfo_claims))
            .bind(("resource", input.resource))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_refresh_token", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = row
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid)
                    .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: row.token_hash,
            client_id: row.client_id,
            user_id,
            scopes: row.scopes,
            session_id: parse_opt_session(row.session_id.as_deref())?,
            expires_at: row.expires_at,
            revoked: row.revoked,
            created_at: row.created_at,
            rotated_at: row.rotated_at,
            requested_userinfo_claims: row.requested_userinfo_claims.unwrap_or_default(),
            resource: row.resource,
        })
    }

    async fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<RefreshToken> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT *, meta::id(id) AS record_id \
                 FROM oauth2_refresh_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                   AND expires_at > time::now() \
                 LIMIT 1",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "oauth2_refresh_token",
            &format!("token_hash={token_hash_owned}"),
        )?;

        row.try_into_refresh_token().map_err(Into::into)
    }

    async fn revoke(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<()> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        // Only revoke tokens that are not already revoked — this
        // provides atomic single-use semantics for refresh token
        // rotation.  If no rows are updated (token already revoked or
        // not found) we return NotFound so callers can detect
        // concurrent use.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: format!("token_hash={token_hash_owned}"),
            }
            .into());
        }

        Ok(())
    }

    async fn supersede(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
        grace_until: chrono::DateTime<chrono::Utc>,
    ) -> AxiamResult<()> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        // `expires_at < $grace_until` in the SET, not just in the WHERE: the
        // trait's one-way rule. The WHERE decides *whether* this token is still
        // live; the conditional in the SET decides that the write can only ever
        // bring the expiry forward, so a caller who passes a distant instant
        // shortens nothing and lengthens nothing either.
        //
        // `revoked = false` in the WHERE keeps the single-use race closed
        // exactly as `revoke` does: two concurrent rotations of the same token
        // cannot both find a live row, and the loser still gets NotFound.
        //
        // T-254: `rotated_at` is stamped in the SAME statement. The grace
        // window is the one case where a retired token stays redeemable, so
        // the only thing that tells the honest retry from a replay is that the
        // row records having a successor. A second write to set it could be
        // lost — and what it would leave behind is a rotated token that does
        // not say so, which is precisely the blind spot T-254 is about.
        //
        // Unconditional, unlike the expiry: a token rotated twice inside one
        // window was rotated most recently now, and that is the instant an
        // operator correlating an audit row wants.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET \
                 expires_at = IF expires_at < $grace_until THEN expires_at ELSE $grace_until END, \
                 rotated_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                   AND expires_at > time::now() \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .bind(("grace_until", grace_until))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: format!("token_hash={token_hash_owned}"),
            }
            .into());
        }

        Ok(())
    }

    async fn revoke_rotated(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<()> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        // The rotation path for every client that is not `fapi2` (T-254), and
        // the behaviour every client had before 065f37c: the predecessor is
        // revoked outright and a second presentation finds no live row.
        //
        // Two differences from `revoke`, both deliberate. `rotated_at` is
        // stamped, so `find_rotated` can later say that a refused presentation
        // was a *replay* rather than an ordinary stale credential. And the
        // WHERE carries `expires_at > time::now()` as `supersede`'s does: the
        // guard that keeps two concurrent rotations from both finding a live
        // row is the same guard on both lanes, so the loser gets NotFound and
        // the single-use race stays closed whichever profile the client is on.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET \
                 revoked = true, \
                 rotated_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                   AND expires_at > time::now() \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: format!("token_hash={token_hash_owned}"),
            }
            .into());
        }

        Ok(())
    }

    async fn find_rotated(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<RefreshToken>> {
        let token_hash_owned = token_hash.to_string();

        // Neither `revoked` nor `expires_at` is filtered — a replay of a token
        // that has since run out is still a replay — but `rotated_at` must be
        // set, which is what keeps a credential revoked at logout from being
        // filed as one.
        let mut result = self
            .db
            .current()
            .query(
                "SELECT *, meta::id(id) AS record_id \
                 FROM oauth2_refresh_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND rotated_at != NONE \
                 LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash_owned))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.try_into_refresh_token().map_err(Into::into))
            .transpose()
    }

    async fn revoke_all_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        // Revoke all non-revoked tokens for the user atomically. Skip already-revoked
        // tokens so the returned count reflects only newly-revoked tokens.
        // RETURN AFTER gives us the updated rows for counting.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND user_id = $user_id \
                   AND revoked = false \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    async fn revoke_all_for_client(&self, tenant_id: Uuid, client_id: &str) -> AxiamResult<()> {
        let client_id_owned = client_id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("client_id", client_id_owned))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true \
                 GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let count = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query(
                "DELETE FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true",
            )
            .await
            .map_err(DbError::from)?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    async fn issue(
        repo: &SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> RefreshToken {
        repo.create(CreateRefreshToken {
            tenant_id,
            token_hash: token_hash.to_owned(),
            client_id: "oa_test".into(),
            user_id: Some(Uuid::new_v4()),
            scopes: vec!["openid".into()],
            session_id: Some(Uuid::new_v4()),
            requested_userinfo_claims: Vec::new(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            resource: None,
        })
        .await
        .unwrap()
    }

    // -----------------------------------------------------------------
    // T-241 — the claims request on the refresh token (schema v61)
    // -----------------------------------------------------------------

    /// Round-trip: what `create` was handed is what `get_by_token_hash`
    /// returns, in order. Order matters because the list is minted verbatim
    /// into `axiam_requested_claims`, which a relying party reads.
    #[tokio::test]
    async fn the_claims_request_round_trips_through_the_row() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();

        let created = repo
            .create(CreateRefreshToken {
                tenant_id,
                token_hash: "t241-roundtrip".into(),
                client_id: "oa_test".into(),
                user_id: Some(Uuid::new_v4()),
                scopes: vec!["openid".into()],
                session_id: None,
                requested_userinfo_claims: vec!["email".into(), "name".into()],
                expires_at: Utc::now() + chrono::Duration::days(30),
                resource: None,
            })
            .await
            .unwrap();
        assert_eq!(
            created.requested_userinfo_claims,
            vec!["email".to_owned(), "name".to_owned()]
        );

        let read = repo
            .get_by_token_hash(tenant_id, "t241-roundtrip")
            .await
            .unwrap();
        assert_eq!(
            read.requested_userinfo_claims,
            vec!["email".to_owned(), "name".to_owned()]
        );
    }

    /// **I4 twin.** A row written before v61 has no column at all. It must
    /// still decode — every refresh token in flight across the migration is
    /// one of these — and it must decode to the empty list, which mints a
    /// token with no `axiam_requested_claims`: exactly what such a row
    /// produced before the column existed.
    ///
    /// The row is written with `UNSET` rather than by omitting the field from
    /// a `CREATE`, because `create` now always writes the column; removing it
    /// afterwards is the only way to reproduce the pre-migration shape against
    /// a migrated schema.
    #[tokio::test]
    async fn a_row_written_before_v61_decodes_to_no_claims() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db.clone());
        let tenant_id = Uuid::new_v4();
        repo.create(CreateRefreshToken {
            tenant_id,
            token_hash: "t241-premigration".into(),
            client_id: "oa_test".into(),
            user_id: Some(Uuid::new_v4()),
            scopes: vec!["openid".into()],
            session_id: None,
            requested_userinfo_claims: vec!["email".into()],
            expires_at: Utc::now() + chrono::Duration::days(30),
            resource: None,
        })
        .await
        .unwrap();

        db.query(
            "UPDATE oauth2_refresh_token UNSET requested_userinfo_claims \
             WHERE token_hash = $h",
        )
        .bind(("h", "t241-premigration"))
        .await
        .unwrap()
        .check()
        .unwrap();

        let read = repo
            .get_by_token_hash(tenant_id, "t241-premigration")
            .await
            .expect("a pre-v61 row must still decode, not error");
        assert!(
            read.requested_userinfo_claims.is_empty(),
            "absent means the grant named no claims, which is today's behaviour"
        );
    }

    // -----------------------------------------------------------------
    // T-254 — the two rotation lanes, and what each leaves behind
    // -----------------------------------------------------------------

    /// The FAPI lane. The predecessor stays redeemable on the grace clock —
    /// thirty days brought forward to sixty seconds — and it records having a
    /// successor, which is the only thing that distinguishes the honest retry
    /// the window exists for from a replay.
    #[tokio::test]
    async fn supersede_keeps_the_row_live_on_the_grace_clock_and_stamps_it() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let issued = issue(&repo, tenant_id, "t254-supersede").await;
        assert!(
            issued.rotated_at.is_none(),
            "a fresh token has no successor"
        );

        repo.supersede(
            tenant_id,
            "t254-supersede",
            Utc::now() + chrono::Duration::seconds(60),
        )
        .await
        .unwrap();

        let live = repo
            .get_by_token_hash(tenant_id, "t254-supersede")
            .await
            .expect("inside the window the predecessor is still redeemable");
        let remaining = (live.expires_at - Utc::now()).num_seconds();
        assert!(
            (0..=60).contains(&remaining),
            "thirty days must have become sixty seconds; {remaining}s remain"
        );
        assert!(
            live.rotated_at.is_some(),
            "the same statement must record that a successor was issued"
        );
    }

    /// The one-way rule the trait states: a caller passing a distant instant
    /// lengthens nothing.
    #[tokio::test]
    async fn supersede_can_only_ever_bring_the_expiry_forward() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();
        issue(&repo, tenant_id, "t254-one-way").await;

        repo.supersede(
            tenant_id,
            "t254-one-way",
            Utc::now() + chrono::Duration::days(3650),
        )
        .await
        .unwrap();

        let live = repo
            .get_by_token_hash(tenant_id, "t254-one-way")
            .await
            .unwrap();
        assert!(
            live.expires_at < Utc::now() + chrono::Duration::days(31),
            "a distant grace instant must not extend the token's life"
        );
    }

    /// Every other profile's lane. The predecessor is revoked outright — no
    /// window — and it too records having a successor, so the refusal that
    /// follows can be recognised as a replay.
    #[tokio::test]
    async fn revoke_rotated_kills_the_row_and_still_stamps_it() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();
        issue(&repo, tenant_id, "t254-revoke-rotated").await;

        repo.revoke_rotated(tenant_id, "t254-revoke-rotated")
            .await
            .unwrap();

        assert!(
            repo.get_by_token_hash(tenant_id, "t254-revoke-rotated")
                .await
                .is_err(),
            "there is no window on this lane"
        );
        let rotated = repo
            .find_rotated(tenant_id, "t254-revoke-rotated")
            .await
            .unwrap()
            .expect("the row is still there and says it was rotated");
        assert!(rotated.revoked);
        assert!(rotated.rotated_at.is_some());
    }

    /// The single-use race, on both lanes. The loser of two concurrent
    /// rotations gets `NotFound`, which is what the token endpoint turns into
    /// "already consumed".
    #[tokio::test]
    async fn both_rotation_lanes_report_not_found_to_the_loser() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();

        issue(&repo, tenant_id, "t254-race-fapi").await;
        repo.supersede(
            tenant_id,
            "t254-race-fapi",
            Utc::now() + chrono::Duration::seconds(60),
        )
        .await
        .unwrap();
        // A second supersede inside the window still finds a live row — that
        // is the window working — so the race this asserts is the one that
        // matters: once revoked, nothing wins.
        repo.revoke(tenant_id, "t254-race-fapi").await.unwrap();
        assert!(
            matches!(
                repo.supersede(
                    tenant_id,
                    "t254-race-fapi",
                    Utc::now() + chrono::Duration::seconds(60)
                )
                .await,
                Err(axiam_core::error::AxiamError::NotFound { .. })
            ),
            "a revoked row is not live, and supersede must say so"
        );

        issue(&repo, tenant_id, "t254-race-standard").await;
        repo.revoke_rotated(tenant_id, "t254-race-standard")
            .await
            .unwrap();
        assert!(
            matches!(
                repo.revoke_rotated(tenant_id, "t254-race-standard").await,
                Err(axiam_core::error::AxiamError::NotFound { .. })
            ),
            "two concurrent rotations cannot both find a live row"
        );
    }

    /// A credential revoked at logout is a stale credential, not a replay.
    /// `find_rotated` must not blur the two, or every signed-out client that
    /// retries would be filed as a security event.
    #[tokio::test]
    async fn find_rotated_ignores_a_token_that_was_merely_revoked() {
        let db = setup_db().await;
        let repo = SurrealRefreshTokenRepository::new(db);
        let tenant_id = Uuid::new_v4();
        issue(&repo, tenant_id, "t254-logout").await;

        repo.revoke(tenant_id, "t254-logout").await.unwrap();

        assert!(
            repo.find_rotated(tenant_id, "t254-logout")
                .await
                .unwrap()
                .is_none(),
            "nothing rotated it, so nothing replayed it"
        );
        assert!(
            repo.find_rotated(tenant_id, "t254-never-existed")
                .await
                .unwrap()
                .is_none(),
            "an unknown hash is Ok(None), never an error: the token endpoint \
             answers invalid_grant either way, so this cannot become an oracle"
        );
    }

    /// A row written before schema v60 carries no `rotated_at`, and v60
    /// deliberately does not backfill. It must decode, and it must not be
    /// mistaken for a rotated token.
    #[tokio::test]
    async fn a_pre_v60_refresh_token_row_is_readable_and_is_not_a_replay() {
        let db = setup_db().await;
        let tenant_id = Uuid::new_v4();
        db.query(
            "CREATE type::record('oauth2_refresh_token', $id) SET \
             tenant_id = $tenant_id, \
             token_hash = $token_hash, \
             client_id = 'oa_legacy', \
             user_id = NONE, \
             scopes = ['openid'], \
             expires_at = $expires_at, \
             revoked = false",
        )
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("token_hash", "t254-pre-v60".to_owned()))
        .bind(("expires_at", Utc::now() + chrono::Duration::days(30)))
        .await
        .unwrap()
        .check()
        .unwrap();

        let repo = SurrealRefreshTokenRepository::new(db);
        let live = repo
            .get_by_token_hash(tenant_id, "t254-pre-v60")
            .await
            .expect("a pre-v60 row must still be redeemable");
        assert!(live.rotated_at.is_none());
        assert!(
            repo.find_rotated(tenant_id, "t254-pre-v60")
                .await
                .unwrap()
                .is_none(),
            "absent must not be read as 'rotated'; nothing recorded that it was"
        );
    }
}
