//! SurrealDB implementation of [`WebauthnAttestationPolicyRepository`] (X3, D5).

use axiam_core::error::AxiamResult;
use axiam_core::models::mds::CertificationLevel;
use axiam_core::models::webauthn_policy::{
    AttestationMode, UnknownAaguidAction, WebauthnAttestationPolicy,
};
use axiam_core::repository::WebauthnAttestationPolicyRepository;
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::parse_uuid;

// ---------------------------------------------------------------------------
// Wire <-> domain mapping
// ---------------------------------------------------------------------------

fn mode_to_str(mode: AttestationMode) -> &'static str {
    match mode {
        AttestationMode::None => "none",
        AttestationMode::Indirect => "indirect",
        AttestationMode::DirectRequired => "direct_required",
    }
}

fn mode_from_str(s: &str) -> Result<AttestationMode, DbError> {
    match s {
        "none" => Ok(AttestationMode::None),
        "indirect" => Ok(AttestationMode::Indirect),
        "direct_required" => Ok(AttestationMode::DirectRequired),
        other => Err(DbError::Migration(format!(
            "invalid webauthn_attestation_policy.mode: {other}"
        ))),
    }
}

fn level_to_str(level: CertificationLevel) -> &'static str {
    match level {
        CertificationLevel::L1 => "L1",
        CertificationLevel::L1Plus => "L1plus",
        CertificationLevel::L2 => "L2",
        CertificationLevel::L2Plus => "L2plus",
        CertificationLevel::L3 => "L3",
        CertificationLevel::L3Plus => "L3plus",
    }
}

fn level_from_str(s: &str) -> Result<CertificationLevel, DbError> {
    match s {
        "L1" => Ok(CertificationLevel::L1),
        "L1plus" => Ok(CertificationLevel::L1Plus),
        "L2" => Ok(CertificationLevel::L2),
        "L2plus" => Ok(CertificationLevel::L2Plus),
        "L3" => Ok(CertificationLevel::L3),
        "L3plus" => Ok(CertificationLevel::L3Plus),
        other => Err(DbError::Migration(format!(
            "invalid webauthn_attestation_policy.min_certification: {other}"
        ))),
    }
}

fn unknown_aaguid_to_str(action: UnknownAaguidAction) -> &'static str {
    match action {
        UnknownAaguidAction::Allow => "allow",
        UnknownAaguidAction::Deny => "deny",
    }
}

fn unknown_aaguid_from_str(s: &str) -> Result<UnknownAaguidAction, DbError> {
    match s {
        "allow" => Ok(UnknownAaguidAction::Allow),
        "deny" => Ok(UnknownAaguidAction::Deny),
        other => Err(DbError::Migration(format!(
            "invalid webauthn_attestation_policy.unknown_aaguid: {other}"
        ))),
    }
}

fn uuids_to_strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

fn strings_to_uuids(ids: Vec<String>, field: &str) -> Result<Vec<Uuid>, DbError> {
    ids.into_iter().map(|s| parse_uuid(&s, field)).collect()
}

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct PolicyRow {
    mode: String,
    require_fido_certified: bool,
    min_certification: Option<String>,
    allowed_aaguids: Option<Vec<String>>,
    blocked_aaguids: Vec<String>,
    block_revoked_status: bool,
    /// `None` = "derive from mode" (see `effective_unknown_aaguid`); stored
    /// as NONE rather than as a concrete action, so a policy whose mode later
    /// changes keeps getting the correct default for its new mode.
    unknown_aaguid: Option<String>,
}

impl PolicyRow {
    fn try_into_policy(self) -> Result<WebauthnAttestationPolicy, DbError> {
        Ok(WebauthnAttestationPolicy {
            mode: mode_from_str(&self.mode)?,
            require_fido_certified: self.require_fido_certified,
            min_certification: self
                .min_certification
                .as_deref()
                .map(level_from_str)
                .transpose()?,
            allowed_aaguids: self
                .allowed_aaguids
                .map(|ids| strings_to_uuids(ids, "allowed_aaguids"))
                .transpose()?,
            blocked_aaguids: strings_to_uuids(self.blocked_aaguids, "blocked_aaguids")?,
            block_revoked_status: self.block_revoked_status,
            unknown_aaguid: self
                .unknown_aaguid
                .as_deref()
                .map(unknown_aaguid_from_str)
                .transpose()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the tenant WebAuthn attestation policy
/// repository (D5). One row per tenant, upserted via a deterministic
/// `Uuid::new_v5` record id derived from `tenant_id` — the same pattern
/// `SurrealSettingsRepository` uses, so concurrent writers for the same
/// tenant converge on one row instead of racing a read-then-create.
#[derive(Clone)]
pub struct SurrealWebauthnAttestationPolicyRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealWebauthnAttestationPolicyRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    fn deterministic_id(tenant_id: Uuid) -> Uuid {
        Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("webauthn_attestation_policy:{tenant_id}").as_bytes(),
        )
    }
}

impl<C: Connection> WebauthnAttestationPolicyRepository
    for SurrealWebauthnAttestationPolicyRepository<C>
{
    async fn get_by_tenant(
        &self,
        tenant_id: Uuid,
    ) -> AxiamResult<Option<WebauthnAttestationPolicy>> {
        let mut result = self
            .db
            .current()
            .query("SELECT * FROM webauthn_attestation_policy WHERE tenant_id = $tenant_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PolicyRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_policy()?)),
            None => Ok(None),
        }
    }

    async fn set(
        &self,
        tenant_id: Uuid,
        policy: WebauthnAttestationPolicy,
    ) -> AxiamResult<WebauthnAttestationPolicy> {
        let id_str = Self::deterministic_id(tenant_id).to_string();

        let query = "UPSERT type::record('webauthn_attestation_policy', $id) SET \
             tenant_id = $tenant_id, \
             mode = $mode, \
             require_fido_certified = $require_fido_certified, \
             min_certification = $min_certification, \
             allowed_aaguids = $allowed_aaguids, \
             blocked_aaguids = $blocked_aaguids, \
             block_revoked_status = $block_revoked_status, \
             unknown_aaguid = $unknown_aaguid, \
             created_at = created_at OR time::now(), \
             updated_at = time::now()";

        let result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("mode", mode_to_str(policy.mode).to_string()))
            .bind(("require_fido_certified", policy.require_fido_certified))
            .bind((
                "min_certification",
                policy
                    .min_certification
                    .map(level_to_str)
                    .map(str::to_string),
            ))
            .bind((
                "allowed_aaguids",
                policy.allowed_aaguids.as_deref().map(uuids_to_strings),
            ))
            .bind(("blocked_aaguids", uuids_to_strings(&policy.blocked_aaguids)))
            .bind(("block_revoked_status", policy.block_revoked_status))
            .bind((
                "unknown_aaguid",
                policy
                    .unknown_aaguid
                    .map(|a| unknown_aaguid_to_str(a).to_string()),
            ))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<PolicyRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "webauthn_attestation_policy".into(),
            id: id_str,
        })?;

        // audit hook (D11): `webauthn.policy_updated`. Full audit-log
        // persistence is wired at the REST/server layer (later wave, where
        // the actor identity is known); this structured event is the
        // repository-level half of that hook so the mutation is observable
        // even before that wiring lands.
        tracing::info!(
            action = "webauthn.policy_updated",
            tenant_id = %tenant_id,
            mode = mode_to_str(policy.mode),
            "WebAuthn attestation policy updated"
        );

        row.try_into_policy().map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query("DELETE webauthn_attestation_policy WHERE tenant_id = $tenant_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        tracing::info!(
            action = "webauthn.policy_updated",
            tenant_id = %tenant_id,
            mode = "none",
            "WebAuthn attestation policy deleted (reverted to default)"
        );

        Ok(())
    }
}
