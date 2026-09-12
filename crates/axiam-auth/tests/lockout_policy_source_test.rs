//! `LockoutPolicySource` resolution, and what happens when it cannot resolve.
//!
//! `SettingsLockoutPolicy` asks two stores for the tenant's merged lockout
//! policy, and both can fail. Its doc states the rule those failures follow —
//! "failure must not mean 'no lockout'" — because the alternative is an
//! account-lockout control that a settings-store outage silently switches off,
//! which is the one moment an attacker most wants it off.
//!
//! Doubles rather than a live database: an unreachable settings store is a
//! state a real repository will not produce on demand, and it is the state
//! under test.

use axiam_auth::lockout::{LockoutPolicySource, SettingsLockoutPolicy, StaticLockoutPolicy};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::settings::{
    LockoutPolicy, SecuritySettings, SetOrgSettings, SetTenantOverride, TenantSettingsOverride,
    settings_from_org_input, system_defaults,
};
use axiam_core::models::tenant::{CreateTenant, Tenant, TenantKind, TenantStatus, UpdateTenant};
use axiam_core::repository::{PaginatedResult, Pagination, SettingsRepository, TenantRepository};
use chrono::Utc;
use uuid::Uuid;

/// Deliberately unlike any stored policy, so a test that reads it knows the
/// fallback ran rather than a coincidence.
fn a_default_policy() -> LockoutPolicy {
    LockoutPolicy {
        max_failed_login_attempts: 3,
        lockout_duration_secs: 900,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 86_400,
    }
}

/// The policy a healthy settings store would answer with.
fn a_stored_policy() -> LockoutPolicy {
    LockoutPolicy {
        max_failed_login_attempts: 7,
        lockout_duration_secs: 60,
        lockout_backoff_multiplier: 1.5,
        max_lockout_duration_secs: 3_600,
    }
}

fn a_tenant() -> Tenant {
    let now = Utc::now();
    Tenant {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        name: "Production".into(),
        slug: "production".into(),
        status: TenantStatus::Active,
        kind: TenantKind::Standard,
        metadata: serde_json::Value::Null,
        created_at: now,
        updated_at: now,
    }
}

// --- doubles ---------------------------------------------------------------

struct Tenants {
    answer: Option<Tenant>,
}

impl TenantRepository for Tenants {
    async fn create(&self, _input: CreateTenant) -> AxiamResult<Tenant> {
        unreachable!("not exercised by this test")
    }
    async fn get_by_id(&self, _id: Uuid) -> AxiamResult<Tenant> {
        self.answer
            .clone()
            .ok_or_else(|| AxiamError::Internal("tenant store unreachable".into()))
    }
    async fn get_by_slug(&self, _org: Uuid, _slug: &str) -> AxiamResult<Tenant> {
        unreachable!("not exercised by this test")
    }
    async fn update(&self, _id: Uuid, _input: UpdateTenant) -> AxiamResult<Tenant> {
        unreachable!("not exercised by this test")
    }
    async fn delete(&self, _id: Uuid) -> AxiamResult<()> {
        unreachable!("not exercised by this test")
    }
    async fn list_by_organization(
        &self,
        _org: Uuid,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<Tenant>> {
        unreachable!("not exercised by this test")
    }
    async fn get_organization_tenant(&self, _org: Uuid) -> AxiamResult<Tenant> {
        unreachable!("not exercised by this test")
    }
}

struct Settings {
    answer: Option<LockoutPolicy>,
}

impl SettingsRepository for Settings {
    async fn get_org_settings(&self, _org: Uuid) -> AxiamResult<SecuritySettings> {
        unreachable!("not exercised by this test")
    }
    async fn set_org_settings(
        &self,
        _org: Uuid,
        _input: SetOrgSettings,
    ) -> AxiamResult<SecuritySettings> {
        unreachable!("not exercised by this test")
    }
    async fn get_tenant_override(
        &self,
        _tenant: Uuid,
    ) -> AxiamResult<Option<TenantSettingsOverride>> {
        unreachable!("not exercised by this test")
    }
    async fn set_tenant_override(
        &self,
        _tenant: Uuid,
        _input: SetTenantOverride,
    ) -> AxiamResult<TenantSettingsOverride> {
        unreachable!("not exercised by this test")
    }
    async fn store_effective_tenant_settings(
        &self,
        _tenant: Uuid,
        _settings: SecuritySettings,
    ) -> AxiamResult<SecuritySettings> {
        unreachable!("not exercised by this test")
    }
    async fn delete_tenant_override(&self, _tenant: Uuid) -> AxiamResult<()> {
        unreachable!("not exercised by this test")
    }
    async fn get_effective_settings(
        &self,
        _org: Uuid,
        _tenant: Uuid,
    ) -> AxiamResult<SecuritySettings> {
        match &self.answer {
            Some(lockout) => {
                // Built the way production builds one, so the only thing this
                // double changes is the field under test.
                let mut settings =
                    settings_from_org_input(Uuid::new_v4(), Uuid::new_v4(), &system_defaults());
                settings.lockout = lockout.clone();
                Ok(settings)
            }
            None => Err(AxiamError::Internal("settings store unreachable".into())),
        }
    }
}

// --- tests -----------------------------------------------------------------

#[tokio::test]
async fn a_resolvable_tenant_meters_against_its_own_stored_policy() {
    // The baseline the failure cases are measured against: when both stores
    // answer, the tenant's merged policy is what is used — not the default.
    let source = SettingsLockoutPolicy::new(
        Settings {
            answer: Some(a_stored_policy()),
        },
        Tenants {
            answer: Some(a_tenant()),
        },
        a_default_policy(),
    );

    let policy = source.policy_for(Uuid::new_v4()).await;

    assert_eq!(policy.max_failed_login_attempts, 7);
    assert_eq!(policy.lockout_duration_secs, 60);
}

#[tokio::test]
async fn an_unresolvable_tenant_still_locks_accounts_on_the_default_policy() {
    // Not "no policy" and not "no lockout": an unknown or unreachable tenant
    // falls back to the deployment default, so brute force is still metered
    // while the tenant lookup is broken.
    let source = SettingsLockoutPolicy::new(
        Settings {
            answer: Some(a_stored_policy()),
        },
        Tenants { answer: None },
        a_default_policy(),
    );

    let policy = source.policy_for(Uuid::new_v4()).await;

    assert_eq!(
        policy.max_failed_login_attempts, 3,
        "a tenant that cannot be resolved must still be metered, on the default"
    );
    assert!(
        policy.max_failed_login_attempts > 0,
        "a fallback of zero attempts would be a lockout that never engages"
    );
}

#[tokio::test]
async fn an_unreachable_settings_store_still_locks_accounts_on_the_default_policy() {
    // The second failure, and the more likely one in production: the tenant
    // resolves but its settings do not. Same rule — an outage in the settings
    // store must not be a window in which lockout is off.
    let source = SettingsLockoutPolicy::new(
        Settings { answer: None },
        Tenants {
            answer: Some(a_tenant()),
        },
        a_default_policy(),
    );

    let policy = source.policy_for(Uuid::new_v4()).await;

    assert_eq!(
        policy.max_failed_login_attempts, 3,
        "unreadable settings must fall back to the default, not to no lockout"
    );
    assert_eq!(policy.lockout_duration_secs, 900);
}

#[tokio::test]
async fn the_static_source_answers_the_policy_it_was_built_with() {
    // The composition root's no-settings-store path, and what most tests run
    // against — worth pinning so a change there does not quietly alter every
    // suite that depends on it.
    let source = StaticLockoutPolicy(a_stored_policy());

    let policy = source.policy_for(Uuid::new_v4()).await;

    assert_eq!(policy.max_failed_login_attempts, 7);
    assert_eq!(policy.max_lockout_duration_secs, 3_600);
}
