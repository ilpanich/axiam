//! #613 (T-289) — [`axiam_oauth2::scope_ceiling::ExternalClientScopePolicy`]
//! over the settings repository: the tenant's **effective** `dcr_allowed_scopes`
//! (organization baseline merged with the tenant override, as
//! `SettingsRepository::get_effective_settings` resolves it — the same value
//! the DCR and CIMD validators read).
//!
//! # What is cached, and what is not
//!
//! The `tenant_id → organization_id` mapping comes from
//! [`crate::tenant_org_cache`], which is immutable for a tenant's lifetime and
//! therefore safe to remember (see that module). The **policy** is read fresh
//! on every call: caching it would reintroduce exactly the delay #613 removes,
//! a withdrawn scope still being served after the tenant withdrew it. The cost
//! is paid only for an externally registered client — `axiam_oauth2`'s
//! `scope_ceiling::applies_to` is answered from the client row before this is
//! reached — and it is the read `crate::cimd::materialise_if_cimd` already
//! makes for every URL-shaped `client_id`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::error::AxiamResult;
use axiam_core::repository::{SettingsRepository, TenantRepository};
use axiam_oauth2::scope_ceiling::ExternalClientScopePolicy;
use uuid::Uuid;

use crate::tenant_org_cache::TenantOrgCache;

/// The settings-backed tenant scope policy.
#[derive(Clone)]
pub struct SettingsScopePolicy<TR, ST> {
    tenants: TR,
    settings: ST,
    tenant_org: Arc<TenantOrgCache>,
}

impl<TR, ST> SettingsScopePolicy<TR, ST> {
    /// Build one over the tenant and settings repositories, sharing the
    /// application's `tenant_id → organization_id` cache.
    pub fn new(tenants: TR, settings: ST, tenant_org: Arc<TenantOrgCache>) -> Self {
        Self {
            tenants,
            settings,
            tenant_org,
        }
    }
}

impl<TR, ST> ExternalClientScopePolicy for SettingsScopePolicy<TR, ST>
where
    TR: TenantRepository + Send + Sync,
    ST: SettingsRepository + Send + Sync,
{
    fn allowed_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let org_id = match self.tenant_org.get(tenant_id) {
                Some(org_id) => org_id,
                None => {
                    let tenant = self.tenants.get_by_id(tenant_id).await?;
                    self.tenant_org.insert(tenant_id, tenant.organization_id);
                    tenant.organization_id
                }
            };
            let settings = self
                .settings
                .get_effective_settings(org_id, tenant_id)
                .await?;
            Ok(settings.oidc.dcr_allowed_scopes)
        })
    }
}
