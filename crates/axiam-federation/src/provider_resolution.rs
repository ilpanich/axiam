//! Which federation providers a tenant may sign in with: its own, plus the
//! ones it inherits from its organization.
//!
//! The rule lives here, in one place, because two very different callers ask
//! it: the browser login (the public providers listing, and the start and
//! callback endpoints that must reach exactly the providers the buttons were
//! rendered from) and native sign-in (G-A), which must not be able to reach a
//! provider the browser could not. Before G-A it lived in `axiam-api-rest`,
//! where `axiam-oauth2` could not reach it.

use axiam_core::error::AxiamResult;
use axiam_core::models::federation::FederationConfig;
use axiam_core::models::tenant::TenantKind;
use axiam_core::repository::{FederationConfigRepository, TenantRepository};
use uuid::Uuid;

/// A provider that is effective for a tenant, and where it came from.
#[derive(Debug, Clone)]
pub struct EffectiveProvider {
    /// The provider's configuration, as the listing projection returns it.
    pub config: FederationConfig,
    /// `true` when the config lives in the organization-scope tenant and this
    /// tenant is using it by inheritance.
    pub inherited: bool,
}

/// Every provider a tenant may sign in with.
///
/// The rule:
///
/// * the tenant's own **enabled** configs, plus
/// * the organization tenant's **enabled** configs with
///   `allow_tenant_inheritance`, minus any whose override key the tenant
///   already uses.
///
/// The subtraction deliberately uses the tenant's configs **including disabled
/// ones**. A tenant administrator who created a Google config and disabled it
/// has said something about Google in this tenant, and the something is "no";
/// falling back to the inherited config there would make "disable" mean
/// "re-enable the organization's".
///
/// `organization_id` must be the organization `tenant_id` belongs to; a caller
/// that has only the tenant reads it from the tenant row.
///
/// # Errors
///
/// A datastore failure listing either tenant's configs. A missing
/// organization tenant is not an error: a deployment that predates
/// organization scope has no inheritance, which is what it always had.
pub async fn effective_providers<FC, TR>(
    configs: &FC,
    tenants: &TR,
    organization_id: Uuid,
    tenant_id: Uuid,
) -> AxiamResult<Vec<EffectiveProvider>>
where
    FC: FederationConfigRepository,
    TR: TenantRepository,
{
    let own_all = configs.list_all(tenant_id).await?;

    let mut effective: Vec<EffectiveProvider> = own_all
        .iter()
        .filter(|c| c.enabled)
        .cloned()
        .map(|config| EffectiveProvider {
            config,
            inherited: false,
        })
        .collect();

    // An organization-scope tenant has nothing to inherit *from*; it is the
    // thing others inherit from.
    let org_tenant = match tenants.get_organization_tenant(organization_id).await {
        Ok(t) => t,
        Err(_) => return Ok(effective),
    };
    if org_tenant.id == tenant_id || org_tenant.kind != TenantKind::Organization {
        return Ok(effective);
    }

    let shadowed: Vec<String> = own_all.iter().map(FederationConfig::override_key).collect();

    for config in configs.list_all(org_tenant.id).await? {
        if !config.enabled || !config.allow_tenant_inheritance {
            continue;
        }
        if shadowed.contains(&config.override_key()) {
            continue;
        }
        effective.push(EffectiveProvider {
            config,
            inherited: true,
        });
    }

    Ok(effective)
}
