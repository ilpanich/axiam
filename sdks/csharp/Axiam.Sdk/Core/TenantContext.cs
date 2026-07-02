namespace Axiam.Sdk.Core;

/// <summary>
/// Immutable tenant-identity value object required at <c>AxiamClient</c> construction
/// time and propagated on every outgoing request (CONTRACT.md &#167;5: <c>X-Tenant-Id</c>
/// header on REST; <c>x-tenant-id</c> gRPC metadata in a later plan). There is no
/// default-constructible/blank instance — the constructor throws a runtime guard
/// backing the compile-time guarantee that <c>AxiamClient</c>'s own tenant-required
/// constructor provides (SC#1): AXIAM is multi-tenant and there is no default tenant.
/// </summary>
public sealed class TenantContext
{
    /// <summary>
    /// The tenant identifier as supplied by the caller — either a human-readable
    /// tenant slug or a tenant UUID rendered as a string (CONTRACT.md &#167;5 accepts
    /// either form). Never blank.
    /// </summary>
    public string TenantId { get; }

    /// <summary>
    /// Optional organization UUID. Mutually exclusive with <see cref="OrgSlug"/> —
    /// the real AXIAM login/refresh endpoints require an organization identifier
    /// beyond &#167;5's documented tenant-only minimum; supply exactly one of
    /// <see cref="OrgId"/>/<see cref="OrgSlug"/> via <c>AxiamClientOptions</c>.
    /// </summary>
    public Guid? OrgId { get; }

    /// <summary>Optional organization slug. Mutually exclusive with <see cref="OrgId"/>.</summary>
    public string? OrgSlug { get; }

    public TenantContext(string tenantId, Guid? orgId = null, string? orgSlug = null)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "tenantId is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5).",
                nameof(tenantId));
        }

        TenantId = tenantId;
        OrgId = orgId;
        OrgSlug = orgSlug;
    }
}
