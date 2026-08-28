#!/usr/bin/env python3
"""Derive the canonical SDK **management** operation registry from ``openapi.json``.

Why this exists
---------------
CONTRACT.md §1 locks the SDK method vocabulary, and it locks it by hand: eight
rows in a Markdown table, written once and reviewed by a human every time they
change. That works for eight operations. §27 adds roughly a hundred and thirty,
across twenty-two namespaces, in eleven languages -- and the same hand-maintained
table would be wrong within a release.

So §27's vocabulary is not maintained by hand. It is *derived*, here, from the
one artifact that already has to be correct: the server's own OpenAPI export.
This script is the single place where an HTTP route becomes an SDK method name,
and ``sdks/management-registry.json`` -- the file it emits -- is what all eleven
SDK code generators read. A route that is not in this script's ``NAMESPACES``
table reaches no SDK, and a name that is in the table but not on the server
fails the build.

The two gates, and the failure each one prevents
------------------------------------------------
``--check`` runs both in CI (job **Architecture Invariants**):

1. **Every registry entry resolves to a live route.** Prevents the registry
   naming an endpoint that was renamed or removed on the server -- eleven SDKs
   would ship a method that 404s, and the first person to find out would be a
   user.

2. **Every management route is claimed by exactly one registry entry.** This is
   the gate that actually earns its keep. Without it, adding a route to
   ``axiam-api-rest`` is enough to create SDK surface that silently does not
   exist: the spec regenerates, nothing fails, and the endpoint is simply
   unreachable from every SDK until somebody notices. Routes that are
   deliberately *not* management surface must say so in ``EXCLUDED_TAGS`` or
   ``EXCLUDED_OPERATIONS`` with a reason -- the same discipline
   ``check-crate-layering.py`` applies to ``TEST_ONLY_INVERSIONS``.

Usage
-----
    scripts/gen-management-registry.py            # regenerate the registry
    scripts/gen-management-registry.py --check    # verify it is in sync (CI)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
OPENAPI_PATH = REPO_ROOT / "sdks" / "openapi.json"
REGISTRY_PATH = REPO_ROOT / "sdks" / "management-registry.json"

# ---------------------------------------------------------------------------
# What is deliberately NOT management surface
# ---------------------------------------------------------------------------
# Each tag here is already covered by a numbered contract section, or is
# excluded by the §27.0 boundary. The reason is not decoration: it is what a
# reviewer reads when a new route lands under one of these tags and the gate
# tells them the route is unclaimed.
EXCLUDED_TAGS: dict[str, str] = {
    "auth": "§1 login/MFA/refresh/logout, §23 OPAQUE, §25 account lifecycle",
    "authz": "§1 check_access / batch_check",
    "oauth2": "§12 RP helpers, §14 device grant, §15 token exchange, §26 PAR",
    "oidc": "§12 discovery/JWKS; /oauth2/userinfo is §1.1 gRPC-only by design",
    "uma": "§20 UMA 2.0 protection API and ticket grant",
    "webauthn": "§24 WebAuthn ceremonies -- credential I/O, not administration",
    "federation-sso": "§12 public SSO entry points, driven by the RP helpers",
    "device": "§14 device-grant user-interaction endpoints",
}

# Individual routes excluded from an otherwise-included tag.
EXCLUDED_OPERATIONS: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/organizations"): (
        "§27.0 boundary -- provisioning an organization is a platform-operator "
        "act performed out of band, never from a tenant-scoped SDK client"
    ),
    ("DELETE", "/api/v1/organizations/{org_id}"): (
        "§27.0 boundary -- destroying an organization destroys every tenant "
        "under it; deliberately unreachable from an SDK"
    ),
    ("POST", "/api/v1/users/me/resend-verification"): (
        "§25 account lifecycle, not §27 management -- this is self-service on "
        "the caller's OWN record, the authenticated sibling of the excluded "
        "`auth`-tagged POST /auth/resend-verification. §27 is about "
        "administering other principals; it is only under the `users` tag "
        "because of where the route sits"
    ),
}

# ---------------------------------------------------------------------------
# The vocabulary
# ---------------------------------------------------------------------------
# namespace -> (doc, [(operation, METHOD, path), ...])
#
# Operation names are canonical and language-neutral: each SDK casts them into
# its own casing per §27.3. They are chosen so that the five CRUD verbs read
# identically in every namespace (list/create/get/update/delete) and anything
# beyond CRUD says what it does.
NAMESPACES: dict[str, dict[str, Any]] = {
    "organizations": {
        "doc": "Organizations an SDK client may read and configure. Creation and "
               "deletion are outside the SDK boundary (§27.0).",
        "operations": [
            ("list", "GET", "/api/v1/organizations"),
            ("get", "GET", "/api/v1/organizations/{org_id}"),
            ("update", "PUT", "/api/v1/organizations/{org_id}"),
        ],
    },
    "tenants": {
        "doc": "Tenants within an organization -- the isolation boundary every "
               "other namespace is scoped to.",
        "operations": [
            ("list", "GET", "/api/v1/organizations/{org_id}/tenants"),
            ("create", "POST", "/api/v1/organizations/{org_id}/tenants"),
            ("get", "GET", "/api/v1/organizations/{org_id}/tenants/{tenant_id}"),
            ("update", "PUT", "/api/v1/organizations/{org_id}/tenants/{tenant_id}"),
            ("delete", "DELETE", "/api/v1/organizations/{org_id}/tenants/{tenant_id}"),
            # T-118: `delete` refuses unless this ran in the last six hours, so
            # it is management surface in the strongest sense -- an SDK that
            # cannot call it cannot delete a tenant at all.
            ("export_audit", "POST",
             "/api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export"),
        ],
    },
    "users": {
        "doc": "Users within the client's tenant, and the administrative side of "
               "their second factor and lockout state.",
        "operations": [
            ("list", "GET", "/api/v1/users"),
            ("create", "POST", "/api/v1/users"),
            ("get", "GET", "/api/v1/users/{user_id}"),
            ("update", "PUT", "/api/v1/users/{user_id}"),
            ("delete", "DELETE", "/api/v1/users/{user_id}"),
            ("list_mfa_methods", "GET", "/api/v1/users/{user_id}/mfa-methods"),
            ("delete_mfa_method", "DELETE", "/api/v1/users/{user_id}/mfa-methods/{method_id}"),
            ("reset_mfa", "POST", "/api/v1/users/{user_id}/reset-mfa"),
            ("unlock", "POST", "/api/v1/users/{user_id}/unlock"),
            ("list_roles", "GET", "/api/v1/users/{user_id}/roles"),
        ],
    },
    "groups": {
        "doc": "Named collections of users. Roles assigned to a group are "
               "inherited by every member.",
        "operations": [
            ("list", "GET", "/api/v1/groups"),
            ("create", "POST", "/api/v1/groups"),
            ("get", "GET", "/api/v1/groups/{group_id}"),
            ("update", "PUT", "/api/v1/groups/{group_id}"),
            ("delete", "DELETE", "/api/v1/groups/{group_id}"),
            ("list_members", "GET", "/api/v1/groups/{group_id}/members"),
            ("add_member", "POST", "/api/v1/groups/{group_id}/members"),
            ("remove_member", "DELETE", "/api/v1/groups/{group_id}/members/{user_id}"),
            ("list_roles", "GET", "/api/v1/groups/{group_id}/roles"),
            # A group is a collection of PRINCIPALS, and a machine identity
            # inherits its roles exactly as a person does -- which is the shape a
            # device fleet wants: granted and revoked as one thing rather than
            # one edge per device.
            ("list_service_accounts", "GET", "/api/v1/groups/{group_id}/service-accounts"),
            ("add_service_account", "POST", "/api/v1/groups/{group_id}/service-accounts"),
            (
                "remove_service_account",
                "DELETE",
                "/api/v1/groups/{group_id}/service-accounts/{service_account_id}",
            ),
        ],
    },
    "roles": {
        "doc": "Roles, their permission sets, and their assignment to users and "
               "groups.",
        "operations": [
            ("list", "GET", "/api/v1/roles"),
            ("create", "POST", "/api/v1/roles"),
            ("get", "GET", "/api/v1/roles/{role_id}"),
            ("update", "PUT", "/api/v1/roles/{role_id}"),
            ("delete", "DELETE", "/api/v1/roles/{role_id}"),
            ("list_users", "GET", "/api/v1/roles/{role_id}/users"),
            ("assign_to_user", "POST", "/api/v1/roles/{role_id}/users"),
            ("unassign_from_user", "DELETE", "/api/v1/roles/{role_id}/users/{user_id}"),
            ("list_groups", "GET", "/api/v1/roles/{role_id}/groups"),
            ("assign_to_group", "POST", "/api/v1/roles/{role_id}/groups"),
            ("unassign_from_group", "DELETE", "/api/v1/roles/{role_id}/groups/{group_id}"),
            ("list_permissions", "GET", "/api/v1/roles/{role_id}/permissions"),
            ("grant_permission", "POST", "/api/v1/roles/{role_id}/permissions"),
            ("revoke_permission", "DELETE", "/api/v1/roles/{role_id}/permissions/{permission_id}"),
            # The authorization engine has always applied RBAC to a service
            # account exactly as it does to a user -- it takes no "is this a
            # machine" flag to branch on. These are the operations that create
            # the grant, without which a machine identity could authenticate and
            # then do nothing.
            ("list_service_accounts", "GET", "/api/v1/roles/{role_id}/service-accounts"),
            ("assign_to_service_account", "POST", "/api/v1/roles/{role_id}/service-accounts"),
            (
                "unassign_from_service_account",
                "DELETE",
                "/api/v1/roles/{role_id}/service-accounts/{service_account_id}",
            ),
        ],
    },
    "permissions": {
        "doc": "Permissions -- an action on a resource, optionally narrowed by a "
               "scope.",
        "operations": [
            ("list", "GET", "/api/v1/permissions"),
            ("create", "POST", "/api/v1/permissions"),
            ("get", "GET", "/api/v1/permissions/{permission_id}"),
            ("update", "PUT", "/api/v1/permissions/{permission_id}"),
            ("delete", "DELETE", "/api/v1/permissions/{permission_id}"),
        ],
    },
    "resources": {
        "doc": "The resource hierarchy role assignments cascade down.",
        "operations": [
            ("list", "GET", "/api/v1/resources"),
            ("create", "POST", "/api/v1/resources"),
            ("get", "GET", "/api/v1/resources/{resource_id}"),
            ("update", "PUT", "/api/v1/resources/{resource_id}"),
            ("delete", "DELETE", "/api/v1/resources/{resource_id}"),
            ("list_children", "GET", "/api/v1/resources/{resource_id}/children"),
            ("list_ancestors", "GET", "/api/v1/resources/{resource_id}/ancestors"),
        ],
    },
    "scopes": {
        "doc": "Sub-resource granularity, always addressed under their resource.",
        "operations": [
            ("list", "GET", "/api/v1/resources/{resource_id}/scopes"),
            ("create", "POST", "/api/v1/resources/{resource_id}/scopes"),
            ("get", "GET", "/api/v1/resources/{resource_id}/scopes/{scope_id}"),
            ("update", "PUT", "/api/v1/resources/{resource_id}/scopes/{scope_id}"),
            ("delete", "DELETE", "/api/v1/resources/{resource_id}/scopes/{scope_id}"),
        ],
    },
    "service_accounts": {
        "doc": "Machine identities, their secrets, and the certificate a "
               "device-bound one authenticates with.",
        "operations": [
            ("list", "GET", "/api/v1/service-accounts"),
            ("create", "POST", "/api/v1/service-accounts"),
            ("get", "GET", "/api/v1/service-accounts/{sa_id}"),
            ("update", "PUT", "/api/v1/service-accounts/{sa_id}"),
            ("delete", "DELETE", "/api/v1/service-accounts/{sa_id}"),
            ("rotate_secret", "POST", "/api/v1/service-accounts/{sa_id}/rotate-secret"),
            ("bind_certificate", "POST", "/api/v1/service-accounts/{sa_id}/bind-certificate"),
            # Direct AND group-inherited, each carrying the resource scope of the
            # grant -- which is what the revoke call needs: omitting
            # `resource_id` removes the GLOBAL assignment specifically.
            ("list_roles", "GET", "/api/v1/service-accounts/{service_account_id}/roles"),
            ("list_groups", "GET", "/api/v1/service-accounts/{service_account_id}/groups"),
        ],
    },
    "certificates": {
        "doc": "End-entity X.509 certificates -- the ones issued to users, "
               "services and IoT devices.",
        "operations": [
            ("list", "GET", "/api/v1/certificates"),
            ("generate", "POST", "/api/v1/certificates"),
            ("get", "GET", "/api/v1/certificates/{id}"),
            ("revoke", "POST", "/api/v1/certificates/{id}/revoke"),
        ],
    },
    "ca_certificates": {
        "doc": "Organization CAs and the per-tenant signing CAs chained beneath "
               "them.",
        "operations": [
            ("list", "GET", "/api/v1/organizations/{org_id}/ca-certificates"),
            ("generate", "POST", "/api/v1/organizations/{org_id}/ca-certificates"),
            ("import_ca", "POST", "/api/v1/organizations/{org_id}/ca-certificates/import"),
            ("get", "GET", "/api/v1/organizations/{org_id}/ca-certificates/{id}"),
            ("revoke", "POST", "/api/v1/organizations/{org_id}/ca-certificates/{id}/revoke"),
            ("migrate_custody", "POST",
             "/api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody"),
            ("set_mtls_trust_anchor", "PUT",
             "/api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor"),
            ("list_signing_cas", "GET",
             "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas"),
            ("generate_signing_ca", "POST",
             "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas"),
            ("sign_signing_ca_csr", "POST",
             "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr"),
        ],
    },
    "pgp_keys": {
        "doc": "OpenPGP keys used for audit signing and encrypted data export.",
        "operations": [
            ("list", "GET", "/api/v1/pgp-keys"),
            ("generate", "POST", "/api/v1/pgp-keys"),
            ("get", "GET", "/api/v1/pgp-keys/{id}"),
            ("revoke", "POST", "/api/v1/pgp-keys/{id}/revoke"),
            ("encrypt", "POST", "/api/v1/pgp-keys/{id}/encrypt"),
            ("sign_audit_batch", "POST", "/api/v1/pgp-keys/sign-audit-batch"),
        ],
    },
    "webhooks": {
        "doc": "Outbound event notifications. Delivery signatures are verified "
               "with the §13 helper, which this namespace configures.",
        "operations": [
            ("list", "GET", "/api/v1/webhooks"),
            ("create", "POST", "/api/v1/webhooks"),
            ("get", "GET", "/api/v1/webhooks/{id}"),
            ("update", "PUT", "/api/v1/webhooks/{id}"),
            ("delete", "DELETE", "/api/v1/webhooks/{id}"),
        ],
    },
    "oauth2_clients": {
        "doc": "Registered OAuth2/OIDC clients -- the registration half of what "
               "§12, §21 and §26 then speak to.",
        "operations": [
            ("list", "GET", "/api/v1/oauth2-clients"),
            ("create", "POST", "/api/v1/oauth2-clients"),
            ("get", "GET", "/api/v1/oauth2-clients/{id}"),
            ("update", "PUT", "/api/v1/oauth2-clients/{id}"),
            ("delete", "DELETE", "/api/v1/oauth2-clients/{id}"),
        ],
    },
    "federation": {
        "doc": "Upstream IdP configuration and the per-user links it produces.",
        "operations": [
            ("list_configs", "GET", "/api/v1/federation-configs"),
            ("create_config", "POST", "/api/v1/federation-configs"),
            ("get_config", "GET", "/api/v1/federation-configs/{id}"),
            ("update_config", "PUT", "/api/v1/federation-configs/{id}"),
            ("delete_config", "DELETE", "/api/v1/federation-configs/{id}"),
            ("list_user_links", "GET", "/api/v1/federation-links/user/{user_id}"),
            ("delete_link", "DELETE", "/api/v1/federation-links/{id}"),
            ("oidc_authorize", "POST", "/api/v1/federation/oidc/authorize"),
            ("oidc_callback", "POST", "/api/v1/federation/oidc/callback"),
        ],
    },
    "notification_rules": {
        "doc": "Which events raise a notification, and to whom.",
        "operations": [
            ("list", "GET", "/api/v1/notification-rules"),
            ("create", "POST", "/api/v1/notification-rules"),
            ("get", "GET", "/api/v1/notification-rules/{id}"),
            ("update", "PUT", "/api/v1/notification-rules/{id}"),
            ("delete", "DELETE", "/api/v1/notification-rules/{id}"),
        ],
    },
    "email_config": {
        "doc": "Transactional-mail transport, configurable at organization level "
               "and overridable per tenant.",
        "operations": [
            ("get_org", "GET", "/api/v1/organizations/{org_id}/email-config"),
            ("set_org", "PUT", "/api/v1/organizations/{org_id}/email-config"),
            ("delete_org", "DELETE", "/api/v1/organizations/{org_id}/email-config"),
            ("test_org", "POST", "/api/v1/organizations/{org_id}/email-config/test"),
            ("get_tenant", "GET", "/api/v1/tenants/{tenant_id}/email-config"),
            ("set_tenant", "PUT", "/api/v1/tenants/{tenant_id}/email-config"),
            ("delete_tenant", "DELETE", "/api/v1/tenants/{tenant_id}/email-config"),
            ("test_tenant", "POST", "/api/v1/tenants/{tenant_id}/email-config/test"),
        ],
    },
    "settings": {
        "doc": "Effective settings, and the organization/tenant layers they "
               "resolve from.",
        "operations": [
            ("get_org", "GET", "/api/v1/organizations/{org_id}/settings"),
            ("set_org", "PUT", "/api/v1/organizations/{org_id}/settings"),
            ("get_effective", "GET", "/api/v1/settings"),
            ("set_effective", "PUT", "/api/v1/settings"),
            ("get_tenant_override", "GET", "/api/v1/tenants/{tenant_id}/settings"),
            ("set_tenant_override", "PUT", "/api/v1/tenants/{tenant_id}/settings"),
            ("delete_tenant_override", "DELETE", "/api/v1/tenants/{tenant_id}/settings"),
        ],
    },
    "scim_tokens": {
        "doc": "Bearer tokens for the SCIM 2.0 provisioning endpoint.",
        "operations": [
            ("list", "GET", "/api/v1/scim-tokens"),
            ("create", "POST", "/api/v1/scim-tokens"),
            ("revoke", "DELETE", "/api/v1/scim-tokens/{id}"),
        ],
    },
    "reactors": {
        "doc": "Registration of §22 AMQP extension actors -- the admin surface "
               "§22.9 describes, which no SDK could previously reach.",
        "operations": [
            ("list", "GET", "/api/v1/reactors"),
            ("create", "POST", "/api/v1/reactors"),
            ("get", "GET", "/api/v1/reactors/{id}"),
            ("update", "PUT", "/api/v1/reactors/{id}"),
            ("delete", "DELETE", "/api/v1/reactors/{id}"),
            ("list_events", "GET", "/api/v1/reactors/events"),
        ],
    },
    "webauthn_policy": {
        "doc": "Per-tenant attestation policy governing the §24 ceremonies, and "
               "the compliance report over it.",
        "operations": [
            ("get", "GET", "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy"),
            ("set", "PUT", "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy"),
            ("compliance_report", "GET",
             "/api/v1/tenants/{tenant_id}/webauthn/compliance-report"),
        ],
    },
    "audit": {
        "doc": "Append-only audit log, read-only by construction.",
        "operations": [
            ("list", "GET", "/api/v1/audit-logs"),
            ("list_system", "GET", "/api/v1/audit-logs/system"),
        ],
    },
    "privacy": {
        "doc": "GDPR self-service: the authenticated account's own export and "
               "erasure. Scoped to the caller, never to another user.",
        "operations": [
            ("request_export", "POST", "/api/v1/account/export"),
            ("download_export", "GET", "/api/v1/account/export/{token}"),
            ("request_delete", "POST", "/api/v1/account/delete"),
            ("cancel_delete", "GET", "/api/v1/auth/account/delete/cancel"),
        ],
    },
    "platform": {
        "doc": "Deployment-level probes and FIDO metadata state. Unauthenticated "
               "where the server leaves them so.",
        "operations": [
            ("health", "GET", "/health"),
            ("ready", "GET", "/ready"),
            ("mds_status", "GET", "/api/v1/mds/status"),
            ("mds_refresh", "POST", "/api/v1/mds/refresh"),
        ],
    },
}

PAGINATION_QUERY = {"offset", "limit"}

# ---------------------------------------------------------------------------
# Fields that carry secret material (§27.5 / §7)
# ---------------------------------------------------------------------------
# Curated as (schema, field) pairs rather than sniffed by name, because both
# directions of a guess are expensive and a bare name is genuinely ambiguous
# here. `password` is a secret on `CreateUserRequest` and a *policy object*
# (`PasswordPolicy`) on `SecuritySettings`; a name-based rule wraps the policy,
# and an SDK annoying enough to fight gets unwrapped everywhere. In the other
# direction a missed field ships a credential straight into a log.
#
# Everything here is either returned exactly once and never again, or is a
# credential the caller supplies. A new one is added to this set in the same
# commit that adds the field to the server.
SENSITIVE_FIELDS: frozenset[tuple[str, str]] = frozenset({
    ("ServiceAccountCreatedResponse", "client_secret"),
    ("RotateSecretResponse", "client_secret"),
    ("OAuth2ClientCreatedResponse", "client_secret"),
    ("CreateFederationConfigRequest", "client_secret"),
    ("UpdateFederationConfigRequest", "client_secret"),
    ("GeneratedCertificate", "private_key_pem"),
    ("GeneratedCaCertificate", "private_key_pem"),
    ("ImportCaCertificateRequest", "private_key_pem"),
    ("GeneratedPgpKey", "private_key_armored"),
    ("CreateScimTokenResponse", "provisioning_token"),
    ("CreateUserRequest", "password"),
    ("CreateWebhookRequest", "secret"),
    ("UpdateWebhookRequest", "secret"),
})


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    node: Any = spec
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def _flat_properties(
    spec: dict[str, Any], name: str | None, _seen: frozenset[str] = frozenset()
) -> set[str]:
    """Every property name of a component schema, ``allOf`` composition resolved.

    The one-time-reveal responses are all ``allOf`` compositions -- a
    ``GeneratedCertificate`` is a ``Certificate`` plus ``private_key_pem`` --
    so a generator reading ``properties`` alone sees an empty object and wraps
    nothing.
    """
    if not name:
        return set()
    name = name.lstrip("[]")
    if name in _seen:
        return set()
    schema = spec["components"]["schemas"].get(name)
    if schema is None:
        return set()
    out = set(schema.get("properties", {}))
    for sub in schema.get("allOf", []):
        if "$ref" in sub:
            out |= _flat_properties(spec, sub["$ref"].rsplit("/", 1)[-1], _seen | {name})
        else:
            out |= set(sub.get("properties", {}))
    return out


def _update_style(spec: dict[str, Any], method: str, schema: str | None) -> str | None:
    """Classify a ``PUT`` body as a sparse update or a full replacement.

    Both shapes live on this surface and they are not interchangeable. Most
    update bodies are entirely optional -- ``UpdateUserRequest`` has four
    nullable fields and no required one -- so a PUT carrying only ``email``
    changes only the email. But ``SetOrgSettings`` requires twenty fields, and
    ``PUT /api/v1/organizations/{org_id}/settings`` with a subset does not
    partially update anything: it is a replacement, and the fields left out are
    gone.

    An SDK that models both as "pass what you want to change" silently wipes a
    tenant's security policy the first time someone raises a lockout threshold.
    Generators read this field to pick the right shape: an optional-everything
    patch type for ``sparse``, a required-everything value type for ``replace``.
    """
    if method != "PUT" or not schema:
        return None
    component = spec["components"]["schemas"].get(schema, {})
    return "replace" if component.get("required") else "sparse"


def _sensitive(spec: dict[str, Any], name: str | None) -> list[str]:
    """Which of a schema's fields §27.5 requires wrapped in ``Sensitive<T>``.

    Matched against the schema the field is *declared* on, following ``allOf``,
    so a composition inherits its parent's secrets without restating them.
    """
    if not name:
        return []
    bare = name.lstrip("[]")
    owners = {bare} | _composed_from(spec, bare)
    present = _flat_properties(spec, bare)
    return sorted({f for (sc, f) in SENSITIVE_FIELDS if sc in owners and f in present})


def _composed_from(
    spec: dict[str, Any], name: str, _seen: frozenset[str] = frozenset()
) -> set[str]:
    """Every schema ``name`` inherits from via ``allOf``, transitively."""
    if name in _seen:
        return set()
    schema = spec["components"]["schemas"].get(name)
    if schema is None:
        return set()
    out: set[str] = set()
    for sub in schema.get("allOf", []):
        if "$ref" in sub:
            parent = sub["$ref"].rsplit("/", 1)[-1]
            out.add(parent)
            out |= _composed_from(spec, parent, _seen | {name})
    return out


def _structural_index(spec: dict[str, Any]) -> dict[str, str]:
    """Map a normalized component schema back to its name.

    The server's export inlines the element schema of every paginated envelope
    instead of ``$ref``-ing it -- ``GET /api/v1/users`` carries a full user
    object under ``items.items`` rather than a reference to ``UserResponse``,
    even though ``UserResponse`` is right there in ``components`` and is what
    ``GET /api/v1/users/{user_id}`` returns.

    Generators need a *name*, because an anonymous element type means each of
    the twenty list operations would mint its own duplicate model and callers
    could not pass the result of a list to anything expecting the item type.
    Matching the inline schema structurally recovers the name the export lost;
    all twenty resolve. An element that genuinely has no counterpart stays
    ``None`` and the generator falls back to a namespace-derived name.
    """
    return {json.dumps(v, sort_keys=True): k for k, v in spec["components"]["schemas"].items()}


def _projection_adds(schema: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The properties an ``allOf`` projection adds on top of its named base.

    ``GET /api/v1/certificates`` answers ``Certificate`` plus one resolved graph
    edge, ``bound_service_account_id``, and the server expresses that as an
    ``allOf`` of the ``$ref`` and an anonymous object. Without this, a generator
    sees only the base name and the extra field is invisible -- which is how the
    field shipped in ``openapi.json`` and reached no SDK.
    """
    if not schema or "allOf" not in schema:
        return []
    adds: list[dict[str, Any]] = []
    for sub in schema["allOf"]:
        if "$ref" in sub:
            continue
        for name, prop in sub.get("properties", {}).items():
            entry: dict[str, Any] = {"name": name, "type": prop.get("type")}
            if "format" in prop:
                entry["format"] = prop["format"]
            entry["required"] = name in sub.get("required", [])
            adds.append(entry)
    return adds


def _schema_name(
    schema: dict[str, Any] | None, index: dict[str, str] | None = None
) -> str | None:
    """Name a schema for the generators: a ``$ref`` target, a structural match, or ``None``."""
    if not schema:
        return None
    if "$ref" in schema:
        return schema["$ref"].rsplit("/", 1)[-1]
    if schema.get("type") == "array":
        inner = _schema_name(schema.get("items"), index)
        return f"[]{inner}" if inner else None
    if "allOf" in schema:
        # A projection: one named base plus anonymous additions. Name the base,
        # because that is the type a caller passes onward; `_projection_adds`
        # carries what the projection put on top of it. Returning `None` here --
        # which is what happened before `certificates.list` grew its extra
        # field -- makes the whole operation untyped over one added property,
        # and crashes a generator that assumes a page has an element name.
        named = [_schema_name(sub, index) for sub in schema["allOf"]]
        named = [n for n in named if n]
        if len(named) == 1:
            return named[0]
        return None
    if index is not None:
        return index.get(json.dumps(schema, sort_keys=True))
    return None


def _shape(
    status: int, kind: str, element: dict[str, Any] | None, index: dict[str, str]
) -> dict[str, Any]:
    """One response shape, with any ``allOf`` projection recorded beside its base.

    ``projected_fields`` is omitted entirely when empty, so the 145 operations
    that are not projections keep the shape they had -- a key present on every
    entry with an empty list would rewrite the whole registry to say nothing.
    """
    shape: dict[str, Any] = {"status": status, "kind": kind, "schema": _schema_name(element, index)}
    adds = _projection_adds(element)
    if adds:
        shape["projected_fields"] = adds
    return shape


def _response_shape(
    spec: dict[str, Any], op: dict[str, Any], index: dict[str, str]
) -> dict[str, Any]:
    """Classify the success response: none / object / array / paginated envelope."""
    for status in ("200", "201", "202", "204"):
        resp = op.get("responses", {}).get(status)
        if resp is None:
            continue
        content = resp.get("content", {}).get("application/json")
        if content is None:
            return {"status": int(status), "kind": "none", "schema": None}
        schema = content["schema"]
        if "$ref" in schema:
            resolved = _resolve_ref(spec, schema["$ref"])
        else:
            resolved = schema
        if resolved.get("type") == "array":
            return _shape(int(status), "array", resolved.get("items"), index)
        props = resolved.get("properties", {})
        if {"items", "total", "offset", "limit"} <= set(props):
            return _shape(int(status), "page", props["items"].get("items"), index)
        return _shape(int(status), "object", schema, index)
    raise SystemExit(f"no success response on {op.get('operationId')!r}")


def build_registry(spec: dict[str, Any]) -> dict[str, Any]:
    paths = spec["paths"]
    index = _structural_index(spec)
    namespaces: dict[str, Any] = {}
    claimed: set[tuple[str, str]] = set()

    for ns_name, ns in NAMESPACES.items():
        ops: dict[str, Any] = {}
        for op_name, method, path in ns["operations"]:
            item = paths.get(path)
            if item is None:
                raise SystemExit(
                    f"registry names {ns_name}.{op_name} -> {method} {path}, "
                    f"which is not a path in openapi.json"
                )
            op = item.get(method.lower())
            if op is None:
                raise SystemExit(
                    f"registry names {ns_name}.{op_name} -> {method} {path}, "
                    f"but that path has no {method} operation"
                )
            claimed.add((method, path))

            params = op.get("parameters", [])
            path_params = [
                {"name": p["name"], "format": p.get("schema", {}).get("format", "string")}
                for p in params
                if p["in"] == "path"
            ]
            query_params = [
                {
                    "name": p["name"],
                    "required": bool(p.get("required")),
                    "type": p.get("schema", {}).get("type", "string"),
                }
                for p in params
                if p["in"] == "query"
            ]
            # Three distinct cases, which a single nullable field would blur:
            # no body at all (`unlock`, `revoke` -- POST as a verb), a body whose
            # schema the export left empty (`/account/export` -- free-form JSON
            # the generator must pass through untyped), and a named schema.
            body = op.get("requestBody")
            body_schema = None
            if body is None:
                body_kind = "none"
            else:
                raw = body.get("content", {}).get("application/json", {}).get("schema")
                body_schema = _schema_name(raw, index)
                body_kind = "schema" if body_schema else "untyped"

            resp = _response_shape(spec, op, index)
            ops[op_name] = {
                "method": method,
                "path": path,
                "path_params": path_params,
                "query_params": query_params,
                "paginated": PAGINATION_QUERY <= {q["name"] for q in query_params},
                "request_body": body_kind,
                "request_schema": body_schema,
                "response": resp,
                "sensitive_response_fields": _sensitive(spec, resp["schema"]),
                "sensitive_request_fields": _sensitive(spec, body_schema),
                "update_style": _update_style(spec, method, body_schema),
                "authenticated": bool(op.get("security")),
                "summary": op.get("summary", "").strip("`"),
            }
        namespaces[ns_name] = {"doc": ns["doc"], "operations": ops}

    # Gate 2: every management route is claimed exactly once.
    unclaimed: list[str] = []
    for path, item in paths.items():
        for method_lower, op in item.items():
            if method_lower not in ("get", "post", "put", "patch", "delete"):
                continue
            method = method_lower.upper()
            if (method, path) in claimed:
                continue
            tags = op.get("tags", [])
            if any(t in EXCLUDED_TAGS for t in tags):
                continue
            if (method, path) in EXCLUDED_OPERATIONS:
                continue
            unclaimed.append(f"{method} {path}  (tags: {', '.join(tags) or 'none'})")
    if unclaimed:
        raise SystemExit(
            "these routes are neither claimed by a §27 namespace nor excluded "
            "with a reason -- add them to NAMESPACES, or to EXCLUDED_TAGS / "
            "EXCLUDED_OPERATIONS saying why they are not SDK management "
            "surface:\n  " + "\n  ".join(sorted(unclaimed))
        )

    total = sum(len(ns["operations"]) for ns in namespaces.values())
    return {
        "$comment": (
            "GENERATED by scripts/gen-management-registry.py from sdks/openapi.json. "
            "Do not edit by hand -- edit the NAMESPACES table in that script. "
            "This file is the input every SDK's §27 code generator reads."
        ),
        "spec_version": spec["info"]["version"],
        # The digest of the spec this registry was derived from.
        #
        # `spec_version` has the same weakness `info.version` does, for the same reason:
        # it is the server's RELEASE version, so it moves when a release is cut rather
        # than when a path is added. Two registries built from genuinely different specs
        # can therefore carry the same `spec_version` -- and an SDK matching its vendored
        # registry against its vendored spec by that string cannot tell them apart.
        #
        # Absent when the spec predates the field, so an older export still generates.
        "spec_digest": spec["info"].get("x-axiam-spec-digest"),
        "operation_count": total,
        "namespace_count": len(namespaces),
        "excluded_tags": EXCLUDED_TAGS,
        "excluded_operations": {f"{m} {p}": r for (m, p), r in EXCLUDED_OPERATIONS.items()},
        "namespaces": namespaces,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
# Runs against fixtures, not against `sdks/openapi.json`. A gate whose only
# evidence is "the repo it guards is currently clean" cannot tell working from
# broken -- the same reasoning `check-crate-layering.py --self-test` records.
# Both gates below have failed open at some point during development; these are
# the cases that caught it.

_FIXTURE_BASE: dict[str, Any] = {
    "info": {"version": "0.0.0-fixture"},
    "components": {
        "schemas": {
            "Thing": {"type": "object", "properties": {"id": {"type": "string"}}},
            "MadeThing": {
                "allOf": [
                    {"$ref": "#/components/schemas/Thing"},
                    {"type": "object", "properties": {"client_secret": {"type": "string"}}},
                ]
            },
        }
    },
    "paths": {
        "/api/v1/things": {
            "get": {
                "tags": ["things"],
                "operationId": "list",
                "parameters": [
                    {"name": "offset", "in": "query", "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["items", "total", "offset", "limit"],
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {"id": {"type": "string"}},
                                            },
                                        },
                                        # (case 6 swaps this element for a
                                        # projection; the base fixture keeps the
                                        # plain inlined form case 1 asserts on.)
                                        "total": {"type": "integer"},
                                        "offset": {"type": "integer"},
                                        "limit": {"type": "integer"},
                                    },
                                }
                            }
                        }
                    }
                },
                "security": [{"bearer": []}],
            },
            "post": {
                "tags": ["things"],
                "operationId": "create",
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Thing"}}}
                },
                "responses": {
                    "201": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/MadeThing"}
                            }
                        }
                    }
                },
                "security": [{"bearer": []}],
            },
        }
    },
}


def _self_test() -> int:
    import copy

    global SENSITIVE_FIELDS

    failures: list[str] = []
    saved = dict(NAMESPACES)
    saved_sensitive = SENSITIVE_FIELDS
    # The real set is schema-qualified against real schema names, so the fixture
    # brings its own entry rather than relying on one of them leaking in.
    SENSITIVE_FIELDS = frozenset({("MadeThing", "client_secret")})

    def use(table: dict[str, Any]) -> None:
        NAMESPACES.clear()
        NAMESPACES.update(table)

    def expect_fail(label: str, spec: dict[str, Any], needle: str) -> None:
        try:
            build_registry(spec)
        except SystemExit as exc:
            if needle not in str(exc):
                failures.append(f"{label}: failed for the wrong reason: {exc}")
            return
        failures.append(f"{label}: gate did not fire")

    def expect_ok(label: str, spec: dict[str, Any]) -> dict[str, Any] | None:
        try:
            return build_registry(spec)
        except SystemExit as exc:
            failures.append(f"{label}: unexpectedly failed: {exc}")
            return None

    full = {"things": {"doc": "fixture", "operations": [
        ("list", "GET", "/api/v1/things"),
        ("create", "POST", "/api/v1/things"),
    ]}}

    # 1. A complete, correct table builds.
    use(full)
    reg = expect_ok("clean fixture builds", copy.deepcopy(_FIXTURE_BASE))
    if reg is not None:
        op = reg["namespaces"]["things"]["operations"]
        if not op["list"]["paginated"]:
            failures.append("pagination not detected on an offset/limit operation")
        # The structural fallback must recover `Thing` from the inlined element.
        if op["list"]["response"] != {"status": 200, "kind": "page", "schema": "Thing"}:
            failures.append(f"page element name not recovered: {op['list']['response']}")
        # allOf must be followed, or every one-time-reveal ships unwrapped.
        if op["create"]["sensitive_response_fields"] != ["client_secret"]:
            failures.append("allOf-inherited secret not detected on MadeThing")

    # 2. Gate 1 -- a registry entry naming a route the server does not serve.
    use({"things": {"doc": "fixture", "operations": [("ghost", "GET", "/api/v1/ghost")]}})
    expect_fail("gate 1 (dead path)", copy.deepcopy(_FIXTURE_BASE), "not a path in openapi.json")

    use({"things": {"doc": "fixture", "operations": [("wrong", "DELETE", "/api/v1/things")]}})
    expect_fail("gate 1 (dead method)", copy.deepcopy(_FIXTURE_BASE), "has no DELETE operation")

    # 3. Gate 2 -- a live management route no namespace claims. This is the one
    #    that silently creates unreachable SDK surface when it fails open.
    use({"things": {"doc": "fixture", "operations": [("list", "GET", "/api/v1/things")]}})
    expect_fail("gate 2 (unclaimed route)", copy.deepcopy(_FIXTURE_BASE), "neither claimed")

    # 4. Gate 2 must stay silent for a route excluded with a reason.
    spec = copy.deepcopy(_FIXTURE_BASE)
    spec["paths"]["/api/v1/things"]["post"]["tags"] = ["auth"]
    expect_ok("gate 2 respects EXCLUDED_TAGS", spec)

    # 5. A page whose element is an `allOf` PROJECTION -- a named base plus
    #    fields the list resolves and the `get` does not. This is what
    #    `GET /api/v1/certificates` became when it started returning
    #    `bound_service_account_id`, and until `_schema_name` followed `allOf`
    #    the element name came back `None`: the whole operation went untyped
    #    over one added property, and a downstream generator that assumes a page
    #    has an element name crashed on it. Both halves are asserted, because
    #    naming the base while dropping the addition is the other way to be
    #    wrong -- it is how the field reached `openapi.json` and no SDK.
    use({"things": {"doc": "fixture", "operations": [
        ("list", "GET", "/api/v1/things"),
        ("create", "POST", "/api/v1/things"),
    ]}})
    spec = copy.deepcopy(_FIXTURE_BASE)
    envelope = spec["paths"]["/api/v1/things"]["get"]["responses"]["200"]
    envelope["content"]["application/json"]["schema"]["properties"]["items"]["items"] = {
        "allOf": [
            {"$ref": "#/components/schemas/Thing"},
            {"type": "object", "properties": {"bound_id": {"type": "string", "format": "uuid"}}},
        ]
    }
    reg = expect_ok("projected page element", spec)
    if reg is not None:
        resp = reg["namespaces"]["things"]["operations"]["list"]["response"]
        if resp.get("schema") != "Thing":
            failures.append(f"allOf projection lost its base name: {resp}")
        if resp.get("projected_fields") != [
            {"name": "bound_id", "type": "string", "format": "uuid", "required": False}
        ]:
            failures.append(f"allOf projection lost its added field: {resp}")

    # 6. A non-projected response carries no `projected_fields` key at all. An
    #    empty list on all 145 of them would be churn saying nothing.
    reg = expect_ok("no projection, no key", copy.deepcopy(_FIXTURE_BASE))
    if reg is not None and "projected_fields" in reg["namespaces"]["things"]["operations"]["list"]["response"]:
        failures.append("projected_fields emitted on a response that projects nothing")

    use(saved)
    SENSITIVE_FIELDS = saved_sensitive
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("OK: self-test passed (8 cases)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify the committed registry matches the spec; do not write")
    ap.add_argument("--self-test", action="store_true",
                    help="exercise both gates against fixtures; touches no repo file")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    spec = json.loads(OPENAPI_PATH.read_text())
    registry = build_registry(spec)
    rendered = json.dumps(registry, indent=2, sort_keys=False) + "\n"

    if args.check:
        if not REGISTRY_PATH.exists():
            print(f"FAIL: {REGISTRY_PATH.relative_to(REPO_ROOT)} does not exist; "
                  f"run scripts/gen-management-registry.py", file=sys.stderr)
            return 1
        if REGISTRY_PATH.read_text() != rendered:
            print(f"FAIL: {REGISTRY_PATH.relative_to(REPO_ROOT)} is stale; "
                  f"run scripts/gen-management-registry.py", file=sys.stderr)
            return 1
        print(f"OK: {registry['operation_count']} management operations across "
              f"{registry['namespace_count']} namespaces, in sync with "
              f"openapi.json {registry['spec_version']}")
        return 0

    REGISTRY_PATH.write_text(rendered)
    print(f"wrote {REGISTRY_PATH.relative_to(REPO_ROOT)}: "
          f"{registry['operation_count']} operations across "
          f"{registry['namespace_count']} namespaces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
