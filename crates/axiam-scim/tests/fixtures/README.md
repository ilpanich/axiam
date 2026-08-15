# SCIM contract fixtures — provenance

**These fixtures are hand-constructed, not captured from real Okta or Entra
traffic.** This sandbox has no network access to either vendor, so nothing
here was recorded from a live integration.

Each file was built from:

- Okta's own published SCIM protocol reference and connector documentation
  (the request shapes Okta's provisioning engine is documented to send for
  push create/update/deactivate on Users and Groups).
- Microsoft's published Entra ID (Azure AD) SCIM provisioning reference
  (including the documented path-less `{"op":"replace","value":{...}}`
  PATCH shape Entra uses in place of Okta's `path`-qualified form).
- RFC 7643/7644's own examples, where a vendor doc didn't spell out a shape
  explicitly (e.g. the `members[value eq "<uuid>"]` filtered-path removal
  both vendors are documented to rely on).

Every fixture also carries a `"_source"` key (ignored by the deserializers
that consume it — `serde` drops unknown fields by default) naming exactly
which reference it was built from. Treat these as "the request shapes these
vendors are documented to send," not as a captured-traffic compatibility
guarantee — see `docs/api/scim-provisioning.md`'s "Fixtures are
hand-constructed, not captured" section for the same disclosure in the
operator-facing docs.
