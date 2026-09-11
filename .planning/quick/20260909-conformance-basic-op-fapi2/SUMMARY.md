---
gsd_summary_version: "1.0"
type: quick
slug: conformance-basic-op-fapi2
status: incomplete
date: 2026-09-09
branch: claude/oidc-conformance-first-real-run
commits:
  - 065f37cb1 fix(oauth2), eight defects the OIDF conformance suite found
  - 11d3c84a4 fix(conformance), five harness gaps
---

# Drive the OIDC Basic OP and FAPI 2.0 lanes to success

## Where the lanes stand

Measured against the pinned suite `release-v5.2.4`, driven end to end.

| Plan | PASSED | FAILED | REVIEW | WARNING | SKIPPED | WAITING |
|------|--------|--------|--------|---------|---------|---------|
| `oidcc-basic-static` (35) | **27** | **0** | 4 | 3 | 1 | **0** |
| `fapi2 …-mtls` (37) | **26** | **0** | 10 | 0 | 1 | **0** |
| `fapi2 …-self-signed` (37) | **26** | **0** | 10 | 0 | 1 | **0** |
| `fapi2 …-private-key-jwt` (56) | 27 | 4 | 8 | 1 | 2 | 0 |

The first run in project history was 0/35 on Basic and 2 PASSED / 31 FAILED on
FAPI mTLS.

`REVIEW` is a terminal verdict, not a failure: those modules decide by
screenshot, and a certification reviewer signs them off. The driver now uploads
real screenshots of the pages the run produced, which is what moved them out of
WAITING.

## The three Basic OP WARNINGs, and why they stay

- `oidcc-scope-profile` / `oidcc-scope-all` — ten of the fifteen `profile`
  claims (`website`, `zoneinfo`, `birthdate`, `gender`, `profile`,
  `middle_name`, `locale`, `picture`, `updated_at`, `nickname`) have no column
  in AXIAM and no provisioning path. OIDC Core §5.3.2 omits a claim the OP
  cannot assert; inventing them would be worse. The five AXIAM does hold are now
  released.
- `oidcc-claims-essential` — the OIDC Core §5.5 `claims` request parameter,
  which AXIAM does not implement and honestly advertises as
  `claims_parameter_supported: false`. The module runs anyway.

## What is left: the DPoP lane

Four FAILED and one WARNING, all in `private-key-jwt`, and three of them are one
missing feature.

**`dpop_jkt` is not implemented (RFC 9449 §10).** A client may pin the DPoP key
at the pushed authorization request; the AS must reject a mismatch there and
must require the token request's proof to use that same key.

- `ensure-mismatched-dpop-jkt-fails` — PAR answers 201 for a mismatched
  `dpop_jkt`; RFC 9449 §10.1 requires 400.
- `ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt`
- `ensure-token-endpoint-fails-with-mismatched-dpop-jkt`

The shape of the work: a `dpop_jkt` field on `PushedAuthorizationRequest`,
validated at PAR against the presented proof's thumbprint; carried on
`PushedAuthParams` → `AuthorizeRequest` → `AuthorizationCode` (a schema change);
and required to equal the token request's proof thumbprint. Multi-crate,
including a migration — which is why it was not started rather than half-done.

Also open:

- `ensure-holder-of-key-required` — still FAILED on the last measured run,
  though `invalid_dpop_proof` (RFC 9449 §5) now replaces `invalid_client`.
  Re-check first: the fix landed and the lane was re-run once, and this module
  may have been measured before the rebuild.
- `dpop-negative-tests` (WARNING) — two halves: a resource endpoint answering
  200 where DPOP-7.1 wants 400/401, and one answering 401 where RFC 3986 §6.2.2
  URI normalisation of `htu` should have made it 200.

## Standing operational notes

- **One browser driver, ever.** Two drivers deliver two callbacks and the suite
  throws `runInBackground called after runFinalisationTaskInBackground()`. It
  cost a whole Basic run — 34 of 35 modules red, none of it AXIAM.
- **`SUITE_PORT` is 8442.** 8443 is `sage-gui`, and probing it returns a
  plausible, wrong answer.
- The rig's admin is `admin@axiam.dev`; `AXIAM_ADMIN_PASSWORD` now lives in the
  gitignored `conformance/suite.local.env`.
