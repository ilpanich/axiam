# PR H — contract 1.50 (C-0): progress ledger

Temporary. Deleted in the PR's final commit. Branch `docs/contract-1.50`, cut
from `1cb1371` (the merge of #496, PR G2). Brief: `dogfooding-findings-fix-plan.md` §6 C-0.

Resume check-ins (send_later): `trig_01QoSznG8scYRczWhYxqJqv9` (fires
2026-09-24T01:40Z), `trig_01RS29Nv81YvNbFnrjT93QxF` (fires 2026-09-24T05:40Z).
Delete both once the PR is open and green.

- [x] 0. Resume check-ins armed, ledger written
- [x] 1. SAGE boot — MCP not connected, noted below
- [x] 2. Citations re-validated against `1cb1371`; S-3/S-4/S-7/S-9/S-10 read in code; drift noted
- [x] 3. Contract amendments 1–8 of §6 C-0 (incl. §27.5 decision, §27.10 tier gap)
- [x] 4. Version bump to 1.50 + every gate that moves with it; drift check red only for SDK re-vendor
- [x] 5. Records: CHANGELOG, roadmap T22.15, EXECUTED block in §6 C-0, §13 item 1, threat model verified
- [x] 6. Gates run (doc links, docs lint, contract/spec checks); signed commits
- [ ] 7. PR opened, subscribed, green
- [ ] 8. Next-session prompt (I₁ = C-1, Rust SDK) printed

## Notes (half-done state, findings)

- Step 1: no SAGE MCP server is connected in this session (none of its tools
  exist); continued without it.
- **Version-number collision (found at step 2, blocks step 4).** Contract
  **1.50 already exists on main**: `d5a6811` (2026-09-18, "mark the DCR initial
  access token Sensitive — contract 1.50") is the top Breaking Changes Log entry,
  and all eleven SDK repositories' `main` vendor that exact `CONTRACT.md`
  (sha256 `d877a1a05e9a…`, identical to `1cb1371`'s). The plan (§3, §6 C-0) was
  written as if 1.50 were free. C-0 therefore cannot reuse 1.50; next free is
  **1.51** (and C-12 would become 1.52). Asked the user; steps 2–3 proceed
  number-agnostic meanwhile.

### Step 2 findings (code at `1cb1371`; agents' reports spot-checked)

- §10.3 names only the RPCs (`TokenService.ValidateToken` / `IntrospectToken`),
  not SDK operations; plan item 1's "the operation names §10.3 already uses" is
  loose. gRPC server reads **no** acting-tenant metadata (only `authorization`,
  `x-forwarded-for`); tenant always from the token → §5.2 helper is REST-only.
- `/auth/device`: no body; 200 `{access_token, token_type:"Bearer", expires_in}`;
  401 for every refusal incl. unbound, unknown, `Server`-type; 429 (60/min/IP)
  undocumented in OpenAPI; `cnf.x5t#S256` only on native mTLS, never on the
  trusted-proxy header path; REST mismatch 401, gRPC `Unauthenticated`.
  `token_type` stays `"Bearer"` for a cert-bound token (gRPC ValidateToken too).
- §6.1 says the device cert is "signed by the tenant's organization CA": since
  S-1 a tenant principal (and every service account, S-9) issues only under its
  tenant signing CA.
- S-7: `CertificateType` gains `"Server"` (PascalCase, closed enum in the spec)
  and appears in **responses** → closed-enum SDK decoders break on a list with
  one. SAN field nullable/optional on both request DTOs; responses carry no SANs.
  Vault sign-csr refusal is 400 and fires after the CA lookup (404 first).
- S-9: 68 operations list `service_account` (66 management + 2 authz). Human-only
  route with m2m token → 401 audience mismatch; m2m no role → 403
  `authorization_denied` + `action`; exchanged user token as m2m → 401.
- S-10: `inherit` nullable on 3 request DTOs; required `bool` on the 3
  `Role*Assignment` listings; optional (default true) on `RoleAssignment`.
- Registry: 162 ops (contract says 147 throughout; §27.1 table stale in users,
  groups, roles, service_accounts, oauth2_clients, privacy), 5
  `excluded_operations` (§27.0 table lists 2). `/admin/bootstrap`: 201/400/403/409
  (+500); public, no 401, **no rate limiter** (server matter, not this PR).
- SDKs: no SDK has resource `metadata` except PHP; no SDK's manifest binds a role
  at a resource; none has `service_accounts`/`webhooks`. Flat tier (PHP, Swift, C,
  C++) holds only resources/permissions/roles/groups; **none of the four sends the
  resource parent** (tree comes out flat), Swift/C/C++ default type to "folder",
  and **PHP holds role grants and group role keys but never reconciles them**
  (docblock says it does). Only C++ has `authenticate_device()`; no SDK sends
  `X-Axiam-Tenant`; no SDK wraps TokenService (Go's stubs are `internal/`,
  Python/PHP generate none).

### Decisions from the user (2026-09-23)

- C-0 ships as **contract 1.51** (1.50 is `d5a6811`'s). C-12 becomes 1.52.
  Branch stays `docs/contract-1.50`; the PR says why.
- §27.1's table and the "147" prose are re-rendered from the registry (162) in
  this PR, recorded in the EXECUTED block as not anticipated.

### Steps 3–4 (commit "docs(sdk-contract): contract 1.51 — the dogfooding remediation (C-0)")

- Contract + website anchors + reference page in one signed commit.
- Drift gate: 33 problems = 11 × {CONTRACT.md, openapi.json, registry} STALE;
  proto, OPAQUE vectors, vendored crate OK. openapi/registry were already stale
  on main (SDKs vendor beta16's, `2617eae`).

### Steps 5–6

- Records commit: CHANGELOG, roadmap T22.15, EXECUTED block, §13 row 1 + rows 15–17,
  T-210 amended (no new threat; gen-threat-model 279/266/13 unchanged, reverted).
- All 21 script gates of ci.yml/docs-ci.yml exit 0 (remediation-evidence needs an
  unshallowed clone: `git fetch --unshallow origin`); website lint/tsc/build 0.

### Step 7 (in progress)

- PR **#497** opened and subscribed. Waiting for CI. Before merge: delete this
  ledger in a final commit, then delete both resume triggers and arm a PR check-in.
