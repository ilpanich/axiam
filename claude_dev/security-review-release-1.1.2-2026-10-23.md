# Security review — release 1.1.2, the combined plan branch (F4)

**Date:** 2026-10-23.
**Against:** `claude/release-1.1.2` at `4a65f2c`, the whole release diff
`origin/main...4a65f2c`: 111 commits, seven of them wave merges; 152 files,
21 673 lines added and 2 081 removed. `main` is the base the wave branches were
cut from (plan §12.0: `dc5bfd4` on top of `dedbf81`). Every commit of the range
carries a `gpgsig` header (111 of 111). The sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them.

**Scope:** what no single review could see. Each wave was reviewed on its own
branch: [W1](security-review-release-1.1.2-w1-2026-10-22.md),
[W2](security-review-release-1.1.2-w2-2026-10-22.md),
[W3](security-review-release-1.1.2-w3-2026-10-22.md),
[W4](security-review-release-1.1.2-w4-2026-10-22.md) and
[W5](security-review-release-1.1.2-w5-2026-10-22.md), each with its addenda.
W6 had no review of its own, so its diff is read here (§6). Contract 1.64 and
the eleven SDK ports were reviewed by
[`sdk-contract-1.64-conformance-review.md`](sdk-contract-1.64-conformance-review.md);
its §7 is not repeated. This review covers, as plan §9 (W8.2) and the
orchestrator's brief ask:

1. the **seven merges** (`f0f4740`, `5f3a2cb`, `cca90ad`, `ae4d3d9`, `61820b5`,
   `bbcf271`, `9779a10`), and the conflict resolutions §12 names;
2. the **cross-wave interactions**: erasure × network gate × decision cache ×
   migration lease × the `TRUSTED_PROXIES` client-address rule × audit
   provenance;
3. **the spec and contract 1.64 against server behaviour**: every normative
   server-side sentence the 1.64 diff adds, read against the code that keeps it;
4. **whether each issue the plan claims to close is closed by the tree**: each
   issue's wording read and the code checked (§7);
5. **W6's diff** (#757, #758 h/i, #561, #513).

**Method:** the method and severity scale of the 1.1.1 combined review
([`security-review-release-1.1.1-2026-10-20.md`](security-review-release-1.1.1-2026-10-20.md)).
The reading was adversarial:
- each merge's `git show --remerge-diff`, and every file two or more waves touched;
- the code each claim rests on at `4a65f2c`, not the commit messages;
- the contract's server sentences, each against the code.

Five parallel read-only investigations fed this text: erasure; client address
and audit; lease, gate and cache; merges, W5 and W6; spec and contract. Every
finding was re-read here at the cited line before it was filed. Four were
reproduced by throwaway probes, deleted afterwards: R112-01, -03, -04 and -06.
The checks run and their exit codes are in §8. IDs are `R112-NN`.

This review fixes nothing. **Nothing is Medium or higher.** Five Low and eight
Informational findings are filed on milestone `1.1.x` as **#794 … #806**. Under
plan §1.4, W9.1 takes them all.

---

## 0. Summary

**No finding is Medium or higher.**
- The seven merges lost nothing. W4's hand-resolved hunks are exact unions:
  T-444 in both copies, and the `docs/admin` rows.
- Every issue the plan closes in W1 … W7 is closed by the tree, with three
  text items that are W8.3's and W8.4's by plan (§7).
- The regenerated spec is byte-identical to `sdks/openapi.json`, and every
  server sentence contract 1.64 adds holds.
- `/uma2/perm` gives no oracle between a foreign resource set and an unknown one.

The findings come from waves meeting, and from paths no wave owned:
- W2.2 added a client IP to audit metadata that W1's erasure scrub and the
  minimisation do not know (R112-01).
- W3.1's comment turns `ci.yml`'s conflict-marker gate red, a step no wave
  branch ran (R112-02).
- The address rule reads one `X-Forwarded-For` line (R112-03).
- #791's generation guard misses the organization-tenant flush (R112-04).
- SCIM `/Groups` never flushes the cache (R112-05).

The last three predate the release. They are found now because W2 and W4 made
the address and the cache load-bearing for more than they were.

### 0.1 Findings index

| ID | Severity | Where (`path:line`) | Rule | What | Fix | Test | Issue |
|---|---|---|---|---|---|---|---|
| R112-01 | Low | `axiam-audit/src/middleware.rs:564,632-633`; `axiam-db/src/repository/audit.rs:446-452`; `axiam-core/src/audit_minimisation.rs:84` | GDPR Art. 17 and Art. 5(1)(c); `gdpr-compliance.md` §2 and §5 | `metadata.forwarded_for_claimed` (W2.2) is a client IP. Erasure's query 1 clears `ip_address` but not this key, and minimisation truncates `ip_address` but not this key. Probe: after `pseudonymize_actor`, `actor=nil ip=None` but `forwarded_for_claimed: "198.51.100.23"` survives. | Query 1 sets `metadata.forwarded_for_claimed = NONE`. `apply` truncates it with `truncate_ip`. Amend the guide and T-212. | `audit_repository_test`: the key is gone after the scrub. A minimisation unit test. The exact-key middleware test sends `X-Forwarded-For`. | #794 |
| R112-02 | Low (CI red; no runtime effect) | `axiam-db/src/schema.rs:2764` | D-09: one classifier for unique violations (`check-conflict-markers.py`) | The comment quotes `"already exists"`. The script exits 1 on the plan branch (0 on `main`), and `ci.yml:85-86` runs it on the PR. | Reword the comment (e.g. "a unique violation"). | `check-conflict-markers.py` and its `--self-test` both exit 0. | #795 |
| R112-03 | Low (pre-existing; W2.2 widened it to audit) | `extractors/client_info.rs:45-48`; `extractors/rate_limit.rs:173`; `axiam-audit/src/middleware.rs:554-556`; `api-grpc/src/middleware/rate_limit.rs:214-217` | T-212, SEC-087 | Only the first `X-Forwarded-For` field line is read. Behind a proxy that appends its own line (HAProxy `option forwardfor`), the client's forged line is used. Probe: `6.6.6.6` selected through a listed proxy. | One `forwarded_for` helper joins every line with `,` (non-ASCII means absent). All four sites use `get_all`. | Two-line cases in `client_info`, `rate_limit_keying_test`, `service_and_middleware` and the gRPC extractor. | #796 |
| R112-04 | Low (pre-existing; beside #791) | `axiam-authz/src/decision_cache.rs:722-727`; `engine.rs:488-492` | T-192, D7 | `invalidate_tenant(O)` drops shard O only. An organization-level principal's decisions about member tenant X live in shard X and survive every O-tenant flush (grant revoke, role delete/update, …). The #791 guard also misses them. Probe: `get` → `Some(Allow)`; `insert_if_unchanged` → `true`. | Also drop `Organization{tenant_id: O}` entries in every stripe and bump every generation, or escalate to `invalidate_all` for an organization tenant. | A cache unit test (miss, refused insert). An engine test: an org admin's allow in X, a revoke in O, then a deny. | #797 |
| R112-05 | Low (pre-existing) | `axiam-scim/src/groups.rs:274,346,352,409,415,434,465` | D7: every narrowing write flushes | SCIM `/Groups` add, remove, `RemoveAll` and delete never invalidate the decision cache. Native groups, SCIM `/Users` and the directory mapper all do. An IdP's group-removal revocation is served stale until the TTL. | `invalidate_subject` per member; `invalidate_tenant` on delete, as `handlers/groups.rs`. | A SCIM PATCH remove with the cache on: the next check is evaluated and denied. | #798 |
| R112-06 | Informational | `axiam-db/src/schema.rs:2513-2566` | #729 (no non-additive migration applied out of order) | The additive check drops only whole-line `--`. A trailing `--`/`//`/`#` comment or a `\'` hides a later `UPDATE`/`REMOVE`/`DELETE`. Probe: four such strings are classified additive. | Make the scanner comment- and escape-aware, or fail closed on any `\`, `/*` or non-leading comment marker. | The four strings in `schema::tests`, each asserting `!is_additive`. | #799 |
| R112-07 | Informational | `handlers/oauth2_clients.rs:1313-1314`; `dcr.rs:607-608`; `cimd.rs:551` | #746 class | The admin `PUT` sets `post_logout_redirect_uris` and `backchannel_logout_uri` on a DCR or CIMD row with no bound. Registration never grants either. | `422 redirect_exceeds_registration_policy` for a new value failing the row's host predicate; held values stay exempt. | `oauth2_client_test`: DCR and CIMD × both members → `422`, row unchanged. | #800 |
| R112-08 | Informational | `axiam-scim/src/auth.rs:131-143,155-158,176-195` | CONTRACT §6.1 rule 11; D-12 (#787) | The provisioning-token branch reads `Authorization` only, case-sensitively, and leaves no verdict. With a cookie for X plus a `scim_` token, the request row names X `authenticated: true`; a refused token still records `true`. | Cookie present → the JWT branch, or refuse as ambiguous; `mark_refused` on every token refusal. | An axiam-scim test of both combinations. | #801 |
| R112-09 | Informational (pre-existing) | `axiam-authz/src/network_gate.rs:1819-1827`; `api-rest/src/network_gate.rs:302-303,736-737`; `audit.rs:494-505`; `axiam-server/src/cleanup.rs:438,3091-3104` | #758 (e); D7 | (a) `network_role.*_refused` rows keep the erased user's UUID in `metadata.after.user`. (b) The erasure's role removal flushes no cache. | (a) Extend the grantee pass to the refusal rows. (b) Give `CleanupTask` the cache handle, or record the gap in T-484's D7 residual. | (a) `audit_repository_test`. (b) `cleanup_task.rs` with the cache on. | #802 |
| R112-10 | Informational (pre-existing; now load-bearing) | `sdks/openapi.json`; `handlers/oauth2.rs:4996-5014`; `handlers/uma.rs:170-177`; `axiam-db/src/pool.rs:343-365`; `api-rest/src/error.rs:154` | #756; CONTRACT §14.2 rules 6 and 9 | `/oauth2/token` declares only `200`/`400`; it also answers `401`, `429` and `500`. `/uma2/perm` omits `429`, and its `400` text omits #745. Login, change and reset-confirm omit `429`. The pool `503` and `write_contention` are in no text. Rule 6's example omits `error_description`. | Declare them and regenerate. The contract notes go to 1.65. | `declared_refusal_tests` pointers; the drift job. | #803 |
| R112-11 | Informational | `.github/workflows/radius-e2e.yml:73-80` | #723 | The e2e filter lacks `axiam-auth/src/carrier.rs`, which W2.1 split out while W5.4 added `extractors/auth.rs`; every Live decision calls it. Smaller gaps: `client_info.rs`, `forwarded_for.rs`, `rate_limit_shared.rs`. | Add the paths. | Every listed path exists; one `workflow_dispatch`. | #804 |
| R112-12 | Informational | `api-rest/tests/oauth2_client_test.rs` (19 sites, 2338 … 2591); `db/tests/network_repository_test.rs:881,911`; `server/tests/radius_e2e.rs:3346-3352,450-456` | plan §10, #757 | The diff's remaining `{body}`/`{err:?}` messages, and a W5 assertion that prints the `-xx` log carrying the Live token. The ten pre-existing PKI `[0u8; 32]` keys are listed in the issue. | Use labels; redact `Bearer` and `access_token` in `log_since`/`log_tail`; a random key for the PKI tests. | A grep gate, or CodeQL on the PR; a redaction unit test. | #805 |
| R112-13 | Informational (text) | §5 of this document | plan §1.3 | (a) SEC-087 rows vs `deployment/README.md:973`; (b) T-484 says nothing of AMQP; (c) the GDPR D-04 sentence; (d) T-444 order; (e) plan §12.2 and §12.6 merge notes; (f) `bench-quick`; (g) the v109 note's place; (h) the `-xx` log note; (i) the mixed-version erasure upgrade line. | As listed in the issue. | None (text); `check-doc-links.sh`, `check-remediation-evidence.py`. | #806 |

Not re-rated: no earlier finding changes severity.

---

## 1. The merges

Every merge has the plan branch as first parent and the wave head as second. W7
was cut after W1 … W6 were merged.

| Merge | Wave | `--remerge-diff` | Verdict |
|---|---|---|---|
| `f0f4740` | W1 | empty | sound |
| `5f3a2cb` | W2 | **empty** | sound. §12.2 credits this merge with the `device_flow_test.rs` label; `5f3a2cb:device_flow_test.rs` still has `"{body}"`. The W6 merge made that change (R112-13 e). |
| `cca90ad` | W3 | empty | textually sound; it carries R112-02 from `8f0be44` |
| `ae4d3d9` | W4 | conflicts in T-444 (`Axiam.json`, `threat-model-stride.md`) and in the `docs/admin/README.md` `network_role` rows | sound. T-444 is the exact union in both copies (+827 characters per side; the #738 and #776 amendments are both present). The admin table keeps W4's `assigned` row and W1's erasure `unassigned` row. |
| `61820b5` | W5 | empty | sound |
| `bbcf271` | W6 | `network_gate_test.rs`, `device_flow_test.rs`, `docs/deployment/README.md` | sound. HEAD's larger hunk is kept, including the `409` already-bound block. Two `err` become `_err` behind "delete refused". Three `{text}` messages are removed; §12.6 does not record this (R112-13 e). The device-poll `{body}` becomes a label (`:2511`). The v109 note is placed above the W3 section (R112-13 g). Assertion counts are equal before and after in all eight W6 test files. |
| `9779a10` | W7 | empty | sound; where it overlaps other waves it only bumps versions |

**Files two or more waves touched, read for semantic conflicts that merged
cleanly.**
- `boot.rs` (W1, W2, W4): `compose_app` (W2) wraps audit at App level. W4's
  `network_writes` is threaded through it and joined beside `join_cleanup`
  (`boot.rs:3524-3542`). The audit drain runs first, which is safe: gate rows
  go straight to `audit_repo`, not the middleware queue.
- `schema.rs` (W3, W5): W5's side is comments only.
- `cleanup.rs` (W1, W3): W3's side is comments.
- `roles.rs`, `permissions.rs`, `certificates.rs`: W3 added `utoipa`
  annotations, W4 changed logic, and no line meets.
- `network_decide.rs` (W2, W4): W4's side is a doc comment.
- The threat model, `threatModel.ts`, `openapi.json` and the registry: every
  line any wave added survives at HEAD, except the T-444 union and the
  relabelled messages above.
- `cargo check -p axiam-api-rest -p axiam-server --tests --no-default-features`
  exits 0 with no warning.

---

## 2. Cross-wave interactions

### 2.1 Erasure × the client-address rule × audit provenance (R112-01)

W2.2 (#752, D-5) records two addresses: `ip_address` (the rule's) and
`metadata.forwarded_for_claimed` (the leftmost entry, when it differs). W1's
erasure scrub was written against the 1.1.1 row shape.

`pseudonymize_actor` query 1 (`audit.rs:446-452`) clears `ip_address` and the
five PII keys; `AuditMinimisation::apply` (`audit_minimisation.rs:84`)
truncates `ip_address`. Neither knows the new key. The probe (§8) shows the
claim surviving both.

This is the common case, not the adversarial one. A user behind a corporate
proxy in front of a listed ingress always produces a differing leftmost entry,
which is their real address. Three guide sentences are now false:
- `gdpr-compliance.md:462-463`, "clears `ip_address` outright";
- the §2 field list;
- `:445-448`, the middleware "collects `http_status` and `authenticated` and
  nothing else". Its pin test sends no `X-Forwarded-For`, so it still passes.

**Low, not Medium.** The value sits beside a keyed pseudonym, not the account,
and only an administrator with audit read sees it. But it is personal data the
release added and the erasure keeps, so it is fixed in this release (§1.4).

**Provenance holds.**
- `ingested_via = "amqp"` is stamped last and unconditionally, as a top-level
  insert after the producer's metadata is merged (`audit_consumer.rs:59-75`,
  `:255-258`). Non-object metadata goes under `producer_metadata`.
- A producer can still write a row that *looks* like a request row
  (`authenticated: true`, a `forwarded_for_claimed`), but it carries the stamp.
- Readers match the exact top-level key (`AuditLogsPage.tsx:82`), so case
  variants and nested copies are inert.
- T-484 does not yet say this (R112-13 b).

### 2.2 The client-address rule everywhere (R112-03)

Every recorder or decider of a client address on the merged tree goes through
`select_client_ip`:
- the REST limiters (`server.rs:115,145`; `rate_limit_shared.rs:397`);
- the audit request row (`middleware.rs:557`);
- `client_info::client_ip` and every handler that uses it: auth, webauthn,
  opaque, federation, network, `network_decide` (`:578,691,853,879`), ssf,
  dcr, cimd, gdpr, users, scim;
- the span (`request_span.rs:179`);
- gRPC (`rate_limit.rs:218`).

Nothing reads `realip_remote_addr`, `X-Real-IP` or `Forwarded` any more. The
SEC-087 peer-only rows are deliberate (R112-13 a). W4's gate and the decision
route decide on the certificate and the account, never on an address; the
address feeds only the row and the backstop limiter.

The one gap is older than the rule: `headers().get` returns the first field
line. RFC 9110 joins repeated lines, and HAProxy appends rather than merges, so
a listed proxy does not protect the per-address buckets (R112-03). The shipped
topologies (ingress-nginx, Caddy) merge, so the rating stays Low.

The gRPC rule is no longer a twin (#790): `select_client_ip` with the same
configured values; `none` is tested at `api-grpc/.../rate_limit.rs:1043`.

### 2.3 Rate limits × the session check × the refund

- `is_session_active_checked` answers `false` on a datastore error
  (`session.rs:499-513`). That is fail-closed: the key falls to the address,
  and an address-keyed charge is never refunded.
- The refund needs both `PrincipalSessionLive` and `SessionCredentialRefused`
  (`rate_limit_shared.rs:335-352`). It exists only on the five federation flow
  routes, each behind a required `AuthenticatedUser`. Login and token are
  address-keyed and never refunded, so the refund cannot be farmed.
- The cost is one session read before the charge, under a per-address backstop
  set at 10×.

### 2.4 Erasure × network gate × decision cache × #791 (R112-04, R112-05, R112-09)

Every write that changes a decision was listed and checked for a flush:
- user, service-account and group assignments; grant and revoke;
- role delete (inside W4's task);
- `roles::update`, permissions, groups, resources, scopes, user update and delete;
- SCIM `/Users`; the directory mapper and sync.

Three gaps, all TTL-bounded, all behind `decision_cache_enabled` (off by
default):
1. **The organization-tenant flush (R112-04).**
   - Shards are keyed by the tenant a decision is about, and
     `invalidate_tenant` touches one shard.
   - `invalidate_subject` already sweeps every shard for this reason; the
     tenant flush was never given the same treatment.
   - #791's per-stripe generation inherits the gap: stripe(X) ≠ stripe(O) in
     15 of 16 cases.
   - This is T-192's class on the other invalidation path, which is why the
     fix is Opus-sized.
2. **SCIM `/Groups` (R112-05).** It is the one membership writer with no flush.
   It is also the usual IdP revocation.
3. **The erasure's role pass (R112-09 b).**
   - It calls the repositories directly from `CleanupTask`, which holds no
     cache.
   - It is moot in practice: sessions were revoked in step (a) and the account
     is inactive.
   - The unassignment does bump the role's holder epoch (`role.rs:995`), so
     W4's version claims see it.

The erasure writes its `network_role.unassigned` row directly, not through
W4's gate task. That is correct for a non-handler path. After #792 it writes
the row only when its own `DELETE … RETURN BEFORE` removed the edge.

The pseudonymization of grantee ids (#758 e) covers success rows only;
refusal rows keep the UUID in `metadata.after.user` (R112-09 a).

### 2.5 Migration lease × erasure lease × boot

- `main.rs:496-520` runs `attest_storage_engine` and then `run_migrations`
  before anything else. Everything else follows (`main.rs:595-678`): the
  bootstrap token, the backfills, the seeder reconcile, and `boot::serve` with
  every listener, the cleanup and erasure sweeps and AMQP.
- So a replica waiting on or losing the lease serves nothing and starts no task.
- The two leases share no name: `_migration_lock` holder and expiry, versus
  `account_deletion.purge_claimed_at` and `user.erasure_audit_pending`.
- The lease is released on success and on failure, conditionally on the holder
  (`schema.rs:2711-2724`). After a panic or `SIGTERM` it expires after 300 s,
  inside the `startupProbe`'s 600 s (#770).
- Two holders need a refresh to fail for five minutes. Even then, the
  per-migration transaction and the tolerated unique `_migration` index hold.
- **Mixed versions:** a 1.1.1 replica's non-exclusive `claim_tx` ignores 1.1.2's
  claim. One erasure can run twice during the roll (#738's 1.1.1 behaviour:
  one record, a doubled SSF send). It needs an upgrade note line, not a fix
  (R112-13 i).

### 2.6 The refresh-token sweep (#753, #781)

- `delete_expired` (`oauth2_refresh_token.rs:576-615`) selects
  `expires_at < $before LIMIT $limit`, then deletes those ids `RETURN BEFORE`
  under `retry_on_write_conflict`.
- `expires_at` is a required `datetime` (`schema.rs:1080`), so no `NONE` row
  matches.
- `before = now − 7 d` (`cleanup.rs:530`); at most 10 × 500 rows per tick;
  stops on shutdown.
- Unexpired revoked rows are kept, by design (T-254 after #783).
- The sweep spans tenants on purpose. The erasure's `delete_all_for_user` is
  scoped to the tenant and user.

---

## 3. The spec and contract 1.64 against the server

The spec regenerates byte-identical
(`axiam-server --dump-openapi | cmp - sdks/openapi.json`), and `apiIndex.ts`
regenerates identically. Every server-side sentence 1.64 adds holds:

| Claim | Verdict | Evidence |
|---|---|---|
| §20.2 rule 9 / §20.4: `/uma2/perm` mints a ticket only for the PAT client's own sets; any other id gets the unknown id's `400` | **HOLDS; no oracle** | `api-rest/src/uma.rs:127-150`: unknown, foreign and admin-made ids all yield empty scope lists after one `get_by_id`, so the work is equal. The checks in `axiam-core/src/models/uma.rs:274-313` do not depend on ownership. One `Validation` (`handlers/uma.rs:621-640`). No row on refusal. Same bucket. The rreg routes give one `NotFound` for both. Only a datastore fault (`500` vs `400`) separates them, which needs no fix. |
| `422 reserved_metadata_key` on tenant create/update | HOLDS | only producer `tenants.rs:198-209`; declared `:240`, `:628` |
| `409 already_exists` on the six issuer/serial stores | HOLDS | `axiam-pki` `cert.rs`, `ca.rs`; all six routes declare `409` |
| PKI and PGP `503` | HOLDS | each `bounded_permit` reaches one of the seven declared routes |
| hash-gate `503` on login, change, reset-confirm (#772) | HOLDS | `acquire_hash_permit` callers `auth.rs:607,1464`, `password_reset.rs:346`, all declared |
| `409 stale_version` on the ten claimed role/permission writes | HOLDS | `role_tx_outcome` (`role.rs:334-345`); ten routes declare it |
| §28.12.2 rule 7: the two `422` codes; CIMD rows by the CIMD policy (#746, #768) | HOLDS | `oauth2_clients.rs:717-785`, `:1277-1306`; `cimd::redirect_uri_refusal` reused, fail-closed without a host. The two logout members are outside the rule (R112-07). |
| §8: `metadata.ingested_via = "amqp"` | HOLDS | §2.1 |
| §8: `network_role.deleted` server-written, not reserved | HOLDS | `network_gate.rs:637`; reserved namespaces are `tenants.` and `gdpr.` only |
| §27.11 rule 5: a recovered `gdpr.user_pseudonymized` row carries `certificates_revoked: null` and `recovered: true` (#760 Q1) | HOLDS | `cleanup.rs:2771-2775` |
| SSF `account_purged` once per erasure (§12.1 note) | HOLDS | emitted only after `anonymize_user_marked` answers true (`cleanup.rs:2509-2540`) |
| §6.1 rule 11: cookie first; a non-token header never shadows the cookie; an invalid cookie is not retried | HOLDS for every JWT reader | `carrier.rs:37-60`, used by the extractor and the audit middleware. SCIM's provisioning token is the exception (R112-08). |
| §14.2 rules 5 and 9 for the device poll | HOLDS | `authorization_pending`, `slow_down` and `expired_token` are `400` (`device_service.rs:390,408`). `429` is `rate_limit_exceeded` with `Retry-After`. The device branch never sends `429 slow_down` (that is uma-ticket, token-exchange and PAR). |
| rule 6, §14.6, §16.1, P11 | server part HOLDS | the `500` body always carries `error_description`; rule 6's example omits it (R112-10 d) |

What the spec does not say (R112-10) predates the release. 1.64 makes it
matter: rules 6 and 9 tell SDKs to act on `429` and `5xx`, which the token
operation does not declare.

---

## 4. Per-area notes

- **W1 (erasure, CRL, Vault).**
  - The exclusive claim (`account_deletion.rs:466-489`), the recovery
    (`cleanup.rs:2811-2846`), the stalled-unit guard (#784) and the single
    `network_role.unassigned` row (#792) hold.
  - `cleanup_task` passes 62 of 62, the race tests on `surrealkv`.
  - CRL `follow_clock` (`crl.rs:417-431`) and the sanitiser's
    `ends_with_escape` (`vault_forward.rs:86,114`) hold.
  - Cross-wave: R112-01, R112-09.
- **W2 (address, limits, provenance, verdict).**
  - No later wave touched W2's address code: `git diff 5f3a2cb..HEAD` reaches
    only a doc comment and W4's write tasks.
  - Cross-wave: R112-03, R112-08, R112-13 a, b.
- **W3 (lease, gap refusal, admin client policy, spec).**
  - The lease holds (§2.5).
  - The refusal rule is right on case, `OVERWRITE`, `REMOVE`, `UPDATE` and
    multi-statement strings. Comments and escapes are the gap (R112-06).
  - The admin `PUT` has no other widening route: no `PATCH`, and
    `managed_by` is not writable. The exception is R112-07.
  - R112-02 is W3.1's.
- **W4 (gate rows in the task, orderly stop, seeder, cache).**
  - The orderly stop waits for gate tasks within `budget.cleanup`. A task past
    the bound can still lose its row; that is logged and documented in T-484.
  - The seeder skip on an unresolved kind covers both halves (#728, #777).
  - `refusal_of` matches the `THROW` head exactly (#778).
  - R112-04 and R112-05 are older than W4, but W4's #791 is where they now
    belong.
- **W5 (RADIUS Live).**
  - The drop is read-only with TTL 0, and both stores use a negative TTL
    (`check-eap-tls:60-104,140-190`).
  - The lock-busy run checks the age (`fetch-crl.sh:204-210`).
  - `-xx` appears only in the e2e override and is the same level as the old
    `-X`, so 1.1.2 adds no leak. The guide's log note should name the token
    (R112-13 h).
  - Cross-wave: R112-11.
- **W7 (contract 1.64, versions).** §3. Version strings agree (spec 1.1.2,
  registry 1.1.2, digest `9960bbbb…`).

---

## 5. Open questions

1. **R112-01's severity.** Rated Low: the residual IP sits beside a keyed
   pseudonym and only audit readers see it. If the maintainer treats any
   personal datum surviving an Art. 17 erasure as Medium, it is fixed first in
   W9.1 either way. A rating change alters only the PR body's line.
2. **R112-10's contract half.** The spec declarations change the spec digest,
   and the eleven SDKs vendor `a221f1bf…`/`9960bbbb…` now. Two options:
   - **Default (proposed):** declare them in W9.1, regenerate, and put the
     §2/rule 6 sentences to contract 1.65. The SDKs re-sync with 1.65; their
     error mapping reads the status alone, so nothing they do changes.
   - Defer the whole item to 1.65.
3. **R112-04's fix shape.** An all-shard sweep for organization tenants, or
   `invalidate_all` when the flushed tenant is an organization's? The first is
   precise, the second simpler. Proposed default: the sweep, matching
   `invalidate_subject`.
4. **R112-08.** Refuse a SCIM request carrying both a cookie and a provisioning
   token, or prefer the cookie? Proposed default: refuse (`401`), since an IdP
   never sends a cookie.

---

## 6. W6's diff (no review of its own)

`git diff dc5bfd4 bbcf271^2`.
- **CI:** the `apiIndex` drift step (`ci.yml:737-744`) adds no new trigger,
  permission or untrusted interpolation.
- **Bench:** `bench-quick`'s `quickvus` guard rejects `''`, `abc`, `0`, `007`,
  `2 0`, `-5` and `1e3`, and accepts `20` and `1`. Its comment over-claims
  (R112-13 f).
- **Runbook:** re-pinned to the 1.1.1 image; `v1.1.1` resolves to `a3174c97`, an
  ancestor of `main`.
- **#757:** zero `{body}`/`{err}`/`{msg}`/`{e}` remain in its five files.
  `permit_bound`, `ca` and `cert` use a per-process random `OnceLock` key. The
  leftovers elsewhere are R112-12.
- #561 and #513 stay open, as plan §0.3 says (comments 6338344373 and
  6338804651).

---

## 7. Issue closures, checked against the tree

**Closed by the tree** (code read at the cited lines; wording from each issue
and its review):
- **W1:** #737, #738, #753, #736, #740, #758 (e) (f) (refusal rows: R112-09),
  #739, #780, #781, #782, #783, #784, #785, #792.
- **W2:** #751, #752 (the first-line limit, R112-03, is separate and older),
  #754, #731, #732, #733, #735, #741, #758 (a) (c) (d) (g), #734, #786, #787
  (except SCIM's token branch, R112-08), #788, #789, #790.
- **W3:** #755, #729 (comments and escapes, R112-06), #746 (two logout
  members, R112-07), #747, #756 (its four rows; the side note on `429` is
  R112-10), #768, #769, #770, #771, #772, #773.
- **W4:** #726, #727, #728, #730, #775, #776, #777, #778, #779, #791 (except
  the organization-tenant flush, R112-04).
- **W5:** #720, #721, #722, #723 (as worded; R112-11), #724, #758 (b) code,
  #764, #765, #766, #767, #774.
- **W6:** #757 (its listed files), #758 (h) (i).
- **W7:** #760 (Q1 at `CONTRACT.md:9547`, Q2 at `:3143`, and the #745 rows),
  #750 (C163-10 at `:9050`, `:9285`, `:13691`; C163-11 present).

**Not yet closed by the tree; closed by W8.3 or W8.4, as the plan assigns:**
- **#725:** "Upgrading from 1.1.0 directly" exists only in
  `claude_dev/release-1.1.2-upgrade-notes.md:9`. `CHANGELOG.md` has no
  `[1.1.2]` yet (W8.4).
- **#755's note:** 1.1.1's "Roll replicas one at a time" is still in
  `CHANGELOG.md:30` and `website/src/data.ts:525` (W8.4 withdraws it).
- **#758 (b), current text:** `Axiam.json` `reasonOutOfScope` (`:22136`,
  `:22315`, "since 1.1.0 (RADIUS D4)") and its `threatModel.ts` copy (W8.3).

**Stay open by design:** #513 and #561 (plan §0.3).

---

## 8. Evidence — checks run at `4a65f2c`

| Command | Exit |
|---|---|
| every commit `origin/main..HEAD`: `git cat-file -p <c> \| grep -q '^gpgsig'` | 111/111 carry a signature |
| `python3 scripts/check-conflict-markers.py` | **1** (R112-02); 0 on `origin/main` |
| `check-spec-digest.py`; `gen-management-registry.py --check` | 0; 0 (202 operations, 1.1.2) |
| `check-crate-layering.py`; `check-remediation-evidence.py` | 0; 0 |
| `check-amqp-transport.py`, `check-audit-ignore-sync.py`, `check-config-key-coverage.py`, `check-docker-context.py`, `check-frontend-coverage.py`, `check-locale-bundle-sync.py`, `check-radius-vendors-nothing.py`; every `--self-test` (9) | 0 each |
| `check-sdk-amqps.py`, `check-sdk-artifact-drift.py` | 2: no SDK sibling repos in the sandbox (environment) |
| `check-website-links.py` | 1: 48 of 55 links refused by the proxy (environment) |
| `bash scripts/check-doc-links.sh`; `check-probe-pin.sh` | 0 (538 links); 0 |
| `docker/radius/tests/check-token-cache.py` and `--self-test`; `fetch-crl-test.sh` (dash, bash) | 0; 0 (20); 0 (91), 0 (91) |
| `cargo build -p axiam-server --no-default-features`, then `--dump-openapi \| cmp - sdks/openapi.json` | 0; 0 (identical) |
| `gen-api-index.mjs` in a scratch copy, then `diff` against `website/src/apiIndex.ts` | 0; identical |
| `cargo check -p axiam-api-rest -p axiam-server --tests --no-default-features` | 0, no warnings |
| `cargo test -p axiam-db --lib schema::tests`; `--test schema_test` | 0 (90); 0 (13) |
| `cargo test -p axiam-db --test deletion_cancel_race_test`; `--test owed_erasure_claim_test`; `--test audit_repository_test`; `--test oauth2_refresh_token_gaps_test` | 0 (6); 0 (1); 0 (10); 0 (10). The last two were re-run after a link-time ENOSPC on the shared target. |
| `cargo test -p axiam-server --no-default-features --test cleanup_task` | 0 (62) |
| `cargo test -p axiam-authz --lib decision_cache` | 0 (31) |
| `cargo test -p axiam-api-rest --no-default-features --test network_gate_test --test oauth2_client_test` | 0 (24 + 44), re-run with `CARGO_INCREMENTAL=0` after a disk-full link failure |
| `cargo test -p axiam-core --lib forwarded_for`; `-p axiam-auth --lib carrier`; `-p axiam-api-rest --no-default-features --test rate_limit_principal_test` | 0 (13); 0 (4); 0 (21) |
| `-p axiam-api-rest --test rate_limit_keying_test`; `-p axiam-amqp --test audit_consumer_test` | "ok. 22 passed"; "ok. 19 passed". The exit codes were lost when the volume filled before the wrapper's `echo`. |
| probe R112-01 (throwaway `axiam-db` test) | the claim survives `pseudonymize_actor` with minimisation on |
| probe R112-03 (throwaway `axiam-api-rest` test) | `client_ip_with` → `6.6.6.6` through a listed proxy |
| probe R112-04 (throwaway `axiam-authz` test) | `Some(Allow)` after `invalidate_tenant(O)`; `insert_if_unchanged` → `true` |
| probe R112-06 (standalone `rustc` copy of both functions) | four non-additive strings classified additive |

Each probe was deleted; the tree at commit carries only this document.

**Not run or not verifiable here:**
- No Docker: the RADIUS e2e, `token-cache-test.sh`, whether FreeRADIUS 3.2.8 at
  `-xx` masks `secret` items, and the examples smoke.
- `cargo test -p axiam-api-grpc --lib rate_limit` and
  `-p axiam-audit --test service_and_middleware`: not run, because the shared
  volume filled.
- R112-05, -07, -08 and -09 rest on reading, not on a running test.
- R112-03's HAProxy behaviour is from HAProxy's documentation; no HAProxy was
  run.
- Live CodeQL alerts: no code-scanning reader in this session.
- `shellcheck` and `actionlint`: not installed.
- Signature validity, as opposed to presence.
- Keycloak 26.8.1 on quay.io.
- The full crate-by-crate suite, workspace clippy, the frontend and website,
  and `cargo deny`/`audit`. These are W8.1's gate, not re-run here.

---

## 9. For W8.3, W8.4, W8.5, W9 and the PR

- **W9.1:** #794 … #806, in this order. R112-04 at Opus 5.5; the rest at
  Sonnet 5.5. R112-02 first, since it alone turns the PR red.
- **W8.3:**
  - T-212 gains R112-01 and R112-03.
  - T-192 and T-484 gain R112-04, R112-05 and R112-09 b (or their fixes).
  - T-484 gains the AMQP sentence (R112-13 b).
  - Reorder T-444's amendments (R112-13 d).
- **W8.4:** the mixed-version erasure line (R112-13 i); #725's note under
  `[1.1.2]`; withdraw "roll replicas one at a time".
- **PR body:** "Security review: no Critical, High or Medium. Low #794 … #798;
  Informational #799 … #806."
- **W8.5:** none of these findings touches coverage.
