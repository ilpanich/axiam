# Security review — release 1.1.1, the combined plan branch (F4)

**Date:** 2026-10-20.
**Against:** `claude/release-1.1.1` at `5298f2980`, the whole release diff
`origin/main...5298f2980` (78 commits, six of them wave merges; 197 files,
15 120 lines added and 1 880 removed). `main` is `6b15aa36a`, the base the six wave branches were cut from (plan
§12.0). Every commit of the range carries a `gpgsig` header (78 of 78; the
sandbox has no `gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them).
**Scope:** what no single review could see. Each wave was reviewed on its own branch:
[W1](security-review-release-1.1.1-w1-2026-10-19.md),
[W2](security-review-release-1.1.1-w2-2026-10-19.md),
[W3](security-review-release-1.1.1-w3-2026-10-19.md),
[W4](security-review-release-1.1.1-w4-2026-10-19.md) and
[W5](security-review-release-1.1.1-w5-2026-10-19.md). W6 had no review of its own;
its diff is read here (§6). Contract 1.63 and the eleven SDK ports were reviewed by
[`sdk-contract-1.63-conformance-review.md`](sdk-contract-1.63-conformance-review.md).
Their findings are not repeated here; their Low and Informational ones are
ilpanich/axiam#720 … #750. This review covers, as plan §9 (W8.2) and the
orchestrator's brief ask:

1. the **six merges** (`9373afab8`, `73955c4ec`, `45abe6561`, `c4f3275fe`,
   `4ba5b7c1b`, `6bae7dd38`), each compared with both parents, and the
   **cross-wave interactions** the brief names;
2. the **commits no wave review read**: `f4224d5ba` and `fc77c562f` (W1, after
   its review), `178568391` (W4, after its review), the two contract commits
   `a6cd10eba` and `d919ba0cc` read as security text, `750be9f0a` (version) and
   `8e90728f8` (threat model 2.43.0);
3. the brief's **eight points**, each judged explicitly (§0.2);
4. **W6's diff** (#699, #691).

**Method:** the method and severity scale of the 1.1.0 combined review
([`security-review-release-1.1.0-2026-10-16.md`](security-review-release-1.1.0-2026-10-16.md)).
The reading was adversarial and covered:
- each merge's `git show --remerge-diff`, and every file two waves touched;
- the code each claim rests on at `5298f2980`, not the commit messages;
- the contract's security sentences, each against the code that keeps it.

The checks run and their exit codes are in §8. IDs are `R111-NN`. Four parallel
read-only investigations (the merges and migrations; limiter, audit and DPoP
interactions; GDPR, audit and AMQP; spec, W6 and CodeQL) fed this text. Every
claim that changes a rating was re-read here at the cited line.

This review fixes nothing. **Nothing is Medium or higher**, so nothing is
dispatched before the release PR. Five Low and three Informational findings are
filed on milestone `1.1.x` (#23) as **#751 … #758**. One earlier finding is
re-rated: **#741, Informational → Low**.

---

## 0. Summary

**No finding is Medium or higher.** The two hand-resolved merges (W3's `schema.rs`
and T-289, W5's deployment guide and spec) lost nothing from either side. v108 and
v109 apply in order, both additive. The cross-wave points the brief names hold,
with one exception that changes a rating: once W4 merged, the threat model rests
T-484's "Mitigated" on the `network_role.*` rows that #741 says an AMQP producer
can forge, so #741 becomes Low. The new findings are all Low or Informational, and
most are older than 1.1.1. They come into view now because two waves meet on them:
- W2.1 gave the server a trust rule for forwarded addresses, but the audit path does not use it (R111-02).
- W2.5 edited the audit middleware's carrier choice and kept a precedence that disagrees with the extractor's (R111-01).
- W3.7 added a key thumbprint to a table that erasure only revokes and nothing sweeps (R111-03).

### 0.1 Findings index

| ID | Finding | Severity | Where | Origin | Issue |
|---|---|---|---|---|---|
| R111-01 | The audit middleware reads `Authorization` first and does not fall back to the cookie when the header yields no token. The extractor reads the cookie first. A cookie-authenticated user who adds a junk `Authorization` header is served, but the request row says `System`, nil tenant. | Low | `axiam-audit/src/middleware.rs:634-664`; `extractors/auth.rs:716-750` | pre-existing; re-touched by W2.5 | #751 |
| R111-02 | Audit and log IPs come from Actix's `realip_remote_addr` (leftmost `X-Forwarded-For`), not from the `TRUSTED_PROXIES`/`TRUSTED_HOPS` rule the limiters now follow. The row records the forged entry the limiter ignores. | Low | `middleware.rs:513-516`; `client_info.rs:31-35`; `request_span.rs:179` | W2.1 × SEC-087 | #752 |
| R111-03 | Erasure revokes the user's `oauth2_refresh_token` rows and never deletes them, and no sweep calls `delete_expired`. Since v109 those rows carry `dpop_jkt`. The GDPR guide calls the table "short-lived". | Low | `cleanup.rs:2544`; `oauth2_refresh_token.rs:505-577`; `gdpr-compliance.md:107-118` | W1 × W3.7 (table pre-existing) | #753 |
| R111-04 | The principal rate-limit key trusts any signature-valid unbound token, including ones the extractor then refuses with `401`, and the shared counter refunds only `429`. A relying party holding a user's token can drain that user's `/federation/*` bucket. | Low | `extractors/rate_limit.rs:357-396`; `rate_limit_shared.rs:458-466` | pre-existing (#633); re-read against W2.5, W3.7 | #754 |
| R111-05 | `_migration_lock` is an `UPSERT` nothing reads. Two replicas booting together run the same migration, and the loser fails its boot on the unique version index. W4.1 rewrote the runner and kept the false doc sentence. | Low | `axiam-db/src/schema.rs:2508-2527` | pre-existing; W4.1 | #755 |
| R111-06 | The spec does not declare `422 reserved_metadata_key`, `409 already_exists`, the PKI `503`, or `409 stale_version`. This is systemic, and no checker compares declared and returned statuses. | Informational | §3 | W1.1, W1.4, W2.6, W4.5 | #756 |
| R111-07 | Test messages in the diff that CodeQL is expected to flag (cleartext logging, one hard-coded key). | Informational | §5 | W1.3, W2.6, W3.1, W3.7 | #757 |
| R111-08 | Text and hygiene after the merges: (a) … (i). | Informational | §7 | cross-wave | #758 |

Re-judged:
- **#741** goes from Informational to **Low** (judgement 3; comment on the issue).
- **#749** stays **Low**, with a precision for the upgrade note (judgement 4; comment on the issue).

### 0.2 The eight points, judged

1. **Cross-wave interactions and merge resolutions — sound.** See §1 and §2.
   - The remerge-diffs of W1, W2, W4 and W6 are empty. W3's and W5's hand hunks keep both sides.
   - Limiter keying × the decision route × the Live profile: every per-address limiter goes through the trusted-proxy rule (§2.1).
   - GDPR and purge × `dpop_jkt`: the purge order covers every tenant table. The enumeration test passes. Erasure leaves the rows behind (R111-03).
   - Grammar × W4's actions: every W4 constant passes the grammar. Server writes are not validated against it (R111-08 (d)).
   - `ConsoleSignIn` × DPoP attribution: the cache never admits a request without its proof (§2.2).
   - W1.10's seam × `audit_wraps_routes`: the scan holds on the merged `boot.rs:3138-3173`.
2. **Undeclared responses in the spec — not a security finding; Informational (R111-06, #756).**
   - SDK error mapping (§2) and retry (§16.3) read the status alone.
   - The registry generator reads 2xx only.
   - Contract 1.63 §27.4 rule 7 already lists all four answers.
   - The fix is annotations plus a regeneration. It changes the spec digest, so it belongs with the next contract bump, not this release: the eleven SDKs vendor `d919ba0cc`'s spec now. Not Medium.
3. **#741 — re-rated Low.** Nothing reads these rows back:
   - no Rust query;
   - no notification mapping (`notification_rule.rs:103-171`);
   - no special case in the console.

   But on the merged tree:
   - T-484 is Mitigated because of these rows;
   - `docs/admin/README.md:556-575` tells operators "the row's `actor_id` is the writer";
   - the AMQP consumer copies actor, type, IP and metadata as sent (`audit_consumer.rs:206-215`), with no provenance field.

   A producer holding one tenant's HMAC subkey can therefore frame an administrator of that tenant with a forged success row (§2.3). Nothing automated acts on it, so not Medium.
4. **#749 — Low stands** (§2.4).
   - A converted client registered for DPoP fails closed: W3.7's rule refuses every confidential-era token, because none is bound to a key.
   - A converted client *not* registered for DPoP — the usual #675 device — redeems those tokens on `client_id` alone.
   - The upgrade note must say so and tell operators to revoke them or enable DPoP binding.
5. **The test seams are unreachable in a release build.**
   - `ServeOptions::audit_hold_for_tests` (`boot.rs:345-389`): not `Deserialize`, read from no configuration, environment variable or CLI flag. `main.rs:672` passes `ServeOptions::default()`, so it is `None`. Only code that links the library, and so already owns the process, can set it.
   - `verify-probe`: `cargo tree -e features,normal -p axiam-server --target all` shows no edge to it.
     - Only the crate's own dev-dependency enables it (`axiam-oauth2/Cargo.toml:54-57`, resolver 3).
     - `docker/Dockerfile.server` builds `--release -p axiam-server` without dev-dependencies.
     - Even if enabled, it is a thread-local counter.
6. **Migrations — safe; the "v109 without v108" datastore cannot exist.**
   - On a 1.1.0 datastore (v107), the runner applies v108, then v109, each in its own transaction.
   - Both contain `DEFINE … IF NOT EXISTS` only, with no `UPDATE` and no `OVERWRITE`; tests `v108_adds_only_…` and `v109_adds_…` pin this.
   - A datastore with v109 recorded and v108 missing needs a deployed W3-only build. Images are published only from `main` and `v*` tags; `v1.1.0` is the newest tag, and `main` stops at v107. So no such build ever existed.
   - If one did, W4.1's runner would apply v108 late with a `WARN`. v108 and v109 touch disjoint tables, so that is safe.
   - The lock the runner claims is not one (R111-05). Its idempotence sentence over-claims for older versions (already #729).
7. **Spec and `apiIndex.ts` agree.**
   - `website/scripts/gen-api-index.mjs`, re-run into a scratch copy, prints "291 operations across 197 paths, 13 domains" and is identical to the committed file.
   - `device_authorization`'s summary and description match the handler's doc comment (`handlers/oauth2.rs:4238-4261`) word for word. The stale summary was a 1.1.0 defect: an unrelated doc comment had been picked up. W3.8 fixed the spec; `apiIndex.ts` followed only at W8.4a, because no CI job regenerates it (R111-08 (i)).
   - `check-spec-digest.py` and `gen-management-registry.py --check` exit 0.
8. **CodeQL — expect alerts in tests, none in `src`** (R111-07, #757).
   - The most likely: `device_flow_test.rs` assertion messages that interpolate token-endpoint answers obtained with the client secret.
   - `vault_provider_test.rs:378-380`, the exact shape #717 removed elsewhere.
   - `permit_bound_test.rs:34`, `[0u8; 32]` as a key.
   - W1.13's six labels in `vault_ca_key_store_test.rs` are correct, but that file still formats `{msg}`/`{err}` in its non-leak assertions.
   - The Rust SDK's hard-coded HMAC test key is in another repository. If CodeQL reports it, that report belongs to the SDK's PR, not this one.

---

## 1. The merges

All six wave branches fork from `6b15aa36a`, and none contains another
(`git merge-base --is-ancestor`, every pair).

| Merge | Wave | `--remerge-diff` | Verdict |
|---|---|---|---|
| `9373afab8` | W1 | empty (clean) | sound |
| `73955c4ec` | W2 | empty | sound |
| `45abe6561` | W3 | `schema.rs`, `Axiam.json` (T-289) | sound — below |
| `c4f3275fe` | W4 | empty | sound |
| `4ba5b7c1b` | W5 | `docs/deployment/README.md`, `sdks/openapi.json` (+ registry) | sound — below |
| `6bae7dd38` | W6 | empty | sound |

**Files two or more waves touched.**
- `schema.rs` (W1, W3, W4, W5).
- `boot.rs` (W1, W2, W5).
- `server.rs` (W2, W3, W5).
- `handlers/oauth2.rs` and `device_flow_test.rs` (W2, W3).
- `cleanup.rs`, `cleanup_task.rs` and `tenant_test.rs` (W1, W3).
- `axiam-server/src/lib.rs` (W1, W2).
- `certificate_repository_test.rs` (W1, W4).
- `state/mod.rs` (W2, W5).
- The network files (W4, W5). W5's side of these is comment-only (the rename).
- The threat model (W1 … W5).
- The deployment guide (W1, W2, W5).

A clean textual merge is not a correct one, so:
- `cargo check -p axiam-db -p axiam-api-rest -p axiam-server --tests --no-default-features` was run on the merged tree: exit 0, no warnings;
- the shared files were searched for duplicated items (the only repeated names are `cleanup.rs` free functions beside `CleanupTask` methods, as intended);
- W2.4's removed public-client bucket has no remaining reference (`git grep rate_limit_client_ip\|oauth2_token_public`: none).

**W3 (`45abe6561`).**
- `schema.rs`: `MIGRATIONS` ends v107, v108 (`pending_record_markers`), v109 (`rate_limit_bucket_updated_at_index`, which also carries W3.7's `dpop_jkt`).
  - It has 105 entries, 1 … 109 without 86 … 89.
  - Each `version` equals its `SCHEMA_V<n>`.
  - Both SQL constants are whole. All three scope tests are kept.
  - The newest-version assertion is `Some(&109)`.
  - W4.1's `UNCLAIMED_VERSIONS = 86..=89` and `migrations_are_contiguous` pass (`cargo test -p axiam-db --lib schema::tests`: 87 passed, exit 0).
- T-289 in `Axiam.json` is the union of both sides, compared character by character. W1's side adds the #684 (a) corrections, the #677, #675 (3) and #681 (ii) amendments and #679. W3's side adds #685's D-3 amendment. The STRIDE document's T-289 cites the same issue, finding and decision keys.

**W5 (`4ba5b7c1b`).**
- The deployment guide keeps W2's `TRUSTED_PROXIES` rows (`:889`, `:936`) and paragraph, and adds W5's Live-profile firewall sentence. It drops W5's now-false "#711 is planned for 1.1.x".
- The spec is the three-way merge of the W4 side, the base and the W5 side, apart from the version and digest lines. The digest was regenerated and the registry is in sync.

**The merged `boot.rs`** still wraps the audit middleware at the App level (`.wrap(audit_middleware…)` at `:3144`, inside the single `App::new()` at `:3138`). That is what `audit_wraps_routes` pins (its stated premise is weaker; R111-08 (g)).

---

## 2. Cross-wave interactions

### 2.1 Limiter keying (W2.1) × the decision route (W4.4) × the Live profile (W5)

Every per-address key goes through `XForwardedForKeyExtractor::configured()` or
`select_rate_limit_ip` with the configured list:
- the REST governor (`server.rs:97-118`);
- the client-aware governors (`:137-150`);
- the federation backstop (`:178-181`);
- the decision route's per-address backstop (`:1956-1964`);
- SCIM (`axiam-scim/src/routes.rs:64`);
- the shared counter (`rate_limit_shared.rs:343`);
- gRPC (`axiam-api-grpc/src/middleware/rate_limit.rs:221,892,926`).

No production `::default()` extractor remains. Lockout is per account. The decision route's own allowance is keyed on the authenticated service account (`network_decide.rs:352-366`), so no caller-written value reaches it.

With the list empty (the default) in the Live topology, a client that reaches the native listener still chooses its per-address key. That is the documented and warned residual:
- the boot `WARN` fires, because native TLS is on and the list is empty (`boot.rs:1615-1621`);
- `docs/pki/freeradius.md:672-692` and the guide tell the operator to set the list and to firewall the listener.

What the documentation cannot express is a deployment with **no** appending proxy. "Empty" means "honour everyone", so per-peer keying needs an undocumented placeholder entry (R111-08 (a)).

The audit row's IP does not follow this rule (R111-02).

### 2.2 DPoP attribution (W2.5) × `ConsoleSignIn` and device tokens (W3.7)

The middleware validates a token's signature, expiry and issuer only
(`middleware.rs:637-680`) and caches the identity. Every reader that admits a
request from the cache goes through `cached_identity()`, which re-runs
`enforce_sender_constraint` against this request's own proof (`auth.rs:1014-1020`).
The proof's single-use record is written in `apply` (`auth.rs:503`).
`ConsoleSignIn`'s refusal of a token carrying `client_id` runs before the session
check either way (`auth.rs:516-525`).

The two readers match the scheme the same way (case-insensitive `bearer`/`dpop`).
A DPoP-bound token sent under `Bearer` still needs its proof, so no downgrade
exists. Attribution of a refused request names the token's subject with the
failure outcome; the `authenticated: true` flag on such rows over-states it
(R111-08 (c)).

The carrier *precedence* differs: header first in the middleware, cookie first in
the extractor (R111-01). The principal limiter keys on the cached identity before
the extractor refuses the request (R111-04).

### 2.3 The audit grammar (W2.8) × W4's actions; #741

Every W4 action passes W2.8's grammar: `network_role.{assigned,unassigned,granted,revoked}`, the `*_refused` set, `certificate_binding.bound` and `network_role.permission_revoked_by_reconcile`. The reserved actions W1 writes (`gdpr.user_pseudonymized`, `tenants.purged`) pass it too, and stay refused at ingestion. So the deduplication reads `erasure_recorded` (`account_deletion.rs:731`) and `purge_recorded_since` (`tenant.rs:644`) cannot be fed a forged row.

The server's own writes are never checked against the grammar; only the consumer checks (`audit_consumer.rs:137,153`). That is fine today, but no test pins it (R111-08 (d)).

**#741 on the merged tree.**
- The producer signs with a key derived per tenant, so the message binds `tenant_id`.
- Within that tenant it can append a row identical to the gate's success row, naming any `actor_id`.
- W4.3 made those rows T-484's evidence and the admin guide's record of "who gave a device its placement".
- An automated consumer would make this Medium; there is none, so **Low**.
- Fix, as #741 proposes: reserve `network_role.` and `certificate_binding.`. Alternatively, stamp ingested rows `metadata.source = "amqp"` and show it. At minimum, qualify T-484 and the guide.

### 2.4 The confidential → public conversion (W3.1) × the refresh binding (W3.7); #749

`refresh_token_binding` binds only a public client registered with
`dpop_bound_access_tokens` (`dpop.rs:113-122`). Confidential-era tokens are therefore always unbound.

**A converted client with DPoP binding:**
- every refresh needs a verified proof (`token.rs:1594-1601`, otherwise `invalid_client`);
- `enforce_refresh_token_binding` refuses an unbound token (`dpop.rs:147-163`, called at `token.rs:2866-2870`);
- the result is fail-closed, at the cost of one new sign-in.

**A converted client without DPoP binding:**
- the binding is a no-op, and the stored token redeems on `client_id` alone (`token.rs:2722-2770`);
- that is #749 as filed;
- the registration is read at redemption time, so enabling DPoP later closes it.

Pending device codes live ≤ 600 s and still need the user's approval: negligible.

**Low stands.** For W8.4's upgrade note: "after converting a client, revoke its refresh tokens or enable DPoP binding for it".

### 2.5 Erasure and purge (W1) × W3's and W4's data

The schema diff adds one table, `tenant_purge_pending` (v108). It is deliberately outside `TENANT_PURGE_ORDER` (`schema.rs:5195-5202`) and has no `tenant_id`. `settle_purge_record` removes it, conditional on its `claimed_at` stamp (`tenant.rs:484`), after `tenants.purged` exists (`cleanup.rs:683-747`). Every other change is a field or an index.

`schema::tests::every_tenant_scoped_table_is_purged` asserts both directions. It passes (`cargo test -p axiam-db --lib every_tenant_scoped_table_is_purged`, exit 0). It covers `oauth2_refresh_token` (`tenant_purge.rs:379`). `rate_limit_bucket` is deployment-wide and swept by W3.3's index.

The recovery of a cut unit writes its record exactly once:
- the claim is a compare-and-set `UPDATE … WHERE marker = $read` (`account_deletion.rs:684-713`, `tenant.rs:599-628`);
- a "record exists" read happens before the write;
- the lease is one hour.

The write and the clear are separate transactions. A duplicate needs a claimant stalled for more than the lease between its read and its write. Only the tenant-purge twin has a concurrency test (R111-08 (f)).

A user's erasure revokes, and never deletes, the refresh-token rows that now carry `dpop_jkt` (R111-03).

W4's bindings tie a certificate to a **service account**, never a user (`certificate.rs:1007-1041`). W1.5's second revocation matches `user_id`/`metadata.user_id`, so it also reaches a user certificate later bound to a service account.

No W4 row carries an e-mail address or a name. `metadata.grantee.id` keeps the UUID, and erasure's role removal writes no `network_role.unassigned` row (R111-08 (e)).

---

## 3. The undeclared responses (point 2; R111-06)

| Answer | Returned by | Declared? |
|---|---|---|
| `422 reserved_metadata_key` | `tenants.rs:198-209` (create `:285`, update `:666`) | no — create `201`; update `200`, `404` |
| `409 already_exists` | `schema.rs:4891-4895` via `classify_write_error` (`b53d74bb0`) | no — certificates `generate`, `sign_csr`; CA `generate`, `import`, `generate_intermediate`, `sign_intermediate_csr` |
| `503 service_unavailable` (permit timeout) | `axiam-pki/src/permit.rs:19-30`; `ca.rs:165,500,668`; `cert.rs:519,610,866`; `pgp.rs:66,169` | no — the six above, `pgp_keys` `generate`, `sign_audit_batch`. No `reason_code`, no `Retry-After` |
| `409` / `stale_version` | `network_gate.rs:144-262`; `roles.rs` (eight sites), `permissions.rs:317,513` | no (and not at 1.1.0) |

The SAML IdP's busy page is HTML and outside the spec. W2.6 left login and register untouched; their older hash-gate `503` and `429` are undeclared too.

**Why this is not a security finding.**
- No SDK behaviour reads the spec's error statuses. Mapping is by status (CONTRACT `:238-249`, §27.4 rule 7 `:8504-8535`), and retry is by status and by whether the operation changes state (§16.3 `:3558-3573`). Every `503` here is a write, which no SDK retries.
- The answers fail closed either way.

The gap is systemic: at 1.1.0 and 1.1.1 alike, 53 of 239 secured operations declare `401`.

**Fix (#756):** the annotations plus a checker. It ships with the next contract bump, because a new digest makes the eleven SDKs re-vendor.

---

## 4. Contract 1.63 as security text

Each security sentence of §34.7 was read against the code:

- **(a) "The server ignores both [cookie, CSRF header] there".** It holds for the operations the §14.6 test exercises (the device operations and `/oauth2/token`). `/oauth2/authorize` reads `axiam_access` and `axiam_op_session` by design (`handlers/oauth2.rs:590-760`): it is the browser's endpoint, not an SDK's. No finding.
- **(d) The public DPoP client's refresh binding.** It is kept as stated: a proof is required, and another key or an unbound token is `invalid_grant` (§2.4). "Bound to the proof's key" applies only to clients registered with `dpop_bound_access_tokens`, which is what the item says.
- **(e) The decision route's four remaining cost differences.** They match `network_decide.rs` as W4.4 left it (the W4 review read them).
- **(o) "a `NetworkError` by §2, not retried for a write".** It matches §2 and §16.3.
- **(c), (m) "The server's refusal is unchanged and stays the authority".** True (§2.3). The contract makes no claim about the `network_role.` namespace, which is #741's subject.

---

## 5. CodeQL (point 8; R111-07)

There is no CodeQL workflow in the repository. CodeQL runs as GitHub's default
setup and scans tests, as shown by the earlier fixes `057a9c5a`, `74ca43f9`,
`ed421f32` and `ac16ca17`. The live alerts could not be listed: code scanning
returns `403` here.

Expected on the platform PR, most likely first:

1. **`rust/cleartext-logging` in `device_flow_test.rs`.** Assertion messages print a whole token response as `"{body}"`.
   - The request carried the client secret: `:1514`, `:1348` (caller `:1501`), `:705`, `:719`, `:733`.
   - The same shape without a secret: `:1218`, `:1265`, `:1397`, `:1422`, `:1529`, `:1535`, `:2292`, `:2316`.
2. **`rust/cleartext-logging` in `vault_provider_test.rs:378-380`** (W1.3): `"{err}"` after `!err.contains("test-token")`.
3. **`rust/hard-coded-cryptographic-value` at `permit_bound_test.rs:34`.**
4. **Lower likelihood:** `network_gate_test.rs:1948-2088`, `vault_pki_test.rs`.

In `src`: nothing expected. The log sites the diff adds name an action length, an
error, a `client_id` or a path. `UNKNOWN_CLIENT_SECRET_HASH` is a dummy digest that
equalises timing.

---

## 6. W6's diff (no review of its own)

**`fapi-conformance.yml` (#691).**
- The dispatch inputs reach `run:` only through `env:` (`:130-133`, `:260`); no `${{ inputs.* }}` appears in a script.
- `permissions: contents: read`; no `secrets.*`; the three actions are SHA-pinned (`:156`, `:158`, `:464`).
- The `steps.inputs.outcome == 'success'` guard skips the teardown only when nothing was started. After a passed validation, `always()` still tears down on failure or cancellation.
- `validate_inputs_test.sh` pins five guarded steps and no bare `always()`.

**`benchmarks/justfile` `bench-quick` (#699).**
- `BENCH_CERTS_DIR` is anchored at `$PWD` and can still be overridden.
- `meta.json` holds the target, profile, image reference, digest or ID, build ref, window, VUs, hook and timestamp. Every value goes through `jq --arg`, so no secret is written and nothing can be injected.
- A non-numeric `quickvus` loses the report (R111-08 (i), robustness only).

**`radius-e2e.yml`:** a path filter and a weekly `schedule:`, `contents: read`.

**No finding.**

---

## 7. R111-08 — text and hygiene (#758)

(a) The empty `TRUSTED_PROXIES` cannot say "honour nobody"; the "Direct, no proxy" row (`docs/deployment/README.md:936`) says "list the proxies".

(b) D3 and D4 remain in current text:
- `Axiam.json`, about l.22136 and l.22315, and therefore `website/src/threatModel.ts`;
- `threat-model-stride.md:4767`;
- `axiam-core/src/models/network.rs:752`;
- `network_decide_test.rs:780`.

(c) The audit middleware records `authenticated: true` on a signature-only validation. Since W2.5 that includes a DPoP token sent without its proof.

(d) No test pins the server's action constants to W2.8's grammar.

(e) Erasure versus W4's rows:
- `pseudonymize_actor` leaves `metadata.grantee.id`;
- erasure's role removal writes no `network_role.unassigned` row.

(f) The owed-erasure recovery has no concurrency test.

(g) `audit_wraps_routes` states a stronger premise than the invariant it checks (cf. #733).

(h) v109 gained `dpop_jkt` after v109 first existed on the W3 branch. Development datastores only; fails closed.

(i) Two robustness gaps:
- `bench-quick` loses its report on a non-numeric `quickvus`;
- no CI job regenerates `website/src/apiIndex.ts`.

---

## 8. Evidence — checks run at `5298f2980`

| Command | Exit |
|---|---|
| every commit `origin/main..HEAD`: `git cat-file -p <c> \| grep -q '^gpgsig'` | 78/78 signed |
| `python3 scripts/check-spec-digest.py` | 0 |
| `python3 scripts/gen-management-registry.py --check` | 0 (202 operations, 29 namespaces) |
| `node website/scripts/gen-api-index.mjs` (scratch copy) then `diff` against `website/src/apiIndex.ts` | identical |
| `python3 scripts/check-remediation-evidence.py` | 0. It was 1 on the session's shallow clone ("commit … does not exist"); 0 after `git fetch --unshallow`. Not a defect. |
| `python3 scripts/check-crate-layering.py` | 0 (19 crates, 4 declared test-only inversions) |
| `bash scripts/check-doc-links.sh` | 0 (537 links, 78 files) |
| `check-config-key-coverage.py`, `check-conflict-markers.py`, `check-audit-ignore-sync.py`, `check-radius-vendors-nothing.py`, `check-docker-context.py`, `check-amqp-transport.py`, `check-locale-bundle-sync.py` | 0 each |
| `cargo check -p axiam-db -p axiam-api-rest -p axiam-server --tests --no-default-features` | 0, no warnings |
| `cargo test -p axiam-db --lib schema::tests` | 0 (87 passed, among them `migrations_are_contiguous` and the v108/v109 scope tests) |
| `cargo test -p axiam-db --lib every_tenant_scoped_table_is_purged` | 0 |
| `cargo tree -e features,normal -p axiam-server --target all \| grep -c verify-probe` | 0 edges |
| threat model: `Axiam.json` 2.43.0 parsed. Ids 1 … 488 unique; `threatTop` 488; 457 Mitigated, 21 Open, 10 Not applicable, equal to `threat-model-stride.md:13`. Every STRIDE table row's status equals the JSON's (484 rows; T-272, T-275, T-276 and T-280 carry "Closed — <sha>" cells, the same since 1.1.0). | script |

**Not re-run here,** because W8.1 ran it on the merged tree with no failure:
- the full test suite crate by crate;
- workspace clippy with SAML on and off;
- the gRPC `client` feature;
- the frontend and the website;
- `cargo deny`, `cargo audit` and `npm audit`;
- the RADIUS end-to-end test on both profiles.

The builds used private target directories, deleted afterwards.

---

## 9. For W8.3, W8.4, W8.5 and the PR

- **CHANGELOG upgrade notes (W8.4):**
  - #749: after a device client is converted to public, its confidential-era refresh tokens redeem on `client_id` alone unless the client is DPoP-bound. Revoke them, or enable DPoP binding.
  - R111-05: roll replicas out one at a time on an upgrade that carries migrations (v108, v109), or expect one replica's boot to fail once and recover on restart.
- **PR body:** "Security review: no Critical, High or Medium. Low #751 … #755, #741 (re-rated); Informational #756 … #758."
- **Threat model (after this release, not now):** T-484's "Mitigated" rests on rows #741 shows an AMQP producer can imitate in-tenant. Qualify T-484 with #741 when #741 is fixed or in the next reconciliation. T-212 and SEC-087 gain R111-02.
- **W8.5:** none of these findings touches coverage.
