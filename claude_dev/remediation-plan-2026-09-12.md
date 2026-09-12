# Remediation plan — the residuals the 2026-09-12 threat review left open

> **Status: NOT YET EXECUTED.** Each section gains an `EXECUTED` block at its
> head as it lands, in the form
> [`remediation-plan-2026-09-04.md`](remediation-plan-2026-09-04.md) uses: what
> actually shipped, which tests went in, what the plan did not anticipate, and
> what the model and the docs now say. A plan whose execution record lives only
> in commit messages is a plan nobody re-reads.

The 2026-09-12 threat review closed T-254 by decision and left the register at
**16 open of 266**. This plan works eight items. Six of them are *residuals
recorded inside entries the model already calls Mitigated* — the sentence at the
end of a mitigation that begins "the residual is" or "known limitation" — and
two are open entries (T-39, T-110) whose recorded remedy has never been built.
Residuals of that kind are the most expensive thing in a threat model to leave
alone: they are invisible to every count, every dashboard and every website
page, and the next person to read the entry reads a control that sounds whole.

| Item | Threat(s) | Today | After |
|---|---|---|---|
| R-1 | T-261 | Mitigated, residual: three hand-maintained personal-data column lists | Mitigated, residual gone |
| R-2 | T-241 | Mitigated, residual: requested claims lost on refresh | Mitigated, residual gone |
| R-3 | T-244 | Mitigated, residual: an unparseable default tenant is silent | Mitigated, residual gone |
| R-4 | T-262 | Mitigated, residual: a contended write is a bare `5xx` | Mitigated, residual gone |
| R-5 | T-132 | Mitigated, residual: three credentials read before any provider exists | Mitigated, residual gone |
| R-6 | T-39, T-143 | **Open** (Medium ×2) | **Mitigated**, residual: one poll interval |
| R-7 | T-110 | **Open** (Medium) | **Mitigated**, residual: the deployment still chooses |
| R-8 | T-266 | Mitigated, residual: no SDK implements contract §21.3 rule 2 | Mitigated, residual gone |

Open register **16 → 13**. Medium open **6 → 3**. *Authentication & session
management* **1 → 0**, *Audit, webhooks, email & notifications* **2 → 1**,
*Client SDKs & admin UI integration surface* **4 → 3**. No other count moves,
because no other item changes a status.

---

## 1. Order, and how to cut the work

1. **R-1, R-2, R-3, R-4** first, in that order, one commit each on one branch.
   They are small, independent, and none of them touches an SDK. R-4 adds one
   test per SDK repository but requires **no SDK behaviour change**, so its
   SDK half rides whichever SDK PR that repository gets for R-6 and R-8.
2. **R-5** next, and **in its own PR if it does not land cleanly** with the
   others. It is the largest server-side item, it changes the boot sequence,
   and it touches every deployment manifest. A boot-ordering change that shares
   a PR with four unrelated fixes is a PR nobody can revert cleanly.
3. **R-6 server-side**, then **R-8 server-side**, then the SDK fan-out for
   both. Server and contract first, pushed, before any SDK branch: an SDK
   change is written against the contract text and the spec it re-vendors,
   never against a draft (the fan-out rules below).
4. **R-7** any time after R-1; it is independent of everything else.

Every `axiam` commit: `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets -- -D warnings` on rustc 1.98.1 (or the
narrow per-crate forms `CLAUDE.md`'s disk-hygiene section prescribes, with
`cargo clean` between items), `scripts/check-crate-layering.py`,
`scripts/check-doc-links.sh`, a `CHANGELOG.md` entry under `[Unreleased]`, and
the threat-model bookkeeping of §9 **in the same commit**. A fix the model does
not know about is a fix the website will not show.

---

## 2. R-1 — the personal-data column lists become structural

> **EXECUTED — R-1, 2026-09-12.** `crates/axiam-core/src/personal_data.rs` is
> the one declaration: a `UserColumn` row per column of the `user` table, with
> `erasure` and `export` as **two** fields rather than one "is personal data"
> flag — the shape that lets `password_hash` be erased and never exported
> (D-10) and `created_at` be exported and never erased, both of which a single
> flag gets wrong — and a `note` required wherever either is `None`, so
> "nobody classified this" and "classified as neither" stay different states.
>
> `anonymize_user` and `delete` render their shared `SET` fragment from it
> (`shared_erasure_fragment`) and keep their own path-specific clauses; the
> asymmetries between them are recorded on the columns they belong to rather
> than harmonised. The two `email` bind names were unified to
> `email_replacement`, which is the only visible consequence and is internal to
> the two statements. The export literal stays hand-written and gained a home
> of its own, `cleanup.rs::profile_section`, because two of its entries are not
> column reads — `id` is the record identifier, and `phone_number_verified` is
> a derived boolean — and deriving it would have to special-case both.
>
> Gates, all three green: `user_schema_matches_the_declared_inventory`
> (`crates/axiam-db/tests/personal_data_gate.rs`) reads `INFO FOR TABLE user`
> off a live in-memory datastore after migrations and compares both ways;
> `the_profile_section_shows_exactly_the_declared_export_keys` and
> `no_credential_column_is_exported` (in `cleanup.rs`); and
> `every_unerased_or_unexported_column_says_why` plus the verbatim fragment pin
> (in `personal_data.rs`). The gate carries its own I4 twin —
> `the_gate_detects_a_column_the_inventory_does_not_declare` builds the same
> comparison against a schema set with one extra column and requires it to be
> reported — so a green run means the check runs rather than that it cannot
> fail. `crates/axiam-db/tests/w7_sensitive_columns_test.rs` is **untouched**,
> all eight still green: reading the row back is the one assertion a fourth
> path sharing a bad statement cannot satisfy.
>
> One thing the plan did not anticipate: `INFO FOR TABLE` does not decode into
> `serde_json::Value` through `Response::take` on surrealdb 3.2 — the index
> must be a `usize` and the target an `Option<T>`. Taking
> `Option<serde_json::Value>` keeps the test free of the driver's own value
> model, which has changed shape across majors.
>
> Docs: `docs/compliance/gdpr-compliance.md` §1 (the warning paragraph becomes
> a three-row table of what fails and where) and §2 (the tombstone paragraph
> names the shared render and its own additions); `CHANGELOG.md` under
> **Security**. Threat model: T-261's residual sentence replaced in
> `Axiam.json` (model 2.12.0 → **2.13.0**; the version string had lagged behind
> the prose, which already said 2.12.1 for the T-254 state),
> `threat-model-stride.md` and `threat-modeling-and-security.md`. Status
> unchanged (Mitigated), so no count moves;
> `node website/scripts/gen-threat-model.mjs` prints `9 diagrams, 266 threats
> (250 mitigated, 16 open)` and the generated files were reverted.

**Closes** the residual T-261 records: *"the three lists are still
hand-maintained, and the compile-time guard covers only the SCIM one."*

**The defect, as the model records it.** Four paths decide what a `user` column
means, and three of them decide it by writing the column name out by hand:

| Path | Location | Guard today |
|---|---|---|
| Art. 17 erasure | `axiam-db/src/repository/user.rs::anonymize_user` | none — an explicit `SET` list |
| Administrator tombstone (`DELETE /api/v1/users/{id}`) | `axiam-db/src/repository/user.rs::delete` | none — an explicit `SET` list |
| Art. 15 export, `profile` section | `axiam-server/src/cleanup.rs::aggregate_export_data` | none — an explicit `json!` field list |
| SCIM no-op detection | `axiam-scim/src/users.rs::user_patch_is_noop` | **compile-time** — destructures `UpdateUser` |

A column named by none of the first three survives erasure and never reaches an
export. That is exactly how `phone_number` and `address` were nearly stranded,
and the entry says so. The fourth path is guarded because somebody wrote the
destructure; the guard does not generalise, because `UpdateUser` is not the
`user` table.

**The design: one declared inventory, two derived statements, two gates.**

Add `crates/axiam-core/src/personal_data.rs` (layer 0 — every consumer is
above it, and `scripts/check-crate-layering.py` needs no new edge):

```rust
/// One row per column of the `user` table. Every column has a row; a column
/// with no row fails `user_schema_matches_the_declared_inventory`.
pub struct UserColumn {
    pub name: &'static str,
    /// What erasure writes, or `None` when the column holds no personal data
    /// and both erasure paths deliberately leave it — `note` then says why.
    pub erasure: Option<Erasure>,
    /// The key this column appears under in the Art. 15 export's `profile`
    /// section, or `None` when it is deliberately withheld — `note` says why.
    pub export: Option<&'static str>,
    pub note: &'static str,
}

pub enum Erasure {
    /// `SET <col> = NONE`.
    ToNone,
    /// `SET <col> = <literal>` — `''`, `{}`, `false`, `0`.
    ToLiteral(&'static str),
    /// `SET <col> = $<param>` — the path binds the value, because it derives
    /// from the row (a pseudonym, an email hash, an `.invalid` placeholder).
    ToParam(&'static str),
}

pub const USER_COLUMNS: &[UserColumn] = &[ /* … */ ];
```

`erasure` and `export` are **orthogonal**, which is the thing a single
"is personal data" boolean gets wrong: `password_hash` and `mfa_secret` are
erased and are deliberately *not* exported (D-10 — exporting a credential is a
security hole, not an Art. 15 obligation), while `created_at` is exported and
deliberately not erased. Both cases are expressible only because they are two
fields, and `note` is required to be non-empty wherever either is `None`, so
"not classified" and "classified as neither" are different states.

Then:

- **`anonymize_user` and `delete` build their shared `SET` fragment from
  `USER_COLUMNS`** rather than spelling it. Each keeps its own path-specific
  clauses verbatim — `status = 'Anonymized'` versus `'Deleted'`,
  `deletion_pending = false` and `scheduled_purge_at = NONE` on the Art. 17 path
  only, `email_verified_at`/`totp_last_used_step`/`failed_login_attempts` on the
  tombstone only. **The clause set is identical to today's** for the
  columns the inventory covers, asserted by a test that pins the rendered
  fragment verbatim. Clause *order* becomes the inventory's — which neither
  statement depended on (the two already disagreed about it) and SurrealDB does
  not observe. The two paths' present asymmetries are preserved rather than
  harmonised, because harmonising them is a behaviour change and this item is a
  gate.
- **The export keeps its `json!` literal** — it maps `phone_number_verified_at`
  to the derived `phone_number_verified`, which no mechanical derivation would
  produce, and the model's own reasoning for that (exporting the internal
  column name would describe AXIAM's storage rather than the subject's data)
  is worth keeping. What it gains is a test that the profile object's key set
  is exactly the set of `export` keys in the inventory.
- **`user_patch_is_noop` keeps its destructure**, unchanged. It guards a
  different thing (`UpdateUser`'s fields) and guards it well.

**The two gates.**

1. `user_schema_matches_the_declared_inventory` (in `axiam-db`, against a live
   in-memory datastore after migrations): runs `INFO FOR TABLE user`, folds
   `address.*` sub-fields into `address`, and asserts the resulting set equals
   the `USER_COLUMNS` names exactly — in both directions, so a removed column
   fails as loudly as an added one. This is the gate the item asks for: a
   column added to `schema.rs` and nowhere else fails here, naming itself.
2. `every_personal_column_is_erased_and_exported` (in `axiam-core`, pure):
   every row with `erasure: Some(_)` appears in the derived fragment, every row
   with `export: Some(_)` has a non-empty key, and every row with both `None`
   carries a non-empty `note`.

**Tests.** The two gates above; the fragment-identity pin; the export key-set
test; **and the existing erase-then-read-back tests unchanged** —
`crates/axiam-db/tests/w7_sensitive_columns_test.rs` is not touched, because a
test that reads the row back is the only one that cannot be satisfied by two
paths sharing a bad statement, and rewriting it against the new machinery would
throw away exactly that property. One negative test with its I4 twin: a fixture
inventory missing a column the schema has fails gate 1; the real inventory
passes it.

**What this does NOT change.** No erasure semantics, no export contents, no
SCIM behaviour, no schema, no route, no wire format. A deployment upgrading
across this commit sees byte-identical erasure SQL and a byte-identical export.

**Docs.** `docs/compliance/gdpr-compliance.md` §1 and §2: the two paragraphs
that warn "anybody adding a user column that holds personal data must add it
here as well" become a description of the gate — where the inventory is, what
fails and with what message, and that the warning is now enforced rather than
addressed to the reader's memory.

**Threat model.** T-261's mitigation: the residual sentence is replaced by the
inventory and the two gates. Status unchanged (Mitigated); no count moves.

---

## 3. R-2 — requested claims survive a refresh

> **EXECUTED — R-2, 2026-09-12.** Schema **v61**: one optional array on
> `oauth2_refresh_token`, v59's shape on the other side of the grant and for
> the same reasons, with no backfill and no index. `RefreshToken` and
> `CreateRefreshToken` carry `requested_userinfo_claims: Vec<String>`; the row
> structs decode `Option<Vec<String>>` through `#[surreal(default)]` and
> `unwrap_or_default`, so a pre-v61 row still reads and reads as "named no
> claims" — which is what it was.
>
> The code exchange writes the list onto the refresh token it issues, and the
> refresh grant copies it onto the successor and passes it to the mint.
> `issue_access_token_for_client` gained a twelfth parameter rather than a
> second function, and `issue_access_token_enriched` passes `&[]`: the empty
> slice produces a byte-identical token, which is the relationship `cnf`, `ext`
> and `client_id` already have to the wrappers above them, and the doc comment
> now says so for one more of them.
>
> Tests: five in `token_service.rs` — the list reaches the refresh token the
> code exchange issues; a refreshed access token asserts it; **rotation copies
> it onto the successor**, which is the one a single-refresh test would not
> catch and which would have let the defect return one rotation later; the I4
> twin (a pre-v61 row mints a token with the member *absent*, not present and
> empty); and the negative, against a **hand-built row** naming `phone_number`
> and `address` — carried verbatim, with no scope granted on the strength of
> the request. Two in the repository: the round trip, and a row whose column is
> `UNSET` after the fact, which is the only way to produce the pre-migration
> shape against a migrated schema. One in `schema.rs`, asserting v61 is
> additive and indexless. The migration tripwire moved 60 → 61.
>
> The companion assertion — that a token naming a sensitive claim releases
> nothing at UserInfo — was **already there**:
> `oauth2_userinfo_post_test::a_consent_gated_claim_is_not_released_by_requesting_it`
> mints a token "assuming the authorization-endpoint filter had been bypassed
> entirely", which is exactly the shape the refresh path now produces. Pinning
> it at the endpoint that would leak is where it belongs; a second copy here
> would assert the same property one layer further from the leak.
>
> Docs: `docs/compliance/oidc-conformance.md` rows **158–160** (carried,
> copied-never-widened, and the I4 twin) under a short section explaining what
> rows 104–129's limitation was; `CHANGELOG.md` under **Security**. Threat
> model: T-241's "Known limitation" sentence replaced in `Axiam.json`,
> `threat-model-stride.md`. Status unchanged (Mitigated), no count moves.
>
> Verified: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
> --no-default-features -- -D warnings`, `cargo test -p axiam-oauth2`
> (389 + 112 + 7 + 1), and the six `axiam-db` binaries this touches (232 lib,
> and the gate, W7, refresh-gaps, revoke-all and permission-ticket suites).
> `-p axiam-db` unscoped fills the sandbox disk — fifteen integration binaries
> — which is what `CLAUDE.md`'s hygiene section warns about; scoping to `--lib`
> plus named `--test` targets is the way to run it here.

**Closes** the residual T-241 records: *"Known limitation, stated rather than
discovered: the requested claims ride the authorization code, not the refresh
token, so a refreshing client must ask again."*

**The defect.** OIDC Core §5.5 `claims` requests are parsed at the
authorization endpoint, filtered through `claims_request::RELEASABLE`, stored
on `oauth2_auth_code.requested_userinfo_claims` (schema v59) and minted into
the access token as `axiam_requested_claims`. The refresh grant
(`crates/axiam-oauth2/src/token.rs`, the `issue_access_token_for_client` call
at ~line 2260) mints a token with no such claim. The client's first access
token releases the claims it asked for; its second, fifteen minutes later,
does not — and the only recovery is a whole new authorization, which the end
user experiences as consent not having worked.

**The design.** Carry the list on the refresh-token row and copy it across
rotation, exactly as `session_id` and the W2 evidence are copied.

- `RefreshToken` and `CreateRefreshToken`
  (`crates/axiam-core/src/models/oauth2_client.rs`) gain
  `requested_userinfo_claims: Vec<String>`, `#[serde(default)]` on the read
  side.
- **Schema v61**, additive, no backfill:
  `DEFINE FIELD IF NOT EXISTS requested_userinfo_claims ON TABLE
  oauth2_refresh_token TYPE option<array<string>>` plus the `.*` member
  definition, in the v54…v59 pattern. The decode path for a pre-migration row
  is `Option::unwrap_or_default()` → the empty vector → a refreshed token with
  no `axiam_requested_claims`, which is today's behaviour. That is documented on
  the field, as v59 documents its own.
- `crates/axiam-db/src/repository/oauth2_refresh_token.rs`: the column joins
  the `SELECT` list, the `CREATE` bind set and both row structs.
- The authorization-code grant writes `auth_code.requested_userinfo_claims`
  into the refresh token it issues alongside the access token; the refresh
  grant copies `stored.requested_userinfo_claims` into the successor row and
  passes it to the mint.
- `issue_access_token_for_client` gains a
  `requested_userinfo_claims: &[String]` parameter, and
  `issue_access_token_enriched` passes `&[]` — preserving that crate's
  established shape, in which each wrapper is a one-line delegation whose
  extra parameter produces a **byte-identical token** when empty. The rule the
  doc comments already state ("passing `None` produces a byte-identical
  token") gains one more instance rather than an exception.

**`RELEASABLE` still decides.** The refresh path must not become a way to name
a sensitive claim into release. The filter runs where it runs today — at the
authorization endpoint — and the refresh path copies a list that has already
been through it. The test that proves this is written against a **hand-built
refresh-token row** carrying `phone_number` and `address`, as though the filter
had been bypassed or the row hand-edited in the datastore: the refreshed token
must not release them at UserInfo. That is the same shape as the existing W7
test that mints a token "as though the filter had been bypassed", and for the
same reason — the endpoint that would leak is the one to assert against.

**Tests** (`crates/axiam-oauth2/tests/token_service.rs` and the REST
sensitive-scopes suite):

1. A code carrying `claims` → refresh → the refreshed access token carries the
   same `axiam_requested_claims`, and UserInfo releases the same set.
2. Two rotations → still carried (the copy is on the successor, not a
   one-hop carry).
3. A refresh token row with `requested_userinfo_claims: None` (the
   pre-migration decode) → a refreshed token with no `axiam_requested_claims`,
   byte-identical to today. **This is the I4 twin.**
4. The negative: a hand-built row naming `phone_number`/`address` → refreshed →
   UserInfo releases neither, whatever the token says.
5. A grant that sent no `claims` parameter → the refreshed token is
   byte-identical to what it is today (the empty-list identity).

**What this does NOT change.** No new endpoint, no new discovery member, no
change to `RELEASABLE`, no change to which scopes exist or which consent
gates apply, and no change for a client that never sent `claims`. The four
gates of T-241 are re-asked at every UserInfo call and stay exactly as they
are; carrying the *request* across refresh does not carry a *release
decision* across anything.

**Docs.** `docs/compliance/oidc-conformance.md` if a row cites the limitation;
`docs/compliance/gdpr-compliance.md` §3.1 if it repeats it; `CHANGELOG.md`.

**Threat model.** T-241's "Known limitation" sentence is replaced by what now
happens. Status unchanged; no count moves.

---

## 4. R-3 — an unparseable default tenant is visible at boot

> **EXECUTED — R-3, 2026-09-12.** `AuthConfig::default_tenant_id_diagnostic()`
> answers `Some(DefaultTenantProblem { length, shape })` exactly when a
> non-empty value failed to parse; `default_tenant_id()` is untouched, so the
> builder still sees `None` and nothing about discovery moved. The composition
> root logs one `WARN` beside `warn_on_mintable_key`, naming the variable and
> saying what will happen rather than merely that something is wrong.
>
> `shape` is one of two phrases — "hexadecimal, but not a 36-character UUID",
> and "contains characters a UUID cannot" — which is the distinction that
> matters to whoever has to fix it: the first is a truncated paste, the second
> is a different identifier entirely (a tenant *slug*, most often). Neither
> echoes the value.
>
> Five tests on the diagnostic: the three quiet cases; the two shapes; and
> `the_rendered_diagnostic_never_echoes_the_value`, which checks **every
> three-character window** of the value against the rendered line — crude on
> purpose, because the way this regresses is somebody appending the value "to
> make it easier to debug". Plus the two identity assertions: the accessor
> answers `None` for a bad value exactly as for no value, and — in
> `oidc.rs` — `an_unparseable_default_tenant_serves_the_unconfigured_document`
> compares the **whole serialized document** byte for byte against the unset
> case, resolving the value through `AuthConfig` the way the handler does. The
> plan asked for the endpoints; asserting the whole serialisation is strictly
> stronger and catches the way this would actually go wrong, which is something
> other than an endpoint URL starting to vary with the setting.
>
> Docs: `docs/conformance/README.md`, where the variable is actually described
> — it is not in `docs/deployment/README.md`, which the plan assumed — and
> `CHANGELOG.md` under **Added**. Threat model: T-244's mitigation gains the
> clause in `Axiam.json` and `threat-model-stride.md`; status unchanged, no
> count moves.

**Closes** the residual in T-244: the deliberate silence of
`AuthConfig::default_tenant_id()` (`crates/axiam-auth/src/config.rs` ~line 407)
when `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` holds something that is not a
UUID.

**The defect, and what stays.** Treating an unparseable value as unset is
**right and stays**: the value is consulted while building a public,
unauthenticated document, and a fat-fingered UUID should not `500` for every
relying party. The entry argues it against the mTLS alias's opposite choice — a
bad alias actively misdirects a client, a missing tenant only fails to help
one — and that argument holds. What is missing is that the operator is never
told. The document simply serves the shape it served before the setting
existed, and the deployment concludes the setting does not work.

**The design.** One `WARN` at boot, beside the other boot-time posture lines in
`crates/axiam-server/src/main.rs`:

```
AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID is set but is not a UUID
(length 8, non-hex characters present); discovery will serve the document it
serves when the variable is unset, and no endpoint URL will carry a tenant.
```

- **At boot, once, never on the request path.** `default_tenant_id()` is called
  per discovery request; a warning there is a log-flood an attacker can drive
  by requesting the document. The composition root calls a new
  `AuthConfig::default_tenant_id_diagnostic() -> Option<DefaultTenantProblem>`
  once and logs.
- **The value's *shape*, never the value.** Length and a character class
  ("non-hex characters present" / "hex, wrong length"), because a tenant id is
  not a secret but a variable this code cannot prove is a tenant id might hold
  anything an operator pasted. Nothing derived from a secret, and no `Debug`
  that would render one.
- The empty and whitespace-only cases stay silent: those are "unset", which is
  the default and needs no warning.

**Tests.** The diagnostic is a pure function: unset → `None`; whitespace →
`None`; a valid UUID → `None`; `"not-a-uuid"` → `Some`, with the rendered
message containing neither the value nor any substring of it longer than the
length digit. And the one that matters — **the document a deployment with an
unparseable value serves is byte-identical to the document it serves with the
variable unset**, asserted over the full serialized JSON, which is the I4 twin
and also the proof that this item changed no behaviour.

**What this does NOT change.** Discovery output, in any configuration. No
endpoint gains or loses a query string. Nothing fails to boot: an unparseable
value is still not fatal, deliberately, and the WARN says what will happen
rather than refusing to start.

**Docs.** `docs/deployment/README.md`'s row for the variable gains "an
unparseable value is treated as unset and logged at WARN at startup".

**Threat model.** T-244's mitigation gains one clause. Status unchanged.

---

## 5. R-4 — the HTTP status of a contended write (decision A)

> **EXECUTED (server side) — R-4, 2026-09-12.** One payload-free
> `AxiamError::WriteContention`, one mapping. `From<DbError>` routes
> `DbError::Conflict` to it instead of through the `other =>
> AxiamError::Database` catch-all; REST answers `503` with the slug
> `write_contention` and `Retry-After: 1`; gRPC answers `UNAVAILABLE` in both
> `axiam_err_to_status` mappers.
>
> The header is inserted next to the `HttpResponse::build(self.status_code())`
> call rather than inside the slug match, so the status and the header cannot
> drift apart — the mapper had no machinery for a header before this, and one
> conditional insertion is all it has now. The slug is its own rather than
> `service_unavailable`: the Argon2-gate `503` and a contended write are
> different operational events, and an operator reading logs has to tell them
> apart.
>
> Tests: four in `api-rest/src/error.rs` — the `503` and the header; that the
> body never carries the engine's words (checked against `Transaction`,
> `write conflict`, `surreal`); the **I4 twin**, that both `409` answers are
> untouched and carry no `Retry-After`; and that `service_unavailable` keeps
> its own slug and gains nothing. Two in `axiam-db/src/helpers.rs`: the
> conversion, with the engine's message asserted **present** on the `DbError`
> and **absent** from the `AxiamError`; and the second I4 twin, that a UNIQUE
> violation still maps to `AlreadyExists` — the `classify_write_error`
> ordering is load-bearing and is now pinned from the other end too. The old
> `conflict_converts_to_a_database_error_not_a_conflict_status`, whose comment
> recorded the deferral, is replaced by the two above.
>
> **`docs/compliance/oauth2-rfc-compliance.md` gains no row, and that is the
> deliverable of the check the plan asked for.** No OAuth2 endpoint can
> surface the status: every OAuth2 write that could contend is a single-use
> redemption, and those answer `invalid_grant` by design — the fail-closed
> branch T-262 records, which never reaches `retry_on_write_conflict`.
>
> Docs: `docs/api/README.md` gained an **Errors** section — it had none, which
> is why the plan's "the errors docs page source" pointed at a page that did
> not exist — with the full status/slug table, the three-way argument for
> `503` over `409` and `500`, and the gRPC equivalence. `CHANGELOG.md` under
> **Changed**. Threat model: T-262's deferral sentence replaced in
> `Axiam.json`, `threat-model-stride.md` and `threat-modeling-and-security.md`;
> status unchanged, no count moves.
>
> The SDK half — one test per repository, no behaviour change — rides each
> SDK's PR; §13.1 records it.

**Closes** the residual T-262 records: *"the HTTP status deliberately stays
`5xx`, since narrowing it to `503` with `Retry-After` is a client-visible
contract change and a separate decision."* This plan is that decision; see §10.

**Recommended and implemented: (a) `503 Service Unavailable` with
`Retry-After: 1`.**

**The design, server-side.** One error type, one mapping.

- `axiam-core`'s `AxiamError` gains **one** variant:

  ```rust
  /// A write that lost an optimistic-concurrency race and stayed lost after
  /// every retry `retry_on_write_conflict` was willing to spend.
  #[error("the datastore is busy; retry this request")]
  WriteContention,
  ```

  It carries **no payload**: the engine's own words ("Transaction write
  conflict…") are a server-side detail and the existing 5xx redaction rule
  (SEC-011/SEC-039/CQ-B33) keeps them out of the body. The `DbError::Conflict`
  variant keeps its message for the log; `From<DbError>` maps it here instead
  of through the `other => AxiamError::Database` catch-all.
- `crates/axiam-api-rest/src/error.rs`: `503`, slug `write_contention`, message
  echoed (it names no internal detail), and — the part the existing mapper has
  no machinery for — a `Retry-After: 1` header. `error_response` currently
  builds every response with `HttpResponse::build(status).json(body)`; this adds
  the single conditional header insertion, next to it and not inside a new
  branch of the slug match, so the two cannot drift.
- gRPC: `UNAVAILABLE` (14), which CONTRACT §2's gRPC table already maps to
  `NetworkError`. No new row.

**Why `503` and not `409`.** An IdP driving SCIM provisioning — Okta, Entra —
treats `503` as transient and retries it, which is exactly what a contended
write wants; and `409` in SCIM (RFC 7644 §3.12) means *your request conflicts
with the resource's state*, which is a statement about the request that
retrying cannot fix. `500` is what we have, and it is the one answer that is
both unhelpful and wrong: it tells a client to stop when the correct advice is
to come back in a second. The full argument and the rejected options are in
§10.

**Why `Retry-After: 1` and not a computed value.** The server does not know how
long contention will last, and a fabricated number is worse than a conventional
one. `1` is a floor an SDK's §16 policy already honours as a floor and never as
a ceiling, so a client's own backoff still governs the wait.

**Tests (server).** `retry_on_write_conflict` exhausted → `DbError::Conflict` →
`AxiamError::WriteContention` → `503` carrying `Retry-After: 1`; the body
carries the slug and no engine text (asserted against the verbatim v3 conflict
message the existing test already pins); a **UNIQUE violation still answers
`409`**, because `classify_write_error` orders the constraint check first and
that ordering is load-bearing (I4 twin); every other `DbError` maps exactly as
it does today.

**The SDK half: a check, not a change.** CONTRACT §16.3 already says `5xx`
retries and §16.1 already says `Retry-After` is honoured as a floor, so **no
SDK behaviour should need to change**. What each SDK gains is one test that
pins it, because a policy nobody asserts through the public surface is the
failure mode §16.7 exists for:

> an eligible operation (`check_access`) answered `503` with `Retry-After: 1`
> makes exactly the §16.1 attempt count, waits at least one second before the
> retry (injected clock, never a real sleep), and succeeds on the retry; a
> **non-idempotent** operation answered the same `503` makes exactly one
> attempt, asserted by counting requests on the wire.

If an SDK's existing tests already pin both with `429`, the new test is the
`503` twin of them and belongs beside them. **If any SDK turns out not to
honour it, that is a finding, not a change of plan**: record it in §8's table
and fix it in that SDK's PR.

**What this does NOT change.** `AxiamError::Conflict`/`409` and
`AlreadyExists`/`409` are untouched; SCIM's uniqueness answers are untouched;
no OAuth2 endpoint can surface the new status (every OAuth2 write that could
contend is a single-use redemption, which answers `invalid_grant` by design),
so `docs/compliance/oauth2-rfc-compliance.md` gains **no** row — stated here
because the item asks for one *only if* an OAuth2 endpoint can surface it, and
the check is the deliverable.

**Docs.** `docs/api/README.md`'s errors table gains the row; `CHANGELOG.md`
in this repository and in each SDK repository touched, under **Changed** for
the server ("a write that loses a datastore race now answers `503` with
`Retry-After: 1` instead of `500`; SDK retry policies already treat it as
transient") and under **Added** for each SDK ("a test pinning §16 against a
`503` with `Retry-After`").

**Threat model.** T-262's mitigation: the deferral sentence becomes what
landed, with the decision and its §10 reference. Status unchanged.

---

## 6. R-5 — datastore and broker credentials through the secret provider (decision B)

> **EXECUTED — R-5, 2026-09-12.** On the same branch as the rest, not its own
> PR: the branch name is fixed for this session, so "its own PR" was not
> available without a second one. It is a self-contained commit and reverts
> cleanly on its own.
>
> Three text secrets on the port — `db_username`, `db_password`, `amqp_url` —
> in `ALL_SECRETS`, so every preloading provider fetches them in the round trip
> it already makes. **The Vault token (or the `file` mount) is now the only
> credential a container spec has to carry.**
>
> `axiam_core::secrets::env_var_override` is the one table mapping those three
> to their **existing shipped** variable names. Two places read it — the `env`
> provider, resolving a logical name, and the composition root, naming a
> variable in the WARN — and two copies is how the warning ends up naming a
> variable nobody reads. Renaming them to `AXIAM__AUTH__DB_PASSWORD` for
> namespace tidiness would have been a breaking change dressed as housekeeping.
>
> **The ordering fix was not the one the plan predicted.** No `_FILE`
> convention was needed, which is what T-132's own text expected. What was
> needed was moving `load_config`'s two assertions on the JWT keys to run
> **after** the provider has been consulted — they are not wrong, they ran at
> the one point where they could see only one of the two sources, and that is
> precisely why a `vault` deployment had to keep setting the variable the
> provider exists to replace. That defect was one release older than the one
> this item is about.
>
> **The Vault policy needed no change**, and that is a finding rather than an
> omission: `docker/vault/axiam-policy.hcl` grants `read` on
> `secret/data/axiam` and the three fields live in that KV entry. The policy is
> path-based, not field-based. Recorded in `vault.md` because "add the new
> secrets to the policy" is the reasonable first assumption.
>
> The seeder carries them and **never mints** them. A 256-bit key is meaningful
> only to AXIAM, so minting into an empty slot is what seeding is for; a
> datastore password has to match what SurrealDB was configured with, and
> inventing one gives a Vault that looks configured and a server that cannot
> connect — strictly worse than an empty slot the operator is told about. An
> existing value always wins over a supplied one (T-231), so re-running the
> seeder with a stale variable in the shell cannot undo a rotation. Five tests
> in `test_vault_seed_payload.py`, including the one asserting the environment
> table matches the Rust side — if they disagree, an operator's variable seeds
> a field the server never reads.
>
> `DbConfig` and `AmqpConfig` lost their derived `Debug`. The broker URL embeds
> its credential inline by the AMQP URI's own design, so a derived `Debug`
> there is a password in every log line, panic message or error chain that
> renders a configuration. The redaction shows scheme, host and path and drops
> the userinfo — a connection failure asks "which broker", never "which
> password" — splits on the **last** `@` of the authority so a password
> containing one cannot walk the boundary backwards, and refuses to echo a
> value that does not parse as a URL at all, since that is the value most
> likely to be a credential pasted into the wrong variable.
>
> `just vault-status` reports the three; an absence there is not the failure an
> absent `jwt_private_key_pem` is, and the report says so.
> `scripts/check-config-key-coverage.py` needed three exemptions — it derives
> `AXIAM__AUTH__<NAME>` from each port constant, and for these three that
> spelling is a variable the server does not read.
>
> Docs: `docs/deployment/vault.md` (a second table, why they are never minted,
> and the policy note), `k8s/server/secret.yml`, the configuration reference
> for all three variables, `CHANGELOG.md` under **Security**. Threat model:
> T-132's residual paragraph replaced in `Axiam.json` and
> `threat-model-stride.md`, with §6's grouping bullet and the closed-items entry
> rewritten; T-180 gains the honest clause — three more secrets now sit behind
> the one Vault credential, which **widens** the concentration that entry
> records rather than narrowing it — and stays **Open**. No count moves.

**Closes** the follow-up T-132's own entry names and §6's *Deployment
responsibilities* grouping repeats: *"`AXIAM__DB__USERNAME`,
`AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` are the remaining environment
variables, read before any provider exists."*

**The defect.** T-132 closed by routing eleven cryptographic secrets through
`SecretProvider`. Three credentials were left behind, and the reason is
structural rather than an oversight: `load_config()`
(`crates/axiam-server/src/main.rs` ~line 2585) deserializes the whole
`AppConfig` from `AXIAM__*` **before** `SecretProviderKind::from_env()` and
`build()` run (~line 249). The datastore connection is opened from that
config, so the credentials must exist before the provider does. A deployment
that put every key in Vault still has its datastore password in the pod spec,
which is the exact sentence T-132 was closed on.

**The design: one bootstrap input, then the provider.** The Vault token (or the
`file` provider's mount directory) is the only credential the container spec
carries. Everything else is fetched.

1. `axiam-core::secrets` gains three text-secret names beside the eleven —
   `DB_USERNAME`, `DB_PASSWORD`, `AMQP_URL` — and they join `ALL_SECRETS`, so
   every preloading provider fetches them in the one round trip it already
   makes.
2. `load_config()` **stops asserting** what the provider supplies. Today it
   asserts `jwt_private_key_pem` non-empty at a point where the provider has
   not run, which already forces a Vault deployment to keep that variable set
   — the same defect, one release older. The assertions move to a
   `validate_after_secrets(&config)` called once the provider has populated
   everything, so there is exactly one place that decides a credential is
   missing and it runs after every source has been consulted.
3. After `secret_provider` is built, the composition root overlays the three
   values onto `config.db.username`, `config.db.password` and `config.amqp.url`
   — the same shape the eleven keys already use (`read_secret(…)`, then assign),
   and the same place. The datastore is connected **after** this point; today it
   already is, so no code moves.
4. **The environment variables stay as a fallback, permanently** (decision B —
   see §10). When the provider answers `None` and the environment supplied the
   value, one `WARN` per credential at boot:

   ```
   AXIAM__DB__PASSWORD was read from the environment; the configured secret
   provider (`vault`) has no `db_password`. Environment variables appear in pod
   specs, crash dumps and orchestrator APIs — see docs/deployment/vault.md §4.
   ```

   Never the value, never a `Debug` that would render one — `DbConfig` and
   `AmqpConfig` both need their `Debug` audited for this, and a redacting
   `Debug` written where either derives one today (`AmqpConfig::url` carries
   the broker password inline, which is the worse of the two).
   Under the `env` provider there is **no warning**: `env` is a supported kind
   and reading an environment variable is what it is for. The warning fires
   only when a *non-`env`* provider is configured and the value came from the
   environment anyway — which is the actual misconfiguration, and the only one
   worth a line.
5. Neither is fatal. A deployment that sets neither fails at the datastore
   connection with the error it fails with today.

**The seeder must never overwrite.** `docker/vault/` seeding gains the three
paths and keeps T-231's rule: a `vault kv patch`-shaped write that creates a
credential only when it is absent, never one that replaces a credential an
operator rotated. The seeder's existing "skip if present" branch is the one to
extend; a test of the seeder script asserts that a second run over a populated
mount writes nothing.

**Files.** `crates/axiam-core/src/secrets.rs` (three names, `ALL_SECRETS`);
`crates/axiam-auth/src/secrets.rs` (the Vault and file providers already
resolve any name; the `env` provider's name→variable mapping needs the three
`AXIAM__DB__*`/`AXIAM__AMQP__*` spellings rather than `AXIAM__AUTH__*`, which
is the one genuinely fiddly part of this item and gets its own test);
`crates/axiam-server/src/main.rs` (the overlay, the warnings, the moved
assertions); `crates/axiam-amqp/src/config.rs` and
`crates/axiam-db/src/connection.rs` (redacting `Debug`);
`docker/vault/axiam-policy.hcl`; the seeder; `justfile`'s `vault-status`;
`k8s/server/secret.yml` and `configmap.yml`; `docker/docker-compose.prod.yml`
and the Vault compose overlay; `docs/deployment/vault.md`; the `secrets` and
`configuration` docs sources; `docs/deployment/README.md` (and
`scripts/check-config-key-coverage.py` must pass).

**Tests.** The `env` provider resolves the three names to the three correct
variables (and to nothing else); the overlay prefers the provider over the
environment when both are present; the fallback warns exactly once per
credential and only under a non-`env` provider; **a deployment configured
exactly as today — `env` provider, three variables set — boots with no new log
line and the same configuration values** (the I4 twin); `AmqpConfig`'s `Debug`
renders no password, asserted against a URL with one; the seeder is idempotent
and non-destructive.

**What this does NOT change.** No datastore or broker behaviour, no connection
logic, no new provider kind, and no removal of any environment variable. A
deployment that never adopts the provider for these three is byte-for-byte
unchanged except that a non-`env` provider now says so.

**Threat model.** T-132's mitigation loses its "datastore and broker
credentials remain env-supplied" clause and gains what landed; §6's
*Deployment responsibilities* etcd bullet loses its last sentence. T-180
gains a clause: three more secrets now sit behind the one Vault credential,
which is the trade that entry exists to record and it stays **Open**. No count
moves.

---

## 7. R-6 — revocation reach: a revocation feed (decision C)

> **EXECUTED (server and contract) — R-6, 2026-09-12. Contract 1.44.**
> **T-39 and T-143 stay Open**, per §11: the feed exists and nothing polls it,
> and a feed nobody reads narrows nothing. They flip when an SDK guard
> implements §10.4; §13.1 tracks that.
>
> Schema **v62** — one new table, `revoked_session`, holding a `sid_hash` and
> an `expires_at` and asserted by its own test to hold *nothing else*: a user
> id or a tenant id there would turn a public, unauthenticated document into a
> disclosure, and that is a decision to be argued rather than a column to be
> added. The entry format is `axiam_core::revocation_feed` (layer 0, because
> the server computes an entry and eleven SDKs compute the same entry from a
> `sid` claim), pinned to a literal vector — eleven independent
> implementations of a wire format need one.
>
> **The write side is on the session repository**, not a second one, because a
> revocation is published by the same call that performs it. Three delete paths
> publish and two deliberately do not: `consume` and `consume_by_token_hash`
> are single-use redemptions of a handoff, where the session is being exchanged
> rather than withdrawn, and publishing one would make a guard reject a caller
> whose grant is proceeding normally. **A feed that can produce a false
> rejection is worse than the fifteen-minute window it narrows**, and that
> sentence is the design.
>
> Two things the plan did not anticipate. `DELETE ... RETURN BEFORE` yields the
> record id in SurrealDB's own form rather than the `meta::id(id) AS record_id`
> alias every row struct in that file expects, so the two bulk paths read the
> ids in a separate `SELECT` **before** the delete — which also means a
> deployment with the feed off issues exactly the queries it issued before. The
> race that opens (a session created between the read and the delete) is the
> right way round: it is missed by the feed and revoked by the delete, costing
> one token lifetime — what the deployment had anyway — where the reverse would
> cost a false rejection. And `ORDER BY` requires its idiom in the projection,
> so `expires_at` is selected and then used by nothing: the document carries a
> single deployment-wide `ttl` rather than a per-entry expiry, because a
> per-entry expiry would say *when* each session was revoked.
>
> **"Rate-limited like `jwks`" turned out to mean "not rate-limited".**
> `/oauth2/jwks` carries no limiter, and the feed is served exactly as it is —
> a plain route with `Cache-Control: public, max-age=15` and an `ETag` over the
> **entry list only**, since `issued_at` changes every call and covering it
> would make every poll a full transfer. Every wrapped endpoint in that scope
> is unauthenticated *and* allocates or terminates state; the feed does
> neither. Recorded here because the plan asserted a limiter and the check is
> the deliverable.
>
> **Mounted, not stubbed.** `RouteOptions` (new, `Default` = everything off) is
> how the composition root turns the route on; `register_api_v1_routes` keeps
> its signature and passes the default, so the forty-odd test files that call
> it are untouched. A route that exists and answers 404 is one an operator
> finds in a log and a scanner reports on — an off-by-default feature that
> leaves traces is not off.
>
> Eight datastore tests and three route tests, the I4 twins among them the two
> that matter: with the feed off **no row is ever written** by any of the five
> delete paths (and the revocations still happen), and the route **does not
> exist**. One test greps the raw row for the session, tenant and user ids
> rather than trusting the projection, because the repository selects one
> column and would hide a second.
>
> Contract **§10.4** (SHOULD, default off, bounded interval and cache, never on
> the request path, **never fail closed** — including not reading an
> unreachable or malformed feed as an empty list, which would be a guard
> silently honouring no revocations while appearing to honour them), plus
> **§10.4.1**'s per-SDK table and the scoping of §10.2's MUST NOT to
> *per-request* polling, which is what its own words ("before each call",
> "unbounded per-request cost") always said. Conformance rows **165–169**.
> `sdks/openapi.json` and `management-registry.json` regenerated from a real
> `--dump-openapi` (153 paths, 159 operations); the `oidc` exclusion reason in
> `gen-management-registry.py` now names the feed as §10.4 guard machinery
> rather than letting it ride on "§12 discovery/JWKS".
>
> Docs: `docs/deployment/README.md` (a new section, including what the document
> does **not** disclose and why that is a non-enumerability argument rather
> than a guarantee), the configuration reference, `CHANGELOG.md` under
> **Added**. Threat model: T-39 and T-143 amended in `Axiam.json` and
> `threat-model-stride.md` — mitigation, §6 register rows and the "Access
> tokens survive revocation" grouping bullet — with **status unchanged** and no
> count moved.

**Closes** T-39 (Open, Medium, *Authentication & session management*) and
T-143 (Open, Medium, *Client SDKs & admin UI integration surface*) — the two
faces of one trade. Both become **Mitigated** only if the feed lands
server-side **and** in the SDKs; otherwise the server work lands and both stay
Open with an amended mitigation. That condition is not negotiable at write-up
time and is restated in §9.

**Recommended and implemented: (a) a small, cacheable, unlinkable revocation
feed.** Options (b) and (c) and the argument are in §10.

**The defect, as the model records it.** An access token is valid for up to
fifteen minutes and is verified statelessly. A role removal, an account
disable or a logout does not reach it. On the server the recorded remedy is
"use the gRPC introspection path"; in an SDK route guard the recorded remedy is
"call gRPC introspection or CheckAccess rather than verifying locally". Both
are real and both cost a network round trip **per request**, which is why
neither is what integrators actually do.

**The design.**

`GET /oauth2/revocations` — published beside the JWKS, unauthenticated,
rate-limited the way `jwks` is, and **off by default**
(`AXIAM__AUTH__REVOCATION_FEED_ENABLED`, default `false`; when off the route is
not mounted at all, so a deployment that has not opted in is byte-identical,
404 included).

```json
{
  "alg": "SHA-256",
  "issued_at": 1757664000,
  "ttl": 900,
  "revoked": ["<base64url-unpadded SHA-256 of a revoked sid>", "…"]
}
```

Five properties, each load-bearing:

1. **Hashes, never identifiers.** The entry is `SHA-256(sid)`, base64url
   unpadded — the same encoding `cnf.x5t#S256` and `jkt` already use, so no SDK
   needs a new primitive. A `sid` is a session id, not a subject, so the feed
   discloses neither who was revoked nor how many distinct users are behind the
   entries; and a hash means an observer who does not already hold the `sid`
   learns nothing they can use. It is not a privacy *guarantee* — a `sid` is a
   UUID, so the preimage space is not enumerable, which is the honest form of
   the claim and the one the docs will make.
2. **Bounded.** An entry expires exactly one access-token lifetime after the
   revocation. After that, every token naming that session has expired on its
   own `exp` and the entry proves nothing. So the feed's size is bounded by the
   revocation rate over fifteen minutes, not by the deployment's history — the
   property that makes it cacheable and makes it safe to serve to anyone.
3. **Rate-limited like `jwks`**, and served with the same `Cache-Control`
   machinery `JwksCacheConfig` already provides, plus an `ETag`. A poller that
   respects the headers costs one conditional request per interval.
4. **Never fail-closed on the feed.** A guard that cannot fetch it behaves
   **exactly** as it does today. This is the rule that decides whether the
   feature is safe to ship: a revocation feed that can deny requests when it is
   unreachable turns a network blip into an outage, and would be a worse
   control than the fifteen-minute window it narrows. The token still decides;
   the feed can only ever turn an *accept* into a *reject*, never the reverse.
5. **Additive to the token format.** Nothing about the JWT changes. `sid` is
   already there (T-249).

Server-side files: a new handler beside `handlers::oauth2::jwks`; a
revocation-hash store fed from the four existing revocation sites
(`SessionRepository::invalidate`, `revoke_all_for_user`, the logout path, the
password/MFA reset path); `AuthConfig`'s new setting; the route in
`permissions.rs`'s unauthenticated list and in `EXCLUDED_OPERATIONS` or a §27
namespace as the registry gate requires; `sdks/openapi.json` and
`management-registry.json` regenerated from a real `--dump-openapi` on the
SAML-off build the drift gate uses.

**Contract.** New **§10.4**, contract **1.43**, written as a **SHOULD**:

> An SDK route guard MAY poll `GET /oauth2/revocations` and reject a token
> whose `sid` hashes to a listed entry. Where it does, it MUST default the
> feature **off**, MUST bound the poll interval and the cached set, and MUST
> behave exactly as it does with the feature off when the feed is unreachable,
> malformed, or `alg` is not `SHA-256`. It MUST NOT fetch the feed on the
> request path.

And §10.2's closing paragraph is **amended, not contradicted**: its MUST NOT on
closing the gap client-side is scoped, in terms, to *per-request* polling of
session state — which is what it always meant ("before each call", "an
unbounded per-request cost on the hot path") — and it gains a sentence pointing
at §10.4 as the bounded, off-the-hot-path alternative. A §27-style conformance
row records the feed.

**Tests (server).** The feed lists a revoked session's `sid` hash and nothing
else; an entry ages out at one access-token lifetime; the document is stable
under repeated calls (ETag); the route is **absent** when the setting is off,
asserted as a 404 and as an absence from the OpenAPI document (the I4 twin);
the rate limit applies; a `sid` never appears in the response in any form other
than its hash, asserted by searching the body for the raw UUID.

**The SDK fan-out.** Every SDK route guard (§10/§11) gains an optional poller:
default off, bounded interval, bounded cache, never on the request path, never
fail-closed. Two tests per SDK:

1. A revoked `sid` is rejected **after one poll** — not before, which pins that
   the guard is not fetching per request.
2. A guard with the feature **off**, and a guard with the feature on whose feed
   is **unreachable**, behave byte-for-byte as they do today — asserted through
   the guard's public surface, and by counting requests on the wire so that
   "does not fetch" is proven rather than asserted.

Per-SDK posture is recorded in a §10.4 table in the §21.9 style: `yes`, or
**`declines`** with the reason. An SDK with no HTTP polling primitive in its
guard layer, or a C ABI that would need a new export, **declines** — recorded,
never a silent omission and never a partial implementation that reads as full.

**What this does NOT change.** The token format; what the server accepts; the
REST session re-check (already immediate); the gRPC posture table in §10.2;
any existing SDK's default behaviour. A deployment that leaves the setting off
and an SDK that leaves the feature off are, together, exactly today.

**Threat model.** T-39 and T-143 → **Mitigated**, each with the residual
stated: *one poll interval*, and *the SDKs that declined, by name*. Open
16 → 14; Medium open 6 → 4; *Authentication & session management* 1 → 0;
*Client SDKs* 4 → 3. §6's *Accepted design trade-offs* bullet "Access tokens
survive revocation for up to 15 minutes" is rewritten rather than deleted, in
the style the closed entries there already use.

---

## 8. R-7 — audit collection minimisation (decision D)

> **EXECUTED — R-7, 2026-09-12. T-110 → Mitigated; open 16 → 15.**
>
> **The plan named the wrong crate, and the right one is worth recording.**
> `AXIAM__AUDIT__MINIMISE` is applied in
> `axiam_db::SurrealAuditLogRepository::append`, not in `axiam-audit`. The
> policy itself is `axiam_core::audit_minimisation` (layer 0 — `axiam-audit`
> and `axiam-db` are layer-2 siblings and neither may depend on the other).
> The reason is the one the plan's own wording asked for and its crate choice
> would have missed: `axiam_audit::AuditService::log` is called by nothing but
> its own tests, and `AuditMiddleware` is **one producer among eighteen** — the
> OAuth2 replay record, the GDPR erasure proof, the webhook consumer, the
> federation secret backfill and the rest all call `append` directly. "Before
> the append-only write" has to mean every write or it means nothing, and only
> the repository is common to all of them.
>
> What minimisation does: `ip_address` → `/24` or `/48`; a `user_agent` member
> of `metadata` → a coarse family, by a total, dependency-free function (a
> UA-parsing library exists to recover precision, which is the thing being
> removed). An address that does not parse is **dropped** rather than written
> through — a value that cannot be parsed cannot be shown to have been
> minimised — and a `host:port` string and a v4-mapped v6 address are both
> handled, so the common shapes do not lose a field for no reason.
>
> What it does **not** do, which is the part the plan's "no request metadata"
> phrasing could have been read into wrongly: it does not strip the structured
> metadata producers write. Two findings here. First, that data — T-254's
> client and disposition, T-241's released claim names, T-161's federated
> subject — is accountability evidence three other mitigations depend on.
> Second, the third minimisation was **already true**: `AuditMiddleware` writes
> `{http_status, authenticated}` and nothing else. So what landed is not a
> change but a pin —
> `the_request_audit_middleware_collects_only_the_outcome` asserts the key set
> **exactly**, against a request carrying a query parameter, a user-agent and a
> custom header, because absence checks only catch the fields whoever wrote
> them thought of.
>
> Erasure and export: asserted, not assumed. `pseudonymize_actor` clears
> `ip_address` outright, so a truncated value is erased by the same statement
> as a whole one. And the Art. 15 export — the plan said to extend its test,
> and what the code says is better than that:
> `aggregate_export_data`'s `audit_entries` section reads `action`, `outcome`,
> `timestamp` and `resource_id` and **never the address**, so minimisation is
> invisible to Art. 15 altogether.
> `minimisation_leaves_every_field_the_art_15_export_reads` pins exactly that —
> those four identical across both postures, and the one field that differs
> being the one the export never reads. Asserting it at the repository is where
> it belongs: it fails the moment somebody adds a minimisation that touches one
> of the four, which is the change that would break Art. 15 unnoticed.
>
> Twelve tests in three places: nine on the policy (the truncation cases
> including the fail-closed one, the user-agent families with their
> most-specific-claim ordering, both postures, and the
> structured-metadata survival); three at the repository (minimised,
> **unminimised — the I4 twin**, and the Art. 15 invariance) plus the erasure
> one; and the middleware key-set pin.
>
> Config: `AuditCollectionConfig` as a nested struct so `AXIAM__AUDIT__MINIMISE`
> maps cleanly, with `AXIAM__AUDIT_RETENTION_DAYS` (single underscore)
> deliberately left where it is — renaming a shipped variable to tidy a
> namespace is a breaking change for every deployment that sets it. Resolved
> above the datastore pool, because the boot backfill writes audit rows before
> the server binds a port. Both states logged at startup;
> `scripts/check-config-key-coverage.py` passes.
>
> Docs: `docs/deployment/README.md` (a new section),
> `docs/compliance/gdpr-compliance.md` **§2a** (Art. 5(1)(c), with the three
> deliberate limits and the executable proof), `website/src/docs/configuration.ts`
> (the coverage gate's required home for a new key — content only, no generated
> file), `CHANGELOG.md` under **Added**. Threat model: T-110 → **Mitigated**
> with the residual stated, `hasOpenThreats` cleared on the audit cell, header
> 250/16 → 251/15, §5.7 "2 open" → "1 open", the §6 row removed and the
> grouping bullet rewritten, §7 Medium open 6 → 5 and the audit diagram 2 → 1;
> mirrored into `threat-modeling-and-security.md` (including its own current-state
> table) and `website-security-beta13-update-plan.md` §1.
> `gen-threat-model.mjs` prints `9 diagrams, 266 threats (251 mitigated, 15
> open)`; generated files reverted.

**Closes** T-110 (Open, Medium, *Audit, webhooks, email & notifications*):
*"What remains open is the collection side: nothing prevents a deployment from
writing personal data into fields the sweep will hold for the full window."*

**Recommended and implemented: (a) a deployment-wide setting, off by default.**
Not per-tenant — see §10 for why a tenant-level switch is the wrong shape.

**The design.** `AXIAM__AUDIT__MINIMISE` (bool, default `false`), applied in
`crates/axiam-audit`'s `AuditService::log` — the single funnel every producer
goes through — **before** the append-only write, because after it there is no
second chance by construction.

When on:

- **`ip_address` is truncated** to `/24` (IPv4) or `/48` (IPv6) before the
  append. The truncation is a pure function with its own tests, including the
  cases that get this wrong: a v4-mapped v6 address, a v6 address with an
  embedded v4 tail, a port-suffixed string (`realip_remote_addr` returns one),
  and a value that does not parse as an address at all — which is dropped
  rather than passed through, because an unparseable value cannot be shown to
  be minimised.
- **A `user_agent` member in `metadata`, where any producer sets one, is
  reduced to its family** (`Firefox`, `Chrome`, `curl`, `other`) by a small
  total function with no dependency — not a UA-parsing library, whose whole
  purpose is the fingerprinting precision this is removing.
- **The request-audit middleware collects no request metadata beyond outcome.**
  Stated plainly because it is already true — `AuditMiddleware` writes
  `{"http_status": …, "authenticated": …}` and nothing else — and what this
  item adds is a test pinning that key set exactly, so the third of the three
  minimisations the GDPR document names cannot regress.

**What minimisation must NOT do**, and this is the part the wording invites
getting wrong: it must not strip the **structured metadata domain producers
write**. `oauth2.refresh_token_replayed` names the client, its profile and the
disposition (T-254); the sensitive-scope release rows name the claim by name
(T-241); the JIT-provision rows name the provider and the external subject
(T-161). Those are accountability evidence that other threats' mitigations
depend on, they are not request metadata, and dropping them would weaken three
controls to narrow one. Minimisation touches the two fields that carry a data
subject's network identity and client fingerprint, and nothing else.

**Both states logged at startup, exactly as retention is** (T-119's line is the
model): one `INFO` naming the setting and what it does, in both the on and off
case, so an operator reading a boot log can always tell which posture is in
force without reading a manifest.

**Erasure and export keep working on minimised rows**, which is the property
worth testing rather than asserting: `pseudonymize_actor` already sets
`ip_address = NONE`, so a truncated value is erased identically; and the Art. 15
export's `audit_entries` section reads `action`, `outcome`, `timestamp` and
`resource_id`, none of which minimisation touches. **The Art. 15 export test is
the one to extend** — seed a subject under minimisation, export, and assert the
inventory is structurally identical to the unminimised one with the truncated
IP where the full one was.

**Tests.** The truncation function's cases above; a minimised append writes the
truncated IP and the unminimised one writes the full IP (the I4 twin); the
middleware metadata key-set pin; the startup line in both states; the extended
Art. 15 export test; erasure over a minimised row.

**What this does NOT change.** Retention (T-119) is untouched and remains the
only deletion path; the append-only property is untouched; the default is off,
so every existing deployment is byte-identical until an operator opts in;
no per-tenant surface is added, so no tenant administrator gains a way to
weaken it.

**Docs.** `docs/deployment/README.md` (the new key, and
`scripts/check-config-key-coverage.py` must pass);
`docs/compliance/gdpr-compliance.md` gains a short section describing the two
postures and naming what is and is not minimised — including, explicitly, that
structured accountability metadata is not.

**Threat model.** T-110 → **Mitigated**, residual: the deployment still chooses,
and a deployment that leaves it off collects what it collects today. Open
14 → 13; Medium open 4 → 3; *Audit, webhooks, email & notifications* 2 → 1.
§6's *Accepted design trade-offs* bullet on audit records is amended.

---

## 9. R-8 — the SDK half of contract 1.40–1.42

> **EXECUTED (this repository) — R-8, 2026-09-12. Contract 1.43.** The SDK
> fan-out is §13.1's table.
>
> **Rule 2 is implementable as written**, checked clause by clause against
> `crates/axiam-oauth2/src/oidc.rs` — the table in §9.1 is the result, and the
> fourth row is the finding: an alias carries the tenant as a query component
> and rule 2 never said what an SDK owes that. So §21.3 rule 2 gains **clause
> 4** and the contract bumps to **1.43**.
>
> **The first draft of that clause said "verbatim", and was wrong.** Reading
> the Rust SDK — which has implemented rule 2 since contract 1.40 — is what
> caught it: that SDK *displaces* the alias's `tenant_id` with the one the
> caller actually authenticated against, and it has to, because the
> multi-tenant document names no tenant and the client supplies its own. A
> "verbatim" clause would have forbidden the one behaviour a multi-tenant
> deployment requires, and eleven SDK PRs would have implemented it. The clause
> now names the two real failures — **appending** (a duplicate the server
> cannot resolve to one tenant) and **stripping** (rebuilding the URL from host
> and path, dropping whatever else the deployment put there) — and says
> outright that displacing the value is correct. This is exactly what the
> plan's "confirm the rule's wording is implementable as written" step is for,
> and it only works if the confirming is done against an implementation.
>
> **The vectors live in `CONTRACT.md` itself** (§21.3.1), not in a new
> `sdks/*.json`. The plan left the location open; this is the reason for the
> choice. `sdk-artifact-drift.yml` vendors four artifacts into eleven
> repositories, and a fifth would be a fifth thing to go stale — the exact
> failure that workflow's own header records (eight SDKs found at contract 1.17
> while this repo was at 1.19, and the plan driving that pass believing they
> were at 1.15). The contract is already vendored byte-for-byte and already
> drift-gated, so vectors inside it are distributed and guarded by machinery
> that exists.
>
> Vector C is a **refusal**, and the plan's wording is worth keeping: falling
> back is the dangerous answer, not the safe one. The caller asked to
> authenticate with a certificate; the operator published something unusable;
> presenting the certificate to the front-channel host authenticates nothing
> while appearing to work.
>
> **§21.10** is the per-SDK table, in §21.9's style, with two columns because
> they separate: *decodes the member* (every SDK has a discovery decoder) and
> *prefers the alias* (only an SDK implementing the §21 client role has a call
> to prefer with — §21.9 says which). Every row is `—` until an SDK's PR fills
> it, and `—` is explicitly **not** a claim either way.
>
> Server-side tests, both pinning what an SDK pins:
> `the_alias_object_has_exactly_the_six_members_the_contract_names` asserts the
> **serialised** member set exactly, plus the four names that must never appear
> — a seventh alias would break every SDK that pinned vector A; and
> `an_unusable_mtls_base_is_refused_rather_than_published` covers all five
> unusable shapes, which is what makes an SDK's vector-C refusal defence in
> depth rather than the only line.
>
> Conformance rows **161–164**, the last of them the invariant-4 twin (absence
> means "no separate host", and that is the common topology).
> `CHANGELOG.md` under **Changed**. T-266's mitigation gains the R-8 paragraph
> in `Axiam.json` and `threat-model-stride.md`; status unchanged (Mitigated),
> no count moves.

**Closes** the residual T-266 records: contract §21.3 rule 2 is normative for
the §21 client role and **no SDK implements it**. The server publishes
`mtls_endpoint_aliases`; every SDK ignores it.

### 9.1 In this repository first

**Confirm the rule is implementable as written**, clause by clause, against
`crates/axiam-oauth2/src/oidc.rs`:

| Clause | Server behaviour | Implementable? |
|---|---|---|
| Absent member = no separate host | `Option<MtlsEndpointAliases>`, `skip_serializing_if` — absent, never `null` | yes |
| Never synthesise the three excluded endpoints | `authorization_endpoint`, `end_session_endpoint`, `jwks_uri` are structurally absent from the alias struct | yes — an SDK cannot read what is not there |
| `iss` validated against the unchanged issuer | `issuer` is not in the alias struct and carries no query | yes |
| An alias carries the tenant query and is used **verbatim** | `build_mtls_aliases(mtls_base_url, tenant_id)` appends `?tenant_id=` to each | yes, **and this is the clause to write down**: an SDK that re-appends its own `tenant_id` produces a duplicated parameter |

The fourth row is the one §21.3 rule 2 does not currently spell out, so the
contract text gains it: **an alias URL is used exactly as published — an SDK
MUST NOT append, strip or reorder its query component.** That is a text change,
so the contract bumps to **1.44**.

Also added here: a **conformance row**, and the **test-vector shape** SDKs pin,
published as a fixture in this repository so eleven SDKs pin the same bytes
rather than eleven hand-written documents:

1. a discovery document **with** `mtls_endpoint_aliases` (six members, each
   carrying `?tenant_id=`);
2. the same document **without** the member;
3. one with a **malformed** alias (a non-absolute URL, and a second vector with
   an alias whose scheme is `http`), which an SDK **MUST refuse rather than
   fall back from** — falling back would silently send a certificate to the
   front-channel host, which is the threat.

### 9.2 Then in every SDK repository

- The **discovery decoder** reads the member (all eleven have one; §12 requires
  it) into an optional structure.
- The **mTLS client path** (§6.1, in all eleven) prefers the alias for the six
  aliased endpoints **when the client is configured with a certificate**, and
  only then. **Check §21.9's table before assuming which SDKs also implement
  the §21 client role** — the ones that do not still decode the member (it is
  §12 discovery data) but have no call that would use it, and that is the
  honest row for them.
- The **two RFC 8414 members of contract 1.42** (`code_challenge_methods_supported`,
  `token_endpoint_auth_signing_alg_values_supported`) are decoded as
  informative and ignored if absent — which is what every decoder already does
  with unknown members, so this is a test rather than a change.
- **Tests**: the three vectors, plus the non-regression that **an SDK with no
  certificate configured never reads the member at all** — asserted by
  constructing a client without a certificate against vector 1 and observing
  that every call goes to the top-level endpoint.
- **README conformance statement** updated, and the vendored `CONTRACT.md`,
  `openapi.json`, `management-registry.json` and `proto/` re-synced from the
  `axiam` commit the PR targets.

An SDK that cannot implement a piece — a language whose HTTP layer cannot
re-target a single call, a C ABI needing a new export the release cannot add —
is recorded in a §21.3 per-SDK table as **`declines`**, with the reason,
exactly as §21.9 does for §21.7.2.

**Threat model.** T-266's mitigation gains what the SDKs now do and names the
decliners. Status unchanged (Mitigated); no count moves.

---

## 10. Decisions

Four items need one. Each is implemented at its recommended default; **the
maintainer reviews the PRs and can reverse any of them there**, which is why
the rejected options are written out rather than summarised.

| # | Item | Question | Options | Recommended | Why |
|---|---|---|---|---|---|
| **A** | R-4 | What HTTP status does a contended write answer? | (a) `503` + `Retry-After: 1` · (b) `409 Conflict` · (c) keep `500` | **(a)** | An IdP driving SCIM (Okta, Entra) treats `503` as transient and retries; `409` in SCIM RFC 7644 §3.12 means "your request conflicts with the resource's state", which is a statement about the request that retrying cannot fix — and this is the opposite, a statement about the *server* that retrying fixes. `500` is the one answer that is both unhelpful and wrong: it tells the client to stop when the correct advice is to come back in a second. Cost of (a): it is a client-visible contract change, which is why it was deferred and why it is a decision. |
| **B** | R-5 | Does the environment-variable fallback stay, or become deprecated with a release date? | (a) permanent · (b) deprecated, removed at a named release | **(a) permanent** | `env` is a **supported provider kind**, not a legacy path: a single-node deployment, a development compose file and the E2E stack all use it deliberately. Deprecating the variables would deprecate the provider that reads them. The warning is scoped to the actual misconfiguration — a *non-`env`* provider configured, and the value arriving from the environment anyway — which is the only case where the operator believes something untrue. |
| **C** | R-6 | How is revocation reach narrowed? | (a) a cacheable, unlinkable revocation feed · (b) shorten the default access-token lifetime · (c) leave as is | **(a)** | It narrows **both** T-39 and T-143 without changing the token format, and costs an SDK one optional fetch on an interval rather than a round trip per request. (b) narrows nothing structurally — it trades the same property against refresh traffic and Argon2 load, and any lifetime short enough to matter for revocation is short enough to hurt; it also cannot be defaulted differently per deployment without the same configuration surface (a) needs. (c) leaves two Open Medium entries whose recorded remedy (gRPC introspection) is a per-request round trip that integrators demonstrably do not adopt. Cost of (a): a new public route, and a new way to get a guard wrong — which is why the feed is off by default, never fail-closed, and bounded on both sides. |
| **D** | R-7 | At what granularity is audit collection minimised? | (a) deployment-wide · (b) per tenant · (c) leave as is | **(a) deployment-wide, off by default** | Audit is an **accountability** control the deployment relies on, including against a tenant administrator. A per-tenant switch would let a tenant weaken the evidence that would be used to investigate that tenant — the same argument that makes `sensitive_scopes_enabled` a disable-only field for tenants under T-241, applied to a control where the tenant is a possible subject rather than a possible victim. Off by default because turning it on reduces forensic precision, and that is a lawful-basis judgement the deployment must make deliberately. |

### 10.1 A maintainer task this plan does not take

The 2026-09-11 conformance run left **14 `REVIEW` modules and 3 `WARNING`
modules**. They need a human to read the suite logs — a `REVIEW` verdict is the
suite saying "a person must look at this", and an agent asserting it is fine is
an agent overriding the one control the verdict exists to be.

One thing worth knowing before opening them: **the recorded cause of the
`WARNING`s is `claims_parameter_supported: false`, and that predates the commit
that set it to `true`.** So the warning may well be an artefact of a stale run
rather than a live finding, and the log is worth reading before anything is
changed on its account.

### 10.2 Also out of scope, deliberately

- **The T-254 refresh-grace work.** Closed by the maintainer's decision of
  2026-09-12 and merged; this plan neither reopens nor extends it.
- **The website.** `website-security-beta13-update-plan.md` owns it. This plan
  carries its numbers into that plan's §1, §3, §5, §7, §10 and Appendix A so
  the pass starts from the right ones, and changes no file under `website/`
  beyond that — `gen-threat-model.mjs` is run only to confirm the model parses,
  and its output is reverted.

---

## 11. After each item: keep the model honest

In the **same commit** as the code, every time:

1. **`ThreatDragonModels/Axiam/Axiam.json`** — the source of truth. Edit the
   threat's `status`, `mitigation` and, where a status moves, nothing else:
   numbers are stable and `threatTop` is never lowered.
2. **`claude_dev/threat-model-stride.md`** — the row, the detail block, the
   count lines, §6's register and its grouping bullets, §7's three coverage
   tables. All five, because a status that moves in one and not the others is
   the stale-`Open` failure the T-16/T-87 entry was written about.
3. **`claude_dev/threat-modeling-and-security.md`** — the prose and the counts.
4. **`claude_dev/website-security-beta13-update-plan.md`** §1, §3, §5, §7, §10
   and Appendix A — so the website pass that follows starts from the right
   numbers rather than rediscovering them.
5. **`node website/scripts/gen-threat-model.mjs`** — run it **only** to confirm
   the model parses, note the headline line in the commit message, then
   **revert the generated files**. The website plan owns them.

**T-39 and T-143 become Mitigated only if R-6 lands server-side *and* in the
SDKs.** If the SDK fan-out is incomplete at the end of the session, they stay
**Open** with the server-side narrowing recorded in the mitigation and the
remaining SDK work named. The same discipline as everywhere else here: an item
that only narrows a threat amends its mitigation and keeps its status.

---

## 12. Verification, the way CI does it

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings     # rustc 1.98.1
scripts/check-crate-layering.py
scripts/check-doc-links.sh
scripts/check-config-key-coverage.py
```

- Build with `--no-default-features` where libxml2 is absent (what CI's
  "Build (SAML off)" job does), and export
  `SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"`
  before any build — the cache lives outside the repository and does not
  survive a fresh container.
- `cargo clean` **between** items, never during one.
- The route/OpenAPI parity gate, and a real `--dump-openapi` regeneration of
  `sdks/openapi.json` and `management-registry.json` if any route changes —
  R-6 adds one, so R-6 regenerates both.
- **The FAPI 2.0 and Basic OP conformance plans must keep their 2026-09-11
  result.** Run the suite if a Docker daemon is available
  (`claude_dev/fapi-conformance-runbook.md`); **if not, say so in the PR** —
  never claim a run that did not happen.
- Never skip, disable or quarantine a test. Every negative test gets its **I4
  twin**: a client, an SDK or a deployment configured as today behaves as
  today. No credential in a panic message or a derived `Debug`.

---

## 13. SDK fan-out rules

These bind R-4's check, R-6 and R-8.

1. **Server and contract first**, merged or at least pushed, before any SDK
   branch. An SDK change is written against the contract text and the spec it
   re-vendors, never against a draft.
2. **One branch and one PR per SDK repository**, named for this plan, each
   re-vendoring `sdks/CONTRACT.md`, `sdks/openapi.json`,
   `management-registry.json` and `proto/` from the `axiam` commit it targets,
   and passing that SDK's own §27 drift-check, its contract-conformance suite,
   its linter and its full test suite **the way its CI runs them**.
3. **Read each SDK's `CLAUDE.md`, README conformance section and CI workflow
   before touching it.** Follow its conventions for redacting types, retry
   policy and guard construction rather than porting one language's shape into
   another. Eleven idiomatic implementations beat one shape transliterated
   eleven times.
4. **Do not tag or publish any SDK release.** `scripts/mass-tag.sh` is the
   release path and it is the maintainer's. Do not touch a publish workflow.
   Do not change any SDK's `alg` pin, its TLS policy, or §5 rule 3 (no Basic
   header, ever).
5. **An SDK that cannot implement a piece `declines`, in the contract's
   per-SDK table, with the reason** — exactly as §21.9 already does for
   §21.7.2. Never a silent omission; never a partial implementation that reads
   as full.
6. **`CHANGELOG.md` under `[Unreleased]`** in every repository touched, one
   entry per item, in the house style: what a client or an operator observes,
   and why.

### 13.1 Fan-out record

Filled in as PRs are opened; `—` means not reached this session.

| SDK | R-4 test | R-6 guard | R-8 alias | PR | CI at session end |
|---|---|---|---|---|---|
| rust | yes | yes | yes | [#104](https://github.com/ilpanich/axiam-rust-sdk/pull/104) | opened |
| typescript | yes | yes | yes | [#103](https://github.com/ilpanich/axiam-typescript-sdk/pull/103) | opened |
| python | — | — | — | — | — |
| java | — | — | — | — | — |
| kotlin | — | — | — | — | — |
| csharp | — | — | — | — | — |
| php | — | — | — | — | — |
| go | — | — | — | — | — |
| swift | — | — | — | — | — |
| c | — | — | — | — | — |
| cplusplus | — | — | — | — | — |

**One ordering consequence, recorded so it is not discovered as a surprise.**
§10.4.1 and §21.10 are tables *inside* `CONTRACT.md`, which every SDK vendors
byte-for-byte. Filling in a row for SDK *n* therefore makes SDK *n−1*'s
vendored copy stale. That is the right trade — the alternative is guessing all
eleven outcomes up front and writing them down before they are true — and the
fix is mechanical: **once the fan-out is done, re-vendor the final
`CONTRACT.md` into every SDK branch that was opened**, as its own commit. Until
`axiam`'s own PR merges, `sdk-artifact-drift.yml` compares against `main` and
sees the whole wave as drift regardless, so this is a merge-ordering matter
rather than a per-PR one.

---

**References** — [`threat-model-stride.md`](threat-model-stride.md) §6 ·
[`remediation-plan-2026-09-04.md`](remediation-plan-2026-09-04.md) (the form) ·
[`website-security-beta13-update-plan.md`](website-security-beta13-update-plan.md) ·
[`t254-refresh-grace-decision.md`](t254-refresh-grace-decision.md) ·
[`../sdks/CONTRACT.md`](../sdks/CONTRACT.md) §10, §16, §21, §27 ·
[`../docs/compliance/gdpr-compliance.md`](../docs/compliance/gdpr-compliance.md)
