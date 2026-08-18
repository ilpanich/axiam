# Token issuance — one description, one signer

**Status:** implemented in `crates/axiam-auth/src/token.rs`
**Introduced by:** the 2026-08 SOLID / clean-architecture review, finding F4

## What was wrong

Access-token issuance had grown into **twelve** public functions arranged in
three telescoping chains:

```text
issue_access_token                            -> _bound -> _enriched
issue_client_credentials_token                -> _bound -> _enriched
issue_service_account_client_credentials_token          -> _enriched
issue_rpt   issue_exchanged_token   issue_id_token   issue_service_account_token
```

Each tier existed only to add **one parameter** to the tier below.
`issue_access_token_bound` is a one-line delegation that adds `cnf`;
`issue_access_token_enriched` is a one-line delegation that adds `ext`. Five of
the twelve carried `#[allow(clippy::too_many_arguments)]`, and `issue_id_token`
takes ten positional parameters, five of them `Option`.

Two costs, and the second is the one that mattered.

**The module was closed to extension.** Adding one claim meant adding one
function *per chain*, plus a doc comment explaining that passing `None`
reproduces the previous tier byte for byte. The module's entire job is
"describe a token and sign it", and it had reached the point where describing a
new kind of token was a refactor.

**The signing tail was copied six times.** Every issuer ended with a
byte-identical block: resolve the pre-parsed key or fall back to parsing the
PEM, build an `EdDSA` header, encode. Six copies meant "AXIAM signs with EdDSA"
was a fact you had to confirm six times — and could have changed in five of
them without the sixth noticing.

## What it is now

### `sign_claims` — one tail

```rust
fn sign_claims<T: Serialize>(claims: &T, config: &AuthConfig) -> Result<String, AuthError>
```

Generic over the claim type, so `issue_id_token` — whose claims are a different
struct entirely — signs through the same path rather than past it. Same
pre-parsed key cache (CQ-B14), same PEM fallback, no runtime cost.

### `AccessTokenSpec` — one description

```rust
let token = AccessTokenSpec::user(user_id, tenant_id, org_id, session.id.to_string())
    .scopes(&granted)
    .cnf(certificate_binding_for(&client, &proofs)?)
    .issue(&config)?;
```

Four constructors name the four kinds of principal AXIAM issues for — `user`,
`oauth2_client`, `service_account`, `exchanged` — and each stamps the `aud` and
`sub_kind` pairing that belongs to it. That pairing is what §4.3 / SEC-006 route
narrowing reads, and §17.2 residual 1 was exactly a case of the two disagreeing
between the mTLS and client-credentials service-account paths; putting it in the
constructor makes the two agree by construction.

Builders add the optional claims, each defaulting to absent: `scopes`, `aud`,
`cnf`, `ext`, `act`, `ext_exchange`, `permissions`, `lifetime_secs`,
`expires_at`.

Adding a claim is now one builder method with a default. No new function, no
new chain tier.

### The twelve names stay

All twelve public functions remain, with unchanged signatures, as thin
delegations. Nothing was deprecated — this crate is compiled with
`clippy -D warnings`, so a `#[deprecated]` on a function called in-tree turns
every call site into a build error. More to the point, a positional convenience
API is a legitimate thing for a caller to prefer; the problem was never that the
names existed, it was that each one carried its own copy of the logic.

## What did not change

- **Token bytes.** The claim set, field order, `iss`, the `scope` join, the
  `jti` policy (session id for a user, fresh UUIDv4 for a machine token), and
  every default are what they were.
- **Runtime cost.** The spec is a stack value, monomorphised away, performing
  exactly the allocations the inline versions did.
- **`AccessTokenClaims`.** Untouched. Serialisation order is a property of that
  struct, so a token minted through the spec is byte-identical to one minted by
  the old inline code at the same instant.

## Two rules the spec encodes

**An RPT never carries `scope`.** `permissions()` attaches the UMA permission
set and deliberately does *not* also stamp a scope claim. Two places to read
authority from, only one of which was evaluated, is a resource server's worst
case.

**A token that is born expired is refused.** `expires_at()` in the past returns
the same `"exchanged token would already be expired"` error
`issue_exchanged_token` has always returned — callers match on it — rather than
minting a credential that is dead on arrival.

## Testing

`claims_at(config, now)` is private, and deliberately: it exists so the tests
can pin the clock and compare two tokens field by field. A public entry point
that let a caller choose `iat` would be a backdating primitive, which is not a
thing an auth library should hand out.

The suite asserts:

- the spec and each named function produce the same claims, comparing every
  field and `exp - iat`, ignoring only the two values that move with the wall
  clock;
- an empty scope slice omits the claim rather than stamping `""` — different
  answers to "what was granted", and a resource server that splits on
  whitespace sees one empty scope rather than none;
- the default lifetime comes from the config, and `lifetime_secs` overrides it;
- `expires_at` in the past is refused, with the message callers match on;
- **one table covering all six entry points**, asserting the documented
  `aud` / `sub_kind` / `iss` triple for each;
- an RPT carries `permissions` and never a `scope`;
- `cnf`, `ext`, `act`, `ext_exchange` and `permissions` all default to absent —
  the pre-X1 / pre-SEC-096 bytes;
- the signed header is `EdDSA`.

`cargo test -p axiam-auth -p axiam-oauth2 --lib`: 174 passed. The pre-existing
token suites (`auth_service_test.rs`, `token_service.rs`, the gRPC token tests)
are the wider net — they assert on issued tokens end to end and all still pass
against the single new code path.
