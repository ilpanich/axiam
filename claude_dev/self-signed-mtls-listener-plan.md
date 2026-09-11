# Accepting RFC 8705 §2.2 self-signed client certificates on the mTLS listener

**Status:** designed, not implemented. This document is the whole brief — a
session starting cold should need nothing else.

**Branch:** `claude/oidc-conformance-first-real-run`. Base your work on its tip
(`91c93aefe` or later). Do **not** branch from `main`; it lacks the four OAuth2
fixes this builds on.

---

## 1. The defect, precisely

`self_signed_tls_client_auth` clients cannot complete a TLS handshake with
AXIAM. In the FAPI 2.0 conformance run that is **34 of 37 modules**, every one
`INTERRUPTED` with no HTTP status at all — the connection dies before AXIAM
sees a request. Only `discovery-end-point-verification` passes, because it is
the one module that presents no client certificate.

### Why

`ReloadableClientCertVerifier::verify_client_cert`
(`crates/axiam-server/src/tls.rs:874`) delegates unconditionally to a
`WebPkiClientVerifier` built over the configured client-CA roots. webpki's job
is chain-building. An RFC 8705 §2.2 certificate is **self-signed by design** —
it chains to nothing — so webpki returns an error, rustls sends a
`bad_certificate` alert, and the connection is gone.

### Why this is not simply "a missing CA"

RFC 8705 defines **two different trust models** under one transport:

| Method | §    | Trust model | Identity is |
|---|---|---|---|
| `tls_client_auth` | 2.1 | PKI — the cert must chain to a trusted CA | the subject DN or a SAN |
| `self_signed_tls_client_auth` | 2.2 | **no PKI at all** | the registered `x5t#S256` thumbprint |

AXIAM's *application* layer already implements both correctly —
`crates/axiam-oauth2/src/mtls.rs:274` (thumbprint) and `:291` (DN/SAN). It is
only the **TLS layer** that knows one of them.

### What is *not* lost by accepting an unchained certificate

TLS 1.3's `CertificateVerify` is a signature over the handshake transcript made
with the leaf's private key, and rustls checks it via `verify_tls13_signature`.
No chain is involved. So a self-asserted certificate still **proves the peer
holds the key**. What is given up is "a CA vouched for who this is", which §2.2
replaces with "an administrator registered this exact thumbprint".

---

## 2. Design

Four layers. The governing constraint is that **`Off` / `Optional` / `Required`
must behave byte-for-byte as they do today** — this is opt-in or it is wrong.

### Layer 1 — a fourth `ClientAuth` variant

`crates/axiam-api-rest/src/config/mod.rs:87`

```rust
pub enum ClientAuth {
    #[default] Off,
    Optional,
    Required,
    /// Offer client auth; accept a certificate that chains to an anchor AND
    /// one that chains to nothing, recording which. RFC 8705 §2.2 only.
    OptionalSelfSigned,
}
```

Serde is `#[serde(rename_all = "lowercase")]`, so the env value is
`AXIAM__SERVER__TLS__CLIENT_AUTH=optionalselfsigned`. If that reads badly,
add an explicit `#[serde(rename = "optional_self_signed")]` — pick one and
document it in the same doc comment.

New behaviour is reachable **only** through a value no deployment currently
sets. That is what makes this non-regressive rather than merely tested.

### Layer 2 — the verifier accepts, and `on_connect` re-derives chained-ness

`crates/axiam-server/src/tls.rs`, `ReloadableClientCertVerifier` (struct at
`:776`, trait impl from `:851`).

Under the new mode `verify_client_cert` tries the inner webpki verifier and, on
failure, **accepts anyway**.

The outcome then has to reach the application, and **it cannot be smuggled
through the return type**: rustls's `ClientCertVerified` is an opaque token
with no payload, and the verifier is handed no connection handle to key a side
channel on. Do not try; you will waste an hour.

Instead, re-derive it where the peer chain is already in hand — the
`on_connect` hook at `crates/axiam-server/src/main.rs:2460`. Add a probe:

```rust
impl ReloadableClientCertVerifier {
    /// Would this leaf have chained to a currently-installed anchor?
    pub fn chains_to_anchor(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> bool
}
```

The live verifier is already reachable from a process-global — see
`LIVE_VERIFIER` and `install_reloadable_verifier` in the same file. Cost is one
extra chain validation per mTLS connection, and only in the new mode.

**Also add an explicit `not_before` / `not_after` check on the unchained
branch.** webpki performs the validity check as part of chain building, so the
self-asserted path silently loses it otherwise, and "the certificate expired,
rotate it" should stay enforceable rather than becoming advisory.

### Layer 3 — `VerifiedClientCert` carries the trust level

`crates/axiam-api-rest/src/extractors/cert_auth.rs:40`. An enum, not a `bool`,
so every call site has to state its choice:

```rust
pub enum CertTrust {
    /// rustls verified the chain to a configured client-CA trust anchor.
    ChainedToAnchor,
    /// The peer proved possession of the key, but the certificate chains to
    /// no configured anchor. Usable ONLY by RFC 8705 §2.2.
    SelfAsserted,
}
```

`VerifiedClientCert::from_der` currently takes only the DER; it will need the
trust level passed in (or a second constructor). Keep `from_der`'s existing
signature working if that is cheap — it has a unit test at `:312`.

### Layer 4 — only the method specified to work this way may consume it

**This is where "without breaking anything" is actually enforced.** Three call
sites:

| Consumer | Rule |
|---|---|
| `cert_auth.rs:130` — device/IoT mTLS auth | **Refuse `SelfAsserted`.** Its entire model is chaining to a flagged `mtls_trust_anchor`. This is the native-listener twin of the **B-06** defect (a cert under a never-flagged CA authenticating via the proxy header) and must not be reopened. |
| `mtls.rs:291` — `TlsClientAuth` (§2.1) | **Require `ChainedToAnchor`.** A no-op today, because TLS already guaranteed it; a real guard once the new mode exists. |
| `mtls.rs:274` — `SelfSignedTlsClientAuth` (§2.2) | Accept either. The thumbprint comparison **is** the authentication. |

The trust level reaches `mtls.rs` through `PresentedCertificate`, built in
`crates/axiam-api-rest/src/handlers/oauth2.rs:1594`
(`token_request_context`). `PresentedCertificate` will need a field for it.
Note that file's existing comment: the `X-Client-Certificate` header is refused
for OAuth2 client authentication **by construction** — do not add a way in.

Net effect: the only thing an unchained certificate can do is authenticate as a
client whose exact SHA-256 an administrator registered. Every other path treats
it as if the handshake had carried no certificate at all.

---

## 3. Files

| File | Change |
|---|---|
| `crates/axiam-api-rest/src/config/mod.rs` | the enum variant + docs |
| `crates/axiam-server/src/tls.rs` | mode plumbing, `chains_to_anchor`, validity check |
| `crates/axiam-api-rest/src/extractors/cert_auth.rs` | `CertTrust`, device-auth refusal |
| `crates/axiam-server/src/main.rs` | `on_connect` sets the trust level |
| `crates/axiam-oauth2/src/mtls.rs` | trust gate on the §2.1 branch |
| `crates/axiam-api-rest/src/handlers/oauth2.rs` | carry it into `PresentedCertificate` |
| `conformance/scripts/serve-axiam.sh` | set the new mode (line ~109 sets `CLIENT_AUTH`) |

---

## 4. Build and test — read this before running cargo

This repo has environment quirks that will otherwise cost you time.

```bash
# REQUIRED after any target/ wipe: the swagger-ui build script downloads from
# github.com, which is blocked here. Idempotent, takes a second.
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
```

- **Always `--no-default-features`.** `axiam-api-rest`'s default `saml` feature
  needs system libxml2. CI has a "Build (SAML off)" job for exactly this.
- **Scope every command with `-p`.** Never build the whole workspace: `target/`
  grows tens of GB and the disk here is quota-limited. Run
  `rm -rf target/debug/incremental` between cargo invocations.
- **Do not trust exit codes alone** — read the actual output.

Commands that matter:

```bash
cargo test  -p axiam-oauth2   --no-default-features --lib
cargo test  -p axiam-oauth2   --no-default-features --test token_service
cargo test  -p axiam-api-rest --no-default-features --test par_test
cargo check -p axiam-server   --no-default-features --all-targets
cargo fmt   -p axiam-oauth2 -p axiam-api-rest -p axiam-server -- --check
cargo clippy -p axiam-oauth2 -p axiam-api-rest -p axiam-server \
             --no-default-features --all-targets
```

`rustfmt.toml` sets `max_width = 100`. Rust edition 2024, MSRV 1.93 — native
async fn in traits, no `async_trait`.

### Tests to write

Unit tests carry this work; **assume you cannot run the conformance suite** (it
needs a local Docker stack: the OIDF suite, MongoDB, two nginx sidecars, a
SurrealDB, and a Playwright driver).

1. `tls.rs` — a self-signed leaf is **accepted** under `OptionalSelfSigned` and
   **refused** under `Optional`. Use `rcgen` as the existing tests there do.
2. `tls.rs` — a leaf that *does* chain is reported `ChainedToAnchor` under the
   new mode; an expired self-signed leaf is refused.
3. `mtls.rs` — a `tls_client_auth` client presenting a `SelfAsserted`
   certificate is **refused**, even when its DN matches. This is the guard.
4. `mtls.rs` — a `self_signed_tls_client_auth` client authenticates with a
   `SelfAsserted` certificate whose thumbprint is registered.
5. `cert_auth.rs` — device auth refuses `SelfAsserted` (the B-06 guard).

**Write tests that pin the operator-facing contract, not the server's own
rendering.** Two defects on this branch survived for months because a test
compared the server against itself: `subject_dn_match_is_exact` built its
expectation from `identity_of(&cert)`, so it passed whichever rendering the
server used — throughout a period when no documented registration could work.

---

## 5. What NOT to do

- **Do not** add a second listener for §2.2. It was considered and rejected:
  the per-client trust decision still has to happen at the application layer,
  so an extra port buys no safety — only another listener to operate and
  another certificate to rotate.
- **Do not** relax the device-auth path "for symmetry". See B-06.
- **Do not** enable the `X-Client-Certificate` header for OAuth2 client
  authentication. FAPI 2.0 requires the authorization server itself to
  authenticate the client; `mtls.rs`'s module docs explain this at length.
- **Do not** change `Off` / `Optional` / `Required` behaviour.
- **Do not** run `cargo test` or `cargo build` unscoped.

---

## 6. Committing

- Sign every commit (`git commit -S`) and verify with
  `git log --format='%h %G? %s'` — it must read `G`.
- **Do not push.** The human pushes.
- Commit messages on this branch are long and explain *why*, including what was
  tried and rejected and why an existing test failed to catch the defect. Match
  that; look at `62284e2f5`, `a76161bc8` and `91c93aefe`.
- Footer, exactly:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

---

## 7. Context you may want

- `crates/axiam-oauth2/src/mtls.rs` module docs — the two RFC 8705 methods and
  why the proxy header is refused.
- `claude_dev/fapi-conformance-runbook.md` — how the rig is run.
- `docs/conformance/` — committed run reports.
- Commit `62284e2f5` — the sibling defect: a registered subject DN that could
  never match, which gated this same lane at PAR.

### Honest note on scope

This is a **functional** defect, not a conformance blocker. The OIDF FAPI 2.0
plan has no self-signed variant — `client_auth_type` is only
`mtls | private_key_jwt`, and the mtls and self-signed plan files in
`conformance/plans/` render to the *identical* suite variant. AXIAM runs that
one plan twice with two different registered clients as its own extra coverage
of RFC 8705's two mTLS methods.

The reason to fix it is simpler and better: AXIAM **accepts a
`self_signed_tls_client_auth` client registration today, and then no such
client can ever connect**.
