# Security review — release 1.0.1, wave W2 (F4)

**Date:** 2026-10-13.
**Against:** `claude/release-1.0.1-w2`, the whole wave diff `v1.0.0..d9584f025`
(`v1.0.0` is commit `0a90de0a3`; **6 commits**, 29 files, 2 361 lines added and
185 removed). All 6 commits carry a signature (`gpgsig` is present on each). The
sandbox has no `allowedSignersFile`, so `%G?` cannot verify them here.
**Scope:** every W2 task of the release plan (§3): W2.1 #605 `ab01a523e` (the
byte-order mark and the receiver's parser options, R1W1-07), W2.2 #606
`20cfb1d03` (the SHA-1 escape hatch, R1W1-08), W2.3 #611(b) `8cd2dd8f1` (the
assertion-certificate audit pair), W2.4 #614 `50cbb6e30` (the federation flow
limiters; with D-3, the four sibling routes are wrapped too), W2.5 #591
`272629e20` (credential-bearing IdP calls go through the no-redirect guard),
W2.6 #538 `d9584f025` (single logout against a real Keycloak).
**Method:** adversarial reading of the diff and of every sibling path it
implies. The review read against [`threat-model-stride.md`](threat-model-stride.md)
and `Axiam.json` (model 2.40.0, 475 threats: 437 / 17 / 21), the plan's §9 rules
(Phase 23 §7 unchanged), and the OWASP ASVS 5.0 areas the diff touches (V6, V9,
V12, V13, V16; V1.5 for the XML parsers). Claims were checked against the code
and the linked libraries, not against the commit messages. Those libraries are
samael 0.0.22, libxml 0.3.3, libxmlsec1 1.2.39 (libxslt 1.1.39 linked) and
libxml2 2.9.14. Two claims were checked by a temporary probe (§12, removed before
this commit), and one against a live identity provider's published metadata.
This review fixes nothing: every finding comes with its evidence, a proposed fix
and an issue body (§13). IDs: `R101W2-nn`.

---

## 0. Summary

**One High finding predates the wave: the wave's own T-69 residual names it but
does not rate it. One Medium regression is introduced by the wave.**

* **R101W2-01 (High, pre-existing; surfaced by W2.2's residual).** Nothing
  restricts the `ds:Transform`s or the `CanonicalizationMethod` a received XML
  signature names: not AXIAM, not samael. xmlsec 1.2.39 is built with XSLT
  support, and it evaluates a `Reference`'s transforms before it checks the
  `SignatureValue`. A sender therefore chooses how much CPU the verifier spends
  before refusing an unsigned document. The probe confirmed this at **all three
  verifiers**:
  * the SP's assertion consumer, which is public;
  * the IdP's SSO and SLO receiver, which is public;
  * the metadata signature check.

  The ACS and the IdP receiver verify inline on the async workers, so this is
  unauthenticated resource exhaustion of the REST API. T-69's new residual
  ("neither path restricts the transforms … xmlsec's defaults decide those")
  states the cause but not the consequence.
* **R101W2-02 (Medium, wave — W2.1).** W2.1 implements the plan's "a BOM is
  refused, not skipped", and that breaks **Microsoft Entra ID**. Its federation
  metadata starts with a UTF-8 byte-order mark (fetched 2026-10-13; the first
  bytes are `ef bb bf 3c 3f 78 6d 6c`). SAML sign-in requires `metadata_url`,
  and a refused document is never cached. So after the 1.0.1 restart, every
  SP-initiated sign-in through an Entra ID configuration fails. ADFS uses the
  same .NET serializer lineage and is very likely affected; that is unverified
  here. Stripping one leading U+FEFF is exactly as safe as refusing it (§3).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R101W2-01** | Signature transforms and canonicalisation are unrestricted, and xmlsec evaluates them before checking the signature value. An unauthenticated sender controls verifier CPU at the SP ACS, the IdP SSO/SLO receiver and the metadata check. | **High** | `saml.rs` `verify_signature`, `saml_idp/request.rs` `verify_post_signature`, `saml_metadata.rs`; samael; xmlsec defaults → T-69, T-67, T-320, T-372, T-474 | pre-existing (W2.2 names the residual) | **Fix in wave** (§2) |
| **R101W2-02** | A leading UTF-8 byte-order mark is refused. Entra ID metadata (verified) and very likely ADFS metadata are refused, so every SAML sign-in through such a configuration fails after the upgrade. | **Medium** | `saml_idp/request.rs` `refuse_other_encodings`, `saml_metadata.rs`, `sp_metadata.rs` → T-474, T-67, T-69 | wave (W2.1) | **Fix in wave** (strip, §3) |
| R101W2-03 | Two of the five new bucket names, `federation_saml_acs` and `federation_oidc_callback`, are already used by the public ACS and the public OIDC callback. The shared counter key (`"{endpoint}:{ip}"`) is therefore one counter for two routes, with two limits and two seeding rules. | Low | `server.rs` (W2.4), `rate_limit_shared.rs` → T-474 extension | wave (W2.4) | Fix in wave (rename, plus a uniqueness test) |
| R101W2-04 | Back-channel logout POSTs the logout token with a plain `reqwest` client. There is no SSRF guard and no validation of `backchannel_logout_uri`, and redirects are followed. T-112's new rule is therefore still not true. | Medium | `backchannel_logout.rs`, `oauth2_clients.rs` → T-112 | pre-existing | **Decide now** (1.0.1, or 1.0.x with a known-issue line) |
| R101W2-05 | The five authenticated routes key their limiter on the peer address. For an authenticated caller, the principal is the better key. | Informational | `server.rs` (W2.4) | wave (design) | Reported |
| R101W2-06 | The IdP's self-checks of its own signed output (`saml_idp/sign.rs:181,276`) parse with `Parser::default()`, which has recovery on. | Informational | `saml_idp/sign.rs` | pre-existing | Reported |
| R101W2-07 | Text drift. T-69's residual understates R101W2-01. T-474 and the CHANGELOG say "each in a bucket of its own" (R101W2-03). The CHANGELOG does not list the BOM refusal as a behaviour change (R101W2-02). The W6 review's correction implies the rule now holds (R101W2-04). | Informational | STRIDE, `Axiam.json`, website, CHANGELOG, W6 review | wave | Reported (lands with the fixes) |

**What held.**
* W2.1's receiver options are used at all five sites the plan named. No
  AXIAM-owned parse of a received document uses anything else (§4).
* W2.2's escape-hatch check is right on every point the carry list raised
  (§5):
  * it reads every `Signature` and every `Reference`;
  * it compares URIs exactly;
  * it reads `Algorithm` in any namespace, as `xmlGetProp` does;
  * it runs on the same bytes that samael verifies.
* W2.3's audit rows fire on exactly the stated transitions and never carry the
  PEM (§6).
* W2.4's five routes each carry a governor and a shared bucket from their first
  commit. None of them is an IdP back channel (§7).
* W2.5's four calls are the only credential-bearing `guarded_fetch` callers in
  the workspace (§8). The refusal echoes neither the `Location`, nor a query,
  nor the body.
* W2.6's Keycloak tests really do exercise Keycloak's signature checks, CI
  already runs them, and they reveal no SLO defect (§9).
* T-67, T-69, T-112 and T-474 read the same in `Axiam.json`, the STRIDE document
  and the generated website file, and a generator run leaves no diff (§10).

**Verdict on merge.**
* R101W2-02 blocks the merge: a patch release must not stop every Entra ID SAML
  sign-in.
* R101W2-01 is not this wave's regression. It is High, unauthenticated, and sits
  on the exact code the wave hardens, with a small fix in two placement functions
  the wave already touches. It should ship in 1.0.1.
* R101W2-03 is a rename.
* R101W2-04 is the maintainer's call.
* Nothing else blocks.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Encoding refusal, receiver parser options | W2.1 #605 | `saml_idp/request.rs`, `saml.rs`, `saml_metadata.rs`, `saml_idp/sp_metadata.rs`, `saml_idp/sign.rs`; libxml `ParserOptions` | **read in full**; every parse site in `axiam-federation` listed (§4); Entra ID metadata fetched (§3) |
| SHA-1 escape hatch | W2.2 #606 | `saml.rs` (`verify_signature`, `check_signature_placement`, `check_sha1_escape_hatch_algorithms`); samael `crypto/xmlsec/mod.rs`, `wrapper/xmldsig.rs`; xmlsec 1.2.39 headers | **read in full**; transform handling **probed** (§12) |
| Assertion-certificate audit | W2.3 #611(b) | `handlers/federation.rs`; every writer of `idp_signing_cert_pem` | **read in full** |
| Federation flow limiters | W2.4 #614 | `server.rs`, `middleware/rate_limit_shared.rs`, `config/rate_limit.rs`, `rl_prod_check.py`, deployment docs | **read**; every bucket name in `server.rs` compared |
| No-redirect guard | W2.5 #591 | `credentialed_fetch.rs`, `oauth2.rs`, `oidc.rs`, `axiam-pki/src/ssrf.rs`; every `guarded_fetch*` caller; every direct `reqwest` client | **read**; callers classified independently (§8) |
| Keycloak SLO | W2.6 #538 | `saml_idp_keycloak_roundtrip_test.rs`, `handlers/saml_idp_slo.rs` `verify`, `ci.yml` e2e step | **read** |
| Threat model and docs | all | `Axiam.json`, STRIDE, `website/src/threatModel.ts`, CHANGELOG, deployment docs, W4/W6 reviews | compared across copies and with the code (§10, §11) |

Not run: the `#[ignore]`d Keycloak binary (the e2e job runs it, and the question
about it is answered by reading, §9), the frontend, and a multi-replica
deployment.

## 2. R101W2-01 — signature transforms are evaluated before the signature is checked

**Severity: High. Pre-existing:**
* the SP verifier since D-23;
* the IdP receiver since T23.2.3;
* the metadata check since #530.

W2.2 records it as a residual. **Proposed for a fix in the wave.**

**What the code admits.**
* **Placement checks.** The SP's `check_signature_placement` (`saml.rs:945`) and
  the IdP's `signature_placement` (`saml_idp/request.rs:486`, also used by the
  metadata check) constrain two things: where a `ds:Signature` sits, and that its
  one `Reference` points at its parent's `ID`. Neither reads `ds:Transforms` or
  `ds:CanonicalizationMethod`.
* **Algorithm checks.** samael's `signature_uses_allowed_algorithm` reads only
  the `SignatureMethod` and the `DigestMethod`s. W2.2's check reads the same two.
* **xmlsec context.** samael creates the context with `xmlSecDSigCtxCreate(NULL)`
  (`wrapper/xmldsig.rs:31`) and sets no `enabledReferenceTransforms`. Every
  transform xmlsec registers for a `Reference` is therefore admitted.
* **What xmlsec registers here.** This build of 1.2.39 has `XMLSEC_NO_XSLT`
  undefined (`transforms.h:966`) and libxslt linked into both xmlsec libraries.
  The admitted set therefore includes XSLT, as well as XPath, XPath Filter 2 and
  XPointer.

**Evidence.** A temporary unit test (§12) drove each verifier with a document
built to pass every AXIAM check:
* the placement rule held;
* the algorithms were on samael's list;
* the digest and signature value were dummies;
* one extra transform was added.

The verifiers were `handle_saml_response_for` (the ACS entry point),
`verify_post_signature` (the IdP receiver) and `parse_idp_metadata` with a
certificate. Each one spent CPU in proportion to work the sender specified
before returning the expected signature-invalid error. With no extra transform,
the same documents were refused in milliseconds. samael's quick-xml parse at
`saml.rs:435` accepted every probe document, so nothing ahead of the verifier
refuses them. The probe code was removed; its measurements are in the session
record, not reproduced here.

**Reach.**
* **SP ACS.** `POST /api/v1/auth/federation/saml/acs` and `/acs/form` are public
  (`login_per_min`, per IP). The relay state they need comes from the public
  `/saml/login`.
* **IdP SSO and SLO.** `handlers/saml_idp.rs:679` and `saml_idp_slo.rs:463`
  verify after looking up the SP by the request's own `Issuer`.
* **Metadata check.** Reached through a configured metadata URL and certificate
  (T-474's attacker).
* **Execution context.** The ACS and the IdP receiver verify inside the async
  handler, without `spawn_blocking` and without `crypto_semaphore`. A slow
  verification therefore holds an Actix worker for its whole duration.

**Not affected.**
* `KeyInfo` is never consulted, because samael sets the key itself.
* The `Reference` URI is pinned to the same document, so nothing is fetched by
  URI.

**Proposed fix.** Add one check, called from both placement functions on the tree
AXIAM already holds, before samael runs:

1. `CanonicalizationMethod/@Algorithm` must be one of:
   * `http://www.w3.org/2001/10/xml-exc-c14n#`
   * `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
   * `http://www.w3.org/2006/12/xml-c14n11`

   The `#WithComments` variants are refused.
2. Each `Reference` carries at most one `Transforms`, holding at most two
   `Transform`s.
   * Each `@Algorithm` is either `http://www.w3.org/2000/09/xmldsig#enveloped-signature`
     or one of the canonicalisation URIs above.
   * No element child is allowed, except `ec:InclusiveNamespaces` under an
     exclusive-c14n transform.
   * Each method has exactly one `Algorithm` attribute, read as W2.2 reads it,
     and compared exactly.
3. Anything else is refused with the placement error.
4. Defence in depth: run the SP and IdP-receiver verification in
   `spawn_blocking` under `crypto_semaphore`, as the IdP's own signing already
   does (`saml_idp.rs:1241`).

These signers all use `enveloped-signature` with `xml-exc-c14n#`, so the
allow-list admits them:
* Keycloak;
* samael;
* AXIAM's own `sign.rs:118-137`;
* Entra ID's metadata (checked in the fetched document).

**Tests:** XSLT, XPath, XPath Filter 2 and XPointer transforms are refused with
the placement error at the ACS, at `verify_post_signature` and at
`parse_idp_metadata`. A `#WithComments` canonicalisation is refused. A third
transform is refused. The existing suites stay green.

**Threat model:** either a new entry (resource exhaustion at the three
verifiers), or dated corrections to T-69 (its residual becomes the mitigation),
T-320, T-372 and T-474.

## 3. R101W2-02 — a byte-order mark is refused, and Entra ID's metadata carries one

**Severity: Medium (an availability regression, in a patch release, for the most
widely deployed enterprise SAML IdP). Wave-introduced (W2.1). Proposed for a fix
in the wave.**

**The belief, checked.**
* **ADFS.** No ADFS instance was reachable from here, so the executor's belief
  could not be checked directly.
* **Entra ID (same .NET lineage).** Two URLs were fetched: the common
  `…/federationmetadata/2007-06/federationmetadata.xml` and a tenant-specific
  one. Both answered `200` with `Content-Type: text/xml; charset=utf-8`. The body
  begins `ef bb bf`, followed by
  `<?xml version="1.0" encoding="utf-8"?><EntityDescriptor ID="_…"`.
* **Why both are expected to match.** .NET's `Encoding.UTF8` writes this
  preamble by default through an `XmlWriter`.

So Entra ID is **verified** and ADFS is **very likely**.

**Effect.**
* **How the document arrives.** `fetch_metadata_document` keeps U+FEFF
  (`String::from_utf8`, `saml_metadata.rs:129`).
* **Where it is refused.** `parse_idp_metadata` (`:180`) calls
  `refuse_other_encodings`, and its new `<` check (`request.rs:304-308`) refuses
  the document.
* **Why every sign-in fails.** `SamlMetadataCache::resolve` needs a
  `metadata_url`, and it is the only source of the SSO URL. A refused document is
  not cached. So every SP-initiated sign-in through such a configuration fails,
  through both the public `/saml/login` and the authenticated `/authn-request`.
* **In 1.0.0** the same document passed. The old check did not see past the BOM,
  and libxml and quick-xml both skip a UTF-8 BOM.
* **SP metadata import.** `sp_metadata.rs:234` refuses a BOM-prefixed SP document
  in the same way.
* **CHANGELOG.** None of this is listed as a behaviour change.

**Is stripping as safe as refusing? Yes,** provided the BOM is stripped exactly
once, at the front, and the stripped text is what every consumer receives:
* **A leading U+FEFF can only be the UTF-8 BOM.** The input is a validated
  `&str`, so a leading U+FEFF is exactly `ef bb bf`. UTF-16 and UTF-32 BOMs never
  form valid UTF-8, and a NUL is refused first.
* **The usual rule then applies.** After the strip, the first character must be
  `<` (after XML whitespace), and a declaration naming any other encoding is
  refused.
* **Every parser reads the same characters.**
  * AXIAM's own parses force UTF-8.
  * samael's re-parse uses libxml defaults (T-474's residual). It receives text
    with no BOM and either a UTF-8 declaration or none, so it detects UTF-8.
* **R1W1-07's case is still refused.** A BOM followed by a declaration naming
  another encoding still fails, because the declaration is now at the start and
  is read.
* **A second BOM is refused.** After the strip, the first character is not `<`.
* **Signatures are unaffected.** Canonicalisation works on the parsed tree, and
  the BOM never enters it.

The only hazard is one consumer seeing the original text while another sees the
stripped text. The fix must rule that out by construction.

**Recommendation: strip, do not refuse.**

**Proposed fix.** Make `refuse_other_encodings` return the accepted slice
(`Result<&str, _>`) after stripping exactly one leading U+FEFF and applying
today's rules to the remainder. Every caller rebinds to that slice before
anything else reads it:
* **The ACS** (`saml.rs:428`): the `xml` given to `verify_signature`, to
  samael's `Response` parse and to `bind_signature_to_assertion`.
* **`parse_idp_metadata`** (`:180`): the text used by `verify_metadata_signature`
  and samael.
* **`parse_sp_metadata`** (`:234`): the libxml parse at `:237` must take the
  stripped slice's bytes.
* **`parse_xml`** (`request.rs:412`): `verify_post_signature` later runs on
  `incoming.document`, so that string must be the stripped one, or `parse_xml`
  must return it.

**Tests:**
* the Entra ID document, or a fixture with its prefix, parses;
* a BOM before a UTF-16 declaration is still refused at all four entries;
* two BOMs are refused;
* BOM-prefixed signed metadata verifies with the certificate set;
* a BOM-prefixed signed `AuthnRequest` verifies at the receiver.

**Docs:** the CHANGELOG entry, and the 2026-10-13 corrections in T-67, T-69 and
T-474, say "stripped once" instead of "refused".

## 4. W2.1 — the receiver's options, site by site

| Site | Before | Now | Verdict |
|---|---|---|---|
| IdP receiver `parse_xml` (`request.rs:412`) | receiver options, inline | `receiver_parser_options()` | same options, one definition |
| SP metadata import (`sp_metadata.rs:237`) | receiver options, inline | `receiver_parser_options()` | same |
| ACS placement parse (`saml.rs:734`) | `Parser::default()` | receiver options | **fixed** |
| ACS binding parse (`saml.rs:1151`) | `Parser::default()` | receiver options | **fixed** |
| Metadata signature check (`saml_metadata.rs:270`) | `Parser::default()` | receiver options | **fixed** |
| samael's libxml re-parse (three verifiers) | libxml defaults | unchanged | T-474's residual, correctly stated: only text that passed the byte refusals and a strict parse reaches it |
| samael quick-xml (`Response`, `EntityDescriptorType`) | quick-xml | unchanged | no DTD reaches it |
| `saml_idp/sign.rs:181,276` | `Parser::default()` | unchanged | AXIAM's own output; R101W2-06 |
| `saml_idp/mod.rs:1092` | quick-xml | unchanged | `test_support` only |

`recover: false` holds at every site that parses a received document. The
leading-whitespace rule trims only XML's `S` (space, tab, CR, LF); other Unicode
spaces are refused.

## 5. W2.2 — the escape-hatch check

* **Every `Signature`, every `Reference`.** The check selects
  `//*[local-name()='Signature']`, and a `Signature` outside the XML-DSig
  namespace refuses the document. Each signature must have exactly one
  `SignedInfo` and one `SignatureMethod`, at least one `Reference`, and exactly
  one `DigestMethod` per `Reference`. samael's `find_signature_nodes` walks the
  same set.
* **Exact match.** URIs are compared with `==` against the list derived from
  `ALLOWED_XML_SIGNATURE_ALGORITHMS`, plus the three SHA-1 constants. A suffix,
  padding or a case change is refused, and this is tested.
* **`Algorithm` in any namespace.** The check requires exactly one attribute with
  local name `Algorithm`. That matters because xmlsec's `xmlGetProp` matches by
  local name and takes the first one. No DTD can default a second attribute,
  since DTDs are refused on the bytes.
* **Same bytes.** The check runs on the tree parsed with the receiver's options.
  samael parses the same well-formed UTF-8 text, so both see the same tree.
* **Transforms and canonicalisation** are unrestricted: R101W2-01.
* **Flag off:** nothing changed. The refusal message echoes no URI.

## 6. W2.3 — the assertion-certificate audit pair

* **Writers.** `update` is the only path that changes `idp_signing_cert_pem`
  after creation; every other construction sets `None` or is a test.
* **Trigger** (`federation.rs:1253-1262`):
  * `_cleared` is written when an existing value is cleared;
  * `_changed` is written when the trimmed value differs;
  * nothing is written for a first set, a re-save, or the clear of an absent
    value.

  This is the metadata pair's rule.
* **Content.** The row is written after the update succeeds:
  * actor: the administrator;
  * resource: the configuration;
  * the client IP;
  * metadata `{federation_config_id, provider, provider_kind}`.

  There is no PEM and no `metadata_signature_checked` key.
* **Failure handling.** A failed audit write is logged and does not fail the
  request.
* **False positive.** Changing only the PEM's internal line endings is reported
  as a change, which is harmless.

Holds.

## 7. W2.4 — the five limiters

* **Coverage.** All five routes carry `build_governor(end_session_per_min)` and
  `RateLimitShared::browser_preset`, from the commit that adds them.
* **Who calls them.** Each handler takes `AuthenticatedUser`. The `api_scope`
  middleware refuses a request without a valid token before the resource's
  limiter runs. The IdP never calls these routes. The IdP-facing routes are the
  public `/api/v1/auth/federation/saml/acs`, `/acs/form` and
  `/federation/oidc/callback`, which have had their own `login_per_min` limiters
  since Phase 4. The executor's classification is right: none of the five is an
  IdP back channel, and the browser preset fits them.
* **R101W2-03.** Two names collide. `"federation_saml_acs"` is used at both
  `server.rs:561` (public, limit 10, standard seeding) and `:1856` (W2.4, limit
  30, human seeding). `"federation_oidc_callback"` is used at both `:467` and
  `:1417`. The shared counter keys on `"{endpoint}:{ip}"`
  (`rate_limit_shared.rs:388`), so each pair is one counter. The in-memory
  governors are separate. The type's own documentation says the endpoint "MUST
  be unique per rate-limited resource". The test covers only the five new routes
  against each other, so it cannot see the collision.
* **R101W2-05.** The key is the peer address. These routes are authenticated, so
  the principal is the natural key:
  * a relaying backend currently shares one bucket per route across all its
    users;
  * one token used from many addresses is currently not bounded.

  Keying on `(tenant, sub)`, or on the pair (address, sub), would fit both.
  Informational.

## 8. W2.5 — the no-redirect guard

**The four calls.** They now use `guarded_fetch_no_redirect`, and each refuses a
`3xx` through `redirect_refusal`:
* `oauth2.rs:339`, the token exchange (client secret, code, PKCE verifier);
* `oauth2.rs:405`, the userinfo call (bearer);
* `oauth2.rs:454`, the GitHub email call (bearer);
* `oidc.rs:774`, the token exchange.

The reason names only the configured endpoint's host and path. It omits the
scheme, the userinfo, the query, the `Location` and the body. The non-2xx paths
still log a body preview server-side only.

**Every `guarded_fetch*` caller, classified independently:**

| Caller | Credential? | Guard |
|---|---|---|
| `discovery_cache.rs:206` | plain GET | `guarded_fetch` — correct |
| `jwks_cache.rs:255` | plain GET | `guarded_fetch` — correct |
| `saml_metadata.rs:108` | plain GET | `guarded_fetch` — correct |
| `saml_idp/sp_metadata.rs:173` | plain GET | `guarded_fetch` — correct |
| `axiam-oauth2/src/cimd.rs:827` | GET with `Accept` | `guarded_fetch` — correct |
| `axiam-pki/src/mds/mod.rs:111` | plain GET of a public blob | `guarded_fetch_with_cap` — correct |
| SCIM client, email egress, SSF push, CIBA ping, webhooks | yes | `guarded_fetch_no_redirect` (already) |

The executor's classification holds.

**R101W2-04: a credential-bearing request outside the guard.** The executor did
not cover direct `reqwest` clients. Reading them finds one credential-bearing
request that bypasses the guard entirely:
* **Client.** Back-channel logout (`backchannel_logout.rs:150`,
  `reqwest::Client::builder().timeout(..)`) uses the default redirect policy and
  does no address check.
* **Payload.** It POSTs `logout_token` to the client's `backchannel_logout_uri`.
* **No validation.** That URI is stored unvalidated by the client create and
  update handlers (`oauth2_clients.rs:664,973`): no scheme or host check exists
  anywhere in the tree.
* **Who can set it.** A tenant administrator who can manage OAuth2 clients.
* **What that gives them.** AXIAM can be made to POST, from inside the
  deployment, to an internal or link-local address, or to a public URL that
  redirects there. The payload is a signed session-termination token. This is
  T-112's class.

It contradicts T-112's 2026-10-13 rule statement, and the W6 review's correction
note.

## 9. W2.6 — single logout against Keycloak

**Keycloak's checks are exercised.** In each of the four tests, the AXIAM message
is first delivered to Keycloak with its signature broken:
* on HTTP-Redirect, one bit of `Signature` is flipped;
* on HTTP-POST, `IssueInstant` is rewritten to the same instant with a fraction,
  so the digest fails.

Keycloak must refuse it, and must still list its session. Only then is the
genuine message delivered and accepted. The forged and genuine messages differ
only in the signed octets, so the refusal is attributable to the signature check.

**AXIAM's side of each test:**
* A `LogoutRequest` must be signed by the registered certificate
  (`saml_idp_slo.rs` `verify`: an SP with no certificate cannot start a logout).
* The AXIAM-initiated tests assert a `success` outcome, which requires a verified
  response.
* AXIAM refusing a tampered message is covered by `saml_idp_slo_test`, with
  samael-signed messages. A Keycloak-bytes negative control in that direction
  would add little.

**CI.** `ci.yml:919-920` runs the whole binary with
`--ignored --test-threads=1`, so the new tests run with no wiring change.

**SLO behaviour.** Nothing in the tests reveals an SLO defect. AXIAM revokes the
session before the other side hears back, in both directions.

## 10. Threat-model text against the code

| Entry | Verdict |
|---|---|
| T-67 (2026-10-13 correction) | true for what it says. The "refused" wording changes with R101W2-02. |
| T-69 (two 2026-10-13 corrections) | the escape-hatch text is true. The residual "neither path restricts the transforms …" is true but understated: it is R101W2-01, unauthenticated, at three verifiers. It also names only the SP path. |
| T-112 (2026-10-13 correction) | true of the four federation calls. "The rule is: every credential-bearing outbound request uses `guarded_fetch_no_redirect`" is **not yet true** (R101W2-04). |
| T-474 (#605 correction) | true. The samael residual is correctly stated. The BOM wording changes with R101W2-02. |
| T-474 (#611 extension) | true (§6). |
| T-474 (#614 extension) | "each in a bucket of its own" is false for two of the five (R101W2-03). The residuals are true. |
| T-320, T-372 | "XML external entities, entity expansion …" are mitigated as stated. Neither covers transform evaluation (R101W2-01). |

The texts of T-67, T-69, T-112 and T-474 are identical across `Axiam.json`,
`threat-model-stride.md` and `website/src/threatModel.ts` (compared after
whitespace and markup normalisation). `node website/scripts/gen-threat-model.mjs`
reports 475 threats (437 mitigated, 17 open, 21 not applicable) and leaves no
diff. `Axiam.json` is at 2.40.0 with `threatTop` 475. Under §9 the model version
bump is W7.3's.

## 11. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "a byte-order mark is refused, never skipped" (CHANGELOG #605, T-67/T-69/T-474) | true of the code; it is the regression (R101W2-02), and no behaviour-change note goes with it |
| "each in a bucket of its own … one route's exhaustion never spends another's allowance" (CHANGELOG #614, `server.rs` comment, deployment README, rate-limit sizing, T-474) | false for `federation_saml_acs` and `federation_oidc_callback` (R101W2-03) |
| "routes a person reaches by navigation, unauthenticated" (`rate-limit-sizing.md`, browser preset) | now also covers five authenticated routes; wording only |
| "They now use `guarded_fetch_no_redirect` … the rule" (W6 review §15 note, T-112) | true for federation; the rule is not yet universal (R101W2-04) |
| "no code changed: no interoperability defect was found" (W4 review P23W4-09 closure, CHANGELOG #538) | true |
| "`allow_sha1_signatures` admits SHA-1, not every algorithm" (CHANGELOG #606, website, `FederationConfig` doc) | true for signature and digest methods; transforms are R101W2-01 |

## 12. Checks run

Each command's own exit code was captured; logs are in the session scratchpad.
No `cargo clean` was run (the orchestrator runs it between items).

| Check | Result |
|---|---|
| `cargo test -p axiam-federation --lib` | pass (330) |
| `cargo test -p axiam-api-rest --test federation_test --test federation_login_providers_test --test saml_idp_slo_test` | pass (86, 47, 26) |
| `cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features` (SAML off) | pass |
| **R101W2-01 probe**: a temporary unit test in `saml.rs`'s test module drove `handle_saml_response_for`, `verify_post_signature` and `parse_idp_metadata` with dummy-signed documents carrying one extra transform, against a no-transform control. Run, then removed (`saml.rs` restored byte for byte). | verifier CPU set by the sender at all three verifiers; the control was refused in milliseconds |
| **R101W2-02**: `curl` of Entra ID's common and tenant federation metadata | both begin `ef bb bf`, `encoding="utf-8"`; signed with `enveloped-signature` + `xml-exc-c14n#`, `rsa-sha256`/`sha256` |
| xmlsec build: `transforms.h`, `ldd libxmlsec1.so.1`, `libxmlsec1-openssl.so.1` | 1.2.39, XSLT compiled in, libxslt linked |
| `node website/scripts/gen-threat-model.mjs` | 475 threats (437 / 17 / 21); no diff |
| T-67/T-69/T-112/T-474 across the three copies | identical |
| Commit signatures | 6 of 6 carry `gpgsig` |

## 13. Issue bodies

### R101W2-01 (High) — SAML signature transforms are evaluated before the signature value is checked

**The gap.** Nothing restricts the `ds:Transform`s or the
`ds:CanonicalizationMethod` of a received XML signature:
* AXIAM's placement checks (`saml.rs` `check_signature_placement`,
  `saml_idp/request.rs` `signature_placement`) do not read them;
* samael 0.0.22 does not read them either, and creates the xmlsec context with
  default settings.

xmlsec 1.2.39, as linked here (XSLT compiled in), admits every registered
transform, including XSLT and XPath. It evaluates a reference's transforms
before it checks the `SignatureValue`. A sender with no valid signature can
therefore make the verifier spend CPU it chooses at three places:
* the SP ACS (`/api/v1/auth/federation/saml/acs`, `/acs/form`; public);
* the IdP SSO and SLO receiver (`verify_post_signature`; public);
* the metadata signature check.

The ACS and the IdP receiver verify inline on the async workers.

**Fix:** one allow-list check, called from both placement functions before
samael:
* `CanonicalizationMethod` must be exclusive c14n, c14n 1.0 or c14n 1.1, without
  comments;
* each `Reference` may carry at most two transforms, from `enveloped-signature`
  plus that set;
* the only child element allowed is `ec:InclusiveNamespaces`;
* each method has exactly one `Algorithm` attribute, compared exactly.

Also move SP and IdP-receiver verification into `spawn_blocking` under
`crypto_semaphore`.

**Tests:** XSLT, XPath, XPath Filter 2 and XPointer transforms, a `#WithComments`
canonicalisation and a third transform are each refused at all three verifiers
with the placement error. The Keycloak, samael and fixture suites stay green.

**Threat model:** a new entry, or dated corrections to T-69, T-320, T-372 and
T-474.

### R101W2-02 (Medium) — a UTF-8 byte-order mark is refused; Entra ID metadata carries one

**The regression.** #605 refuses any document whose first character is not `<`,
which includes a UTF-8 BOM. Microsoft Entra ID's federation metadata begins with
`ef bb bf` (verified 2026-10-13), and ADFS's very likely does too. SAML sign-in
fetches metadata through `SamlMetadataCache::resolve`, which requires
`metadata_url`, and a refused document is never cached. After upgrading to 1.0.1,
every SP-initiated sign-in through such a configuration fails. 1.0.0 accepted
these documents. The SP metadata import refuses BOM-prefixed SP metadata the same
way.

**Fix:** strip exactly one leading U+FEFF, then apply the existing rules. Return
the stripped slice, and make every consumer use it: the ACS's
`verify_signature`, samael parse and binding check; the metadata signature check
and samael; the SP metadata libxml parse; and the IdP receiver's
`verify_post_signature` input.

**Tests:**
* an Entra-shaped document parses;
* a BOM plus a UTF-16 declaration is still refused at the four entries;
* two BOMs are refused;
* BOM-prefixed signed metadata and a signed `AuthnRequest` verify.

**Docs:** CHANGELOG, and T-67, T-69 and T-474.

### R101W2-03 (Low) — two new rate-limit buckets share a name with existing ones

**The collision.** #614 registers `federation_saml_acs` and
`federation_oidc_callback` for the authenticated routes. These names are already
used by the public `/api/v1/auth/federation/saml/acs` and
`/api/v1/auth/federation/oidc/callback` buckets (`server.rs:561`, `:467`). The
shared counter key is `"{endpoint}:{ip}"`, so each pair is one counter, with two
limits (`login_per_min`, `end_session_per_min`) and two seeding rules.

**Fix:** rename the new buckets, for example to `federation_link_saml_acs` and
`federation_link_oidc_callback`. Add a test that fails on any duplicate endpoint
name passed to `RateLimitShared`, for example by collecting them from a
registration table, or by scanning `server.rs`. Correct T-474, the CHANGELOG and
the deployment docs.

### R101W2-04 (Medium) — back-channel logout delivery bypasses the SSRF guard and follows redirects

**The gap.** `backchannel_logout.rs` POSTs `logout_token` to the client's
`backchannel_logout_uri` with a default `reqwest` client:
* there is no resolve-and-pin guard and no private-address refusal;
* redirects are followed;
* `http` is accepted.

The URI is never validated on create or update (`oauth2_clients.rs`). A tenant
administrator can therefore make AXIAM send requests to internal addresses from
inside the deployment. This contradicts T-112's 2026-10-13 rule ("every
credential-bearing outbound request uses `guarded_fetch_no_redirect`").

**Fix:**
* validate the URI on save: `https`, an absolute URL with a host, no fragment,
  `http` for loopback only, as `redirect_uris` are validated;
* deliver through `guarded_fetch_no_redirect`, treating a `3xx` as a failed
  attempt.

**Tests:**
* a private, loopback or link-local URI is refused at registration;
* a delivery to an endpoint answering `307` is not followed, and the target sees
  nothing;
* a source pin like `webhook.rs`'s.

**Threat model:** a dated correction to T-112's rule statement.

### R101W2-05 (Informational) — the authenticated federation routes key their limiter on the address

**The issue.** Per-IP keying on authenticated routes does two things badly:
* it throttles a backend that relays many users;
* it does not bound one token used from many addresses.

**Suggestion:** a principal key, `(tenant, sub)`, or the pair (address, sub),
through a new `RateLimitKeyMode`.

### R101W2-06 (Informational) — the IdP's self-checks parse its own output with recovery on

**The issue.** `saml_idp/sign.rs:181,276` use `Parser::default()`. The input is
AXIAM's own serializer output, so nothing is reachable through this. But a
repaired tree is not what an SP parses, and recovery would hide a serializer
bug.

**Suggestion:** use `receiver_parser_options()`.

### R101W2-07 (Informational) — text drift

The following land with their fixes:
* T-69's residual (R101W2-01);
* "each in a bucket of its own" in T-474, the CHANGELOG and the docs
  (R101W2-03);
* the missing behaviour-change note for the BOM (R101W2-02);
* T-112's rule and the W6 review note (R101W2-04).

## 14. Invariants

I1 (nothing registered today changes behaviour unless the wave says so) holds,
with one exception: R101W2-02, an unannounced refusal of BOM-prefixed metadata.

The behaviour changes the wave does announce are:
* a 3xx from a token or userinfo endpoint is refused;
* five routes are limited;
* a flagged configuration refuses non-SHA algorithms;
* two new audit actions are written.

No contract file changed (`sdks/CONTRACT.md` and `openapi.json` were untouched,
as §9 requires outside W5). No schema migration was added. This review changed
no file but itself, and the probe test was removed before the commit.
