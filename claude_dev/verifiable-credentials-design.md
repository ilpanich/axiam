# Verifiable credentials — AXIAM as OID4VCI issuer and OID4VP verifier

**Status: DESIGN ONLY — no code.** No crate, schema, route, contract section or
threat-model entry accompanies this document. It is G-9 of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md)
(task T23.9.1) and exists so that, when the go criterion in §13 is met, the
implementation starts from argued decisions rather than from a specification
reading.

Written 2026-10-02 against `1.0.0-beta17` plus the Phase 23 W1 branch. Every
claim about AXIAM below names the file it was read from. Every claim about a
specification names the revision it was read from and how it was verified;
§16 collects what could not be verified.

> **Why design only.** The plan's §3 says it in one line: OID4VCI is preview and
> OID4VP experimental in Keycloak 26.8, and the EUDI wallet framework is still
> moving. This document confirms the second half with dates (§2): the two
> OpenID protocols are Final, but the two IETF documents every credential
> depends on are not yet RFCs, and HAIP 1.0 pins *draft* revisions of both.
> Writing the design now and implementing when those settle is the cheaper
> order.

---

## 0. Summary — the decisions in one place

1. **Verifier first, issuer second** (§3). The eIDAS 2 obligation that lands on
   AXIAM's customers is to *accept* the EUDI wallet (from 24 December 2027 for
   the regulated private relying parties); being an *issuer* in that ecosystem
   additionally requires registration as an attestation provider, which is a
   per-adopter decision. AXIAM-as-verifier also gives AXIAM's own login a new
   method ("present your PID") with no SDK change.
2. **SD-JWT VC only** in the first cut (§4). ISO mdoc is evaluated and deferred
   to adopter demand (mDL is mdoc-only, so an adopter verifying driving licences
   is the trigger). W3C VCDM / JSON-LD is declined.
3. **Credential-signing keys are not the ID-token key** (§5.1). They are
   per tenant, ES256 (P-256), bound to an X.509 chain carried in `x5c`, and
   custodied like CA keys. The Ed25519-only pin on ID tokens and the eleven SDK
   `alg` pins ([`basic-op-gap-plan.md`](basic-op-gap-plan.md) §10 decision B)
   are untouched.
4. **The integrated CA is a trust anchor for closed ecosystems only** (§5.2).
   In the EUDI ecosystem the issuer and verifier certificates come from a
   Member State *Access Certificate Authority* and the trust anchors live in
   Trusted Lists / LoTEs; AXIAM therefore needs "generate key → export CSR →
   import external chain", which `axiam-pki` half-has today.
5. **Request objects stay rejected on the OP side**; the verifier role
   *produces* them and never fetches one (§7.1). The SSRF argument of
   [`basic-op-gap-plan.md`](basic-op-gap-plan.md) §4.10 does not apply in
   reverse, and nothing in `authorize.rs` changes.
6. **Scope, not `authorization_details`**, in the first cut (§6.2). HAIP 1.0
   makes `scope` mandatory and RFC 9396 optional, and AXIAM has no RFC 9396
   support at all today (`grep -rn authorization_details crates/` is empty).
7. **A new crate, `axiam-vc`, at layer 5, behind a `vc` feature that is off by
   default** (§8). It depends on `axiam-oauth2` for the JOSE and DPoP rules it
   must not re-implement.
8. **Status via Token Status List, published per tenant**, deliberately *not*
   merged with the session-revocation feed (§5.4). They share caching and
   rate-limit machinery, and opposite failure rules.
9. **Cost: XL.** About 18–27 sessions for the verifier and 19–29 for the
   issuer, with mdoc a further XL (§12).
10. **Go = specification stability AND one concrete adopter** (§13). Neither
    alone.

---

## 1. What exists today, and two premises the tree corrects

### 1.1 Ingredients already in the tree

| Ingredient | Where | Use in this design |
|---|---|---|
| FAPI 2.0 authorization server: PAR, PKCE `S256`, `iss` in the authorization response (RFC 9207), DPoP with server nonces | `crates/axiam-oauth2/src/{par,pkce,dpop,fapi}.rs`; `DPoP-Nonce` at `crates/axiam-api-rest/src/handlers/oauth2.rs:2319` | HAIP's OID4VCI profile *is* FAPI 2.0 plus credential endpoints. The authorization-code flow needs no new AS machinery |
| One JOSE rulebook: `PERMITTED_ALGORITHMS = [PS256, ES256, EdDSA]`; the algorithm comes from the key, never from the header; RFC 7638 thumbprints | `crates/axiam-oauth2/src/jose.rs:47`, `:149` (`algorithm_for_key`), `:232` (`verify_permitted_header`), `:267` (`jwk_thumbprint`) | Verifies OID4VCI key proofs, key and wallet attestations, and KB-JWTs. ES256 is already on the list |
| Per-tenant path issuers `{root}/t/{tenant_id}` and the RFC 8414 §3.1 insertion form `/.well-known/<x>/t/{tenant_id}` (T21.6, off by default) | `crates/axiam-auth/src/config.rs:47` (`TENANT_PATH_PREFIX`), `:182–203` (`tenant_issuer_paths`), `:507` (`tenant_issuer`); routes at `crates/axiam-api-rest/src/server.rs:651–676` | The Credential Issuer Identifier and its `/.well-known/openid-credential-issuer/t/{tenant_id}` metadata URL are exactly this form (§6.1) |
| `x5c` chain verification with the "an end-entity cert is never an issuer" rule | `crates/axiam-pki/src/mds/blob.rs` (`assert_is_issuer`, `MAX_X5C_LEN`) | Generalised, it is the verifier's issuer-certificate path validation (§5.5) |
| Per-CA key custody: AES-256-GCM in the row, Vault KV, Vault PKI | `crates/axiam-pki/src/ca_key_store.rs`, `crates/axiam-pki/src/vault_pki.rs` | The custody model for credential-signing keys (§5.1) |
| SSRF guard with resolve-and-pin | `crates/axiam-pki/src/ssrf.rs` (`resolve_and_pick`, `is_disallowed_ip`) | Every URL the verifier dereferences (status lists) goes through it |
| Session-revocation feed `GET /oauth2/revocations` (T-39, T-143) | `crates/axiam-core/src/revocation_feed.rs`; route at `crates/axiam-api-rest/src/server.rs:1681` | Shares the publish-and-cache shape with the status list, not the semantics (§5.4) |
| Federated login with subject mapping (`LinkedOnly` / `JitProvision`) | `crates/axiam-core/src/models/federation.rs:450` | The OID4VP login method reuses the linking rules (§7.4) |
| Tenant switches for GDPR-sensitive claims (`address`, `phone`) | [`basic-op-gap-plan.md`](basic-op-gap-plan.md) §4.8 | A credential claim drawn from those attributes passes the same switch (§11) |
| `flate2` already in the workspace | `crates/axiam-federation/Cargo.toml:36` | Token Status List compresses its bitstring with DEFLATE/zlib |

### 1.2 Premise 1: there is no per-tenant signing key

The task brief speaks of "tenant EdDSA signing keys and the per-tenant JWKS".
The tree has **one** Ed25519 signing key per deployment:
`AuthConfig::jwt_private_key_pem` / `jwt_public_key_pem`
(`crates/axiam-auth/src/config.rs:53–56`). The per-tenant discovery document
publishes `jwks_uri = {issuer}/oauth2/jwks` (`crates/axiam-oauth2/src/oidc.rs:441`),
which on a tenant path is a per-tenant *URL* serving the same deployment key
(`build_jwks`, `oidc.rs:636`, accepts exactly one 44-byte Ed25519 SPKI). The
threat model's principal-asset table records the consequence: compromise of
that key means "any identity in any tenant can be forged"
([`threat-model-stride.md`](threat-model-stride.md) §4).

That is acceptable for 15-minute tokens. It is not acceptable for credentials
that live for months in wallets AXIAM cannot reach. §5.1 therefore introduces
per-tenant credential keys rather than reusing a per-tenant key that does not
exist.

### 1.3 Premise 2: there is no `authorization_details`

The brief proposes `authorization_details` of type `openid_credential`. AXIAM
has no RFC 9396 support at any endpoint. HAIP 1.0 §4.3 requires the wallet to
"use the `scope` parameter to communicate Credential Type(s)", and §4.1
requires a scope for every credential configuration; RFC 9396 stays optional
(HAIP: optional parameters of the profiled specifications "remain optional
unless stated otherwise"). §6.2 takes
the scope path and lists RFC 9396 as a later, separately-sized item.

### 1.4 Things that are absent and would have to be built

- An ECDSA P-256 key algorithm: `KeyAlgorithm` is `Rsa4096 | Ed25519`
  (`crates/axiam-core/src/models/certificate.rs:22`), and the CA issues only
  those.
- JWE. `jsonwebtoken` 11.1 (the workspace's only JOSE crate) signs and verifies
  JWS, supports `typ`, `x5c` and `jwk` header members and ES256 under
  `rust_crypto`, and has no JWE module. HAIP requires the verifier to decrypt
  `ECDH-ES` / `A128GCM` + `A256GCM` responses (§7.2).
- Attestation-based client authentication (wallet attestations).
  `ClientAuthMethod` is `ClientSecretPost | ClientSecretBasic | TlsClientAuth |
  SelfSignedTlsClientAuth | PrivateKeyJwt | None`
  (`crates/axiam-core/src/models/oauth2_client.rs:203`).
- Anything credential-shaped: no model, no route, no crate.

---

## 2. Specifications targeted

As of 2026-10-02. "Verified" means read in this session from the source named;
"search" means confirmed only by web-search summaries of the publisher's pages,
because `openid.net`, `datatracker.ietf.org` and `www.ietf.org` were blocked by
this environment's egress proxy for direct fetches. The spec sources were
instead read from the working groups' GitHub repositories (shallow clones).

| Specification | Target | State today | How verified |
|---|---|---|---|
| **OpenID for Verifiable Credential Issuance (OID4VCI)** | **1.0 Final** (approved September 2025), plus errata set 1 when published | Final. Errata set 1 in progress (editor's draft `-19`); a 1.1 working draft exists | Final approval: search (openid.net notice). Content: `openid/OpenID4VCI` `1.0/` editor's draft, read |
| **OpenID for Verifiable Presentations (OID4VP)** | **1.0 Final** (vote 24 Jun – 8 Jul 2025) | Final. Errata set 1 in progress (editor's draft `-31`); 1.1 working draft exists | Approval: search. Content: `openid/OpenID4VP` `1.0/`, read |
| **OpenID4VC High Assurance Interoperability Profile (HAIP)** | **1.0 Final** | Final; errata set 1 in progress (editor's `-09`); 1.1 working draft exists | Approval: search. Content: `openid/oid4vc-haip` `1.0/`, read |
| **SD-JWT** | **RFC 9901** (November 2025, Standards Track) | Published | Search (rfc-editor.org listing); cited normatively by the HAIP 1.0 source as `RFC9901` |
| **SD-JWT VC** (`draft-ietf-oauth-sd-jwt-vc`) | Implement against **the revision HAIP pins (`-13`)**, track to the RFC | Latest published **`-19`** (August 2026); editor's copy `-20` (AD and HTTP-directorate review comments addressed). Not an RFC | Draft numbers: search (ietf.org archive). Editor's copy and history: `oauth-wg/oauth-sd-jwt-vc`, read. HAIP's pin of `-13`: read |
| **Token Status List** (`draft-ietf-oauth-status-list`) | Implement against **HAIP's pin (`-14`)**, track to the RFC | Latest **`-21`** (30 June 2026); reported in the RFC Editor queue, intended Proposed Standard. No RFC number assigned that could be found | Revision and queue state: search (datatracker summary). History `-17`…`-21`: `oauth-wg/draft-ietf-oauth-status-list`, read. **RFC Editor queue state not verified directly** |
| **ISO/IEC 18013-5** (mdoc, mDL) | 18013-5:2021; HAIP also references a second edition for MSO revocation | 2021 edition published; **second-edition status not verified** | HAIP source, read |
| **ISO/IEC 18013-7** (online presentation) | 18013-7:2025, Annex B (OID4VP over redirects) and Annex D (OID4VP over the DC API) | Published 2025 per vendor documentation; **the ISO catalogue entry was not checked** | Search only |
| **EUDI Architecture and Reference Framework (ARF)** | **v3.0.0** | Tagged `v3.0.0` in `eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework`; the CHANGELOG at that tag still reads "Unreleased"; last dated release **2.9.0 (2026-05-11)**; press reported v3.0 in July 2026 | Tag list and CHANGELOG: `git ls-remote` + clone, read. **v3.0.0 publication date not verified** |
| Attestation-Based Client Authentication (`draft-ietf-oauth-attestation-based-client-auth`) | The revision OID4VCI pins (`-07`) | Draft | OID4VCI §"Pre-Final Specifications", read. **Current revision not checked** |
| OpenID Federation 1.0 | Not targeted (§15) | Pinned at `-43` by OID4VCI and OID4VP | Read |
| W3C Digital Credentials API | Not targeted in the first cut (§7.5) | Not checked | Not checked |

**The fact that shapes §13.** HAIP 1.0 §"Pre-Final Specifications" (read)
pins *SD-JWT VC `-13`* and *Token Status List `-14`*, and says implementations
"should continue to use the specifically referenced versions above in
preference to the final versions, unless updated by a profile or new version of
this specification". OID4VCI 1.0 pins SD-JWT VC `-11` and Status List `-12`;
OID4VP 1.0 pins SD-JWT VC `-09`. Today, therefore, a HAIP-conformant
implementation is built against drafts that are six to seven revisions behind
the documents' current state, and will be re-pinned when the RFCs land. That
is the moving target the plan meant.

**What is already stable.** OID4VCI, OID4VP and HAIP are Final; SD-JWT is
RFC 9901; and the OpenID Foundation's OID4VCI-issuer and OID4VP-verifier
conformance tests under HAIP were declared ready by the DCP working group in
July 2026 and opened for self-certification (search; not read at source).

---

## 3. Roles

| Role | In scope | Why |
|---|---|---|
| **Verifier (OID4VP), for AXIAM's own login** | **Yes — first** | A relying party that uses AXIAM gets "sign in with your EUDI wallet" as one more login method, and sees an ordinary AXIAM ID token. Zero SDK change (§12.2) |
| **Verifier (OID4VP), as a service for relying parties** | Yes — first, same machinery | An RP backend asks AXIAM to run a presentation and reads a verified, minimised result. The RP never handles wallet cryptography |
| **Issuer (OID4VCI)** | Yes — second | A tenant issues its own attestations (an employee badge, a device-operator qualification, a membership) to wallets. In EUDI terms AXIAM would be a *non-qualified EAA provider*'s issuance engine |
| **Holder (wallet)** | **No** | A wallet is a device-resident, key-attesting application; it is a product, not an IAM surface |
| **PID provider** | **No** | PID is issued by or on behalf of Member States, in both mdoc and SD-JWT VC (ARF v3.0.0 annex 2: "A PID Provider SHALL issue any PID in both the format specified in ISO/IEC 18013-5 and the format specified in [SD-JWT VC]") |

**Why the verifier goes first.** Three reasons, in decreasing weight:

1. **The obligation lands on relying parties.** eIDAS 2 (Regulation
   (EU) 2024/1183) requires each Member State to offer a wallet by
   24 December 2026, and regulated private relying parties to accept it for
   authentication from 24 December 2027 (secondary sources, §16). AXIAM's
   customers are relying parties. A customer who must accept the wallet asks
   its IAM for that before it asks to issue anything.
2. **Issuing into EUDI is gated outside AXIAM.** An attestation provider
   registers with a Member State registrar and receives access and
   registration certificates (ARF v3.0.0 §6.3.2.3). That is a per-adopter
   process, not a feature.
3. **The verifier needs no long-lived signing key with a public trust chain**
   beyond its access certificate. The issuer needs the whole of §5.

Because PID is always issued in SD-JWT VC as well as mdoc, a verifier that
speaks SD-JWT VC alone can consume every PID.

---

## 4. Credential formats

### 4.1 SD-JWT VC — first

`application/dc+sd-jwt`, header `typ: dc+sd-jwt`; the issuer-signed JWT is an
RFC 9901 SD-JWT whose payload carries `vct`, `iss`, optional `exp`/`iat`/`nbf`,
`cnf` (holder key) and `status`. HAIP's credential format identifier is
`dc+sd-jwt` (HAIP 1.0 §5.3.2, read).

Why first:

- **The JOSE stack is already there.** `jsonwebtoken` 11 with `rust_crypto`
  signs and verifies ES256 and exposes `typ`, `x5c`, `jwk` and free-form
  `extras` in the header (checked in the 11.1.0 source). SD-JWT itself is
  salted SHA-256 digests over JSON, plus `~`-separated disclosures and an
  optional KB-JWT — no new primitive.
- **The verification rules are already written down once.**
  `crates/axiam-oauth2/src/jose.rs` is the single place that decides which
  algorithms are permitted and that the key decides the algorithm. A KB-JWT
  and an OID4VCI proof JWT are both "a JWT signed by a key AXIAM did not
  mint" and go through it unchanged.
- **Every EUDI wallet must support it** (ARF v3.0.0 §5.4.1: mdoc and SD-JWT VC
  are mandatory for wallet units), and every PID exists in it.

### 4.2 ISO mdoc — evaluated, deferred to an adopter

mdoc (`mso_mdoc`) is CBOR (RFC 8949) with a COSE_Sign1 *Mobile Security
Object* over per-element digests, issuer `x5chain`, and device authentication
by a COSE signature or MAC over a session transcript.

| Aspect | Cost to AXIAM |
|---|---|
| Encoding | CBOR is new to production code. `ciborium` is in `Cargo.lock` only via `surrealdb-core` and `criterion`; `serde_cbor_2` via `webauthn-rs-core` |
| Signatures | COSE_Sign1 — `coset` (Google, Apache-2.0, depends only on `ciborium`) would be the base |
| Device authentication | Session-transcript construction differs between ISO 18013-7 Annex B (redirects) and Annex D (DC API); both would be needed |
| Issuance | MSO construction, validity-info, per-namespace digests, device key binding |
| Status | MSO revocation per ISO 18013-5 second edition (HAIP §5.3.1) — the second edition's status was not verified |
| Conformance | Separate test profile; separate interop |

**Estimate: XL on its own** (§12). **Trigger:** an adopter that must verify an
mDL (the driving licence is mdoc-only) or issue into an mdoc-only scheme. Until
then, SD-JWT VC covers PID.

### 4.3 W3C VCDM / JSON-LD — declined

- **JSON-LD processing dereferences `@context` URLs.** That is either an SSRF
  primitive or a pinned-context allow-list that has to be maintained per
  credential type. AXIAM spent the SEC-054 machinery and §4.10 of the
  Basic OP plan refusing exactly this class of fetch.
- **Data Integrity proofs require RDF canonicalisation**, a large, subtle
  algorithm with no counterpart anywhere in the tree.
- **It is optional in EUDI.** ARF v3.0.0 §5.4.1: wallet support for W3C VCDM v2.0
  is "optional and meant for non-qualified EAAs only", and HAIP 1.0 profiles
  only SD-JWT VC and mdoc.
- **The Rust candidate (`ssi`) brings the whole DID/JSON-LD/RDF stack** (§9).

**Re-evaluation trigger:** ARF v3.0.0 notes that wallets "may be required to
support this format when the new profiles (created by ETSI) on the W3C VCDM
format are available", citing education. An adopter in that sector *and* a
published ETSI profile would reopen this; the `VC-JOSE-COSE` securing mechanism
(no JSON-LD processing) would be the only variant considered.

---

## 5. Trust mapping

### 5.1 Key separation — credential keys are not the ID-token key

| Property | ID-token / access-token key (today) | Credential-signing key (proposed) |
|---|---|---|
| Scope | One per deployment (§1.2) | **One or more per tenant**; optionally per credential configuration |
| Algorithm | Ed25519 (`EdDSA`), pinned in eleven SDKs | **ES256** (P-256) |
| Lifetime of what it signs | ≤ 15 minutes | Months, in wallets AXIAM cannot reach |
| Key resolution by the relying party | JWKS at `{issuer}/oauth2/jwks` | `x5c` chain in the credential header (HAIP §6.1.1) |
| Rotation | Coordinated with every RP's JWKS cache | Overlapping keys; retired keys stay valid until the last credential they signed expires |
| Custody | Secret provider | `CaKeyStore`-style custody per key row (DB AES-256-GCM, Vault KV); a JWS-capable "never leaves" custodian (Vault Transit, a KMS) is a follow-up — Vault **PKI** signs certificates, not arbitrary JWS |

Why separate, argued once:

1. **Algorithm.** HAIP 1.0 §7 makes ES256 the floor: issuers, verifiers and
   wallets "MUST, at a minimum, support ECDSA with P-256 and SHA-256" for
   attestations, proofs, KB-JWTs and status lists. A HAIP-minimal verifier may
   support nothing else, so an EdDSA-signed credential would be unverifiable to
   it in practice. Signing ID tokens with ES256 instead would reverse the
   maintainer's 2026-09-07 decision B in [`basic-op-gap-plan.md`](basic-op-gap-plan.md)
   §10 and touch eleven SDK pins. Separate keys keep that decision intact.
2. **Blast radius.** The deployment key forges any identity in any tenant. A
   per-tenant credential key, if compromised, forges one tenant's credentials
   and is revoked by revoking one certificate.
3. **Rotation cadence.** Rotating the token key must not invalidate every
   credential in every wallet, and the reverse must not force a JWKS rotation.
4. **Cross-protocol confusion.** A key that signs both ID tokens and SD-JWTs
   lets an attacker try to present one artefact as the other. `typ` checks
   defend this; separate keys make it impossible.

The status-list signing key is a third role. It may be the same key as the
credential key for a tenant, but the design keeps it a
separate row so that an adopter whose trust framework outsources status
publication (ARF §6.3.2.4 notes the anchors "may be different") can do so.

### 5.2 Issuer trust: the integrated CA versus EUDI's trust lists

HAIP 1.0 §6.1.1 (read): the SD-JWT VC "MUST contain the credential issuer's
signing certificate along with a trust chain in the `x5c` JOSE header"; the
trust anchor is not included; the signing certificate is not self-signed. It
leaves *which* anchors to trust to the ecosystem.

Two ecosystems follow, and AXIAM must serve both:

| | Closed ecosystem (enterprise, IoT, a federation of partners) | EUDI ecosystem |
|---|---|---|
| Anchor | The **organization CA** of the integrated PKI, distributed out of band to the verifiers that matter | A **Trusted List** (QEAA) or the Commission's **LoTE** (PID, PuB-EAA); non-qualified EAA anchors are not in a LoTE (ARF v3.0.0 §6.3.2.4) |
| Chain AXIAM produces | Org CA → tenant signing CA (path-length-zero intermediate, [`threat-model-stride.md`](threat-model-stride.md) §4) → **credential-signing leaf** | AXIAM generates the key and a **CSR**; the provider's CA (QTSP, or the scheme's CA) signs it; AXIAM **imports the chain** |
| Wallet authenticates the issuer by | Signed issuer metadata with `x5c` (OID4VCI §12.2.2, optional; HAIP §4.1 requires wallets and issuers to support it) | The provider's **access certificate** from a Member State Access Certificate Authority (ARF v3.0.0 §6.3.2.3) |
| Verifier discovers anchors by | Configuration | Trusted List / LoTE, and DCQL `trusted_authorities` by Authority Key Identifier (`aki`), which HAIP §5 makes mandatory |

What `axiam-pki` needs for this:

- A `KeyAlgorithm::EcdsaP256` variant (`rcgen` supports `PKCS_ECDSA_P256_SHA256`),
  and a leaf profile for credential signing: `keyUsage: digitalSignature`, no
  `clientAuth`/`serverAuth` EKU. `LeafProfile::for_leaf`
  (`crates/axiam-core/src/models/certificate.rs`) would get a new
  `CertificateType` arm, not a new code path.
- **CSR export and external-chain import for a leaf whose key AXIAM keeps.**
  Today AXIAM returns leaf private keys once and never stores them (CLAUDE.md,
  security standards). A credential-signing key is the first *leaf* key AXIAM
  must keep, and it is therefore custodied as a CA key is, not as a leaf is.
  This is the single most consequential change in the design and is called out
  as threat-model element E3 (§10).

The Credential Issuer Identifier and the SD-JWT `iss` are the same string,
`{root}/t/{tenant_id}` (OID4VCI 1.0 §"Relationship between the Credential
Issuer Identifier in the Metadata and the Issuer Identifier in the Issued
Credential"). With `x5c` resolution the verifier additionally sees the leaf
subject; the leaf's subject or SAN should name that URL so the two cannot
disagree.

**Not used: `/.well-known/jwt-vc-issuer`.** SD-JWT VC also defines web-based
key resolution (JWT VC Issuer Metadata with a `jwks_uri`). AXIAM would publish
only `x5c`: it is what HAIP mandates, it binds the key to a certificate a trust
list can name, and on the verifier side it removes a fetch of an
attacker-influenced URL.

### 5.3 Holder binding and DPoP

- **Holder binding.** The credential's `cnf.jwk` is the public key from the
  wallet's OID4VCI key proof (`typ: openid4vci-proof+jwt`) or key attestation
  (HAIP §4.5.1). Proof verification is `jose.rs` as it stands: the key decides
  the algorithm; ES256 is permitted; `aud` is the Credential Issuer Identifier;
  `nonce` is a `c_nonce` from the nonce endpoint.
- **Presentation.** A KB-JWT signed by the `cnf` key, with `aud` = the
  verifier's client identifier, `nonce` = the request nonce, `iat` fresh and
  `sd_hash` over the presented SD-JWT. HAIP §6.1.1.1: if the credential has
  holder binding, the KB-JWT "MUST always be present".
- **DPoP.** HAIP §4 makes DPoP mandatory for the access token at the
  credential endpoint. That is `dpop.rs` unchanged, including `DPoP-Nonce`,
  which OID4VCI lets the nonce endpoint return alongside `c_nonce`.
- **The DPoP key and the holder key are different keys, and AXIAM must not
  require otherwise.** The DPoP key lives for an issuance session; the holder
  key for the credential. Requiring equality would give a verifier and the
  issuer a shared correlator (§11).

### 5.4 Status: Token Status List per tenant, and the revocation feed

Each tenant that issues publishes one or more **Status List Tokens**
(`typ: statuslist+jwt`, signed with `x5c` per HAIP §6.1) at
`{issuer}/vc/status/{list_id}`. A credential's `status.status_list` carries
`{idx, uri}`. HAIP §6.1: every credential gets "its own unique, unpredictable
status list index".

How it relates to `GET /oauth2/revocations`
(`crates/axiam-core/src/revocation_feed.rs`):

| | Session-revocation feed | Token Status List |
|---|---|---|
| Subject | Sessions (hashed `sid`) | Credentials (an index into a bitstring) |
| Lifetime of an entry | One access-token lifetime, then gone (property 2) | The credential's lifetime; bits are never reused while a credential could be presented |
| Size | Tracks the 15-minute revocation rate | Fixed per list; must be large (herd privacy, §11) |
| Who reads it | AXIAM SDK route guards | Any verifier, anywhere |
| Failure rule | **Never fail closed** (property 4): the feed narrows a window on an already-authenticated token | As AXIAM-the-verifier: **fail closed for login** — a status the verifier cannot establish is not "valid", because the status check is part of authenticating, not a narrowing after it |

They share the *shape* — a public, signed or hashed, cacheable, rate-limited
document beside the JWKS — and therefore share the ETag and `Cache-Control`
machinery of `jwks_cache` and a rate-limit preset. They do **not** share a
store, a route or a failure rule.

They do share **triggers**. The events that write a revocation-feed entry
(account disable, admin session revoke, logout) are a subset of those that
should flip credential status, and Art. 17 erasure is another (§11). The
implementation hooks status updates at the same call sites, which is the one
place the two features meet.

### 5.5 Verifier trust anchors

A tenant-scoped **trust-anchor set**: anchors from the integrated CA, imported
PEM anchors, and (later) a periodically fetched Trusted List / LoTE snapshot.
Issuer-certificate path validation generalises `crates/axiam-pki/src/mds/blob.rs`:
bounded `x5c` length, `basicConstraints: CA=true` and `keyCertSign` on every
issuing position, signature chain to a configured anchor, validity at
verification time, the anchor itself never accepted from the header. The MDS
module's doc comment on `assert_is_issuer` explains the forged-leaf attack this
prevents; it applies verbatim to an SD-JWT VC `x5c`.

---

## 6. Issuer design (OID4VCI)

### 6.1 Identifier and metadata

- **Credential Issuer Identifier:** `{root}/t/{tenant_id}` — the T21.6 tenant
  issuer. OID4VCI 1.0 §12.2.1 forbids a query component, exactly as RFC 8414 §2
  does, so the `?tenant_id=` form cannot be an issuer here either. **The `vc`
  feature therefore refuses to start unless `tenant_issuer_paths` is on.**
- **Metadata:** `GET /.well-known/openid-credential-issuer/t/{tenant_id}` —
  OID4VCI §12.2.2 builds it by *inserting* the well-known segment, the same rule
  `server.rs:669–676` already routes for `oauth-authorization-server` and
  `openid-configuration`. Unsigned `application/json` always; signed
  `application/jwt` with `x5c` when the tenant has a metadata-signing
  certificate (HAIP §4.1 requires support for it).
- **The issuer is its own authorization server.** `authorization_servers` is
  omitted, so wallets use the tenant's existing RFC 8414 document, which gains
  the pre-authorized grant type and
  `pre-authorized_grant_anonymous_access_supported` (default `false`).

### 6.2 Flows

**Authorization code (HAIP: MUST).** Unchanged FAPI 2.0 machinery: PAR, PKCE
`S256`, DPoP, RFC 9207 `iss`. The wallet sends `scope=<configuration scope>`;
the scope maps to exactly one credential configuration (HAIP §4.3). The
authorization decision is an **RBAC check**: each credential configuration is a
resource, and issuing it is a permission (`vc:issue`) evaluated by
`axiam-authz` with deny-override. "Who may hold the contractor badge" is then
an ordinary role assignment, reviewable in the same console as everything else.
`issuer_state` from an issuer-initiated offer is carried through PAR.

**Pre-authorized code (optional; issuer-initiated only).** An admin or an
integration creates an offer for a user; AXIAM returns a credential offer (by
value, or by reference at `{issuer}/vc/offers/{id}`, single-use) with a
`pre-authorized_code` and, by default, a `tx_code`. The code and `tx_code` are
stored hashed, single-use, short-lived, with a failed-attempt ceiling after
which the code is burned (OID4VCI §13.6, "Transaction Code Guessing"). The
`tx_code` is delivered out of band through `axiam-email`, never in the same
channel as the offer.

**RFC 9396 `authorization_details` (later, M).** Adds per-request claim
selection, which the scope path cannot express. Not needed for HAIP.

### 6.3 Endpoints (proposed, not built)

All wallet-facing routes are under the tenant scope `/t/{tenant_id}`.

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/.well-known/openid-credential-issuer/t/{tenant_id}` | GET | none | JSON or signed JWT by `Accept` |
| `/t/{tenant_id}/vc/nonce` | POST | none | `c_nonce`, `Cache-Control: no-store`, optional `DPoP-Nonce`. Rate-limited like `/oauth2/token` |
| `/t/{tenant_id}/vc/credential` | POST | DPoP-bound access token | Proofs or key attestation; returns `credentials[]` (batch) or `transaction_id` |
| `/t/{tenant_id}/vc/deferred_credential` | POST | DPoP-bound access token | Reuses the pending-state discipline of the device grant (`crates/axiam-oauth2/src/device_service.rs`) |
| `/t/{tenant_id}/vc/notification` | POST | DPoP-bound access token | `credential_accepted` / `_failure` / `_deleted`, audited, idempotent |
| `/t/{tenant_id}/vc/offers/{id}` | GET | none (unguessable id) | By-reference credential offer; single-use; short TTL |
| `/t/{tenant_id}/vc/status/{list_id}` | GET | none | Status List Token; ETag; long `max-age` |
| `/t/{tenant_id}/oauth2/token` | POST | (existing) | New `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`, dispatched by one `match` arm as the device grant is |
| `/api/v1/vc/credential-configurations` | CRUD | admin | Tenant-scoped |
| `/api/v1/vc/signing-keys` | CRUD + `csr` + `chain` | admin | Generate key, export CSR, import chain, rotate, retire |
| `/api/v1/vc/offers` | POST | admin / service account | Create a pre-authorized offer for a user |
| `/api/v1/vc/issuances/{id}/status` | PUT | admin | Revoke / suspend (2-bit lists) |

Credential request and response encryption (OID4VCI §10) is optional and is
left out of the first cut; it needs the same JWE work as §7.2 and can follow it.

### 6.4 Data model (proposed)

| Table | Key fields | Deliberately absent |
|---|---|---|
| `credential_configuration` | `tenant_id`, `configuration_id` (wallet-facing), `format` (`dc+sd-jwt`), `vct`, `scope`, claim map (claim path → user attribute, `sd: always\|never`), display, validity, `binding_required`, accepted proof types, `key_attestation_required`, `signing_key_id`, `status_list_bits` (1 or 2), `batch_size`, `enabled` | — |
| `credential_signing_key` | `tenant_id`, `alg` (ES256), custody reference, `x5c` chain (excluding anchor), `source` (`integrated_ca` \| `external`), `role` (`credential` \| `status_list` \| `metadata`), `state` (`next` \| `active` \| `retired`), validity | Private key in clear |
| `credential_issuance` | `tenant_id`, `user_id`, `configuration_id`, `status_list_id`, `status_index`, `issued_at`, `expires_at`, `notification_id`, `state` | **The credential, the disclosures, the salts, the holder key** (§11) |
| `status_list` | `tenant_id`, `bits`, `size`, compressed bitstring, `version`, signing key, `ttl` | Any mapping from index to user outside `credential_issuance` |
| `pre_authorized_code` | hash, `tenant_id`, `user_id`, configuration ids, `tx_code` hash, `attempts`, `expires_at` | Codes in clear |
| `deferred_issuance` | `transaction_id` hash, `tenant_id`, `issuance_id`, `ready_at` | — |

Every table is tenant-scoped at the repository layer, as every AXIAM table is.

---

## 7. Verifier design (OID4VP)

### 7.1 Request objects: why the OP-side refusal does not apply in reverse

[`basic-op-gap-plan.md`](basic-op-gap-plan.md) §4.10 and §9 reject request
objects on AXIAM's **OP** side, permanently, for two reasons: JAR by value
duplicates PAR with a weaker integrity story, and `request_uri` by reference is
an **SSRF primitive** because *the OP fetches an attacker-chosen URL*.

As a verifier AXIAM is the **client**, not the OP. HAIP §5 and §5.1 require signed
request objects (JAR) passed by `request_uri`, with client identifier prefix
`x509_hash`. The roles are inverted:

| | OP side (today, unchanged) | Verifier side (proposed) |
|---|---|---|
| Who signs the request object | The client | **AXIAM** |
| Who serves it | The client, at a URL it chooses | **AXIAM**, at its own `request_uri` |
| Who dereferences `request_uri` | The OP — the SSRF | **The wallet**; AXIAM dereferences nothing |
| `authorize.rs` | Rejects `request` / non-PAR `request_uri` | Not involved |
| Discovery `request_parameter_supported: false` | Remains true — it describes the OP | Not a statement about the verifier |

So §4.10 stands exactly as written, and nothing on the OP side changes. What
*is* new is an unauthenticated inbound endpoint that returns signed requests
(`request_uri_method=post` with the wallet's `wallet_nonce`, OID4VP §5.10) and
must be single-use, short-lived and rate-limited. That is element E5 in §10.

The verifier's signing key is an ES256 key whose certificate is the relying
party's **access certificate** (ARF v3.0.0 §6.3.2, for EUDI) or a leaf from the
integrated CA (closed ecosystem). Its `x509_hash` client identifier is the
SHA-256 of that leaf. It is custodied as a credential-signing key is (§5.1) and
is a different key from both the token key and any issuer key.

### 7.2 Response: `direct_post.jwt`, encrypted, with a response code

- HAIP §5.1 and §5: response mode `direct_post.jwt`, JWE with `ECDH-ES` on P-256 and
  `A128GCM` / `A256GCM` (verifier MUST support both), with a **fresh ephemeral
  encryption key per request** passed in client metadata.
- The `response_uri` is a new unauthenticated `POST` that receives PII. It
  accepts JWE only, enforces a body ceiling, checks `state` against a recent
  request (OID4VP §14.4.2), and refuses a second response for the same request.
- **Session fixation (OID4VP §14.3).** Same-device: the `response_uri`
  returns a `redirect_uri` carrying a fresh **response code**, and the result is
  released only to the browser session that started the request and presents
  that code. HAIP: "Verifiers MUST reject presentations if Wallets do not follow
  the redirect back or the redirect back arrives in a different user session".
  Cross-device (QR) is weaker by construction and is off by default per tenant.
- **JWE implementation** is the one cryptographic primitive the tree lacks.
  Options in §9; the recommendation is decrypt-only `ECDH-ES` (direct key
  agreement) + `A128GCM`/`A256GCM` composed from RustCrypto (`p256`, `aes-gcm`,
  Concat KDF), tested against RFC 7518 Appendix C and the OIDF verifier
  conformance suite, *unless* a maintained pure-Rust JWE crate exists at
  implementation time. This is decision VC-D6 (§14), not settled here.

### 7.3 DCQL

Requests use `dcql_query` (HAIP §5). AXIAM stores **query templates** per
tenant (a credential query by `vct`, the claim paths needed, and
`trusted_authorities` by `aki` from the tenant's trust-anchor set) rather than
accepting arbitrary DCQL from RPs. A template is reviewable and minimal by
construction; an arbitrary query from an RP backend is a data-minimisation
decision made outside AXIAM's audit.

### 7.4 OID4VP as an AXIAM login method

The login hop (Basic OP Gap 0) offers "Sign in with your wallet" when the
tenant enables it. On a valid presentation:

1. **Validate**: issuer `x5c` chain to a tenant anchor (§5.5); SD-JWT digests
   and disclosures (the RFC 9901 verification rules); `typ`; `vct` is one the template allows;
   KB-JWT `aud`, `nonce`, `iat`, `sd_hash`; status list (fetched through the
   SSRF guard, cached, **fail closed**).
2. **Map the subject.** OID4VP §14.5 (read): a claim used to authenticate must
   be "stable … locally unique and never reassigned" and used "in combination
   with the Credential Issuer identifier". The link key is therefore
   `(issuer certificate subject or iss, claim)`, never the claim alone, stored
   as a federation link with the same `LinkedOnly` / `JitProvision` choice the
   federated-login design uses (`SubjectMapping`,
   `crates/axiam-core/src/models/federation.rs:450`). Default `LinkedOnly`.
3. **Issue an ordinary AXIAM session.** The RP sees a normal ID token. `amr`
   and `acr` values for "authenticated by wallet presentation" go through
   `crates/axiam-oauth2/src/acr.rs`; the exact values are an implementation
   decision, recorded as VC-D9.

### 7.5 The W3C Digital Credentials API

HAIP §5.2 defines OID4VP over the browser's Digital Credentials API, which
avoids custom-scheme invocation and most session-fixation problems. It needs
JavaScript in the login page and `dc_api.jwt`. Not in the first cut; it is the
first follow-up once the redirect flow ships, because browser support is the
direction the ecosystem is moving.

### 7.6 Verifier data model and endpoints (proposed)

| Item | Shape |
|---|---|
| `verifier_identity` | `tenant_id`, signing key reference, access-certificate chain, derived `x509_hash` client id, registration certificate (EUDI), `cross_device_enabled` |
| `presentation_template` | `tenant_id`, name, DCQL template, purpose text, allowed `vct`s, linked login config |
| `presentation_request` (transient) | `id`, `tenant_id`, `state`, `nonce`, `wallet_nonce`, ephemeral JWE private key (sealed, deleted on completion), `response_code` hash, `expires_at`, outcome |
| `trust_anchor` | `tenant_id`, source (`integrated_ca` \| `imported` \| `trusted_list`), certificate, `aki`, validity |

| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/v1/vc/presentations` | POST | RP service account | Start a request from a template; returns the wallet invocation (`openid4vp://?client_id=x509_hash:…&request_uri=…&request_uri_method=post`) |
| `/t/{tenant_id}/vp/request/{id}` | POST | none | Returns `application/oauth-authz-req+jwt`; single-use |
| `/t/{tenant_id}/vp/response` | POST | none | `direct_post.jwt`; returns `redirect_uri` with response code |
| `/api/v1/vc/presentations/{id}` | GET | RP service account + `response_code` | The verified, minimised result; one read, then deleted |

---

## 8. Crate placement and layering

**Proposal: a new crate `axiam-vc` at layer 5**, beside `axiam-amqp`, behind a
`vc` Cargo feature that `axiam-server` does not enable by default.

```
axiam-vc (5) -> axiam-oauth2 (4)   jose.rs rules, dpop.rs, TokenService for the
                                   pre-authorized grant, the login hop
             -> axiam-db (2)       repositories for §6.4 / §7.6
             -> axiam-audit (2)    issuance / presentation events
             -> axiam-pki (1)      keys, CSR, chain import, x5c path validation, SSRF guard
             -> axiam-authz (1)    vc:issue on credential-configuration resources
             -> axiam-auth (1), axiam-core (0)
axiam-api-rest (6) -> axiam-vc     mounts the routes under the same feature
axiam-server (8)   -> axiam-vc
```

Why not inside `axiam-oauth2` (layer 4):

- **The format code is not OAuth.** SD-JWT encoding, Status List compression,
  DCQL, and later CBOR/COSE for mdoc would bring a dependency set to the
  authorization server that every deployment compiles and that has nothing to do
  with issuing tokens. `axiam-oauth2` is already 31 modules.
- **A feature flag at a crate boundary is the pattern that works.** SAML lives
  behind `saml` and CI's *Build (SAML off)* job keeps the off build honest. A
  `vc` feature on `axiam-api-rest` and `axiam-server` with the crate absent when
  off gives the same guarantee: a deployment that does not issue credentials
  does not compile, link or expose the code.
- **The dependency direction forbids the alternative.** `axiam-vc` needs
  `jose.rs` and `dpop.rs`; putting it *below* `axiam-oauth2` would force those
  rules to move or be duplicated, and [`jose.rs`](../crates/axiam-oauth2/src/jose.rs)'s
  own header says why one copy matters: "Two copies would be two chances to fix
  one and not the other".

Why layer 5 and not a new layer: `scripts/check-crate-layering.py` requires a
strictly-lower layer for every edge. `axiam-vc` and `axiam-amqp` need nothing
from each other, so sharing layer 5 is legal. The layer's name in the script
and in [`crate-layering.md`](crate-layering.md) would change from "messaging
adapter" to "protocol services" with a sentence on why both sit there. If a
future edge between them appears, the gate fails and the table is the thing to
change — which is what the gate is for.

The crate opts into `missing_docs` from its first commit (§7.4 of the plan).

---

## 9. Rust crates evaluated

Versions and metadata from the crates.io API on 2026-10-02; repository
activity from shallow clones on the same day.

| Crate | Version / last release | Licence | Crypto backend | Fit | Verdict |
|---|---|---|---|---|---|
| `jsonwebtoken` (workspace) | 11.1.0 (2026-09-16) | MIT | `rust_crypto` (pure Rust); no OpenSSL | JWS ES256/EdDSA/PS256; header `typ`, `x5c`, `jwk`, `extras`. **No JWE** | **Use** for every JWS in this design |
| `sd-jwt-rs` (OpenWallet Foundation labs) | 0.7.1 (**2024-10-18**) | Apache-2.0 OR MIT | via `jsonwebtoken` | The released 0.7.1 depends on `jsonwebtoken` **^9** and `sha2` 0.10, so it would add a second `jsonwebtoken` major beside the workspace's 11 (and `surrealdb-core`'s 10). Git `main` is active (last commit 2026-09-25) and has moved to `jsonwebtoken` 11, but is unreleased; README still says "Supported version: 7" (draft) | **Not as released.** Re-check at go time; a release on `jsonwebtoken` 11 claiming RFC 9901 makes it the first choice |
| `sd-jwt-payload` (IOTA) | 0.5.1 (2026-01-14) | Apache-2.0 | Crypto-agnostic: `JwsSigner` and `Hasher` traits | README claims RFC 9901. Signing is ours (through `jsonwebtoken`), which is the right split | **Candidate.** Licence is Apache-2.0 only (fine for AXIAM). Pulls `anyhow`, `async-trait`, `multibase`, `json-pointer` |
| `sd-jwt` (kushaldas) | 0.1.0 (2025-12-17) | MIT OR Apache-2.0 | `josekit` → **OpenSSL** | Young, low adoption | **No** |
| `ssi` / `ssi-sd-jwt` / `ssi-status` (SpruceID) | 0.16.0 (2026-04-16) / 0.6.0 / 0.8.1 | Apache-2.0 | Own stack | Brings DIDs, JSON-LD, RDF, EIP-712, UCAN, ZCAP; `ssi-sd-jwt` and `ssi-status` are separable but share `ssi-*` core crates | **No** for the whole; `ssi-status` could be read as a reference implementation of status lists |
| `isomdl` (SpruceID) | 0.2.0 (2025-10-09); `main` active (2026-10-01) | Apache-2.0 OR MIT | RustCrypto (`p256`, `p384`, `ecdsa`) | mdoc issuance and presentation; depends on `coset` **0.3**, `ssi-jwk` 0.2, and `clap` / `clap-stdin` as *library* dependencies | **Re-evaluate at mdoc time.** Pre-1.0, 6.5k downloads; the CLI dependencies in the library would need a feature split upstream |
| `coset` (Google) | 0.4.2 (2026-03-02) | Apache-2.0 | none (types only) | COSE structures over `ciborium` | **Use** if mdoc goes ahead |
| `ciborium` | 0.2.2 (2024-01-24) | Apache-2.0 | — | CBOR; already in `Cargo.lock` via `surrealdb-core` | **Use** with `coset` |
| `josekit` | 0.10.3 (2025-05-20) | MIT OR Apache-2.0 | **OpenSSL** | Full JOSE incl. JWE `ECDH-ES` | **No.** OpenSSL is already linked through `webauthn-rs-core` and `samael`, so the objection is not linkage: it is a *second JOSE implementation* beside `jsonwebtoken`, which `jose.rs` exists to prevent |
| `biscuit` | 0.8.0 (2026-04-05) | MIT | `ring` | JWS + JWE; **whether it implements `ECDH-ES` was not verified** | Check at go time for VC-D6 |
| `jose-jwk` / `jose-jws` (RustCrypto) | 0.1.2 (2023-08-21) | Apache-2.0 OR MIT | RustCrypto | Stalled; no JWE crate published (`jose-jwe` is not on crates.io) | No |
| `p256`, `aes-gcm`, `concat-kdf` (RustCrypto) | 0.13 in lock (0.14.0 released 2026-07-03); `aes-gcm` 0.11 in workspace; `concat-kdf` 0.1.0 (2022) | Apache-2.0 OR MIT | pure Rust | Building blocks for decrypt-only `ECDH-ES` + AES-GCM | **Candidate** for VC-D6, with RFC 7518 App. C vectors |
| `x509-parser` (workspace) | 0.18 | MIT OR Apache-2.0 | — | Already used by `mds/blob.rs` | **Use** for `x5c` path validation |
| `rcgen` (workspace) | 0.14 | MIT OR Apache-2.0 | `ring` / `aws-lc-rs` | `PKCS_ECDSA_P256_SHA256` key generation and CSRs | **Use** |
| `dcql`, `openid4vp`, `oid4vci` | 0.1.0 (2025), 0.1.0 (2023), 0.1.0 (2023) | various | — | Placeholder-grade, < 2.1k downloads each | **No.** DCQL is small enough to model in-tree |

No Rust crate implements the Token Status List under that name on crates.io
(`token-status-list` and `status-list` return 404). It is a compressed
bitstring in a signed JWT; in-tree with `flate2` is the expected answer.

---

## 10. Threat-model elements this would add

**Named here, not entered.** Per §7.2 of the plan, threats enter
[`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` in the same
commit as the code, with numbers allocated from `threatTop` at that time
(threat model §9). The labels below (E1…, V-…) are this document's only.

### 10.1 New elements and one new trust boundary

| Id | Element | Type |
|---|---|---|
| E1 | Credential issuer endpoints (metadata, nonce, credential, deferred, notification, offer-by-reference) | Process, Internet-facing |
| E2 | Pre-authorized code and `tx_code` store | Data store |
| E3 | Credential, status-list and metadata signing keys, and their certificate chains | Data store (secret) — **the first leaf private key AXIAM keeps** |
| E4 | Status-list publisher and index allocator | Process + data store |
| E5 | Verifier `request_uri` endpoint and verifier signing key / access certificate | Process + secret |
| E6 | Verifier `response_uri` (`direct_post.jwt`) and ephemeral decryption keys | Process, Internet-facing, receives PII |
| E7 | Trust-anchor store (integrated CA, imported anchors, Trusted List snapshots) | Data store |
| E8 | Outbound status-list fetches (verifier) | Data flow, crosses *AXIAM ↔ third parties* |

**New boundary: Wallet ↔ AXIAM.** A holder-controlled application whose
integrity AXIAM can learn only through wallet and key attestations. What must
hold on every crossing: DPoP-bound access, fresh `c_nonce` in key proofs,
attestation verification where the tenant requires it, `x5c` chains to
configured anchors, single-use transaction artefacts.

### 10.2 Candidate threats (STRIDE)

| Id | STRIDE | Element | Threat | Mitigation in this design |
|---|---|---|---|---|
| V-S1 | S | E1, E2 | **Pre-authorized code replay** — shoulder-surfed or forwarded QR redeemed on the attacker's device (OID4VCI §13.6) | `tx_code` on by default, out of band; single-use; short TTL; offers bound to one user |
| V-S2 | S | E2 | **`tx_code` phishing** — a malicious issuer relays a code from another service (OID4VCI §13.6) | Wallet-side mainly; AXIAM never sends a `tx_code` that could be valid elsewhere: issuance codes have their own prefix and template, and are never reused from OTP/MFA channels |
| V-S3 | S | E2 | **`tx_code` guessing** | Attempt ceiling per code, then burn; rate limit per code and per IP |
| V-S4 | S | E1 | Wallet impersonation (a non-genuine wallet obtains a high-assurance credential) | Wallet attestation client auth when the configuration requires it; key attestation; per-configuration policy |
| V-S5 | S | E6 | **Session fixation / cross-device relay** of a presentation (OID4VP §14.3) | Response code bound to the initiating browser session; cross-device off by default |
| V-S6 | S | E6, login | Authenticating by a non-unique or reassigned claim, or the same claim from a different issuer (OID4VP §14.5) | Link key is `(issuer, claim)`; `LinkedOnly` default |
| V-T1 | T | E6 | Disclosure tampering / digest mismatch | RFC 9901 verification; reject undisclosed duplicates and unknown `_sd_alg` |
| V-T2 | T | E7, E6 | **Forged `x5c` chain** using an end-entity certificate as issuer | `mds/blob.rs` rules generalised (§5.5); anchors never from the header |
| V-T3 | T | E1, E6 | Algorithm confusion in proofs, attestations, KB-JWTs | `jose.rs`: key decides the algorithm |
| V-R1 | R | E1 | Disputed issuance or revocation | Audit events with issuance id, configuration id and actor — no claim values (§11) |
| V-I1 | I | E1 | **Selective-disclosure leakage** — a claim marked `never` SD by misconfiguration is disclosed on every presentation | `sd: always` by default; non-SD only for `iss`, `vct`, `cnf`, `status`, `exp`, `iat`; console warning for any other |
| V-I2 | I | E1, E4 | **Correlation / linkability** across verifiers via issuer signature, holder key, status index, exact timestamps | Batch issuance of single-use credentials; random index; rounded `iat`/`exp` (OID4VCI §15.4.1); DPoP key ≠ holder key; nothing stored that could serve a colluding verifier |
| V-I3 | I | E4 | **Status-list privacy** — the fetch reveals which list (and so which cohort) a verifier checks; small lists reveal individuals | Minimum list size (herd privacy); lists not partitioned by user attribute; long caching; no per-credential URLs |
| V-I4 | I | E6 | Presentation data retained or leaked through the result interface (OID4VP §14.4.3) | Result read once with the response code, then deleted; only the minimised mapped claims are stored |
| V-I5 | I | E1 | Credential offer URLs in logs or mail previews | By-reference offers are single-use; offer URLs redacted in logs as secrets are |
| V-D1 | D | E1, E6 | Nonce, request and response endpoint floods | Rate-limit presets on every new route before merge (plan §7.6) |
| V-D2 | D | E6 | Oversized or deeply nested SD-JWT / disclosures; CBOR bombs (mdoc) | Body ceilings; disclosure count and depth limits |
| V-D3 | D | E8 | Status-list fetch failures or slowloris from an issuer | SSRF guard, timeouts, size cap, cache; login fails closed (§5.4), which bounds the DoS to that issuer's holders |
| V-E1 | E | E3 | **Issuer key compromise** — forged credentials with fresh status indices that look valid | Per-tenant keys; revoke the *certificate* (forged credentials die with the chain); custody as CA keys; short leaf validity; rotation with overlap |
| V-E2 | E | E1 | **Key-proof replay** — a stolen proof used to obtain a duplicate credential (OID4VCI §13.8) | `c_nonce` from the nonce endpoint, single-use; `aud` check |
| V-E3 | E | E6 | **KB-JWT / presentation replay** | `nonce` per request, `aud` = verifier client id, `iat` window, `sd_hash`; request single-use |
| V-E4 | E | E1 | **Cross-tenant issuance** (token from tenant A at tenant B's credential endpoint) | Tenant from the verified token must equal the path tenant; refusal is not a fallback |
| V-E5 | E | E1 | Credential-type escalation (a wallet asks for a configuration the user is not entitled to) | `vc:issue` evaluated by the RBAC engine per configuration resource, deny-override |

---

## 11. GDPR and privacy

- **Art. 5(1)(c) minimisation, issuer side.** A credential contains only the
  claims its configuration maps. Claims drawn from attributes behind a tenant
  GDPR switch (`address`, `phone`; [`basic-op-gap-plan.md`](basic-op-gap-plan.md)
  §4.8) are refused unless the switch is on.
- **Art. 5(1)(c), verifier side.** RPs use reviewed DCQL templates (§7.3), not
  free-form queries. In EUDI the wallet additionally checks the RP's
  registration certificate against what it asks for (ARF v3.0.0 §6.4.2).
- **Art. 25 by default.** The `vc` feature is off; per tenant, issuance and
  verification are off until enabled; every claim is selectively disclosable by
  default; cross-device presentation is off.
- **Unlinkability.** Batch issuance of single-use credentials, random status
  indices, rounded timestamps, distinct DPoP and holder keys (§10, V-I2). The
  issuer stores no signature, disclosure, salt or holder key, following
  OID4VCI §15.4.1: issuers "SHOULD discard values that can be used in collusion
  with a Verifier to track a user".
- **The append-only audit log.** Issuance and presentation events carry ids,
  configuration names and outcomes, never claim values or keys. The existing
  minimisation of IP and user agent (`crates/axiam-core/src/audit_minimisation.rs`)
  applies unchanged.
- **Art. 17 erasure.** A credential already in a wallet is beyond AXIAM's
  reach. Erasure therefore **revokes** every outstanding credential (status bit
  set) and then deletes the `credential_issuance` rows, so the bit can no longer
  be tied to anyone. The data subject is told that copies in their wallet remain
  theirs to delete.
- **Art. 13/14 information.** Configuration display metadata states what the
  credential contains, before issuance, in the wallet's consent screen.
- **Art. 35.** Verifying PID at scale is likely to require a DPIA by the
  deploying organization. The operator guide would say so; AXIAM does not
  perform one on the operator's behalf.

---

## 12. Cost estimate and SDK / contract impact

### 12.1 Estimate

Session units as the plan uses them: S ≤ 1, M 2–3, L 4–6, XL > 6.

| # | Work item | Size |
|---|---|---|
| **Prerequisites** | | |
| P-1 | ES256 keys in `axiam-pki`: `KeyAlgorithm::EcdsaP256`, credential-signing leaf profile, kept-leaf custody, CSR export, external-chain import, `x5c` assembly | M |
| P-2 | Decrypt-only JWE `ECDH-ES` + AES-GCM (VC-D6), with RFC 7518 vectors | M |
| P-3 | Attestation-based client authentication (wallet attestation) as a `ClientAuthMethod` | M |
| **Phase A — verifier** | | |
| A-1 | Trust-anchor store; `x5c` path validation generalised from `mds/blob.rs`; status-list client behind the SSRF guard | M |
| A-2 | SD-JWT VC + KB-JWT verification (RFC 9901; crate or in-tree per §9) | M |
| A-3 | Signed request objects, `request_uri` (POST), `x509_hash`, DCQL templates, `direct_post.jwt` response endpoint, response code, presentation state | L |
| A-4 | OID4VP as a login method: login hop, subject mapping, linking, `amr`/`acr` | M |
| A-5 | Admin API, rate-limit presets, threat-model entries, contract section, OpenAPI | M |
| A-6 | OIDF OID4VP verifier conformance (HAIP) and EUDI reference-wallet interop | M |
| | **Phase A with P-1, P-2: one L, seven M** | **≈ 18–27 sessions (XL)** |
| **Phase B — issuer** | | |
| B-1 | Credential configuration model, repository, admin API, `vc:issue` resources | M |
| B-2 | Issuer metadata (unsigned and signed), nonce endpoint, AS metadata additions | S |
| B-3 | Credential endpoint: DPoP-bound access, proof JWT and key attestation, SD-JWT VC encoding with disclosure policy, batch | L |
| B-4 | Authorization-code wiring: scope → configuration, `issuer_state` | S |
| B-5 | Pre-authorized code grant, credential offers, `tx_code` with attempt ceiling | M |
| B-6 | Token Status List: allocator, bitstring, signed list token, publish route, revocation hooks, erasure | M |
| B-7 | Deferred and notification endpoints | M |
| B-8 | Admin UI, rate limits, threat model, OpenAPI | M |
| B-9 | OIDF OID4VCI issuer conformance (HAIP) and wallet interop | M |
| | **Phase B with P-3: one L, seven M, two S** | **≈ 19–29 sessions (XL)** |
| **Later, each on its own trigger** | | |
| C-1 | ISO mdoc issuance and verification (ISO 18013-5 / -7 Annexes B and D) | XL |
| C-2 | RFC 9396 `authorization_details` | M |
| C-3 | W3C Digital Credentials API (`dc_api.jwt`) | M |
| C-4 | Credential request/response encryption at the issuer | S (after P-2) |
| C-5 | JWS-capable non-exportable custody (Vault Transit or KMS) for credential keys | M |

For scale: the whole of G-2 (SAML IdP) in the plan reuses a 3 500-line SAML
stack; this item reuses the authorization server but starts its format, key and
trust code from nothing. Model assignment when it is scheduled: Opus for P-1,
P-2, P-3, A-1, A-2, A-3, B-3, B-6 (key custody, cryptography, trust decisions);
Sonnet for the rest, where the specifications and the conformance suite pin the
behaviour.

### 12.2 SDK and contract impact

- **Wallet-facing endpoints:** none. They are standard OID4VCI/OID4VP surfaces
  consumed by wallets, not by AXIAM SDKs, and are documented by the
  specifications they implement plus the OpenAPI spec.
- **OID4VP as a login method:** none. The RP receives a normal ID token; the
  only visible difference is an `amr`/`acr` value, which the contract's existing
  claim sections would list.
- **Admin API** (configurations, keys, offers, revocation): OpenAPI only, like
  the rest of the management surface (CONTRACT §27 covers how SDKs consume it).
- **RP-facing presentation API** (`/api/v1/vc/presentations`): **yes, a new
  CONTRACT section**, because RP backends would call it through the SDKs and its
  one-read result semantics are a contract, not a convenience. The number is
  allocated when it is written (§29 is earmarked for the SAML IdP by G-2). SDK
  helpers follow the contract-before-SDK rule and are a separate decision; the
  seven full-surface SDKs would be the first candidates.

---

## 13. Go / no-go criterion

**Go requires both halves. Either alone is no-go.**

### 13.1 Specification stability — all of

1. **SD-JWT VC is published as an RFC.** Today: `-19` published, `-20`
   editor's copy after AD review.
2. **Token Status List is published as an RFC.** Today: `-21`, reported in the
   RFC Editor queue.
3. **HAIP has re-pinned to those RFCs**, through an errata set or HAIP 1.1
   Final. Building against HAIP's `-13`/`-14` pins and then migrating is the
   cost this design exists to avoid.
4. **The ARF's issuer and relying-party chapters have survived two consecutive
   minor releases without a breaking change** to issuer certificates, RP
   registration or the formats in §5.4, measured from v3.0.0.

Already met and recorded so they are not re-litigated: OID4VCI 1.0, OID4VP 1.0
and HAIP 1.0 are Final; SD-JWT is RFC 9901; the OIDF HAIP conformance tests for
issuers and verifiers are open for self-certification (July 2026).

### 13.2 One concrete adopter — at least one of

- **(a)** an organization obliged by eIDAS 2 to accept the EUDI wallet that
  wants AXIAM to be its verifier or login (Phase A);
- **(b)** an organization registered, or registering, as an attestation
  provider that wants AXIAM to issue into EUDI wallets (Phase B);
- **(c)** a closed-ecosystem deployment (enterprise or IoT) that wants
  credentials anchored in the integrated CA (Phase B, closed variant).

"Concrete" means: named, with a use case written down, a credential type or
query identified, and a commitment to test against a real wallet (the EUDI
reference wallet at minimum) during implementation. Interest expressed in a
comparison or a conference conversation does not count.

### 13.3 Partial go

If the adopter is (a), Phase A may start when stability items 1 and 3 hold for
SD-JWT VC alone; the verifier can treat status as "not checked" for credentials
without a `status` claim until item 2 holds, and fail closed for credentials
that carry one. The issuer (Phase B) waits for all four.

### 13.4 Re-evaluation triggers

Re-run this criterion when any of these happens; otherwise at each
comparison refresh (plan W6):

- SD-JWT VC or Token Status List is published as an RFC;
- HAIP publishes an errata set or 1.1 Final;
- an ARF release changes chapters 5 or 6;
- Keycloak promotes OID4VCI or OID4VP to *supported*, or Zitadel or authentik
  ships either (competitive pressure; today Keycloak 26.8 has them preview and
  experimental, [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md));
- 24 December 2026 (Member State wallets) and 24 December 2027 (RP acceptance)
  pass — the second is when adopter (a) is most likely to appear;
- a maintainer receives an adopter request matching §13.2;
- an ETSI W3C-VCDM profile is published (reopens §4.3 only).

---

## 14. Decisions this design asks for (proposed, for the plan's §8 when scheduled)

| # | Question | Recommendation |
|---|---|---|
| VC-D1 | Verifier or issuer first? | **Verifier** (§3) |
| VC-D2 | `authorization_details` in the first cut? | **No**; scope only (HAIP-sufficient). RFC 9396 later (C-2) |
| VC-D3 | Issuer key resolution | **`x5c` only**; no `/.well-known/jwt-vc-issuer` |
| VC-D4 | Credential keys | **Per tenant, ES256, separate from the Ed25519 token key**; status-list key a separate row |
| VC-D5 | Crate | **`axiam-vc`, layer 5, `vc` feature off by default** |
| VC-D6 | JWE | Decrypt-only `ECDH-ES` + AES-GCM from RustCrypto with RFC 7518 vectors, unless a maintained pure-Rust JWE crate exists at go time |
| VC-D7 | mdoc | **Deferred** to an adopter that needs mDL or an mdoc-only scheme |
| VC-D8 | Per-tenant issuer paths | **Required**: `vc` refuses to start without `tenant_issuer_paths` |
| VC-D9 | `amr`/`acr` for wallet login | Decide in A-4 against `acr.rs`; no value invented here |
| VC-D10 | Status on unavailability, AXIAM as verifier for login | **Fail closed** (§5.4) |

---

## 15. What this design does not do

- **It writes no code**, no schema, no route, no contract section and no
  threat-model entry. Those land with the implementation, in the same commits,
  per the plan's §7.
- **No wallet / holder role**, no wallet SDK, no key storage on devices.
- **No PID provider role**, and no qualified (QEAA) status for AXIAM itself.
- **No W3C VCDM, JSON-LD or Data Integrity proofs** (§4.3).
- **No DIDs**: no `did:web`, `did:key`, `did:jwk`, and no
  `decentralized_identifier` client-identifier prefix.
- **No OpenID Federation trust** (`openid_federation` prefix, trust chains). It
  is pinned at draft `-43` by both OpenID specifications and is a separate
  decision.
- **No request objects on the OP side.** [`basic-op-gap-plan.md`](basic-op-gap-plan.md)
  §4.10 stands; §7.1 explains why the verifier role does not touch it.
- **No mdoc proximity presentation** (BLE, NFC) and no ISO 18013-5 reader role.
- **No zero-knowledge or BBS+ credentials**, although the ARF has technical
  specifications for them (TS4, TS13, TS14).
- **No SIOPv2.**
- **No change to the ID-token signing key, its algorithm, or any SDK `alg`
  pin.**
- **No edit to** `roadmap.md`, the plan, the website or the three comparison
  documents; the orchestrator does those.

---

## 16. Verification log

**Verified in this session from source** (shallow clones of the working-group
repositories, 2026-10-02):

- OID4VCI 1.0 editor's draft for errata set 1 (`openid/OpenID4VCI`, `1.0/`,
  revision `-19`): issuer metadata path insertion (§12.2.2), nonce endpoint
  (§7), encryption (§10), pre-authorized code security considerations (§13.6),
  proof replay (§13.8), correlation (§15.4.1), pre-final pins (SD-JWT VC `-11`,
  Status List `-12`, attestation-based client auth `-07`, OpenID Federation `-43`).
- OID4VP 1.0 editor's draft (`openid/OpenID4VP`, `1.0/`, `-31`): client
  identifier prefixes including `x509_hash`, `request_uri_method=post`, session
  fixation (§14.3), `direct_post` protections (§14.4), end-user authentication
  by credential (§14.5), pre-final pins (SD-JWT `-22`, SD-JWT VC `-09`).
- HAIP 1.0 editor's draft (`openid/oid4vc-haip`, `1.0/`, `-09`): every HAIP
  requirement cited above, including the ES256 floor and the `-13`/`-14` pins.
- SD-JWT VC editor's copy (`oauth-wg/oauth-sd-jwt-vc`, history through `-20`):
  `dc+sd-jwt`, the two key-resolution mechanisms, HTTP-directorate changes.
- Token Status List (`oauth-wg/draft-ietf-oauth-status-list`, history through
  `-21`).
- ARF at tag `v3.0.0`: CHANGELOG (2.9.0 dated 2026-05-11; 3.0.0 "Unreleased"
  in the tagged file), §5.4 formats, §6.3.2 access and registration
  certificates, §6.3.2.4 Trusted Lists / LoTE, annex 2 PID dual-format rule.
- `jsonwebtoken` 11.1.0 source: header members and ES256 under `rust_crypto`;
  no JWE.
- crates.io API: every version, date, licence and dependency list in §9;
  `sd-jwt-rs`, `isomdl`, `sd-jwt-payload` repository activity by clone.

**Verified by web search only** (publisher pages blocked by the egress proxy):
OID4VCI 1.0 Final approval (September 2025); OID4VP 1.0 Final vote dates;
HAIP 1.0 Final approval; RFC 9901 publication (November 2025); SD-JWT VC `-19`
as latest published draft; Token Status List `-21` in the RFC Editor queue;
ISO/IEC 18013-7:2025 publication and annex structure; OIDF HAIP conformance
tests opened for self-certification (July 2026); Keycloak OID4VCI status;
eIDAS 2 dates (24 December 2026, 24 December 2027 — secondary sources, the
regulation text was not read).

**Not verified:** the exact publication date of ARF v3.0.0; whether Token
Status List has an RFC number yet; the current revision of
`draft-ietf-oauth-attestation-based-client-auth`; the publication status of the
ISO/IEC 18013-5 second edition; whether `biscuit` implements JWE `ECDH-ES`; the
state of the W3C Digital Credentials API.
