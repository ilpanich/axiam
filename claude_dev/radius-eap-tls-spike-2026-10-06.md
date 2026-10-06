# RADIUS and EAP-TLS — a spike on whether AXIAM should speak RADIUS

**Status: DECISION RECORD — no code.** No crate, schema, route, contract section
or threat-model entry accompanies this document. It is G-11 of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md)
(task T23.11.1, a one-session spike) and exists so that, if the reopen condition
in §1.4 is met, the work starts from argued decisions and a written security
baseline instead of from a protocol reading.

Written 2026-10-06 against `1.0.0-beta17` plus the Phase 23 W5 merge (`406a155`).
Every claim about AXIAM names the file it was read from. Every claim about a
specification, a product or a library says in §9 whether it was **verified in
this session** or only **recalled**; a sentence marked *(recalled)* in the body
is listed there and must be re-read against the RFC before anything is built on
it.

> **Why a record and not a design.** The plan's G-11 asks one question — is a
> RADIUS front end with EAP-TLS over the integrated CA a fit for the
> network-device audience, and what would it cost — and says the outcome is a
> decision. The honest answer turns on three facts the tree supplies (§1.2) and
> one it withholds (§1.3): AXIAM has no certificate-revocation publication of any
> kind today. That last fact changes the cheap option from "a guide" to "a guide
> and a prerequisite", and it is the most useful thing this spike found.

---

## 1. Question and verdict

### 1.1 The question

*Is a RADIUS front end — in particular EAP-TLS validated against AXIAM's
integrated, per-tenant PKI — a fit for AXIAM's network-device audience, what
would it cost, and what must it never do?*

### 1.2 The verdict, in one place

1. **Fit: partial, and unproven.** The part that fits is narrow and real:
   **802.1X port and Wi-Fi access for fleets of machine identities whose
   certificates AXIAM already issues** — IoT and OT devices, gateways, workload
   hosts. There, AXIAM holds the three things a RADIUS server otherwise has to be
   stitched to: the CA (§2.2), a per-authentication revocation answer that is
   real-time inside AXIAM (`DeviceAuthService::authenticate_der`,
   `crates/axiam-pki/src/mtls.rs`), and an authorization engine with
   deny-override that can express "quarantine this subtree". The part that does
   not fit is the rest of what RADIUS is used for: password-based network login
   (PAP-only against an Argon2id store, §4.3), MS-CHAPv2 and CHAP (impossible
   against Argon2id), accounting at fleet volume, and per-vendor attribute
   sprawl. **No adopter has asked.** The only demand signal on file is the
   authentik comparison's observation that authentik ships it
   ([`competitor-comparison-authentik.md`](competitor-comparison-authentik.md)
   gap item 6, citing [A2]).
2. **Recommended decision: decline the native front end (option A) now; record
   the FreeRADIUS-backend route (option B) as the first step when the reopen
   condition is met; do the one prerequisite that stands on its own merits
   regardless — publish revocation for the integrated CA (§8, item D1).**
   Option A is XL (§5.1: about 24–36 sessions) and opens a new authentication
   path and a new trust boundary for an audience nobody has put a name to. Option
   B puts the protocol where the protocol's maintained implementation already is
   and leaves AXIAM as the CA and the policy source.
3. **Cost.** Option A: **XL, about 24–36 sessions**, roughly 70% of them
   Opus 5.5 by plan §6's rule. Option B: **L, about 4–6 sessions** for the
   prerequisite plus the guide and recipe, or **L to XL, about 6–9**, with a
   dedicated authorize endpoint. Option C (this record): **S, done.**
4. **Reopen / trigger condition.** Reopen when **either** (a) a concrete adopter
   — an organisation running AXIAM-issued device certificates that needs 802.1X,
   VPN or network-device login against AXIAM and cannot or will not operate
   FreeRADIUS — names itself, **or** (b) option B has shipped and an adopter
   documents a concrete shortfall (revocation lag, attribute assignment, session
   kill). A standards-track RadSec (§4.5) and a Rust EAP-TLS stack that does not
   have to be written from scratch (§5.1) each lower option A's cost and are
   reasons to look again, not reasons to build.
5. **What was found that is not about RADIUS.** (i) The design document
   (§6.2: "Revoke … propagates to CRL"), the threat model (T-102, *Revocation &
   CRL*) and the website's threat-model data all describe a CRL, and the tree
   contains none — no publication endpoint, no OCSP responder, no CRL in the
   OpenAPI spec (§2.2). (ii) `AuthService::login` refuses a locked account
   *before* the Argon2id work that a wrong password costs, so a locked account is
   distinguishable by timing (§6.2). Both are listed for decision in §8.

### 1.3 What a reader should not conclude

This record does not say RADIUS is a bad idea for AXIAM. It says that the
cheapest honest version of "AXIAM for 802.1X" is **a better CA with a published
revocation answer and a recipe**, and that the expensive version should be paid
for by a named user. If the maintainer prefers to ship option A anyway, §6 and
§7 are the floor it must stand on; they are written to be implementable without
this document's author in the room.

### 1.4 Go criterion for option A

Go requires **all** of:

- a named adopter with an 802.1X, VPN or device-login requirement (§1.2 item 4);
- option B tried, or credibly ruled out, with the shortfall written down;
- the CRL/OCSP prerequisite (§8 D1) shipped, because option A's RadSec and
  EAP-TLS flows are the in-process version of the same revocation question;
- the §6 requirements accepted as the acceptance tests of the first commit, not
  as follow-ups.

---

## 2. Audience, and what AXIAM uniquely brings

### 2.1 Who needs RADIUS, in AXIAM's niche

AXIAM targets "microservices and IoT environments" with strict multi-tenancy and
an integrated PKI for mTLS fleets (`CLAUDE.md`, *Project Overview*). The RADIUS
audiences that intersect that niche:

| Audience | What they do with RADIUS | Credential | Intersects AXIAM's niche? |
|---|---|---|---|
| **802.1X wired and Wi-Fi port access** for devices (IoT, OT, kiosks, gateways, managed laptops) | The switch or access point (the NAS) relays an EAP exchange; the server decides, and on success returns a VLAN or policy and, for Wi-Fi, the session key | EAP-TLS with a client certificate | **Yes** — a device fleet that already holds AXIAM-issued `Device` certificates (`CertificateType::Device`, `crates/axiam-core/src/models/certificate.rs`) |
| **VPN concentrators and remote-access gateways** | Per-user authentication and group-based authorization | Password plus a second factor, or certificate | Partly — certificate yes; password plus OTP needs an Access-Challenge flow (§4.3) |
| **Network-device administration** (CLI login to switches and routers) | Per-administrator login with a privilege level carried as a vendor attribute | Password, often with TACACS+ instead | **Weak** — a vendor-attribute matrix per manufacturer; TACACS+ (not discussed here, *unverified*) is the other protocol operators choose for it |
| **Guest and BYOD onboarding** | Captive-portal and MAC-based flows | Varies | **No** — a portal feature, outside the API-first scope (comparison gap item 7) |

The strong case is the first row. The device is a machine identity with a
certificate, the person responsible for it is a tenant administrator, and the
fleet already speaks to AXIAM over mTLS (`docs/pki/README.md`, *Bind a
certificate for mTLS*).

### 2.2 What they use today, and what AXIAM would add

**Today** the pattern is FreeRADIUS (or a commercial NAC) with a CA behind it:
the RADIUS server trusts a CA bundle, validates the client certificate itself,
checks revocation by CRL file or OCSP, and looks an attribute set up in a local
file, SQL or LDAP. The CA, the device inventory and the policy live in three
places and drift. FreeRADIUS is the incumbent and its configuration is a skill
of its own *(general knowledge; not a cited claim)*.

**What AXIAM already has that a RADIUS server needs**, each read from the tree:

| Need | In the tree | Where |
|---|---|---|
| A per-tenant CA signed by an organisation CA | CA lifecycle, signing CAs below the organisation CA, per-CA key custody (sealed row, Vault KV, Vault PKI); CAs carry `keyCertSign` and `cRLSign` | `crates/axiam-pki/src/ca.rs` (`params.key_usages` at `:968`), `ca_key_store.rs`, `vault_pki.rs` |
| Validating a client certificate to that CA | `DeviceAuthService::authenticate_der`: fingerprint lookup (global), `Active` and validity window, chain verification (SEC-024), issuing CA `Active` and in window (SECHRD-05), chain walk to a CA flagged `mtls_trust_anchor` with a depth bound of 8, then the bound service account | `crates/axiam-pki/src/mtls.rs` |
| **Real-time revocation** | The certificate row's `status` (`Active` / `Revoked` / `Expired`) is read on **every** authentication; a revoked CA anywhere in the chain refuses the leaf | `mtls.rs` (`CertificateStatus`, `require_trust_anchor`); threat model T-102's own mitigation says the same |
| An identity to authorize | A certificate binds to a **service account**; roles, groups and deny-override apply to service accounts | `docs/pki/README.md`; `crates/axiam-authz/src/engine.rs` (`check_access`); [`deny-override-design.md`](deny-override-design.md) |
| Hot-reloadable trust anchors | `ReloadableClientCertVerifier` over `WebPkiClientVerifier` | `crates/axiam-server/src/tls.rs` (`:834`, `:26`) |
| Per-tenant lockout and an unknown-name lockout | `LockoutPolicy`; `UnknownNameLockout` (T-332); SEC-026's equalising dummy Argon2id verify | `crates/axiam-core/src/models/settings.rs:44`; `crates/axiam-auth/src/unknown_name_lockout.rs`; `crates/axiam-auth/src/service.rs:424` |
| Sealed credentials that must be *recoverable* | AES-256-GCM under `pki_encryption_key`, nonce and ciphertext in their own columns, key version, never projected on read; the SCIM target credential and SSF push header are the two live examples | `crates/axiam-db/src/repository/scim_target.rs` (module docs, `seal`), `ssf_stream.rs`; `crates/axiam-core/src/secrets.rs:88` |
| A credential that stays bound to its address | `moves_credential`: a change of `base_url` or `token_url` without the secret in the same write is refused, in the repository, against the row the conditional write replaces | `scim_target.rs:184`, `:444` (P23W5-01, T-409) |
| An audit log, and a gate in front of notifications | `NotifyingAuditLog` with `NotificationGate` | `crates/axiam-audit/src/notification.rs:264`, `:308` |
| Rate-limit presets | `RateLimitProfile` (`internet` / `gateway` / `mesh`) and `MachineLimitPreset` | `crates/axiam-api-rest/src/config/rate_limit.rs:125`, `:170`, `:270` |

**What the tree does not have, and a RADIUS story needs:**

| Gap | Evidence | Consequence |
|---|---|---|
| **No CRL and no OCSP.** `grep -ri "crl\|ocsp"` over `crates/` finds only the `cRLSign` key-usage bit, an unrelated rustls trait parameter, and a comment; `sdks/openapi.json` has zero hits; `CONTRACT.md` has none | `crates/axiam-pki/src/ca.rs:968`; `crates/axiam-pki/src/saml_signing.rs:287` ("No CRL entry is made"); [`design-document.md`](design-document.md) §6.2 says "propagates to CRL"; [`threat-model-stride.md`](threat-model-stride.md) T-102 says "relying parties consuming the CRL" | A relying party **outside AXIAM** (a FreeRADIUS server, a VPN gateway) has **no way to learn a leaf was revoked** except by asking AXIAM per authentication. Option B cannot be a guide alone (§5.2). The model's T-102 text describes something that is not built. |
| **Certificates bind only to service accounts**, not users | D-53 (plan §8): "certificates bind only to service accounts … and an SSF subject is a user, so no source exists"; `docs/pki/README.md` | EAP-TLS for **devices** works with what exists. EAP-TLS for **people's laptops** needs a user-certificate binding that does not exist |
| **The RBAC engine answers allow or deny, with a reason**, nothing else | `AccessDecision::Deny(reason)` in `crates/axiam-authz/src/engine.rs:468` onward | A VLAN, a privilege level or a filter name has no source. A reply-attribute model is new work (§5.1, task A-8) |
| **Passwords are Argon2id with a pepper only** | `crates/axiam-auth/src/password.rs`; no NT hash or reversible form anywhere (`grep -ri "nt_hash\|ntlm\|md4" crates/` is empty) | CHAP, MS-CHAP, MS-CHAPv2 and EAP-MD5 are **unimplementable**, which is the correct state of affairs (§4.3) but cuts out most legacy password-over-RADIUS deployments. Only PAP (inside a TLS-protected channel) can verify against the store |
| **The human login limiter is per-IP and no preset moves it** | `rate_limit.rs:125–131`: `login_per_min` and the other human endpoints "stay at their strict per-IP defaults in every profile" | A RADIUS bridge that calls `/auth/login` from one server address gets **one bucket for the whole fleet** — D-70's NAT'd fleet problem. A RADIUS design needs its own bucket keyed on the **authenticated NAS** (§6.1) |

---

## 3. What competitors ship

| | RADIUS | EAP-TLS | Licence gate | Source |
|---|---|---|---|---|
| **authentik** | Yes — a RADIUS provider | Yes, **enterprise**. The provider supports "EAP-TLS and PAP"; the documentation says only PAP is used for password authentication "due to security considerations regarding password hashing"; custom reply attributes via property mappings since 2024.8; the guide tells operators not to use a globally known CA and to use private PKI | EAP-TLS is listed under the enterprise features' *Authentication and network access*: "RADIUS EAP-TLS authenticates network clients with EAP-TLS and client certificates." PAP and the provider itself are in the MIT core | [A2] outposts; [R1] RADIUS provider; [R2] enterprise features |
| **Keycloak** | **None in the product.** A community extension exists (an embedded RADIUS server as a Keycloak plugin, mapping roles, groups and attributes to RADIUS attributes, with RadSec among its features) | Not in the product | n/a — not a Keycloak feature | plan §2 gap matrix; [R3] (the plugin's own page; maintained by a third party, not assessed here) |
| **Zitadel** | **None**, per the plan's gap matrix | None | n/a | plan §2 gap matrix. A search in this session found no Zitadel RADIUS feature or issue; the absence of a hit is not evidence of absence |
| **AXIAM today** | None | None | Nothing to gate | — |

Two observations.

**authentik confirms the shape of the market, not the size of it.** It ships
PAP and EAP-TLS only — no MS-CHAPv2 — for the reason §2.2 gives AXIAM:
a modern password store cannot verify the legacy challenge-response methods. The
phrase worth reusing is its own: the EAP-TLS guide steers operators to a **private
CA trusted by the end device**, which is exactly AXIAM's integrated CA.

**The enterprise gate is the opening the plan names, and it is a licence
opening, not a technical one.** authentik's EAP-TLS is useful because it ties the
RADIUS server to the identity provider's CA and policy. AXIAM would be shipping
open source what authentik sells. That is a positioning argument for building
option A; it is not evidence that adopters want it, and §1.2 weighs it as such.

---

## 4. Protocol landscape and the security baseline

### 4.1 The documents, and how they fit

| Document | What it is | Verified? |
|---|---|---|
| RFC 2865 | RADIUS: the Access-Request / Accept / Reject / Challenge exchange, the Request and Response Authenticators, `User-Password` hiding, `CHAP-Password` | recalled |
| RFC 2866 | RADIUS Accounting | recalled |
| RFC 2869 | RADIUS Extensions: introduced `Message-Authenticator` (HMAC-MD5 over the packet) | **verified** that RFC 2869 defines it (search, Blast-RADIUS advisories); the rest recalled |
| RFC 3579 | RADIUS Support for EAP: `EAP-Message`, and that `Message-Authenticator` must accompany it | recalled |
| RFC 3748 | EAP itself | recalled |
| RFC 2548 | Microsoft vendor attributes, including `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key`, which carry the session key to the NAS, obfuscated with MD5 and the shared secret | recalled |
| RFC 5216 | EAP-TLS, for TLS up to 1.2: the MSK and EMSK derived by a PRF keyed on the TLS master secret with the label `client EAP encryption` | recalled |
| **RFC 9190** | **EAP-TLS 1.3** — "Using the Extensible Authentication Protocol with TLS 1.3", February 2022, Proposed Standard; **updates** (does not obsolete) RFC 5216; always forward-secret; never discloses the peer identity; **mandates revocation checking**; older TLS versions fall back to RFC 5216 | **verified** (search of the datatracker listing) |
| RFC 9427 | TLS-based EAP types (PEAP, TTLS, FAST …) with TLS 1.3 — the key-derivation definitions for TLS 1.3 use the `EXPORTER_EAP_TLS_Key_Material` label | **verified** that it exists and carries that label; the context byte and lengths are recalled |
| RFC 5705 | TLS keying-material exporters, the mechanism RFC 5216's PRF use is equivalent to when no context value is given | recalled |
| RFC 6614 | **RadSec** — RADIUS over TLS (TCP). Experimental. Fixed shared-secret string for the legacy packet authentication | **verified** as Experimental (search); the fixed-secret string `radsec` is recalled |
| RFC 7360 | RADIUS over DTLS. Experimental | **verified** as Experimental (search) |
| `draft-ietf-radext-radiusdtls-bis` | A standards-track document that **obsoletes RFC 6614 and RFC 7360**; revision 18 is dated September 2026 | **verified** that the draft exists and what it intends (search listing); its final status is unknown to this record |
| **RFC 9765** | **RADIUS/1.1** — "RADIUS/1.1", April 2025: ALPN negotiation inside RADIUS/TLS and RADIUS/DTLS of a profile in which **the shared secret is no longer used, all MD5-based packet authentication and attribute obfuscation are removed, TLS 1.3 or later is required, and `Message-Authenticator` is not sent and is ignored if received** | **verified** (title, date and the four properties, from a search summary of the RFC); Experimental status recalled |
| **CVE-2024-3596** ("Blast-RADIUS") | An on-path attacker can turn any valid response (Accept, Reject, Challenge) into any other by a chosen-prefix collision against the MD5 **Response Authenticator**, in exchanges that do not use `Message-Authenticator`; the mitigation is that the client **include** `Message-Authenticator` and the server **require** it; FreeRADIUS recommends `require_message_authenticator = true` for every client definition | **verified** (vendor advisories and the FreeRADIUS notice, via search) |
| RFC 5176 | Dynamic authorization (CoA, Disconnect) — the server-to-NAS direction | recalled |
| RFC 5080 | Common RADIUS implementation issues, incl. duplicate-request handling | recalled |
| RFC 5280, RFC 6960 | X.509 and CRL profile; OCSP | recalled |

### 4.2 Where the MD5 is — every construct, and how a design treats it

RADIUS is MD5 throughout. A design that ships RADIUS has to say what it does
about each, and "RadSec" is not by itself an answer, because RFC 6614's
RADIUS/TLS still uses the legacy packet authentication with a fixed secret
*(recalled)*. The table below is the baseline.

| MD5-only construct | Where | What goes wrong | Required treatment |
|---|---|---|---|
| **Response Authenticator** | `MD5(Code ‖ ID ‖ Length ‖ Request Authenticator ‖ Attributes ‖ Secret)` on every response (RFC 2865) | The Blast-RADIUS forgery: chosen-prefix collision turns a Reject into an Accept without the secret | UDP: `Message-Authenticator` **required** in every Access-Request and **present** in every response; AXIAM refuses an Access-Request without it, silently, and never answers one. RadSec classic: same. **RADIUS/1.1**: removed by the profile |
| **`Message-Authenticator`** | HMAC-MD5 over the packet keyed by the secret (RFC 2869, 3579) | It is the Blast-RADIUS *mitigation*, and it is MD5-only; it holds as long as the secret is strong and the packet is covered | Required wherever the secret exists (UDP, RadSec classic), position as the vendor guidance asks *(recalled: first attribute; re-verify against RFC 9765 and the advisory before building)*; verified in constant time **before** any state is created or any hash computed (§6.1, §6.3). Under RADIUS/1.1 it is **not sent and ignored on receipt**, so a design must not "require" it there: the rule is "required on every packet of every profile that has a shared secret" |
| **`User-Password` hiding** | MD5 stream XOR keyed by the secret and Request Authenticator | An eavesdropper with the secret, or a weak secret, recovers the password offline | **No PAP over plain UDP, ever.** PAP only over RadSec, preferably RADIUS/1.1 where the hiding is removed and TLS 1.3 carries the confidentiality; or inside EAP-TTLS/PEAP's TLS tunnel (deferred) |
| **`CHAP-Password`** | MD5 challenge-response (RFC 1994, *recalled*) | MD5, and it needs the plaintext or a reversible secret on the server | **Off. Unimplementable** against Argon2id |
| **`MS-MPPE-Send-Key` / `Recv-Key`** (and `Tunnel-Password`) | Salt-encryption with MD5 over the secret and Request Authenticator (RFC 2548, RFC 2868) | These carry the **EAP-TLS MSK**, which becomes the Wi-Fi session key. Passive capture plus a weak secret is a key recovery | Only ever on RadSec; on RADIUS/1.1 the obfuscation is removed and TLS 1.3 protects them. On UDP: allowed only per NAS, flagged `legacy_udp`, with a generated secret of at least 128 bits (§6.4) and documented as the weakest profile |
| **Accounting-Request authenticator** | MD5 over the packet and secret (RFC 2866) | Same class | Accounting is **not implemented** in the first cut (§5.1 scope) |
| **MS-CHAP, MS-CHAPv2** | MD4-derived NT hash and DES | Not MD5, but worse, and it requires the NT hash | **Off. Unimplementable** against Argon2id |
| **EAP-MD5** | An EAP method | MD5 challenge-response, no mutual authentication | **Off.** The EAP method allow-list is `TLS` and nothing else; a peer's NAK to another method is a refusal, not a negotiation (§7 R15) |
| **Fixed `radsec` secret** | RFC 6614's legacy packet authentication over TLS *(recalled)* | The MD5 constructs above are then keyed with a public string and add nothing | Treat TLS as the only protection; prefer RADIUS/1.1 so the question disappears |

**The consequence, stated once.** The strongest profile is **RADIUS/1.1 over TLS
1.3 with mutual certificate authentication** (RFC 9765); the next is classic
RadSec with `Message-Authenticator`; plain UDP is a per-NAS opt-in for equipment
that can do nothing else, and carries every limitation above. A design that makes
UDP the default, or that falls back to it when a TLS profile fails, is the
weakness this section exists to prevent.

### 4.3 Which authentication methods an Argon2id store can serve

| Method | Verifiable against AXIAM's store? | Verdict |
|---|---|---|
| **EAP-TLS** (client certificate) | Yes — no password involved | **The first-class method.** TLS 1.3 by default (RFC 9190); TLS 1.2 per NAS only, because older supplicants need it |
| **PAP** (cleartext password to the server) | Yes, through `AuthService::login` (hash verify) | Only over RadSec / RADIUS/1.1; **never** plain UDP. Subject to MFA (§7 R16) |
| EAP-TTLS/PAP, PEAP/GTC (password inside a TLS tunnel) | Yes | Deferred. A second TLS state machine for the same password path |
| CHAP, MS-CHAP, MS-CHAPv2, EAP-MD5, EAP-MSCHAPv2 | **No** | Off |
| Access-Challenge (OTP, push) | Possible: TOTP via `AuthService` MFA | Deferred. Push approval would go through CIBA's console-only approval (W5 review P23W5-04), never a RADIUS-side approval surface |

### 4.4 EAP-TLS over rustls — what is reachable *(recalled; not compiled in this session)*

This section is a reading, not an experiment: the sandbox's package registry
and `docs.rs` are blocked, and a spike writes no Rust. The first implementation
task (§5.1, A-1) opens with the one-hour experiment that settles it.

- **The TLS stack is already rustls.** The workspace pins `rustls 0.23.45` with
  `tokio-rustls 0.26` and `ring` (`Cargo.lock`, root `Cargo.toml:198–205`); the
  REST and gRPC listeners use it with a reloadable client-certificate verifier
  (`crates/axiam-server/src/tls.rs`). EAP-TLS does not need a socket: rustls is
  sans-IO (`ServerConnection::read_tls` / `write_tls` over a buffer), which is
  the right shape for a TLS handshake that travels in EAP fragments.
- **Key derivation.** rustls exposes `export_keying_material` (an RFC 5705
  exporter) on an established connection, for TLS 1.2 and 1.3. For **TLS 1.3**,
  RFC 9190's MSK and EMSK come from the exporter with the
  `EXPORTER_EAP_TLS_Key_Material` label and an EAP type-code context — directly
  reachable. For **TLS 1.2**, RFC 5216's PRF over the master secret with the
  label `client EAP encryption` and the two randoms equals an RFC 5705 export
  **with no context value** — reachable by the same call, with `None` for the
  context. If either claim fails, the fallback is `dangerous_extract_secrets`,
  which exposes secrets the project would rather not touch; the experiment
  decides.
- **Fragmentation.** EAP-TLS carries a handshake larger than one RADIUS packet's
  attribute budget (a RADIUS packet is capped near 4 096 octets and one
  `EAP-Message` attribute at 253): the server fragments, the supplicant
  reassembles, with flag bits and a length field (RFC 5216 §3.1 *(recalled)*).
  This is the state machine to write and to fuzz; it is also where a memory
  bound belongs (§7 R8).
- **Client-certificate validation.** rustls verifies a chain to a configured
  root set; AXIAM's per-tenant anchor set comes from CAs flagged
  `mtls_trust_anchor`. The in-tree `ReloadableClientCertVerifier` is global, not
  per tenant. A per-NAS (hence per-tenant) verifier is a new construction, and
  **chain verification alone is not tenant isolation**: the organisation CA is
  shared by its tenants, so a leaf from tenant B chains to the same root as
  tenant A's. The tenant check is the equality of the certificate row's
  `tenant_id` (from `DeviceIdentity`) and the NAS's (§6.5).
- **Revocation.** RFC 9190 mandates it. `rustls` can take CRLs in its verifier
  builder *(recalled)*; AXIAM has none to give it (§2.2). The in-process answer
  is better than a CRL: `DeviceAuthService::authenticate_der` reads the row's
  status per authentication.

### 4.5 RadSec's standing

RFC 6614 and RFC 7360 are Experimental; a standards-track successor is in
progress (`draft-ietf-radext-radiusdtls-bis`, revision 18, September 2026) and
RFC 9765 sits on top of them. A build begun today would target the successor's
behaviour, not RFC 6614's, and the **reopen condition names that settling** as a
reason to look again.

---

## 5. Design options

Cost in the roadmap's single-session units: **S ≤ 1, M 2–3, L 4–6, XL > 6**.
Models follow plan §6: **Opus 5.5** when a mistake is a vulnerability, when the
task writes `CONTRACT.md` normative text or a threat entry, or when it makes a
cross-crate design decision nobody has pinned; **Sonnet 5.5** otherwise.

### 5.1 Option A — a native RADIUS / RadSec front end, in a new crate

**Shape.** A new crate, `axiam-radius`, behind a **`radius` Cargo feature that is
off by default** (the shape `axiam-vc` takes in
[`verifiable-credentials-design.md`](verifiable-credentials-design.md) §8, and
for the same reason: a default build carries no new listener, and the website's
claims do not move). It owns a UDP socket, a RadSec TLS listener, the packet
codec, the EAP-TLS state machine, and a NAS registry; it reaches the rest of
AXIAM only through domain services and core ports.

**Where it sits in the layering table.** `scripts/check-crate-layering.py` places
`axiam-api-grpc` and `axiam-api-rest` at layer 6 as the *protocol adapters*, and
`axiam-api-grpc` depends on `axiam-core`, `axiam-authz`, `axiam-auth`, `axiam-db`
and `axiam-amqp` (`crates/axiam-api-grpc/Cargo.toml`). `axiam-radius` is the same
kind of thing: it is called by the network, calls the domain services, and
**nothing depends on it** but the composition root. The recommended placement is **layer 6, beside `axiam-api-grpc`**, with
`axiam-core`, `axiam-auth`, `axiam-authz`, `axiam-pki`, `axiam-audit` and (for the
sealed-secret repository, as the gRPC crate does) `axiam-db` as its inward edges
and no edge to `axiam-api-rest` or `axiam-oauth2`.
Placing it at layer 3 beside `axiam-directory` (the other candidate) would give
the table a protocol *adapter* in the *federation protocol* row, which
[`crate-layering.md`](crate-layering.md) is careful not to do. The commit that
creates the crate adds the row to the `LAYERS` dict and the doc's table, `--graph`
passing, and `[lints] workspace = true` in its own `Cargo.toml` — it opts into
`missing_docs` from its first commit (`CLAUDE.md`, *Documentation lint*). Rate-limit
numbers are **injected by the composition root** from `MachineLimitPreset` as a
plain struct, the way `grpc_authz_per_sec` reaches the gRPC crate; the crate
never imports `axiam-api-rest`.

**Rust ecosystem.** Several crates exist for the packet layer (`radius` / radius-rs,
an async tokio client and server with RFC 2865 and dictionary support and MD5
authentication; `radius-rust`; `radius-server`) — their existence is **verified**;
their EAP coverage is limited to the RFC 4072 attribute dictionary, none
implements an EAP-TLS state machine, and **maintenance, licence and fuzzing
status are unverified**. The prudent plan is a small in-house codec (RFC 2865 §3
is a page of structure) with `cargo-fuzz` targets, after a short evaluation of the
existing crates that is itself a task (A-1). There is **no off-the-shelf EAP-TLS
server in Rust** *(unverified; the absence of a hit in one search)*; the state
machine is written over rustls.

**Mapping a NAS to a tenant.** A registry row per NAS: `{ tenant_id, name,
transport ∈ {radius_1_1, radsec, legacy_udp}, source address (a single address;
a CIDR only with an explicit flag), sealed shared secret, key version, for
RadSec the NAS certificate's SHA-256 pin, min TLS version, allowed EAP methods,
enabled }`. **The address is unique across all tenants** (a unique index on the
normalised address, not on `(tenant, address)`): two NASes behind one address are
an ambiguity between tenants, and ambiguity is refused at write time. The tenant
of a request is the tenant of the **authenticated NAS and nothing the packet
says** — never a realm in `User-Name`, never `Called-Station-Id` (§6.5).

**How EAP-TLS validates the supplicant certificate.** After the handshake,
`DeviceAuthService::authenticate_der(der)` — the function the REST mTLS path
already shares — resolves the certificate to a `DeviceIdentity`; the front end
then requires `identity.tenant_id == nas.tenant_id`, the bound service account
`Active` (`account_may_act`, as every other path), and the issuing chain to a CA
flagged as an anchor. Revocation is the row's status, read now. The handshake's
own verifier may be permissive about *which* chain (so every failure becomes the
same post-handshake outcome, §6.2) and strict in the post-handshake call; the
design keeps the cryptographic chain verification in `authenticate_der`, not in a
second implementation.

**Authorization attributes from RBAC.** The engine returns allow or deny. The
cheapest model that fits: a **network segment is a resource**, a permission
`network:join` (and, for admin login, `network:admin`) is checked with
`check_access(subject = the service account, resource = the segment, action =
"network:join")`, and the **reply profile hangs off the resource**: a validated
set of `Tunnel-Type` / `Tunnel-Medium-Type` / `Tunnel-Private-Group-Id` (the
VLAN assignment pattern of RFC 3580, *recalled*), `Session-Timeout`, and
dictionary-listed vendor attributes. Deny-override gives quarantine for free: a
deny on the quarantine subtree beats every allow. Reply attributes come from an
**allow-list of attribute types**, never free-form (§7 R17). This is new data
model and a cross-crate decision (task A-8).

**What option A is, task by task.**

| # | Task | Size | Model | Why that model |
|---|---|---|---|---|
| A-1 | Experiment and evaluation: rustls `export_keying_material` for TLS 1.3 and 1.2 against `eapol_test` (§4.4), the existing RADIUS crates' licence, maintenance and fuzz status, the one-hour answer to what the plan cannot settle from here | S | Sonnet 5.5 | An experiment with an external oracle |
| A-2 | Contract section (NAS registry API, normative profile behaviour, error vocabulary), the threat entries (§7 becomes real ids), the layering row, the threat-model elements | M | **Opus 5.5** | Normative text and threat entries (rule b); a new trust boundary |
| A-3 | NAS registry: schema, repository with the sealed secret, the address-and-pin binding (§6.4), REST management API with its limiter, audit rows | M | **Opus 5.5** | A new write surface; a mistake is P23W5-01 again |
| A-4 | Packet codec, `Message-Authenticator` verification and generation, duplicate detection, fuzz targets | M | **Opus 5.5** | A parser of unauthenticated network input and the Blast-RADIUS control |
| A-5 | RadSec listener and the RADIUS/1.1 ALPN negotiation, per-NAS certificate pin, no-fallback rule (§6.4) | M | **Opus 5.5** | The trust boundary itself |
| A-6 | EAP-TLS state machine over rustls: fragmentation, state table with caps, MSK/EMSK, `MS-MPPE-*` placement, the TLS 1.2 opt-in | L | **Opus 5.5** | Cryptographic key flow and an attacker-reachable state machine |
| A-7 | Limiters, lockout and the oracle-free answer (§6.1, §6.2): the preset field, the per-NAS bucket, the account-lockout path, the identical-reject tests including timing | M | **Opus 5.5** | The lessons this wave paid for |
| A-8 | Network-segment resources, reply profiles, the `radius`-reply attribute allow-list; RBAC integration | M | **Opus 5.5** | A cross-crate model decision |
| A-9 | PAP over RadSec through `AuthService`, the MFA rule (§7 R16) | S–M | **Opus 5.5** | An authentication path |
| A-10 | Console page for the NAS registry; website docs and the three comparison tables; deployment guide | M | Sonnet 5.5 | Pinned by A-2; a review catches the rest |
| A-11 | End-to-end: `eapol_test` and FreeRADIUS `radclient` as peers in compose (accept, wrong cert, revoked, cross-tenant, no `Message-Authenticator`, wrong secret, moved address) | M | Sonnet 5.5 | An external oracle |
| A-12 | SDK fan-out for the registry management API (per D-35's shape), after the merge | M | Sonnet 5.5 | A port from a merged contract |

**Total: about 24–36 sessions — XL.** Opus tasks are roughly 70% of that (17–27 of the 24–36),
which is the price of a protocol whose every mistake is an authentication bypass.
Accounting, dynamic authorization (CoA / Disconnect), EAP-TTLS and PEAP, Access-
Challenge, proxying and TACACS+ are **not** in that number (§8 lists them as
separate, later items).

**Security.** Highest *surface*, and the surface is the product. In the best
configuration (RADIUS/1.1, TLS 1.3, mutual certificates) it is sound, and it
beats FreeRADIUS-plus-CA in one respect only: revocation, authorization and audit
are one system. **Operational burden.** Highest: a new listener, a new port
(UDP 1812 and TCP 2083 *(recalled)*), a new class of customer equipment, a
conformance matrix across NAS vendors and supplicants that AXIAM does not
control. **Fit.** The first-row audience of §2.1 only.

### 5.2 Option B — AXIAM as the PKI and policy backend behind FreeRADIUS

**Shape.** The operator runs FreeRADIUS. FreeRADIUS terminates RADIUS and EAP-TLS
itself, trusting a CA bundle exported from AXIAM (the organisation CA, or a
tenant signing CA). AXIAM ships what FreeRADIUS needs from it, **and the
implementation of the protocol stays where it is maintained**.

What AXIAM would ship, from smallest:

| Piece | What it is | Why it is there | Size | Model |
|---|---|---|---|---|
| **B-1 (= D1): CRL publication** per issuing CA — `GET` the current CRL (RFC 5280 profile), signed by the CA through its existing custodian, with a `nextUpdate`, `Cache-Control`, the rate-limit preset and an audit row on publication | FreeRADIUS checks revocation by CRL (`check_crl`) or OCSP. **AXIAM publishes neither today (§2.2).** Without B-1 the guide must tell operators the only revocation bound is a short leaf lifetime, which defeats the point | M | **Opus 5.5** (a signing path; contract text; threat entries) |
| **B-2 (= D3): guide, compose recipe and an `eapol_test` end-to-end** — "802.1X with an AXIAM-issued Device certificate": issue and bind, export the CA, a FreeRADIUS config trusting it, TLS 1.3 only, `require_message_authenticator = true` for every client, RadSec or RADIUS/1.1 where the NAS allows, the CRL refresh interval and what it means for revocation lag | The product of B. The recipe pins a FreeRADIUS image and ships the configuration | M | Sonnet 5.5, with the security wording reviewed (the end-to-end is its oracle) |
| **B-3 (= D4): an authorize endpoint** for `rlm_rest` — `POST` a certificate fingerprint and NAS identity, get `{ allow, reply attributes }` from `DeviceAuthService` and `check_access`; the caller is a service account with a dedicated permission, its token bound to its own certificate (`cnf`), a machine-preset limiter keyed on the **authenticated caller**, an audit row per decision | Closes the CRL lag (real-time status), delivers RBAC-derived attributes, and puts the policy in AXIAM. It is also a **new authenticated oracle** for "is this certificate good", hence Opus | M | **Opus 5.5** |

**Where B is thinner than A.** Revocation lag is the CRL's `nextUpdate` unless
B-3 ships; a revoked device keeps its port until its session re-authenticates,
because dynamic authorization is FreeRADIUS's to do, not AXIAM's; the attribute
model lives in FreeRADIUS's configuration unless B-3 ships. **Where B is stronger
than A:** a mature, widely deployed RADIUS and EAP-TLS implementation under the
operator's control, with its own Blast-RADIUS fixes; AXIAM carries no listener,
no new trust boundary at the protocol level, and no conformance matrix. B-3
adds one authenticated REST endpoint — a trust boundary of the ordinary AXIAM
kind (a service-account caller), reviewed the ordinary way.

**What B must not do** (so it does not inherit option A's problems by the back
door): it does **not** bridge passwords. FreeRADIUS calling `/auth/login` for PAP
is a per-IP fleet bucket (§2.2) and a path around the lockout rules; a password
flow through B is option A's A-9 and is out of B's scope.

**Cost.** B-1 + B-2: **L, about 4–6 sessions**. With B-3: **L to XL, about
6–9**. **Security:** the lowest new surface of the three. **Operational
burden:** the operator's, and they already carry it. **Fit:** the first-row
audience, served; the others unchanged.

*Licensing note.* FreeRADIUS is GPLv2 *(recalled)*. A recipe that **references**
an upstream image distributes none of it; a recipe that builds and ships one does.
The guide references.

### 5.3 Option C — decline

Record that AXIAM does not speak RADIUS, why, and what would change the answer
(§1.2). Cost: this document. What it forgoes: the authentik EAP-TLS parity story,
and a certificate-authority story that stops at the HTTP edge. What it does not
forgo: nothing in the roadmap depends on RADIUS.

### 5.4 The three, side by side

| | **A — native** | **B — FreeRADIUS backend** | **C — decline** |
|---|---|---|---|
| **Security** | New authentication path and trust boundary; sound in RADIUS/1.1 + TLS 1.3, hostile surface in legacy UDP | Smallest new surface; FreeRADIUS's protocol security, AXIAM's PKI security; B-3 adds one ordinary authenticated endpoint | None added |
| **Cost** | XL, 24–36 | L 4–6 (B-1, B-2); L to XL, 6–9 with B-3 | S (done) |
| **Opus share** | About 70% | B-1 and B-3 only | None |
| **Operational burden** | AXIAM's: a listener, a port, a vendor conformance matrix | The operator's, already carried | None |
| **Revocation** | Real-time, in-process | CRL interval, or real-time with B-3 | n/a |
| **Authorization attributes** | New model in AXIAM (A-8) | In FreeRADIUS config, or from B-3 | n/a |
| **Password methods** | PAP over TLS only | Operator's choice in FreeRADIUS | n/a |
| **Fit** | The first-row audience, fully | The first-row audience, mostly | None |
| **Gets AXIAM something regardless?** | Yes, B-1 is on its critical path | **Yes — B-1 stands alone** (revocation for every relying party) | Nothing |

### 5.5 Cross-cutting rules (plan §7) — how a future implementation would meet each

| # | Rule | Option A | Option B |
|---|---|---|---|
| 1 | **Contract before SDK** | The NAS registry API is SDK-visible: its `CONTRACT.md` section and the OpenAPI regeneration ship in the same PR as the routes (A-2, A-3); the SDK ports follow from the merge commit (A-12, D-35's shape). The RADIUS wire behaviour is *not* an SDK surface, but its normative profile (which transports, which attributes, which errors never appear) is written into the contract too, because the conformance tests cite it | B-1's CRL endpoint is a contract section and a spec regeneration; B-3 likewise. Nothing in B-2 is SDK-visible |
| 2 | **Threat model in the same commit** | A new trust boundary (*NAS ↔ AXIAM*) and new elements enter `threat-model-stride.md` and `Axiam.json` with the code (§7 is the list); the ids start where the model stands then | B-1 and B-3 add their elements; B-1 also **repairs T-102's description** or builds what it describes |
| 3 | **Layering** | Row added in the commit that creates the crate; layer 6, §5.1; `--graph` clean; `crate-layering.md` records the placement | No new crate |
| 4 | **`missing_docs` from the first commit** | `[lints] workspace = true`, as `axiam-directory` does | n/a |
| 5 | **Features** | `radius` feature, off by default; CI builds with it off and on | n/a |
| 6 | **Safe defaults — every new inbound surface covered by the rate-limit presets before merge** | The listener has **its own** limiter (it is outside the Actix middleware, which is how a surface "forgets" its limiter); `radius_per_min`-class fields in `RateLimitConfig` and `MachineLimitPreset` for all three profiles; a test enumerates the surface (§6.1). The Keycloak 26.7.x lesson, applied from the first commit | The endpoint is a REST route: its limiter lands with it; the CRL `GET` too |
| 7 | **Website and comparisons** | The Operate docs module and the three comparison tables flip with a dated change-log line (A-10) | The guide is linked from the website's PKI page; the authentik row reads "recipe, not native" |

---

## 6. Security requirements a future implementation must meet from its first commit

Written as acceptance criteria: each is a test the first commit carries, not a
follow-up. They bind option A fully and option B where it adds an endpoint (B-1,
B-3) or the recipe's configuration. The W5 security review's §15 gives the five
constraints; each has its subsection, followed by the ones the multi-tenant model
and the rest of the wave add.

### 6.1 The brute-force lockout and the limiters, from the first commit (T-429, the Keycloak 26.7.x class)

**What the lesson was.** A surface that authenticates a credential but forgets to
be covered by the limiters and the lockout. A RADIUS server is exactly that
surface: it is a *second front door* beside the REST login, and it reaches the
same `AuthService`.

**Concretely, the buckets:**

| Bucket | Keyed on | Applies when | Why that key |
|---|---|---|---|
| **Pre-authentication drop** | Source address | Before any state or hash — a coarse, cheap per-address counter on packets that **failed** `Message-Authenticator` or came from an unregistered address | It protects the CPU and memory, spoofable by construction (UDP), so it is **never** a lockout and **never** produces a response |
| **Per authenticated NAS** | The NAS id of a request whose `Message-Authenticator` verified | Every request after verification | The NAS is authenticated by the secret; a request that proves the secret may be limited by the thing it proved. **This is D-70's answer** for a NAT'd fleet: a NAS forwards many users from one source address, so a per-IP bucket alone collapses a site into one bucket (§2.2), and the human login limiter, which no preset moves, is the wrong tool |
| **Per tenant** | The tenant of the NAS | After verification | A ceiling on what one tenant's equipment can draw from a shared deployment |
| **Account lockout** | The **user's own failures** — the tenant's `LockoutPolicy`, through `AuthService::record_failed_login` | PAP failures (a wrong password) | The same counter and policy as the console, not a second one |
| **Unknown name** | `(tenant, name as typed, lower-cased)` via `UnknownNameLockout` | An identity that matches no account | The T-332 rule, so a guess at a never-seen name does not get unlimited attempts |
| **Per (NAS, supplied identity)** | `(NAS id, User-Name or Calling-Station-Id)` | Rate only | Bounds one device or user hammering through one NAS; **a bucket, never a lockout**, because the identity is caller-supplied |

**What is deliberately not a lockout** (D-69): nothing keyed on a caller-supplied
value that anyone can trigger. A NAS, a MAC address (`Calling-Station-Id`), an
EAP identity and a source address are all values an attacker supplies; locking
any of them out is a denial of service against whoever it names. The account
lockout is the one that stays, because it is keyed on the user's own failed
credential verification (the property T-302 already accepts), and **it can be
provoked by anyone who can type a wrong password at a NAS** — bounded by the
tenant policy's backoff and by the per-(NAS, identity) bucket, and stated here so
it is not discovered later. **EAP-TLS has no password to guess**, so there is no
account lockout for it: its failures are rate-limited per NAS and audited, and
never lock a service account (a lockout keyed on a presented fingerprint would be
keyed on an attacker-minted value).

**Sizing is measured, not guessed.** A power-restore storm is the real peak: a
site of several hundred access points re-authenticating within one minute, each
EAP-TLS authentication being several RADIUS round trips. The bucket therefore
counts **authentications started** (an EAP identity response), with a separate,
higher per-NAS packet ceiling, and the preset numbers (a `radius_*` field in
`MachineLimitPreset`, three values for `internet` / `gateway` / `mesh`, human
endpoints untouched) come from a measurement taken in A-7, as the run-3 numbers
did for the others (`rate_limit.rs:107–121`).

**The test that closes the lesson:** a test enumerates the listener's accept
paths (UDP, RadSec, each EAP state) and fails if any reaches `AuthService`, the
certificate path or the registry without passing the limiter. A limiter that
forgets a route fails the build.

### 6.2 No unknown-user oracle (D-63's decoy, translated to RADIUS)

**D-63's rule**: an unknown user, one who may not sign in, or one under lockout
gets a response with the same shape as a known one, and the difference is never
observable at the response. For `bc-authorize` the answer was a decoy request that
simply expires. RADIUS has the same obligation and a simpler mechanism, because
the protocol already has one negative answer: **Access-Reject**.

1. **One answer.** For **unknown, locked, disabled (`Inactive`/`Deleted`),
   wrong-credential, wrong-tenant, revoked-certificate and unbound-certificate**
   alike, the response is an Access-Reject (EAP-Failure inside, for EAP) with **no
   `Reply-Message`, no vendor error attribute and no text**. The reason goes to
   the audit row (internal vocabulary), never to the wire. The same applies to
   `Session-Timeout` and every optional attribute: absent on every reject.
2. **No early exit that distinguishes.** For EAP, the server answers an EAP-
   Identity with the EAP-TLS Start **whatever the identity says**; the identity
   is never looked up before the handshake, so "this name exists" is not
   answerable at that step. After the handshake every failure takes the same
   path to the same message.
3. **Timing.** SEC-026's equalising dummy verify is the baseline for the
   password path (`service.rs:424`). **An observation from this spike: the
   locked-account branch of `AuthService::login` returns at `service.rs:371–373`
   before any Argon2id work**, so a locked account answers faster than a wrong
   password, and a locked account is by definition an existing one. It was read,
   not measured. A RADIUS caller must not inherit it: the RADIUS path runs the
   dummy verify on the locked and disabled branches, and the acceptance test
   asserts a response-time band, not just equal bytes. Whether the REST login
   gets the same fix is §8 item D8.
4. **Byte-identical.** The test compares, for each rejecting condition, the
   decoded packet with only the fields that must differ (Identifier, the two
   authenticators, `Message-Authenticator`) excluded.
5. **Unregistered or unauthenticated sources get nothing.** A packet from an
   address with no NAS row, or whose `Message-Authenticator` fails, is dropped
   silently (RFC 2865 says a server silently discards a request from an unknown
   client *(recalled)*). The absence of an answer is not an oracle when it is the
   same for every such packet; the pre-auth bucket (§6.1) meters it.
6. **No oracle through the registry or the notifications.** The management API
   and any alert do not reveal whether a given address or secret exists beyond
   what the administrator who registered it can already see.

### 6.3 `Message-Authenticator` required, MD5-only attributes treated as the weakness they are (Blast-RADIUS, RFC 9765)

- **Every Access-Request on every profile that has a shared secret carries
  `Message-Authenticator` and every response carries one.** A request without it
  is dropped silently and counted; there is no "optional for non-EAP" path (the
  gap Blast-RADIUS exploited: RFC 2869's rule made it mandatory only with EAP).
  Verified in constant time, **before** any state is created, any registry
  decryption beyond the one needed to verify, any Argon2id verify, any
  certificate lookup.
- **`Proxy-State` is refused** from a request: AXIAM is not a proxy, a NAS does
  not send it, and echoing attacker-chosen attribute bytes into a response is
  the shape of the collision attack *(recalled from the attack's description;
  re-verify against the advisory)*. `Message-Authenticator` goes **first** in the
  response *(recalled; verify)*.
- **Under RADIUS/1.1 (RFC 9765)** the secret and `Message-Authenticator` are
  gone by design: the rule becomes "negotiate the profile with ALPN, require
  TLS 1.3, ignore `Message-Authenticator` if received, and never mix the two
  profiles on one connection". A NAS registered `radius_1_1` that fails to
  negotiate is **refused, not downgraded**.
- **The MD5 table in §4.2 is the checklist**: PAP and `MS-MPPE-*` on UDP only
  under an explicit per-NAS `legacy_udp` flag, with a generated secret; CHAP,
  MS-CHAP(v2), EAP-MD5 off and unimplemented; accounting not implemented.
- **The weakness is stated in the product.** The management API and console mark
  a `legacy_udp` NAS as such, and the audit row for each of its decisions says
  which profile it used.

### 6.4 The per-NAS shared secret — sealed, write-only, bound to its address (P23W5-01's lesson)

**P23W5-01's lesson:** a credential bound to one endpoint but not to **every**
endpoint that receives what it yields is a credential an administrator who never
held it can redirect. The SCIM target's `base_url` moved without the secret, and
the next freshly minted token went to the new host
([`security-review-phase23-w5-2026-10-05.md`](security-review-phase23-w5-2026-10-05.md)
§2).

**The translation.**

1. **Sealed.** The secret is *recoverable* — the server needs it to compute
   `Message-Authenticator` and, on UDP, the MD5 constructs — so it cannot be a
   hash. It is sealed with AES-256-GCM under `pki_encryption_key`, fresh nonce
   per write, nonce and ciphertext in their own columns, a key version, exactly as
   `scim_target.rs` seals its credential (`seal`, `encrypt_separate`). The
   repository is built with the key optional and **refuses any write that sets a
   secret without it** (fail closed, naming the key); the REST handler answers
   `503`, as `scim_targets.rs` does. Plaintext exists only inside the verifier,
   zeroized on drop.
2. **Write-only.** No read projects the ciphertext (`PUBLIC_COLUMNS` pattern); the
   API says `secret_set: true` and the key version, never the value. A secret is
   **generated server-side** (at least 128 bits, rejecting anything else) and
   shown **once** at creation, the way a CA private key is returned once
   (`design-document.md` §6.3); an operator-supplied secret is accepted only if
   it meets the same length and entropy floor.
3. **Bound to the address it was registered for.** The secret authenticates
   *that address*. A write that changes the **source address, the transport, or
   (for RadSec) the NAS certificate pin** requires the new secret in the **same
   write**, refused with `400` naming the field otherwise — `moves_credential`
   for the NAS (`scim_target.rs:184`). The check runs in the **repository against
   the very row its conditional write replaces**, so a racing write cannot slip an
   address past it (T-416). The handler's pre-check mirrors it; the console
   mirrors the handler.
4. **Bound to every endpoint that receives what it yields.** What the secret
   *yields*: it keys the authentication of requests; it keys the obfuscation of
   `MS-MPPE-*` (the session key) and `User-Password`; and — if dynamic
   authorization is ever added — it authenticates AXIAM's *own* messages **to the
   NAS address**, carrying session and user identifiers. Every one of those
   goes to, or comes from, the **registered address**; none to an address taken
   from the packet. **No response is ever sent to an address named in an
   attribute** (`NAS-IP-Address`, `NAS-Identifier`, `Called-Station-Id` are
   audit fields, never routing). The reply goes to the packet's authenticated
   source, which is the registered address, and nowhere else.
5. **For RadSec and RADIUS/1.1 the secret is not the credential; the NAS
   certificate is.** The registry holds the NAS certificate's SHA-256 pin, the
   same binding rule applies to it, and the listener's mutual TLS is verified
   against the tenant's own anchors. The pin and the source address are both
   checked; either alone is not the NAS.
6. **Revocation of a NAS** (disable, delete, rotate) takes effect on the next
   packet or connection: the listener consults the registry row per request
   within a short bounded cache (an `Inactive` NAS must not be served from a
   stale cache; the bound is stated and tested), and an open RadSec connection of
   a disabled NAS is closed.

### 6.5 Multi-tenant isolation: a NAS of tenant A can never authenticate a user of tenant B

- **The tenant is the NAS's, only.** It is fixed when the NAS row is resolved from
  the authenticated source address and secret (or certificate pin). It is never
  read from `User-Name` (a realm), `Called-Station-Id`, `NAS-Identifier`, a
  vendor attribute or the EAP identity.
- **The address is globally unique** across tenants (§5.1); a collision is a
  write-time refusal, so no packet can match two tenants.
- **Every repository call takes the NAS's `tenant_id`.** `AuthService::login`
  takes it already; `DeviceAuthService::authenticate_der` looks a certificate up
  *globally* by fingerprint (`get_by_fingerprint_global`) and returns the
  `DeviceIdentity` with its tenant — the front end compares that to the NAS's and
  **refuses on mismatch**, because the organisation CA is shared by its tenants
  and a chain check alone does not separate them (§4.4).
- **Anchors are per tenant**: the chain the RADIUS front end accepts is the one
  that reaches a CA flagged `mtls_trust_anchor` **for that tenant's NAS**, not the
  deployment-wide set the REST and gRPC listeners use. A test issues a valid
  certificate under tenant B's signing CA and presents it through tenant A's NAS.
- **A NAS registry listing never crosses tenants**; the management API is
  tenant-scoped like every other admin route.

### 6.6 An audit row for every decision

One row per **authenticated** decision (accept and reject), carrying the NAS, the
tenant, the subject when one was resolved, the method (`eap_tls`, `pap`), the
transport profile, the outcome and an **internal** reason; never a password, a
shared secret, an EAP payload, a private key or an MSK. Unauthenticated packets
(wrong `Message-Authenticator`, unknown source) are **aggregated** — a counter per
source per window and one row per window — because a row per forged packet is
attacker-controlled audit volume (the audit-loss lesson of the W5 review's A10).
Rows are append-only like the rest (`CLAUDE.md`, *Security Standards*).
`Calling-Station-Id` (a MAC address) and `User-Name` are personal data: they enter
the personal-data register (`crates/axiam-core/src/personal_data.rs`) and its
erasure paths in the same commit.

### 6.7 `NotificationGate` for any background notification

If a RADIUS event can notify — a NAS presenting a wrong secret from its
registered address, a lockout, a NAS going silent — its audit action maps to a
notification event only **through** a `NotificationGate` (`NotifyingAuditLog`,
`crates/axiam-audit/src/notification.rs:264`, D-73's per-target-per-hour rule
for SCIM). One notification per NAS per hour, claimed in the datastore, never one
per packet; the gate says `false` and logs once when it cannot decide. Every
reject still produces its audit row. A RADIUS reject must never be a notification
amplifier (T-117's reopened lesson, P23W5-13).

### 6.8 No approval surface; a console sign-in only if one is ever added

Option A **ships no approval flow**. Access-Challenge for TOTP is the only
interactive method contemplated, and it is a code the user types, not an
approval. If push approval were ever added it routes through the CIBA approval
routes, **which take a console sign-in only** (P23W5-04, T-447): an access token
AXIAM minted for a client — a RADIUS service account's, a NAS's — must not
approve anything.

### 6.9 Two further rules the design owes

- **MFA is not bypassable by choosing the protocol.** A tenant with
  `mfa_enforced` does not accept a password-only RADIUS login: PAP for such a
  tenant is refused, or runs through an Access-Challenge for the second factor
  (deferred), never password alone. The console's rule is the floor.
- **Downgrade is refused, not negotiated**: EAP methods are an allow-list of
  `TLS`; a NAK to another method is a reject; TLS 1.2 is a per-NAS opt-in and
  the default is 1.3; a RADIUS/1.1 NAS never falls back to the secret-based
  profile.

---

## 7. Risks the threat entries must cover

Prose, for the Opus executor who writes the model's entries. **Threat ids are
assigned in the threat model (T-448 onwards)**; this list carries none and
edits no threat-model file. *Status* reads: **Mitigated by design** — the §6
requirement closes it if the thing is built; **Open** — a residual or a decision
that nothing in the design closes, or a finding about what exists today. Because
nothing ships under the recommendation, the entries for option A are *design
entries*: they enter the model with the code, per plan rule 2, and until then
the status column is the status they would have.

New trust boundary: **NAS ↔ AXIAM** (and, for option B, **FreeRADIUS ↔ AXIAM's
authorize endpoint**, an ordinary authenticated REST boundary). New elements:
the RADIUS listener (UDP, RadSec), the EAP-TLS state machine, the NAS registry.

| # | STRIDE | Element / boundary | What goes wrong | Mitigation the design requires | Status |
|---|---|---|---|---|---|
| R1 | Spoofing | NAS ↔ AXIAM, UDP | A host forges a registered NAS's source address and a guessed or leaked secret; requests are accepted as that NAS | `Message-Authenticator` verified with the per-NAS secret before anything else; generated secrets of at least 128 bits; RadSec / RADIUS/1.1 preferred, with the NAS certificate pin; UDP only per NAS under `legacy_udp` (§6.3, §6.4) | Mitigated by design; the weak-secret residual on UDP is accepted and documented |
| R2 | Tampering | NAS ↔ AXIAM, UDP responses | **Blast-RADIUS (CVE-2024-3596)**: an on-path attacker rewrites a Reject into an Accept via an MD5 chosen-prefix collision in a response lacking `Message-Authenticator` | Required in every request and response; `Proxy-State` refused; first position; RADIUS/1.1 removes the construct; a NAS that cannot send it is refused, not served (§6.3) | Mitigated by design |
| R3 | Information disclosure | `MS-MPPE-*`, `User-Password` on UDP | A passive on-path attacker with the shared secret (weak, leaked, or the public `radsec` string) recovers the MSK (the Wi-Fi session key) or a password from the MD5 obfuscation | EAP-TLS and PAP only over RadSec / RADIUS/1.1; UDP carries them only under `legacy_udp`, flagged in the API, console and audit | **Open** — inherent in the legacy profile; accepted only by an explicit per-NAS flag |
| R4 | Information disclosure | Access-Reject path | An unknown, locked, disabled or wrong-credential user is distinguishable by content, by message, by silence, or by timing — a user-enumeration oracle (D-63) | One Access-Reject, no text on the wire, the EAP-TLS Start regardless of identity, equalising dummy verify on every branch, byte-identical and timing-band tests (§6.2) | Mitigated by design |
| R5 | Denial of service | Account lockout via a NAS | Anyone who can type a wrong password at a NAS provokes the lockout of a named user | Tenant `LockoutPolicy` backoff; a per-(NAS, identity) bucket; no lockout on a caller-supplied value (D-69); EAP-TLS never locks an account (§6.1) | Mitigated by design; the provocation residual is the one T-302 already accepts for the console |
| R6 | Denial of service | The listener (outside the Actix middleware) | The surface authenticates but is covered by none of the limiters — the Keycloak 26.7.x class | Its own limiter, preset fields in all three profiles, per authenticated NAS and per tenant, a test enumerating the accept paths (§6.1; plan rule 6) | Mitigated by design |
| R7 | Denial of service | UDP flood and Argon2id exhaustion | Unauthenticated packets reach the hash path; a PAP flood saturates the Argon2id semaphore (`CQ-B02` backpressure) and starves the console login | `Message-Authenticator` before any hash or state; pre-auth source-address bucket; per-NAS and per-tenant buckets; the shared hash permit is not RADIUS's to monopolise (a per-surface sub-limit) | Mitigated by design |
| R8 | Denial of service | EAP-TLS state table and reassembly | A registered but compromised NAS, or a flood of conversation starts, exhausts memory in the conversation table or in a fragment reassembly buffer | A cap on in-flight conversations per NAS and per tenant, a TTL, a cap on reassembled TLS-record size, a cap on rounds, a cap on certificate-chain size; `State` is a server-generated random value bound to the NAS (§4.4) | Mitigated by design |
| R9 | Elevation of privilege | Tenant boundary, EAP-TLS | A NAS of tenant A authenticates a device of tenant B because the organisation CA is shared and the chain verifies | Tenant equality of the certificate row and the NAS after `authenticate_der`; per-tenant anchors; a cross-tenant test (§6.5) | Mitigated by design |
| R10 | Elevation of privilege | Tenant boundary, PAP | The tenant is chosen by a caller-supplied value: a realm in `User-Name`, `Called-Station-Id`, a vendor attribute | The tenant is the authenticated NAS's, only (§6.5) | Mitigated by design |
| R11 | Information disclosure | NAS registry at rest | A database dump plus the process's `pki_encryption_key` yields every NAS secret (they must be recoverable, so they cannot be hashed) | AES-256-GCM under `pki_encryption_key`, key version, no read projection, zeroize; the same class and posture as webhook secrets, SSF push headers, SCIM credentials and CA keys | Mitigated by design; the shared-key residual is the existing one |
| R12 | Spoofing / Information disclosure | NAS registry write path (P23W5-01's class) | An administrator moves a NAS's address, transport or RadSec pin without the secret, redirecting what the secret yields (an Accept's session key, later AXIAM-to-NAS messages) to a host they control | A move requires the secret in the same write, enforced in the repository against the row the conditional write replaces; replies only to the registered address (§6.4) | Mitigated by design |
| R13 | Repudiation | Audit of RADIUS decisions | A decision unaudited, audited without the NAS or subject, or an unauthenticated flood writing unbounded rows | One row per authenticated decision, aggregation for unauthenticated packets, no secrets or payloads in rows, the audit-durability posture of the W5 review (§6.6) | Mitigated by design |
| R14 | Information disclosure | Personal data in audit and registry | MAC addresses and user names enter the audit log and escape the erasure paths | Entered in the personal-data register with erasure paths in the same commit (§6.6) | Mitigated by design |
| R15 | Tampering | EAP / TLS / ALPN negotiation | A downgrade: EAP-MD5 or another method accepted on a NAK, TLS 1.2 where 1.3 was configured, RADIUS/1.1 falling back to the secret profile | EAP allow-list `TLS`; per-NAS minimum TLS version; no fallback from RADIUS/1.1 (§6.9) | Mitigated by design |
| R16 | Elevation of privilege | PAP vs the console's MFA | A password-only RADIUS login on a tenant that enforces MFA: the weaker path wins | MFA parity: refuse PAP for `mfa_enforced` tenants, or challenge for the second factor (§6.9) | Mitigated by design |
| R17 | Elevation of privilege | Reply attributes from RBAC | A reply profile, writable by a broad administrator, assigns a VLAN or privilege level outside what the writer may grant; a free-form attribute becomes a vendor-specific escalation | Attribute-type allow-list; values validated against the dictionary; profile writes behind their own permission and audit row; deny-override for quarantine; a profile cannot grant more than its writer holds | Mitigated by design |
| R18 | Elevation of privilege | Approval surfaces | An access token AXIAM minted for a RADIUS service account or a client approves something | **No approval surface in the first cut**; any later push approval is CIBA's console-sign-in-only (P23W5-04) | Mitigated by design (by absence) |
| R19 | Denial of service | Notification rules | A reject or a failed-secret event notifies once per packet: the flood that buries the real alert (T-117, D-73) | Notifications only through a `NotificationGate`, one per NAS per hour, a rejected packet is audited and never mailed (§6.7) | Mitigated by design |
| R20 | Tampering | Duplicate requests | A replayed or retransmitted Access-Request produces a second decision, a second lockout increment, a second EAP step | Duplicate detection by (NAS, Identifier, Request Authenticator) with a short cache returning the identical cached answer (RFC 5080 *(recalled)*) | Mitigated by design |
| R21 | Elevation of privilege | Revocation and live sessions | A revoked certificate or disabled account keeps its port until the session re-authenticates, because AXIAM cannot kill a session (no CoA / Disconnect) | `Session-Timeout` capped per tenant; the bound stated in the product; dynamic authorization as a separate, later item that inherits R12 | **Open** — a residual until dynamic authorization ships |
| R22 | Elevation of privilege | Option B: a revocation channel that does not exist | FreeRADIUS trusts the AXIAM CA and has no way to learn of a revocation: a revoked device authenticates for the life of its certificate. The design document and T-102 describe a CRL the tree does not contain | B-1 publishes the CRL; until then the guide says the bound is the leaf lifetime. **T-102's text needs repair or the CRL needs building** | **Open** — a finding about what exists today |
| R23 | Spoofing | Option B: the authorize endpoint | A new authenticated oracle for "is this certificate good in this tenant", callable by whoever holds the caller credential | A dedicated permission; the caller's token bound to its own certificate (`cnf`); a limiter keyed on the authenticated caller; a response that carries no reason on a deny | Mitigated by design |
| R24 | Information disclosure | Observation, **not a RADIUS threat** | `AuthService::login` returns for a locked account before the Argon2id work, so a locked, hence existing, account answers faster than a wrong password (`service.rs:371–373`; read, not measured) | Equalise the branch with the dummy verify (§8 D8); a RADIUS caller must not inherit it | **Open** — pre-existing; for the model's author to place against T-302 / SEC-026 |
| R25 | Tampering | Supply chain | An unmaintained or unreviewed RADIUS crate or a GPL image enters the build | A task (A-1) evaluates licence and maintenance; the recipe references an upstream image and ships none | Mitigated by design |

---

## 8. What is deferred

If the maintainer accepts the recommendation (§1.2), these are the items an issue
would track. **D1 stands on its own merits whatever happens to RADIUS** and is
the one this record recommends doing regardless.

| # | Item | Size | Model | Notes |
|---|---|---|---|---|
| **D1** | **Publish revocation for the integrated CA**: a CRL per issuing CA (RFC 5280 profile) signed through the CA's custodian, `nextUpdate` and `Cache-Control`, a rate-limit preset, an audit row, a contract section, threat entries, and a decision whether to add an OCSP responder (RFC 6960) later | M | **Opus 5.5** | A signing path and normative text. Fixes the mismatch between `design-document.md` §6.2 / T-102 and the tree. Useful to every relying party that cannot call AXIAM per request |
| **D2** | OCSP responder | M–L | **Opus 5.5** | Only if a relying party needs it; many FreeRADIUS deployments are content with a CRL |
| **D3** | FreeRADIUS integration guide, compose recipe (referencing an upstream image) and an `eapol_test` end-to-end: issue, bind, accept, wrong CA, revoked after CRL refresh | M | Sonnet 5.5 | After D1. Oracle: the end-to-end. A review reads the security wording against §4.2 |
| **D4** | Authorize endpoint for `rlm_rest` (§5.2 B-3) | M | **Opus 5.5** | Only after D3 shows the CRL interval or the attribute model inadequate |
| **D5** | Reply-profile data model and the network-segment resource pattern, as a design note, not code | S | **Opus 5.5** | The cross-crate decision A-8 and B-3 both need; written only when one of them is scheduled |
| **D6** | User-certificate binding (certificates bound to users, not only service accounts) | M | **Opus 5.5** | Needed for EAP-TLS on people's laptops; also unblocks the SSF `x509` source D-53 records as having none. Its own item, with its own reason to exist |
| **D7** | Repair the description of T-102 and §6.2 of the design document if D1 is *not* scheduled, so the documents stop describing a CRL that does not exist | S | **Opus 5.5** (threat entry) | The alternative to D1; one of the two is owed |
| **D8** | Equalise the locked-account branch of `AuthService::login` with the dummy Argon2id verify, with a timing test | S | **Opus 5.5** | An authentication path; found, not built, here (§6.2). Separate from RADIUS |
| **D9** | Comparison refresh: authentik gap item 6 and the matrix row G-11 read "decided 2026-10-06: decline native, FreeRADIUS backend when asked" | S | Sonnet 5.5 | Part of the W6 comparison refresh already planned |
| **D10** | **If option A is ever reopened:** the task table of §5.1 (A-1 … A-12) becomes the issue list; then, separately, dynamic authorization (RFC 5176, inherits R12), accounting (RFC 2866), EAP-TTLS / PEAP, Access-Challenge for OTP | XL | mixed, §5.1 | Not scheduled |

---

## 9. Sources, and what was and was not verified

### 9.1 Sources

**In this repository** (every claim about AXIAM above names its file).

- [`CLAUDE.md`](../CLAUDE.md); [`crate-layering.md`](crate-layering.md);
  `scripts/check-crate-layering.py`
- [`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md)
  — G-11, §2, §6, §7, §8 (D-53, D-63, D-69, D-70, D-73)
- [`security-review-phase23-w5-2026-10-05.md`](security-review-phase23-w5-2026-10-05.md)
  — §2 (P23W5-01), §15 (G-11 constraints)
- [`competitor-comparison-authentik.md`](competitor-comparison-authentik.md),
  [`-keycloak.md`](competitor-comparison-keycloak.md),
  [`-zitadel.md`](competitor-comparison-zitadel.md)
- [`deny-override-design.md`](deny-override-design.md),
  [`verifiable-credentials-design.md`](verifiable-credentials-design.md) (form,
  and the off-by-default feature-flagged crate precedent)
- [`threat-model-stride.md`](threat-model-stride.md) (T-102, T-117, T-302, T-332,
  T-409, T-416, T-418, T-429, T-447); [`design-document.md`](design-document.md) §6.2, §6.3
- `crates/axiam-pki/src/{mtls,ca,cert,ca_key_store,vault_pki,saml_signing}.rs`;
  `crates/axiam-server/src/tls.rs`;
  `crates/axiam-auth/src/{service,unknown_name_lockout,lockout}.rs`;
  `crates/axiam-api-rest/src/config/rate_limit.rs`;
  `crates/axiam-db/src/repository/{scim_target,ssf_stream}.rs`;
  `crates/axiam-api-rest/src/handlers/scim_targets.rs`;
  `crates/axiam-audit/src/notification.rs`; `crates/axiam-core/src/{secrets,personal_data}.rs`,
  `models/{certificate,settings,service_account}.rs`;
  `crates/axiam-authz/src/engine.rs`; `docs/pki/README.md`

**External.**

- **[A2]** authentik, Outposts — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/outposts/index.mdx> (reused from the authentik comparison)
- **[R1]** authentik, RADIUS provider — <https://github.com/goauthentik/authentik/blob/main/website/docs/add-secure-apps/providers/radius/index.mdx>
- **[R2]** authentik, Enterprise features — <https://github.com/goauthentik/authentik/blob/main/website/docs/enterprise/enterprise-features.mdx>
- **[R3]** Keycloak RADIUS plugin (community) — <https://github.com/elkman/keycloak-radius-plugin>
- **[R4]** RFC 9765, *RADIUS/1.1*, April 2025 — <https://www.rfc-editor.org/rfc/rfc9765.html>
- **[R5]** RFC 9190, *EAP-TLS 1.3* — <https://datatracker.ietf.org/doc/rfc9190/>
- **[R6]** RFC 9427, *TLS-Based EAP Types for Use with TLS 1.3* — <https://www.rfc-editor.org/rfc/rfc9427.html>
- **[R7]** RFC 6614 and RFC 7360 (Experimental) and the draft that obsoletes them — <https://datatracker.ietf.org/doc/html/draft-ietf-radext-radiusdtls-bis>
- **[R8]** Blast-RADIUS, CVE-2024-3596 — <https://blastradius.fail/>; FreeRADIUS's notice — <https://freeradius.org/security/>; the Cisco ISE advisory — <https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222287-blast-radius-cve-2024-3596-protocol-sp.pdf>
- **[R9]** Rust RADIUS crates — <https://github.com/moznion/radius-rs>, <https://lib.rs/crates/radius>, <https://docs.rs/radius-rust>, <https://docs.rs/crate/radius-server/0.2.0/source/src/handler.rs>

### 9.2 Verification log

**Verified in this session** (a fetch or a search returned it): the authentik RADIUS
provider's EAP-TLS-is-enterprise, PAP-only-for-passwords and attribute-mapping
statements (fetched [R1], [R2]); RFC 9765's title, date, ALPN mechanism and its
four properties (search summary); RFC 9190's title, date, status, "updates RFC 5216"
and the revocation-checking mandate (search); RFC 9427's existence and the
`EXPORTER_EAP_TLS_Key_Material` label (search); RFC 6614 and RFC 7360 as
Experimental and the successor draft's existence, intent and revision 18 dated
September 2026 (search); the Blast-RADIUS mechanism, the `Message-Authenticator`
mitigation and FreeRADIUS's `require_message_authenticator` recommendation (search
of vendor advisories); that RFC 2869 defines `Message-Authenticator` (same); the
Keycloak community RADIUS plugin and its features (search); the existence of the
Rust RADIUS crates (search).

**Not verified — recalled.** The `rfc-editor.org`, `datatracker.ietf.org`,
`ietf.org`, `docs.rs`, `crates.io` and `blastradius.fail` hosts were refused by the
sandbox's egress proxy, so no RFC text was read. The following are from memory and
**must be re-read against the RFC before anything is built on them**:

1. RFC 2865, 2866, 3579, 3748, 2548, 2868, 5216, 5705, 5176, 5080, 3580, 1994,
   5280, 6960 — that each says what §4.1 attributes to it (the numbers themselves
   are not in doubt; the section-level claims are).
2. RFC 6614's fixed shared-secret string `radsec` and that the legacy packet
   authentication survives in RADIUS/TLS.
3. The TLS 1.3 exporter context value and output lengths for the MSK and EMSK
   (RFC 9190), and the TLS 1.2 equivalence of RFC 5216's PRF to an RFC 5705 export
   with no context.
4. That `rustls::ConnectionCommon::export_keying_material` accepts those labels on
   both TLS versions, and that its verifier builder takes CRLs.
5. That the `Message-Authenticator` should be the **first** attribute in a
   response, and that a request carrying `Proxy-State` should be refused by a
   non-proxy server (§6.3).
6. That a RADIUS server silently discards a request from an unknown client
   (RFC 2865), the default ports (1812/UDP, 2083/TCP), and the minimum secret
   length guidance.
7. The licence of FreeRADIUS (GPLv2).
8. RFC 9765's and RFC 9190's final **status** words (Experimental; Proposed
   Standard) beyond what the search results said.
9. That no Rust EAP-TLS server exists and the maintenance, licence and fuzzing
   state of the three RADIUS crates.
10. That Zitadel has no RADIUS provider: the plan's gap matrix says so; this
    session's search found nothing either way.
11. That TACACS+ is the alternative network-administration protocol operators
    choose (named once, §2.1).

**Read from the tree and not run:** `grep -ri "crl\|ocsp"` over `crates/`,
`sdks/openapi.json`, `docs/` and `sdks/CONTRACT.md` (no CRL publication, no OCSP
anywhere); the `AuthService::login` branch order (read at `service.rs:340–425`,
not timed).
