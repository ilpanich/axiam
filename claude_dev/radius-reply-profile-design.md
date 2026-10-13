# RADIUS reply profiles and the network-segment resource pattern (D5)

**Status: DESIGN NOTE — nothing is built.** No crate, schema, route, permission,
contract section or setting accompanies this document, and **no threat entry
changes status in W6.1**: T-448 … T-468 stay *Not applicable*
([`threat-model-stride.md`](threat-model-stride.md) §5.10). Statuses move in W6.2,
with the `eapol_test` end-to-end as the test for the entries the recipe's
configuration mitigates, or later, with the code that builds an element.

Written 2026-10-13 on `claude/release-1.0.1-w6` (cut from the plan branch at
`55c3e3072`). It is deferred item **D5** of the RADIUS spike
([`radius-eap-tls-spike-2026-10-06.md`](radius-eap-tls-spike-2026-10-06.md) §8),
task W6.1 of [`release-1.0.1-plan.md`](release-1.0.1-plan.md) §7, under maintainer
decision **D-2 = yes**: W6 ships D3 (guide, recipe, end-to-end) and D5 (this
note) in 1.0.1; **D4, the `rlm_rest` authorize endpoint, does not**, and #563
stays open with D4 as its remaining item.

It answers the spike's R17 / **T-461** ("a reply profile assigns a VLAN or
privilege level its writer could not grant") with a data model concrete enough
that D4, an export, or option A's A-8 can build on it without reopening the
decision. Every claim about AXIAM names the file it was read from. Every claim
about a specification, a product or a library says where it was read, or that it
was not.

---

## 1. The eleven recalled claims, re-read (2026-10-13)

The spike's §9.2 lists eleven claims it could only recall, because its sandbox
could not fetch RFC text. #563 asks that they be re-read before anything is
built. This session re-read what it could reach.

**What this session could and could not reach.** `www.rfc-editor.org`,
`datatracker.ietf.org`, `www.ietf.org`, `tools.ietf.org`, `docs.rs`,
`blastradius.fail` and the RFC mirrors `ftp.ripe.net`, `ftp.nic.ad.jp`,
`mirror.ircam.fr`, `ftp.kaist.ac.kr` were all refused (`curl`: `CONNECT tunnel
failed, response 403`; the fetch tool: DNS failure); `github.com`, `api.github.com`
and the `crates.io` API answered `403`. Three hosts answered:

- `raw.githubusercontent.com` — notably the **FreeRADIUS repository's
  `doc/rfc/` directory**, which carries copies of the RADIUS RFCs (the
  repository's `COPYRIGHT` §2.1 attributes that directory's files to the
  Internet Society). A claim marked *confirmed* against one of these copies was
  read in **RFC text**, but in a copy, not at the RFC Editor; the copies' headers
  (number, category, date) match the RFCs they name. Base URL below:
  `FR/doc/rfc/` = <https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/master/doc/rfc/>.
- `static.crates.io` and `index.crates.io` — crate tarballs (source, `Cargo.toml`)
  and the sparse index (latest versions).
- Web search (summaries, not text). A claim supported **only** by a search
  summary is marked *not verifiable from this session*, with the summary noted;
  it is not marked confirmed.

**Verdicts:** **Confirmed** — read in the source, quoted, URL given.
**Corrected** — the source says something different; what it says is quoted.
**Not verifiable** — no source reachable from this session; says which.

| # | Recalled claim (spike §9.2) | Verdict | What the source says, and where |
|---|---|---|---|
| 1a | RFC 2865: the Access-Request / Accept / Reject / Challenge exchange, the Response Authenticator, `User-Password` hiding, `CHAP-Password` | **Confirmed** | `FR/doc/rfc/rfc2865.txt`, *Category: Standards Track*. §4.1–§4.4 define the four packets. §3: "ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)". §5.2: "On transmission, the password is hidden … A one-way MD5 hash is calculated over a stream of octets consisting of the shared secret followed by the Request Authenticator." §5.3 defines `CHAP-Password`. |
| 1b | RFC 2866: RADIUS Accounting, MD5 authenticator | **Confirmed** | `FR/doc/rfc/rfc2866.txt`, *Category: Informational*: "This memo documents the RADIUS Accounting protocol"; §3 the Request Authenticator is "a one-way MD5 hash calculated over … the shared secret". |
| 1c | RFC 2869 defines `Message-Authenticator` (HMAC-MD5) | **Confirmed** (already verified by the spike; re-read) | `FR/doc/rfc/rfc2869.txt` §5.14, *Category: Informational*: "an HMAC-MD5 checksum of the entire Access-Request packet"; "It MAY be used in any Access-Request. It MUST be used in any Access-Request, Access-Accept, Access-Reject or Access-Challenge that includes an EAP-Message attribute." — the optionality Blast-RADIUS exploited. |
| 1d | RFC 3579: `EAP-Message`, and `Message-Authenticator` must accompany it | **Confirmed** | `FR/doc/rfc/rfc3579.txt`, *Category: Informational*. §3.1 `EAP-Message`; §3.2: "the Message-Authenticator attribute MUST be used to protect all Access-Request, Access-Challenge, Access-Accept, and Access-Reject packets containing an EAP-Message attribute." |
| 1e | RFC 3748 is EAP | **Confirmed** | `FR/doc/rfc/rfc3748.txt`, *Category: Standards Track*, "Extensible Authentication Protocol (EAP)". |
| 1f | RFC 2548: `MS-MPPE-Send-Key` / `Recv-Key` carry the session key, obfuscated with MD5 and the shared secret | **Confirmed** | `FR/doc/rfc/rfc2548.txt`, *Category: Informational*. §2.4.2 "contains a session key for use by the Microsoft Point-to-Point Encryption Protocol"; the construction is "b(1) = MD5(S + R + A) c(1) = p(1) xor b(1)" with S the secret, R the Request Authenticator, A the salt; §2.4.3 `Recv-Key` likewise. |
| 1g | RFC 2868: `Tunnel-Password` is salt-encrypted the same way; the tunnel attributes | **Confirmed** | `FR/doc/rfc/rfc2868.txt`, *Category: Informational*. §3.5 `Tunnel-Password`, "b(1) = MD5(S + R + A)"; §3.1 `Tunnel-Type`, §3.2 `Tunnel-Medium-Type` ("6 802 (includes all 802 media plus Ethernet "canonical format")"), §3.6 `Tunnel-Private-Group-ID`. |
| 1h | RFC 3580: the VLAN-assignment pattern | **Confirmed, and sharpened** | `FR/doc/rfc/rfc3580.txt` §3.31, *Category: Informational*: "Tunnel-Type=VLAN (13) / Tunnel-Medium-Type=802 / Tunnel-Private-Group-ID=VLANID"; "the VLANID is 12-bits, taking a value between 1 and 4094, inclusive … the VLANID integer value is encoded as a string"; "where it is only desired to specify the VLANID, the tag field SHOULD be set to zero (0x00) in all tunnel attributes." §3.17: with `Termination-Action` = RADIUS-Request, `Session-Timeout` "specifies the maximum number of seconds of service provided prior to re-authentication", and "a Session-Timeout value of zero indicates the desire to perform another authentication … immediately". The string encoding, the tag and the zero case all bind §3 below. |
| 1i | RFC 5176: dynamic authorization (CoA, Disconnect) | **Confirmed** | `FR/doc/rfc/rfc5176.txt`, *Category: Informational*, "Dynamic Authorization Extensions to RADIUS": `CoA-Request`, `Disconnect-Request`. |
| 1j | RFC 5080: duplicate-request handling | **Confirmed; the spike's cache key corrected** | `FR/doc/rfc/rfc5080.txt` §2.2.2, *Category: Standards Track*: "RADIUS servers MUST therefore implement duplicate detection … MUST also cache the Responses … it MUST resend its original Response without reprocessing the request"; entries purged after "no less than 5 seconds, and no more than 30 seconds"; the match is on "source address, source port, RADIUS Identifier, and receiving socket", and a **differing Request Authenticator purges** the entry rather than forming the key; "Packets with invalid Message-Authenticators MUST NOT affect the cache in any way." The spike's R20 / T-453 key "(NAS, Identifier, Request Authenticator)" should read so (§10). |
| 1k | RFC 5216, RFC 5705, RFC 1994, RFC 5280, RFC 6960 — the section-level claims | **Not verifiable from this session** | None is in `FR/doc/rfc/` (each fetch `404`), and every RFC host was refused. |
| 2 | RFC 6614's fixed secret `radsec`, and that the legacy packet authentication survives in RADIUS/TLS | **Confirmed** | `FR/doc/rfc/rfc6614.txt`, *Category: Experimental*, §2.3 item 4: "The shared secret to compute the (obsolete) MD5 integrity checks and attribute encryption MUST be "radsec"". |
| 3 | RFC 9190's TLS 1.3 exporter context and lengths for MSK / EMSK; RFC 5216's PRF equal to an RFC 5705 export with no context | **Not verifiable from this session** (RFC 9190, 5216 and 5705 unreachable) | A search summary of RFC 9427 (not RFC 9190) gave `Key_Material = TLS-Exporter("EXPORTER_EAP_TLS_Key_Material", Type, 128)`, MSK = octets 0–63, EMSK = 64–127, and itself flagged that it did not confirm RFC 9190's context for plain EAP-TLS. **Half of the TLS 1.2 side is confirmed in code**: rustls 0.23.45's TLS 1.2 exporter (`src/tls12/mod.rs`, `export_keying_material`) computes `PRF(master_secret, label, client_random ‖ server_random)` and appends a length-prefixed context only when one is given — so `None` yields exactly the RFC 5216 shape **if** RFC 5216 says what the spike recalls. Option A only; nothing in this note depends on it. |
| 4 | That rustls's `export_keying_material` accepts those labels on both TLS versions, and that its verifier builder takes CRLs | **Confirmed** | rustls 0.23.45 source (<https://static.crates.io/crates/rustls/rustls-0.23.45.crate>, the version `Cargo.lock` pins): `impl<Data> ConnectionCommon<Data>` (`src/conn.rs:460`) has `export_keying_material(output, label: &[u8], context: Option<&[u8]>)`, an arbitrary label, documented "See RFC5705 for more details", failing "if called prior to the handshake completing"; the TLS 1.2 path is `src/tls12/mod.rs:242`. `ClientCertVerifierBuilder::with_crls` (`src/webpki/client_verifier.rs:99`): by default every certificate in the chain has its revocation checked, and an undeterminable status "will be treated as an error". Option A only. |
| 5a | That `Message-Authenticator` should be the **first** attribute in a response | **Not verifiable normatively; confirmed as the reference implementation's practice** | No position rule in RFC 2869 §5.14 or RFC 3579 §3.2 (read). FreeRADIUS 3.2.x `src/lib/radius.c` (<https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/v3.2.x/src/lib/radius.c>): "Always add Message-Authenticator for replies to Access-Request packets, and for all Access-Accept, Access-Reject, Access-Challenge. It must be the FIRST attribute in the packet." The normative text (RFC 9765, or the Blast-RADIUS guidance) was not reachable. |
| 5b | That a non-proxy server should **refuse** a request carrying `Proxy-State` | **Corrected** | RFC 2865 §5.33 (`FR/doc/rfc/rfc2865.txt`): `Proxy-State` "MUST be returned unmodified in the Access-Accept, Access-Reject or Access-Challenge". FreeRADIUS's Blast-RADIUS control does not refuse it either: `limit_proxy_state = yes` means "Allow Access-Request packets without Message-Authenticator, but only when they do not contain Proxy-State. Packets which contain Proxy-State MUST also contain Message-Authenticator, otherwise they are discarded", it is ignored when `require_message_authenticator = yes`, and the same text warns that "some aggregators (e.g. Wireless LAN Controllers) may act as a RADIUS proxy … and in such cases will provide a Proxy-State attribute" (`raddb/radiusd.conf.in`, v3.2.x). So with `Message-Authenticator` required — which the spike requires anyway — refusing `Proxy-State` adds no Blast-RADIUS protection and breaks aggregating controllers. It concerns option A and T-449's text, not this note (§10). |
| 6 | RFC 2865: silent discard of a request from an unknown client; the default ports (1812/UDP, 2083/TCP); the minimum secret length | **Confirmed** | RFC 2865 §2: "A request from a client for which the RADIUS server does not have a shared secret MUST be silently discarded." §3: "The officially assigned port number for RADIUS is 1812." §3: "It is preferred that the secret be at least 16 octets … The secret MUST NOT be empty". RFC 6614 §2.1: "The default destination port number for RADIUS over TLS is TCP/2083." (AXIAM's 128-bit floor in spike §6.4 is the RFC's 16 octets.) |
| 7 | FreeRADIUS is GPLv2 | **Confirmed, with a refinement** | `LICENSE` on `master` and `v3.2.x`: "GNU GENERAL PUBLIC LICENSE Version 2, June 1991". `COPYRIGHT` (v3.2.x) §3.1: everything "except the files in src/lib directory is the GNU GPL version 2"; §2.2.1: "The license for all files in the src/lib directory is the GNU LGPL version 2". The recipe references an upstream image and vendors nothing, so neither licence reaches AXIAM's tree (T-454). |
| 8 | The final status words of RFC 9765 (Experimental) and RFC 9190 (Proposed Standard) | **Not verifiable from this session** | Neither RFC is in `FR/doc/rfc/`; the hosts were refused. A search summary described RFC 9765 as "not an Internet Standards Track specification; it is published for examination, experimental implementation, and evaluation" — the Experimental boilerplate — and as updating RFCs 2865, 2866, 5176, 6613, 6614 and 7360. Search only. Read in text this session: RFC 6614 and RFC 6613 *Experimental*; RFC 2865, 3748, 5080, 6929 *Standards Track*; RFC 2548, 2866, 2868, 2869, 3579, 3580, 5176 *Informational*. |
| 9 | No Rust EAP-TLS server exists; the maintenance, licence and fuzzing state of the three RADIUS crates | **Licences confirmed; the rest not verifiable** | From the tarballs at `static.crates.io` and the latest versions in `index.crates.io`: `radius` **0.4.0**, `license = "MIT"`, `moznion/radius-rs`, ships `src/core/rfc4072.rs` (EAP attribute dictionary) and no EAP method; `radius-rust` **0.4.4**, `MIT`, `MikhailMS/rust-radius`; `radius-server` **0.2.3**, `MIT OR Apache-2.0`, `SetliteWeb/radius-server`. Release dates and fuzzing: the `crates.io` API and GitHub refused, and a packaged tarball without `fuzz/` proves nothing. "No Rust EAP-TLS server" is a negative and stays unverified. Option A only. |
| 10 | Zitadel has no RADIUS provider | **Not verifiable from this session** (a negative) | Zitadel's `README.md` (<https://raw.githubusercontent.com/zitadel/zitadel/main/README.md>) lists "SSO, MFA, Passkeys, OIDC, SAML, SCIM", LDAP as an identity provider and device authorization, and no RADIUS. Consistent with the claim; a feature list is not proof of absence. |
| 11 | TACACS+ is the alternative network-administration protocol operators choose | **Not verifiable from this session** | RFC 8907 was unreachable. Corroboration only: FreeRADIUS `master` implements TACACS+ (`src/protocols/tacacs/tacacs.h`, citing "3.4. The TACACS+ Packet Header"). Which protocol operators choose is a market claim no source settles. |

**What the re-read changes.** For this note: §3's dictionary uses the RFC
3580 encoding as read (decimal string, tag 0, VLAN 1–4094) and its Session-Timeout
floor follows from the §3.17 zero case. For the record and the model: the duplicate
cache key (1j) and the `Proxy-State` rule (5b) are corrected, and §10 hands both to
the review. Everything that stays unverifiable (1k, 3, 8, 9, 10, 11) concerns
option A's key derivation and the competitive narrative, and nothing in option B
rests on it.

---

## 2. What exists today, and what this note may assume

Read from the tree on 2026-10-13:

- **Resources** are a tenant-scoped tree with a free-form `resource_type: String`
  and an optional `parent_id` (`crates/axiam-core/src/models/resource.rs`). The
  generic routes check `resources:create` / `resources:update` / `resources:delete`
  tenant-wide, on `Uuid::nil()` (`crates/axiam-api-rest/src/handlers/resources.rs`).
  No `resource_type` is reserved.
- **Permissions** are tenant-scoped `action` strings; a fixed catalogue is seeded
  from `PERMISSION_REGISTRY` (`crates/axiam-api-rest/src/permissions.rs`), and
  tenants may create their own (`permissions:create`).
- **Deny-override** is the engine's precedence ([`deny-override-design.md`](deny-override-design.md)):
  an applicable deny beats every allow at any depth, a child allow does not undo an
  inherited deny (§2.2 row 4), and `inherit: false` on an assignment stops it at
  its node — which on a **deny** can widen access (§2.1, row 10).
- **Role assignment carries no delegation bound.** `assign_to_user`,
  `assign_to_service_account` and `assign_to_group` check `roles:assign` on
  `Uuid::nil()` and nothing about what the role grants or what the assigner holds
  (`crates/axiam-api-rest/src/handlers/roles.rs:554ff`, `:699ff`, `:915ff`); X1's
  `grant.pre_assign` veto hook runs first (`crates/axiam-api-rest/src/reactor_hooks.rs:194`).
  Any `roles:assign` holder can assign any role. §5.3 matters because of this.
- **Device certificates bind to service accounts**: `DeviceIdentity { service_account_id,
  tenant_id, org_id, certificate_id }` (`crates/axiam-core/src/models/certificate.rs:886`).
  Certificates bound to users are item D6 and do not exist.
  **Binding is a write with its own permission and no network check.**
  `POST /api/v1/service-accounts/{sa_id}/bind-certificate` checks `certificates:bind`
  on `Uuid::nil()` and that the certificate and the account share the tenant, and
  writes the `cert_bound_to` edge (`crates/axiam-api-rest/src/handlers/certificates.rs:527`);
  issuance checks `certificates:generate` on `Uuid::nil()` (`:168`, `:292`) and
  binds nothing. Placement (§4.3) is decided for the account a certificate is bound
  to, so this edge is half of what places a device. §5.3 bounds it
  (correction of 2026-10-13, see there).
- **Tenant signing CAs exist** (`CaCertificate::tenant_id`,
  `crates/axiam-core/src/models/certificate.rs:190ff`); the organization CA is shared
  by the organization's tenants.
- **CRLs are published** (#565, model 2.38.0; `crates/axiam-api-rest/src/handlers/crl.rs`):
  `nextUpdate` one day after `thisUpdate` by default
  (`AXIAM__PKI__CRL_NEXT_UPDATE_SECS`); [`docs/pki/README.md`](../docs/pki/README.md)
  §"Certificate revocation lists" tells a FreeRADIUS operator how to consume them.
- **Organization-level subjects** carry only *global* grants into a tenant
  (`SubjectScope::Organization`, `crates/axiam-authz/src/types.rs:120ff`).

Option B (spike §5.2): **FreeRADIUS terminates RADIUS and EAP-TLS**; AXIAM is the
PKI and, with D4, the policy backend. In 1.0.1 AXIAM ships no RADIUS-facing route
at all. This note designs the policy model that D4 (or the export of §6.2, or
option A's A-8) would serve.

---

## 3. The reply-profile data model

### 3.1 What a profile is

A **reply profile** is the set of RADIUS attributes AXIAM would put in an
Access-Accept for a device placed on one **network segment** (§4). It is
**owned by that segment** (one profile per segment, at most), not by a device,
a role or a NAS. It is policy, not identity: it names no person, no device and no
MAC address (§8).

It is a **typed record, not an attribute list.** There is no field in which a
writer names an attribute type. Every attribute a profile can produce is a named,
typed, bounded field, and the dictionary of §3.2 is the closed set of fields. A
vendor attribute, an unknown attribute number or a free-form string attribute
cannot be expressed, so it cannot be validated wrongly.

**The VLAN is not a profile field.** The three tunnel attributes are derived from
the owning segment's `vlan_id`. A profile cannot name a VLAN, so the only way to
put a device on VLAN 99 is to write the profile of the segment that owns VLAN 99,
which takes permissions on *that* segment (§5.2). This is the structural answer to
"a VLAN outside what the writer may grant".

### 3.2 The dictionary: `axiam-radius-reply/1`

The dictionary is **named and versioned**. Every profile records the version it
was validated against (`dictionary: "axiam-radius-reply/1"`). It is a compile-time
table in `axiam-core` (layer 0, no dependencies), each entry citing its RFC
section. The D3 end-to-end, or the first commit that builds this, checks the
numbers and data types against FreeRADIUS's own dictionary files (`share/dictionary.rfc2865`,
`.rfc2868` on `v3.2.x`, fetched this session; their lines are quoted below). A
dictionary change is a code change with review. No API adds an entry.

| Attribute | # | FreeRADIUS dictionary line | RFC | Source in AXIAM | Allowed values |
|---|---|---|---|---|---|
| `Tunnel-Type` | 64 | `ATTRIBUTE Tunnel-Type 64 integer has_tag` | 2868 §3.1; 3580 §3.31 | derived from the segment | exactly `VLAN` (13), tag `0x00` |
| `Tunnel-Medium-Type` | 65 | `ATTRIBUTE Tunnel-Medium-Type 65 integer has_tag` | 2868 §3.2; 3580 §3.31 | derived | exactly `802` (6), tag `0x00` |
| `Tunnel-Private-Group-Id` | 81 | `ATTRIBUTE Tunnel-Private-Group-Id 81 string has_tag` | 2868 §3.6; 3580 §3.31 | derived from `segment.vlan_id` | decimal `1`–`4094`, no sign, no leading zero, tag `0x00` |
| `Session-Timeout` | 27 | `ATTRIBUTE Session-Timeout 27 integer` | 2865 §5.27; 3580 §3.17 | profile field `session_timeout_secs` | `300` ≤ v ≤ the tenant cap (§3.4); never `0` |
| `Termination-Action` | 29 | `ATTRIBUTE Termination-Action 29 integer` | 2865 §5.29; 3580 §3.17 | profile field `termination_action` | `RADIUS-Request` (1, the default) or `Default` (0) |
| `Idle-Timeout` | 28 | `ATTRIBUTE Idle-Timeout 28 integer` | 2865 §5.28 | profile field `idle_timeout_secs` | `60` ≤ v ≤ `session_timeout_secs` |
| `Filter-Id` | 11 | `ATTRIBUTE Filter-Id 11 string` | 2865 §5.11 | profile field `filter_id` | one of the owning segment's declared `filter_ids`; each matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` |
| `Service-Type` | 6 | `ATTRIBUTE Service-Type 6 integer` | 2865 §5.6 | profile field `service_type` | **option B:** `Framed-User` (2) or absent. `Administrative-User` (6) and `NAS-Prompt-User` (7) are in the table flagged `admin_class`, **disabled for option B** (§3.3) |

Every attribute in this table is allowed in an Access-Accept by RFC 2865's §5.44
table (Service-Type `0-1`, Filter-Id `0+`, Session-Timeout / Idle-Timeout /
Termination-Action `0-1`) or RFC 2868's (Tunnel-Private-Group-ID `0+`), read in
the copies of §1.

### 3.3 What the dictionary excludes, and why

| Excluded | Why |
|---|---|
| **`Vendor-Specific` (26), every VSA** — `Cisco-AVPair`, `Aruba-User-Role`, `Filter-Id`-like vendor ACLs, vendor privilege levels | The escalation path T-461 names: a vendor attribute's meaning is the NAS's, unbounded and unknowable to AXIAM. A vendor attribute enters only as a specific `(vendor-id, type)` row added to the dictionary in a reviewed commit, with a value type and bound of its own. **None in `/1`.** |
| `Service-Type` admin values (6, 7) | They grant **administrative login to the NAS**, which is a password flow in practice. Option B does not bridge passwords (spike §5.2, "What B must not do"), so under option B the admin class has no legitimate consumer. It stays in the table so that option A's A-9 inherits the rule in §5.2 (H4) and does not invent one. |
| `Reply-Message` (18) | Text on the wire. Spike §6.2 forbids it on rejects. On accepts, a writer-chosen string reaches the supplicant's UI and its logs, and nothing needs it. |
| `Class` (25) | Echoed by the NAS into accounting. If it is ever emitted, it is an AXIAM-generated opaque correlation value per decision, decided by D4, and never writer-set. |
| `Tunnel-Password` (69), `MS-MPPE-*` (VSAs) | MD5 salt-encrypted secrets (RFC 2868 §3.5, RFC 2548 §2.4.2, read in §1), T-450. The MPPE keys are the EAP method's (FreeRADIUS's) to emit, never policy. |
| `Message-Authenticator` (80), `EAP-Message` (79), `State` (24), `Proxy-State` (33) | Protocol-owned. FreeRADIUS sets them. A profile that could write one would be a protocol-forgery primitive. |
| `Framed-IP-Address`, `Framed-Pool` and the address attributes; `Egress-VLANID` (RFC 4675) | Out of scope for `/1`. Address assignment is not an identity decision, and RFC 4675 was not read in this session. A later version may add them by the same reviewed-commit rule. |

### 3.4 Validation

- **Typed and closed.** The wire and storage form deserialises with
  `deny_unknown_fields`. An unknown key is a `400` naming it, never ignored. A
  dictionary version the server does not know is a `400`.
- **Bounded.** The bounds in §3.2 are checked at write time. The tenant cap is a
  new tenant setting, `network.session_timeout_max_secs` (default **3600**,
  settable from **300** to **86400**). It is the per-tenant `Session-Timeout`
  cap that T-462 requires. With `Termination-Action = RADIUS-Request`, it is the
  bound on how long a quarantine or a revocation waits for the device to
  re-authenticate (RFC 3580 §3.17, §1). The floor of 300 refuses RFC 3580's
  "zero = re-authenticate immediately" case, a re-authentication loop, and keeps
  a fleet's re-authentication rate inside the power-restore budget of spike §6.1.
- **Re-validated on every read that produces a reply.** The decision path (D4)
  and the export (§6.2) re-check each profile against its dictionary version and
  the *current* tenant cap. A value above the cap is clamped down, which only
  narrows. A row that fails validation, for example one edited in the datastore
  behind the API, makes its segment **not a candidate** (fail closed) and writes
  one audit row per profile per window. It is never rendered.
- **Never rendered as text by concatenation.** Every rendering (rlm_rest JSON,
  an export fragment) is produced from the typed fields by an encoder that
  accepts only dictionary values. Since §3.2 admits only integers, enumerations,
  a decimal VLAN and identifiers matching a fixed pattern, there is no quoting
  problem to get wrong.

### 3.5 Storage shape (when built)

Two tables, both tenant-scoped, added by an additive migration
(`DEFINE … IF NOT EXISTS`, plan §9):

```
network_segment            -- sidecar of a `resource` row whose resource_type is reserved (§4.1)
  tenant_id, resource_id (unique), kind ∈ {access, quarantine},
  site_key, vlan_id (1–4094; unique per (tenant_id, site_key)),
  filter_ids: [string] (≤ 32, pattern of §3.2), rank (unique per (tenant_id, site_key) among kind=access),
  enabled, version, created_by, updated_by, created_at, updated_at

reply_profile
  tenant_id, segment_id (unique), dictionary ("axiam-radius-reply/1"),
  session_timeout_secs, termination_action, idle_timeout_secs?, filter_id?, service_type?,
  version, created_by, updated_by, created_at, updated_at
```

There is no secret, no ciphertext and no personal data in either. Both are
written conditionally on the `version` read (plan §9's two-writer rule). A profile
write is also conditional on the owning segment's `version`, so a concurrent
segment change (its `filter_ids`, `kind` or `vlan_id`) cannot slip a profile past
an envelope that no longer holds. The T-416 lesson: the check runs against the row
the write replaces.

---

## 4. The network-segment resource pattern

### 4.1 A reserved subtree of the resource tree

Segments are **resources**, so that RBAC, the hierarchy cascade and deny-override
apply to them unchanged. They live in a reserved subtree with reserved
`resource_type`s:

```
/network                        network_root      (one per tenant, created on first use)
├── /network/zones              network_branch    (reserved name)
│   └── /network/zones/hq       network_site      site_key = "hq"
│       ├── …/hq/corp           network_segment   kind=access, vlan 10, rank 10
│       └── …/hq/iot            network_segment   kind=access, vlan 20, rank 20
└── /network/quarantine         network_branch    (reserved name)
    └── /network/quarantine/hq  network_site      site_key = "hq"
        └── …/hq/q              network_segment   kind=quarantine, vlan 999
```

- **The generic resource routes refuse the reserved types.** `resources:create`,
  `resources:update` and `resources:delete` answer `400` for a row of type
  `network_*`, for a `parent_id` that names one, and for a type change into or out
  of the set. A broad `resources:*` administrator can therefore not create a
  segment, move one out from under a deny, or delete the quarantine branch.
  Moving a resource is the one way to change access under deny-override without
  changing a rule, so moves within `/network` go only through the network routes,
  under `network:segments_write` on the old and the new parent.
- **Quarantine is a sibling branch, never a descendant of `zones`.** Deny-override
  cannot express "deny the subtree except this leaf"
  ([`deny-override-design.md`](deny-override-design.md) §2.1, §6). A quarantine
  segment under `zones` would be denied by the very rule that quarantines. The
  fixed two-branch shape makes the correct placement the only placement.
- **A site is a key, not a location.** VLAN numbers are per-site facts (VLAN 20 at
  HQ is not VLAN 20 at a branch office), so `vlan_id` is unique per
  `(tenant, site_key)`. A single-site tenant has one site, `default`.

### 4.2 Permissions

All of them are new, seeded, and in a **reserved `network:` namespace**:
`permissions:create` refuses an action starting `network:` (`400`), so a tenant
cannot mint a look-alike.

| Permission | Held by | Checked on | Meaning |
|---|---|---|---|
| `network:join` | the device's **service account** | a segment (cascades from site and branch) | may be placed on this segment |
| `network:admin` | — | — | admin login to the segment's NAS devices. **Defined, not grantable under option B** (§3.3) |
| `network:read` | administrators | `/network` or below | read segments and profiles |
| `network:segments_write` | network administrators | the parent (create), the node (update/delete), both parents (move) | the tree and each segment's envelope: `kind`, `vlan_id`, `filter_ids`, `rank`, `enabled` |
| `network:profiles_write` | network administrators | the segment | create, replace, delete its reply profile — **the profile's own permission** (R17) |
| `network:grant` | network administrators | the node an assignment names | confer `network:join` there: write a profile, or assign or unassign a role carrying a `network:*` grant (§5.3) |
| `network:grant_admin` | — | — | confer the admin class. Option A only |
| `network:decide` | the FreeRADIUS caller's service account (D4) | a site | ask for decisions for that site (§6.3) |
| `network:export` | the export's caller (§6.2, if built) | a site | read the rendered export for that site |

Roles carrying any `network:` grant are **network-sensitive**. Three write-time
rules apply to them, each a `400`:

1. Not `is_global`. A global role is "everywhere by definition" (deny-override
   §2.2), which defeats segment scoping. Global grants are also what an
   organization-level subject carries into a tenant (§2), so a global network role
   would cross tenants.
2. Never assigned to a **group**. Group membership is written by `groups:add_member`,
   by SCIM and by directory sync, and every one of those would become a network
   grant. Devices are service accounts and are assigned directly. A group that
   already holds a role also refuses having a `network:` permission granted to that
   role. This closes the hole for the first cut. D6, which binds certificates to
   users, reopens the question with the user and group paths in hand.
3. A role whose grants include a `network:` **deny** may not be assigned with
   `inherit: false`. On a deny that flag makes the quarantine of row 10 silently
   reach nothing (deny-override §2.1).

### 4.3 How a profile is chosen

A decision is asked for a subject (the service account the presented certificate
is bound to) in a tenant (§7) and a site. Two writes therefore decide where a
device lands: the role assignment that gives the account `network:join`, and the
certificate binding that makes the device that account (§5.3 bounds both):

1. The subject is `Active` (`account_may_act`) and, with D4, the certificate's row
   is valid now (`DeviceAuthService::authenticate_der`, tenant-equal, spike §6.5).
2. **Candidates** are the enabled segments under `/network/*/<site>` for which
   `check_access(subject, "network:join", segment)` is **Allow** and whose profile
   passes §3.4 re-validation.
3. **No candidate means Access-Reject.** No reason goes on the wire (T-457, T-468).
   No fallback segment exists: "authenticated but unplaced" is a reject, not a
   default VLAN.
4. Among `kind = access` candidates, the **lowest `rank`** wins. `rank` is unique
   per `(tenant, site_key)`, so the choice is deterministic and decided at write
   time, not by query order.
5. A `kind = quarantine` candidate is used **only when no `kind = access`
   candidate remains**. Deny-override makes that the case for a quarantined device
   (§4.4), so quarantine needs no precedence rule of its own.
6. The reply is the segment's tunnel triple (§3.2) plus the profile's fields,
   rendered by the encoder of §3.4.

The engine is unchanged. It still answers allow or deny for one
`(subject, action, resource)`. Selection is a loop over a site's segments
(`check_access_batch` exists, `crates/axiam-authz/src/engine.rs:687`) and needs no
new precedence semantics.

### 4.4 Quarantine by deny-override

A quarantine role `network-quarantined` carries `network:join` with `effect: "deny"`,
assigned to the device at `/network/zones` (inheritable). A baseline role
`network-quarantine-baseline` carries an allow `network:join` at
`/network/quarantine/<site>`, assigned at enrolment.

| # | Device's assignments | Check on `/network/zones/hq/iot` | Check on `/network/quarantine/hq/q` | Placed on |
|---|---|---|---|---|
| Q1 | allow at `zones/hq/iot`; baseline | **allow** | **allow** | `iot` (an access candidate exists, step 5) |
| Q2 | Q1 + deny at `/network/zones` | **deny** (`denied_by_rule`, row 3) | **allow** | `q` |
| Q3 | Q2 + a new allow at `zones/hq/corp` by another administrator | **deny** on `corp` too (row 4: a child allow does not undo an inherited deny) | **allow** | `q`. **Adding allows cannot release a quarantine** |
| Q4 | deny at `/network/zones`, no baseline | **deny** | `no_grant` | **Reject** (step 3) |
| Q5 | deny at `/network` (the root) | **deny** | **deny** (row 3) | **Reject**. The deny at the root is the "off the network" switch, and the shape of §4.1 makes it distinct from quarantine |

**Release** is the removal of the deny assignment. That widens access, so it takes
`network:grant` at the node (§5.3) and writes its audit row. The property
deny-override buys (deny-override §2.1, "adding a deny rule can never widen
access, and can never be undone by adding allows") is exactly the property a
quarantine needs: no administrator who can grant `network:join` somewhere in
`zones` can release a device by granting more.

When it takes effect: in the authorization engine, on the next decision after the
assignment's cache invalidation (the existing hooks). On the wire, at the device's
next re-authentication, bounded by `Session-Timeout` (§3.4; T-462) under D4, and
additionally by the export interval under §6.2.

---

## 5. The write path

### 5.1 Routes, limiter, conditional write (when built)

The segment and profile writes are ordinary tenant-scoped management routes, `/api/v1/network/…`.
The tenant comes from the token, as for every admin route. **From their first
commit**, each write route has its own bucket under one `network_admin_per_min`
setting, wired as `scim-targets` wires `scim_target_admin_per_min`
(`crates/axiam-api-rest/src/server.rs:1680ff`; plan §9's limiter rule). Reads are
not separately limited. Each write is conditional on the `version` it read (§3.5).
X1's veto-only reactor hook is extended with `network.pre_profile_write` and
`network.pre_segment_write`, fired before the write, as `grant.pre_assign` is.
That is how a tenant configures a four-eyes rule on network policy. It is a veto
the server calls, not an approval surface a token can drive (§6.8 of the spike).

The authorization logic of §5.2 and §5.3 lives in **one domain function in
`axiam-authz`**, not in handlers. A test enumerates every write path that can
create a profile, a segment, a network-sensitive role grant or assignment, or a
certificate binding to a service account (today REST only: `roles.rs`,
`permissions.rs`, `certificates.rs` `bind`, the new network handlers), and fails if
one reaches the repository without that function. This is the T-429 lesson
applied to a write surface. `axiam-authz` is opted into `missing_docs`
(`CLAUDE.md`), so that code is documented from its first commit.

### 5.2 "A profile cannot grant more than its writer holds" — the definition

**What a profile confers.** A profile `P` on segment `S` confers on every subject
that may join `S`:

- `conf_join(P, S)`: placement on VLAN `S.vlan_id`, with `P`'s session and filter
  parameters, always;
- `conf_admin(P, S)`: administrative login to `S`'s NAS devices, only if
  `P.service_type` is in the `admin_class`. That is impossible under option B
  (§3.3) and kept for option A.

**What the writer holds** is what `check_access` answers for the writer, evaluated
**at write time**, with the writer's own subject scope (an organization-level
writer carries only global grants, §2), with deny-override in full force. A deny
at `S` or at any ancestor is a "does not hold".

**The rule.** A writer `W` may create or replace `P` on `S` only if all of the
following hold. Otherwise the answer is `403`, the response names the missing
permission (as `RequirePermission` already surfaces the checked action), and an
audit row records the refusal:

| | Condition | Why |
|---|---|---|
| **H1** | `W` holds `network:profiles_write` on `S` | The profile's own permission. It is not `resources:update` and not `roles:*` (R17) |
| **H2** | `W` holds `network:grant` on `S` | `P` confers `conf_join`. Writing it is a grant, and only someone who may grant joining `S` may shape what joining `S` gives |
| **H3** | every value lies inside `S`'s envelope: `filter_id ∈ S.filter_ids`, `session_timeout_secs ≤` the tenant cap, the VLAN derived from `S` and never chosen | The envelope is written under `network:segments_write` on `S`'s parent, a **separate** permission. A profile writer cannot widen the set of ACL names or the VLAN they choose from, and a tenant can split the two duties between two people |
| **H4** | if `conf_admin(P, S)`: `W` holds `network:grant_admin` **and** `network:admin` on `S` | Literally "no more than the writer holds": conferring administrative login on a segment's equipment requires holding it. Vacuous under option B |
| **H5** | `S.kind` is not changed by this write, and a write to a `kind = quarantine` segment's profile also needs `network:grant` on `/network/quarantine/<site>` | The quarantine profile is reached by every quarantined device of a site. Shaping it is a grant to all of them |
| **H6** | `W ≠` a subject that is itself `network:join`-able on `S` through the same write | A service account that writes its own segment's profile is a device configuring its own access. Refused, whatever it holds. The same holds for binding (§5.3): a subject may not bind a certificate to itself, nor one authenticated through a certificate bound to the account being written |

A **delete** of `P` needs H1 only: no profile means no candidate, which only
narrows. A segment **envelope** write (`network:segments_write`) that would leave
an existing profile outside the new envelope (removing the profile's `filter_id`,
or turning `access` into `quarantine`) is refused `409`, naming the profile.
Lowering the tenant cap is allowed, because §3.4 clamps at read time and that only
narrows.

**What the rule deliberately is not.** "Holds" is a **write-time** condition. A
profile does not lapse when its writer later loses `network:grant`, just as a role
assignment survives its assigner losing `roles:assign` today. A profile is tenant
policy, not a delegation chain. The audit row (§5.4) records who wrote it, and a
re-validation sweep that flags profiles whose last writer no longer holds H1–H4 is
a possible later item (§9, residual 1), not a gate.

### 5.3 The role-assignment and certificate-binding sides — where the rule would otherwise leak

A profile is inert until a device may join its segment. Joining is a role
assignment, **and a device is the account that holds the join only through
the certificate bound to that account** (§4.3 step 1). Today any `roles:assign` holder
can assign any role, at any node, to any subject (§2). Unless the assignment side
is held to the same rule, H2 is decoration. So, for **network-sensitive** roles
only (§4.2), in addition to `roles:assign` / `roles:unassign`:

| Write | Additional requirement |
|---|---|
| Assign a role carrying an **allow** `network:join` at node `N` (or with no resource: then `N = /network`) | `W` holds `network:grant` at `N` |
| Assign a role carrying a **deny** `network:join` (quarantine) at `N` | `W` holds `network:grant` at `N`. It narrows, but a broad administrator quarantining a fleet is a denial of service, and the audit row should name a network administrator |
| **Unassign** a role carrying a deny (release) | `W` holds `network:grant` at `N`. This widens access |
| Assign a role carrying a meta permission (`network:grant`, `network:profiles_write`, `network:segments_write`, `network:decide`, `network:export`) at `N` | `W` holds **every such permission** at `N`. You delegate only what you hold |
| `permissions:grant` / `permissions:revoke` of a `network:` permission on a role (either effect) | `W` holds `network:grant` at `/network`, plus every meta permission granted. It changes every existing assignment of the role at once |
| `roles:delete` of a role carrying a `network:` **deny** | as unassign, at `/network` |
| **Bind** a certificate to a service account `A` (or re-bind it from another account), at `certificates:bind`, where `A` holds any `network:join` **allow** at a node `N`, directly or through a role | `W` holds `network:grant` at **every such `N`**. `A`'s `network:join` allows are read at write time with `check_access`'s own evaluation, deny-override in force, so an allow that a deny already beats is not one `W` must hold. Binding to an account with no `network:join` allow, or only a deny, asks nothing extra |
| Any other path that issues a certificate already bound to an account (none exists today: `certificates:generate` and `sign-csr` bind nothing) | the same row, evaluated at issuance. Such a path is not built until it calls the §5.1 function |

**Correction of 2026-10-13 (R101W6-03, F4 review of W6).** This note first said
that the assignment side is the whole of the leak ("joining is a role
assignment"). It is not: a holder of `certificates:generate` and `certificates:bind`
(both tenant-wide) could issue a certificate for a device they hold and bind it to a
service account that already holds `network:join` on a privileged segment. That
confers the segment's placement and its profile without `network:grant`, by the
second door. The two rows above close it. The rule is that **placement is conferred by the
pair (the account's joins, the certificate binding), and a write to either edge needs `network:grant` on what the other already
carries.** Role assignment to an account with certificates already bound is the
first rows' case (the assignment needs `network:grant` at `N`); binding to an
account that already has the join is the new rows' case. The alternative, deriving
placement only from roles the binder could assign, was rejected: it needs the
binder recorded on the edge and re-evaluated at every decision, and it would make a
role revocation by someone else change a device's placement silently. The write-time
gate is the same shape as every other row of this table. Binding is also bound by
H6's spirit: a service account that authenticates by a certificate may not bind a
certificate to itself or to the account it is. D6, which binds certificates to
users, adds a user path to this row and reopens it with §4.2 rule 2.

*Plan vs tree:* the review words the second door as "issue a certificate and bind
it". In the tree the two are separate routes and issuance binds nothing, so the rule
attaches to the bind (`certificates.rs:527`), with the second table row held ready
for any future path that binds at issuance. The permission names
(`certificates:generate`, `certificates:bind`, `network:grant`'s tenant-wide
`Uuid::nil()` checks) match `crates/axiam-api-rest/src/permissions.rs:76ff`.
`network:*` is not in the tree yet (nothing is built).

This is a **namespace-limited** delegation bound. AXIAM today has no general "you
cannot assign more than you hold" rule, and this note does not propose one. That
would be a change to every assignment in every tenant, and it belongs in its own
item (§9, residual 7).

### 5.4 An audit row for every write, and for every refusal

Append-only rows (`CLAUDE.md`, *Security Standards*), with the action vocabulary
the tree uses (`scim_target.created`, `crates/axiam-api-rest/src/handlers/scim_targets.rs:69`):

`network_segment.created` · `.updated` · `.moved` · `.deleted` ·
`reply_profile.created` · `.replaced` · `.deleted` · `reply_profile.write_refused` ·
`network_segment.write_refused` · `network_role.assign_refused` ·
`certificate_binding.refused` (§5.3, a bind refused for want of `network:grant`) ·
`reply_profile.invalid` (§3.4, one per profile per window) · and, if §6.2 is built,
`network_export.read`.

Each row carries the actor and actor kind, the tenant, the segment and profile
ids, the dictionary version, the attribute values **before and after** (they are
policy, not secrets or personal data, and a reviewer must be able to see that VLAN
20 became VLAN 99), the `version`s, and for a refusal the **internal** reason
(`H2`, `envelope:filter_id`, …). Refusals are audited because an escalation
attempt is exactly the event a reviewer wants to find. Their volume is bounded by
the route limiter, and the actor is an authenticated administrator, so this is not
the attacker-chosen volume T-463 warns about.

### 5.5 Notifications

A profile or segment change may map to a notification event only **through** the
existing `NotificationGate` (`crates/axiam-audit/src/notification.rs`, D-73's
per-target-per-hour rule). In option B no reject flows through AXIAM, so T-465's
flood has no source here until D4.

---

## 6. How FreeRADIUS consumes it under option B

### 6.1 In 1.0.1 (D3 ships, D4 does not): nothing consumes it, by design

1.0.1 builds none of §3–§5. The D3 guide (`docs/pki/freeradius.md`, W6.2) places
devices on VLANs, if it shows that at all, **in FreeRADIUS's own configuration**,
keyed on the certificate the tenant's CA issued. AXIAM's checks do not reach that
configuration. Its writers are FreeRADIUS administrators, and T-461 for option B in
1.0.1 is a statement about the operator's configuration, not about AXIAM. What
this note asks of the guide (§10): any VLAN example uses **only the attribute set
of §3.2**, encoded as §1 (1h) read it, so an operator's hand-written mapping is
already an instance of this model and moving to §6.2 or §6.3 loses nothing.

### 6.2 An optional bridge, not scheduled: the segment export

If an adopter needs AXIAM to own VLAN policy before D4, the smaller step is a
**static export**:
`GET /api/v1/network/sites/{site}/export?format=freeradius`, rendering one
fragment for FreeRADIUS's `files` module per active, non-revoked, unexpired
device certificate of an `Active` service account that the selection of §4.3
places in that site, keyed on the certificate's **issuer and serial**. FreeRADIUS
re-reads it on a timer (a pull and a `HUP`, the same shape as its CRL refresh).

- **Freshness** is the pull interval. A quarantine or a VLAN change reaches the NAS
  at `pull interval + Session-Timeout`. Revoked certificates drop out of the next
  export as well as the next CRL.
- **Caller:** a service account holding `network:export` on the site, its token
  bound to its own certificate (`cnf`), a machine-preset limiter keyed on the
  authenticated caller, one `network_export.read` row per read. These are T-468's
  bindings, because an export is a bulk answer to "which certificates are good
  here" and is at least as sensitive as D4's per-certificate one.
- **Contents:** issuer, serial and the rendered attributes. No subject names, no
  service-account names, no personal data (§8).
- **Recalled, not verified this session:** that FreeRADIUS 3.2 exposes the
  presented certificate's serial and issuer to `post-auth` as
  `TLS-Client-Cert-Serial` / `TLS-Client-Cert-Issuer`, and that the `files` module
  can key on such an expansion. The D3 end-to-end, or whichever task builds this,
  settles it first. **Settled 2026-10-13 for the serial (R101W6-02):** the D3
  recipe now keys its own placement table on `TLS-Client-Cert-Serial`, read in
  the EAP-TLS `virtual_server` (`check-eap-tls`) rather than `post-auth`, and
  the end-to-end admits a placed device through a `files` module keyed on it.
  The issuer is not needed while a server trusts one tenant signing CA; an
  export for several CAs would still need it.

### 6.3 When D4 ships: a decision per authentication

D4 (spike §5.2 B-3, T-468) replaces §6.2 rather than adding to it. FreeRADIUS's
`rlm_rest`, in `post-auth` after EAP-TLS succeeds, posts the presented
certificate (or its fingerprint) and the **site key from its own client
configuration**. The endpoint resolves the certificate through
`DeviceAuthService::authenticate_der`, refuses on tenant mismatch (§7), runs §4.3,
and returns either `{ allow: false }` with **no reason**, or `{ allow: true,
reply: … }` rendered from the typed profile.

What changes with it:

- **Revocation and quarantine are read per request.** The CRL lag and the export
  interval disappear. What remains is the `Session-Timeout` bound (T-462), until
  dynamic authorization exists. That is not in option B: FreeRADIUS owns the
  sessions.
- **The caller** holds `network:decide` on the sites it serves, so a stolen
  FreeRADIUS credential for HQ answers nothing about a branch office. Its token is
  `cnf`-bound, it is metered on a machine preset keyed on the authenticated caller,
  and each decision writes a row (T-463's content rules, and T-464 for whatever the
  request carries).
- **Defence in depth on the FreeRADIUS side.** The guide's `rlm_rest` mapping copies
  only the §3.2 attributes from the response into the reply. An AXIAM bug cannot
  then emit an attribute the dictionary excludes, and a FreeRADIUS administrator
  sees the allow-list in their own configuration. (`rlm_rest`'s response-mapping
  syntax is recalled, not read this session.)
- **It needs** a contract section (1.62) and the §6 bindings as code (plan §7).
  The decision of §4.3 becomes a hot path for a site's power-restore storm (spike
  §6.1), so `check_access_batch` and the decision cache are the budget, and
  "no candidate" must cost the same as a placement (T-457's timing rule).

| | 1.0.1 (D3) | §6.2 export | D4 |
|---|---|---|---|
| Who owns VLAN policy | the FreeRADIUS operator | AXIAM | AXIAM |
| Revocation reaches the NAS | CRL refresh (`nextUpdate` ≤ 1 day by default) + `Session-Timeout` | the earlier of CRL and export pull, + `Session-Timeout` | next authentication, bounded by `Session-Timeout` |
| Quarantine reaches the NAS | operator edits config | pull interval + `Session-Timeout` | `Session-Timeout` |
| New AXIAM surface | none | one bulk read (T-468's bindings) | one decision route (T-468) |

The D4 trigger the spike set ("only once D3 shows the CRL interval or the
attribute model inadequate") reads, against this table: if an adopter cannot live
with the left column's revocation or quarantine latency, or needs AXIAM-owned VLAN
policy, §6.2 answers the second need, and only D4 answers the first.

---

## 7. Multi-tenant isolation (T-459)

Under option B there is no NAS registry in AXIAM. The "authenticated NAS" is the
**authenticated caller**: FreeRADIUS's service account.

- **The tenant is the caller's, and nothing else.** No request field, query
  parameter, certificate extension, realm or packet attribute names it. Segments,
  profiles and the export are read with the caller's `tenant_id` on every
  repository call. A caller's `network:decide` / `network:export` are tenant
  grants. Network-sensitive roles cannot be global (§4.2 rule 1), so an
  organization-level subject cannot carry a network grant across tenants.
- **Certificate and caller tenants must be equal.** `authenticate_der` looks the
  certificate up globally and returns its tenant. D4 refuses on mismatch, with the
  same reject as every other failure. The export only ever lists the caller
  tenant's certificates.
- **FreeRADIUS must trust the tenant's signing CA, not the organization CA**
  (§10). The organization CA is shared by its tenants (spike §4.4, §6.5), so a
  FreeRADIUS trusting it lets a device of tenant B complete EAP-TLS on tenant A's
  network. Without D4, nothing on the AXIAM side would catch that, because the
  §6.2 export keys on issuer and serial and simply has no row. The device would
  then be authenticated but unplaced, which is a reject only if the operator's
  configuration rejects an unplaced device. The guide must make both true: trust
  only the tenant signing CA, and reject when no placement matches.
- **Site keys are tenant-scoped strings.** Two tenants may both have `hq`.

---

## 8. Personal data (T-464)

- **Segments and profiles contain none** (§3.5). VLAN numbers, ACL names and
  timeouts describe a network, not a person.
- **Audit rows for writes** carry the writing administrator's subject id, as
  every admin audit row already does. They carry no device identifier, MAC address
  or user name.
- **The export (§6.2) and D4's request** carry certificate issuer and serial (and
  for D4, whatever FreeRADIUS posts). Today those certificates are bound to
  **service accounts**, machines, and are not personal data in the register's
  sense (`crates/axiam-core/src/personal_data.rs` inventories the `user` table).
  **When D6 binds certificates to users**, a user certificate's serial becomes an
  identifier of a person. The export and D4's decision rows then enter the
  personal-data register and its erasure paths in the commit that first emits them
  (T-464's rule). Erasure reaches the export at the next pull, because the export
  is regenerated, not stored. D4's rows must not carry `Calling-Station-Id` or
  `User-Name` unless they enter the register in the same commit.
- FreeRADIUS's own logs (MAC addresses, identities) are the operator's data
  under their own retention. The D3 guide says so (§10).

---

## 9. Residuals

1. **"Holds" is checked at write time.** A profile outlives its writer's
   permissions, as a role assignment does. A re-validation sweep that flags
   profiles and network-role assignments whose author no longer holds H1–H4 is a
   possible later item, not a gate.
2. **In 1.0.1, VLAN policy lives in FreeRADIUS's configuration** (§6.1), outside
   AXIAM's permissions and audit. That is option B's stated shape (spike §5.2,
   "the attribute model lives in FreeRADIUS's configuration unless B-3 ships").
3. **No dynamic authorization.** A quarantine or revocation waits for
   re-authentication, bounded by `Session-Timeout` and the tenant cap (T-462,
   which stays Open-if-built).
4. **FreeRADIUS can add attributes AXIAM did not send.** The operator's
   configuration is outside AXIAM's guarantee. §6.3's defence-in-depth mapping
   narrows the window, and no AXIAM control closes it.
5. **No vendor attributes.** Deployments that steer by `Aruba-User-Role`,
   `Cisco-AVPair` and the like keep that mapping in FreeRADIUS, keyed on the VLAN
   AXIAM assigned. That is an accepted feature gap.
6. **AXIAM cannot know what a VLAN is on the switch.** `vlan_id` is a number an
   administrator asserts. Placing the wrong number on the quarantine segment is a
   configuration error AXIAM audits and cannot detect.
7. **The general delegation gap.** Outside the `network:` namespace,
   `roles:assign` remains unbounded, and so does `certificates:bind` for an
   account that holds no `network:join` (§2, §5.3). This note does not change that. It
   is pre-existing and its own item.

---

## 10. What this note hands to others

**To W6.2 (the D3 guide, recipe and end-to-end):**

- FreeRADIUS's EAP `ca_file` is the **tenant signing CA** (and its CRL), not the
  organization CA (§7). An end-to-end case for "tenant B's certificate on tenant
  A's FreeRADIUS is rejected" falls out of the wrong-CA case if the recipe issues
  under two tenants.
- Any VLAN example uses only §3.2's attributes, encoded per RFC 3580 §3.31 (decimal
  string, tag 0), with `Termination-Action = RADIUS-Request` and a bounded
  `Session-Timeout`. The guide states the revocation and quarantine latency of
  §6.3's first column.
- An unplaced device is rejected, not dropped onto the NAS's default VLAN.
- FreeRADIUS logs are the operator's personal data (§8).
- `require_message_authenticator = yes` is confirmed as FreeRADIUS's recommended
  setting (§1, 5b, `raddb/radiusd.conf.in` v3.2.x). `limit_proxy_state` is then
  ignored, and the guide need not set it.

**To W6.3 (the F4 review) and W7.3 (the model reconciliation):** two corrections
the re-read found, for the entries' own text, dated, in the pass that edits them.
**This note edits no threat entry.**

- **T-449** says "`Proxy-State` in a request is refused (AXIAM is not a proxy)".
  RFC 2865 §5.33 requires it to be echoed, and FreeRADIUS's mitigation is
  `Message-Authenticator` required whenever `Proxy-State` is present, not refusal
  (§1, 5b). With `Message-Authenticator` required on every packet, the refusal
  adds nothing against Blast-RADIUS and breaks aggregating controllers. It is
  option A's to re-decide. The same sentence's "first" position is the reference
  implementation's practice and not yet a normative citation (§1, 5a).
- **T-453** (spike R20): the duplicate cache matches on source address, source
  port, Identifier and receiving socket. A different Request Authenticator purges
  the entry, and a packet failing `Message-Authenticator` must not touch the cache
  (RFC 5080 §2.2.2; §1, 1j).

**To D4, when scheduled:** §4.3 is the decision; §6.3 its caller rules and its
contract section; §8 its personal-data rule; §5.3 must already be built (both
its role-assignment rows and its certificate-binding rows), or D4 serves a model any
`roles:assign` or `certificates:bind` holder can rewrite.

**To option A's A-8 / A-9, if reopened:** the same model with a NAS registry in
place of the caller. The site key is then a property of the NAS row, and moving a
NAS between sites is the T-467 move rule. The admin class (H4, `network:admin`,
`network:grant_admin`) becomes live with PAP over RadSec, under T-460's MFA
rule.

---

## 11. Checklist — spike §6 and the threat entries

| Requirement | Where this note meets it | Status of the requirement *for this design* |
|---|---|---|
| **§6.1** limiters and lockout from the first commit | §5.1 (`network_admin_per_min` per write route); §6.2 / §6.3 (machine preset keyed on the authenticated caller) | Met for the management and caller routes. **Lockout: not applicable**: these routes verify no credential; EAP-TLS failures never lock (spike §6.1) |
| **§6.2** no unknown-user oracle | §4.3 step 3 (no candidate = the same reject, no reason); §6.3 (no reason on deny; equal cost) | Met for D4; **deferred to D4** for the timing test. Not applicable to the management API beyond `network:read` |
| **§6.3** `Message-Authenticator`; MD5-only attributes | §3.3 (protocol attributes and MD5-obfuscated `Tunnel-Password` / `MS-MPPE-*` excluded from every profile); §10 (Proxy-State correction) | The packet rules are **FreeRADIUS's under option B** (W6.2's configuration) and **option A's**; this note only keeps profiles out of them |
| **§6.4** per-NAS secret sealed, write-only, bound | — | **Not applicable to option B**: FreeRADIUS holds its clients' secrets. D4's caller credential is `cnf`-bound (§6.3). Option A: the site key binds to the NAS row under T-467's move rule (§10) |
| **§6.5** multi-tenant isolation | §7; §4.2 rule 1 | Met |
| **§6.6** an audit row for every decision | §5.4 (every write and refusal); §6.2 (every export read); §6.3 (every D4 decision) | Writes: met. Decisions: **deferred to D4** |
| **§6.7** `NotificationGate` | §5.5 | Met (gate only) |
| **§6.8** no approval surface | §5.1 (the reactor hook is a server-called veto, not an approval a token drives) | Met (by absence) |
| **§6.9** MFA not bypassable; downgrade refused | §3.3 (admin class disabled in option B: no password path); §3.4 (unknown dictionary version or field refused, never ignored) | MFA: **not applicable to option B** (no password flow, spike §5.2). Downgrade: met for the dictionary; the EAP/TLS downgrade rules are FreeRADIUS's (W6.2) |
| **T-461** reply profile beyond its writer | §3 (closed typed dictionary, VLAN derived), §4.4 (quarantine), §5.2 (H1–H6), §5.3 (assignment **and certificate-binding** sides; added 2026-10-13, R101W6-03), §5.4 (audit) | **The design T-461 asks for.** Still *Not applicable*, and Mitigated only when built with the tests §5.1 names |
| **T-459** cross-tenant | §7 | Design input to D4 and W6.2 |
| **T-462** session outlives revocation | §3.4 (tenant cap, floor, `RADIUS-Request`); §6.3 table | Bound defined; stays Open-if-built |
| **T-463** decisions audited | §5.4; §6.3 | Writes here; decisions **deferred to D4** |
| **T-464** personal data | §8 | None in the model; the D6 trigger stated |
| **T-465** notification flood | §5.5 | No source under option B until D4 |
| **T-468** authorize-endpoint oracle | §6.2 (the export gets the same bindings), §6.3 (`network:decide` per site) | **Deferred to D4**; narrowed by site scoping |
| **T-457** reject oracle | §4.3 step 3; §6.3 | **Deferred to D4** |
| **T-450** MD5 attribute hiding | §3.3 | Profiles never carry an MD5-obfuscated attribute |
| **T-454** supply chain | §1 (7) | Licence confirmed; the recipe vendors nothing (W6.2) |
| **T-449**, **T-453** | §10 | Text corrections handed to W6.3 / W7.3; **option A** |
| **T-448**, **T-451**, **T-452**, **T-455**, **T-456**, **T-458**, **T-460**, **T-466**, **T-467** | — | **Option A** (listener, EAP state machine, PAP, NAS registry); T-456's TLS/EAP side is FreeRADIUS's configuration under option B (W6.2). T-460's admin-class rule is pre-wired by H4 |
