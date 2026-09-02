# Authenticator policies

WebAuthn registration accepts any authenticator by default — the same
behavior AXIAM has always had. This page covers the opt-in **attestation
policy** (X3): per-tenant rules that restrict *which* security key or
passkey models may register, backed by the FIDO Alliance's Metadata Service
(MDS3) for authenticator identity, certification level, and revocation
status.

**The default is unchanged.** A tenant with no policy configured — which is
every tenant today — behaves exactly as before: no attestation is requested,
every authenticator is accepted, and AXIAM makes zero MDS lookups. Read the
[passkey caveat](#the-passkey-caveat--read-this-before-enabling-anything)
below before opting in to anything stricter.

See also: [Admin Guide](README.md), [PKI Guide](../pki/README.md).

## The passkey caveat — read this before enabling anything

Turning attestation on **at all** — `mode: indirect` just as much as
`mode: direct_required` — excludes an entire class of authenticator that a
lot of your users already have: **iCloud Keychain, Google Password Manager,
and any other synced/passkey provider, plus hybrid ("use your phone")
sign-in.** This is not a policy choice you make per mode; it is a property
of requesting attestation at all, verified against the `webauthn-rs` 0.5.5
library AXIAM uses:

- Starting an attested registration ceremony **always** requests `direct`
  attestation conveyance from the browser — there is no library-level
  `indirect` wire conveyance. AXIAM's `mode: indirect` still uses this same
  ceremony; it only differs from `mode: direct_required` in how *strict* the
  policy evaluation is afterwards (lax unknown-AAGUID handling by default),
  never in what is requested over the wire. **Do not describe `indirect`
  mode as requesting `indirect` conveyance — it does not.**
- The attested ceremony **always** requires user verification and **always**
  rejects synchronised authenticators, regardless of mode.
- Synced/cloud passkey providers (iCloud Keychain, Google Password Manager)
  return `none`-format attestation by design — there is nothing for the
  library to verify — so they cannot complete an attested ceremony at all.
  Hybrid (phone-as-authenticator) flows do not attest either and are
  excluded the same way.

So the honest trade is:

| Posture | What you get | What you give up |
|---|---|---|
| `mode: none` (default) | Every authenticator works, including passkeys and hybrid | No control over authenticator make/model, certification, or revocation |
| `mode: indirect` or `mode: direct_required` | Only attested, non-synced hardware authenticators (YubiKey and similar) register, filtered by your policy fields | iCloud Keychain, Google Password Manager, and phone-as-authenticator (hybrid) sign-in no longer work for **new** registrations |

This is a **hardware-key-only enterprise posture** versus a
**passkey-friendly consumer posture** — not a dial you can split the
difference on. If your users need both hardware keys and consumer passkeys,
keep `mode: none` and use `allowed_aaguids`/`blocked_aaguids` only if you
still need per-model control without attestation (note: without attestation
there is no AAGUID to check against those lists in practice, since the
AAGUID is only reliably resolved through the attested ceremony — see
[Policy fields](#policy-fields) below).

Existing passkeys registered before you turn attestation on are **never**
affected — see [Compliance report](#compliance-report) for how already-registered
credentials are treated.

## User verification: which authenticators can enrol at all

This is a **separate** control from the attestation policy on the rest of this
page, and it is the one that decides whether a security key with no PIN
configured can be enrolled.

WebAuthn distinguishes two things an authenticator can prove:

| Bit | Name | Means | A PIN-less YubiKey |
|---|---|---|---|
| `UP` | User **presence** | a human is at the authenticator (a touch) | sets it |
| `UV` | User **verification** | *which* human — a PIN, fingerprint, or face | cannot set it |

Up to and including `1.0.0-beta08`, AXIAM required `UV` unconditionally, because
the `webauthn-rs` library hard-codes it. Enrolling a security key with no PIN
failed with:

```json
{"error":"authentication_failed",
 "message":"Authentication failed: WebAuthn registration failed: \
            The user verified bit is not set, and required by policy"}
```

The "policy" it named existed nowhere an operator could see or change. It is now
a real setting.

### The setting

`webauthn_user_verification` lives in security settings — an **organization**
baseline that every tenant inherits and may only make **stricter**:

```
PUT /api/v1/organizations/{org_id}/settings
{ ..., "webauthn_user_verification": "preferred" }

PUT /api/v1/tenants/{tenant_id}/settings
{ "webauthn_user_verification": "required" }     # tightening: accepted
{ "webauthn_user_verification": "discouraged" }  # relaxing: 400
```

| Value | Enrolment | Use |
|---|---|---|
| `discouraged` | No verification requested | The key is unambiguously a second factor behind a password |
| `preferred` **(default)** | Requested, accepted either way, and what happened is recorded | Supporting security keys generally, PIN-protected or not |
| `required` | A key that cannot verify is refused | A WebAuthn credential may stand alone as a login factor |

The order for the tighten-only rule is `required` > `preferred` > `discouraged`.
Raising the organization baseline past a tenant's override clears that override,
so the tenant tracks the new baseline — the same behaviour as every other
setting here.

### Two ceremonies do not follow it

* **Usernameless (passwordless) sign-in always requires user verification**,
  whatever this is set to. There the credential is the only factor, so without
  `UV` mere possession of the token is a complete login. The practical
  consequence: a PIN-less security key **enrols and works as a second factor**,
  and **cannot be used for passwordless sign-in**. Give the key a PIN if you
  want that.
* **Attested registration always requires user verification**, because
  `webauthn-rs` imposes it on the attested ceremony and AXIAM does not override
  it. A tenant with any attestation `mode` other than `none` has already opted
  into the strict path — see [the passkey
  caveat](#the-passkey-caveat--read-this-before-enabling-anything) — and a
  PIN-less key does not enrol there.

### Nothing already enrolled is weakened

`webauthn-rs` records the policy a credential was **registered** under and
requires `UV` at authentication whenever either that stored policy or the
current one says `required`. Every credential enrolled before this change was
enrolled under the old hard-coded `required`, so it keeps demanding
verification for the rest of its life no matter what the setting becomes. The
policy governs new enrolments.

The default is `preferred` rather than `required` because nobody chose
`required` — it was a library constant, and backfilling it would have preserved
the bug rather than an intent. If your deployment wants the strict posture, set
`required` at the organization and you lose nothing you had.

## Policy fields

Each tenant has at most one attestation policy row
(`GET|PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`). An absent
row means the defaults below, which reproduce today's behavior exactly.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"none"` \| `"indirect"` \| `"direct_required"` | `"none"` | Whether attestation is requested at all, and how strict the fallback defaults are. `"none"` short-circuits every other field — no MDS lookup happens. |
| `require_fido_certified` | bool | `false` | Deny unless the authenticator has *any* `FIDO_CERTIFIED*` status in its MDS history, any level. Only enforceable when `mode != "none"`. |
| `min_certification` | `"L1"` \| `"L1Plus"` \| `"L2"` \| `"L2Plus"` \| `"L3"` \| `"L3Plus"` \| `null` | `null` | Deny unless the authenticator's **highest ever** certified level meets this bar. Only enforceable when `mode != "none"`. |
| `allowed_aaguids` | array of UUID \| `null` | `null` | `null` = every AAGUID is allowed except `blocked_aaguids`. `[]` (explicitly empty) means *nothing* may register — a deliberate lockout, not an accident of leaving the field unset. |
| `blocked_aaguids` | array of UUID | `[]` | AAGUIDs that may never register, regardless of `allowed_aaguids`. |
| `block_revoked_status` | bool | `true` | Deny an authenticator whose MDS history ever reported `REVOKED`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, or `USER_KEY_PHYSICAL_COMPROMISE` — see the [known limitation](#known-limitation-user_verification_bypass-is-not-covered) below. |
| `unknown_aaguid` | `"allow"` \| `"deny"` \| `null` | `null` (= this mode's default) | What to do when the AAGUID has no MDS entry at all (MDS coverage is incomplete for some legitimate authenticators, so "unknown" is not itself evidence of anything malicious). See below for what `null` resolves to. |

Setting `require_fido_certified` or `min_certification` while `mode` is
`"none"` is rejected at the API with a validation error — those fields
cannot be enforced without requesting attestation, and AXIAM would rather
refuse the write than let an admin believe a control is active when it is
not.

**`unknown_aaguid` defaults to the mode you chose.** Left unset (`null`),
it resolves to:

| `mode` | `unknown_aaguid: null` resolves to |
|---|---|
| `none` | `allow` (nothing is enforced at all in this mode) |
| `indirect` | `allow` |
| `direct_required` | **`deny`** |

The strictest mode therefore fails closed by default: a tenant that opts
into `direct_required` without mentioning this field does **not** admit
every authenticator FIDO happens to have no metadata for. Setting the field
explicitly always wins, in both directions — if you want
`direct_required` *with* lenient handling of unlisted authenticators, send
`"unknown_aaguid": "allow"` and that is what you get.

`GET` returns both values: `unknown_aaguid` is your stored intent (possibly
`null`), and the read-only `effective_unknown_aaguid` is what it currently
resolves to. Read the second one when you want to know what the policy is
actually doing.

### Decision order

Registration attempts are evaluated in this exact order (the normative
implementation is `evaluate` in
`crates/axiam-core/src/models/webauthn_policy.rs`; every step is unit-tested
and the order is asserted not to change without updating both):

1. **`mode == "none"` → allow unconditionally.** No MDS lookup happens at
   all, even if the AAGUID happens to be in `blocked_aaguids` — no
   attestation was requested, so there is nothing to police. This is the
   guarantee that makes the default byte-for-byte identical to
   pre-X3 behavior.
2. **`mode == "direct_required"` and attestation is absent or format
   `"none"` → deny** (`attestation_required`). `mode: "indirect"` does not
   have this check — a `"none"`-format credential under `indirect` proceeds
   to the rest of the checks instead of being rejected outright (in
   practice `webauthn-rs` cannot complete an attested ceremony with
   `"none"`-format attestation at all — see the
   [passkey caveat](#the-passkey-caveat--read-this-before-enabling-anything)).
3. A missing or nil AAGUID is treated as **unknown** from here on.
4. **`blocked_aaguids` beats `allowed_aaguids`.** If the AAGUID is blocked,
   it is denied even if it also appears in `allowed_aaguids` — the same
   deny-override posture the RBAC engine uses elsewhere in AXIAM (see
   [`claude_dev/deny-override-design.md`](../../claude_dev/deny-override-design.md)).
5. **`allowed_aaguids` is `Some(list)` and the AAGUID is not in it → deny**
   (`aaguid_not_allowed`). This includes an unknown/nil AAGUID — it can
   never be "in" an explicit list.
6. **No MDS entry for this AAGUID:** if it is nonetheless explicitly present
   in `allowed_aaguids`, an admin has vouched for it directly and it is
   **allowed regardless of `unknown_aaguid`**. Otherwise the outcome is
   whatever `unknown_aaguid` says.
7. **Sticky compromise/revocation check** (`block_revoked_status`): any
   occurrence of a compromise/revocation status *anywhere* in the
   authenticator's MDS status history denies it — even if a later, benign
   status report followed it. History cannot be used to launder a past
   compromise.
8. **`require_fido_certified`**: any `FIDO_CERTIFIED*` status, any level.
9. **`min_certification`**: the authenticator's *highest ever* certified
   level must meet the configured bar. An authenticator never certified
   fails this unconditionally.
10. Otherwise, **allow**.

## MDS3 metadata: refresh, opt-in, and air-gap operation

MDS ingestion lives in `axiam-pki` and is entirely opt-in, controlled by
server-level environment variables (not per-tenant):

| Env var | Default | Meaning |
|---|---|---|
| `AXIAM__PKI__MDS_ENABLED` | `false` | Master switch. **`false` means zero outbound calls** — no background refresh job is spawned, and the admin-triggered refresh endpoint refuses to run. Upgrading to a build with this feature changes no deployment's runtime behavior until you turn it on. |
| `AXIAM__PKI__MDS_BLOB_URL` | `https://mds3.fidoalliance.org/` | Fetch source for the network path. |
| `AXIAM__PKI__MDS_BLOB_PATH` | unset | Local BLOB file for **air-gapped deployments**. When set, it wins over `MDS_BLOB_URL` and **no network fetch happens at all** — every refresh (scheduled or admin-triggered) reads this file instead. |
| `AXIAM__PKI__MDS_REFRESH_INTERVAL_SECS` | `604800` (weekly) | Background refresh interval. `0` disables the background job; the admin-triggered endpoint still works. |
| `AXIAM__PKI__MDS_LEAF_DNS` | `mds.fidoalliance.org` | Expected DNS name on the BLOB's signing certificate (see [trust anchor](#updating-the-vendored-trust-anchor) below). Configurable so a legitimate FIDO Alliance hostname change is an ops action, not a code release. |

**The ~10 MB BLOB is deliberately not vendored in this git repository.** For
an air-gapped deployment, fetch a current BLOB from
`https://mds3.fidoalliance.org/` on a network-connected machine as part of
building your release image (or through whatever process moves files across
your air gap), bake it into the image or a mounted volume, and point
`AXIAM__PKI__MDS_BLOB_PATH` at it.

Two admin/observability endpoints:

- `POST /api/v1/mds/refresh` — admin-triggered ingestion (network fetch or
  local file, per the config above). Refuses to run if
  `AXIAM__PKI__MDS_ENABLED=false`.
- `GET /api/v1/mds/status` — returns the last successfully ingested BLOB's
  `{no, next_update, entry_count, last_refreshed_at, stale}`.

### Staleness never hard-fails

`next_update` (the BLOB's own `nextUpdate` claim) passing does **not** block
ingestion or use of already-ingested entries. It is logged at `WARN` and
reflected as `stale: true` on `GET /api/v1/mds/status` — a transient outage
at the FIDO Alliance, or an air-gapped deployment that has not re-supplied
its local file recently, must not brick WebAuthn registration outright. If
you care about staleness, monitor the `stale` field and the
`mds.refreshed` / `mds.refresh_failed` audit actions rather than expecting
AXIAM to refuse traffic on your behalf.

### Rollback protection

Ingestion compares a freshly-verified BLOB's serial number (`no`) against
the currently stored serial before replacing anything:

- a **lower** `no` is rejected outright as a rollback attempt — nothing is
  written;
- an **equal** `no` is a no-op refresh — only `last_refreshed_at` is
  bumped;
- only a **strictly higher** `no` replaces the stored entries.

This closes the obvious attack of replaying an older, validly-signed BLOB to
quietly reintroduce an authenticator model the FIDO Alliance has since
revoked or decertified.

## Updating the vendored trust anchor

Every MDS3 BLOB's signature chain roots in a certificate AXIAM vendors in
the repository: `crates/axiam-pki/src/mds/fido-mds-root-ca-r3.pem`
(GlobalSign Root CA – R3). This certificate is never fetched at runtime —
matching its SHA-256 digest against the pinned constant

```
FIDO_MDS_ROOT_SHA256_HEX = cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b
```

**is the security check.** Re-downloading the file from anywhere is not a
substitute for that comparison. This anchor is the root of trust for *every*
attestation decision the policy engine makes: if it were ever silently
swapped, "only FIDO-certified authenticators may register" quietly becomes
"any authenticator an attacker can mint an attestation chain for" — with no
test failure and no runtime error, just a bad key. The loader recomputes
this digest on every use and fails closed on any mismatch.

Chaining to this root by itself only proves "some genuine GlobalSign EV
customer signed this," not "the FIDO Alliance signed this" — GlobalSign Root
CA – R3 sits above the entire public web, not just the FIDO Alliance. Two
additional checks close that gap and are part of what makes the pinned
anchor mean anything:

- the BLOB's leaf certificate must carry `AXIAM__PKI__MDS_LEAF_DNS`
  (`mds.fidoalliance.org` by default) as a DNS `subjectAltName` (falling
  back to the certificate's CN only when it carries no SAN extension at
  all); and
- every certificate used as an issuer in the chain must actually be a CA
  (`basicConstraints: CA=true`, and `keyCertSign` asserted when `keyUsage`
  is present) — otherwise an attacker holding an ordinary, genuinely-issued
  end-entity certificate under the same public root could splice a
  self-minted leaf beneath it and pass a naive "everything verifies" check.

To rotate the anchor (a GlobalSign root renewal, or a future FIDO Alliance
CA change):

1. Obtain the new root certificate from a trusted, independently-verifiable
   source — e.g. GlobalSign's own published fingerprint page — not just a
   bare download URL.
2. Compute its SHA-256 digest over the **DER** encoding.
3. Update both `crates/axiam-pki/src/mds/fido-mds-root-ca-r3.pem` and
   `FIDO_MDS_ROOT_SHA256_HEX` in `crates/axiam-pki/src/mds/mod.rs` **in the
   same commit**.
4. Get that commit reviewed with the digest change called out explicitly —
   the digest constant is the actual control; the PEM file is inert without
   it matching.

## Compliance report

`GET /api/v1/tenants/{tenant_id}/webauthn/compliance-report` re-evaluates
every credential already registered in the tenant against the **current**
policy and returns, per credential: `{credential_id, user_id, name, aaguid,
authenticator_name, compliant, reason}`.

Three things to know before you read the results:

- **Nothing is ever auto-revoked.** The report is read-only. If you want to
  remove a non-compliant credential, do it through the existing
  credential-delete path, as a deliberate human decision — no code path in
  AXIAM deletes or disables a credential as a side effect of a policy
  change or a compliance-report evaluation.
- **A credential with no recorded AAGUID is reported `unknown`, never as a
  violation** — regardless of what the current policy says, including under
  `direct_required`. Every credential registered before you enabled
  attestation policy falls into this bucket (AAGUID tracking is new in X3),
  and so does any authenticator that legitimately reports no AAGUID. The
  fixed reason text is *"registered before attestation policy was
  enabled."*
- Under `mode: "none"`, every credential with a recorded AAGUID reports
  **compliant** without an MDS lookup — mirroring the same "nothing is
  requested, nothing to police" guarantee the registration path itself
  gives.

`reason` (when not compliant) is one of the machine-readable denial reasons
also used by registration-time denials and the audit log:
`attestation_required`, `aaguid_blocked`, `aaguid_not_allowed`,
`unknown_authenticator`, `authenticator_revoked`, `not_fido_certified`,
`certification_too_low`.

## Known limitation: `USER_VERIFICATION_BYPASS` is not covered

`block_revoked_status` denies `REVOKED`, `ATTESTATION_KEY_COMPROMISE`,
`USER_KEY_REMOTE_COMPROMISE`, and `USER_KEY_PHYSICAL_COMPROMISE`. It does
**not** cover `USER_VERIFICATION_BYPASS` — an authenticator model with a
known user-verification-bypass advisory in its MDS status history still
passes this check. This was left as specified rather than silently widened
to cover more than the field's name promises. If you need to exclude a
specific model with a UV-bypass advisory, add its AAGUID to
`blocked_aaguids` explicitly.

## Registration denial

When registration is denied by policy, the API returns a fixed,
non-specific error — *"this security key model is not permitted by your
organization"* — never a raw library error string. The machine-readable
reason (one of the values listed under
[Compliance report](#compliance-report) above) goes only to the audit
record (`webauthn.attestation_denied`, carrying the AAGUID and reason), not
to the end user.

## Reference: endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/tenants/{tenant_id}/webauthn/attestation-policy` | Read the tenant's current policy (defaults if no row exists) |
| `PUT` | `/api/v1/tenants/{tenant_id}/webauthn/attestation-policy` | Replace the tenant's policy |
| `GET` | `/api/v1/tenants/{tenant_id}/webauthn/compliance-report` | Evaluate every registered credential against the current policy |
| `POST` | `/api/v1/mds/refresh` | Admin-triggered MDS3 BLOB ingestion |
| `GET` | `/api/v1/mds/status` | Last-ingested BLOB metadata and staleness |

All of the above require an administrative permission on the tenant, on the
same footing as the other tenant security-settings endpoints described in
the [Admin Guide](README.md).
