# OPAQUE (RFC 9807) — design and operator runbook

Status: implemented. Server, React admin UI, and all eleven SDKs.
Contract: `sdks/CONTRACT.md` §23. Fixtures: `sdks/opaque-test-vectors.json`.
Replaces: `srp-design.md` (SRP-6a), removed in the same change.

---

## 1. Why we replaced SRP

AXIAM shipped SRP-6a first. The reasoning in the SRP design document was sound
at the time and is worth reading before this one, because most of it carries
over unchanged: the threat model, the three enforcement modes, and the argument
for why `required` is tenant-wide are identical.

Three things changed.

**RFC 9807.** OPAQUE was a CFRG draft when SRP was chosen. It was published as
RFC 9807 in July 2025, with a byte-level specification and published test
vectors. `srp-design.md` §1 listed "vetted implementations do not exist across
all eleven SDK languages" as the blocker, and named improving library coverage
as the migration trigger. That trigger fired.

**Pre-computation resistance.** This is the substantive cryptographic argument
and it is not a small one. A stolen SRP verifier database is offline-attackable
at exactly the cost of the KDF. That is why AXIAM's SRP had to bolt a
memory-hard KDF onto RFC 5054's bare hash — not to be better than Argon2id, but
to *match* it, because adopting SRP as specified would have been a net
regression at rest. OPAQUE's OPRF removes the offline attack rather than
repricing it: recovering a password from a stolen record additionally requires
the tenant's OPRF seed, and without it there is no dictionary attack to mount at
any cost.

**One implementation instead of eleven.** SRP is modular arithmetic and every
language has a bignum, so every SDK hand-wrote it. That produced a bundled
Montgomery modular exponentiation over `[UInt64]` limbs in the Swift SDK, a PHP
SDK whose `srpAvailable()` returned `false` without `ext-gmp`, and a
cross-language fixture whose job was to catch the drift between eleven
implementations of one protocol. None of that was a mistake by the people who
wrote it; it is what eleven independent implementations of an authentication
primitive cost.

OPAQUE cannot be hand-written that way — it needs an OPRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE — so this
migration also changes *how* SDKs get their implementation. See §6.

### What OPAQUE does not do

Unchanged from the SRP document, and still the thing not to overclaim:

- It does not protect against a compromised AXIAM server. A server that wants
  the password can serve a login page that steals it.
- **For browser clients the benefit is bounded**, because AXIAM serves the code
  that performs the computation. The strong case is native SDK clients, IoT
  devices, and deployments behind infrastructure the tenant does not control.
- It closes the same holes SRP did: a TLS-terminating proxy, an accidental
  request-body log, a heap dump. That was always the point, and it is unchanged.

---

## 2. What the migration deleted

Worth listing, because "we replaced a protocol" usually means net new code.

| Gone | Why |
|---|---|
| `server_proof` on the login response | RFC 9807's AKE authenticates the server during the handshake. SRP needed the client to verify `M2` or it kept only half the protocol, and CONTRACT §23.3 rule 6 had to say so in capitals. An SDK can no longer forget. |
| `invalidate_on_rename` and its extra read | SRP derived `x` over `username ":" password`, so `PUT /users/{id}` had to detect a rename and drop the verifier. OPAQUE binds to a random server-chosen identifier. |
| The username in `/auth/reset/context` | That endpoint existed largely to tell an unauthenticated reset page which username SRP had bound `x` to. |
| `pbkdf2_sha256` | It existed only because PHP, Swift and pre-3.2 OpenSSL had no usable Argon2id. One shared core removes the constraint; the weaker rung is now scrypt, which is memory-hard. |
| CONTRACT 1.25's errata | Four SDKs could not compute an interoperable `argon2id` at all. That whole paragraph, and the tenant-wide KDF weakening it forced, is moot. |
| Eleven hand-written PAKE implementations | Replaced by one audited crate. |

Nothing was migrated, and nothing needed to be. An SRP verifier cannot be
converted into an OPAQUE record — both are sealed against the plaintext, which
the server has never had — and AXIAM is unreleased, so no deployment holds
verifiers worth carrying.

---

## 3. Configuration

Deliberately the same shape as SRP's: an organization baseline that a tenant may
tighten but never relax, over three fields.

| SRP | OPAQUE | Values |
|---|---|---|
| `srp_mode` | `opaque_mode` | `disabled` (default) < `optional` < `required` |
| `srp_group` | `opaque_suite` | `ristretto255_sha512` |
| `srp_kdf` | `opaque_ksf` | `scrypt` < `argon2id` (default) |

`opaque_suite` ships with one value. RFC 9807 also defines a P-256/SHA-256
profile, which is the slot a FIPS deployment would want; it is not shipped
because every additional suite multiplies the cross-language conformance
surface, and nothing in AXIAM's compliance targets requires P-256 today. The
field, its explicit `rank()` and the tighten-only check are kept live so that
adding it later is an additive change to a working lattice rather than a schema
and policy break.

### Why `required` cannot be a global switch

Unchanged from SRP, and for the same reason. A record can only come into
existence at a moment when the plaintext password is legitimately in hand on the
client:

| Moment | Endpoint |
|---|---|
| user creation | `POST /api/v1/users` |
| authenticated password change | `POST /api/v1/auth/password/change` |
| password-reset completion | `POST /api/v1/auth/reset/confirm` |
| first-run bootstrap | `POST /api/v1/admin/bootstrap` |

A stored Argon2id hash is not invertible, so nobody can be enrolled
retroactively.

### Why `required` is tenant-wide rather than per-user

Also unchanged, and the argument is worth repeating because it is the one people
try to "fix". Refusing password login only for users who *have* a record makes
`/auth/login` an enumeration oracle: one junk password per candidate name
distinguishes `403` from `401` and reveals which accounts exist and are enrolled.
A uniform refusal reveals a property of the tenant, which is not a secret, and
nothing about any individual.

---

## 4. Implementation notes worth knowing

### Per-tenant key material, and the rotation hazard

Each tenant has an `opaque_server_setup` row holding a serialized RFC 9807
`ServerSetup` — the OPRF seed and the long-term AKE key pair — plus a decoy key,
both AES-256-GCM encrypted at rest alongside CA private keys and MFA secrets.

Scoped per tenant to match AXIAM's isolation model: one tenant's stolen seed
tells an attacker nothing about another's records.

**Rotating a tenant's `ServerSetup` destroys every record in that tenant.** The
OPRF seed is an input to the key that seals each envelope, so a new seed makes
every existing envelope unopenable and every user in the tenant needs a password
reset. This is sharper than anything in the SRP design, where the session key
sealed only 120 seconds of in-flight state. It is why the repository exposes
`get`/`get_or_create` and no `update` or `delete`.

`get_or_create` derives the row id from `(tenant, suite)` rather than randomly,
so two concurrent first logins address the same row and the loser of the race
re-reads instead of writing a second seed. A tenant with two seeds would have
records that only sometimes open — an intermittent wrong password, which is the
kind of defect that takes weeks to find.

### Two server keys, split by what rotating them costs

- `opaque_session_key` seals 120 seconds of in-flight exchange state. Rotate it
  whenever you like; it invalidates exchanges in flight and nothing else.
- `opaque_setup_key` encrypts the `ServerSetup` rows above. Rotating it means
  re-encrypting those rows. **Losing it** means every record in every tenant is
  unopenable.

Sharing one key would put the cheap rotation and the catastrophic one on the
same schedule, which is how an operator ends up doing neither. Both absent, or
either absent, and the OPAQUE endpoints answer `503` regardless of policy —
falling back to password login on a misconfiguration would turn it into an
undetectable downgrade of a control the operator believes is on.

### Where the keys come from, and why the seeds are in the database

This is the question the design gets asked most, so it is worth answering
precisely.

**The seeds are in the database. The key is not.** `opaque_server_setup` rows
hold AES-256-GCM ciphertext; the setup key is supplied by a
[`SecretProvider`](../crates/axiam-core/src/secrets.rs) and never written to
SurrealDB. Every vector OPAQUE's pre-computation resistance is *for* — SQL
injection, a stolen backup, a compromised read replica, a DBA or cloud provider
with storage access, a decommissioned disk — yields ciphertext and no key.

A frequent suggestion is to move the seeds to an encrypted file on the server
volume instead. That is **not** an improvement, and it is worth being explicit
about why:

- It removes the separation rather than adding one. An attacker who can read
  `/var/lib/axiam/seeds.enc` can generally also read `/proc/<pid>/environ`. The
  ciphertext ends up on the *same* side of the boundary as the key.
- It breaks horizontal scaling. Seeds are minted on first use per tenant, so a
  tenant created on replica A would be unopenable on replica B until some
  out-of-band sync caught up — presenting as an intermittent wrong password.
- It loses transactionality with the `opaque_credential` rows the seeds belong
  to, and the replication, backup and restore the database already provides.
- It creates a failure mode that did not exist: a lost or corrupted volume
  becomes total tenant lockout, with no database backup to restore from.

What *does* improve things is changing where the **key** comes from, which is
why that is the pluggable part:

| Provider | `AXIAM__AUTH__SECRET_PROVIDER` | What it is actually good for |
|---|---|---|
| Environment | `env` (default) | Simplicity. What every existing deployment does. |
| Mounted file | `file` | Docker secrets and Kubernetes `Secret` volumes, which mount files rather than inject variables. **Not** a security improvement over `env` — same trust boundary. |
| HashiCorp Vault | `vault` | The key is never in a container spec, a Compose file, a CI variable or a shell history; access is authenticated per workload, audited and revocable; rotation is a write to Vault rather than a redeploy. |

The `vault` provider fetches at startup and serves from memory, so a KMS is
never on a login path and a KMS outage fails the process at boot rather than
degrading logins an hour later.

None of the three defends against a compromised *application server*: the key
must reach the process to decrypt anything. The construction that would is
envelope encryption against a Transit-style API where the plaintext key never
leaves the KMS — every seal and open becomes a network round trip. That is the
natural next implementation of the same trait, and deliberately not this change.

```bash
# Default: unchanged from before this feature existed.
export AXIAM__AUTH__OPAQUE_SESSION_KEY="$(openssl rand -hex 32)"
export AXIAM__AUTH__OPAQUE_SETUP_KEY="$(openssl rand -hex 32)"

# Docker/Kubernetes secret volumes.
export AXIAM__AUTH__SECRET_PROVIDER=file
export AXIAM__AUTH__SECRET_DIR=/run/secrets      # expects files named
                                                  # opaque_session_key, opaque_setup_key

# HashiCorp Vault KV v2.
export AXIAM__AUTH__SECRET_PROVIDER=vault
export AXIAM__AUTH__VAULT_ADDR=https://vault.internal:8200
export AXIAM__AUTH__VAULT_TOKEN=...              # a token with read on the path below
export AXIAM__AUTH__VAULT_MOUNT=secret           # optional, defaults to `secret`
export AXIAM__AUTH__VAULT_PATH=axiam             # optional, defaults to `axiam`
```

An unknown provider name is refused at startup rather than falling back to
`env`: a typo would otherwise silently revert a deployment to reading variables
that are probably unset, which presents as "OPAQUE stopped working" with nothing
in the logs pointing at the cause.

### Sealed session, not a session table

Unchanged from SRP: the state between the two messages of each exchange is
sealed into an AES-256-GCM token the client carries back, rather than stored.
Works across replicas with no coordination, nothing to garbage-collect, and a
replayed token grants no new power because using it still requires a valid `KE3`.

New: registration and login sessions are sealed under the same key but carry
distinct `kind` tags checked on open, so a token minted by one exchange cannot
be presented to the other. Both directions are tested.

### Credential identifiers

Each record is keyed by a random 32-byte `credential_identifier`, generated
server-side at enrolment and never derived from any human-readable name. Two
consequences:

- A rename is free.
- A password change mints a fresh identifier, so the new record is unlinkable
  from the old one even to somebody holding both database dumps.

The client never sees it and never needs it — it keys the server's OPRF only —
so `login/start` does not return it. This is a real difference from SRP, whose
challenge *had* to carry the canonical `identity` because that string was inside
the client's key derivation.

### Account enumeration

`/auth/opaque/login/start` returns a well-formed `200` for identities that do not
exist. RFC 9807 designs this case in and `opaque-ke` implements it: passing
`password_file: None` to `ServerLogin::start` produces a `KE2` of identical shape
from the setup's dummy public key. Under SRP this needed hand-built machinery — a
fabricated-but-stable HMAC salt and a dummy verifier chosen so the modular
exponentiation cost matched.

What AXIAM adds is the *stability* half: the decoy credential identifier is
`HMAC(decoy_key, tenant_id || lowercased identity)`, so probing the same
non-existent name twice gets the same answer. A random identifier would announce
non-existence as loudly as a `404`.

**One residual, stated rather than hidden.** The KSF parameters returned for a
decoy are the tenant's *current* policy, while a real user carries whatever they
enrolled under. An attacker who knows a tenant changed its KSF cost, and who can
find a user still on the old cost, learns that that account exists. The window
closes as users rotate passwords, it requires knowledge of the tenant's policy
history, and it is the same residual the SRP design carried for the same reason.

### Lockout

A failed `KE3` is a wrong password and accrues toward lockout exactly as a failed
Argon2id verify does. This is why `OpaqueRejection` has two variants rather than
one: the caller cannot accrue an attempt it cannot attribute. Collapsing them —
the obvious shape — would mean enabling OPAQUE silently removed brute-force
protection from every account that adopted it.

### Client errors are not server errors

`AuthError::OpaqueMalformed` (→ `400`) is separate from `AuthError::Crypto`
(→ `500`), with distinct hex decoders for client-supplied input and for values
read back from storage. A malformed `KE1` is the caller's mistake; a stored
record that will not parse is AXIAM's own corruption. The first version of this
code collapsed them, and a client sending junk got a `500` — which reads as "the
server is broken" in every dashboard and pager rule an operator has.

### Bootstrap runs both halves itself

`POST /api/v1/admin/bootstrap` takes no `opaque` object, unlike every other
enrolment path. It already receives the plaintext password — it has to, to
compute the Argon2id hash — so the "server never sees it" property was never held
there. The SRP version still asked the client for a verifier, but that bought
nothing: the password was in the same request body.

So bootstrap runs the client half of the registration itself, from the password
it already holds. This keeps bootstrap a single call. A client-built record would
have needed either a second endpoint that creates the organization before
bootstrap does, or a three-call first-run flow, in exchange for a property the
endpoint cannot have.

An operator who wants a record the server provably never had material for changes
the admin password once after bootstrap, through `/auth/password/change`, which
is client-built like every other path.

Bootstrap still refuses `opaque_mode` other than `disabled` when the server keys
are absent, because that combination produces a deployment whose only
administrator cannot authenticate and which nobody has the access to repair.

---

## 5. Operator runbook

### Configuration

```bash
# Seals in-flight exchange state. Cheap to rotate.
export AXIAM__AUTH__OPAQUE_SESSION_KEY="$(openssl rand -hex 32)"
# Encrypts per-tenant OPRF seeds at rest. Back this up. Losing it means every
# user in every tenant needs a password reset.
export AXIAM__AUTH__OPAQUE_SETUP_KEY="$(openssl rand -hex 32)"
```

Either absent and the OPAQUE endpoints answer `503`, whatever the policy says.
Half-configured is logged as a warning at startup, because an operator who set
one of the two almost certainly believes OPAQUE is on.

### Migration: `disabled` → `optional` → `required`

**Step 1 — turn it on as optional.**

```bash
curl -X PUT "$AXIAM/api/v1/settings/org" -H 'Content-Type: application/json' \
  -d '{ ..., "opaque_mode": "optional", "opaque_suite": "ristretto255_sha512", "opaque_ksf": "argon2id" }'
```

Clients that speak OPAQUE start using it. Clients that do not keep working.
Every password change from now on records a credential.

**Step 2 — drive coverage to 100%.** A record appears only when a password is
set, so an estate migrates at the rate users rotate credentials. To finish it,
run a password-reset campaign. Check progress against
`OpaqueCredentialRepository::count_for_tenant` and the tenant's user count.

**Do not skip this step.** `required` locks out every user without a record, and
nobody can be enrolled retroactively.

**Step 3 — require it**, once coverage is complete:

```bash
curl -X PUT "$AXIAM/api/v1/settings/org" -d '{ ..., "opaque_mode": "required" }'
```

`/auth/login` now answers `403 opaque_required` for every principal in the
tenant.

### Fresh deployments

A deployment that must be OPAQUE-only from day one passes `opaque_mode` to
`POST /api/v1/admin/bootstrap`. No verifier field is needed — see §4.

### Rollback

`opaque_mode` back to `optional` restores password login immediately; records are
retained and keep working. Back to `disabled` also stops new enrolments. Nothing
is destroyed by either move.

**What is not a rollback:** deleting an `opaque_server_setup` row. That destroys
every record in the tenant.

---

## 6. Cross-language strategy, and why the fixture shrank

Eleven independent OPAQUE implementations would not interoperate by accident,
and — unlike SRP — they could not reasonably be written at all. So there is one
implementation, `crates/axiam-opaque`, and every client binds it:

| SDK | How |
|---|---|
| Rust | direct crate dependency |
| TypeScript, React admin UI | WebAssembly |
| Go | native `github.com/bytemare/opaque` (RFC 9807), kept native to avoid forcing cgo on every consumer |
| Python, Java, Kotlin, C#, PHP, Swift, C, C++ | the crate's C ABI |

`axiam-opaque` sits at layer 0 with no internal dependencies, because anything
it depended on would become a dependency of every SDK. It also owns the *only*
definition of the ciphersuite; `axiam-auth`'s server half imports it rather than
declaring its own, so the two halves cannot drift.

### The Go exception, and how it is kept honest

Go is the one SDK permitted a native implementation. The justification has two
halves and both are required: a vetted RFC 9807 library exists for it, and
binding the C ABI would force cgo on every consumer, breaking `CGO_ENABLED=0`
builds. Any future exception needs the same two.

That leaves one real risk — that the two implementations disagree. "Both say
RFC 9807" is not evidence: they must agree on the OPRF, the key schedule, the
envelope, the AKE transcript **and** the KSF parameters, of which only the first
four are in the specification. The KSF is where it would actually break, because
`opaque-ke` stretches with a 16-byte all-zero salt and a 64-byte output, and
nothing in the RFC says it must.

So it is checked rather than assumed. `cargo run -p axiam-opaque --example
interop` is the server half of a harness the Go SDK's interop test drives; a
verified run completes a full registration and login across the two
implementations with matching message widths at every step (32, 192, 96, 320,
64) and an envelope that opens. A failure there means one side moved, and the
right response is to find out which — not to loosen the test.

`sdks/opaque-test-vectors.json` is correspondingly smaller than the SRP fixture,
and the change is deliberate. The SRP file pinned every protocol intermediate
because eleven implementations had to agree on each one. No SDK computes any of
those any more, so re-pinning them would be eleven copies of one test of one
library. What each SDK still owns, and can still get wrong, is the layer around
the protocol: hex in and out, which JSON field goes where, honouring the KSF
parameters the server named rather than its own defaults, and mapping failures
onto the §2 error taxonomy. That is what the fixture pins.

One thing an SDK cannot do locally is complete a real exchange: OPAQUE is
randomized and the blind is generated inside the core, so no pre-recorded server
response matches a fresh `KE1`. Round-trip correctness is asserted in
`axiam-opaque` and in `axiam-api-rest`'s end-to-end tests, against a real
server, rather than eleven times against a fixture.

Regenerate with:

```bash
UPDATE_OPAQUE_VECTORS=1 cargo test -p axiam-opaque --test vectors_test
```

and re-sync into all eleven SDK repositories. A change here without that fan-out
is a silent cross-language break.
