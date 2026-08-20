# Secure Remote Password (SRP-6a) — design and operator runbook

Status: implemented. Server, React admin UI, and all eleven SDKs.
Contract: `sdks/CONTRACT.md` §23. Vectors: `sdks/srp-test-vectors.json`.

---

## 1. Why

AXIAM mandates TLS 1.3 for external traffic, which protects a password against a
network attacker. It does nothing about the places a password is exposed *at the
endpoints*, and in a multi-tenant deployment the tenant frequently does not own
those endpoints:

- **A TLS-terminating hop sees plaintext.** A reverse proxy, ingress controller,
  CDN or service mesh sidecar decrypts the request body. Every one of them sees
  the password today. Under SRP it sees `A` and `M1`, which are useless without
  the verifier.
- **Logs and dumps.** An accidentally verbose access log, a heap dump captured
  during an incident, or a crash reporter can capture a plaintext password. Under
  SRP there is no plaintext to capture — the server never has one.
- **Insider access at the edge.** Whoever can read proxy logs can read passwords.

What it does **not** do, and what no AXIAM documentation may claim it does:

- It does not protect against a compromised AXIAM server. A server that wants the
  password can serve a login page that steals it.
- **For browser clients specifically, the benefit is bounded**, because AXIAM
  serves the JavaScript that performs the SRP computation. The strong case is
  native SDK clients, IoT devices, and any deployment sitting behind
  infrastructure the tenant does not control.
- A leaked verifier database is not harmless. It is roughly as attackable as a
  leaked Argon2id database — which is the bar we had to *meet*, not clear, and is
  the whole reason for the KDF decision in §3.

### Why not OPAQUE

OPAQUE is the CFRG-selected aPAKE and is cryptographically stronger: it has a
security proof, uses standard elliptic curves, and resists the pre-computation
attack SRP is open to. It was not chosen because vetted implementations do not
exist across all eleven SDK languages, and an authentication protocol that only
six SDKs can speak is not a protocol this project can adopt.

The wire format is versioned (`group`, `kdf`) so an OPAQUE mode can be added
later without breaking deployed clients. If OPAQUE library coverage improves,
that is the migration path.

---

## 2. Why `required` cannot be a global switch

A verifier is `v = g^x mod N` where `x = KDF(identity ":" password, salt)`. Both
need the **plaintext password**.

A stored Argon2id hash is, by construction, not invertible. There is therefore no
migration that mints verifiers for an existing user base. A verifier can only
come into existence at a moment when the plaintext is legitimately in hand:

| Moment | Endpoint |
|---|---|
| user creation | `POST /api/v1/users` |
| authenticated password change | `POST /api/v1/auth/password/change` |
| password-reset completion | `POST /api/v1/auth/reset/confirm` |
| first-run bootstrap | `POST /api/v1/admin/bootstrap` |

This is why the three modes exist and why `required` is the last step of a
migration rather than a switch an operator flips on a whim.

### Why `required` is tenant-wide rather than per-user

The obvious design refuses password login only for users who *have* a verifier,
so that unenrolled users keep working. It was rejected: it makes `/auth/login`
an enumeration oracle. An attacker sending one junk password per candidate name
would get `403 srp_required` for enrolled accounts and `401` for everything else,
learning which accounts exist and are enrolled without ever guessing a password.

A uniform refusal reveals a property of the tenant, which is not a secret, and
nothing about any individual. The cost is that `required` locks out anyone not
yet enrolled — which is real, and is why the coverage query in §5 exists.

---

## 3. Divergences from RFC 5054

Both are deliberate and both are recorded at the call site in
`crates/axiam-auth/src/srp.rs`.

**SHA-256, not SHA-1.** RFC 5054 §2.6 specifies SHA-1. AXIAM does not use SHA-1
anywhere and does not start here.

**`x` is a memory-hard KDF output, not a bare hash.** RFC 5054 defines
`x = H(s | H(I ":" p))`. With a bare hash, a leaked verifier database is
*cheaper* to attack offline than the Argon2id password hashes AXIAM stores
today — so adopting SRP as specified would have been a net security regression at
rest. Instead:

```
x = OS2IP(KDF(identity ":" password, salt)) mod N
```

The identity stays inside the KDF input exactly as RFC 5054 intends, so a
verifier remains bound to one identity and cannot be replayed against another
account.

**Two KDFs, negotiated per exchange.** `argon2id` (preferred, parameters
mirroring `password::hash_password`: m=19456 KiB, t=2, p=1) and
`pbkdf2_sha256` (600 000 iterations, OWASP 2023). PBKDF2 exists because Swift,
and Java/Kotlin and C# without pulling a third-party crypto library into an
authentication path, have no vetted Argon2 binding in their standard
distribution. Shipping SRP that only half the SDKs could speak would have been
worse than shipping a weaker-but-universal fallback.

---

## 4. Implementation notes worth knowing

### Sealed session, not a session table

Between the two messages the server must remember what it derived. Rather than a
`srp_session` table with a TTL, the derived state is sealed into an AES-256-GCM
token the client carries back — the same pattern the MFA challenge already uses.

- Works across replicas with no coordination; no write and read on the login hot
  path.
- Nothing to garbage-collect; expiry is a field inside the blob.
- A replayed token grants no new power: opening it needs the server key, and
  *using* it still needs `M1`, which still needs the password. An attacker who
  can replay a captured `(srp_session, M1)` pair has already broken TLS, at which
  point they have the session cookie the exchange would have produced anyway. The
  120-second lifetime bounds even that.

### Constant-time properties, stated precisely

`num_bigint::BigUint::modpow` is **not** constant-time. What that does and does
not expose:

- The verifier `v` — the only long-term secret — is used as a *base*
  (`v.modpow(&u, n)`), never as an exponent. Exponent-dependent timing is the
  leak `modpow` has; `v` is not exposed by it.
- The exponent `b` is fresh per request and discarded when the exchange ends.
- The password never reaches the module in any form.
- The `M1` comparison uses `subtle::ConstantTimeEq` over raw bytes, not hex text.

### Account enumeration

`/auth/srp/challenge` returns a well-formed `200` for identities that do not
exist. The fabricated salt is `HMAC(server_key, "srp-fake-salt" | tenant | identity)`
so it is **stable** — a random salt per attempt would announce non-existence as
loudly as a `404`. The full modular exponentiation runs in that branch too, so
timing matches.

### `A ≡ 0 (mod N)` is refused

The classic SRP break. `A ≡ 0` forces `S = 0` server-side for any `b`, so an
attacker who sends it can compute `K` and forge `M1` with no password at all.
Tested at both the library and HTTP boundaries.

### Lockout

A wrong `M1` is a wrong password and accrues toward lockout exactly as a failed
Argon2id verify does. This needed `SrpRejection::BadProof` to carry the identity;
the first implementation collapsed every failure into one opaque error, which
meant enabling SRP would have silently removed brute-force protection from every
account that adopted it.

### Renames invalidate verifiers

`x` is derived over `username ":" password`. Renaming a user leaves a verifier
that answers challenges no client can satisfy — "invalid credentials" for an
entirely correct password. `PUT /api/v1/users/{id}` therefore drops the verifier
on a username change, making the state honest: no verifier, so the account is
reported as unenrolled.

---

## 5. Operator runbook

### Configuration

```bash
# 256-bit key sealing the SRP exchange's server state. REQUIRED whenever any
# org or tenant has srp_mode != disabled.
export AXIAM__AUTH__SRP_SESSION_KEY="$(openssl rand -hex 32)"
```

Absent, the SRP endpoints answer `503` **regardless of policy**. That is
deliberate: falling back to password login when the key is missing would turn a
misconfiguration into an undetectable downgrade of a control the operator
believes is on.

Rotating the key invalidates in-flight exchanges only (120-second window).
Verifiers are unaffected — the key seals session state, not credentials.

### Migration: `disabled` → `optional` → `required`

**Step 1 — turn it on as optional.**

```bash
curl -X PUT "$AXIAM/api/v1/settings/org" -H 'Content-Type: application/json' \
  -d '{ ..., "srp_mode": "optional", "srp_group": "rfc5054_4096", "srp_kdf": "argon2id" }'
```

Clients that speak SRP start using it. Clients that do not keep working. Every
password change from now on records a verifier.

**Step 2 — drive coverage to 100%.** A verifier appears only when a password is
set, so an estate migrates at the rate users rotate credentials. To finish it,
run a password-reset campaign. Check progress with the coverage figure backing
`SrpCredentialRepository::count_for_tenant` and compare it against the tenant's
user count.

**Do not skip this step.** `required` locks out every user without a verifier,
and nobody can be enrolled retroactively.

**Step 3 — require it**, once coverage is complete:

```bash
curl -X PUT "$AXIAM/api/v1/settings/org" -d '{ ..., "srp_mode": "required" }'
```

`/auth/login` now answers `403 srp_required` for every principal in the tenant.

### Fresh deployments

A deployment that must be SRP-only from day one passes the policy and the admin's
verifier to bootstrap in one call — see `POST /api/v1/admin/bootstrap`'s
`srp_mode` / `srp` fields. Bootstrap **refuses** `srp_mode: required` without a
verifier, because that combination produces a deployment whose only administrator
cannot authenticate by any route and which nobody has the access to repair.

### Rollback

`srp_mode` back to `optional` restores password login immediately; verifiers are
retained and keep working. Back to `disabled` also stops new enrolments.
Nothing is destroyed by either move.

---

## 6. Cross-language conformance

Eleven independent SRP implementations will not interoperate by accident.
`sdks/srp-test-vectors.json` is generated from the server implementation by
`crates/axiam-auth/tests/srp_vectors_test.rs`, which also drift-gates it, and is
vendored into every SDK repository alongside `CONTRACT.md` and `openapi.json`.

Two fixture choices are load-bearing:

- **The salt and `x` both begin with a zero byte.** An implementation that skips
  `PAD()` agrees with everyone else until a value carries a leading zero, then
  fails roughly one login in 256 in a way that reads as a flaky network. These
  vectors fail it immediately instead.
- **One identity is non-ASCII (`renée`).** An SDK hashing a platform-default
  encoding rather than UTF-8 fails here rather than for one unlucky user.

Every intermediate is pinned — `k`, `v`, `A`, `B`, `u`, `S`, `K`, `M1`, `M2` —
not just the final proof, so an SDK that gets `u` wrong finds out at `u`.

Regenerate with:

```bash
UPDATE_SRP_VECTORS=1 cargo test -p axiam-auth --test srp_vectors_test
```

and re-sync into all eleven SDK repositories. A change here without that fan-out
is a silent cross-language break.
