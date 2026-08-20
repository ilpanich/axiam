# axiam-opaque

AXIAM's OPAQUE ([RFC 9807](https://datatracker.ietf.org/doc/rfc9807/))
ciphersuite, key-stretching functions and **client** operations — the single
implementation every AXIAM client binds.

[![crates.io](https://img.shields.io/crates/v/axiam-opaque.svg)](https://crates.io/crates/axiam-opaque)
[![docs.rs](https://img.shields.io/docsrs/axiam-opaque)](https://docs.rs/axiam-opaque)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

## What OPAQUE buys

In an ordinary password login the plaintext reaches the server inside the TLS
session, and the server hashes it. TLS protects it in transit, but the server
*has* it — so a TLS-terminating proxy, an accidentally verbose request log, or a
heap dump can capture it.

OPAQUE is an augmented PAKE: the client blinds the password, the server
evaluates an oblivious PRF over it without learning either the input or the
output, and the client uses the result to open a sealed envelope holding its
long-term key material. The server never holds a plaintext password.

It also means a **stolen record database is not offline-crackable on its own**.
Recovering a password additionally requires the tenant's OPRF seed, which is
encrypted at rest under a key that is not in the database — so unlike a stolen
password-hash database, there is no dictionary attack to mount at any cost.

What it does **not** do: protect against a compromised AXIAM server. A server
that wants the password can serve a login page that steals it. For browser
clients the benefit is bounded for exactly that reason. The strong case is
native SDK clients, IoT devices, and deployments behind infrastructure the
tenant does not control.

## Why this crate exists

AXIAM speaks OPAQUE from twelve places: the server, the React admin UI, and
eleven client SDKs. Every one of them must agree on every byte, and OPAQUE is
not the kind of protocol that can be hand-written twelve times and be expected
to agree — it needs an oblivious PRF, `hash_to_curve`, `expand_message_xmd`, an
envelope construction and a three-message AKE.

The SRP-6a implementation this replaces *was* hand-written eleven times, because
SRP is modular arithmetic and every language has a bignum. That produced a
bundled Montgomery modular exponentiation in the Swift SDK, a PHP SDK that
reported itself unavailable without `ext-gmp`, and a cross-language conformance
fixture whose job was to catch the drift between eleven implementations of one
protocol. None of that is a criticism of the implementations; it is what
shipping eleven independent implementations of an authentication primitive
costs.

So this crate is the *only* implementation. It is compiled directly into the
Rust SDK and the server, to WebAssembly for the TypeScript SDK and the admin UI
([`axiam-opaque-wasm`](../axiam-opaque-wasm)), and behind a C ABI for the rest
([`axiam-opaque-ffi`](../axiam-opaque-ffi)). That is also why it sits at **layer
0** with no internal dependencies: anything it depended on would become a
dependency of every SDK.

`sdks/CONTRACT.md` §23.1 forbids an SDK from implementing OPAQUE itself, with
one audited exception — the Go SDK uses `github.com/bytemare/opaque`, because
binding this crate's C ABI would force cgo on every consumer and break
`CGO_ENABLED=0` builds. That exception is only safe if the two implementations
actually agree, which `examples/interop.rs` checks rather than assumes.

## What is here, and what is not

**Here:** the ciphersuite, the key-stretching functions, and the four
**client**-side operations. The client half is what needs to exist in every
language.

**Not here:** the server half — key material, sealed sessions, credential
identifiers, lockout attribution. That lives in `axiam-auth` and has no business
being compiled into a client. The one thing the server borrows from this crate
is `AxiamOpaqueSuite`, so that there is exactly one definition of the suite and
the two halves cannot drift.

## The ciphersuite

| Component | Choice |
|---|---|
| OPRF | ristretto255 |
| Key exchange | Triple-DH over ristretto255 with SHA-512 |
| Hash | SHA-512 |
| KSF | `AxiamKsf` — Argon2id (default) or scrypt |

Both KSF variants are memory-hard. The SRP scheme this replaces offered
PBKDF2-HMAC-SHA256 as a fallback purely because three SDK languages had no
usable Argon2id — a constraint one shared implementation removes, so there is no
longer a reason to offer a KSF that a GPU farm enjoys.

KSF parameters live *in the value* rather than in the type, because a credential
enrolled under one cost must keep working after a tenant raises its policy. The
server stores the parameters a record was created with and echoes them at login.

> **A client MUST stretch with the parameters the server named, never with local
> defaults.** Anything else derives a different randomized password and cannot
> open its own envelope.

## Wire encoding

Every protocol message crosses the AXIAM API as lowercase hex, so this crate's
public surface is **hex in and hex out**. That is a deliberate narrowing: a
`&str` API is expressible in every SDK language and across a C ABI without
anyone inventing a byte-buffer convention, and hex has no variant spellings to
disagree about the way base64 does.

## Usage

```rust
use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};

// --- registration ---
let ksf = AxiamKsf::argon2id(19456, 2, 1)?;
let (state, request) = ClientRegistrationState::start(password)?;
// ... POST `request` to /auth/opaque/register/start, receive `registration_response` ...
let record = state.finish(password, &registration_response, &ksf)?;

// --- login ---
let (state, ke1) = ClientLoginState::start(password)?;
// ... POST `ke1` to /auth/opaque/login/start, receive `ke2` AND the KSF parameters ...
let finished = state.finish(password, &ke2, &ksf)?;
// ... POST `finished.ke3` to /auth/opaque/login/finish ...
```

Each state value is **consumed** by `finish`: there is no way to reuse one OPRF
blind across two exchanges.

### Errors are coarse on purpose

`OpaqueError` does not distinguish "wrong password" from "no such account" from
"this server does not hold the record". A client that could tell them apart
would be reporting a fact it cannot actually establish — a wrong password and a
hostile server both surface as an envelope that will not open.

## MSRV

**1.88**, stated explicitly rather than inherited from the workspace (which is
1.93). This crate is vendored into the Rust SDK, whose MSRV is 1.88 and is
CI-enforced; inheriting the workspace floor made that SDK's MSRV job fail on a
requirement nothing in this crate actually has. Raising it is a breaking change
for every SDK that depends on it, and should be a deliberate edit here rather
than a side effect of bumping the server's toolchain.

## Testing

```bash
cargo test -p axiam-opaque
```

`tests/vectors_test.rs` generates and drift-gates
[`sdks/opaque-test-vectors.json`](../../sdks/opaque-test-vectors.json), the
fixture every SDK is checked against. It pins the layer each SDK still owns —
hex in and out, which JSON field goes where, honouring the server's KSF
parameters, and mapping failures onto the CONTRACT §2 error taxonomy — rather
than re-pinning the protocol internals, which are now one library rather than
eleven implementations.

`examples/interop.rs` is the server half of the cross-implementation harness
that checks the Go SDK's independent implementation against this one.

## Related

- [`axiam-opaque-ffi`](../axiam-opaque-ffi) — C ABI, for the SDKs that bind it natively
- [`axiam-opaque-wasm`](../axiam-opaque-wasm) — WebAssembly build, published as `@axiam/opaque-wasm`
- [`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §23 — the cross-language protocol contract
- [`claude_dev/opaque-design.md`](../../claude_dev/opaque-design.md) — design rationale and the operator runbook

## License

Apache-2.0
