# axiam-opaque-wasm

WebAssembly build of AXIAM's OPAQUE (RFC 9807) client, published to npm as
`@axiam/opaque-wasm` and consumed by the TypeScript SDK and the React admin UI.

## Why this exists

`sdks/CONTRACT.md` §23.1 forbids an SDK from implementing OPAQUE itself. SRP was
hand-written eleven times because it is modular arithmetic and every language
has a bignum; OPAQUE needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE. So there
is one implementation — `crates/axiam-opaque` — and this crate is how JavaScript
reaches it.

## Building

```bash
wasm-pack build --target web --release crates/axiam-opaque-wasm
```

Not a Cargo workspace member on purpose: it only ever builds for `wasm32`, and
including it would make a plain `cargo test` at the repository root try to
compile `wasm-bindgen` for the host.

## Usage

```js
import init, { OpaqueLogin, OpaqueKsf } from "@axiam/opaque-wasm";

await init();

// 1. Blind the password and start the exchange.
const login = new OpaqueLogin(password);
const started = await postJson("/api/v1/auth/opaque/login/start", {
  org_slug, tenant_slug, username_or_email, ke1: login.ke1,
});

// 2. Build the KSF from what the SERVER named — never from local defaults.
const ksf = started.ksf === "argon2id"
  ? OpaqueKsf.argon2id(started.memory_kib, started.iterations, started.parallelism)
  : OpaqueKsf.scrypt(started.log_n, started.r, started.p);

// 3. Open the envelope. A throw here means wrong password, unknown account,
//    or a server that does not hold the record — indistinguishable by design,
//    and nothing further may be posted.
const finished = login.finish(password, started.ke2, ksf);

await postJson("/api/v1/auth/opaque/login/finish", {
  opaque_session: started.opaque_session,
  ke3: finished.ke3,
});
```

`login` is **consumed** by `finish`: a second call throws rather than reusing
one OPRF blind across two exchanges.

## What this does not do

It performs no HTTP. Endpoint selection, cookie handling and error mapping
belong to the SDK or application that calls it — see CONTRACT §23.4 and §23.5.
