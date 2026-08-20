# axiam-opaque-ffi

C ABI for AXIAM's OPAQUE ([RFC 9807](https://datatracker.ietf.org/doc/rfc9807/))
client. Eight SDKs bind this rather than implementing OPAQUE: **Python, Java,
Kotlin, C#, PHP, Swift, C and C++.**

## Why this exists

`sdks/CONTRACT.md` §23.1 forbids an SDK from implementing OPAQUE itself. There
is one implementation — [`axiam-opaque`](../axiam-opaque) — and this crate is
how the non-Rust, non-WebAssembly languages reach it. JavaScript reaches it
through [`axiam-opaque-wasm`](../axiam-opaque-wasm) instead; Go is the single
audited exception, using `github.com/bytemare/opaque` because binding this ABI
would force cgo on every consumer and break `CGO_ENABLED=0` builds.

## Shape of the interface

Everything crosses the boundary as **NUL-terminated lowercase hex**, which is
also the AXIAM wire encoding. A `const char *` API is expressible in all eight
languages without anyone inventing a byte-buffer ownership convention, and hex
has no variant spellings to disagree about the way base64 does. The cost is a
constant factor on messages that top out at 320 bytes.

## Rules an integrator must follow

1. **Every non-null `char *` returned by this library must be released with
   `axiam_opaque_string_free`.** It was allocated by Rust and cannot be freed by
   the caller's allocator.
2. **Every state handle must be released** — either by passing it to its
   `finish` function, which consumes it, or by calling the matching `_free`. A
   handle is single-use; `finish` takes ownership, so calling it twice is not
   expressible.
3. **A `NULL` return means failure.** `axiam_opaque_last_error` returns a
   description for the calling thread. It is deliberately coarse: a caller that
   could distinguish "the server sent a malformed KE2" from "your password is
   wrong" would be reporting a fact it cannot establish.

## Thread safety and panics

Every function is safe to call from any thread. State handles are **not** shared
— a handle belongs to one in-flight exchange and must be used by one thread at a
time. The last-error slot is thread-local, so an error raised on one thread is
never observed on another.

Every entry point is wrapped so that a Rust panic becomes a `NULL` return rather
than an unwind across the ABI boundary, which would be undefined behaviour.

## Building

```bash
cargo build -p axiam-opaque-ffi --release
```

Produces `cdylib` and `staticlib` artifacts. The `cdylib` is for SDKs that
dlopen or link dynamically (PHP's `ext-ffi`, C#'s P/Invoke, Python's cffi,
Java's FFM); the `staticlib` is for the C and C++ SDKs, which prefer to vendor.

The library file is `libaxiam_opaque_ffi.{so,dylib,dll}` — deliberately not
named `axiam_opaque`, since that is the crate this one wraps. The exported C
symbols are `axiam_opaque_*` regardless of the filename.

## Related

- [`axiam-opaque`](../axiam-opaque) — the implementation this exposes
- [`axiam-opaque-wasm`](../axiam-opaque-wasm) — the WebAssembly build, for JavaScript
- [`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §23 — the cross-language protocol contract

## License

Apache-2.0
