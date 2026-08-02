# Go SDK benchmark — now wired

The Go SDK bench glue is wired to the real SDK
(`ilpanich/axiam-go-sdk`, module `github.com/ilpanich/axiam-go-sdk`). It times
the four canonical CONTRACT.md §1 ops (`login`, `refresh`, `check_access`,
`batch_check`) and emits one `axiam.sdk-bench/v1` JSON object to stdout
(see `../HARNESS-SPEC.md`).

## Layout
- `go.mod` depends on the SDK via a `replace` directive pointing at the sibling
  checkout (`../../../../axiam-go-sdk`), because the tagged release
  (`v1.0.0-alpha2`) may not be on the module proxy.
- `main.go` is the entrypoint (`package main`, run with `go run .`).
- `run.sh` runs `go mod tidy` defensively (self-heals a stale `go.sum` when
  network access is available; otherwise falls through to the committed
  `go.sum`), then `exec`s `go run .`.

## Running
- `cd benchmarks && just sdk=go sdk-bench`

## H8 status (verified in this environment)
- `go.sum` is now committed (tidied with `go mod tidy` against the sibling
  `axiam-go-sdk` checkout's real transitive deps — 49 lines, live network
  access confirmed this environment can reach the module proxy). Previously
  it was gitignored/absent, which made `go run .` fail with "go: updates to
  go.mod needed; go mod tidy" on any checkout that hadn't run that command by
  hand. `go build ./...` and `go run .` both succeed against the sibling
  checkout as of this fix.
- `BENCH_ORG_SLUG` is now wired: `main.go` never read it or passed
  `axiam.WithOrgSlug(...)`, so every login went out with no org context
  (CONTRACT.md §5.1 requires it) — the only one of the six languages
  validated here missing it (python/typescript/rust/java/csharp/php all
  already had it). `config.orgSlug` now flows into both `axiam.NewClient`
  call sites.
- `BENCH_CA_CERT` is now wired (HARNESS-SPEC.md's documented input for
  trusting a TLS profile's throwaway CA — previously unread, so every p2
  run failed at the first HTTPS call): `config.caCertPath` is read, the PEM
  bytes are loaded in `buildOps`, and `axiam.WithCustomCA(pem)` is appended
  to both `NewClient` call sites' options when set. `run.sh` also resolves
  the (relative) path to absolute before its `cd "$HERE"`, since
  `profiles/*.env` sets it relative to `benchmarks/`.
- Verified `ok`, double-run-clean at both p0-plaintext and p2-tls13 against
  a live seeded target, after the H8(2) server-side CSRF-header-echo fix
  (`crates/axiam-api-rest`) unblocked check_access/refresh in the first
  place.

## p3-mtls (CONTRACT.md §6.1)

Wired: `loadConfig` reads `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` (file paths)
and `buildOps` appends `axiam.WithClientCertificate(certPEM, keyPEM)` to the
same `opts` slice both the shared client and the per-iteration `login` client
are built from, so the identity cannot drift between them.

```
cd benchmarks && just target=axiam profile=p3-mtls sdk=go sdk-bench
just sdk-bench-test go     # proves the cert reaches the wire, no stack needed
```

Verified: phase A (half-configured pair -> `status:"error"` naming both vars)
and phase B (stub mTLS server observes `CN=bench-client`) both pass.
