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
