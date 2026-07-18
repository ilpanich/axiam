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
- `run.sh` `exec`s `go run .`.

## Running
- `cd benchmarks && just sdk=go sdk-bench`

## Before running for real
- No `go.sum` is committed (this environment can't fetch the SDK's transitive
  deps). Run `go mod tidy` once, with network access, to generate it.
