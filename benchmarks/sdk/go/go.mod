module axiam-sdk-bench

go 1.25

require github.com/ilpanich/axiam-go-sdk v1.0.0-alpha2

// The tagged release (v1.0.0-alpha2) may not be published to the module proxy,
// so resolve the dependency against the sibling SDK checkout in this monorepo
// layout instead. Path is relative to this directory
// (benchmarks/sdk/go/ -> /home/user/axiam-go-sdk).
//
// No go.sum is committed here (this environment can't fetch the SDK's
// transitive deps). Run `go mod tidy` once, with network access, before
// running this bench for real.
replace github.com/ilpanich/axiam-go-sdk => ../../../../axiam-go-sdk
