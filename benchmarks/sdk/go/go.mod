module axiam-sdk-bench

go 1.26

require github.com/ilpanich/axiam-go-sdk v1.0.0-alpha2

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/nistec v0.0.4 // indirect
	github.com/bytemare/ecc v0.9.0 // indirect
	github.com/bytemare/hash v0.6.2 // indirect
	github.com/bytemare/hash2curve v0.5.4 // indirect
	github.com/bytemare/ksf v0.5.0 // indirect
	github.com/bytemare/opaque v0.18.0 // indirect
	github.com/bytemare/secp256k1 v0.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gtank/ristretto255 v0.2.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.3.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/jwx/v3 v3.2.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/grpc v1.83.2 // indirect
)

// The tagged release (v1.0.0-alpha2) may not be published to the module proxy,
// so resolve the dependency against the sibling SDK checkout in this monorepo
// layout instead. Path is relative to this directory
// (benchmarks/sdk/go/ -> /home/user/axiam-go-sdk).
//
// H8: go.sum IS committed (tidied via `go mod tidy` with network access) and
// pins the transitive deps pulled in through the `replace` above. run.sh also
// runs `go mod tidy` defensively before `go run .`, so a go.sum drift (e.g.
// the sibling SDK's own deps changed) self-heals instead of hard-failing with
// "go: updates to go.mod needed; go mod tidy".
replace github.com/ilpanich/axiam-go-sdk => ../../../../axiam-go-sdk
