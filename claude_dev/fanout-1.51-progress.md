# Fan-out 1.51 — resume ledger (C-2 … C-11)

Temporary. Exists only so an interrupted orchestrator session can resume the fan-out of
`dogfooding-findings-fix-plan.md` §6 (C-2 … C-11). Deleted in the final records commit,
once every port PR is merged or closed.

- Reference: C-1, [ilpanich/axiam-rust-sdk#115](https://github.com/ilpanich/axiam-rust-sdk/pull/115), merged `8e9eb90`.
- Re-vendor source: axiam `56fbe44`. `CONTRACT.md` sha256 `0ac7fd75f83cc1ed8002a2e9a503cfc9027c1176070f3b37090bc75521890e42`.
  Every SDK vendors 1.48 (`d877a1a05e9a…`) before its port.
- Port branch in every SDK repository: `feat/contract-1.51`, cut from that repository's `origin/main`.
- axiam branch (records, this ledger): `claude/beautiful-bell-pjwmo8`.
- Artefact drift before the fan-out: 33 problems at C-0, 30 after C-1 (Rust cleared 3). After: _pending_.

## Rows

| Wave | Task | SDK | Repository | Branch | Worker | PR | CI | Merged |
|---|---|---|---|---|---|---|---|---|
| 1 | C-2 | TypeScript | `ilpanich/axiam-typescript-sdk` | `feat/contract-1.51` | reviewed (1389 pass / 1 skip re-run) | [#116](https://github.com/ilpanich/axiam-typescript-sdk/pull/116) | pending | |
| 1 | C-3 | Python | `ilpanich/axiam-python-sdk` | `feat/contract-1.51` | running | | | |
| 1 | C-7 | Go | `ilpanich/axiam-go-sdk` | `feat/contract-1.51` | pushed `90a0aa9`; sent back: 1.51 model tests missing | | | |
| 2 | C-4 | Java | `ilpanich/axiam-java-sdk` | `feat/contract-1.51` | running | | | |
| 2 | C-5 | C# | `ilpanich/axiam-csharp-sdk` | `feat/contract-1.51` | running | | | |
| 2 | C-8 | Kotlin | `ilpanich/axiam-kotlin-sdk` | `feat/contract-1.51` | not started | | | |
| 3 | C-6 | PHP | `ilpanich/axiam-php-sdk` | `feat/contract-1.51` | not started | | | |
| 3 | C-9 | Swift | `ilpanich/axiam-swift-sdk` | `feat/contract-1.51` | not started | | | |
| 3 | C-10 | C | `ilpanich/axiam-c-sdk` | `feat/contract-1.51` | not started | | | |
| 3 | C-11 | C++ | `ilpanich/axiam-cplusplus-sdk` | `feat/contract-1.51` | not started | | | |

Worker states: not started → running → pushed → reviewed (orchestrator re-ran the main
test command) → PR open → green → merged.

## CI commands per SDK (the local gates), and toolchains

Search for each tool was done twice (PATH lookup, then a filesystem/installer probe).

| SDK | CI commands (`sdk-ci-*.yml`, PR jobs) | Toolchain here | How obtained if absent |
|---|---|---|---|
| TypeScript | `npm ci`; `npm ls amqplib`; `npm run generate` (buf); `npm run build`; `npm run typecheck`; `npm test -- --run`; `npm run docs`; `npm audit --audit-level=high --omit=dev`; `npm run bundle-grep`; CJS smokes `node -e "require('./dist/grpc/index.js')"` and `…/middleware/index.js`; `eyJ` leak grep on `dist/`; TLS-lint grep on `src/`; `npm publish --dry-run --tag <pre>`; drift `node scripts/gen-management.mjs --check`. Matrix Node 22, 26 | Node 22.22 ✔; buf ✘ | buf: `npm i -g @bufbuild/buf` (registry reachable); Node 26 via `/opt/nvm` (nodejs.org reachable) |
| Python | `pip install -e '.[dev,fastapi,django]'`; `pytest tests -v`; `pip-audit --skip-editable --desc`; `python -m py_compile examples/*.py`; TLS grep; `pip install 'grpcio-tools==1.78.*'` + `bash scripts/gen_grpc.sh` + `git diff --exit-code src/axiam_sdk/grpc/gen`; drift `python scripts/gen_management.py --check`; `mypy --strict src`; `ruff check .`; `ruff format --check .`; `interrogate -c pyproject.toml src/axiam_sdk`; `python -m build` + `twine check dist/*`. Matrix 3.10, 3.14 | Python 3.11 ✔, uv ✔ | 3.10/3.14: try `uv python install`; else CI covers the two legs |
| Go | `go build ./...`; `go vet ./...`; `go test ./...`; `govulncheck ./...`; `go build ./examples/...`; OPAQUE interop (`cargo build -p axiam-opaque --example interop` in axiam + `go test -tags interop -run Interop ./...`); TLS grep; `buf generate` + `git diff --exit-code internal/gen`; drift `go run ./internal/cmd/genmanagement -check`. Matrix Go 1.26.7, 1.27.0 | go 1.24.7 (below go.mod floor) | `GOTOOLCHAIN=go1.26.7` / `go1.27.0` auto-download (proxy.golang.org reachable); buf via npm |
| Java | `mvn -B test` (JDK 21, 25); `mvn -B compile javadoc:javadoc`; `bash scripts/tls-bypass-gate.sh`; `mvn -B verify -Dgpg.skip=false` (ephemeral key) + bom; `mvn -B dependency:tree`; `mvn -B generate-sources compile`; drift `python3 scripts/gen_management.py --check`; `mvn -B -f bom/pom.xml validate`; `mvn -B install -DskipTests` + `mvn -B -f examples/spring-boot-app/pom.xml verify` | JDK 21 ✔, Maven 3.9.11 ✔ | `repo.maven.apache.org` answers 429 at times; `repo1.maven.org` reachable (mirror in `~/.m2/settings.xml` if needed). JDK 25: CI leg |
| C# | `dotnet restore Axiam.Sdk.sln`; `dotnet build Axiam.Sdk.sln -c Release --no-restore`; `dotnet build examples/<X> -c Release` ×12; `dotnet test Axiam.Sdk.sln -c Release --no-build`; vulnerable-package scan; TLS grep; `dotnet pack` ×2; drift `python3 scripts/gen_management.py --check`. SDKs 8.0.x + 10.0.x | dotnet ✘ | `apt-get install -y dotnet-sdk-8.0 dotnet-sdk-10.0` (candidates 8.0.125, 10.0.104); nuget.org reachable |
| Kotlin | `./gradlew build test koverXmlReport --no-daemon -PkotlinVersion=… -PtestJavaVersion=…` (floor JDK 17 / Kotlin 2.1.0, newest JDK 25 / Kotlin 2.4.10); `./gradlew koverVerify` (≥ 98 % line, floor leg); `bash scripts/tls-bypass-gate.sh`; drift `python3 scripts/gen_management.py --check`; private-key grep; `./gradlew dokkaJavadocJar` | JDK 21 ✔, Gradle 8.14 ✔ (wrapper used) | JDK 17: `apt-get install -y openjdk-17-jdk` (Gradle runs on 17); JDK 25: CI leg |
| PHP | `composer validate --strict`; `composer install`; `composer test` (phpunit); `composer audit`; `vendor/bin/phpstan analyse --memory-limit=512M`; `php tools/docblock-coverage.php`; PHPStan on §27 examples; TLS grep; drift `python3 scripts/gen_management.py --check`; protoc drift (`php tools/grpc-gen.php` + `git diff --exit-code -- src/Grpc/Gen`). Matrix PHP 8.2, 8.5 | PHP 8.4 ✔, composer ✔; protoc ✘ | protoc: `apt-get install -y protobuf-compiler` (CI pins its own; compare versions); PHP 8.2/8.5: CI legs (ondrej PPA unreachable) |
| Swift | `swift build`; `swift test --enable-code-coverage` in container `swift:{5.9,6.3}-jammy`; drift `python3 Scripts/gen_management.py --check`; TLS grep; private-key grep | swift ✘ | `download.swift.org` is denied by the egress policy; Docker Hub rate-limited; **`mirror.gcr.io/library/swift:{5.9,6.3}-jammy` resolves** — start `dockerd`, run CI's own image |
| C | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_STANDARD={11,23}` with gcc and clang; `cmake --build build -j`; `ctest --test-dir build --output-on-failure`; ASan+UBSan build + ctest; valgrind sweep; drift `python3 scripts/gen_management.py --check`; TLS / private-key grep; conan create | cmake, gcc 13, clang 18, valgrind, conan ✔; libcurl dev headers ✘ | `apt-get install -y libcurl4-openssl-dev` |
| C++ | `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD={17,23}` gcc/clang; build; `ctest`; `./build/examples/axiam_example_reactor`; ASan+UBSan; valgrind; drift `python3 scripts/gen_management.py --check`; TLS / key grep; vcpkg/conan validation | as C, plus ninja ✔ | as C |

Installed by the orchestrator at 09:30Z (apt, no worker running apt): dotnet SDK 8.0.131 and 10.0.112, OpenJDK 17.0.20 (the default `java` stays 21), `libcurl4-openssl-dev` 8.5.0, `protoc` 3.21.12. These do not survive a fresh container; re-run the apt line if the session resumes elsewhere.

## Scope additions beyond §6's table

- C-6, C-9, C-10, C-11 also take §13 row 17's manifest defects: PHP never reconciles role
  grants or group bindings; PHP, Swift, C and C++ never send `parent_id`; Swift, C and C++
  default `resource_type` to `"folder"`. Each fixed with an idempotence test over a nested
  manifest that asserts the parent on the wire.

## Half-done state

Wave 1 (C-2, C-3, C-7) started 09:25Z. C-2 pushed and reviewed, PR open; its build output deleted. C-7 pushed `90a0aa9`, then sent back for the missing 1.51 model tests (SAN wire shape, inherit defaults, open CertificateType). C-4 and C-5 started as slots freed (~10:35Z).

For C-12, found in review: C-2 and C-7 both differ from Rust on question 5. They read the principal's reach from OPAQUE login and the WebAuthn / MFA setup too, because those responses carry `LoginUserInfo`. Confirmed in `crates/axiam-api-rest/src/handlers/opaque.rs`: the `200` of `/auth/opaque/login/finish` uses the password path's builder, but its utoipa annotation documents no body (a spec gap).

Wave 3 order changed: C-9 Swift runs last, after C-10 finishes, not beside C-6/C-10/C-11 (the cap is three workers, and Swift's toolchain is a Docker image pulled from `mirror.gcr.io`, so it starts once C-10's `build*/` trees are gone).

When a worker is cut off, record here: the SDK, the last pushed
commit on `feat/contract-1.51`, what the worker's last report said was left, and the
agent id if it can still be resumed with SendMessage.

## Resume check-ins

- `trig_01Sw9PGBzLKLriWid2DQRbZ8` — fires 2026-09-24T15:21Z (+6 h)
- `trig_011Mkt9C44XdJhPs46Qe9XAj` — fires 2026-09-24T19:21Z (+10 h)
