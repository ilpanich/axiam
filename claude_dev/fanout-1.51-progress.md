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
| 1 | C-2 | TypeScript | `ilpanich/axiam-typescript-sdk` | `feat/contract-1.51` | reviewed (1389 pass / 1 skip re-run) | [#116](https://github.com/ilpanich/axiam-typescript-sdk/pull/116) | green `978efdb` | `9102c91` |
| 1 | C-3 | Python | `ilpanich/axiam-python-sdk` | `feat/contract-1.51` | reviewed `0507daf` (two send-backs; re-run 1746 pass, 98.61 %) | [#88](https://github.com/ilpanich/axiam-python-sdk/pull/88) | green `0507daf` (3.10 and 3.14 legs) | `231a686` |
| 1 | C-7 | Go | `ilpanich/axiam-go-sdk` | `feat/contract-1.51` | reviewed `6898cc5` (model tests added on send-back; re-run 0 fail) | [#86](https://github.com/ilpanich/axiam-go-sdk/pull/86) | green `8ba1a4b` (coverage 94.6 %, main 94.4 %) | `9013027` |
| 2 | C-4 | Java | `ilpanich/axiam-java-sdk` | `feat/contract-1.51` | reviewed `678d310` (header on every call fixed on send-back; re-run 1238/0, 95.03 %) | [#102](https://github.com/ilpanich/axiam-java-sdk/pull/102) | green `678d310` (JaCoCo and Sigstore gates in CI) | `fa6803a` |
| 2 | C-5 | C# | `ilpanich/axiam-csharp-sdk` | `feat/contract-1.51` | reviewed `2aef3f3` (SSO reset fixed on send-back; re-run 1241+72 on net8/net10) | [#95](https://github.com/ilpanich/axiam-csharp-sdk/pull/95) | green `2aef3f3` | `d1dc37a` |
| 2 | C-8 | Kotlin | `ilpanich/axiam-kotlin-sdk` | `feat/contract-1.51` | reviewed `2fc30ba` (README gate paragraph fixed by orchestrator; re-run 1057/0, 98.07 %) | [#68](https://github.com/ilpanich/axiam-kotlin-sdk/pull/68) | green `2fc30ba` (both legs, Kover, Sigstore) | `fbf98c5` |
| 3 | C-6 | PHP | `ilpanich/axiam-php-sdk` | `feat/contract-1.51` | reviewed `16f5467` (scoped bindings + service accounts added on send-back; re-run 1649/5072) | [#73](https://github.com/ilpanich/axiam-php-sdk/pull/73) | green `16f5467` (PHP 8.2 and 8.5, coverage) | `ceb7f2c` |
| 3 | C-9 | Swift | `ilpanich/axiam-swift-sdk` | `feat/contract-1.51` | pushed `9884130` (1183 tests on 5.9 and 6.3; 95.34 %); sent back: self-service header, plain-over-scoped Update, secret-survives-failure, apply-then-plan-converges tests missing | | | |
| 3 | C-10 | C | `ilpanich/axiam-c-sdk` | `feat/contract-1.51` | reviewed `7fd9564` (SSO reset + never-set `authenticated` fixed on send-back; re-run gcc/C11 64/64) | [#65](https://github.com/ilpanich/axiam-c-sdk/pull/65) | green `7f3d5db` (after the orchestrator's valgrind-race fix; conan create passes in CI) | `0b87547` |
| 3 | C-11 | C++ | `ilpanich/axiam-cplusplus-sdk` | `feat/contract-1.51` | pushed `678fd85` (1283 cases, 98.69 %); sent back: refuses a stated `inherit: true` (§27.6.1 only forbids SENDING it), plain-over-scoped Update and all-additions convergence tests missing | | | |

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

**Coverage floors (`.github/workflows/coverage.yml`, runs on every PR; missed in the first gate list, found when C-7 went red at 93.5 % < 94.4 %):**

| SDK | Coverage command | Floor |
|---|---|---|
| TypeScript | `npm run coverage` | vitest `thresholds` lines/statements 95 |
| Python | `pytest --cov=axiam_sdk --cov-report=lcov` | `fail_under = 98` (unrounded) |
| Go | `go test ./... -coverprofile=coverage.raw.out -covermode=atomic`; drop `/examples/`, `/internal/gen/`, `/internal/cmd/`; `go tool cover -func` total | 94.4 % statements |
| Java | `mvn -B verify` | jacoco COVEREDRATIO 0.95 |
| C# | merged line coverage of both test projects (see workflow) | 96 % |
| Kotlin | `./gradlew koverVerify` | 98 % line |
| PHP | `vendor/bin/phpunit --coverage-clover coverage.xml` + the inline floor check | 95 % line |
| Swift | `swift test --enable-code-coverage` + llvm-cov total | 92 % line |
| C | cmake `-DAXIAM_ENABLE_COVERAGE=ON` + gcovr | 98 % line, 84 % branch |
| C++ | llvm profile of `tests/axiam_cpp_tests` (logic layer) | 98 % line |

## Scope additions beyond §6's table

- "Flat-entity tier" (C-6, C-9, C-10, C-11) means only §7.2's exclusion (no `users`/`scopes` entities). The three §27.6.1 additions — metadata, the resource-scoped binding, `service_accounts` — are §8 rule 7 tests every port ships; Swift, C and C++ must add group → role bindings to carry the scoped shape.

- C-6, C-9, C-10, C-11 also take §13 row 17's manifest defects: PHP never reconciles role
  grants or group bindings; PHP, Swift, C and C++ never send `parent_id`; Swift, C and C++
  default `resource_type` to `"folder"`. Each fixed with an idempotence test over a nested
  manifest that asserts the parent on the wire.

## Half-done state

Wave 1 (C-2, C-3, C-7) started 09:25Z. C-2 pushed and reviewed, PR open; its build output deleted. C-7 pushed `90a0aa9`, then sent back for the missing 1.51 model tests (SAN wire shape, inherit defaults, open CertificateType). C-4 and C-5 started as slots freed (~10:35Z).

For C-12, found in review: C-3 Python answers question 5 like C-2/C-7 (it records the scope from OPAQUE and the WebAuthn/MFA setup; WebAuthn login, SSO and the device login reset it through `_absorb_session_cookies`). Also C-2 and C-7 both differ from Rust on question 5. They read the principal's reach from OPAQUE login and the WebAuthn / MFA setup too, because those responses carry `LoginUserInfo`. Confirmed in `crates/axiam-api-rest/src/handlers/opaque.rs`: the `200` of `/auth/opaque/login/finish` uses the password path's builder, but its utoipa annotation documents no body (a spec gap).

Wave 3 order changed (and changed back at 14:40Z, once the cleared caches left 24 GB free): C-9 Swift runs last, after C-10 finishes, not beside C-6/C-10/C-11 (the cap is three workers, and Swift's toolchain is a Docker image pulled from `mirror.gcr.io`, so it starts once C-10's `build*/` trees are gone).

When a worker is cut off, record here: the SDK, the last pushed
commit on `feat/contract-1.51`, what the worker's last report said was left, and the
agent id if it can still be resumed with SendMessage.

**Follow-up fixes to merged ports (SSO gate reset).** The user chose a new branch, `fix/contract-1.51-sso-gate`, cut from each repository's main:
- Go: [ilpanich/axiam-go-sdk#87](https://github.com/ilpanich/axiam-go-sdk/pull/87), `c8049b1`, CI pending.
- TypeScript: [ilpanich/axiam-typescript-sdk#117](https://github.com/ilpanich/axiam-typescript-sdk/pull/117), `89d406a`, CI pending (reproduced red on main first).
- Python needs no follow-up (verified). C#, Java, Kotlin, PHP, C, Swift and C++ carry the reset in their port PRs.

**Usage-limit cut-off, 2026-09-24 ~13:50–14:10Z.** Three workers were stopped mid-task. They were resumed at 14:15Z; the state at the cut-off:
- C-6 PHP: branch at `a554518` (pushed). Uncommitted work in progress on the §27.6.1 scoped binding and service accounts: `RoleBinding.php`, `BindingRebindFailed.php`, `Contract151ManifestScopedBindingsTest.php`, and edits to `ManifestApi/Builder/Validation/Kind/ApplyReport.php`.
- C-10 C: local commits up to `77d699b` (the rule-9 fix), not pushed. Uncommitted manifest work in `management_manifest.{h,c}`.
- C-11 C++: nothing written yet; it was still reading. Its checkout is still on the session branch.
- C-8 Kotlin: pushed `8b06813`, plus the orchestrator's README fix `2fc30ba`. PR not yet opened; the orchestrator's test re-run is pending.
- Disk: the composer (11 GB), go-build, uv and pip caches were cleared at 14:13Z (45 % used afterwards).

## Resume check-ins

- `trig_011KPyuytijTBNUtrTjoU38X` — fires 2026-09-24T21:22Z (+6 h; re-armed at 15:21Z, when the first pair fired)
- `trig_01FsrAVmHhZCMECo6vrKpzAC` — fires 2026-09-25T01:22Z (+10 h)
- PR check-in, hourly: latest `trig_01KfxgY8XPDAKqbycRRJHamb` (16:20Z)
