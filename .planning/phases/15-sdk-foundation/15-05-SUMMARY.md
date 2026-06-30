---
phase: 15-sdk-foundation
plan: "05"
subsystem: sdks
status: complete
tags: [sdk, scaffold, ci, license, fnd-05]
requirements: [FND-05]

dependency_graph:
  requires: [15-01, 15-03]
  provides: [sdks/rust, sdks/typescript, sdks/python, sdks/java, sdks/csharp, sdks/php, sdks/go, sdk-ci-workflows]
  affects: [15-06, 16, 17, 18, 19, 20, 21, 22]

tech_stack:
  added:
    - "sdks/ monorepo subdir layout (7 language directories)"
    - "Apache-2.0 LICENSE (verbatim copies from repo root)"
    - "Cargo.toml (axiam-sdk, publish=true, edition 2021)"
    - "package.json (axiam-sdk, export conditions for rest/grpc/amqp personas)"
    - "pyproject.toml (axiam-sdk, setuptools build backend)"
    - "pom.xml (io.axiam:axiam-sdk, Maven Central ready)"
    - "Axiam.Sdk.csproj (PackageId Axiam.Sdk, Apache-2.0)"
    - "composer.json (axiam/axiam-sdk, PSR-4 autoload)"
    - "go.mod (module github.com/axiam/axiam/sdks/go, go 1.22)"
    - "7 path-filtered per-SDK GitHub Actions CI workflows (Phase-15 scaffold-check stubs)"
  patterns:
    - "Monorepo subdir module path for Go (D-13): github.com/axiam/axiam/sdks/go"
    - "SHA-pinned actions/checkout in all CI workflows (T-15-14 mitigated)"
    - "Verbatim LICENSE copy from repo root (T-15-15 mitigated)"
    - "CONTRACT.md §1-§10 reference in all 7 READMEs"
    - "C# Grpc.Tools exception documented (D-01)"

key_files:
  created:
    - sdks/rust/LICENSE
    - sdks/rust/src/lib.rs
    - sdks/rust/Cargo.toml
    - sdks/rust/README.md
    - sdks/typescript/LICENSE
    - sdks/typescript/src/index.ts
    - sdks/typescript/package.json
    - sdks/typescript/README.md
    - sdks/python/LICENSE
    - sdks/python/axiam_sdk/__init__.py
    - sdks/python/pyproject.toml
    - sdks/python/README.md
    - sdks/java/LICENSE
    - sdks/java/pom.xml
    - sdks/java/README.md
    - sdks/csharp/LICENSE
    - sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj
    - sdks/csharp/README.md
    - sdks/php/LICENSE
    - sdks/php/composer.json
    - sdks/php/README.md
    - sdks/go/LICENSE
    - sdks/go/go.mod
    - sdks/go/README.md
    - .github/workflows/sdk-ci-rust.yml
    - .github/workflows/sdk-ci-typescript.yml
    - .github/workflows/sdk-ci-python.yml
    - .github/workflows/sdk-ci-java.yml
    - .github/workflows/sdk-ci-csharp.yml
    - .github/workflows/sdk-ci-php.yml
    - .github/workflows/sdk-ci-go.yml
  modified: []

decisions:
  - "Go SDK uses monorepo subdir path github.com/axiam/axiam/sdks/go (D-13); NOT a separate repo or axiam-go-sdk name"
  - "C# is the documented exception to the buf pipeline — uses Grpc.Tools MSBuild codegen; all others use buf generate"
  - "Phase-15 CI is scaffold-check only (verify LICENSE present); real build/test steps added per-SDK in Phases 16-22"
  - "LICENSE copied verbatim from repo root (Apache-2.0); Cargo.toml license field was stale and not used as source"
  - "actions/checkout SHA-pinned to 11bd71901bbe5b1630ceea73d27597364c9af683 (T-15-14)"

metrics:
  duration: "8"
  completed_date: "2026-06-30"
  tasks_completed: 3
  files_created: 31
  files_modified: 0
---

# Phase 15 Plan 05: SDK Monorepo Scaffold Summary

**One-liner:** Seven language SDK directories scaffolded with verbatim Apache-2.0 LICENSE, locked D-11/D-12/D-13 package identities, CONTRACT.md-referencing READMEs, and 7 path-filtered GitHub Actions CI workflows.

## Objective

Implements FND-05: establish the `sdks/` monorepo layout that all per-SDK phases (16-22) build on, with O(1) per-SDK CI (workflows trigger only on changes to their own directory + shared artifacts).

## Tasks Completed

| # | Task | Commit | Key Files |
|---|------|--------|-----------|
| 1 | Scaffold 7 SDK dirs with LICENSE + stub source | 6cf9f57 | 10 files: sdks/{rust,typescript,python,java,csharp,php,go}/LICENSE + stub sources |
| 2 | Add package manifests + READMEs with locked identities | f8c79c5 | 14 files: Cargo.toml, package.json, pyproject.toml, pom.xml, .csproj, composer.json, go.mod + 7 READMEs |
| 3 | Create 7 path-filtered per-SDK CI workflows | 09d71cb | 7 files: .github/workflows/sdk-ci-{rust,typescript,python,java,csharp,php,go}.yml |

## Package Identities Locked (D-11/D-12/D-13)

| Language | Registry | Package identity |
|----------|----------|------------------|
| Rust | crates.io | `axiam-sdk` |
| TypeScript | npm | `axiam-sdk` |
| Python | PyPI | `axiam-sdk` |
| Java | Maven Central | `io.axiam:axiam-sdk` |
| C# | NuGet | `Axiam.Sdk` |
| PHP | Packagist | `axiam/axiam-sdk` |
| Go | pkg.go.dev | `github.com/axiam/axiam/sdks/go` (D-13) |

## Security Threat Mitigations

| Threat | Mitigation | Status |
|--------|------------|--------|
| T-15-13: Package identity spoofing | Identities locked to D-11/D-12/D-13 names; availability verified separately in Plan 06 | Mitigated |
| T-15-14: CI supply-chain tampering | `actions/checkout` SHA-pinned to `11bd71901bbe5b1630ceea73d27597364c9af683` (verbatim from ci.yml) | Mitigated |
| T-15-15: License non-compliance | LICENSE copied verbatim from repo-root Apache-2.0; stale Cargo.toml field not used | Mitigated |

## Deviations from Plan

None - plan executed exactly as written.

## Threat Flags

None - no new network endpoints, auth paths, file access patterns, or schema changes introduced (this is a scaffold/documentation plan).

## Self-Check: PASSED

- All 31 created files verified to exist
- All 7 LICENSE files contain "Apache License" text
- diff sdks/rust/LICENSE LICENSE: clean (verbatim copy)
- All 7 manifests contain locked identities (grep verified)
- go.mod declares `module github.com/axiam/axiam/sdks/go` (D-13 exact)
- All 7 READMEs contain "CONTRACT.md §1" text
- C# README contains "Grpc.Tools"
- All 7 CI workflows contain path filter for sdks/<lang>/ and SHA 11bd71901bbe5b1630ceea73d27597364c9af683
- No libxmlsec1-dev in any sdk-ci-*.yml
- 3 task commits verified: 6cf9f57, f8c79c5, 09d71cb
