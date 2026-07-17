# AXIAM — Publishing Guide: Registries, Secrets & Setup

Everything AXIAM publishes, where it goes, what credentials each destination needs, and
exactly how to create them. All destinations are **free for open-source projects**.

> **Read this first — the repository layout changed (2026-07).**
> The seven client SDKs no longer live in this repository. Each one is now its own GitHub
> repository, and **each publishes itself, from its own tags, with its own secrets**:
>
> | Language | Repository | This repo (`ilpanich/axiam`) keeps |
> |---|---|---|
> | Rust | `ilpanich/axiam-rust-sdk` | `sdks/CONTRACT.md` — the binding cross-language contract |
> | TypeScript | `ilpanich/axiam-typescript-sdk` | `sdks/openapi.json` — the REST spec (drift-gated in CI) |
> | Python | `ilpanich/axiam-python-sdk` | `proto/` — the gRPC contract |
> | Java | `ilpanich/axiam-java-sdk` | |
> | C# | `ilpanich/axiam-csharp-sdk` | |
> | PHP | `ilpanich/axiam-php-sdk` | |
> | Go | `ilpanich/axiam-go-sdk` | |
> | Kotlin | `ilpanich/axiam-kotlin-sdk` | |
> | Swift | `ilpanich/axiam-swift-sdk` | |
> | C | `ilpanich/axiam-c-sdk` | |
> | C++ | `ilpanich/axiam-cplusplus-sdk` | |
>
> Those three inputs are **maintained here and vendored (copied) into each SDK repo**. When
> one of them changes, the copies downstream must be re-synced — nothing enforces this
> automatically yet (see §8).
>
> Consequences you must internalise before releasing anything:
> - **Tags are now per-repo and plain — everywhere, including the server.** A release is
>   `v1.0.0` **in its own repo**; no more `axiam-rust-sdk/v1.0.0` namespacing, and the
>   server's release workflow was reconciled from the old `axiam-server/v1.0.0` prefix to a
>   plain `v1.0.0` too (`.github/workflows/release.yml` triggers on `v*`, which does not
>   match a `axiam-server/…` ref). Tags are per-repo, so `v1.0.0` is unambiguous everywhere.
> - **Secrets live in the SDK repos**, not here. This repo now needs **zero** publishing
>   secrets.
> - **Two flows changed shape**, not just location — C# (§4.6) and PHP (§4.7). Read them.

Nothing here is aspirational — every secret name below is one the workflows actually
reference.

---

## 1. At a glance

| Artifact | Published from | Registry | Free? | Secrets you must create |
|---|---|---|---|---|
| Server + frontend images | `axiam` | **GHCR** (`ghcr.io`) | Yes | **None** — built-in `GITHUB_TOKEN` |
| Image signatures | `axiam` | **Sigstore** (cosign keyless) | Yes | **None** — OIDC, no private key exists |
| Server rustdoc + docs index | `axiam` | **GitHub Pages** | Yes | **None** — but Pages must be enabled |
| Rust SDK | `axiam-rust-sdk` | **crates.io** | Yes | `CRATES_IO_TOKEN` |
| Python SDK | `axiam-python-sdk` | **PyPI** | Yes | **None** — Trusted Publishing (OIDC) + one-time PyPI config |
| TypeScript SDK | `axiam-typescript-sdk` | **npm** | Yes | `NPM_TOKEN` |
| Java SDK (+ BOM) | `axiam-java-sdk` | **Maven Central** | Yes | `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` |
| C# SDK | `axiam-csharp-sdk` | **NuGet.org** | Yes | **None** — Trusted Publishing (OIDC) via the `production` environment |
| PHP SDK | `axiam-php-sdk` | **Packagist** | Yes | **None** — Packagist's own GitHub webhook |
| Go SDK | `axiam-go-sdk` | **pkg.go.dev** | Yes | **None** — the module proxy pulls it from the git tag |
| Kotlin SDK | `axiam-kotlin-sdk` | **Maven Central** | Yes | `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` |
| Swift SDK | `axiam-swift-sdk` | **Swift Package Index** (+ CocoaPods trunk) | Yes | **None** for SwiftPM (git-tag) — `COCOAPODS_TRUNK_TOKEN` only if also pushing the podspec to CocoaPods trunk |
| C SDK | `axiam-c-sdk` | **GitHub Releases** (+ vcpkg / Conan recipes in-repo) | Yes | **None** — `GITHUB_TOKEN` attaches the release artifacts |
| C++ SDK | `axiam-cplusplus-sdk` | **GitHub Releases** (+ vcpkg / Conan recipes in-repo) | Yes | **None** — `GITHUB_TOKEN` attaches the release artifacts |
| Rust SDK docs | — | **docs.rs** | Yes | **None** — built from the crates.io release |
| Java SDK docs | — | **javadoc.io** | Yes | **None** — served from the `-javadoc.jar` on Central |
| Go SDK docs | — | **pkg.go.dev** | Yes | **None** — automatic |
| Python/TS/C#/PHP SDK docs | each SDK repo | **that repo's GitHub Pages** | Yes | **None** — but Pages must be enabled per repo |
| Test coverage (all 7 SDKs) | each SDK repo | **Coveralls** | Yes | **None** if the repo is public (`GITHUB_TOKEN`); otherwise `COVERALLS_REPO_TOKEN` |

**A handful of secrets, spread across a few repos.** The original six (Rust `CRATES_IO_TOKEN`,
npm `NPM_TOKEN`, and the four Java Maven-Central/GPG secrets) are now joined by the **Kotlin
SDK's four Central/GPG secrets** (which may reuse the same dedicated CI GPG key as Java, §4.10)
and, only if you opt into CocoaPods, one `COCOAPODS_TRUNK_TOKEN` for Swift (§4.11). The C, C++
and Swift-via-SwiftPM SDKs need **no** publishing secret. Everything else is OIDC, a webhook, or
the built-in token. **No secret is a long-lived push credential for another repository** —
the old PHP mirror PAT is gone (§4.7).

### Package identifiers (already set in the manifests)

| Registry | Identifier |
|---|---|
| crates.io | `axiam-sdk` |
| PyPI | `axiam-sdk` |
| npm | `axiam-sdk` (unscoped) |
| Maven Central | `io.github.ilpanich:axiam-sdk` (+ `axiam-sdk-bom`) |
| NuGet | `Axiam.Sdk`, `Axiam.Sdk.AspNetCore` |
| Packagist | `axiam/axiam-sdk` |
| Go | **`github.com/ilpanich/axiam-go-sdk`** — changed, see §4.8 |
| Maven Central (Kotlin) | `io.github.ilpanich:axiam-sdk-kotlin` |
| CocoaPods | `AxiamSDK` (Swift; SwiftPM uses the git URL directly) |
| vcpkg / Conan (C) | `axiam-c-sdk` (port/recipe name; consumed via overlay/remote) |
| vcpkg / Conan (C++) | `axiam-cpp-sdk` (port/recipe name; consumed via overlay/remote) |
| GHCR | `ghcr.io/ilpanich/axiam/server`, `.../frontend` |

---

## 2. How to add a secret or variable

**UI:** repository → **Settings** → **Secrets and variables** → **Actions** → *Secrets* tab
→ **New repository secret**.

**CLI** (faster, and avoids pasting keys into a browser) — note the `--repo` now names the
**SDK's** repo, not `ilpanich/axiam`:

```bash
gh secret set CRATES_IO_TOKEN --repo ilpanich/axiam-rust-sdk           # prompts, reads stdin
gh secret set GPG_PRIVATE_KEY --repo ilpanich/axiam-java-sdk < key.asc # from a file
gh secret list --repo ilpanich/axiam-rust-sdk                          # verify
```

---

## 3. One-time repository settings

### 3.1 In `ilpanich/axiam` (this repo)

1. **Enable GitHub Pages** — Settings → **Pages** → Source: **Deploy from a branch** →
   Branch **`gh-pages`** / **`/ (root)`**. The branch is created by the first
   `docs-publish.yml` run.
   Site layout: the **root** (`https://ilpanich.github.io/axiam/`) is the AXIAM project
   website; the **documentation index** lands at `…/axiam/docs/` and the server rustdoc at
   `…/axiam/server/`. The index links *out* to each SDK's own docs site.
2. **Allow Actions to write packages/contents** — Settings → **Actions** → **General** →
   *Workflow permissions* → **Read and write permissions** (GHCR pushes and the `gh-pages`
   commit need this).
3. **Make the GHCR packages public** after the first image push — profile → **Packages** →
   `axiam/server` → *Package settings* → **Change visibility** → **Public**.

### 3.2 In every SDK repo

1. **Enable GitHub Pages** (Python, TypeScript, C#, PHP — the four that build their own API
   docs): Settings → **Pages** → Branch **`gh-pages`** / **`/ (root)`**. Rust, Java and Go
   get their docs from docs.rs / javadoc.io / pkg.go.dev and need nothing.
2. **Allow Actions read/write permissions** (the docs job commits to `gh-pages`).
3. **Create the GitHub *environment*** the publish job declares — the name must match
   **exactly**, because the registry's OIDC trust is bound to it:

   | Repo | Environment name | Why |
   |---|---|---|
   | `axiam-python-sdk` | `pypi` | PyPI Trusted Publishing binds to it |
   | `axiam-csharp-sdk` | `production` | NuGet Trusted Publishing binds to it |
   | `axiam-java-sdk` | `maven-central` | Gates the Central deploy (not OIDC, but the job declares it) |
   | `axiam-kotlin-sdk` | `maven-central` | Gates the Central deploy (same as Java; reuses the `io.github.ilpanich` namespace) |

   Optionally add yourself as a required reviewer on these, so a release needs an explicit
   approval click.
4. **Add the repo to Coveralls** — <https://coveralls.io/repos/new>, pick the repo. Public
   repos need no token (the workflow authenticates with `GITHUB_TOKEN`); for a private repo,
   copy the repo token and `gh secret set COVERALLS_REPO_TOKEN --repo ilpanich/axiam-<lang>-sdk`.

---

## 4. Per-registry setup

### 4.1 GHCR — Docker images (`axiam` repo, no secret needed)

`release.yml` authenticates with the automatically-provided `GITHUB_TOKEN`; there is nothing
to create. Images are signed with **cosign keyless** — Sigstore issues a short-lived
certificate from the workflow's OIDC identity, so **no signing key exists and none can
leak**. Consumers verify with:

```bash
cosign verify ghcr.io/ilpanich/axiam/server:1.0.0 \
  --certificate-identity-regexp 'https://github.com/ilpanich/axiam/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 4.2 PyPI — Python SDK (no secret, but one-time config) → `axiam-python-sdk`

Uses **Trusted Publishing**: PyPI trusts a specific GitHub workflow via OIDC, so there is no
API token to create, rotate, or leak.

> **⚠️ If you already configured this against the monorepo, you MUST update it.** A trusted
> publisher is bound to `(owner, repository, workflow filename, environment)`. The repository
> changed, so the old binding (`Repository: axiam`) will now **reject** the OIDC token.

1. Account at <https://pypi.org/account/register/>, 2FA enabled.
2. <https://pypi.org/manage/account/publishing/> → edit the existing publisher for
   `axiam-sdk`, or **Add a new pending publisher**.
3. Fill in **exactly**:
   - PyPI Project Name: `axiam-sdk`
   - Owner: `ilpanich`
   - Repository name: **`axiam-python-sdk`**  ← changed
   - Workflow name: `sdk-ci-python.yml`
   - Environment name: `pypi`
4. Create the `pypi` environment in the repo (§3.2) — the names must match or PyPI rejects
   the token.

### 4.3 crates.io — Rust SDK → `CRATES_IO_TOKEN` in `axiam-rust-sdk`

1. Sign in at <https://crates.io/> with GitHub.
2. **Account Settings** → **API Tokens** → **New Token**.
3. Name `axiam-ci`; scopes **`publish-new`** + **`publish-update`**. Restrict it to the
   `axiam-sdk` crate after the first publish (the crate must exist to be selectable).
4. `gh secret set CRATES_IO_TOKEN --repo ilpanich/axiam-rust-sdk`

docs.rs builds the documentation automatically — nothing further to configure
(`[package.metadata.docs.rs] all-features = true` is already in the SDK's `Cargo.toml`).

### 4.4 npm — TypeScript SDK → `NPM_TOKEN` in `axiam-typescript-sdk`

1. Account at <https://www.npmjs.com/signup>, 2FA enabled.
2. Avatar → **Access Tokens** → **Generate New Token** → **Granular Access Token**.
3. Packages and scopes: **Read and write**, limited to `axiam-sdk` (on the very first publish
   the package does not exist — either allow all packages for that one run, or `npm publish`
   manually once to claim the name). The token must **bypass 2FA for automation**, or
   `npm publish` from CI prompts for an OTP and hangs (granular tokens do this by default; a
   Classic token must be type **Automation**).
4. `gh secret set NPM_TOKEN --repo ilpanich/axiam-typescript-sdk`

The workflow publishes with `--provenance`, which attests the build to Sigstore over OIDC (no
extra secret).

### 4.5 Maven Central — Java SDK → 4 secrets in `axiam-java-sdk`

The heaviest setup, because Central requires **namespace ownership** and **GPG-signed
artifacts**.

**Step A — claim the namespace.** The poms publish under `io.github.ilpanich`, the
GitHub-backed namespace Central verifies for free (the `axiam.io` domain is not owned, so the
`io.axiam` groupId is not available).

1. Register at <https://central.sonatype.com/> (sign in with GitHub).
2. **View Namespaces** → **Add Namespace** → `io.github.ilpanich`.
3. Central verifies GitHub-backed namespaces by having you create a temporary public repo it
   names (no DNS TXT record — that path is only for domain-based namespaces).

> **The groupId cannot be changed after publishing** without shipping a new artifact. It is
> fixed at `io.github.ilpanich` before the first Java release.

**Step B — the publishing token** (a *portal token*, not your password):
central.sonatype.com → your name → **View Account** → **Generate User Token**. It returns XML
with a `<username>` and `<password>`:

```bash
gh secret set CENTRAL_TOKEN_USERNAME --repo ilpanich/axiam-java-sdk
gh secret set CENTRAL_TOKEN_PASSWORD --repo ilpanich/axiam-java-sdk
```

**Step C — the GPG signing key** (Central rejects unsigned artifacts):

```bash
gpg --full-generate-key                         # RSA 4096, real email, strong passphrase
gpg --list-secret-keys --keyid-format=long      # -> sec rsa4096/ABCD1234EF567890
gpg --keyserver keyserver.ubuntu.com --send-keys ABCD1234EF567890   # Central checks a keyserver

gpg --armor --export-secret-keys ABCD1234EF567890 > /tmp/axiam-signing-key.asc
gh secret set GPG_PRIVATE_KEY --repo ilpanich/axiam-java-sdk < /tmp/axiam-signing-key.asc
shred -u /tmp/axiam-signing-key.asc             # do not leave the private key on disk
gh secret set GPG_PASSPHRASE --repo ilpanich/axiam-java-sdk
```

> Use a **dedicated release key**, not your personal git-signing key — a CI secret should be
> revocable without disrupting your commit signatures.

The release deploys **both** the SDK artifact and the BOM. javadoc.io then serves the docs
automatically from the `-javadoc.jar` the build attaches.

### 4.6 NuGet.org — C# SDK → **Trusted Publishing**, no secret (`axiam-csharp-sdk`)

**This replaces the old `NUGET_API_KEY` flow.** NuGet now supports OIDC trusted publishing,
so there is no API key to create, store, or rotate — and, unlike a NuGet API key, **nothing
expires** (NuGet keys are capped at 365 days and fail *silently at release time*).

1. Sign in at <https://www.nuget.org/> and enable 2FA.
2. **Reserve the ID prefix** (recommended): the `Axiam.*` prefix can be reserved so nobody
   else can publish under it — see
   <https://learn.microsoft.com/en-us/nuget/nuget-org/id-prefix-reservation>.
3. Avatar → **Trusted Publishing** → add a policy bound to:
   - Repository owner: `ilpanich`
   - Repository: `axiam-csharp-sdk`
   - Workflow file: `sdk-ci-csharp.yml`
   - Environment: **`production`**
4. Create the `production` environment in the repo (§3.2). The publish job declares
   `environment: production` + `permissions: id-token: write`, exchanges the GitHub OIDC
   token for a **short-lived** NuGet key at publish time, and pushes both `Axiam.Sdk` and
   `Axiam.Sdk.AspNetCore`.

No `NUGET_API_KEY` secret should exist anywhere. If one is left over, delete it.

### 4.7 Packagist — PHP SDK → **no secret at all** (`axiam-php-sdk`)

**The mirror-repo hack is gone.** In the monorepo, Packagist could not consume a
subdirectory, so CI did a `git subtree split` of `sdks/php/` and force-pushed it to a mirror
repo using a `PHP_SDK_MIRROR_TOKEN` PAT. `axiam-php-sdk` **is** the package now, so:

- the subtree-split/mirror-push job is **deleted**;
- `PHP_SDK_MIRROR_TOKEN` (secret) and `PHP_SDK_MIRROR_REPO` (variable) are **gone** — delete
  them if they still exist anywhere;
- **no PHP publishing secret is needed.** (This is why PHP is the one SDK repo with no
  secrets to create.)

Setup is one click: sign in at <https://packagist.org/> with GitHub → **Submit** → paste
`https://github.com/ilpanich/axiam-php-sdk` → Submit. On the package page, confirm the
**GitHub webhook / auto-update** is enabled. Every tag you push then publishes a new version
automatically.

### 4.8 pkg.go.dev — Go SDK → nothing to create (`axiam-go-sdk`)

> **⚠️ Breaking: the module path changed.**
> Old: `github.com/ilpanich/axiam/sdks/go` — New: **`github.com/ilpanich/axiam-go-sdk`**.
> This is forced, not a preference: the Go module proxy derives the import path from the
> repository URL. Consumers must update their imports and `go get`.
>
> The **tag scheme changed with it**: the old `sdks/go/v1.0.0` form existed only because the
> module sat in a subdirectory (the proxy requires `<module-subdir>/vX.Y.Z`). At the repo
> root the tag is simply **`v1.0.0`**.

The module proxy fetches straight from the git tag; the workflow merely asks
`proxy.golang.org` to fetch it immediately rather than waiting for the first user request. No
account, no token. Docs appear at <https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk>.

### 4.9 Coveralls — test coverage for all 7 SDKs

Each SDK repo has a `coverage.yml` workflow that runs its test suite with coverage and
uploads the report to **Coveralls** on every push to `main` and every PR (so PRs get a
coverage-delta comment).

| Language | Coverage tool | Report format |
|---|---|---|
| Rust | `cargo llvm-cov` | lcov |
| TypeScript | vitest + `@vitest/coverage-v8` | lcov |
| Python | `pytest-cov` | lcov |
| Java | JaCoCo | jacoco xml |
| C# | coverlet (`--collect:"XPlat Code Coverage"`) | lcov |
| PHP | PHPUnit + pcov | clover |
| Go | `go test -coverprofile` | golang |
| Kotlin | Kover (`koverXmlReport`) | jacoco/cobertura xml |
| Swift | `swift test --enable-code-coverage` + `llvm-cov export -format=lcov` | lcov |
| C | `gcov` + `lcov` (or `llvm-cov`) | lcov |
| C++ | `llvm-cov`/`gcov` + `lcov` | lcov |

Setup: add each repo at <https://coveralls.io/repos/new>. Public repos authenticate with the
built-in `GITHUB_TOKEN` — no secret. Private repos need `COVERALLS_REPO_TOKEN` (§3.2).

### 4.10 Maven Central — Kotlin SDK → 4 secrets in `axiam-kotlin-sdk`

Identical mechanics to the Java SDK (§4.5): the Kotlin SDK publishes `io.github.ilpanich:axiam-sdk-kotlin`
under the same `io.github.ilpanich` namespace (already claimed for Java — **no second namespace
verification is needed**). The Gradle build (`maven-publish` + `signing` plugins, or the
`central-publishing` Gradle plugin) signs artifacts with GPG and deploys to the Sonatype Central
Portal.

```bash
gh secret set CENTRAL_TOKEN_USERNAME --repo ilpanich/axiam-kotlin-sdk
gh secret set CENTRAL_TOKEN_PASSWORD --repo ilpanich/axiam-kotlin-sdk
gh secret set GPG_PRIVATE_KEY        --repo ilpanich/axiam-kotlin-sdk < key.asc
gh secret set GPG_PASSPHRASE         --repo ilpanich/axiam-kotlin-sdk
```

You can reuse the **same dedicated CI GPG key** created for Java (§4.5 Step C) — it is already on
the keyserver — or generate a second one. Create the `maven-central` GitHub environment in the repo
(§3.2). Docs are served automatically by **javadoc.io** from the released `-javadoc.jar` (Dokka emits
a Javadoc-format jar).

### 4.11 Swift Package Index + CocoaPods — Swift SDK → 0–1 secret in `axiam-swift-sdk`

SwiftPM has **no registry upload** — like Go, the git tag *is* the release; consumers add the
package by its GitHub URL and pin `from: "1.0.0"`. To list it on the Swift Package Index, submit the
repo once at <https://swiftpackageindex.com/add-a-package> (no secret, no token).

CocoaPods is optional and only needed if you want `pod 'AxiamSDK'` support. To push the podspec to the
CocoaPods trunk on each tag:

1. Register once locally: `pod trunk register you@example.com 'Your Name'` (confirm via email).
2. `pod trunk me --verbose` prints the session token; store it:
   `gh secret set COCOAPODS_TRUNK_TOKEN --repo ilpanich/axiam-swift-sdk`
3. The release workflow runs `pod trunk push AxiamSDK.podspec` with
   `COCOAPODS_TRUNK_TOKEN` in the environment.

If you skip CocoaPods, **no secret at all** is required for the Swift SDK. DocC HTML is published to
that repo's GitHub Pages (§3.2).

### 4.12 / 4.13 C and C++ SDKs → no publishing secret (`axiam-c-sdk`, `axiam-cplusplus-sdk`)

C and C++ have no single canonical package registry. Both repos ship:

- a **CMake** build with `install()` + `CPack` producing a `.tar.gz` (headers + static/shared lib +
  CMake package-config) attached to the **GitHub Release** with the built-in `GITHUB_TOKEN`
  (`softprops/action-gh-release`) — **no secret**;
- an in-repo **vcpkg port** (`ports/axiam-*-sdk/{portfile.cmake,vcpkg.json}`) and **Conan recipe**
  (`conanfile.py`) that CI validates by building the package from source, so consumers can install via
  a vcpkg overlay-port or a Conan remote pointing at the repo.

Pushing the port/recipe to the **upstream** `microsoft/vcpkg` (`ports/`) or `conan-io/conan-center-index`
registries is a separate, manual pull-request to those third-party repositories — it is deliberately
**not** wired into tag-push CI (those registries gate on human review and cannot be published to with a
repo secret). The in-repo recipes make that upstream PR mechanical when you choose to do it.

Doxygen HTML for both is published to each repo's GitHub Pages (§3.2).

---

## 5. What each tag publishes

Tags are the only trigger. **A release tag must be on `main`** — every publishing workflow
runs a `verify-tag-on-main` gate first, because git tags are not branch-scoped and a tag cut
on a feature branch would otherwise ship unreviewed code to a registry under a version number
that **can never be reclaimed** (crates.io, npm, PyPI, Maven Central, NuGet and Packagist all
refuse to re-use a version).

Every component is versioned and released **independently** — and now from its own repo.

| Repo | Tag you push | What happens |
|---|---|---|
| `axiam` | `v1.0.0` | Server **and** frontend images (amd64 + arm64) → GHCR, Trivy-scanned, cosign-signed; `x86_64` + `aarch64` binary tarballs → GitHub Release; server rustdoc + docs index → Pages |
| `axiam-rust-sdk` | `v1.0.0` | crates.io → docs.rs picks it up automatically |
| `axiam-python-sdk` | `v1.0.0` | PyPI (Trusted Publishing) + API docs → that repo's Pages |
| `axiam-typescript-sdk` | `v1.0.0` | npm (with provenance) + API docs → that repo's Pages |
| `axiam-java-sdk` | `v1.0.0` | Maven Central (SDK + BOM) → javadoc.io picks it up automatically |
| `axiam-csharp-sdk` | `v1.0.0` | NuGet (Trusted Publishing) + API docs → that repo's Pages |
| `axiam-php-sdk` | `v1.0.0` | Packagist picks up the tag via its webhook + API docs → that repo's Pages |
| `axiam-go-sdk` | `v1.0.0` | proxy.golang.org nudge → pkg.go.dev |
| `axiam-kotlin-sdk` | `v1.0.0` | Maven Central (GPG-signed, Dokka javadoc jar) → javadoc.io picks it up automatically |
| `axiam-swift-sdk` | `v1.0.0` | SwiftPM tag is the release (Swift Package Index re-indexes); optional `pod trunk push` to CocoaPods + DocC → that repo's Pages |
| `axiam-c-sdk` | `v1.0.0` | CPack tarball + vcpkg/Conan recipe validation → GitHub Release; Doxygen → that repo's Pages |
| `axiam-cplusplus-sdk` | `v1.0.0` | CPack tarball + vcpkg/Conan recipe validation → GitHub Release; Doxygen → that repo's Pages |

The `axiam` release ships the **admin-UI (frontend) image too**: the two are deployed as a
pair (`docker-compose.prod.yml` runs both), so they share a version. Split them only if you
ever want to ship a UI-only patch.

The server tag is a plain `v1.0.0` (its workflow triggers on `v*`). Tags are per-repo, so
even though *this* repo holds more than one releasable thing (server images, binaries, docs),
a single `v1.0.0` tag drives them all — no prefix is needed to disambiguate.

### Colons are not legal in git tags

A tag like `axiamserver:1.0.0` cannot exist — git's `check-ref-format` rejects `:` (along
with space, `~`, `^`, `?`, `*`, `[`, `\`). The colon in `ghcr.io/ilpanich/axiam/server:1.0.0`
belongs to the **Docker image reference**, not the git tag; the release workflow derives it
from the `v1.0.0` git tag automatically (`docker/metadata-action`, stripping the leading `v`).

Example:

```bash
# Server (+ admin UI) release — in the axiam repo
git checkout main && git pull
git tag -s v1.0.0 -m "AXIAM server v1.0.0"
git push origin v1.0.0

# Rust SDK release — in the axiam-rust-sdk repo, independently
cd ../axiam-rust-sdk && git checkout main && git pull
git tag -s v1.0.0 -m "AXIAM Rust SDK v1.0.0"
git push origin v1.0.0
```

### Known gap worth your attention

The **PHP and C#** publish jobs re-run the full build + test suite on the tagged commit
(`needs: [build-test, verify-tag-on-main]`). The **Rust, Go, Java, Python and TypeScript**
publish jobs do **not** — their test jobs are declared `if: github.event_name ==
'pull_request'`, so on a tag push they are skipped entirely and `publish` runs alone. Those
five therefore rely on the tests having passed on the PR *before* the merge, and would
happily publish a commit that main has since broken.

`verify-tag-on-main` closes the dangerous half of this (you can no longer publish code that
was never reviewed). If you want tag-time test enforcement everywhere, drop the
`pull_request`-only condition from those five workflows' test jobs and add them to the publish
job's `needs:`, exactly as PHP and C# already do. It is a small change; it is called out here
rather than made silently because it changes when those jobs run.

---

## 6. Recommended order for the first release

Do the zero-secret ones first and leave Maven Central (the only one with a real prerequisite)
for last.

1. Repo settings (§3) — Pages, workflow permissions, and the three GitHub environments
   (`pypi`, `production`, `maven-central`).
2. `axiam`: tag `v1.0.0` → images on GHCR; make the packages public.
   **This needs no secrets at all.**
3. `axiam-go-sdk`: tag `v1.0.0` (no secret).
4. `axiam-php-sdk`: submit to Packagist, tag `v1.0.0` (no secret).
5. `axiam-csharp-sdk`: NuGet trusted-publishing policy + `production` environment → tag `v1.0.0`.
6. `axiam-python-sdk`: PyPI trusted publisher **re-bound to the new repo** → tag `v1.0.0`.
7. `axiam-rust-sdk`: `CRATES_IO_TOKEN` → tag `v1.0.0`. docs.rs comes free.
8. `axiam-typescript-sdk`: `NPM_TOKEN` → tag `v1.0.0`.
9. `axiam-java-sdk`: namespace verification → the 4 Central/GPG secrets → tag `v1.0.0`.

---

## 7. Rotation & hygiene

- **npm granular tokens** expire on the date you chose, and fail *silently at release time* —
  set a calendar reminder. (NuGet's expiry problem is gone: C# now uses OIDC, §4.6.)
- `CRATES_IO_TOKEN` does not expire; scope it to the `axiam-sdk` crate after the first publish
  so a leak cannot touch anything else.
- The **GPG release key should be dedicated to CI**, so it can be revoked without affecting
  your commit signatures. Keep the revocation certificate offline.
- **No Classic PAT with broad scopes is needed anywhere** — and after the PHP mirror removal
  (§4.7), no repo holds a push credential for another repo at all. Keep it that way.
- GHCR + cosign, PyPI, NuGet and Packagist need **no long-lived credential**. That is
  deliberate, and it is the model to copy for anything added later.

---

## 8. Keeping the SDK repos in sync with this one

Three files are authored here and **vendored** into every SDK repo:

| Source (in `ilpanich/axiam`) | Copy (in each `axiam-<lang>-sdk`) |
|---|---|
| `sdks/CONTRACT.md` | `CONTRACT.md` |
| `sdks/openapi.json` | `openapi.json` |
| `proto/` | `proto/` |
| `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json` | `testdata/v2_reference_vectors.json` (Rust/TS/Python/Go; C#/Java/PHP carry their own equivalent fixture in their test tree) |

This repo's CI still guards the **sources**: `sdk-openapi-drift.yml` fails if
`sdks/openapi.json` drifts from a fresh `--dump-openapi` export, and `sdk-buf-gates.yml` runs
buf lint/breaking/format on `proto/`.

Nothing yet detects a **stale copy downstream**. Until that gate exists, treat any change to
the three files above as a change that must be propagated: open a follow-up PR in each SDK
repo re-copying them, and re-run that SDK's codegen. This is the single sharpest edge
introduced by the multi-repo split — a silently stale `proto/` in one SDK produces stubs that
compile fine and talk to the server incorrectly.
