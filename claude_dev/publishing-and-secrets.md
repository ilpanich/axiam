# AXIAM — Publishing Guide: Registries, Secrets & Setup

Everything AXIAM publishes, where it goes, what credentials each destination needs, and
exactly how to create them. All destinations are **free for open-source projects**.

Nothing here is aspirational — every secret name below is one the workflows in
`.github/workflows/` actually reference. If a secret is absent, the corresponding publish
step degrades to a documented `::warning::` no-op rather than failing the pipeline, so you
can set them up one at a time.

---

## 1. At a glance

| Artifact | Registry | Free? | Secrets you must create |
|---|---|---|---|
| Server + frontend images | **GHCR** (`ghcr.io`) | Yes | **None** — uses the built-in `GITHUB_TOKEN` |
| Image signatures | **Sigstore** (cosign keyless) | Yes | **None** — OIDC, no private key exists |
| Rust SDK | **crates.io** | Yes | `CRATES_IO_TOKEN` |
| Python SDK | **PyPI** | Yes | **None** — Trusted Publishing (OIDC), but needs one-time PyPI config |
| TypeScript SDK | **npm** | Yes | `NPM_TOKEN` |
| Java SDK | **Maven Central** | Yes | `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` |
| C# SDK | **NuGet.org** | Yes | `NUGET_API_KEY` |
| PHP SDK | **Packagist** | Yes | `PHP_SDK_MIRROR_TOKEN` (secret) + `PHP_SDK_MIRROR_REPO` (variable) |
| Go SDK | **pkg.go.dev** | Yes | **None** — the module proxy pulls it from the git tag |
| Rust SDK docs | **docs.rs** | Yes | **None** — built automatically from the crates.io release |
| Java SDK docs | **javadoc.io** | Yes | **None** — served from the `-javadoc.jar` on Maven Central |
| Go SDK docs | **pkg.go.dev** | Yes | **None** — automatic |
| Python/TS/C#/PHP docs + server rustdoc | **GitHub Pages** | Yes | **None** — but Pages must be *enabled* (§3) |

**Six secrets and one variable in total.** Everything else is automatic or uses the
built-in token.

### Package identifiers (already set in the manifests)

| Registry | Identifier |
|---|---|
| crates.io | `axiam-sdk` |
| PyPI | `axiam-sdk` |
| npm | `axiam-sdk` (unscoped) |
| Maven Central | `io.axiam:axiam-sdk` |
| NuGet | `Axiam.Sdk`, `Axiam.Sdk.AspNetCore` |
| Packagist | `axiam/axiam-sdk` |
| Go | `github.com/ilpanich/axiam/sdks/go` |
| GHCR | `ghcr.io/ilpanich/axiam/server`, `.../frontend` |

---

## 2. How to add a secret or variable

**UI:** repository → **Settings** → **Secrets and variables** → **Actions**
- *Secrets* tab → **New repository secret** (encrypted, never printed in logs)
- *Variables* tab → **New repository variable** (plaintext, fine for non-sensitive values like a repo name)

**CLI** (faster, avoids pasting keys into a browser):

```bash
gh secret set CRATES_IO_TOKEN --repo ilpanich/axiam            # prompts, reads from stdin
gh secret set GPG_PRIVATE_KEY --repo ilpanich/axiam < key.asc  # from a file
gh variable set PHP_SDK_MIRROR_REPO --repo ilpanich/axiam --body "ilpanich/axiam-php-sdk"
gh secret list --repo ilpanich/axiam                            # verify
```

---

## 3. One-time repository settings (do these first)

1. **Enable GitHub Pages** — required before the first docs tag, or the docs jobs fail.
   Settings → **Pages** → *Build and deployment* → Source: **Deploy from a branch** →
   Branch: **`gh-pages`** / **`/ (root)`** → Save.
   The branch is created automatically by the first `docs-publish.yml` run; if Pages
   refuses to save because the branch does not exist yet, push any docs tag first, then
   set it. Docs then land at `https://ilpanich.github.io/axiam/`.

2. **Allow Actions to write packages/contents** — Settings → **Actions** → **General** →
   *Workflow permissions* → **Read and write permissions**. (GHCR pushes and the `gh-pages`
   commit need this.)

3. **Create the `pypi` environment** — Settings → **Environments** → **New environment** →
   name it exactly **`pypi`**. The Python publish job declares `environment: pypi`, and
   PyPI Trusted Publishing binds to that name (§4.2). Optionally add yourself as a required
   reviewer so a release to PyPI needs an explicit approval click.

4. **Make the GHCR packages public** (after the first image push) — the packages appear
   under your profile → **Packages** → `axiam/server` → *Package settings* → **Change
   visibility** → **Public**. Until you do this, `docker pull` requires authentication.

---

## 4. Per-registry setup

### 4.1 GHCR — Docker images (no secret needed)

`release.yml` authenticates with the automatically-provided `GITHUB_TOKEN`; there is
nothing to create. Images are signed with **cosign keyless** — Sigstore issues a
short-lived certificate from the workflow's OIDC identity, so **no signing key exists and
none can leak**. Consumers verify with:

```bash
cosign verify ghcr.io/ilpanich/axiam/server:1.0.0 \
  --certificate-identity-regexp 'https://github.com/ilpanich/axiam/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Only do step 3.4 above (make the package public).

### 4.2 PyPI — Python SDK (no secret needed, but one-time config)

Uses **Trusted Publishing**: PyPI trusts a specific GitHub workflow via OIDC, so there is
no API token to create, rotate, or leak. Set it up once:

1. Create an account at <https://pypi.org/account/register/> and enable 2FA.
2. Go to <https://pypi.org/manage/account/publishing/> → **Add a new pending publisher**.
3. Fill in **exactly**:
   - PyPI Project Name: `axiam-sdk`
   - Owner: `ilpanich`
   - Repository name: `axiam`
   - Workflow name: `sdk-ci-python.yml`
   - Environment name: `pypi`
4. Save. The first `sdks/python/v*` tag creates the project and publishes it.

> The environment name must match the `environment: pypi` in the workflow, or PyPI rejects
> the OIDC token.

### 4.3 crates.io — Rust SDK → `CRATES_IO_TOKEN`

1. Sign in at <https://crates.io/> with GitHub.
2. **Account Settings** → **API Tokens** → **New Token**.
3. Name: `axiam-ci`. Scopes: **`publish-new`** and **`publish-update`**.
   Optionally restrict to the crate `axiam-sdk` (do this after the first publish, since the
   crate must exist to be selectable).
4. Copy the token (shown once) and store it:
   ```bash
   gh secret set CRATES_IO_TOKEN --repo ilpanich/axiam
   ```

docs.rs then builds the documentation automatically — nothing further to configure
(`[package.metadata.docs.rs] all-features = true` is already in `sdks/rust/Cargo.toml`).

### 4.4 npm — TypeScript SDK → `NPM_TOKEN`

1. Create an account at <https://www.npmjs.com/signup> and enable 2FA.
2. Avatar → **Access Tokens** → **Generate New Token** → **Granular Access Token**.
3. Configure:
   - Expiration: your choice (a calendar reminder to rotate is wise)
   - Packages and scopes: **Read and write**, limited to `axiam-sdk`
     (on the very first publish the package does not exist yet — either allow all packages
     for that one run, or run `npm publish` manually once to claim the name)
   - **Important:** the token must be allowed to bypass 2FA for automation, otherwise
     `npm publish` from CI prompts for an OTP and hangs. Granular tokens do this by
     default; if you use a Classic token, choose type **Automation**.
4. Store it:
   ```bash
   gh secret set NPM_TOKEN --repo ilpanich/axiam
   ```

The workflow publishes with `--provenance`, which additionally attests the build to
Sigstore using OIDC (no extra secret).

### 4.5 Maven Central — Java SDK → 4 secrets

The heaviest setup, because Central requires **namespace ownership** and **GPG-signed
artifacts**.

**Step A — claim the namespace.** The pom publishes under `io.axiam`, which Central treats
as a domain you must prove you own.

1. Register at <https://central.sonatype.com/> (sign in with GitHub).
2. **View Namespaces** → **Add Namespace** → enter `io.axiam`.
3. Central asks you to prove control of `axiam.io` by adding a **DNS TXT record**
   containing the verification code it shows you.

> **If you do not own the domain `axiam.io`, you cannot use the `io.axiam` groupId.**
> The zero-cost alternative is the GitHub-backed namespace **`io.github.ilpanich`**, which
> Central verifies just by having you create a temporary public repo it names. Choosing it
> means changing `<groupId>` in `sdks/java/pom.xml` (and the coordinates in the docs and in
> `benchmarks/sdk/java/TODO.md`) to `io.github.ilpanich`. **Decide this before the first
> Java release — the groupId cannot be changed after publishing without shipping a new
> artifact.**

**Step B — generate the publishing token** (this is a *portal token*, not your password):

1. central.sonatype.com → your name → **View Account** → **Generate User Token**.
2. It returns an XML block containing a `<username>` and `<password>`. Store both:
   ```bash
   gh secret set CENTRAL_TOKEN_USERNAME --repo ilpanich/axiam
   gh secret set CENTRAL_TOKEN_PASSWORD --repo ilpanich/axiam
   ```

**Step C — create the GPG signing key** (Central rejects unsigned artifacts):

```bash
# 1. Generate a key (pick RSA 4096; use a real email; set a strong passphrase)
gpg --full-generate-key

# 2. Find its ID
gpg --list-secret-keys --keyid-format=long
#   sec   rsa4096/ABCD1234EF567890 2026-07-11 [SC]

# 3. Publish the PUBLIC key — Central verifies signatures against a keyserver
gpg --keyserver keyserver.ubuntu.com --send-keys ABCD1234EF567890

# 4. Export the PRIVATE key and store it as a secret
gpg --armor --export-secret-keys ABCD1234EF567890 > /tmp/axiam-signing-key.asc
gh secret set GPG_PRIVATE_KEY --repo ilpanich/axiam < /tmp/axiam-signing-key.asc
shred -u /tmp/axiam-signing-key.asc      # do not leave the private key on disk

# 5. Store the passphrase
gh secret set GPG_PASSPHRASE --repo ilpanich/axiam
```

> Use a **dedicated key for releases**, not your personal git-signing key — a CI secret
> should be revocable without disrupting your commit signatures.

javadoc.io then serves the docs automatically from the `-javadoc.jar` the build attaches —
nothing further to configure.

### 4.6 NuGet.org — C# SDK → `NUGET_API_KEY`

1. Sign in at <https://www.nuget.org/> (Microsoft account) and enable 2FA.
2. **Reserve the package IDs first** (recommended): the `Axiam.*` prefix can be reserved so
   nobody else can publish under it — see
   <https://learn.microsoft.com/en-us/nuget/nuget-org/id-prefix-reservation>
   (apply by emailing NuGet support from the account that owns the packages).
3. Avatar → **API Keys** → **Create**.
   - Key name: `axiam-ci`
   - Select Scopes: **Push** (choose *Push new packages and package versions*)
   - Glob pattern: `Axiam.*` (covers both `Axiam.Sdk` and `Axiam.Sdk.AspNetCore`)
   - Expiration: max 365 days — **NuGet keys always expire**, so diarise the rotation.
4. Copy it and store:
   ```bash
   gh secret set NUGET_API_KEY --repo ilpanich/axiam
   ```

### 4.7 Packagist — PHP SDK → `PHP_SDK_MIRROR_TOKEN` + `PHP_SDK_MIRROR_REPO`

Packagist has **no monorepo-subdirectory support**, and this repository's root is a Rust
Cargo workspace, so `sdks/php/` cannot be published directly. The workflow therefore does a
`git subtree split` of `sdks/php/` and pushes the result to a **read-only mirror
repository** that Packagist watches.

1. **Create the mirror repo**: a new *public, empty* GitHub repo, e.g.
   `ilpanich/axiam-php-sdk`. Do not add a README — the split branch becomes its `main`.
2. **Create a token that can push to it.** Prefer a *fine-grained* PAT:
   - GitHub → Settings → **Developer settings** → **Personal access tokens** →
     **Fine-grained tokens** → **Generate new token**
   - Repository access: **Only select repositories** → pick `ilpanich/axiam-php-sdk`
   - Permissions: **Contents: Read and write**
   - Generate, copy, then:
     ```bash
     gh secret set PHP_SDK_MIRROR_TOKEN --repo ilpanich/axiam
     gh variable set PHP_SDK_MIRROR_REPO --repo ilpanich/axiam --body "ilpanich/axiam-php-sdk"
     ```
3. **Register on Packagist**: sign in at <https://packagist.org/> with GitHub → **Submit** →
   paste `https://github.com/ilpanich/axiam-php-sdk` → Submit. Then on the package page
   click **Settings** and confirm the **GitHub webhook / auto-update** is enabled, so each
   mirrored tag publishes a new version automatically.

### 4.8 pkg.go.dev — Go SDK (nothing to create)

The Go module proxy fetches the module straight from the git tag; `docs-publish.yml` merely
asks `proxy.golang.org` to fetch it immediately rather than waiting for the first user
request. No account, no token. Docs appear at
<https://pkg.go.dev/github.com/ilpanich/axiam/sdks/go>.

---

## 5. What each tag publishes

Tags are the only trigger. **A release tag must be on `main`** — every publishing workflow
runs a `verify-tag-on-main` gate first, because git tags are not branch-scoped and a tag cut
on a feature branch would otherwise ship unreviewed code to a registry under a version
number that **can never be reclaimed** (crates.io, npm, PyPI, Maven Central, NuGet and
Packagist all refuse to re-use a version).

| Tag you push | What happens |
|---|---|
| `v1.0.0` | Server + frontend images (amd64 **and** arm64) → GHCR, Trivy-scanned, cosign-signed; `x86_64` + `aarch64` binary tarballs → GitHub Release; server rustdoc → Pages |
| `sdks/rust/v1.0.0` | crates.io → docs.rs picks it up automatically |
| `sdks/python/v1.0.0` | PyPI (Trusted Publishing) + API docs → Pages |
| `sdks/typescript/v1.0.0` | npm (with provenance) + API docs → Pages |
| `sdks/java/v1.0.0` | Maven Central → javadoc.io picks it up automatically |
| `sdks/csharp/v1.0.0` | NuGet + API docs → Pages |
| `sdks/php/v1.0.0` | subtree-split → mirror repo → Packagist + API docs → Pages |
| `sdks/go/v1.0.0` | proxy.golang.org nudge → pkg.go.dev |

Example:

```bash
git checkout main && git pull
git tag -s v1.0.0 -m "AXIAM v1.0.0"     # -s = signed tag
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
was never reviewed), but if you want tag-time test enforcement everywhere, the fix is to
drop the `pull_request`-only condition from those five workflows' test jobs and add them to
the publish job's `needs:`, exactly as PHP and C# already do. It is a small change; it is
called out here rather than made silently because it changes when those jobs run.

---

## 6. Recommended order for the first release

Do the free, zero-risk ones first and leave Maven Central (the only one with a real
prerequisite) for last.

1. Repo settings (§3) — Pages, workflow permissions, `pypi` environment.
2. Tag `v1.0.0` → images land on GHCR; make the packages public. **This needs no secrets at
   all.**
3. `CRATES_IO_TOKEN` → tag `sdks/rust/v1.0.0`. docs.rs comes free.
4. PyPI Trusted Publishing → tag `sdks/python/v1.0.0`.
5. `NPM_TOKEN` → tag `sdks/typescript/v1.0.0`.
6. `NUGET_API_KEY` → tag `sdks/csharp/v1.0.0`.
7. Mirror repo + `PHP_SDK_MIRROR_TOKEN`/`PHP_SDK_MIRROR_REPO` → tag `sdks/php/v1.0.0`.
8. Tag `sdks/go/v1.0.0` (no secret).
9. **Decide the Java groupId** (`io.axiam` needs the `axiam.io` domain; `io.github.ilpanich`
   is free) → namespace verification → the 4 Central/GPG secrets → tag `sdks/java/v1.0.0`.

---

## 7. Rotation & hygiene

- **NuGet keys expire** (365 days max) and **npm granular tokens** expire on the date you
  chose. Both fail *silently at release time*, which is the worst moment to discover it —
  set a calendar reminder.
- `CRATES_IO_TOKEN` does not expire; scope it to the `axiam-sdk` crate after the first
  publish so a leak cannot touch anything else.
- The **GPG release key should be dedicated to CI**, so it can be revoked without affecting
  your commit signatures. Keep the revocation certificate offline.
- Nothing needs a *Classic* PAT with broad scopes. If you find yourself creating one, prefer
  a fine-grained token limited to the single repository that needs it.
- GHCR and cosign need **no long-lived credential at all** — that is deliberate, and worth
  preserving as the model for anything added later.
