# Maven Central publishing: can the stored credential go? — decision memo

> **H-1 step 1**, from [`security-hardening-plan-beta03.md`](security-hardening-plan-beta03.md) §2.
> Written 2026-08-28. Researched against Sonatype's live documentation, not from
> training data — the plan says so explicitly because this ecosystem has moved
> twice in eighteen months (OSSRH sunset, Central Portal, Sigstore validation).

## The question

T-148 — the threat model's only open **Critical** — records that nine of the
eleven SDK release pipelines publish without a long-lived registry credential,
and two do not:

> Rust, TypeScript, Python and C# and the shared `axiam-opaque` core publish via
> Trusted Publishing (OIDC); PHP through Packagist's webhook; Go, Swift, C and
> C++ from git tags. **Maven Central (Java, Kotlin) still requires stored
> credentials.**

Can those two stored credentials be eliminated? If not, what narrows the gap?

## Answer

**No. Not today, and not by anything we can do in our repositories.**

Maven Central has no trusted-publishing equivalent. Publishing goes through the
Central Publisher Portal, whose API authenticates a deployment with a **user
token** — a username/password pair, base64-encoded and sent as
`Authorization: Bearer`. The token is minted by hand at
`central.sonatype.com/usertoken`, is shown once, and is a bearer credential for
the whole namespace. There is no OIDC exchange, no workload-identity
federation, and no per-repository scoping.

Three things make it easy to believe otherwise, and all three are about
something else:

1. **The Portal supports OIDC for *account sign-in*.** You can create a Central
   account through a GitHub OIDC dialog, and doing so auto-verifies the
   matching `io.github.<user>` namespace. That is how you log in to the web UI.
   It is not how a deployment authenticates.
2. **Sigstore signature validation shipped (announced 2025-01-28) and uses
   OIDC.** The Portal now validates `.sigstore.json` bundles alongside the PGP
   `.asc` signatures. Sigstore's keyless signing gets its identity from the
   workflow's OIDC token — so an OIDC token *is* involved in a modern Maven
   Central release, just in **signing** the artifact, never in **authorising**
   the upload. Sigstore signatures remain optional; PGP is still what the
   Portal requires.
3. **"Improvements to the tokens used for publishing" is a stated roadmap
   item**, gated behind the OSSRH sunset finishing. A roadmap item is not a
   control. Re-check when it ships; do not wait for it.

So T-148's Maven clause cannot be closed. It can be narrowed, and the rest of
this memo is what to do instead.

## What we do instead

Five controls, in descending order of how much they actually buy. All five are
in-repository except the first, which is a GitHub setting.

### 1. The token lives in a protected environment, not in repository secrets

Both publish jobs already declare `environment: maven-central`, which is the
hard part. What remains is a repository setting on `axiam-java-sdk` and
`axiam-kotlin-sdk`:

- `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY` and
  `GPG_PASSPHRASE` are **environment** secrets of `maven-central`, not
  repository secrets. A repository secret is readable by any job in any
  workflow that asks for it; an environment secret is readable only by a job
  that names the environment — and naming it triggers the protection rules
  below.
- **Required reviewers**: at least one, so a publish waits for a human. The tag
  push stops being the last irreversible step.
- **Deployment branch/tag rule**: `v*` tags only. Combined with the existing
  `verify-tag-on-main` gate, a workflow run that is not a release tag cut from
  `main` cannot reach the credential at all.

This is the control that matters most, because it changes what an attacker who
can push to the repository gets: not a publish, but a request for one that a
human has to approve.

*Owner action — not implementable from a PR.* Everything below is.

### 2. Sigstore bundles alongside the PGP signatures

Publish `.sigstore.json` next to each artifact. The signature is keyless and
its identity is the workflow's OIDC claim — repository, workflow file, ref — so
it says *where the jar was built*, which a stolen Portal token cannot forge.
It is the closest thing to trusted publishing that Maven Central offers, and it
is available now.

- Java: the `sigstore-maven-plugin`, bound to `verify`, in the release profile.
- Kotlin: the `dev.sigstore.sign` Gradle plugin on the publication.

Both need `id-token: write` on the publish job — the same permission the
Trusted Publishing repos already grant, for the same OIDC reason.

### 3. `attest-build-provenance` over the built artifacts

Independent of Central: the jars, the sources jar, the javadoc jar and the BOM
get a GitHub build-provenance attestation, verifiable with
`gh attestation verify <jar> --repo ilpanich/axiam-java-sdk`. This is the same
control P0-2 adds to the server release, and it is what makes the "verify what
you installed" section of H-5 possible for the JVM SDKs.

### 4. Rotation, with a stated cadence

A credential that cannot be scoped or expired must be replaced on a clock
instead. Portal tokens are replaceable at any time and generating a new one is
the revocation of the old one, so rotation is cheap and the failure mode is
loud (the next publish 401s) rather than silent.

- **Quarterly**, and immediately on any suspected exposure or maintainer change.
- Recorded in each repo's `SECURITY.md` so the date of the last rotation is
  somewhere other than one person's memory.

The GPG signing key is the more valuable of the two secrets and rotates on a
different clock (a new key needs distribution to the keyservers Central
checks); it is not folded into the same cadence.

### 5. Every action pinned by commit digest

Already true of `axiam-java-sdk`. `axiam-kotlin-sdk` still uses floating major
tags (`actions/checkout@v4`, `gradle/actions/setup-gradle@v4`), which means a
compromised tag in any of four upstream actions runs inside the job that holds
the Portal token. Pinning is part of the same H-1 pass.

## What landed, and what did not

Recorded here rather than left to be inferred from eleven pull requests:

| Control | Java | Kotlin | Where |
|---|---|---|---|
| 1. Protected environment | **owner action** | **owner action** | repository settings; the requirement is written into each repo's `RELEASING.md` and into the publish job as a comment |
| 2. Sigstore bundles | done | done | `sigstore-maven-plugin` on both POMs / the `dev.sigstore.sign` Gradle plugin on the publication, plus a PR gate in each repo; see below |
| 3. `attest-build-provenance` | done | done | the publish job, before the Portal forwarding step on Kotlin (which stages first) and after `mvn deploy` on Java (which deploys in one lifecycle pass) |
| 4. Rotation cadence | done (documented) | done (documented) | `RELEASING.md`, with a table to record each rotation in |
| 5. Digest-pinned actions | already true | done — fourteen references | the workflows |

**Sigstore was the one that did not ship, and deliberately — it has since shipped.** Both
plugins configure on the *release* path, so a misconfiguration is invisible until the next
tag and then breaks it. The plan's own rule applies — "workflow changes get a validation
run before they meet a real tag" — and no throwaway-version validation run was possible in
the session that did the rest of this work, so it was held back rather than shipped
untested.

What unblocked it was noticing that the throwaway version was the wrong instrument. A
one-off run proves the release path worked *once*; what the risk actually calls for is a
run that repeats. Both repositories now carry a pull-request gate — `verify-sigstore`
(Java), `sigstore-sign-gate` (Kotlin) — that performs a **real** keyless signing of the
real artifact set on every same-repository pull request: Actions OIDC, a Fulcio
certificate, a Rekor entry, a `.sigstore.json` per file. Each then asserts the property the
deployment depends on — every publishable file has both a `.asc` and a `.sigstore.json`,
and neither signer signed the other's output. Nothing is published: Maven stops at
`verify`, Gradle publishes to the runner's own `~/.m2`, and neither job holds a
`CENTRAL_TOKEN_*` secret. Fork pull requests skip the gate, because a fork's token cannot
mint an OIDC token whatever the job's `permissions:` say.

Two details worth carrying forward. First, the signing is free and adds no credential:
Fulcio and Rekor are the Sigstore public good instance, the certificate is issued against
the workflow's OIDC claim and expires ten minutes later, and the only repository-side
requirement is `id-token: write` — which both publish jobs already had for
`attest-build-provenance`. There is nothing for the owner to configure. Second, the two
signers must not sign each other: maven-gpg-plugin and sigstore-maven-plugin share gpg's
`FilesCollector`, whose default excludes cover `**/*.asc` and `**/*.sigstore.json` (hence
the maven-gpg-plugin >= 3.2.5 floor), and the Gradle plugin strips the
`.sigstore.json.asc` files Gradle's `signing` plugin would otherwise add. Both gates assert
this rather than trusting it.

Both `RELEASING.md` files lose their "Still open" section and gain the `cosign verify-blob`
command an integrator runs against an artifact pulled from Central.

**A second thing the H-1 pass turned up, in the release process rather than the
pipelines.** `sdks/openapi.json` and `sdks/management-registry.json` are
authored in the platform repo and vendored into all eleven SDK clones, and
`mass-tag.sh` re-stamps two fields in them on every release — the spec's
`info.version` and the `x-axiam-spec-digest` that covers it. It did not copy
the result into the SDK repos, so **every** platform release left eleven stale
vendored copies behind, fixed only by eleven hand-opened pull requests. That is
what `sdk-artifact-drift.yml` exists to notice, and it is what happened at
1.0.0-beta03: the SDK pull requests for this very hardening pass merged with the
beta02 stamp, minutes before the beta03 tag re-stamped the source.

`mass-tag.sh` now re-vendors the three artifacts into each SDK repo as part of
the bump commit it already makes, and refuses to run when the platform clone's
spec does not already carry the version being tagged — so "tag the platform
first, then the SDKs" is enforced rather than remembered. Both paths were
validated with `--dry-run` against the real clones.

**One thing worth carrying forward from control 5.** Pinning
`dtolnay/rust-toolchain` by digest silently *removes* an input: the action reads the
toolchain to install from the ref it was called by, so `@stable` → `@6c977a6…` means
rustup is asked for a toolchain named after a hex string. It is not a YAML error and no
linter catches it; the Go SDK's OPAQUE-interop job failed on the first CI run and was
fixed by passing `toolchain: stable` explicitly. Any future pinning pass should check for
actions that read `github.action_ref`.

## What this leaves open

T-148 stays **Open** after all five land, with a narrower residual, stated
honestly: two SDKs publish with a bearer credential that a sufficiently
determined attacker with both repository write access and approval from a
reviewer could use. What changes is that the credential is unreachable without
that approval, that every published artifact carries two independent statements
of origin (Sigstore in Central, provenance in GitHub) that the credential
cannot produce, and that the credential is replaced four times a year.

Revisit when Sonatype ships publishing-token improvements. The check is
cheap — whether the Publish Portal API accepts anything other than a user
token — and the payoff is closing the clause outright.

## Sources

- [Generating a Portal Token for Publishing](https://central.sonatype.org/publish/generate-portal-token/)
- [Publish Portal API](https://central.sonatype.org/publish/publish-portal-api/)
- [Central Publisher Portal Guide](https://central.sonatype.org/publish/publish-portal-guide/)
- [Register to Publish Via the Central Portal](https://central.sonatype.org/register/central-portal/)
- [Sigstore Signature Validation Is Now Available Via The Central Publisher Portal](https://central.sonatype.org/news/20250128_sigstore_signature_validation_via_portal/)
- [OSSRH Sunset Announcement](https://central.sonatype.org/news/20250326_ossrh_sunset/)
