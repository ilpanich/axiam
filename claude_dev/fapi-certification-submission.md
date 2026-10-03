# FAPI 2.0 certification submission — operator runbook (X5.3)

Everything §X5.3 asks for, as a sequence you can follow. This is an **operator
document**: every step needs either money, a legal identity, or an account
nobody but the maintainer should hold, which is why it is written for a human
rather than automated.

Prerequisite: [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md) —
how to run the suite and read what it says. This document assumes you have
already got a green local run and are ready to make it official.

**T23.1.7 added a package at the end of this document** ("The X5.3 package"):
what is submitted, what is attached, the pre-send checklist and the website
wording for the mark, for **both** certifications G-1 targets (OpenID Connect
Basic OP, and FAPI 2.0 Security Profile (Final) as OP). The Steps above are the
FAPI-era sequence and stay as written. Nothing in either has been sent.

---

## Read this before anything else

### The A/B/C decision: **option B was taken** (2026-08-14)

This section used to open by saying the implementation was not submittable for
the scope §X5.4's letter promises, because of one gap:

> **`private_key_jwt` (RFC 7523) client authentication is not implemented.**

**It is implemented now.** The decision below is recorded rather than deleted,
because the reasoning is what a reader needs to evaluate whether the right
option was taken — and because "why was there a gap at all" is the question the
certification team is most likely to ask.

FAPI 2.0 §5.3.1.1 permits two *families* of client authentication —
`private_key_jwt` and mutual TLS. AXIAM implemented the mutual-TLS family first
and both of its RFC 8705 methods (`tls_client_auth` and
`self_signed_tls_client_auth`), because mTLS is the project's differentiator and
the listener infrastructure already existed. The conformance harness therefore
ran **both mTLS methods**, which is not the same thing as both FAPI families —
and §X5.4's fee-waiver letter, drafted earlier, promised a submission covering
both families.

The three options were:

| Option | What it means | Consequence | Status |
|---|---|---|---|
| **A. Certify mTLS-only** | Submit with `client_auth_type: mtls` only, and say so plainly | Legitimate, but requires **amending §X5.4's letter** to a narrower scope | not taken |
| **B. Implement `private_key_jwt` first** | The second half of X5.1's client-auth row | Delays submission; produces the coverage the letter as drafted already claims | **✅ taken — landed 2026-08-14** |
| **C. Ask the Foundation** | Send the fee-waiver request without a submission scope, and ask | Slowest, costs nothing, and the answer decides A vs B for you | not needed |

**Why B rather than A or C.** Option A would have bought an earlier submission
at the price of editing a commitment downward before it had ever been sent —
and the narrower scope would then have had to be widened again as soon as
`private_key_jwt` landed, which is a second conversation with the certification
team for no engineering reason. Option C's only advantage was that it cost
nothing, but its answer would have been useful only if the answer were "A is
fine", and B was a bounded piece of work: key resolution reusing the federation
JWKS cache, an SSRF guard that already existed, and a single-use `jti` store
following the pattern `saml_replay` and `amqp_nonce_replay` already set. Nothing
in it needed inventing.

**The consequence for the letter, stated plainly because the previous revision
of this document said the opposite:**

> §X5.4's letter says "…covering both `private_key_jwt` and mutual-TLS client
> authentication variants."
>
> **That sentence is now accurate as originally drafted. It needs no amendment.
> Send the letter as written.**

The previous instruction — "whichever you pick, do not send §X5.4's letter as
currently drafted" — is withdrawn, and the suggested narrower rewrite that used
to sit at the end of this document is no longer applicable. Sending an
inaccurate scope claim to a certification body remains the one mistake in this
process that is genuinely hard to walk back; the way that risk was closed here
was by making the claim true.

### What DPoP changes for the submission

The sender-constraining row's second half landed in the same pass. AXIAM now
implements **both** RFC 8705 certificate binding and RFC 9449 DPoP, so the
submission can claim either or both. Nothing in the letter turns on this — it
does not mention sender-constraining — but the conformance report will show a
third plan (`…-private-key-jwt.json`) whose client is DPoP-bound, and a reviewer
comparing the report against the letter should not be surprised by it.

---

## Step 0 — Send the fee-waiver letter first

§X5.4's letter is drafted and ready (in
[`extra-B-track-features.md`](extra-B-track-features.md) §X5.4). Its own closing
note says to finish §X5.2 and send it **with** the conformance report attached,
because a completed test plan materially strengthens the request.

So the ordering is:

1. Get a green run (§X5.2). "Green" now covers both client-authentication
   families across three methods.
2. **Send the letter unmodified.** Its scope sentence is accurate; do not edit
   it.
3. Send it with the report attached.
4. **Wait for the answer before paying anything.** §X5.3 is explicit: do not pay
   before the waiver answer arrives.

Fees at time of writing are non-member per-profile, in the hundreds to
low-thousands USD; member rates are lower. Verify the current figure on the
Foundation's certification page rather than trusting this paragraph — it is the
kind of number that goes stale quietly.

---

## Step 1 — Build and pin the release image

A certified result must be reproducible by somebody who is not you. That means
the thing under test is a **digest**, not a tag and certainly not a working
tree: tags move, and "we tested `:latest`" is not evidence six months later
when the question is which build was certified.

```bash
# Tag the release commit and let the release workflow build and publish it.
git tag -s v1.0.0-alphaNN     # signed; the tag is part of the provenance
git push origin v1.0.0-alphaNN

# Once the image is published, resolve the tag to its immutable digest.
docker pull ghcr.io/ilpanich/axiam/server:v1.0.0-alphaNN
docker inspect --format='{{index .RepoDigests 0}}' \
  ghcr.io/ilpanich/axiam/server:v1.0.0-alphaNN
# → ghcr.io/ilpanich/axiam/server@sha256:...
```

**Record that digest.** It goes into the submission, into the published report,
and into the certification record. Everything downstream refers to it.

This mirrors the benchmark archive's provenance culture deliberately: the
benchmark results say which image produced them, and a conformance result that
did not would be weaker evidence than the performance numbers.

---

## Step 2 — Run the certified test plan against the pinned image

Use the CI workflow rather than a laptop, so the run is recorded, attributable
and repeatable by anyone with repository access:

**Actions → “FAPI 2.0 conformance” → Run workflow**, with:

- `axiam_image` = the **digest** from step 1 (leaving it empty builds from the
  checkout, which the workflow labels as a smoke test and not evidence)
- `plan_name` = the default unless upstream has renamed the plan
- `module_timeout` = the default

Then:

1. Download the run's artifact (`fapi-conformance-<run id>`). It carries both
   the rendered Markdown reports and the raw per-module results.
2. **Complete the interactive modules.** Several FAPI 2.0 modules need a browser
   to finish an authorization; no unattended runner can do that, and they will
   show as `TIMEOUT` or `INTERRUPTED`. Finish them against the same pinned image
   from a local suite instance (`just conformance-up`, then the plan detail page
   in the suite UI), and re-render the report.
3. **Read every `REVIEW`.** `REVIEW` is not a pass — it is the suite saying it
   cannot judge that module mechanically. A wall of unread `REVIEW`s is the most
   common reason a first submission comes back rejected.
4. Iterate until both variants are genuinely green. Each iteration is a code
   change, a new tag, a new digest, and a new run — the digest in the
   submission must be the digest that produced the green result, not an earlier
   one that produced a nearly-green one.

---

## Step 3 — Publish the receipts

Commit the final reports under `docs/conformance/`, alongside — **not over** —
any earlier ones.

```bash
just conformance-report          # writes docs/conformance/<date>-<plan>.md
git add docs/conformance/
git commit -S -m "docs(conformance): FAPI 2.0 Security Profile (Final), <digest>"
```

Keeping the red runs matters. AXIAM publishes complete benchmark results
including its own regressions and failing tables, and the fee-waiver letter
commits to treating conformance the same way:

> "…our OpenID conformance-suite results will be published in full alongside the
> certification, green and red alike."

That is a promise in a letter you are about to send to a certification body.
Deleting an inconvenient earlier report would break it.

Make sure the published report states the digest it was produced against. The
reporter records the plan id; add the image digest to the commit message and to
`docs/conformance/README.md` so the pairing survives.

---

## Step 4 — Submit to the OpenID Foundation

The current process lives at
<https://openid.net/certification/> — follow the Foundation's own instructions,
not a summary in this file, because the mechanics change. Broadly it is:

1. Sign the **Certification of Conformance** declaration (a legal statement by
   an authorised representative of the implementer — this is the step that needs
   a human identity, not an agent).
2. Attach the conformance-suite results from step 2.
3. Name the **exact profile and variants** you are certifying. Since option B
   was taken, that is FAPI 2.0 Security Profile (Final), OP, covering **both
   client-authentication families**: mutual TLS (`tls_client_auth` and
   `self_signed_tls_client_auth`) and `private_key_jwt`.
4. Reference the fee waiver if it was granted, or pay the fee.
5. Submit and wait for the Foundation's review.

**Keep the submission scope and the letter's scope identical.** The letter is
sent unmodified, so the submission must claim both families — which is what the
three conformance plans produce evidence for. Do not narrow the submission to
mTLS-only out of caution: a submission narrower than the letter is the same
mismatch as one wider than it, and the evidence supports the wider claim.

---

## Step 5 — After the mark is granted

- **Publish the mark** on the website, per the Foundation's usage guidelines.
  Use it accurately: the mark covers the profile, variants and version you
  certified, and nothing else. The submission covers both client-authentication
  families, so "FAPI 2.0 Security Profile (Final), OP" is accurate without a
  client-auth qualifier — but it does **not** cover FAPI Message Signing (JARM
  and friends), which is a separate optional certification. Do not let a
  marketing page widen it into that.
- **Link the evidence.** The mark should sit next to the published reports and
  the image digest, so a reader can verify rather than trust.
- **Re-certification.** The letter commits to "maintaining certification across
  future releases per the Foundation's re-certification policy". In practice
  that means: on each release that touches the OAuth2/OIDC surface, re-run the
  workflow against the new digest, and re-certify when the policy requires it.
  Put a reminder somewhere that outlives this document.
- **Update `CLAUDE.md` and the README** so the next contributor knows the server
  is certified and what breaking the profile would now cost.

---

## The §X5.4 letter: no amendment needed (option A's rewrite, retired)

**Send §X5.4's letter exactly as drafted.** Option B was taken, so its scope
sentence —

> We have reviewed the self-certification process and expect to submit results
> for the FAPI 2.0 Security Profile (Final) OP test plan, covering both
> `private_key_jwt` and mutual-TLS client authentication variants.

— is accurate. `private_key_jwt` (RFC 7523 §2.2) and both RFC 8705 mutual-TLS
methods are implemented, and `conformance/plans/` carries a plan template for
each.

This document previously ended with a narrower rewrite of that sentence, for use
if option A had been taken. It is retired rather than kept, because a stale
"replace this with that" instruction sitting under a heading is the kind of
thing somebody follows without reading the option table above it — and the
result would be a submission that under-claims what the evidence supports.

If a future release ever *removes* a client-authentication family, this is the
paragraph to come back to.

---

# The X5.3 package (T23.1.7)

Prepared 2026-10-03, ahead of the maintainer's run. **Nothing in this package has
been sent, and no agent sends it.** Every field the run decides is a placeholder
in angle brackets; the fields the repository fixes are filled. Where a requirement
comes from the Foundation's own process rather than from this repository, it is
marked **to verify on the Foundation's certification page before sending**
(<https://openid.net/certification/>), because it could not be checked offline and
the mechanics change.

Order of work: the maintainer's run (runbook, "Maintainer run checklist"), then
`docs/conformance/REVIEW-JUDGEMENTS.md` confirmed against its logs, then this
package. Issue #513 (G-1) stays open until the mark is granted and the receipts
are merged.

## 1. What is submitted

| | Certification profile | Suite plan | Plan files (`conformance/plans/`) | Variant block in the plan file |
|---|---|---|---|---|
| 1 | OpenID Connect **Basic OP** (OpenID Connect Core, Basic Certification Profile), as OpenID Provider | `oidcc-basic-certification-test-plan` | `oidcc-basic-static.json` | `server_metadata: discovery`, `client_registration: static_client` |
| 2a | **FAPI 2.0 Security Profile (Final)**, as OpenID Provider | `fapi2-security-profile-final-test-plan` | `fapi2-security-profile-final-mtls.json` | `fapi_profile: plain_fapi`, `openid: openid_connect`, `client_auth_type: mtls`, `sender_constrain: mtls`; client authenticates with a CA-issued certificate (`tls_client_auth`) |
| 2b | the same | the same | `fapi2-security-profile-final-self-signed.json` | the same variant block; client authenticates with a self-signed certificate (`self_signed_tls_client_auth`) |
| 2c | the same | the same | `fapi2-security-profile-final-private-key-jwt.json` | `fapi_profile: plain_fapi`, `openid: openid_connect`, `client_auth_type: private_key_jwt`, `sender_constrain: dpop` |

The claim for row 2 is the one Steps 4 and 5 above fix, and the §X5.4 letter makes:
FAPI 2.0 Security Profile (Final), OP, covering **both client-authentication
families**: mutual TLS (`tls_client_auth` and `self_signed_tls_client_auth`) and
`private_key_jwt`. It does **not** include FAPI Message Signing (JARM and the
rest), which is a separate certification. Keep the submission's scope identical
to the letter's.

Points the repository cannot settle, for the maintainer:

- **Plan 2a and 2b name the same suite variant** (the plan files above), differing
  in the client's credential. Whether the Foundation's form takes them as one
  variant entry with two runs, or as two entries, is **to verify on the
  Foundation's certification page before sending**.
- **The letter covers FAPI only.** The §X5.4 letter, which the Steps say to send
  unmodified, names the FAPI 2.0 OP plan alone. Whether the fee waiver extends to
  the Basic OP certificate is not stated anywhere in this repository; ask, or pay
  the Basic OP fee, before submitting row 1. Do not edit the letter to widen it.
- **The Basic OP image path is undocumented.** The runbook records that
  `serve-axiam.sh` runs `AXIAM_BIN` and that no workflow runs the Basic plan.
  Whether the Basic run must be against the digest-pinned release image is not
  decided here; the package assumes it is, and has a field for the digest.

## 2. The run-dependent fields

Fill from the maintainer's run. None of these is known today; the 2026-09-25
baseline is **not** a submission run (its build predates the Phase 23 W1 gates and
is a working tree, not a release image).

| Field | Where it comes from | Value |
|---|---|---|
| AXIAM release tag (signed) and commit | Step 1 | `<release tag>`, `<commit sha>` |
| AXIAM release image digest | Step 1 (`docker inspect`) | `<AXIAM release image digest>` |
| Suite release and suite image digest | `SUITE_VERSION` and `SUITE_DIGEST` as the run used them; the baseline pin is recorded in `docs/conformance/README.md` | `<suite version>`, `<suite image digest>` |
| Run date | the report date | `<run date, YYYY-MM-DD>` |
| Plan id, Basic OP | the report's header | `<Basic OP plan id from the maintainer's run>` |
| Plan id, FAPI `mtls` | the same | `<mtls plan id from the maintainer's run>` |
| Plan id, FAPI `self-signed` | the same | `<self-signed plan id from the maintainer's run>` |
| Plan id, FAPI `private-key-jwt` | the same | `<private-key-jwt plan id from the maintainer's run>` |
| Verdict counts per plan | the four verdict-summary tables | `<passed / review / warning / skipped / failed per plan>` |
| Suite log id of each `REVIEW` module | "Modules that did not pass" tables | Basic OP: `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` each `<log id from the maintainer's run>`. FAPI, for each of `mtls`, `self-signed`, `private-key-jwt`: `ensure-unsigned-authorization-request-without-using-par-fails` and `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` each `<log id from the maintainer's run>` |
| Suite log id of the claims `WARNING` | the same | `test-claims-parameter-identity-claims` for each variant: `<log id from the maintainer's run>` |
| Every `SKIPPED` module, named, with its reason | the report's "Modules skipped" section, the reason read from the module's log | Basic OP: `<module name>`, `<reason from its log>`. FAPI `private-key-jwt` (one on 2026-09-25): `<module name>`, `<reason from its log>` |
| Directory of the published receipts | Step 3 | `docs/conformance/<run date>-*.md`, `docs/conformance/evidence/<run date>/` |
| Commit that publishes them | Step 3 | `<receipts commit sha>` |
| Fee-waiver reply, or payment receipt | Step 0 / Step 4 | `<waiver reply reference, or receipt>` |
| Authorised representative | Step 4 (a human) | `<name>`, `<title>`, `<date signed>` |
| Contact for the Foundation | the maintainer | `<maintainer contact>` |
| The Foundation's request or certification id, once opened | the Foundation | `<id issued by the Foundation>` |

## 3. Files to attach

Everything below is in the repository or produced by the run. Attach the dated
files **and** point the reviewer at the whole directory: the letter promises results
"published in full alongside the certification, green and red alike", so earlier
reports stay where they are and are linked, never replaced.

1. The four dated reports of the run: `docs/conformance/<run date>-oidcc-basic-static.md` and
   `docs/conformance/<run date>-fapi2-security-profile-final-{mtls,self-signed,private-key-jwt}.md`.
2. The suite's own results for each plan, in the form the Foundation asks for
   (**to verify on the Foundation's certification page before sending**: this
   repository's own record is the raw per-module `conformance/.run/results/*.results.json`
   and the CI artifact `fapi-conformance-<run id>` of Step 2, not a format the
   Foundation specified).
3. `docs/conformance/REVIEW-JUDGEMENTS.md`, with the new log ids added **beside**
   the 2026-09-25 ones and its sign-off table filled. A submission is this file
   plus a green run.
4. `docs/conformance/evidence/<run date>/`: the `manifest.json`, every image and
   the directory's README, each image viewed and matched to its condition.
5. `docs/conformance/README.md` and `docs/conformance/index.md`, with the
   AXIAM image digest and the suite image digest recorded beside the run date.
6. The plan templates in `conformance/plans/` (committed, with placeholders and no
   secrets), so the run can be reproduced by someone else.
7. The fee-waiver letter as sent, and the Foundation's reply (or the payment
   receipt).
8. The signed Certification of Conformance (Step 4, item 1).

**Never attach, commit or paste:** `conformance/suite.env` (it is tracked, and the
registrars rewrite it in place with client secrets), `conformance/suite.local.env`,
anything under `conformance/.run/` (the rendered plans carry client credentials and
keys), `conformance/certs/` private keys, or a suite-log export that has not been
checked for secrets. The plan templates in item 6 are the safe copy.

## 4. Declarations and forms

Only what the existing documents describe; nothing is invented.

| What | Source in this repository | Status |
|---|---|---|
| Certification of Conformance, a legal statement by an authorised representative of the implementer | Step 4 item 1 above; a human identity, not an agent | Sign it yourself. Its current wording and form are **to verify on the Foundation's certification page before sending** |
| The exact profile and variants being certified | Step 4 item 3; section 1 above | Filled in section 1 |
| The conformance-suite results | Step 4 item 2; section 3 above | Attach as section 3 |
| The fee waiver, or the fee | Step 0 and Step 4 item 4; §X5.3 says not to pay before the waiver answer arrives | Open for Basic OP (section 1) |
| Re-certification commitment | The §X5.4 letter, commitment 2 | Already made in the letter |
| Use of the certification mark | The §X5.4 letter, commitment 4, and Step 5 | Per the Foundation's usage guidelines, **to verify on the Foundation's certification page before sending** |
| Anything else the Foundation's form asks (product and version naming, deployment description, logo permission, terms and conditions) | not in this repository | **To verify on the Foundation's certification page before sending**; read the page fresh, do not rely on this list |

## 5. Pre-send checklist

- [ ] The maintainer's run is finished, against the digest-pinned image, and the
      digest in section 2 is the digest that produced the results (Step 2, item 4).
- [ ] No `FAILED`, `INTERRUPTED`, `TIMEOUT`, `WAITING` or `COULD_NOT_START` in any
      of the four plans; the comparison with the 2026-09-25 baseline (runbook §3) is
      done and every difference was read in its log.
- [ ] Every `REVIEW` image was viewed and matched to its condition, and each entry in
      `REVIEW-JUDGEMENTS.md` is confirmed against the new logs, edited where a
      log contradicts it, and signed off. An entry the log does not support is left
      marked open, not smoothed over.
- [ ] The claims `WARNING` is judged against its log (runbook §3, F4 item (g)); if
      the cause needs a product decision (the entry's *Open, for the maintainer*),
      that decision is taken and recorded before sending.
- [ ] D-12 (T23.1.4) has landed if it was to, and the claims entry describes the
      code as it is.
- [ ] Every `SKIPPED` module is named with its reason read from its log.
- [ ] Reports and evidence are committed under `docs/conformance/` **alongside**
      the earlier ones, with the digests in the commit message and in
      `docs/conformance/README.md`; `scripts/check-doc-links.sh` passes.
- [ ] Letter scope = submission scope. The waiver question for Basic OP is
      answered (section 1). Nothing was paid before the waiver reply.
- [ ] No secret is in any attachment (section 3, "Never attach"). Grep the
      attachments for `client_secret`, `PRIVATE KEY` and the suite's tokens.
- [ ] The Foundation's certification page was re-read today and the points marked
      to verify are settled. Update this document if a requirement differs.
- [ ] The Certification of Conformance is signed by the authorised representative.
- [ ] The website wording (section 6) is still unpublished.

## 6. Website wording for the mark

**Publish only once the certification is granted.** Until then none of this
renders anywhere: it lives in this document, not in `website/src/`. When the
Foundation has granted a certificate, paste what applies, keep only the
certifications actually granted (delete the sentence of one that was not), and fill
the placeholders from the Foundation's listing. Use the mark itself only as the
Foundation's guidelines allow (**to verify on the Foundation's certification page
before sending**).

**Where it goes.** The site's documentation is authored one module per section under
`website/src/docs/`, assembled by `website/src/docs/index.ts`.

- `website/src/docs/reference.ts`, page `compliance` (sidebar section
  "Reference", "Standards & compliance"), heading `oidf` ("The OpenID Foundation
  conformance suite"). This is where the certification belongs. Two blocks there
  say the opposite today and must change in the same commit: the `warn` block
  headed "165 modules, zero `FAILED` — and that is not a certification … No
  submission has been made", and the page-wide `warn` under `honesty`, "Everything
  on this page is a self-assessment backed by test evidence, not a third-party
  certification". Narrow the second to the claims that remain self-assessments;
  do not remove it, because the rest of the page is still one. The table above
  them is the 2026-09-18 sweep; replace it with the certified run's counts.
- `website/src/security.ts`, the section `oauth2` ("OAuth2 & OpenID Connect") on
  the Security page: the paragraph ending "That is a self-run against a working-tree
  build, not a certification".
- Optionally, `website/src/docs/oauth2.ts`, page `fapi2` ("FAPI 2.0 & mTLS"), as a
  one-line note under its introduction.

Ready to paste, in the site's block form. The first replaces the `warn` block under
`oidf`:

```ts
{
  type: "note",
  text: `**Certified, as of <certification date>.** AXIAM <release version> is certified by the OpenID Foundation as an OpenID Provider for **OpenID Connect Basic OP** and for **FAPI 2.0 Security Profile (Final)**, the latter covering both client-authentication families: mutual TLS (\`tls_client_auth\` and \`self_signed_tls_client_auth\`) and \`private_key_jwt\`. The certification covers exactly those profiles and variants, at that release, and nothing else: it does not include FAPI Message Signing. [The Foundation's listing](<certification listing URL on the Foundation's site>).`,
},
{
  type: "p",
  text: `The certified run is against the release image \`<AXIAM release image digest>\`, with the suite pinned at \`<suite version>\` (\`<suite image digest>\`), on <run date>. Every module's result is published, green and red alike, as is the judgement for each module the suite leaves to a human reviewer: [the receipts](${GH_BLOB}/docs/conformance/README.md), [the judgements](${GH_BLOB}/docs/conformance/REVIEW-JUDGEMENTS.md) and [the run](${GH_BLOB}/docs/conformance/index.md). A \`REVIEW\` is a module the suite cannot decide automatically; it is not counted as a pass, and each is written up with the log, the screenshot and the clause. Certification is re-run on releases that touch the OAuth2/OIDC surface, per the Foundation's re-certification policy.`,
},
```

The second narrows the `honesty` warning:

```ts
{
  type: "warn",
  text: "Apart from the OpenID Foundation certifications named under *The OpenID Foundation conformance suite* below, everything on this page is a **self-assessment backed by test evidence**, not a third-party certification. Each conformance matrix in the repository maps a normative MUST to the test that exercises it, so a claim can be checked rather than believed. That is stronger than a marketing bullet and weaker than an audit — treat it accordingly.",
},
```

The third replaces the closing sentences of the `oauth2` paragraph on the Security
page (everything from "run against the OpenID Foundation's conformance suite
itself"):

```text
… and, since <certification date>, certified by the OpenID Foundation as an OpenID Provider for OpenID Connect Basic OP and for FAPI 2.0 Security Profile (Final), covering mutual TLS and private_key_jwt client authentication, at release <release version>. The receipts, including every module that was not a clean pass and the judgement written for it, are published green and red alike.
```

The optional note for the `fapi2` page:

```ts
{
  type: "note",
  text: "AXIAM <release version> is certified by the OpenID Foundation for FAPI 2.0 Security Profile (Final), as an OpenID Provider, with mutual TLS and `private_key_jwt` client authentication. See [Standards & compliance](#/docs/compliance) for the run, the digests and the receipts.",
},
```

Rules for whoever publishes it: say "certified" only for a profile the Foundation
has listed; keep the release version in the sentence, so the claim cannot outlive
the release it was made for; do not widen "FAPI 2.0 Security Profile (Final)" into
Message Signing or into FAPI 1.0; keep the link to the receipts next to the mark
(Step 5). After publishing, update `docs/conformance/README.md`, `CLAUDE.md` and the
repository README (Step 5), and change the `compliance` page's verified-release
constant only if the page was actually re-verified.

