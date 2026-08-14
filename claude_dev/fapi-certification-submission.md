# FAPI 2.0 certification submission — operator runbook (X5.3)

Everything §X5.3 asks for, as a sequence you can follow. This is an **operator
document**: every step needs either money, a legal identity, or an account
nobody but the maintainer should hold, which is why it is written for a human
rather than automated.

Prerequisite: [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md) —
how to run the suite and read what it says. This document assumes you have
already got a green local run and are ready to make it official.

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
