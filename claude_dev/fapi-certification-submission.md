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

**The implementation is not yet submittable for the scope §X5.4's letter
promises.** One gap decides your whole path through this document:

> **`private_key_jwt` (RFC 7523) client authentication is not implemented.**

FAPI 2.0 §5.3.1.1 permits two *families* of client authentication —
`private_key_jwt` and mutual TLS. AXIAM implements the mutual-TLS family, and
both of its RFC 8705 methods (`tls_client_auth` and
`self_signed_tls_client_auth`). The conformance harness therefore runs **both
mTLS methods**, which is not the same thing as both FAPI families.

That leaves you three options, and you must pick one before you send anything:

| Option | What it means | Consequence |
|---|---|---|
| **A. Certify mTLS-only** | Submit with `client_auth_type: mtls` only, and say so plainly | Legitimate — check with the certification team whether the profile requires both families for the mark you want. **Amend §X5.4's letter** (see below). |
| **B. Implement `private_key_jwt` first** | The second half of X5.1's client-auth row | Delays submission; produces the coverage the letter as drafted already claims |
| **C. Ask the Foundation** | Send the fee-waiver request without a submission scope, and ask | Slowest, but it costs nothing and the answer decides A vs B for you |

**Whichever you pick, do not send §X5.4's letter as currently drafted.** It
says:

> "…covering both `private_key_jwt` and mutual-TLS client authentication
> variants."

That sentence is ahead of the implementation. Under option A, replace it with
something true — a suggested rewrite is at the end of this document. Under
option B, implement first and the sentence becomes accurate. Sending an
inaccurate scope claim to a certification body is the one mistake in this whole
process that is genuinely hard to walk back.

---

## Step 0 — Send the fee-waiver letter first

§X5.4's letter is drafted and ready (in
[`extra-B-track-features.md`](extra-B-track-features.md) §X5.4). Its own closing
note says to finish §X5.2 and send it **with** the conformance report attached,
because a completed test plan materially strengthens the request.

So the ordering is:

1. Get a green run (§X5.2, and the amendment above about what "green" covers).
2. Amend the letter's scope sentence.
3. Send it, with the report attached.
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
3. Name the **exact profile and variants** you are certifying. Per the gap
   above, that is FAPI 2.0 Security Profile (Final), OP, mutual-TLS client
   authentication — and *not* `private_key_jwt`, unless you took option B.
4. Reference the fee waiver if it was granted, or pay the fee.
5. Submit and wait for the Foundation's review.

**Keep the submission scope and the letter's scope identical.** If you amended
the letter (you should have), the submission must match the amendment.

---

## Step 5 — After the mark is granted

- **Publish the mark** on the website, per the Foundation's usage guidelines.
  Use it accurately: the mark covers the profile, variants and version you
  certified, and nothing else. Do not let a marketing page widen it into "FAPI
  2.0 certified" without qualification if you certified mTLS-only.
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

## The §X5.4 letter, amended for option A

If you are certifying mTLS-only, replace the letter's scope sentence. The rest
of the letter stands as drafted.

> **Replace:**
>
> > We have reviewed the self-certification process and expect to submit results
> > for the FAPI 2.0 Security Profile (Final) OP test plan, covering both
> > `private_key_jwt` and mutual-TLS client authentication variants.
>
> **With:**
>
> > We have reviewed the self-certification process and expect to submit results
> > for the FAPI 2.0 Security Profile (Final) OP test plan, covering **mutual-TLS
> > client authentication** — both the PKI (`tls_client_auth`) and self-signed
> > (`self_signed_tls_client_auth`) methods of RFC 8705. AXIAM implements
> > mutual TLS natively and treats it as a first-class deployment mode rather
> > than an option, which is why we have built the mTLS family out first;
> > `private_key_jwt` is on our roadmap and we would welcome the Foundation's
> > guidance on whether it is required for the certification scope we are
> > requesting.

That last clause turns the gap into a question, which is both honest and
useful — the answer tells you whether option A was ever viable, and asking it in
the letter costs you nothing.

---

## Checklist

- [ ] Decided A / B / C on the `private_key_jwt` gap
- [ ] Amended §X5.4's scope sentence to match that decision
- [ ] Sent the fee-waiver letter, with a conformance report attached
- [ ] Waited for the waiver answer — **paid nothing before it arrived**
- [ ] Tagged a release and resolved it to an immutable digest
- [ ] Ran the CI workflow against that digest
- [ ] Completed the interactive modules against the same digest
- [ ] Read every `REVIEW` verdict rather than counting it as a pass
- [ ] Both variants genuinely green
- [ ] Reports committed under `docs/conformance/`, earlier ones kept
- [ ] Digest recorded next to the reports
- [ ] Submitted with a scope identical to the letter's
- [ ] Mark published accurately, with the evidence linked
- [ ] Re-certification reminder set somewhere durable
