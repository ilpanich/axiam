# REVIEW-module screenshot evidence — 2026-09-25

The OIDF suite ends a module in `REVIEW` when it cannot decide automatically: the
module's condition reads *"if the server does not return the error to the client,
it must show an error page saying X — upload a screenshot"*, and a human
certification reviewer judges the screenshot. `REVIEW` is therefore a terminal
verdict, **not** a failure.

This directory holds the image each `REVIEW` module actually uploaded during the
2026-09-25 sweep. `manifest.json` carries the machine-readable mapping
(plan → module → testId → condition → image → md5).

## What was under test

A host build (`cargo build -p axiam-server --no-default-features`) of branch
`claude/deps-update-2026-09-25` — `origin/main` at `8a0af1033` (1.0.0-beta16)
plus a lockfile-wide `cargo update`, which among other things moves surrealdb
3.2.4 → 3.3.0. The admin SPA the front door serves was rebuilt from the same tree
after a clean `npm ci`, so the pages below are the ones HEAD renders.

The rig itself was rebuilt from nothing for this run: the datastore volume had
been recreated since 2026-09-18, so the organization, tenant, admin, the seven
registered clients and `conformance-user` were all provisioned fresh through the
public API (`scripts/e2e-bootstrap.sh` with the server's one-time setup token,
then `conformance-register` and `conformance-register-basic`).

## Result: 165 modules, 0 FAILED — identical in shape to 2026-09-18

| Plan | Modules | Passed | Not passing |
|---|---:|---:|---|
| `oidcc-basic-static` | 35 | 30 | 4 REVIEW, 1 SKIPPED |
| `fapi2-security-profile-final-mtls` | 37 | 34 | 2 REVIEW, 1 WARNING |
| `fapi2-security-profile-final-self-signed` | 37 | 34 | 2 REVIEW, 1 WARNING |
| `fapi2-security-profile-final-private-key-jwt` | 56 | 52 | 2 REVIEW, 1 WARNING, 1 SKIPPED |

The same ten modules end `REVIEW` as on 2026-09-15 and 2026-09-18, and the single
WARNING per FAPI variant is the same one (`test-claims-parameter-identity-claims`,
which the suite runs although AXIAM advertises `claims_parameter_supported: false`).

## Verdict: 10 of 10 match their condition

Ten modules ended `REVIEW`; each uploaded exactly one image; six are distinct by
md5. Every distinct image was **viewed** — not classified by size or hash.

| Evidence | Modules | The condition asks for | The screenshot shows | Match |
|---|---|---|---|:-:|
| `dc2918eeb2` | `ensure-unsigned-authorization-request-without-using-par-fails` (mtls, self-signed, private-key-jwt) | an error page, `invalid_request` | error page — "This authorization request cannot be completed" / "this client must use pushed authorization requests (RFC 9126); send parameters to /oauth2/par first" / `Error code: invalid_request` | ✅ |
| `f39dea4139` | `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | "Show redirect URI error page" | error page — "redirect_uri not registered" / `Error code: invalid_request` | ✅ |
| `d4f4ba0105` | `oidcc-prompt-login` | "the server must ask the user to login **for a second time**" | the sign-in page carrying the banner **"Please sign in again to continue."** | ✅ |
| `f77ce8cb67` | `oidcc-max-age-1` | same | the same re-authentication page, banner present | ✅ |
| `3bfc90363d` | `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (mtls, self-signed) | "The **login page** should be shown" | the sign-in page | ✅ |
| `736d1520ee` | same module (private-key-jwt) | same | the sign-in page | ✅ |

Three of the six are byte-identical to earlier evidence (`dc2918eeb2` and
`f39dea4139` to 2026-09-15 and 2026-09-18; `736d1520ee` to the 2026-09-18
self-signed shot). The other three are the same pages captured at a different
render instant, which is expected for a screenshot of a live SPA; none of this
run's login-page captures is mid-render.

## One caveat, carried forward unchanged

**A wording divergence, not a behavioural one.** On
`ensure-unsigned-authorization-request-without-using-par-fails` the condition says
the page must report *"the request is invalid as it is missing the
request_object"*, while AXIAM's page says *"this client must use pushed
authorization requests (RFC 9126)"*. These are the same refusal — a request that
did not arrive through PAR carries no request object — and the rendered error code
is `invalid_request`, exactly the one the condition names.

## Why the `prompt-login` / `max-age-1` banner is load-bearing

Those two conditions do not ask for *a* login page, they ask for evidence the
user was made to authenticate **again**. A bare sign-in form cannot distinguish a
re-authentication from a first one; the "Please sign in again to continue."
banner is what makes the screenshot answer the question actually asked. Each
module produced its own capture of it, so both are independently evidenced.

## How this was produced

Per `REVIEW` module, from the suite's own API:

```
GET /api/log/{testId}/images
```

The condition is the entry's `msg`; the evidence is the entry whose **`img`**
field is set. The `img` value is a `data:` URI, so it is split on `,` and
base64-decoded. Files are named `<plan>__<module>__<md5[:10]>.jpg`.
