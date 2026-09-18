# REVIEW-module screenshot evidence — 2026-09-18

The OIDF suite ends a module in `REVIEW` when it cannot decide automatically: the
module's condition reads *"if the server does not return the error to the client,
it must show an error page saying X — upload a screenshot"*, and a human
certification reviewer judges the screenshot. `REVIEW` is therefore a terminal
verdict, **not** a failure.

This directory holds the image each `REVIEW` module actually uploaded during the
2026-09-18 sweep, so the evidence can be checked before a submission is built on
it. `manifest.json` carries the machine-readable mapping
(plan → module → testId → condition → image → md5).

## What was under test

A host build of branch `claude/deps-update-and-reverify` — `origin/main` at
`e4c62180e` (the T21 MCP-authorization track: RFC 8414 discovery, public clients
and loopback redirects, RFC 8707 resource indicators, DCR, CIMD, path issuers)
plus a `cargo update` of the whole lockfile. The admin SPA the front door serves
was rebuilt from the same tree, so the pages below are the ones HEAD renders.

## Result: 165 modules, 0 FAILED — identical in shape to 2026-09-15

| Plan | Modules | Passed | Not passing |
|---|---:|---:|---|
| `oidcc-basic-static` | 35 | 30 | 4 REVIEW, 1 SKIPPED |
| `fapi2-security-profile-final-mtls` | 37 | 34 | 2 REVIEW, 1 WARNING |
| `fapi2-security-profile-final-self-signed` | 37 | 34 | 2 REVIEW, 1 WARNING |
| `fapi2-security-profile-final-private-key-jwt` | 56 | 52 | 2 REVIEW, 1 WARNING, 1 SKIPPED |

The same ten modules end `REVIEW` as on 2026-09-15, and the single WARNING per
FAPI variant is the same one (`test-claims-parameter-identity-claims`, which the
suite runs although AXIAM advertises `claims_parameter_supported: false`).

## Verdict: 10 of 10 match their condition

Ten modules ended `REVIEW`; each uploaded exactly one image; seven are distinct by
md5. Every distinct image was **viewed** — not classified by size.

| Evidence | Modules | The condition asks for | The screenshot shows | Match |
|---|---|---|---|:-:|
| `dc2918eeb2` | `ensure-unsigned-authorization-request-without-using-par-fails` (mtls, self-signed, private-key-jwt) | an error page, `invalid_request` | error page — "This authorization request cannot be completed" / "this client must use pushed authorization requests (RFC 9126); send parameters to /oauth2/par first" / `Error code: invalid_request` | ✅ |
| `f39dea4139` | `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | "Show redirect URI error page" | error page — "redirect_uri not registered" / `Error code: invalid_request` | ✅ |
| `6048c9a5ad` | `oidcc-prompt-login` | "the server must ask the user to login **for a second time**" | the sign-in page carrying the banner **"Please sign in again to continue."** | ✅ |
| `6fc3c01f78` | `oidcc-max-age-1` | same | the same re-authentication page, banner present | ✅ |
| `9903841dae` | `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (mtls) | "The **login page** should be shown" | the sign-in page | ✅ |
| `736d1520ee` | same module (self-signed) | same | the sign-in page | ✅ |
| `fac163408e` | same module (private-key-jwt) | same | the sign-in page | ✅ |

Four of the seven are byte-identical to the 2026-09-15 evidence (`dc2918eeb2`,
`f39dea4139`, `6048c9a5ad`, `9903841dae`). The other three are the same pages
captured at a slightly different render instant, which is expected for a
screenshot of a live SPA.

## Two caveats, stated rather than buried

1. **A wording divergence, not a behavioural one** — unchanged from 2026-09-15.
   On `ensure-unsigned-authorization-request-without-using-par-fails` the
   condition says the page must report *"the request is invalid as it is missing
   the request_object"*, while AXIAM's page says *"this client must use pushed
   authorization requests (RFC 9126)"*. These are the same refusal — a request
   that did not arrive through PAR carries no request object — and the rendered
   error code is `invalid_request`, exactly the one the condition names.
2. **One image is mid-render.** The private-key-jwt `par-ensure-reused…` shot
   (`fac163408e`) has an empty placeholder between the two "OR" dividers where
   the federated sign-in options paint. It is unmistakably the login page the
   condition asks for. On 2026-09-15 the mid-render shot was the mtls one; which
   variant catches it varies run to run.

## Why the `prompt-login` / `max-age-1` banner is load-bearing

Those two conditions do not ask for *a* login page, they ask for evidence the
user was made to authenticate **again**. A bare sign-in form cannot distinguish a
re-authentication from a first one. The "Please sign in again to continue."
banner is what makes the screenshot answer the question actually asked — and on
this run `max-age-1` produced its own capture of it rather than sharing
`prompt-login`'s bytes, so both modules are independently evidenced.

## How this was produced

Per `REVIEW` module, from the suite's own API:

```
GET /api/log/{testId}
```

The condition is the entry whose `result` is `REVIEW`; the evidence is the entry
whose **`img`** field is set (`img`, *not* `upload` — an `upload` of `null` means
the slot was filled). The `img` value is a `data:` URI, so it is split on `,` and
base64-decoded. Files are named `<plan>__<module>__<md5[:10]>.jpg`.
