# REVIEW-module screenshot evidence — 2026-09-15

The OIDF suite ends a module in `REVIEW` when it cannot decide automatically: the
module's condition reads *"if the server does not return the error to the client,
it must show an error page saying X — upload a screenshot"*, and a human
certification reviewer judges the screenshot. `REVIEW` is therefore a terminal
verdict, **not** a failure.

This directory holds the image each `REVIEW` module actually uploaded during the
2026-09-15 sweep, so the evidence can be checked before a submission is built on
it. `manifest.json` carries the machine-readable mapping
(plan → module → testId → condition → image → md5).

Ten modules ended `REVIEW`; each uploaded exactly one image; six are distinct by
md5 (several modules legitimately share one page).

## Verdict: 10 of 10 match their condition

| Evidence | Modules | The condition asks for | The screenshot shows | Match |
|---|---|---|---|:-:|
| `dc2918eeb2` | `ensure-unsigned-authorization-request-without-using-par-fails` (mtls, self-signed, private-key-jwt) | an error page, `invalid_request` | error page — "This authorization request cannot be completed" / "this client must use pushed authorization requests (RFC 9126); send parameters to /oauth2/par first" / `Error code: invalid_request` | ✅ |
| `f39dea4139` | `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri` | "Show redirect URI error page" | error page — "redirect_uri not registered" / `Error code: invalid_request` | ✅ |
| `6048c9a5ad` | `oidcc-prompt-login`, `oidcc-max-age-1` | "the server must ask the user to login **for a second time**" | the sign-in page carrying the banner **"Please sign in again to continue."** | ✅ |
| `6368b3c290` | `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (mtls) | "The **login page** should be shown" | the sign-in page | ✅ |
| `fa745bfdd5` | same module (self-signed) | same | the sign-in page | ✅ |
| `9903841dae` | same module (private-key-jwt) | same | the sign-in page | ✅ |

## Two caveats, stated rather than buried

1. **A wording divergence, not a behavioural one.** On
   `ensure-unsigned-authorization-request-without-using-par-fails` the condition
   says the page must report *"the request is invalid as it is missing the
   request_object"*, while AXIAM's page says *"this client must use pushed
   authorization requests (RFC 9126)"*. These are the same refusal — a request
   that did not arrive through PAR carries no request object — and the rendered
   error code is `invalid_request`, exactly the one the condition names.
2. **One image is mid-render.** The mtls `par-ensure-reused…` shot
   (`6368b3c290`) has an empty placeholder where the sign-in options paint. It is
   unmistakably the login page the condition asks for, but it is the least
   polished of the six.

## Why the `prompt-login` / `max-age-1` banner is load-bearing

Those two conditions do not ask for *a* login page, they ask for evidence the
user was made to authenticate **again**. A bare sign-in form cannot distinguish a
re-authentication from a first one. The "Please sign in again to continue."
banner is what makes the screenshot answer the question actually asked.

## How this was produced

Per `REVIEW` module, from the suite's own API:

```
GET /api/log/{testId}
```

The condition is the entry whose `result` is `REVIEW`; the evidence is the entry
whose **`img`** field is set (`img`, *not* `upload` — an `upload` of `null` means
the slot was filled). The `img` value is a `data:` URI, so it is split on `,` and
base64-decoded.

Every distinct image was **viewed** to classify it. Classifying these by file
size does not work and has produced a wrong answer before: a 25 KB file sat in
the same size band as the login-page shots and was in fact a proper error page.
