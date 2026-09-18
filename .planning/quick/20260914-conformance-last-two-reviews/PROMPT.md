---
task: Close the last two OIDF conformance REVIEW modules that cannot pass a certification review
created: 2026-09-14
depends-on: commit ad1cb67d8 "fix(oauth2): refuse an unusable authorization request before the login hop"
sdk-fan-out: CONDITIONAL — see §6. Do not start one without reading it.
---

# Two REVIEW modules still hand a certification reviewer the wrong evidence

Paste everything below into a fresh cloud session. It is self-contained.

---

## 1. Where things stand

`main` passes the OIDF suite with **165 modules and zero FAILED** across four
plans (Basic OP, FAPI 2.0 mTLS / self-signed / private-key-jwt). This task is
**not** about a failure. It is about two modules whose terminal verdict is
`REVIEW` and whose uploaded evidence would not satisfy the human reviewer who
signs a certification off.

A `REVIEW` module's condition always has this shape:

> **If the server does not return an error back to the client**, it must show an
> error page saying X — upload a screenshot of the error page.

So there are two acceptable outcomes: return the error to the client over the
protocol (the module then **passes outright**, no screenshot needed), or render
an error page the reviewer can read. Today these two do neither — the browser is
sent to `/login`, and the driver uploads a screenshot of the **sign-in page**
against a condition asking for an error page.

Five sibling modules were closed this way in `ad1cb67d8` by refusing earlier, so
the error reaches the client and the module passes. Use the same shape.

## 2. The two modules

### A. `fapi2-security-profile-final-par-attempt-reuse-request_uri`

Condition: *"If the server does not return an error back to the client, It must
show an error page that the request_uri is invalid."*

What happens now: the suite completes a normal authorization, then re-sends the
browser to `/oauth2/authorize` with the **already-consumed** `request_uri`. With
no OP session, `resolve_authorize_principal` redirects to `/login` **without
looking at the handle at all**, because the handle is single-use and is consumed
later, in the handler, after a principal exists. The user signs in for a request
that was dead before they started.

The constraint that makes this non-trivial is deliberate and documented in
`crates/axiam-api-rest/src/handlers/oauth2.rs` (`resolve_authorize_principal`,
the comments around the `prompt=none` arm): *"a pushed request's parameters
cannot be seen at this point (the handle is consumed inside the handler, after a
principal exists)"*. `ParService::consume`
(`crates/axiam-oauth2/src/par.rs`) both resolves **and** spends the handle, and
`PushedAuthRequestRepository::consume` is the single-statement single-use
guarantee — §2 rule 1 of that file's own module docs.

So the fix is a **non-consuming existence check** before the login hop, not a
second `consume`:

- Add a `peek`-style method to `ParService` (and the repository trait it needs)
  that resolves a `request_uri` **without marking it used**, answering the same
  three questions `consume` does: does the handle exist and is it unexpired, and
  does it belong to this `client_id`.
- Call it in `resolve_authorize_principal` before the login redirect is built,
  when `q.request_uri` is present. On refusal answer exactly as `ad1cb67d8`
  does — `build_error_redirect` only when `q.redirect_uri` exactly matches a
  registered URI, `authorize_error_response` otherwise (RFC 6749 §4.1.2.1).
- The existing refusal text is already right and already proven to render:
  `ParService::consume` returns `REQUEST_URI_GONE` ("request_uri is unknown,
  expired, or used") and "request_uri was not issued to this client".

**Do not** make the peek consume, and **do not** widen the window between peek
and consume into a way to spend a handle twice: the authoritative single-use
decision must stay in `consume`, inside the handler. The peek is an early
refusal, never an authorization.

**Watch for the deliberate twin.** `par-ensure-reused-request-uri-prior-to-auth-
completion-succeeds` requires the **opposite**: a `request_uri` re-sent *before*
the first authorization completed must still work, and its condition literally
says *"The login page should be shown"*. It passes today. A peek that refuses an
unconsumed handle breaks it. Run both modules.

### B. `fapi2-security-profile-final-state-only-outside-request-object-not-used`

Condition: *"If the server does not return an `invalid_request_object` error back
to the client, it must show an error page…"*

What happens now: the suite pushes a request object whose `state` is present
only **outside** it, and expects the server to notice. AXIAM advertises
`request_parameter_supported: false` and ignores request objects entirely, so it
uses the outer `state` and never errors.

**Establish the cheapest correct fix before writing code**, because the obvious
one is far larger than the problem:

1. Read the module's full condition from the suite
   (`GET /api/log/{testId}`, the entry whose `result` is `REVIEW`) — the log
   truncates in the UI and the full text has settled questions like this before.
2. Decide between: (a) refusing a pushed request that carries a `request` object
   at all, with `invalid_request_object`, since AXIAM does not support them and
   silently ignoring a signed object a client believed was authoritative is
   itself the defect; or (b) implementing request-object parsing.
3. **Prefer (a).** It is a refusal, not a feature; it matches what discovery
   already advertises; and it keeps `request_parameter_supported: false` honest.
   Option (b) is a new capability with an SDK surface — see §6.

If the suite's full condition turns out to require (b), **stop and report**
rather than starting it.

## 3. Hard constraint — do not break what works

`main` is at 165 modules / 0 FAILED and both benchmark lanes are green. Treat
every one of these as a regression gate:

- `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (the twin
  above — the single most likely thing to break).
- `fapi2-security-profile-final-happy-flow`,
  `-ensure-authorization-request-without-nonce-success`.
- `oidcc-server`, `oidcc-scope-all`, `oidcc-refresh-token`.
- The three PAR refusals that already render proper error pages and must keep
  doing so: `par-attempt-to-use-expired-request_uri`,
  `par-attempt-to-use-request_uri-for-different-client`,
  `ensure-unsigned-authorization-request-without-using-par-fails`.

## 4. Verifying — read this before running anything

**A whole-plan sweep is the wrong tool here.** Use the targeted runner: create a
plan, then start only the modules you care about.

```
POST {SUITE}/api/plan?planName=<plan>&variant=<urlencoded variant json>
POST {SUITE}/api/runner?test=<module>&plan=<planId>
GET  {SUITE}/api/info/<testId>          # poll until status FINISHED, read .result
GET  {SUITE}/api/log/<testId>           # conditions, and evidence
```

A working implementation is in this repo's history for this task as
`run-some.sh`; `conformance/scripts/run-plan.sh` is the full-sweep original to
copy the plan-creation call from.

**Reading evidence.** A filled screenshot slot appears as `img` on the log entry
and the suite sets `upload` to **null** once filled. So `img != null` means
evidence exists; `upload != null` means it is still missing. Getting this
backwards reads as "no screenshots anywhere", which is wrong.

**One browser driver, ever.** Two deliver two callbacks and the suite throws
`runInBackground called after runFinalisationTaskInBackground()`. Check with
`pgrep -a -f drive-browser.mjs` and read the rows — a `pgrep -c` matches its own
command line and always over-counts. Kill by PID, never with a `pkill -f`
pattern that appears in your own command line (it self-kills, exit 144).

**Rig.** `SUITE_PORT` is 8442, the AXIAM front door 8444, its mTLS listener
8445. `just conformance-up`, then a host build
(`cargo build -p axiam-server --no-default-features`) driven by
`conformance/scripts/serve-axiam.sh`, then `just conformance-register` and
`just conformance-register-basic`, then `just conformance-drive`.

Two rig traps that cost an hour on 2026-09-14 and are **not** fixed in the repo:

- `/api/v1/admin/bootstrap` answers **403** unless the server process was
  started with `AXIAM_BOOTSTRAP_ADMIN_EMAIL` set (or a valid setup token).
- `register-clients.sh` does a read-modify-write on
  `/api/v1/organizations/{id}/settings`, but that endpoint is **asymmetric**:
  GET returns a *grouped* document and PUT wants a *flat* full replacement. Its
  PUT fails with `missing field min_length`, the script sends the response to
  `/dev/null`, and it surfaces only as `sensitive_scopes_enabled did not stick`.
  `benchmarks/runner/seed.sh` solved this on 2026-08-30 with
  `jq '([to_entries[] | select(.value|type=="object") | .value] | add) | .field = value'`.
  Fixing the registrar the same way is a welcome drive-by; it is not the task.

## 5. Build constraints

- `--no-default-features` wherever system libxml2 is absent (the `saml` feature
  pulls `libxml`); the same thing CI's "Build (SAML off)" job does.
- After a `target/` wipe, `utoipa-swagger-ui` needs
  `export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"`.
- Scope cargo commands (`-p axiam-oauth2`, `-p axiam-api-rest`); disk is
  quota-limited. `cargo clean` between steps, never during a run.
- `cargo fmt` and `cargo clippy -D warnings` on every changed crate.
  `rustfmt.toml` sets `max_width = 100`.
- Crate layering is CI-enforced (`scripts/check-crate-layering.py`). A new
  repository method belongs in `axiam-core`'s trait and `axiam-db`'s impl;
  `axiam-oauth2` may not reach sideways.
- **Sign every commit.** Cloud sessions in this project have historically
  committed unsigned (`%G?` = `N`); verify with
  `git log --format='%G?'` before opening the PR and re-sign if needed.

## 6. SDK fan-out — READ BEFORE STARTING ONE

**The dependency commit `ad1cb67d8` needs no fan-out.** It adds no signature, no
new error code and no field. Both refusals surface as `invalid_request` /
`unsupported_response_type` from an `/oauth2/*` endpoint, which
`sdks/CONTRACT.md` already models as `OAuthProtocolError` dispatched on the
`error` field (§2, and the taxonomy row at CONTRACT.md:155). Contract stays
**1.45**. Nothing to re-vendor.

**Module A (`par-attempt-reuse`) needs no fan-out** for the same reason: an
earlier refusal of a dead `request_uri`, using error text that already exists.

**Module B may need one, and that is the decision point.**

- Taking option (a) — refusing a pushed `request` object with
  `invalid_request_object` — is a new *refusal*, not a new capability. It is
  worth one sentence in CONTRACT.md §21, and **a documentation-only change still
  bumps the contract version** in this project (see the §21.6 changelog: 1.14
  was explicitly "documentation only, no SDK behaviour changes and no signature
  moves" and still took a number). A bump means re-vendoring `CONTRACT.md` to
  all eleven `ilpanich/axiam-<lang>-sdk` repos.
- Taking option (b) — implementing request objects — flips
  `request_parameter_supported` to `true`. That is a genuine new SDK-visible
  capability, needs a contract section, and is a real fan-out across eleven
  repos. **Do not start it without saying so first.**

Separately and optionally: the 256-character `state`/`nonce` cap that
`ad1cb67d8` introduced for `fapi2` clients is currently **undocumented** in
CONTRACT.md. Documenting it is correct — an SDK's §12 relying-party helpers
generate `state` and `nonce`, and nothing today stops one generating a longer
value — but it is the same doc-only contract bump plus eleven-repo re-vendor.
Fold it into whatever bump Module B forces, rather than spending one on its own.

**If you conclude a fan-out is needed, stop and report before starting it.**

## 7. Definition of done

1. Both modules reach a verdict a certification reviewer can sign: either
   `PASSED`, or `REVIEW` whose uploaded evidence is a genuine AXIAM error page
   stating the right reason. Prefer `PASSED`.
2. Every regression gate in §3 still passes.
3. Unit tests for the new refusals, in the style of the crate you touch —
   `par.rs` uses `const` blocks to pin a constant so a bad edit fails to
   compile rather than waiting for a 56-module plan.
4. `cargo fmt` clean, `cargo clippy -D warnings` clean, signed commits.
5. **Open a PR** against `main` referencing the issue(s) it closes, with a
   description of the change and the measured before/after module verdicts.
6. **Drive every CI check to green** before handing back — do not leave a red
   or pending check for someone else.
