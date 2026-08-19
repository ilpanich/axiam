# `AppState` — seven cohesive sub-states

**Status:** implemented in `crates/axiam-api-rest/src/state/`
**Introduced by:** the 2026-08 SOLID / clean-architecture review, finding F3

## What was wrong

`AppState<C>` carried **75 public fields**, nearly all concrete
`Surreal*Repository<C>` values, and every handler received all of them
regardless of what it used. That is a god object by the usual definition, and
it had the usual consequences:

- `state.rs` referenced `axiam_db` in nineteen places — the REST adapter's
  widest coupling to infrastructure.
- `C: Connection + Clone` propagated through every handler signature in the
  crate.
- Twenty-five `#[allow(clippy::too_many_arguments)]` sites sat downstream of
  the same pressure.
- A handler that wanted one repository had to be read against a list of
  seventy-five to know that was all it wanted.

## What it is now

Twenty-nine fields stay on the root — the ones most of the crate reads: the
tenant, user, role, permission, resource and scope repositories, the auth and
authz config, the session machinery, the audit log, the shared rate-limit
counter, the crypto semaphore.

Forty-six move into **seven sub-states**, each named for what it is *for*:

| Sub-state | Fields | Read by |
|---|---:|---|
| `PkiState` | 5 | `ca_certificates`, `certificates`, `pgp_keys`, the mTLS device-auth extractor |
| `WebauthnState` | 7 | `webauthn`, `webauthn_policy`, `mds` |
| `GdprState` | 4 | `gdpr`, the cleanup job |
| `MailState` | 5 | `email_config`, `email_verification`, `password_reset` |
| `EventsState` | 7 | `reactors`, `webhooks`, `notification_rules`, `reactor_hooks` |
| `OAuth2State` | 12 | `oauth2`, `uma`, `token_exchange`, `backchannel_logout` |
| `FederationState` | 6 | `federation` |

The selection was not taste. A scan of the crate found that **46 of the 75
fields are referenced by exactly one handler module each** — those are the ones
that moved, grouped by subject.

The root goes from 75 members to 36 (29 + 7), and each group now has a name, a
docstring and a boundary.

## Why not `Arc<dyn Repository>`

The obvious "fix" for a struct full of concrete types is to box them behind
trait objects, which would also collapse the `C` parameter. **That was
deliberately not done.** It puts vtable dispatch on the authorization hot path
— `check_access` is what a service mesh calls on every request — for a purely
cosmetic gain.

This is a **field-grouping change, not a dispatch change**. Every type is what
it was, monomorphisation is what it was, and the generated code is what it was.
What changes is who can see what.

## Two placements worth explaining

**`attestation_ca_cache` and `attestation_metadata_source` are in
`WebauthnState`, not `PkiState`.** They look like PKI — they are certificate
chains and metadata — but they exist to answer "is this authenticator's
attestation acceptable", which is a WebAuthn question. Putting them next to the
policy they serve is what makes the WebAuthn handler readable.

**`assertion_replay_repo` is in `FederationState`, not with the other replay
guards.** The three replay repositories share a mechanism (see
`claude_dev/conflict-classification.md`), but what this one guards is a SAML
assertion, and the SAML ACS handler is its only caller. Mechanism is not
cohesion.

## `state.rs` became `state/`

`state/mod.rs` holds `AppState`, its helper methods and `for_test`;
`state/bundles.rs` holds the seven sub-states. `bundles.rs` opens with
`use super::*` — deliberate: the two files are halves of one dependency-
injection container and name the same forty-odd types, so a duplicated import
list would be a second place to update every time a repository is added, for no
reader's benefit.

## Migration shape

Mechanical and compiler-verified. `state.foo` became `state.<bundle>.foo` at
131 call sites across 19 files, plus 7 internal `self.foo` uses and the
`for_test` literal. Nothing else changed: no handler logic, no route, no wire
format, no test expectation.

The compiler found every site — which is the argument for doing this as one
change rather than seven. A missed field is a build error, not a runtime
surprise.
