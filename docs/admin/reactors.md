# Reactors

A **Reactor** is an external process that subscribes to a small set of
authorization-adjacent hook events on the AMQP bus and answers back —
allow, deny, or a narrowly field-allow-listed mutation — inside a timeout
the server declared. It is AXIAM's answer to Zitadel Actions and Keycloak
SPIs, and the difference is the whole design: those load third-party code
*into* the authorization server; a Reactor stays outside, reachable only
through a signed reply schema the server validates before it believes a
word of it.

This page is a concept guide for operators deciding *whether* and *how* to
use a Reactor, and how it differs from a webhook. It does not restate the
wire protocol — that is normative in
[`sdks/CONTRACT.md` §22](../../sdks/CONTRACT.md), and if anything here and
that chapter ever disagree, §22 is authoritative. Registration is managed
through `/api/v1/reactors` (REST) or `ReactorAdminService` (gRPC), both
described in §22.9; the admin console's Reactors page is the same surface
with a form on top.

## Webhook vs. listener Reactor

AXIAM already has webhooks (fire-and-forget HTTP callbacks on domain
events like `user.created`). A `mode: "listen"` Reactor looks similar at a
glance — both are "the server tells an external system something
happened" — but they solve different problems and make different
promises. Don't reach for one where the other fits better.

| | Webhook | Listener Reactor (`mode: "listen"`) |
|---|---|---|
| **Transport** | Outbound HTTPS POST to a URL you configure | AMQP consume from a durable, server-declared queue |
| **Authenticity** | HMAC-SHA256 signature over the body (`X-Axiam-Signature`) | §8 v2 HMAC over the whole message, replay-protected (nonce + freshness window) |
| **Delivery guarantee** | At-least-once, with retry/backoff and a DLQ after `max_attempts` | At-least-once (standard AMQP redelivery on a broker hiccup) — **your consumer must be idempotent**; nothing here promises exactly-once |
| **Event catalog** | Domain events: `user.created`, `role.assigned`, etc. — a fixed, growing list | Any event in the reactor registry, **including non-interceptable ones** (§22.5) — a listener can observe everything, because it can influence nothing |
| **Can it affect the operation?** | Never. The server has already committed the change by the time a webhook fires. | Never, by construction — the server does not wait for a listener's reply and does not read one if it sends one anyway |
| **Latency budget** | None enforced — retries happen on your schedule | None either, for the same reason: nothing is blocking on it |
| **Typical use** | Sync a CRM, trigger a Slack notification, fan out to a SIEM | Cheap, best-effort observation of a hook event without the cost or risk of being on the critical path |

The one case a listener Reactor is worth choosing over a webhook: you want
to observe an event the webhook catalog doesn't cover (say,
`login.post_auth` traffic shape, for a fraud-analytics pipeline) without
adding an HTTP endpoint per environment. Otherwise, if the event you care
about already has a webhook, use the webhook — its retry/DLQ story is more
mature and its transport (HTTPS) needs no AMQP client.

## Interceptor Reactors — the part a webhook cannot do at all

`mode: "intercept"` is the feature webhooks have no equivalent of: the
server **waits** for the reactor's reply (up to `timeout_ms`, capped at
5 000 ms server-side, §22.8) and applies it — `allow`, `deny` with a
reason, or (on a mutable event) a merged `patch` restricted to that
event's allow-list. Five events are interceptable in v1 (§22.5):

| Event | Can it veto? | Can it mutate? | Default failure policy |
|---|---|---|---|
| `token.pre_issue` | yes | `ext.` claim namespace only | `fail_open` |
| `login.post_auth` | yes (or demand step-up MFA) | no | `fail_closed` |
| `user.pre_create` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `user.pre_update` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `grant.pre_assign` | yes | no | `fail_closed` |

**What is deliberately absent:** `authz.check`, `authz.check_batch`, and
`token.introspect`. These run at 1 000–12 000 req/s in the benchmark
matrix; a reactor round trip is milliseconds. Hooking them would not
produce a slower check — it would produce a different product. If you need
external input on a per-request authorization decision, write a **deny
grant** in the RBAC engine; it evaluates at hot-path cost, and no reactor
registration can reach that decision path at all (§22.7).

### Failure-policy implications — read this before registering anything security-relevant

Every interceptor registration carries a `failure_policy`, and it decides
what happens when the reactor does not produce a usable reply — a timeout,
a crash, a dropped connection, a rejected reply (bad signature, stale
timestamp, a patch field outside the allow-list). §22.8 puts all of those
in one closed set: **every member resolves the same way.**

- **`fail_open`** — proceed as if the reactor had replied `allow`. Correct
  *only* for a hook that adds something optional, where absence degrades a
  feature rather than a security decision. `token.pre_issue`'s default:
  losing an `ext.` claim enrichment because the reactor is down is a
  product annoyance, not an authorization hole.
- **`fail_closed`** — deny the underlying operation, with an audited
  reason naming the failure. The safe default for every veto-capable
  security hook: `login.post_auth`, `user.pre_create`, `user.pre_update`,
  `grant.pre_assign`. An unreachable fraud check has not passed.

Two operational consequences worth planning around, not just knowing:

1. **A `fail_closed` registration is a single point of failure you just
   introduced.** If you register a `login.post_auth` interceptor with
   `fail_closed` (the default — and changing it to `fail_open` on a login
   veto is almost never what you want, see §22.8's composition rule
   below), your reactor process going down starts denying every login in
   that tenant. Run it with the same availability discipline you'd give
   any other component the login path depends on: health checks,
   auto-restart, and — because AMQP redelivers rather than silently
   dropping — a consumer that doesn't wedge on a poison message.
2. **Mixing a `fail_open` hook and a `fail_closed` hook in one
   registration inherits the stricter policy.** A registration subscribed
   to both `token.pre_issue` (open) and `login.post_auth` (closed) can
   veto a login, so it takes `fail_closed` overall — regardless of which
   order you listed the events in, and regardless of what
   `failure_policy` you explicitly set on the enrichment-only half of that
   pair. You cannot make a login-affecting hook fail open by pairing it
   with an enrichment event.

The per-tenant in-flight cap (64 concurrent interceptions by default,
§22.8) fails immediately rather than queueing when breached — an
overloaded `fail_closed` reactor denies under load rather than making
every other request wait behind it. That is deliberate: a concurrency
bound that queued would have turned into an unbounded latency bound on the
login path.

### The listener idempotency note

Stated once above, worth restating on its own: **a listener MUST be
written idempotently.** AMQP redelivers a message when a consumer
disconnects mid-processing without acking — this is normal broker
behavior, not a bug, and it happens to well-behaved consumers during a
deploy or a network blip. A listener that double-counts, double-charges,
or double-fires an external side effect on redelivery was built assuming
an exactly-once guarantee the transport never promised. Interceptors have
the same exposure in principle, but in practice a redelivered *intercept*
event simply produces a second (usually identical) veto/allow decision for
the same underlying operation — a listener's side effects, being
fire-and-forget, are the case where this actually bites.

## Registering a Reactor

Through the admin console's **Reactors** page, or directly:

```
POST /api/v1/reactors
{
  "name": "fraud-check",
  "description": "Scores logins against the fraud service",
  "events": ["login.post_auth"],
  "mode": "intercept",
  "timeout_ms": 800,
  "failure_policy": "fail_closed"
}
```

`timeout_ms` and `failure_policy` are both optional — omitting them takes
the registry default for the events you named (§22.9's table above). The
full field-by-field reference, the merged-validation rule on `PUT`, and
the gRPC equivalent (`ReactorAdminService`) are in
[`sdks/CONTRACT.md` §22.9](../../sdks/CONTRACT.md).

The console's Reactors table shows `last_seen_at` (when the reactor last
consumed from its queue — `null` means it has never connected, shown
distinctly from "connected once, silent since") alongside a rolling 24-hour
health summary: recent timeouts and recent vetoes, read from the audit
trail every dispatch failure and every denial writes. A `fail_open`
timeout is invisible in the outcome by design (the operation proceeded)
but is never invisible here — that pairing is what tells you apart "no
reactor is configured for this event" from "a reactor is configured and
not answering."

## Writing the reactor process itself

Out of scope for this page — that is
[`sdks/CONTRACT.md` §22.10](../../sdks/CONTRACT.md)'s `reactor_serve`
helper, shipped in the eight managed-runtime SDKs. The one rule worth
repeating here because it is the one an operator, not just an SDK author,
needs to hold a vendor to: **an unsigned reply is not a reply.** Both
directions of the exchange are signed with the same §8 v2 primitives
AXIAM's own AMQP consumers use, and a reactor implementation — hand-rolled
or SDK-provided — that skips verifying the event or signing the reply is
not a weaker integration, it is a hole in the authorization server it is
attached to.

See also: [Admin Guide](README.md).
