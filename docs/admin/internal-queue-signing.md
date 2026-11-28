# Internal AMQP queue signing

**Since:** the 2026-11 security-audit release (SA-14). Procedures, key
derivation and the full configuration reference are in the
[deployment guide](../deployment/README.md#the-server-internal-queues-are-signed-too-sa-14);
this page is what an administrator needs to run it.

## What it protects

AXIAM writes some RabbitMQ queues for itself: outbound mail
(`axiam.mail.outbound`) and the outbound kinds `axiam.webhook`,
`axiam.ssf_push`, `axiam.scim_push` and `axiam.ciba_ping`, each with a `.retry`
queue. What it does with a message there is high-trust: it sends tenant-branded
mail, signs webhook calls with the webhook's secret and signs security events
with the deployment key. A message on those queues is therefore accepted only
inside an envelope signed with a server-only key. A broker user that can publish
cannot make AXIAM send mail to an address of its choosing or deliver a forged
webhook.

The envelope key is derived from `AXIAM__AMQP__SIGNING_KEY`, the same master key
as the SDK-facing queues, but under its own label. No tenant's AMQP key can sign
an internal message.

## What you have to do

| When | Action |
|---|---|
| **Upgrading** | Drain the five queues and the four outbound `.retry` queues (mail has none), then roll producers and consumers together. Old replicas cannot read the envelope. The alternative, `AXIAM__AMQP__INTERNAL_QUEUES__REQUIRE_SIGNATURE=false` for one rollout, reopens the hole while it is set: use it only where no principal other than AXIAM can publish on AXIAM's vhost, and remove the variable and redeploy once no old replica is left and the `.retry` queues have turned over (an hour by default). |
| **Always** | Do not give AMQP SDK principals a way to publish on AXIAM's vhost beyond what they need: RabbitMQ authorizes publishing on the exchange, not the queue, so a per-queue publish rule does not stop a principal that may publish to the default exchange. Keep SDK producers on a separate vhost (the only way to stop them publishing here), and deny them consume on these queues (which closes replay through a requeue). |
| **Capacity** | Messages may wait up to `AXIAM__AMQP__INTERNAL_QUEUES__MAX_AGE_SECS` (86400, 24 h) before they are refused as stale. Raise it only if your mail or outbound consumers can be down longer. |

Messages already sitting in a `.dlq` from before the upgrade are in the old,
unsigned shape and can be replayed only with the flag off. A message
dead-lettered after the upgrade is refused as a replay at once if the consumer
had admitted it before dead-lettering it (an exhausted delivery, the common
case), and as stale after `MAX_AGE_SECS` in any case; re-send the event from its
source instead.

## Watching it

Every refused message is dead-lettered and writes an
`amqp.internal_message_rejected` row to the **system** audit log, with the
queue and a reason in its metadata: `malformed`, `unsigned`, `wrong_purpose`,
`bad_signature`, `key_version`, `stale`, `replay`, `nonce_store_error` or
`malformed_body`. The system partition is readable by organization principals
(`GET /api/v1/audit-logs/system`; see
[Organization scope](organization-scope.md)).

- A burst of `unsigned` right after a rollout means a replica still runs the old
  version, or something other than AXIAM is publishing.
- `bad_signature` or `key_version` outside a rollout means a replica holds a
  different `AXIAM__AMQP__SIGNING_KEY` than the others.
- `stale` means a consumer was down longer than the age bound.
- `wrong_purpose` has no benign cause worth waiting for: check who can publish
  on the vhost. `replay` has one: an operator's own replay of a dead-lettered
  message is refused as `replay` (see above), so a `replay` row that matches a
  replay you sent is expected; one you cannot account for is the case to chase.

## Delivery rules that came with it

- Mail of every type except a notification rule's goes only to the address of
  the user the message names; if that user cannot be read, nothing is sent.
- A queued webhook delivery is dropped, not retried, when the webhook was since
  disabled or no longer subscribes to the event.

The SDK-facing queues (`axiam.authz.request`, `axiam.audit.events`) keep their
own per-tenant signing described in [`sdks/CONTRACT.md`](../../sdks/CONTRACT.md)
§8; since SA-15 the authorization response is signed too.
