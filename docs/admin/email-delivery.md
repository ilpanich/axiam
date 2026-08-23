# Email Delivery

**Last verified:** 2026-08-23

How AXIAM resolves an email configuration, how to test one before you rely on
it, and what each supported provider requires of the sender address. See also:
[Admin Guide](README.md), [Deployment Guide](../deployment/README.md).

---

## How a configuration is resolved

Every outbound message resolves its configuration from two rows:

1. The **organization baseline** — `PUT /api/v1/organizations/{org_id}/email-config`.
   Complete: delivery switch, sender identity, provider, credential.
2. The **tenant override** — `PUT /api/v1/tenants/{tenant_id}/email-config`.
   Partial. Every field is optional, and an omitted field inherits the
   baseline.

The effective configuration is the baseline with the tenant's overrides
applied. A tenant with no override row at all uses the baseline unchanged.

There is no per-message configuration and no server-wide fallback. **If the
organization has no email configuration, nothing sends** — a tenant override
alone is not enough, because an override is a diff against a baseline that has
to exist.

### Which fields are tri-state

`enabled` and `reply_to` distinguish three states, not two:

| Field       | Absent from the request | Present                       |
| ----------- | ----------------------- | ----------------------------- |
| `enabled`   | inherit the org switch  | `true`/`false` overrides it   |
| `reply_to`  | inherit the org address | `null` clears it; a string replaces it |

In the admin UI the "Override delivery on/off" and "Override sender identity"
checkboxes are what send or omit these fields. Leaving reply-to empty *while
the sender override is on* clears the organization's reply-to for that tenant;
to inherit it again, turn the sender override off.

### Secrets are write-only and preserve on omit

Provider credentials (`SmtpConfig.password`, `ApiProviderConfig.api_key`) are
encrypted at rest with `AXIAM__EMAIL_ENCRYPTION_KEY` and are **never** returned
by any `GET`. On the write path an empty credential means *"no new secret
supplied — keep the stored one"*, which is why the admin panel can show a
provider's settings without ever holding its key.

Two consequences worth knowing:

- Changing an unrelated field (a sender name, an API URL) does not require
  re-typing the credential.
- **Switching provider kind does.** A secret entered for SendGrid is not a
  Resend credential, so a kind change with a blank credential field does not
  carry the old one across — the new configuration has no credential and is
  refused with *"email configuration is incomplete"* until you supply one.

---

## Test it before you rely on it

`PUT` validates *structure* only. It never opens a connection to the provider,
by design — a write path that made a live network call would fail for reasons
unrelated to the configuration being written. Real sends then happen on an AMQP
consumer in a different process, so a provider's rejection lands in that
consumer's log, not in front of the operator who configured it.

Use the delivery self-test instead:

```
POST /api/v1/organizations/{org_id}/email-config/test
POST /api/v1/tenants/{tenant_id}/email-config/test
```

or the **Send test email** button under either email panel in the admin UI.

It resolves the effective configuration, builds the provider and sends one real
message, then reports what happened — including the provider's own words on a
rejection. The tenant-scoped variant tests the *merged* configuration, so it is
the one that answers "does this tenant actually deliver".

The endpoint takes **no recipient**. The server reads the caller's own address
from their user record, so the test can only mail the person invoking it. It is
gated on `email_config:write`.

---

## Sender domains, per provider

Almost every failed first configuration is a sender-domain problem rather than
a credential problem. A provider will accept your API key and still refuse the
message, because the `from_email` you configured is on a domain you have not
proven you control:

```
Resend returned 403 Forbidden: {"statusCode":403,"message":"The example.org
domain is not verified. Please, add and verify your domain on
https://resend.com/domains","name":"validation_error"}
```

`example.org` here is the *sender*, not the recipient. Pointing the sender at a
domain you own but have not verified fails the same way, and so does an invented
one.

### Resend

Resend's free tier gives you a sending domain with no DNS setup at all:
`onboarding@resend.dev` is pre-verified on every account. Configure the
organization baseline as:

- **From address:** `onboarding@resend.dev`
- **From name:** anything
- **Provider:** Resend, with an API key from
  <https://resend.com/api-keys>

With an unverified-domain sender the free tier can only deliver to the address
that owns the Resend account; that is enough for the self-test, which sends to
the caller. To reach other addresses, add a real domain at
<https://resend.com/domains> and publish the SPF/DKIM records it prints.

Resend also runs fixed simulator addresses — `delivered@resend.dev`,
`bounced@resend.dev`, `complained@resend.dev` — which accept mail without
delivering anything, for exercising the bounce path.

**Do not invent a sender domain.** `admin@axiam.org` and friends look plausible
and are simply someone else's domain, or nobody's; either way they never
verify.

### SendGrid

Requires Single Sender Verification (one address, confirmed by clicking a link
in mail sent to it) or full domain authentication. The free tier includes
both. An unverified sender is a `403` with `from address does not match a
verified Sender Identity`.

### Postmark

Requires a verified Sender Signature for the exact `from_email`, or a verified
domain. New accounts are sandboxed until approval and can only send to
addresses on the account's own domain.

### Brevo

Requires a validated sender address or an authenticated domain. Brevo's free
tier permits an individual sender address validated by email, with no DNS
changes.

### SMTP

No provider-side verification, but the relay's own rules still apply: most
require the envelope sender to be a mailbox the authenticated user may send as.
An empty password is accepted — an unauthenticated local relay on
`localhost:25` is a legitimate deployment — but an empty **host** is refused.

---

## Diagnosing a failure

| Symptom | Cause |
| --- | --- |
| `no email configuration applies to this tenant` | The organization has no baseline row. Set one; a tenant override alone does not send. |
| `email configuration is incomplete: the ... is empty` | The stored credential is empty. Re-save the configuration with the credential filled in. Usually follows a provider-kind switch with a blank credential field. |
| `email is disabled for this scope` | The effective `enabled` is false — either the org switch or a tenant override of it. |
| `403 ... domain is not verified` (or a provider's equivalent) | The **sender** domain is not verified with the provider. See the per-provider section above. |
| `401`/`403` naming the key or token | The credential is wrong or revoked. |
| Nothing at all, no error | Delivery is asynchronous. Check the mail consumer's log for `email.delivery_failed` audit events, and use the self-test to reproduce it in the foreground. |

Failed deliveries retry three times with exponential backoff and then
dead-letter, writing an `email.delivery_failed` audit entry. That entry carries
the provider name and a coarse error class but **never** the recipient address
or any other PII, so the provider's full message lives only in the consumer's
log — which is exactly why the self-test exists.
