# Security Policy

AXIAM is identity and access-management software, so a weakness here is a
weakness in every application that trusts it. Reports are welcome and taken
seriously.

The public write-up of how AXIAM is designed to be secure — the STRIDE threat
model, the trust boundaries, the compliance posture and the shared-responsibility
checklist — is published in the **Security** section of the website:
<https://ilpanich.github.io/axiam/>.

## Supported versions

AXIAM has not reached a stable release. Security fixes land on `main` and ship in
the next `1.0.0-alpha*` release; older pre-release tags are not patched.

| Version | Supported |
|---|---|
| `main` / latest `1.0.0-alpha*` | ✅ |
| Any earlier pre-release tag | ❌ |

> **This is alpha software.** It has not undergone an independent third-party
> penetration test or security certification. Do not use it to protect
> production systems until it reaches a stable, audited release.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

**<https://github.com/ilpanich/axiam/security/advisories/new>**

The report is visible only to you and the maintainers. If you cannot use GitHub
advisories, open a public issue that says only that you have a security report to
send and asks for a private channel — no details.

### What to include

- The affected component and version or commit (`crates/…`, an SDK, the admin UI,
  a Helm/Kubernetes manifest).
- What an attacker can achieve — the impact, not just the anomaly.
- Reproduction steps or a proof of concept, plus the configuration it needs.
- Anything you already know about scope: whether it crosses a tenant boundary,
  whether it needs authentication, and which trust boundary it breaches.

Please test only against your own instance. Do not run tests against
infrastructure you do not own, and do not access, modify or retain data that is
not yours.

### What to expect

- **Acknowledgement** within 5 working days.
- **An initial assessment** — severity, affected versions, whether we can
  reproduce it — within 10 working days.
- **Progress updates** at least every 14 days while the issue is open.
- **Coordinated disclosure**: we ask for 90 days from the acknowledgement before
  public disclosure, or until a fix ships if that comes sooner. If a fix will
  take longer, we will say so and agree a date with you.
- **Credit** in the advisory and release notes, unless you prefer to stay
  anonymous.

## Scope

In scope: the AXIAM server and its crates, the eleven client SDKs, the admin UI,
the protocol definitions, and the deployment artifacts published from this
repository.

Out of scope, because they belong to whoever runs the deployment rather than to
the code: cluster and broker configuration, secret storage and backup encryption,
and the platform hardening items listed under *Shared responsibility* in the
Security section of the website. Reports about those are still useful as
documentation gaps — please raise them as ordinary issues.

Findings from automated scanners are welcome, but a scanner's output alone is not
a report: tell us what an attacker could actually do with it.
