---
gsd_plan_version: "1.0"
type: quick
slug: conformance-basic-op-fapi2
created: 2026-09-09
branch: claude/oidc-conformance-first-real-run
---

# Drive the OIDC Basic OP and FAPI 2.0 conformance lanes to success

Continue from the cloud session's four fixes (`fb7956fdd` private_key_jwt wiring,
`a76161bc8` four OAuth2 defects, `91c93aefe` six harness gaps, `2d4cb5900`
self-signed TLS client auth listener). None of them has been validated against a
live suite run — the newest results in `conformance/.run/results/` predate all four.

## Goal

`oidcc-basic-static` and the three `fapi2-security-profile-final-*` plans finish
with no FAILED and no unexplained WARNING. Every remaining non-PASS is either a
documented AXIAM decision or a suite-side limitation, written down.

## Approach

1. Rebuild, bring the stack up, re-register, restart the server so it publishes
   the tenant, run all four plans — establish the post-fix baseline.
2. Triage per lane. Fix AXIAM defects in the crates; fix harness defects in
   `conformance/`. One atomic signed commit per defect.
3. Re-run the affected lane after each fix; full re-run at the end.
4. Regenerate `docs/conformance/*.md` and update the README's findings.

## Known open items carried in

- `oidcc-server-client-secret-post` fails `GetStaticClientConfiguration` — not root-caused (harness gap #6).
- Basic OP's 8 WARNINGs are one claim-placement finding (id_token over-returns
  `email`/`tenant_id`/`org_id`; UserInfo under-returns scope-promised claims).
  `tenant_id`/`org_id` may be load-bearing for the SDKs — check `sdks/CONTRACT.md`
  before moving them.
- `oidcc-refresh-token` fails `CheckTokenEndpointHttpStatus200`.

## Disk hygiene

`target/` is 12G with 24G free. Build only `-p axiam-server --no-default-features`;
reclaim `target/debug/incremental` between cargo runs; never mid-build.
