# Security review — release 1.1.0, wave W3 (F4)

**Date:** 2026-10-15.
**Against:** `claude/release-1.1.0-w3`, the whole wave diff `3d011573e..ee2a3bacc`
(8 commits, 65 files, 4 367 lines added and 493 removed). Every commit carries a
signature (`gpgsig` header in 8 of 8; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W3 task of the release-1.1.0 plan (§4):
* W3.1 #635 (`3fcac1532`): the device-code grant authenticates its client at
  both endpoints.
* W3.2 #636 (`1d9b8664b`): the admin `PUT` of a `dcr`/`cimd` client refuses,
  `422`, a scope outside the ceiling.
* W3.3 #637 (`fe6878687`): AMQP refuses the server's control actions; the
  purge bound is clamped to its receipt.
* W3.4 #638 (`f07713169`): the hint cap reads the previous window with a
  `SELECT`; the `rate_limit_bucket` sweep.
* W3.5 #639 (`8492128e7`): the hint cap's allowance is configured; a refused
  call is taken back; the bound holds under concurrency.
* W3.6 #640 (`3ae58f5d4`): the export bound is read from the datastore clock.
* W3.7 #641 (`afa4dce4f`): the tombstone deletes `device_grant`; the `sa_`
  path answers a tombstoned tenant `invalid_client`.
* W3.8 #642 (`ee2a3bacc`): the CIBA grant mints no ID token without `openid`;
  text, hygiene and the in-wave regeneration of `sdks/openapi.json`.

**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.41.0, 477 threats), the plan's §10 rules, RFC 6749 §2.3 /
§3.2.1, RFC 8628 §3.1 / §3.4 / §5.6, RFC 9449 §5, RFC 9068 §2.2, and the OWASP
ASVS 5.0 areas the diff touches (V2 anti-automation, V6 authentication, V7/V9
session and tokens, V8 authorization, V16 logging). Every commit message was
read in full and its claims are answered in §3 … §12. Claims were checked
against the code. The OpenAPI document was regenerated from the branch and
compared byte for byte (§9), and the wave's own tests were run (§15). Each
concurrency and clock question was settled by reading the statements and their
order (§6). One probe confirmed R110W3-01 (§2.1); it was run and removed, not
committed. This review fixes nothing. Every finding has
evidence, a proposed fix and an issue body (§16). IDs: `R110W3-nn`.

---

## 0. Summary

**One Medium, one Low and ten Informational.**

The wave does what its eight issues ask, on the paths they name, with the tests
they name. Three of the new tests were not mutation-checked by their
executors; reading them against the unfixed code shows each would fail there
(§8, §9). Two findings need action before release:

* **R110W3-01 (Medium, wave — W3.1, on a pre-existing bucket).** The device
  poll now passes T21.2's public-client bucket. That bucket is keyed on
  (tenant, `client_id`, **transport peer**) at `token_per_min` (120 by
  default).
  * Both shipped topologies put one reverse proxy in front of the server, so
    the transport peer is the proxy. Every device of one public client then
    shares a single bucket.
  * One unauthenticated address can fill that bucket with credential-less
    requests naming the client's public `client_id`. The route limiter, keyed
    on the forwarded address, admits exactly 120 a minute from it. Every real
    device's poll is then answered `429 slow_down` until its code expires.
  * Without an attacker, more than ten devices polling at the default five
    seconds already exceed it.
  * In 1.0.1 the poll ran above this bucket, so the device flow could not be
    starved this way.
  * **Fix in wave:** exempt the device-code grant from that bucket (§2.1).
    The root cause, the transport-peer key, is pre-existing for public
    clients' code and refresh requests and is filed in the same issue.
* **R110W3-02 (Low, wave — W3.1).** This one is not a vulnerability. It is what
  the chosen full fix of #635 costs existing deployments. A device client
  registered as confidential is now refused `invalid_client` at both device
  endpoints unless it sends its credential. Confidential is the default when
  `token_endpoint_auth_method` is omitted, and the 1.0.x B2 quickstart
  registered device clients that way.
  * Devices in the field send only `client_id`, as CONTRACT §14.1 told every
    SDK to, so they stop working at the upgrade.
  * The admin API cannot turn such a client public: it refuses a
    confidential→public change (`oauth2_clients.rs:955`). The operator must
    register a new public client and re-provision every device with its
    `client_id`, or ship a secret to every device.
  * No upgrade note exists. `## [Unreleased]` is empty, and the plan's W8.4
    list of upgrade notes does not name W3.1.
  * Disposition: **the upgrade note is required before release.** The
    orchestrator adds it to §13.3 for W8.4; the proposed text is in §2.2. Two
    small code aids are for the maintainer to choose.

| ID | Finding | Severity | Surface → threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R110W3-01** | The device poll now passes the public-client bucket, keyed on the **transport peer**. Behind the shipped single reverse proxy, every device of one public client shares one `token_per_min` allowance. One unauthenticated address can exhaust it (the route limiter admits it exactly 120 a minute), and every device's poll is then answered `429 slow_down` until its code expires. More than ten honest devices polling at the default interval already exceed it. | **Medium** | `handlers/oauth2.rs:2200-2216`, `extractors/client_info.rs:49` → T-212, T-289 (availability), T21.2 | wave (W3.1) on a pre-existing bucket | **Fix in wave** (§2.1); root cause filed |
| **R110W3-02** | Existing confidential device clients (the default, and the 1.0.x quickstart's) are refused at both device endpoints after the upgrade. The method cannot be switched to `none`, SDKs must not send a secret, and no upgrade note exists. | **Low** | `token_device.rs`, `oauth2_clients.rs:955`, `CHANGELOG.md` → T-289 (availability), RFC 8628 §3.1 | wave (W3.1) | **Upgrade note required (W8.4)**; issue |
| R110W3-03 | The `rate_limit_bucket` sweep compares `updated_at` (datastore clock) with a cutoff on the sweeping replica's clock. A sweeper more than 60 s ahead of the datastore deletes the hint cap's previous-window row while it is still read, so a ten-minute stretch can admit twice the allowance. T-424's "exactly" omits this. Each pass also scans the unindexed table. | Informational | `cleanup.rs:326`, `rate_limit.rs:242` → T-424 | wave (W3.4) | Issue |
| R110W3-04 | The device docs, the website and `device_service.rs` say a leaked device code "is worth nothing to anyone but its client". For a **public** client, which is the documented default for devices, anyone can name the `client_id`, so a leaked approved code still redeems for its holder. | Informational | `docs/api/device-flow.md:83`, `website/src/docs/oauth2.ts:640`, `device_service.rs:42` → T-289 | wave (W3.1) | Issue (text) |
| R110W3-05 | The hint cap's count and take-back retry a write conflict four times (`MAX_WRITE_ATTEMPTS`). More than a handful of concurrent `bc-authorize` calls for one (client, hint) end in `server_error` (`500`) where a refusal would be correct. | Informational | `ciba.rs:1018-1029`, `helpers.rs:284` → T-424 | wave (W3.5) | Issue |
| R110W3-06 | An unknown-client refusal costs no verify on every client-authenticating path except the device grant: the `sa_` path, the three grants of `exchange`, CIBA's and `authenticate_client`. The device grant's equaliser covers a presented secret only, and it creates the reverse asymmetry for a `client_secret_basic` client that sends a body secret. | Informational | `token.rs:1585,1915,2405,2617,3325`, `token_ciba.rs:107`, `token_device.rs:221` → T-3, plan §10 | pre-existing (W3.1 equalises one path) | Issue |
| R110W3-07 | The admin `PUT` bounds a `dcr`/`cimd` row's scopes but not its `grant_types`. An administrator can give a self-registered client `client_credentials`, the device grant or CIBA, which `dcr::validate`/`cimd::validate` never admit. | Informational | `oauth2_clients.rs:432,539` → T-289 | pre-existing (W3.2 left it, stated) | Issue |
| R110W3-08 | Device-grant access tokens carry no `client_id` and no `sid` (unchanged by the wave). The session check therefore answers `401` at every session-validated AXIAM route, UserInfo included. CONTRACT §14 says they carry `client_id` and are answered `403`. RFC 9068 §2.2 requires `client_id`. A DPoP-bound public client's refresh token is not key-bound (RFC 9449 §5, tree-wide). | Informational | `device_service.rs:501`, `extractors/auth.rs:476,1188` → T-289, T-447 | pre-existing (executor note confirmed as pre-existing; rejected as a wave regression) | Issue |
| R110W3-09 | The reserved-namespace check is an ASCII-case prefix test. ` tenants.audit_exported`, a Cyrillic `tеnants.…` or a zero-width-joined form is persisted. No server reader matches any of them, but a human reading the log sees a row that looks like a receipt. | Informational | `models/audit.rs`, `audit_consumer.rs:139` → T-118 | wave (W3.3) | Issue |
| R110W3-10 | `/oauth2/device_authorization` requires `client_id` in the body even for a Basic or assertion client, where RFC 6749 §2.3.1 and RFC 7521 §4.2 allow omitting it. Without it the request gets actix's plain-text `400`, because the route has no `FormConfig` handler. | Informational | `device_service.rs:113`, `server.rs:2116-2123` → interop | wave (W3.1, newly reachable) | Issue |
| R110W3-11 | Contract text the wave made stale: §14 intro and §14.1–14.2, §27 rule 2's device poll answer, §33.3 rule 13, §8/§8b on reserved actions, `oauth2_clients.update`'s `422`, `tenants.delete`'s second `409`. | Informational | `sdks/CONTRACT.md` → W7.1 | wave | Recorded for W7.1 (§13); the device question is the maintainer's |
| R110W3-12 | Text and hygiene: two false sentences in T-289's #635 amendment; T-424's #638 amendment names a trait method #639 removed; a stale `server.rs` comment; a misattributed `token_ciba.rs` comment; an implementation note in the public schema; a wrong operation `summary` (pre-existing); the website's threat-model copy (W8.3). | Informational | various | wave | Issue |

**What held.**
* **W3.1 (§3).**
  * Both endpoints reach the client only through `TokenService`'s private
    authentication. The registration decides the method; the tenant is read
    after the credential.
  * Order at the poll: `device_code` presence; client authentication; FAPI;
    the grant check; binding; then the grant read. A foreign client is
    `invalid_grant` before `record_poll`.
  * No refusal writes to the grant or reveals its state. Foreign and unknown
    codes are indistinguishable in answer, writes and cost.
  * The equalising hash can never verify. A match needs an all-zero
    HMAC-SHA256 tag, and the verdict is discarded anyway.
  * `cnf` and `token_type: DPoP` follow `certificate_binding_for`, the rule of
    every other grant.
  * A public client presenting any credential is refused.
  * The DPoP proof is verified once, before client authentication, as for
    every grant.
  * The poll now passes every limiter the CIBA grant does. It also passes the
    public-client bucket, which behind a proxy is not a per-device limit
    (R110W3-01).
  * CIMD materialisation is skipped where it would buy only a fetch.
* **W3.2 (§4).** The `422` reads the same policy and predicate as the grant
  points. Keeping a held scope that is now outside the ceiling launders
  nothing: it can only keep a scope, never add one, and every grant withholds
  it.
* **W3.3 (§5).**
  * The refusal sits after the signature and freshness checks and before the
    nonce.
  * Every reader of a control action matches the exact ASCII spelling.
  * No path but the AMQP one writes a caller-chosen audit action.
  * The clamp is `min(exported_through, receipt.timestamp)` over a receipt
    found by id, action and tenant.
* **W3.4 / W3.5 (§6).**
  * The count-read-take-back protocol proves its two-window bound, and the
    "overtaken" rule closes the 1.0.1 hole.
  * The sweep's retention covers every reader in the tree.
  * Two sweepers delete a row once.
  * A `0` allowance stops the boot.
* **W3.6 (§7).** Every `AuditLogRepository` implementation implements
  `datastore_now`. The only production wrapper forwards it. The receipt is
  stamped after the bound.
* **W3.7 (§8).** The tombstone transaction deletes `device_grant`. The `sa_`
  path reads the tenant after one verify. Both new tests fail on the old code.
* **W3.8 (§9).** No ID token without `openid`. The regenerated spec is
  byte-identical to the committed one, and each change in it is the wave's.
* **§10, CI parity, threat model (§10, §11, §15).**
  * The §10 rules hold for what the wave added, save the pre-existing
    exception R110W3-06.
  * The SAML-off `check`, clippy `-D warnings` and fmt pass on the touched
    crates under `RUSTFLAGS=-Dwarnings`.
  * The five amended entries are word for word in both copies.

**Verdict on merge.** Two items before the merge:
* **R110W3-01** is a few lines in `token_inner` and its test, and should be
  fixed in the wave. Without it, any deployment behind the shipped proxy lets
  one address starve a public client's device onboarding.
* **R110W3-02** must reach the release notes. It is the only finding that
  changes what an operator has to do at the upgrade.

The contract question (§13) decides what the eleven SDKs tell a confidential
device client, and it should be answered before W7.1. The rest are issues for
the next patch milestone.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Device grant client authentication | W3.1 #635 | `token_device.rs` (new), `token.rs` (`resolve_client_id`, `carries_no_client_credential`, `authenticate_client_credential`, `verify_client_credential`, `live_tenant`, `certificate_binding_for`, `authenticate_client`), `device_service.rs`, `handlers/oauth2.rs` (`token_inner`, `poll_device_grant`, `device_authorization*`), `client_secret.rs` (`verify`), `fapi.rs`, `server.rs` (route limiters), `extractors/auth.rs` (session check), `device_flow_test.rs`, `oauth2_client_test.rs`, `resource_indicators_test.rs` | **read in full**; every exit of both endpoints listed with what it writes and costs |
| Admin scope refusal | W3.2 #636 | `oauth2_clients.rs` (`update`, `scopes_outside_ceiling`), `scope_ceiling.rs`, `scope_policy.rs`, `error.rs` | read in full |
| Reserved actions, receipt, purge bound | W3.3 #637 | `models/audit.rs`, `audit_consumer.rs`, `tenants.rs` (`recent_export_receipt`, `delete`, `export_audit`), `tenant_purge.rs` (`audit_export_cutoff`), every audit-append site in `crates/*/src` (`rg 'action: *(req\|msg\|input\|body…)\.'`), every SQL reader of `action` | **read in full**; writers and readers enumerated |
| Hint cap, sweep | W3.4 #638, W3.5 #639 | `ciba.rs` (`CibaHintCap`, `admit`, `MemStore`), `rate_limit.rs` (`increment_by`, `peek_bucket`, `decrement`, `delete_stale`), `rate_limit_counter.rs` (window, sliding mode), gRPC `WINDOW_SECS`, `cleanup.rs`, `job_health.rs`, `boot.rs`, `config/rate_limit.rs`, `helpers.rs` (`retry_on_write_conflict`) | **read in full**; the bound re-derived from the statements (§6) |
| Export clock | W3.6 #640 | `repository.rs`, `audit.rs`, `notification.rs`, `tenants.rs`, `audit_export_clock_test.rs`, every `impl AuditLogRepository` (14) | read in full |
| Tombstone residuals | W3.7 #641 | `tenant.rs` (tombstone transaction), `token.rs` `handle_client_credentials_service_account`, the two new tests | read in full; the tests read against the parent commit |
| CIBA ID token, spec | W3.8 #642 | `token_ciba.rs`, `client_grants.rs`, `boot.rs`, `sdks/openapi.json`, `management-registry.json`, CHANGELOG | read; spec regenerated (§9) |
| Threat model, docs, contract | all | T-118, T-289, T-422, T-424, T-472 in both copies; `docs/api/device-flow.md`, `asyncapi.yml`, `docs/admin/README.md`, `rate-limit-sizing.md`, `docs/conformance/README.md`, the website, the quickstart, the bench scenario; `sdks/CONTRACT.md` §8, §8b, §14, §27, §33.3 | compared (§11 … §13) |

Not run: the W3.8 (e) quick-bench cell (it needs the bench host; the executor
reported it for §13.3), the frontend, a multi-replica deployment, a networked
SurrealDB, and the eleven SDKs' device-flow fixtures (not in this repository,
see §13).

## 2. The two findings that need action before release

### 2.1 R110W3-01 — one address can starve a public client's device polls

**Severity: Medium.** The attack is unauthenticated and cheap: about two
requests a second from one address. It is targeted at a named public client,
and it works on the shipped topology. Its effect is availability: no device of
that client completes the flow while the flood lasts, and no data is exposed.
It is an instance of T-212 ("an unaccounted proxy hop collapses every per-IP
rate limit into one bucket"; High, Mitigated), whose mitigation this bucket
does not use.

**Origin.** The wave (W3.1) moved the device poll under a bucket that already
had this property. For public clients' code and refresh requests the property
is pre-existing (T21.2).

**Evidence.**
* `crates/axiam-api-rest/src/handlers/oauth2.rs:2200-2216`: every token
  request that carries no client credential is counted in
  `oauth2_token_public:{tenant}:{client_id}:{peer_ip}` at `token_per_min`
  (120 by default; 600 and 6 000 under the gateway and mesh presets).
* Since `3fcac15` the device poll is dispatched below that check
  (`:2267-2273`), and a public device client's poll carries no credential by
  definition.
* `peer_ip` (`extractors/client_info.rs:49-53`) is `connection_info().peer_addr()`:
  the TCP peer, which is the reverse proxy whenever there is one. Its own doc
  says so ("Behind a trusted reverse proxy that is the proxy's own address").
* `docs/deployment/README.md:878`: "Both shipped topologies have exactly one
  proxy". T-212's mitigation (`AXIAM__RATE_LIMIT__TRUSTED_HOPS`,
  `XForwardedForKeyExtractor`) keys the route's own governor and shared
  counter on the address the proxy saw (`server.rs:42-99`). The public bucket
  does not use it.
* Before the wave the poll returned above this point
  (`3d011573e:handlers/oauth2.rs:2151-2186`). Its only limiters were the
  route's, keyed on the forwarded address, and each grant's own poll interval.

**Probe (run, not committed).** The probe was a copy of `device_flow_test.rs`
with the harness's `rate_limit_cfg.token_per_min` set to 3. Every request
came from one transport peer, `127.0.0.1:34567` (the proxy). Three
credential-less token requests from `X-Forwarded-For: 203.0.113.7` named the
public fixture client, and each was answered `400`. The fixture device's
poll then came from `X-Forwarded-For: 198.51.100.9`, and it was answered
`429 {"error":"slow_down","error_description":"token rate limit exceeded for
this client and address"}`.

**Failure scenario.** Behind the shipped edge, take a tenant with a public
device client `oa_tv`.
1. An attacker at one address sends 120 requests a minute to
   `POST /oauth2/token?tenant_id=…` with `client_id=oa_tv`, any `grant_type`
   and no credential. The route limiter keys on the attacker's forwarded
   address and admits all 120.
2. Each is counted in `oauth2_token_public:{tenant}:oa_tv:{proxy}`, the bucket
   every device of `oa_tv` polls through.
3. Every device's poll is answered `429 slow_down`. The device adds five
   seconds and polls again, into the same full bucket, until `expires_in`
   passes.
4. Users approve, and no device ever collects.

Without an attacker, a fleet of more than ten devices onboarding at once
through the proxy (twelve polls a minute each) exceeds the default allowance
and is slowed by everyone else's polls.

**Proposed fix (in wave).**
1. **The root cause, preferred.** Key the public-client bucket on the address
   T-212's extractor derives, not on the transport peer. Factor the
   selection in `XForwardedForKeyExtractor::extract`
   (`extractors/rate_limit.rs:101-131`: the rightmost untrusted hop, else the
   peer, with the R-4 warning) into a function over `&HttpRequest`. Read
   `AXIAM__RATE_LIMIT__TRUSTED_HOPS` as `build_governor` does, and use the
   function at `oauth2.rs:2205` in place of `peer_ip`.
   * This is the address the route limiter on the same endpoint already
     trusts. Under `trusted_hops = proxies − 1` it is appended by the proxy,
     not chosen by the caller, so SEC-087's forgeability concern does not
     apply.
   * The `ip_address` written to audit rows stays `peer_ip`.
   * It also fixes the same exposure for public clients' code and refresh
     requests.
2. **The narrow alternative**, if T21.2 is to stay untouched in this wave.
   Skip the public-client bucket when `grant_type` is the device-code URN.
   That restores 1.0.1's limiters for the poll: the route's, on the forwarded
   address, and the grant's own `slow_down` interval, which only the grant's
   authenticated client reaches. Root cause (1) is then filed with this
   review's issue body.

**Tests** (`device_flow_test.rs`, with `token_per_min` set low in the
harness's `rate_limit_cfg`):
* Requests from one transport peer with two different `X-Forwarded-For`
  addresses: filling the public bucket from address A does not answer a
  device poll from address B `429`, for fix (1). For fix (2), polls are not
  counted in the public bucket at all.
* The existing T21.2 tests still pass: a credential-less flood from one
  address still meets `slow_down`.
* Fix (1) only: with `trusted_hops >= hops` the key falls back to the peer,
  as the governor's does.

### 2.2 R110W3-02 — existing confidential device clients break at the upgrade

**Severity: Low.** No security property is lost; this is an availability and
upgrade cost of the security fix. **Origin: the wave (W3.1).** It follows from
the plan's choice of "the full fix, not the registration-time refusal" (§4,
W3.1), which is sound. Nothing tells an operator about the cost.

**Evidence.**
* **Both endpoints authenticate.** `crates/axiam-oauth2/src/token_device.rs:108-169`
  authenticates the client at both endpoints through
  `authenticate_client_credential`, so a `client_secret_post` client that
  sends no secret is refused `invalid_client` (`token.rs:1366-1367`).
* **Confidential is the default.** The device docs now say so:
  `docs/api/device-flow.md`, "Omit `token_endpoint_auth_method` and the client
  is confidential (`client_secret_post`, the default): it must then send its
  `client_secret` at both endpoints".
* **The 1.0.x quickstart registered exactly that.**
  `examples/b2-iot-device-quickstart/device-quickstart.sh` registered without
  `token_endpoint_auth_method`, and its device sent `client_id` alone. W3.1
  changed the script and the README to register a public client.
* **The SDKs send no secret.** CONTRACT §14.1 (`sdks/CONTRACT.md:2859-2861`):
  "`device_authorize` is **unauthenticated** … SDKs MUST NOT send
  `client_secret` on it". Every SDK built to that rule sends only `client_id`.
* **The method cannot be changed to `none`.**
  `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:955` refuses any
  change between public and confidential ("whether a client is public is
  decided at registration").
* **No upgrade note exists.** `CHANGELOG.md` `## [Unreleased]` is empty. The
  plan's W8.4 row lists "W3.2's 422; W1.10's key form; W3.5's knob; the
  `network:*` permissions" and not W3.1.

**Failure scenario.** An operator runs a 1.0.x fleet of devices registered by
the quickstart. Every device's next `POST /oauth2/device_authorization` after
the upgrade is `401 invalid_client`. Re-enabling the fleet means one of:
* registering a new public client and changing the `client_id` baked into
  every device;
* distributing a client secret to devices that cannot keep one, as RFC 8628
  §5.6 warns.

The server logs only the per-request `oauth2.client_auth_failed` audit row, so
the cause is not obvious.

**Proposed fix.**
1. **Required — the upgrade note** (W8.4, `## [1.1.0]`, "Upgrading — read
   before you upgrade"):
   > **Device-flow clients must be public or authenticate (#635).** Both
   > device endpoints now authenticate the client by its registered method. A
   > device client registered without `token_endpoint_auth_method` is
   > confidential (`client_secret_post`) and is refused `401 invalid_client`
   > unless it sends its secret at `/oauth2/device_authorization` and at the
   > poll. The 1.0.x B2 quickstart registered such clients. Before upgrading,
   > find them (`GET /api/v1/oauth2-clients`, `grant_types` containing
   > `urn:ietf:params:oauth:grant-type:device_code`, `token_endpoint_auth_method`
   > not `none`). Register a public client (`token_endpoint_auth_method: none`)
   > for devices that keep no secret, and move the devices to its `client_id`.
   > A client's method cannot be changed between public and confidential.
   > SDKs do not send a secret on `device_authorize` (CONTRACT §14.1).
2. **Optional, small — make it visible.** At boot, `warn!` once with the
   number of confidential clients that hold the device grant, per tenant (one
   query over `oauth2_client`). Test: a boot with one such client logs the
   count.
3. **Maintainer's choice — a migration path without re-provisioning.** Allow
   `PUT … token_endpoint_auth_method: none` on a confidential client whose
   `grant_types` hold only the device grant (and `refresh_token`), clearing
   `client_secret_hash` in the same write. Its devices keep their `client_id`.
   This relaxes `oauth2_clients.rs:955` for one grant shape; the rule's
   rationale ("a stale secret on a public row would be a credential AXIAM
   never checks") is met by clearing the hash. Tests:
   * the conversion succeeds and the row holds no hash;
   * a client that also holds `client_credentials` or CIBA is still refused;
   * the converted client's device flow works with `client_id` alone.

**Test.** For the note, none. For (2) and (3), as above.

## 3. W3.1 — the device grant's client authentication (orchestrator point 1)

### 3.1 Order, writes and answers at the poll

The order is: `token_inner` (`handlers/oauth2.rs:2128-2300`), then
`poll_device_grant` (`:2366-2396`), then `authenticate_device_poll`
(`token_device.rs:144-169`), then `poll_at` (`device_service.rs:349-525`).

| Step | Refusal | Writes | Verifies |
|---|---|---|---|
| CIMD materialise (URL-shaped `client_id`) | none | a CIMD row, as for every grant | — |
| context, DPoP proof (`dpop_from_request`, `:2168`) | `invalid_dpop_proof` | the proof's `jti` | the proof |
| public-client bucket (`:2200`), only without a credential | `429 slow_down` | a counter | — |
| `device_code` present | `invalid_request` | — | — |
| `client_id` resolved (body, Basic, assertion) | `invalid_request` | — | — |
| client read; unknown / other tenant | `invalid_client` | — | one HMAC if a secret was presented (§3.2) |
| public client presenting a credential | `invalid_client` | — | one HMAC (`spend_one_verify`), then refused without another |
| `authenticate_client_credential` | `invalid_client` | — | the method's own |
| tenant live (`live_tenant`) | `invalid_client` | — | — (after the credential) |
| `fapi::enforce_token_request` | its codes | — | — |
| holds the device grant | `invalid_client` | — | — |
| `certificate_binding_for` | `invalid_client` | — | — |
| grant read; **another client's** | `invalid_grant "unknown device code"` | **nothing** | — |
| `record_poll`; too fast | `slow_down` | `last_polled_at` | — |
| expired, `resource`, pending / denied / redeemed | as RFC 8628 | — | — |
| redeem; subject re-read | `invalid_grant` | the redeem | — |

**"Grant read before client auth?"** No. The client is authenticated first
(`poll_device_grant`, `oauth2.rs:2382-2386`), and the grant is read only inside
`poll_at`.

**"A foreign `client_id` → `invalid_grant` before `record_poll`: does that
leak grant existence, and is that a change?"** It leaks nothing.
* An unknown code and another client's code take the same path: one indexed
  read, no write, and the same status, `error` and `error_description`
  (`device_service.rs:363-370`). The test pins the description
  (`a_foreign_client_id_is_invalid_grant_and_leaves_the_grant_untouched`).
* Device codes are 256-bit CSPRNG values, so guessing is not a threat model.
* Before the wave, anyone holding a code learned its whole state and could
  redeem it; an unknown code got `invalid_grant` after a `record_poll` that
  matched nothing. So the change strictly removes information.
* Only the grant's own authenticated client now records a poll or sees a
  state.

**"No refusal spends or reveals a grant."** Holds. Every refusal above the
grant read leaves the row untouched; `assert_untouched` checks
`last_polled_at` in seven tests. Below it, only the grant's own client is
answered.

**The start endpoint.** `device_authorization_inner` (`oauth2.rs:4335-4425`)
builds the token endpoint's context. It resolves `client_id` with
`resolve_client_id`, and `authenticate_device_authorization` then runs:
1. the read and the credential;
2. `fapi::enforce_client_authentication`;
3. the grant check, `unauthorized_client`, after authentication.

A refusal there allocates no grant and no user code. An `invalid_client` is
audited as at the token endpoint, detached as `§22.3 residual 1` requires.

### 3.2 One verify per refusal, and the fixed v2 hash

* **The hash can never verify.** `ClientSecretHasher::verify`
  (`axiam-auth/src/client_secret.rs:364-412`) takes the v2 branch for any
  stored string that is not 64 characters long. It computes
  `v2.hs256$<hex HMAC-SHA256(pepper, presented)>` (and the previous pepper's,
  when one is configured) and compares in constant time. A match needs an
  all-zero 256-bit tag, which has probability 2⁻²⁵⁶ per pepper. The verdict
  is discarded in any case (`black_box`, `token_device.rs:230-232`), so even a
  match would authenticate nothing.
* **The construction is sound.** The constant has `V2_HASH_LEN` and the
  prefix, so the branch, the work (one or two HMACs) and the comparison
  length equal a real row's. The unit test pins this
  (`the_unknown_client_hash_is_a_well_formed_v2_hash`).
* **Coverage.** It covers a secret in the body or the Basic header. It does not
  cover an unknown client that presented only a `client_assertion`: no
  verify, against a signature verify for a known `private_key_jwt` client.
  Nor does it cover the reverse case: a known `client_secret_basic` client
  that sent only a body secret is refused without a verify (`token.rs:1410-1415`),
  while an unknown client with a body secret now costs one. Both differences
  are microseconds, and client ids are not secrets. They are filed with the
  tree-wide pre-existing case in R110W3-06.
* **`global()` failing.** A release build without an installed hasher would
  skip the verify. The boot installs it before serving (`install_from_config`),
  so this does not arise.

### 3.3 FAPI, binding, a public client's credential, the DPoP order

* **FAPI at both endpoints.**
  * At the start, `enforce_client_authentication` (`token_device.rs:118`): no
    DPoP proof is carried there, as at PAR and `bc-authorize`.
  * At the poll, the whole of `enforce_token_request` (`:156`), after
    authentication, so the refusal reports registration facts only to the
    credential's holder.
  * `a_fapi2_device_client_must_meet_the_profile_at_the_poll` covers the poll.
* **`cnf` binding.** `certificate_binding_for` (`token.rs:1492-1535`) runs
  before the grant is read. A DPoP-bound client without a verified proof, or
  an mTLS-bound one without a certificate, is refused, never downgraded.
  `issue_access_token_bound(…, client.cnf)` carries the binding
  (`device_service.rs:501-510`), and `token_type_for` announces `DPoP`. With
  `cnf = None` the token is byte-identical to 1.0.1's (`axiam-auth`
  `token.rs:870-875`). Tests: `a_dpop_bound_clients_device_token_carries_cnf_jkt`
  and `an_unbound_clients_device_token_stays_a_bearer_token`. The mTLS binding
  has no device-specific test; it is the shared function every grant's tests
  cover.
* **A public client presenting a credential** is refused at both endpoints:
  `verify_client_credential`'s T21.2 arm, after `spend_one_verify`. Test:
  `a_public_device_client_presenting_a_secret_is_refused`.
* **The DPoP order.** The proof is verified and its `jti` spent once, before
  any grant authenticates its client (`oauth2.rs:2168`). A bad proof is
  `invalid_dpop_proof`, decided from the request alone, so the order creates
  no client oracle. A device must now send a fresh proof on every poll, as
  RFC 9449 requires.

### 3.4 Limiters on the moved branch

* **Before the wave.** The poll passed the route's governor and shared counter
  (`server.rs`, `/token`), both keyed on the forwarded address under
  `TRUSTED_HOPS`, and nothing else.
* **Now.** It also passes the public-client bucket
  (`oauth2_token_public:{tenant}:{client_id}:{peer}` at `token_per_min`)
  whenever it carries no credential, which is the public device's normal
  poll.
* **Without a proxy** the bucket is a subset of the route's per-address bucket
  at the same allowance, and adds coverage without refusing a fleet the route
  would admit.
* **Behind the shipped proxy** `peer` is the proxy. The bucket then becomes
  one allowance for every device of the client, which any one address can
  exhaust (R110W3-01, §2.1).
* `/oauth2/device_authorization` keeps its own per-address limiter (12/min)
  and shared bucket. It is not under the public bucket.

### 3.5 CIMD

* The start endpoint skips `materialise_if_cimd` (`oauth2.rs:4343-4347`). A
  CIMD client can never hold the grant (`cimd.rs:75`), so a fetch would buy
  only a refusal.
* The token endpoint materialises for every grant, the device poll now
  included. That fetch path and its limiter already served every other grant
  for any caller who chose another `grant_type`, so nothing new is reachable.

### 3.6 The executor's note: device tokens carry no `sid` and no `client_id`

**Confirmed as a fact; rejected as a wave regression.**
* The device grant mints with `issue_access_token_bound`, which passes
  `client_id: None` and `session: None` (`axiam-auth/src/token.rs:888-958`).
  Before the wave it minted with `issue_access_token`, which delegates to the
  same function with `cnf: None`. The claims are therefore unchanged except
  for `cnf`.
* With no `sid`, `check_user_aud_and_parse_jti` falls back to the random `jti`
  (`extractors/auth.rs:1188`). `is_session_active` finds no such session, so
  every `AuthenticatedUser` route answers `401 "session revoked or expired"`
  (`:476-482`). That includes `/api/v1/device/verify` and `/decide`, and
  UserInfo.
* So a device token cannot use AXIAM's own user APIs. It never could, and
  `/api/v1/device/*` is the approving user's console surface, not the
  device's, so nothing the device flow needs breaks.
* What is wrong is the contract's description of it, and two standards
  points. All are in R110W3-08.

### 3.7 A leaked device code of a public client

* RFC 8628 §5.6 accepts that a public client's device code is the grant's
  only secret. For a public client, `authenticate_device_poll` authenticates
  "nothing", so anyone who names the public `client_id` (which is public data)
  and holds the code redeems the grant. If the client is DPoP-bound, the
  tokens are bound to the holder's own key.
* The wave closes the case for confidential, mTLS and `private_key_jwt`
  clients, as intended.
* Its text claims more (R110W3-04).

## 4. W3.2 — the admin scope refusal (orchestrator point 2)

* **The refusal applies only to `dcr` and `cimd` rows.**
  `scopes_outside_ceiling` (`oauth2_clients.rs:621-646`) returns nothing
  unless `scope_ceiling::applies_to(stored.managed_by)`. That is the same
  exhaustive predicate the read points use, and `Admin` is `false`. The list
  comes from the same `SettingsScopePolicy`. A failed read is an error,
  never "no ceiling".
* **The match is the same.** Matching is exact string equality, as
  `scope_ceiling::narrow` uses (`scope_ceiling.rs:136-138`), so the write-time
  and grant-time answers cannot disagree.
* **No laundering.** A scope the row already holds but the ceiling has since
  removed may be re-sent. That cannot launder anything:
  * The exemption is `!stored.scopes.contains(scope)` (`:641`). It can only
    keep a scope the row holds. It never adds one, and a scope dropped once
    cannot come back while it is outside the list.
  * Every grant applies the ceiling at read time and withholds it
    (`apply_to_client`, `ceiling_for`).
  * If the tenant later re-admits the scope, the row serves it again. That is
    exactly what happens to a row nobody edited, so the edit changed nothing
    an attacker could use.
  * The decision is sound. It avoids stranding a row whose admin form posts
    the record back.
* **Residuals.**
  * The read-then-write window is stated in T-289; the grant-time ceiling
    covers it.
  * An administrator's edit of a `cimd` row is overwritten at the next
    re-materialisation anyway.
  * `grant_types` is unbounded on `dcr`/`cimd` rows (R110W3-07).
* **Create.** `POST` cannot claim `dcr`/`cimd` provenance; the test pins it
  (`admin_create_cannot_claim_dcr_provenance`).
* **The new slug.** `scope_exceeds_ceiling` with a `422` is new wire surface.
  §2 maps a `422` to `ValidationError`, so SDKs need no code. The contract
  text is W7.1's (R110W3-11).

## 5. W3.3 — reserved actions, the clamp, the receipt (orchestrator point 3)

* **Variants of the reserved namespaces** (`models/audit.rs`,
  `reserved_action_namespace`).
  * ASCII case is ignored: `TENANTS.Audit_Exported` is refused.
  * A leading space, a Unicode confusable (Cyrillic `е`, U+0435), a full-width
    dot or a zero-width character is **not** refused.
  * `tenants` without a dot is not refused, by design.
  * None of these matters to the server. Every reader of a control action
    matches the exact ASCII string in SQL: `tenant_purge.rs:577,598` and the
    receipt lookup through `AuditLogFilter.action` (`audit.rs:194`, `action =
    $action`).
  * A lookalike row cannot unblock a deletion or set a purge bound. It can
    mislead a human reading the audit log (R110W3-09).
* **Position.** The check runs after the HMAC, `key_version` and freshness
  checks, and before the nonce is recorded (`audit_consumer.rs:139-146`).
  * An unsigned or stale message never reaches it.
  * A refused one does not spend its nonce. Replaying it within the freshness
    window costs a signature check and a nack each time, bounded by the
    broker, and persists nothing.
* **Other writers of a caller-chosen action.** None. Every audit append in
  `crates/*/src` was enumerated:
  * the server's fixed constants;
  * the request middleware's `METHOD /path`, which never starts with
    `tenants.` or `gdpr.`;
  * the GDPR file dead-letter, which replays the server's own entries and is
    operator-side.

  The other `action:` fields from requests (`authz_consumer.rs:163`,
  `authz_check.rs:228`, `authorization.rs:153`) are authorization requests,
  not audit rows. gRPC writes no audit row.
* **Can a forged receipt be planted in the deleted tenant's log?**
  * Not since this commit: AMQP was the only path for a caller-chosen action.
  * A receipt planted under 1.0.x would have to be the tenant's **newest**
    receipt, less than six hours old at the deletion. That is reachable only
    if the deletion follows the upgrade within six hours.
  * Even then, `delete` refuses one claiming rows after itself
    (`tenants.rs:733`), and the purge clamps to its datastore timestamp
    (`tenant_purge.rs:611`).
  * The remaining forgery, `exported_through` at or before the forged row's
    own timestamp, deletes only rows written before the forgery. Those rows
    the operator's own export (if any) did not cover. The case is negligible
    and is stated in T-118.
* **The purge's clamp.**
  * The receipt is found by id, action and `tenant_id = $id`
    (`tenant_purge.rs:597-604`), so another tenant's receipt yields no bound
    (fail-safe: keep everything).
  * A clamped pass deletes the receipt itself (its timestamp equals the
    bound). A resumed purge then finds no receipt and keeps the rest, which is
    strict.
  * An honest receipt's `exported_through` (the datastore time at export
    start, since W3.6) is earlier than its stamp, so it survives.
* **The `409` at deletion** is decided before any revocation. The newest
  receipt alone is judged, so a bad newest receipt blocks even if an older
  good one exists. That is strict, and the remedy (export again) is in the
  message.

## 6. W3.4 / W3.5 — the hint cap under concurrency, and the sweep (orchestrator point 4)

### 6.1 The protocol, re-derived

The statements:
* `increment_by` is one `UPSERT` (`rate_limit.rs:110-125`). It resets to
  `delta` when the stored window is older, and otherwise adds, including when
  the stored window is newer.
* `peek_bucket` is a `SELECT`.
* `decrement` is one conditional `UPDATE … WHERE window_start = $w AND count >
  0`.

A call stamped in window *s* increments slot(*s*), then reads slot(*s*−1),
which shares its parity with *s*+1.

* **Within a window.**
  * A bucket's count is the admitted calls already counted, plus refused
    calls not yet taken back.
  * A take-back is conditional on its own window and follows its own
    increment, so it can never remove another call's count.
  * So the admitted call whose increment came last has *v* ≥ the window's
    admissions.
* **Across a boundary (*s*−1, *s*).** Let *X* be an admitted call stamped
  *s*−1, and *Y\** the admitted call of *s* whose increment came last.
  * *X* read slot(*s*) and did not find window *s*, or it would have been
    overtaken. So *X*'s read preceded every increment stamped *s*, in
    particular *Y\**'s.
  * Each call's increment precedes its own read. So
    X.inc < X.read < Y\*.inc < Y\*.read, and *Y\** counts *X*.
  * *X* is never taken back, and the bucket cannot move to *s*+1 before
    *Y\**'s read without *Y\** being overtaken.
  * So *v*(*Y\**) + prev(*Y\**) ≥ admitted(*s*) + admitted(*s*−1), and it is
    at most the allowance because *Y\** was admitted.
  * If *s* admits nothing, the within-window argument bounds *s*−1 alone.
* **The bound holds as stated**, under the stated assumption (no call in
  flight across two windows), and the 1.0.1 hole (a late *s*−1 call reading
  window *s*'s count by parity) is the overtaken case, now refused.
* **Taking back a refused call cannot be exploited across clients.** Keys
  carry the client, so a client can only cause spurious refusals for itself.
* **What depends on the hint.** The cost of a refusal (a count, a read, a
  take-back) does not depend on the hint's resolution: the cap runs before
  the lookup (`ciba.rs:1427-1435`). T-422 holds.
* **Conflict retries.** An aborted statement wrote nothing, so a retry cannot
  double-count. `MAX_WRITE_ATTEMPTS = 4`, so heavy same-hint concurrency
  surfaces as `server_error` (R110W3-05).

### 6.2 Can the sweep delete a row a live limiter reads?

The readers of a stored count in the tree:
1. the REST and gRPC shared counters, by the `increment_by` return, in their
   own 60-second window (`DEFAULT_WINDOW_SECS`, fixed in code and not
   configurable; the sliding mode's previous window is in local memory);
2. the hint cap's own window and its previous window.

No other writer exists (`rg increment_by`). The worst reader is the hint cap
at the end of window *s* reading window *s*−1's row, last written at its
window's start: an age just under 2 W = 20 min. Retention is 2 W + 60 s, so
**on one clock** no live row is deleted, the REST/gRPC shared counters'
current and previous windows included. Two replicas sweeping at once delete a
row once (`DELETE $ids WHERE updated_at < $cutoff` re-checks the condition per
record), and a conflict between them is reported as `0`.

**Across clocks it is not safe.**
* `updated_at` is the datastore's `time::now()`, but the cutoff is
  `Utc::now() − retention` on the **sweeping replica**
  (`cleanup.rs:326`, `sweep_rate_limit_buckets(repo, Utc::now())`).
* If the sweeper runs more than 60 s ahead of the datastore, the hint cap's
  previous-window row is deleted while it is still read. It then reads as
  `Counted(0)`, and the stretch admits up to twice the allowance.
* If the sweeper runs more than about 11 min ahead, the current row can be
  deleted too.
* The commit's doc comment states this as "never a refusal that should not
  happen", and T-424's #638 amendment states it as a residual. It is lenient
  in exactly the direction the "exactly … no overshoot" of #639's amendment
  and `CibaHintCap`'s doc rule out, and those two texts do not name the
  assumption.
* W3.6 removed the same app-versus-datastore mix from the export for this
  reason. This is R110W3-03; the fix is to evaluate the cutoff in the
  datastore.

### 6.3 The allowance at boot

* `boot.rs:1334` passes `config.rate_limit.bc_authorize_per_hint_checked()`.
  It panics with `validate()`'s message on `0` before the server serves,
  because the CIBA service is built before `validate()` runs.
* The value is never preset, so it is final when read.
* The test harness's `AppState::for_test` (`state/mod.rs:791`) keeps the default.
  Production builds `AppState` in `boot.rs` and does not use that path.
* `the_hint_cap_allowance_is_read_from_the_environment` covers `25`, unset and
  `0`.

## 7. W3.6 — `datastore_now` (orchestrator point 5)

* **Implementations.** Fourteen implement `AuditLogRepository`; the trait
  method is required, with no default.
  * The production implementation (`axiam-db` `audit.rs:279`) runs `RETURN
    time::now()`, the default that stamps `audit_log.timestamp`.
  * The only production wrapper, `NotifyingAuditLog`
    (`axiam-audit/src/notification.rs:605-609`), forwards to `inner`.
  * The other twelve are test doubles. Eleven return `Utc::now()`: in
    `axiam-amqp` (`inprocess.rs:1352` is inside `#[cfg(test)] mod tests`,
    `:759`), `axiam-audit`, `axiam-federation`, `axiam-oauth2` and
    `axiam-server` tests. The twelfth, `Behind` in
    `audit_export_clock_test.rs`, skews the inner repository's clock on
    purpose.
  * No production code calls `Utc::now()` in its place.
* **Order.** The bound is read before the first page, and the receipt is
  appended after the last (`tenants.rs:880-…`), so the receipt's stamp is at
  or after the bound on one node.
* **The cluster residual** (nodes disagreeing on time) and the six-hour
  freshness on the app clock are stated in T-118. Both are confirmed as
  harmless in §14.

## 8. W3.7 — the tombstone and the `sa_` path (orchestrator point 6)

* **(c)** The tombstone transaction runs `DELETE device_grant WHERE tenant_id
  = $id` (`tenant.rs:646`), beside `ciba_request` and inside the same
  transaction. The purge keeps its own idempotent step.
* **(d)** `live_tenant` runs after the secret verify and the status check,
  and before the scope check (`token.rs:1631-1642`). A wrong secret is
  refused before the read; a tombstoned tenant costs one verify and one read
  and answers the same `invalid_client`.
* **Do the tests fail on the old code?** Both, read against `3d011573e`:
  * `token_service.rs::a_tombstoned_tenants_service_account_authenticates_nowhere`.
    Old code answered "the right secret" with `invalid_request "unknown
    tenant"` and "a scope" with `invalid_scope` (the scope check ran first).
    The test asserts `invalid_client` with `CLIENT_AUTH_FAILED` for both, so
    it fails twice.
  * `device_flow_test.rs::tombstoning_a_tenant_deletes_its_device_grants_and_no_other_tenants`.
    Old code left both rows, and the test asserts `rows(f.tenant_id) == 0`
    after `delete`. Its last assertion, the poll's `invalid_client`, also
    depends on W3.1.
* **The executor's follow-up: an unknown `sa_` id is refused without a
  verify.** Confirmed (`token.rs:1574-1590`). It is pre-existing and not
  touched by the wave, and it matches every other unknown-client refusal
  except the device grant's: **Informational**, R110W3-06.

## 9. W3.8 and the specification (orchestrator point 7)

* **(c) No ID token without `openid`.** `token_ciba.rs:296-318` mints only when
  the **narrowed** `redeemed.scopes` holds `openid`; the narrowing is at
  `:196-198`.
  * `ciba_test.rs::no_id_token_when_the_scope_ceiling_removed_openid` asserts
    `id_token` absent after the tenant withdraws `openid`. The old code always
    minted one, so the test fails there; read, not mutated.
  * The comment's cause is misattributed (R110W3-12 (d)).
* **The spec.** Regenerated here, on this branch, with
  `cargo build -p axiam-server --no-default-features` (exit 0) and
  `axiam-server --dump-openapi` (exit 0). The output is **byte-identical** to
  the committed `sdks/openapi.json` (`cmp` exit 0). The committed diff
  `3d011573e..HEAD` contains exactly:
  * the digest;
  * W3.1: `DeviceAuthorizationRequest` gains `client_secret`,
    `client_assertion` and `client_assertion_type`; the `resource` text; the
    operation's description; its `401`;
  * W3.2: the `PUT /api/v1/oauth2-clients/{id}` `422`, and the `scopes`
    member's text;
  * W3.3: the tenant `DELETE` `409`;
  * W3.8 (b): the client `DELETE` `204` text;
  * #656: the CIBA list `429` text.

  Nothing else moved.
* **Checks.** `check-spec-digest.py` exit 0.
  `gen-management-registry.py --check` exit 0 (190 operations, 28
  namespaces); the registry diff is the `spec_digest` line only.
* **Two text faults in the regenerated spec** (R110W3-12 (e)):
  * The schema description now carries "`Debug` is written by hand so that
    the credentials never reach a log line".
  * The operation's `summary` is "Build an OAuth2 JSON error response with the
    appropriate HTTP status." This is pre-existing; utoipa took a neighbouring
    doc line.
* **(e)** The bench was not runnable here. Confirmed; it is recorded for
  §13.3.

## 10. The §10 rules, against what the wave added (orchestrator point 8)

| Rule | Verdict |
|---|---|
| A new route carries a limiter from its first commit | **No route added.** The device poll moved into the CIBA arm and gained the public-client bucket. Behind the shipped proxy, that bucket is one allowance per client that any address can exhaust (R110W3-01, §2.1, §3.4). |
| Credential-bearing outbound requests use `guarded_fetch_no_redirect` | None added. The start endpoint deliberately skips the CIMD fetch. |
| Every refusal of a credential check costs one verify | **Holds for what the wave added**: <br>• the device grant's refusals with a presented secret, including the unknown client and the public client with a credential; <br>• the tombstoned tenant at the device endpoints and on the `sa_` path, read after the verify. <br>Exceptions: <br>• an assertion presented for an unknown client (no verify), a residual; <br>• the pre-existing unknown-client arms of every other path (R110W3-06). |
| Two-writer registries written conditionally | The hint cap's count is an atomic upsert, and its take-back is conditional on the window. The sweep's delete re-checks per row. The admin `PUT` is read-then-write, but not a versioned registry; the residual is stated in T-289. |
| Schema | No migration (`schema.rs` untouched). `rate_limit_bucket.updated_at` stays unindexed (R110W3-03). |
| Contract / spec | `CONTRACT.md` untouched. `openapi.json` regenerated by W3.8, as §10 allows. `management-registry.json` was also refreshed (`spec_digest` only). §10 reserves that to W6.3 and W7.1, but `gen-management-registry.py --check` fails on a stale digest, so the tree overrules the plan, and the commit says so. |
| Threat model: edit only named entries; every named test exists | Five entries were edited: T-118, T-289, T-422, T-424, T-472. The plan names T-289 (W3.1, W3.8) and T-118 (W3.3). The rest hold the claims each commit corrects, as in W2's precedent. Every test the added text names resolves to a `fn` in `crates/` (each identifier in the added text was resolved with `rg 'fn <name>'`; the only misses were field names), and `check-remediation-evidence.py` passes. |
| No `[lints] workspace = true` on an undocumented crate; no new crate | Holds. `token_device.rs` is a module of `axiam-oauth2`; `check-crate-layering.py` passes. |
| CI parity: the SAML-off build and clippy `-D warnings` | Hold (§15). |

## 11. Threat-model text against the code (orchestrator point 9)

| Entry | Verdict |
|---|---|
| **T-289**, amended (#635) | **Mostly true.** Two sentences are false or loose (R110W3-12 (a)): <br>• "An unknown client costs the one HMAC verify a wrong secret costs" holds only when a secret was presented. <br>• "`invalid_grant` once a re-materialised row names it again" holds only for the test's repository-written row. A real CIMD row cannot hold the grant, so the poll answers `invalid_client`. <br>It also says nothing about a public client's leaked code (R110W3-04). The rest is true, including "before the grant is read" and "no refusal spends the grant, records a poll or reveals its state". |
| **T-289**, amended (#636) | True. The residuals (read-then-write; `grant_types` unbounded) are stated. |
| **T-289**, corrected (#642 (a)) | True: CIMD registers only the code grants. Its last sentence ("the grant's deletion is what refuses the case where a row names the `client_id` again") shares the hypothetical above. |
| **T-422**, amended (#639) | True (§6.1). |
| **T-424**, amended (#638) | True, with one fault: it names `SharedRateLimitStore::peek_count`, which #639 removed from the trait (the next amendment says so). Its residual is the lenient sweep of R110W3-03. |
| **T-424**, amended (#639) | The bound and its argument are true (§6.1). "Exactly … provided … latency plus skew under ten minutes" omits the sweep's own assumption, a sweeper within 60 s of the datastore (R110W3-03). |
| **T-118**, amended (#637) | True (§5). "No other path writes an action a caller chooses" was verified by enumeration. |
| **T-118**, amended (#640) | True (§7). |
| **T-472**, amended (#637) | True. |
| **T-472**, amended (#641) | True (§8). |

* **Both copies agree.** All 271 sentences on the STRIDE lines the wave
  touched are present verbatim in `Axiam.json`, after stripping Markdown
  emphasis and code spans.
* **Dates and labels.** Each paragraph is dated 2026-10-15 and labelled an
  amendment or a correction.
* **Model version.** It stays 2.41.0, `threatTop` 477.
* **The website copy.** `node website/scripts/gen-threat-model.mjs` (477: 443
  / 19 / 15) leaves a 5-line diff in `website/src/threatModel.ts`, one line
  per amended entry. That is W8.3's reconciliation; the file was restored.

## 12. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "None of these spends the code or records a poll against it, so a leaked device code is worth nothing to anyone but its client" (`docs/api/device-flow.md:82-83`, `website/src/docs/oauth2.ts:640`) | **False for a public client** (R110W3-04). The first half is true. |
| "cannot spend it, slow it down or redeem it under a client it can authenticate as" (`device_service.rs:41-43`) | False for a public client, which anyone can authenticate as (R110W3-04) |
| "Omit `token_endpoint_auth_method` and the client is confidential … it must then send its `client_secret` at both endpoints" (`device-flow.md`) | True; it is the fact R110W3-02's upgrade note must carry |
| "a failure is `401 invalid_client`" (`device-flow.md`, website) | True; the RFC 6749 §5.2 challenge is applied |
| `BC_AUTHORIZE_PER_HINT` text and posture row (`rate-limit-sizing.md`, `README.md`, `configuration.ts`, `docs/conformance/README.md`) | True; `check-config-key-coverage.py` passes |
| "a receipt whose `exported_through` is later than the receipt itself … Only the server writes receipts" (`docs/admin/README.md`) | True since #637 |
| `asyncapi.yml` `AuditEventMessage.action` names the reserved namespaces | True, with the confusable caveat (R110W3-09) |
| `/health/jobs` lists `rate_limit_bucket`, "Eighteen sweeps" (`operate.ts`) | True on this branch. The W1 branch's rewrite of that list must gain it at merge (stated in `f077131`). |
| "RFC 8628 clients are public, so `client_id` is caller-supplied and worthless as a bucket key here" (`server.rs:2113-2115`) | Stale (R110W3-12 (c)). The per-address keying stays right: callers are unauthenticated until the handler runs. |

## 13. The contract (orchestrator point 10)

### 13.1 The question for the maintainer (not answered here)

**The text that now contradicts the server** is CONTRACT §14.1
(`sdks/CONTRACT.md:2859-2861`):

> `device_authorize` is **unauthenticated**: a device that cannot show a browser also cannot
> hold a client secret. SDKs MUST NOT send `client_secret` on it, and MUST NOT refuse to call
> it from a client constructed without one.

**What the server does after W3.1.**
* `POST /oauth2/device_authorization` authenticates the client by its
  registered method.
* A public client (`token_endpoint_auth_method: none`) sends nothing and is
  **refused** if it sends a credential.
* A confidential client must send its credential, as at the token endpoint:
  `client_secret` in the body, `Authorization: Basic`, a client assertion, or
  its certificate. It is refused `401 invalid_client` without it.
* The poll (`device_poll`) authenticates the same way, and `client_id` is
  required.

**SDK impact.**
1. An SDK that follows §14.1 cannot drive the device grant for a confidential
   client at all. `device_authorize` is refused, and `device_poll` is refused
   unless the SDK adds the client's credential to the token request.
2. Applications that registered a confidential device client break at the
   upgrade (R110W3-02). Their only SDK-side remedy, sending the secret, is
   forbidden by "MUST NOT send `client_secret`".
3. The §14.2 table lists five `400` answers. The poll now also answers
   `401 invalid_client`: a gone client, a lost grant, a failed credential, or a
   missing DPoP proof or certificate for a bound client. By rule 5 that falls
   to §2's `401` mapping, not to a §14 terminal error. Whether §14 names it is
   part of the question.
4. A DPoP-bound device client must send a DPoP proof on every poll, and it
   receives `token_type: DPoP`. §14 says nothing about DPoP on this grant.
5. **Not verifiable here.** Whether each SDK's device-flow integration fixture
   registers its client as public. A confidential fixture fails against 1.1.0
   (the plan's W3.1 oracle, "the SDK device-flow fixtures still pass", depends
   on it).

**The decision needed.** Pick one:
* **(a)** §14.1 keeps "unauthenticated" for public clients only. It says a
  confidential device client must authenticate, SDKs may send the credential
  they were constructed with, and §14 names `invalid_client` and DPoP.
* **(b)** The server is held to §14.1. That reverses W3.1 for the start
  endpoint, which the review does not recommend: R101W3-01's impersonation
  case lives there.
* **(c)** Device clients must be public. That is a registration-time refusal,
  which the plan rejected for W3.1.

### 13.2 Other contract text the wave made stale (for W7.1; R110W3-11)

* **§14 intro (`:2842-2846`).** It says an access token "from the code, refresh,
  CIBA or device grant" carries a `client_id` claim and is answered `403
  authorization_denied` at `/api/v1/device/*`. A device-grant token carries
  no `client_id` and no `sid`, and is answered **`401`** by the session check
  first (§3.6, R110W3-08).
* **§27 rule 2 (`:9068-9072`).** It says a device polling with the code of a
  deleted client's grant "is answered `invalid_grant`". After W3.1 the client
  is read first, so the answer is **`401 invalid_client`**. Its CIMD sentence
  is moot, since a CIMD client cannot hold the grant.
* **§33.3 rule 13 (`:11906-11924`).** It still says "at most three", "a
  refused call counts", and "waits between ten and twenty minutes".
  * Now the allowance is `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_HINT`, three by
    default.
  * Refused calls are taken back.
  * A client that stopped for one window after the one in which it used its
    allowance is admitted again.
  * Q8's `rate_limit_exceeded` → `slow_down` fix is already W7.1 (c).
* **§8 / §8b, `AuditEventMessage.action`.** Nothing says that `tenants.*` and
  `gdpr.*`, ASCII case ignored, are refused (nack, no requeue). A producer SDK
  that publishes one sees its message dead-lettered and no error. An SDK
  producer could refuse such an action client-side; the contract should say
  whether it must.
* **§27 `oauth2_clients.update`.** The new `422` with `error:
  "scope_exceeds_ceiling"` on a `dcr`/`cimd` row. §2's `422` mapping covers
  it, so the change is text only.
* **§27 rule 3 / §27.12 `tenants.delete`.** The second `409` (a receipt
  claiming rows after itself; export again) is informative.
* **§14.1 `DeviceAuthorizationRequest`.** The schema gained three optional
  credential members. The vendored `openapi.json` in each SDK changes
  accordingly.

## 14. Executors' follow-ups, confirmed or rejected

| Follow-up | Verdict |
|---|---|
| An unknown `sa_` id is refused without any verify | **Confirmed, Informational, pre-existing** (R110W3-06). It is the same as every other unknown-client arm. The difference is a few microseconds of HMAC against a datastore read, and `sa_` ids are random. |
| Other grants' unknown-client refusal skips the verify | **Confirmed, Informational** (R110W3-06), with the device equaliser's two gaps (an assertion; the reverse asymmetry for Basic). |
| `grant_types` on `dcr`/`cimd` rows unbounded via the admin `PUT` | **Confirmed, Informational** (R110W3-07). |
| A receipt without `exported_through` is still accepted at deletion | **Confirmed; no issue.** `is_some_and` is false, so it is accepted. Its deletion record then carries no export time, and the purge reads none from the receipt either, so it **keeps the whole trail** (`tenant_purge.rs:607-611`). Fail-safe. Only pre-#602 receipts lack the key, and those are over six hours old. |
| Deletion's six-hour freshness compared on the app clock | **Confirmed; no issue.** The check is a window of hours, and a skew of seconds or minutes moves it by that much. It bounds no row; the clamp does. Stated in T-118. |
| More than ~10 concurrent hint-cap calls → `server_error` after retries | **Confirmed, Informational** (R110W3-05). The threshold is lower than ten: four attempts, one winner per round. |
| `rate_limit_bucket.updated_at` index | **Confirmed, Informational** (in R110W3-03). It needs a migration this wave does not own. |
| W3.8 (e) bench not runnable here | **Confirmed.** Not a security matter; the number goes to §13.3. |
| (W3.1) device tokens carry no `sid` and no `client_id`; does the session check reject them? | **Confirmed that it rejects them (`401`), rejected as a wave regression** (§3.6): the claims are those of 1.0.1. Filed as R110W3-08. |

## 15. Checks run

Each command's own exit code was captured. Logs are in the session
scratchpad. All cargo commands ran with `RUSTFLAGS=-Dwarnings`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` and
the swagger placeholder, as CI and the executor rules require.

| Check | Exit | Result |
|---|---|---|
| `cargo fmt -p <crate> -- --check` for `axiam-core`, `-db`, `-oauth2`, `-api-rest`, `-amqp`, `-audit`, `-server`, `-federation` | 0 ×8 | clean |
| `cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features` (CI "Build (SAML off)") | 0 | pass |
| the same with `--tests` | 0 | pass |
| `cargo clippy -p <crate> --lib --tests -- -D warnings` (default features) for `axiam-core`, `-db`, `-oauth2`, `-amqp`, `-audit`, `-api-rest`, `-server`, `-federation` | 0 ×8 | clean |
| `cargo build -p axiam-server --no-default-features` | 0 | built |
| `axiam-server --dump-openapi` vs `sdks/openapi.json` | 0 | byte-identical (`cmp` 0) |
| `python3 scripts/check-spec-digest.py` | 0 | digest matches |
| `python3 scripts/gen-management-registry.py --check` | 0 | 190 operations / 28 namespaces in sync |
| `python3 scripts/check-remediation-evidence.py` | 0 | 37 verified, 0 failed |
| `python3 scripts/check-config-key-coverage.py` | 0 | every key documented |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, 62 edges inward |
| `python3 scripts/check-conflict-markers.py` | 0 | OK |
| `scripts/check-doc-links.sh` | 0 | 507 links across 78 files |
| `node website/scripts/gen-threat-model.mjs` | 0 | 477 threats; a 5-line diff in the website copy (W8.3), restored |
| STRIDE additions against `Axiam.json` | — | 271 of 271 sentences present |
| Tests named in the amendments | — | every name resolves to a `fn` |
| `cargo test -p axiam-core --lib models::audit` | 0 | 1 passed (the reserved namespaces) |
| `cargo test -p axiam-oauth2 --lib` | 0 | 619 passed (hint cap: configured allowance, take-back, concurrent and boundary bounds, datastore bound; `token::device_grant` hash test) |
| `cargo test -p axiam-oauth2 --test token_service` | 0 | 137 passed (incl. `a_tombstoned_tenants_service_account_authenticates_nowhere`) |
| `cargo test -p axiam-db --lib repository::rate_limit` | 0 | 6 passed (`peek_bucket`, `decrement`, `delete_stale`) |
| `cargo test -p axiam-db --test tenant_purge_test` | 0 | 10 passed (the clamp; the receipt not in the log) |
| `cargo test -p axiam-amqp --test audit_consumer_test` | 0 | 13 passed (`a_reserved_control_action_is_refused_and_not_persisted`) |
| `cargo test -p axiam-api-rest --test device_flow_test` | 0 | 28 passed (the nine W3.1 tests, W3.7's tombstone test) |
| `cargo test -p axiam-api-rest --test ciba_test` | 0 | 28 passed (`a_new_hint_creates_one_rate_limit_row`, `the_per_hint_allowance_is_the_deployments`, `no_id_token_when_the_scope_ceiling_removed_openid`) |
| `cargo test -p axiam-api-rest --test oauth2_client_test` | 0 | 40 passed (the four W3.2 tests; the amended deletion test) |
| `cargo test -p axiam-api-rest --test tenant_test` | 0 | 24 passed (`a_receipt_claiming_rows_after_itself_does_not_unblock_delete`) |
| `cargo test -p axiam-api-rest --test resource_indicators_test` | 0 | 20 passed |
| `cargo test -p axiam-api-rest --lib -- audit_export_clock config::rate_limit` | 0 | 23 passed (the export clock; the allowance's config tests) |
| `cargo test -p axiam-server --test cleanup_task -- rate_limit_bucket tenant_purge` | 0 | 4 passed (the sweep, two replicas, the retention derivation; the purge sweep) |
| `cargo test -p axiam-server --lib -- boot::tests job_health` | 0 | 9 passed (`the_hint_cap_allowance_is_read_from_the_environment`, the sweep registry) |
| probe `probe_r110w3_01_public_bucket_ignores_the_forwarded_address` (a copy of `device_flow_test.rs`, removed afterwards) | 0 | the device poll from another forwarded address is `429 slow_down` (§2.1) |

`cargo clean` was run at the end.

## 16. Issue bodies

### R110W3-01 (Medium) — the public-client token bucket is keyed on the proxy, and the device poll now runs through it

**Where:** `crates/axiam-api-rest/src/handlers/oauth2.rs:2200-2216` (T21.2),
`:2267-2273` (#635, `3fcac15`); `crates/axiam-api-rest/src/extractors/client_info.rs:49-53`.
Threats: T-212, T-289.

**The gap.** A token request with no client credential is counted in
`oauth2_token_public:{tenant}:{client_id}:{peer_ip}` at `token_per_min`.
`peer_ip` is the TCP peer, which is the reverse proxy in both shipped
topologies. Since #635 a public device client's polls are counted there too,
so all of a client's devices share one allowance. One unauthenticated address
can fill it: the route limiter, keyed on the forwarded address, admits it
`token_per_min` a minute. Every device poll is then answered `429 slow_down`
until its code expires. Public clients' code and refresh requests have had
the same exposure since T21.2.

**Fix:**
* Key the bucket on the address `XForwardedForKeyExtractor` derives under
  `AXIAM__RATE_LIMIT__TRUSTED_HOPS`. Factor its selection into a function
  over `&HttpRequest`, used here and by the extractor.
* Or, the narrow form: skip the bucket for the device-code grant, whose polls
  the route limiter and the grant's own interval bound.

**Tests:**
* Behind one peer, a credential-less flood from forwarded address A does not
  answer a device poll, or a public client's code exchange, from address B
  `429`.
* The T21.2 flood test still meets `slow_down`.
* `trusted_hops >= hops` falls back to the peer.

### R110W3-02 (Low) — existing confidential device clients are refused after the upgrade, and nothing says so

**Where:** `crates/axiam-oauth2/src/token_device.rs:108-211` (#635, `3fcac15`);
`crates/axiam-api-rest/src/handlers/oauth2_clients.rs:955`; `CHANGELOG.md`
`## [Unreleased]`; `sdks/CONTRACT.md:2859-2861`. Threat: T-289 (availability).

**The gap.** Since #635 both device endpoints authenticate the client by its
registered method. A client registered without `token_endpoint_auth_method`
is confidential (`client_secret_post`), and the 1.0.x B2 quickstart registered
device clients that way. Their devices send `client_id` alone, as CONTRACT
§14.1 requires of every SDK, so they are now refused `401 invalid_client` at
both endpoints. The admin API refuses to change a client between confidential
and public. No upgrade note exists, and the release plan's W8.4 list of
upgrade notes omits it.

**Fix:**
1. **Required.** An upgrade note in `## [1.1.0]` (proposed text in
   `claude_dev/security-review-release-1.1.0-w3-2026-10-15.md` §2.2).
2. **Optional.** A boot-time `warn!` counting confidential clients that hold
   the device grant.
3. **Maintainer's decision.** Let `PUT` set `token_endpoint_auth_method: none`
   on a confidential client whose grants are only the device grant (and
   `refresh_token`), clearing its secret hash in the same write.

**Tests:** for (2), the warning names the count. For (3):
* the conversion succeeds and clears the hash;
* a client holding `client_credentials` or CIBA is still refused;
* the converted client's device flow works with `client_id` alone.

### R110W3-03 (Informational) — the `rate_limit_bucket` sweep's cutoff is on the application clock

**Where:** `crates/axiam-server/src/cleanup.rs:262,300-330` (#638, `f077131`);
`crates/axiam-db/src/repository/rate_limit.rs:236-255`. Threat: T-424.

**The gap.**
* `updated_at` is stamped by the datastore (`time::now()`), but the cutoff is
  the sweeping replica's `Utc::now()` minus 21 minutes.
* If that replica runs more than 60 s ahead of the datastore, the hint cap's
  previous-window row is deleted while it is still read. The next window then
  admits the allowance again, and a ten-minute stretch admits up to twice the
  allowance. More than about 11 minutes ahead, the current row can go too.
* T-424's #639 amendment and `CibaHintCap`'s documentation claim the bound
  "exactly", naming only the call-latency-plus-skew assumption.
* Each pass selects with `WHERE updated_at < $cutoff LIMIT 500` on an
  unindexed field, up to 100 times a tick, each a scan.

**Fix:**
* Evaluate the cutoff in the datastore: `… WHERE updated_at < time::now() -
  $retention` in both the selection and the `DELETE`, binding the retention
  as a duration. The only remaining assumption is then inter-replica skew
  below the margin, which the cap already assumes.
* State the assumption in T-424 and in `CibaHintCap`'s doc.
* When a migration is next free, add `DEFINE INDEX IF NOT EXISTS
  rate_limit_bucket_updated_at ON rate_limit_bucket FIELDS updated_at`.

**Tests:**
* A sweep run with an application clock 5 minutes ahead keeps a previous-window
  hint row aged 20 minutes.
* The existing `the_sweep_removes_stale_rows_and_keeps_current_ones` keeps
  passing.

### R110W3-04 (Informational) — "a leaked device code is worth nothing" is not true of a public client

**Where:** `docs/api/device-flow.md:82-83`; `website/src/docs/oauth2.ts:640`;
`crates/axiam-oauth2/src/device_service.rs:41-43`. Threat: T-289.

**The gap.** The text says the poll's ordering makes a leaked device code
"worth nothing to anyone but its client". For a public client, the documented
default for devices, anyone can name the `client_id`. A leaked approved code
is therefore still redeemable by its holder (RFC 8628 §5.2, §5.6), and for a
DPoP-bound public client the tokens are bound to the holder's key. #635 closes
this for confidential and key-bound-authentication clients only.

**Fix:** reword all three places to say so, for example: "…so for a
confidential client a leaked device code is worth nothing without the client's
credential. A public client's device code remains the grant's only secret
(RFC 8628 §5.2, §5.6): keep it on the device and out of logs." Add the same
sentence to T-289's #635 amendment.

**Test:** none (text).

### R110W3-05 (Informational) — concurrent `bc-authorize` calls for one hint end in `server_error`

**Where:** `crates/axiam-oauth2/src/ciba.rs:1018-1042` (#639, `8492128`);
`crates/axiam-db/src/helpers.rs:284`. Threat: T-424.

**The gap.**
* Concurrent calls for one (client, hint) write one record, and the datastore
  aborts all but one per round.
* The count is retried `MAX_WRITE_ATTEMPTS` (4) times. A call that loses four
  rounds returns `server_error` (`500`), and so does a failed peek after the
  count.
* Only the client can cause this for its own hint, and the per-client
  `bc-authorize` limiter bounds the flood. But a `500` is an operator alarm,
  and a conformance or SDK run with parallel modules meets it.

**Fix:**
* When the count's conflict survives the retries, answer `Ok(false)`
  (refused, `slow_down`). Nothing was counted, so this is strict.
* Or use `retry_hot_row` (32 attempts), as other hot rows do.
* Keep `server_error` for non-conflict faults.

**Test:** a store that injects a conflict on every attempt makes `admit`
return `Ok(false)` and leaves no count. Forty concurrent calls against the
in-memory datastore produce no `server_error`.

### R110W3-06 (Informational) — unknown-client refusals cost no verify outside the device grant

**Where:** `crates/axiam-oauth2/src/token.rs:1585` (`sa_`), `:1915`
(`authorization_code`), `:2405` (`client_credentials`), `:2617`
(`refresh_token`), `:3325` (`authenticate_client`: revoke, introspect, PAR,
`bc-authorize`, token exchange, UMA), `token_ciba.rs:107`;
`token_device.rs:221-233`. Plan §10 ("every refusal of a credential check
costs one verify").

**The gap.**
* Every client-authenticating path but the device grant answers an unknown
  client after the lookup alone. A known client with a wrong secret costs one
  HMAC verify.
* The device grant's equaliser (`spend_one_verify`, against a v2 hash no
  secret produces) covers a secret in the body or Basic header. It does not
  cover an assertion.
* It also creates the reverse asymmetry: a known `client_secret_basic`
  client sent only a body secret is refused without a verify
  (`token.rs:1410-1415`), while an unknown client with a body secret costs
  one.
* All differences are microseconds against a datastore read, and client ids
  are not secrets. This fails the §10 rule's letter, not a property an
  attacker can use.

**Fix:**
* Move `UNKNOWN_CLIENT_SECRET_HASH` and `spend_one_verify` into `token.rs`
  as `pub(crate)`.
* Call it in each `NotFound` arm and tenant-mismatch arm listed, and in
  `authenticate_client_secret_basic`'s no-header refusal when a body secret is
  present.
* For an assertion presented to an unknown client, verifying against a fixed
  dummy key would equalise; or state the residual.

**Tests:** a `#[cfg(test)]` verify counter. One verify for:
* an unknown client with a secret;
* a wrong secret;
* a Basic-registered client with a body secret;

on each path.

### R110W3-07 (Informational) — the admin `PUT` does not bound a self-registered client's grant types

**Where:** `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:432,539`
(`KNOWN_GRANT_TYPES`), `update`. Threat: T-289.

**The gap.** #636 refuses a scope outside the ceiling on a `dcr`/`cimd` row,
but `grant_types` is checked only against `KNOWN_GRANT_TYPES`. An
administrator can give a self-registered client:
* `client_credentials`: an M2M credential held by a third party;
* the device grant: whose poll does not re-apply the scope ceiling (T-289's
  #613 residual);
* CIBA.

`dcr::validate` and `cimd::validate` never admit any of these. The client's
own RFC 7592 `PUT` then starts failing as "widening".

**Fix:** on a `dcr`/`cimd` row, refuse `422` (for example
`grant_exceeds_registration_policy`) a grant `dcr::validate` would refuse,
with the same held-grant exemption as scopes.

**Tests:** adding `client_credentials` to a `dcr` row is `422` and leaves it
unchanged. The same on an `admin` row is accepted.

### R110W3-08 (Informational) — device-grant access tokens carry no `client_id`; the contract says they do

**Where:** `crates/axiam-oauth2/src/device_service.rs:501-510`;
`crates/axiam-auth/src/token.rs:888-958`;
`crates/axiam-api-rest/src/extractors/auth.rs:476-482,1188`;
`sdks/CONTRACT.md:2842-2846`. Threats: T-289, T-447.

**The state** (pre-existing; unchanged by #635).
* **The claims.** The device grant mints with no `client_id` and no `sid`,
  and with a random `jti`.
* **The session check.** It therefore finds no session, so every
  session-validated AXIAM route answers `401`, UserInfo and `/api/v1/device/*`
  included.
* **The contract.** CONTRACT §14 says device-grant tokens carry `client_id`
  and get `403 authorization_denied` there.
* **T-447.** T-447's refusal of a client-minted token at the approval routes
  rests, for device tokens, on the session check rather than on the
  `minted_for_client` check it names. A future device token with a session
  would pass it.
* **RFC 9068.** §2.2 makes `client_id` REQUIRED in a JWT access token.
* **Refresh tokens.** A DPoP-bound public device client's refresh token (as
  every grant's) is not bound to the DPoP key. RFC 9449 §5 requires that for
  public clients, and a stolen one refreshes under the thief's key. This is
  tree-wide.

**Fix:**
* Mint the device token with `.client_id(Some(client))`, as the CIBA grant
  does. Decide whether it should carry a session; there is none to name.
* Correct §14's sentence in W7.1.
* Separately, store the `jkt` on refresh tokens issued to public DPoP-bound
  clients and require it at refresh.

**Tests:**
* A device token carries `client_id`.
* `/api/v1/device/verify` answers it `403 authorization_denied` (or the
  contract says `401`).
* A public DPoP client's refresh with another key is refused.

### R110W3-09 (Informational) — reserved audit actions can be imitated by lookalikes

**Where:** `crates/axiam-core/src/models/audit.rs` (`reserved_action_namespace`);
`crates/axiam-amqp/src/audit_consumer.rs:139`. Threat: T-118.

**The gap.** The check is an ASCII-case-insensitive prefix test. These pass and
are persisted:
* ` tenants.audit_exported` (leading space);
* `tеnants.audit_exported` (Cyrillic U+0435);
* a full-width dot;
* a zero-width joiner.

No server reader matches them, because the deletion and purge use exact ASCII
equality. But in the console's audit view they read as a receipt, a deletion
or a GDPR record.

**Fix:** refuse, at ingestion, an action that is not printable ASCII
(`[\x21-\x7e]` plus the space the middleware's `METHOD /path` uses, or the
documented action grammar), or apply NFKC plus trim before the namespace
check. Document it in `asyncapi.yml`.

**Test:** each lookalike above is nacked and not persisted.

### R110W3-10 (Informational) — `/oauth2/device_authorization` requires a body `client_id` and answers parse failures in plain text

**Where:** `crates/axiam-oauth2/src/device_service.rs:113`;
`crates/axiam-api-rest/src/server.rs:2116-2123`.

**The gap.**
* `DeviceAuthorizationRequest.client_id` is a required `String`.
* A `client_secret_basic` or `private_key_jwt` client that identifies itself
  by its header or assertion (RFC 6749 §2.3.1, RFC 7521 §4.2), as
  `resolve_client_id` allows at the token endpoint, is refused before the
  handler.
* The route has no `FormConfig` error handler, so the refusal is actix's
  plain-text `400`, not an OAuth2 JSON error.

**Fix:**
* Make `client_id` `Option<String>` and resolve it with `resolve_client_id`
  (header or assertion).
* Add `FormConfig::error_handler(handlers::oauth2::par_form_error)` (or the
  token endpoint's) to the route.

**Tests:**
* A Basic client without a body `client_id` gets a user code.
* A malformed body gets a JSON `invalid_request`.

### R110W3-11 (Informational) — contract text the wave made stale

**Where:** `sdks/CONTRACT.md`: §14 intro (`:2842-2846`), §14.1 (`:2859-2861`),
§14.2, §27 rule 2 (`:9068-9072`), §27 rule 3 and §27.12, §27
`oauth2_clients.update`, §33.3 rule 13 (`:11906-11924`), §8/§8b
`AuditEventMessage.action`.

**The state.** The list is in the review's §13.2. §14.1 depends on the
maintainer's answer to the device-client question (review §13.1).

**Fix:** W7.1 records each in contract 1.62, and W7.2 … W7.12 re-sync the
vendored spec. Each SDK's device-flow fixture must register a public client.

**Test:** the W7.13 conformance review checks each item.

### R110W3-12 (Informational) — text and hygiene after W3

* **(a) T-289's #635 amendment.**
  * "An unknown client costs the one HMAC verify a wrong secret costs" holds
    only when a secret is presented.
  * "`invalid_grant` once a re-materialised row names it again" (and the #642
    correction's last sentence) describes a row only the repository can write
    (`oauth2_client_test.rs` upserts a CIMD row with the device grant). A real
    CIMD row cannot hold the grant, so the poll answers `invalid_client`.
* **(b) T-424's #638 amendment.** It names `SharedRateLimitStore::peek_count`,
  which #639 replaced with `peek_bucket` on the trait.
* **(c) A stale comment.** `server.rs:2113-2115`: "RFC 8628 clients are
  public, so `client_id` is caller-supplied". The keying is still right; the
  reason is now "callers are unauthenticated until the handler".
* **(d) A misattributed comment.** `token_ciba.rs:292-294` attributes the
  missing `openid` to "an administrator edited it after registration". The
  ceiling removes it when the tenant's `dcr_allowed_scopes` drops it. Since
  #636 an administrator cannot add an outside scope.
* **(e) The public spec.**
  * `DeviceAuthorizationRequest`'s description carries "`Debug` is written by
    hand…" (`device_service.rs:110`). Move it to a `//` comment.
  * `POST /oauth2/device_authorization`'s `summary` is "Build an OAuth2 JSON
    error response with the appropriate HTTP status." (pre-existing). Give the
    handler a one-line first doc paragraph or an explicit `summary`.
* **(f) The cleanup comment.** `cleanup.rs:293-295` says "never a refusal that
  should not happen". Say "lenient: the count reads as zero" (R110W3-03).
* **(g) The website copy.** `website/src/threatModel.ts` is behind
  `Axiam.json` by five entries (W8.3).

**Fix:** the edits above. **Test:** `check-remediation-evidence.py`,
`check-doc-links.sh`, and the spec drift job after (e).

## 17. Invariants

* **I1 (nothing registered today changes behaviour unless the wave says so)
  holds**, with one consequence the wave states only in docs (R110W3-02). The
  behaviour changes the wave announces:
  * both device endpoints authenticate the client;
  * the poll requires `client_id`;
  * a foreign client is `invalid_grant`;
  * bound clients get bound device tokens;
  * the admin `PUT` refuses outside scopes on `dcr`/`cimd` rows (`422`);
  * AMQP refuses `tenants.*` and `gdpr.*` actions;
  * the deletion refuses a receipt claiming rows after itself (`409`);
  * the purge bound is clamped to its receipt;
  * the hint cap is configurable and takes back refusals;
  * stale `rate_limit_bucket` rows are swept;
  * the export bound is the datastore's;
  * the tombstone deletes device grants;
  * the `sa_` path answers a tombstoned tenant `invalid_client`;
  * the CIBA grant omits the ID token without `openid`.
* **Contract and schema.** `sdks/CONTRACT.md` is unchanged, and so is the
  schema (no migration). `sdks/openapi.json` and the registry digest are
  regenerated, byte-identical to a fresh build.
* **This review.** It changed no file but itself. The website copy
  regenerated for §11 was restored. The one probe (§2.1) was a temporary test
  file, deleted after its run.
