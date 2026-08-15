# B2 — IoT device quickstart (OAuth2 Device Authorization Grant)

**What this demonstrates.** The full RFC 8628 Device Authorization Grant
ceremony from both sides at once: a headless "device" (this script, standing
in for a sensor, a set-top box, or a fleet gateway with no keyboard) starts
the flow and polls for a token, while an already-authenticated human (the
tenant admin) looks the short code up and approves it — exactly the split
described in [`docs/api/device-flow.md`](../../docs/api/device-flow.md).

**What it requires.**

- A running, bootstrapped AXIAM instance (see
  [`scripts/e2e-bootstrap.sh`](../../scripts/e2e-bootstrap.sh)).
- `curl` and `jq` on `PATH`.

**What it does NOT cover — mTLS provisioning.** RFC 8628 is the *first-boot*
story: a device with nothing yet gets a user-bound token by having a human
type a code. It is explicitly not the *steady-state* story for a fleet of
already-commissioned devices, which is certificate-based mTLS
authentication (`POST /api/v1/auth/device`, `AXIAM__PKI__*`, see
[`docs/pki/README.md`](../../docs/pki/README.md)) — a device that already
holds a certificate signed by the tenant's CA authenticates directly, no
human and no polling involved. `claude_dev/improvement-after-run5-benchmark.md`
§B2 calls this out explicitly as a **follow-on**, not part of this grant, and
this example does not implement it: provisioning the CA-signed certificate
onto a device in the first place is its own (mostly physical/logistics)
problem, and mTLS device auth itself is already covered by the PKI docs
rather than needing a second example here.

## Run it

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh
AXIAM_URL=http://localhost:8090 ./examples/b2-iot-device-quickstart/device-quickstart.sh
```

## What the script does

1. Logs in as the tenant admin — this stands in for "the person with the
   sensor picks up their phone" later in the flow.
2. Registers the device as an OAuth2 client (`grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]`,
   no `redirect_uris` — a device never receives a browser redirect). Real
   fleets do this once, ahead of time, from provisioning tooling, not on
   every boot.
3. **Device side:** `POST /oauth2/device_authorization` — unauthenticated,
   gets back a `device_code`, a short `user_code`, and a polling `interval`.
4. **Human side:** `GET /api/v1/device/verify?user_code=…` to see what's
   being asked for, then `POST /api/v1/device/decide {"approved": true}` —
   both authenticated and CSRF-protected, because approval is an act of
   authorization by a specific human (see the design rationale in the
   handler docs, `crates/axiam-api-rest/src/handlers/device.rs`).
5. **Device side:** polls `POST /oauth2/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`, treating
   `authorization_pending` as "keep going" and `slow_down` as "wait longer"
   per RFC 8628 §3.5 — both are normal, expected answers, not errors. Stops
   the moment tokens come back.

## History: the registration gap found while building this example

Step 2 registers the device client through `POST /api/v1/oauth2-clients`
with `grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]` — the
exact call [`docs/api/device-flow.md`](../../docs/api/device-flow.md#registering-a-device-client)
documents. While this example was first being built, that call was refused
with `400 unknown grant_type`: `KNOWN_GRANT_TYPES` in
`crates/axiam-api-rest/src/handlers/oauth2_clients.rs` (used by both
`create` and `update`) did not yet include the device-flow grant URN, even
though the engine underneath fully accepted clients registered for it
(`crates/axiam-oauth2/src/device_service.rs` checks for
`DEVICE_CODE_GRANT_TYPE` directly, and every device-flow integration test
created its fixture client by calling the repository layer directly —
`oauth2_client_repo.create(...)` — bypassing this REST validator entirely,
per `crates/axiam-api-rest/tests/device_flow_test.rs:128`). The gap was
REST-registration-only, and it blocked every caller of the public API, not
just this example. **`KNOWN_GRANT_TYPES` has since been fixed** (it now
includes both the device-flow and token-exchange grant URNs) — step 2
registers cleanly against a current checkout.

## Verification status

`bash -n` and `shellcheck` are both clean. The polling answer table
(`authorization_pending` / `slow_down` / `access_denied` / `expired_token` /
`invalid_grant`) and the `/api/v1/device/verify` response shape
(`found`/`client_id`/`scopes`) are read directly from
`docs/api/device-flow.md` and
`crates/axiam-api-rest/src/handlers/device.rs`, not guessed. **It has not
been run against a live server** — no docker daemon in the environment this
was authored in (see the repo root `examples/README.md`).
