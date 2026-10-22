# FreeRADIUS e2e: 802.1X with an AXIAM-issued Device certificate

This is the stack behind `crates/axiam-server/tests/radius_e2e.rs` (W6.2, the Static profile of
the RADIUS spike; and, as an override of it, the Live profile of W6.5, below). The guide it proves is
[`docs/pki/freeradius.md`](../../docs/pki/freeradius.md); read that for what the
configuration means and why. This page is how to run it.

Nothing here is FreeRADIUS. `docker/docker-compose.radius.yml` names the upstream
image (`freeradius/freeradius-server`, a 3.2.x tag **and its digest**) and mounts
the configuration files in `raddb/` over the image's own. The image is pulled, not
built, and nothing of it (GPLv2) is copied into this repository. Nothing in this
directory is a credential: the shared secret, the server certificate, AXIAM's CA
and every device key are minted by the test, per run, into
`docker/.secrets/radius/` (gitignored).

## Run it locally

Prerequisites beyond the Rust toolchain: Docker with the compose plugin,
`openssl`, `curl` (the fetch script), and `eapol_test`, which is `wpa_supplicant`'s test tool
(`sudo apt-get install -y eapoltest` on Ubuntu 24.04; elsewhere build it from
`wpa_supplicant`'s sources with `CONFIG_EAPOL_TEST=y`).

```bash
# Build prerequisites as for any crate-level test: protobuf-compiler, and the
# swagger placeholder (CLAUDE.md).
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"

AXIAM_E2E_RADIUS=1 cargo test -p axiam-server --no-default-features \
    --test radius_e2e -- --nocapture
```

The test brings the stack up itself, once AXIAM has issued the CA, the list and the
placement table FreeRADIUS reads, and takes it down when it ends (`down -v`).
`--nocapture` prints a line for each step, including the measured revocation lag.

It takes **five to seven minutes** once built, and almost all of that is one wait: after the
test fetches the revocation list from AXIAM it waits for FreeRADIUS to re-read it,
which FreeRADIUS does at `ca_path_reload_interval`, 300 seconds at the smallest
(the guide's [revocation lag](../../docs/pki/freeradius.md#the-revocation-lag)).

| Variable | Effect |
|---|---|
| `AXIAM_E2E_RADIUS=1` | **Required.** Without it the test prints `SKIPPED` and passes. With it, a missing `docker`, `eapol_test` or `openssl`, or a FreeRADIUS that does not come up, is a **failure** that names the fix. |
| `AXIAM_E2E_RADIUS_REFRESH=restart` | Refresh FreeRADIUS's lists by restarting the container instead of waiting for the reload interval. For iterating; CI does not set it, because the reload interval is what the guide recommends and what the test is meant to show. |
| `AXIAM_E2E_RADIUS_KEEP=1` | Leave the stack up afterwards (`docker logs axiam-radius-e2e-freeradius`). Take it down with `docker compose -f docker/docker-compose.radius.yml --env-file docker/.secrets/radius/env down -v`. |
| `AXIAM_E2E_RADIUS_DIR` | A working directory other than `docker/.secrets/radius`. It must end in `radius`: the test deletes and recreates it. |
| `RADIUS_E2E_IP`, `RADIUS_E2E_SUBNET` | The container's address and its network (default `172.28.78.10` in `172.28.78.0/24`), for a host where that range is taken. `clients.conf` lists the default subnet, so change that file as well. |

## The Live profile: AXIAM decides, per authentication

`docker/docker-compose.radius-live.yml` is an **override** of the compose file above
(`docker compose -f docker-compose.radius.yml -f docker-compose.radius-live.yml …`):
the same container, the same pinned image (the override names none), but the
placement table is gone and `sites-enabled/check-eap-tls` asks AXIAM,
over mutual TLS with `rlm_rest`, where the device goes
([guide, section 5](../../docs/pki/freeradius.md#5-the-decision-per-authentication-live-profile)).
The second test of `radius_e2e.rs` brings it up itself, with AXIAM in the test
process behind a real TLS listener, and the same command above runs both tests,
one after the other. The Live test takes about a minute and a half: nothing in it waits for a CRL.

| Path | What |
|---|---|
| `docker/docker-compose.radius-live.yml` | the override: the Live mounts, a `tmpfs` for the hook, `axiam.radius.test` mapped to the host, the AXIAM address and site key from the environment |
| `docker/radius/raddb/live/clients.conf` | the clients, each `shortname` the AXIAM site key |
| `docker/radius/raddb/live/check-eap-tls` | the decision and the mapping of the answer into the Access-Accept |
| `docker/radius/raddb/live/axiam_live` | the `rest` modules (token, decision), the token cache and the `exec` module |
| `docker/radius/raddb/live/verify.conf` | the `verify` hook, included by `eap` when this file is mounted |
| `docker/radius/raddb/live/axiam-live.sh` | what carries the certificate's fingerprint from the hook to the decision |

It needs one thing more of the host than the Static profile: AXIAM listens on all interfaces on a
port the OS picks, and the container reaches it at its network's gateway
(`172.28.78.1`, or the `.1` of `RADIUS_E2E_SUBNET`), so a host firewall that drops
traffic from the Docker bridge to the host breaks it. The test writes the extra
variables the override reads (`RADIUS_E2E_AXIAM_URL`, `RADIUS_E2E_SITE`,
`RADIUS_E2E_AXIAM_HOST_IP`) into `docker/.secrets/radius/env`, and re-creates the
container when a case changes one (a wrong site key, AXIAM stopped).

## What is where

| Path | What |
|---|---|
| `docker/docker-compose.radius.yml` | the pinned upstream image, the mounts, a network of its own with a fixed address |
| `docker/radius/raddb/clients.conf` | the NAS clients; `require_message_authenticator = yes`; the secret from the environment |
| `docker/radius/raddb/eap` | EAP-TLS only, TLS 1.3 only, the tenant signing CA, `check_crl`, `ca_path_reload_interval`; `$-INCLUDE` of the Live hook when it is mounted |
| `docker/radius/raddb/default` | the one virtual server: EAP, and nothing else |
| `docker/radius/raddb/check-eap-tls` | the placement decision, after the certificate is verified, keyed on the certificate serial (the Static profile; the Live profile mounts its own) |
| `docker/radius/raddb/axiam_placement` | the `files` module that reads the placement table |
| `docker/radius/fetch-crl.sh` | the revocation-list fetch job the guide's section 4 describes; the test runs it on the host, against a local stand-in for the CRL route (needs `curl` and `openssl`; it sets `FETCH_CRL_ALLOW_HTTP=1`, because the stand-in is plain HTTP and the script refuses that otherwise) |
| `docker/radius/tests/` | `fetch-crl-test.sh <shell>`: the fetch script's own cases (tags, lock, curl options) against a stand-in for the route and a throwaway CA, no docker and no AXIAM; `radius-e2e.yml` runs it under `dash` and `bash` |
| `docker/radius/tests/check-token-cache.py` | the shape of every call `raddb/live/check-eap-tls` makes on the token cache (read-only, or a negative-TTL store of a fetched token; #764); `--self-test` runs its fixtures; no docker |
| `docker/radius/tests/token-cache-test.sh` | what those calls do in the pinned image: the concurrent interleavings of #720 and #764 played call by call in one `radclient` request against the cache module copied from `axiam_live`; needs docker |
| `docker/.secrets/radius/` | per run: `env`, `server-ca.pem`, the supplicants' files, and `trust/` (`server.pem`, `server.key`, `ca.pem`, `capath/<hash>.r0`, `placement`), mounted at `/etc/freeradius/axiam` |
| `.github/workflows/radius-e2e.yml` | the same, in CI |

## History note

The HUP/INT/TERM signal trap in `fetch-crl.sh` came in with `f0fe8b064` (the run-long lock,
R110W5-02), on top of the `EXIT` trap that `384d2c772` had added. The body of `b915783`
(1.1.1 W5.3) credits it to `3da7e0c`, which is an unrelated docs commit; that history is
not rewritten, and this note is the correction.

## Changing the image

The digest in the compose file is the manifest of the tag next to it. To move to
another 3.2.x release: pull the tag, read the digest (`docker inspect --format
'{{index .RepoDigests 0}}' freeradius/freeradius-server:<tag>`), replace both in
the compose file, check that the mounted files still match what the new image's
`mods-available/eap` and `sites-available/default` expect, and run the test.
