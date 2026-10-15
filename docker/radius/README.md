# FreeRADIUS e2e: 802.1X with an AXIAM-issued Device certificate

This is the stack behind `crates/axiam-server/tests/radius_e2e.rs` (W6.2, D3 of
the RADIUS spike). The guide it proves is
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

## What is where

| Path | What |
|---|---|
| `docker/docker-compose.radius.yml` | the pinned upstream image, the mounts, a network of its own with a fixed address |
| `docker/radius/raddb/clients.conf` | the NAS clients; `require_message_authenticator = yes`; the secret from the environment |
| `docker/radius/raddb/eap` | EAP-TLS only, TLS 1.3 only, the tenant signing CA, `check_crl`, `ca_path_reload_interval` |
| `docker/radius/raddb/default` | the one virtual server: EAP, and nothing else |
| `docker/radius/raddb/check-eap-tls` | the placement decision, after the certificate is verified, keyed on the certificate serial |
| `docker/radius/raddb/axiam_placement` | the `files` module that reads the placement table |
| `docker/radius/fetch-crl.sh` | the revocation-list fetch job the guide's section 4 describes; the test runs it on the host, against a local stand-in for the CRL route (needs `curl` and `openssl`) |
| `docker/.secrets/radius/` | per run: `env`, `server-ca.pem`, the supplicants' files, and `trust/` (`server.pem`, `server.key`, `ca.pem`, `capath/<hash>.r0`, `placement`), mounted at `/etc/freeradius/axiam` |
| `.github/workflows/radius-e2e.yml` | the same, in CI |

## Changing the image

The digest in the compose file is the manifest of the tag next to it. To move to
another 3.2.x release: pull the tag, read the digest (`docker inspect --format
'{{index .RepoDigests 0}}' freeradius/freeradius-server:<tag>`), replace both in
the compose file, check that the mounted files still match what the new image's
`mods-available/eap` and `sites-available/default` expect, and run the test.
