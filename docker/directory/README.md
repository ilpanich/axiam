# Directory e2e: a real OpenLDAP and a real Samba AD DC

This is the stack behind `crates/axiam-server/tests/directory_e2e.rs` (G-3,
T23.3.6). Every other test of the LDAP / Active Directory identity source runs
against an in-process directory that AXIAM's own authors scripted; this one
drives the same code against servers somebody else wrote, so it is the oracle
for what the connector assumes about LDAP.

Nothing in this directory is a credential. The CA, both servers' certificates
and every password are minted at run time into `docker/.secrets/directory/`
(gitignored) by `scripts/gen-directory-e2e-secrets.sh`.

## Run it locally

From the repository root. Docker with the compose plugin is the only
prerequisite beyond the Rust toolchain.

```bash
# 1. CA, certificates, passwords (idempotent; delete the directory to rotate)
bash scripts/gen-directory-e2e-secrets.sh

# 2. the two servers; --wait returns when both report healthy
#    (Samba provisions a domain on first start: allow about 30 seconds)
docker compose -f docker/docker-compose.directory.yml \
    --env-file docker/.secrets/directory/env up -d --wait

# 3. the suite (build prerequisites as for any crate-level test:
#    protobuf-compiler, and the swagger placeholder, see CLAUDE.md)
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
AXIAM_E2E_DIRECTORY=1 cargo test -p axiam-server --test directory_e2e

# 4. tear down, volumes included
docker compose -f docker/docker-compose.directory.yml \
    --env-file docker/.secrets/directory/env down -v
```

Without `AXIAM_E2E_DIRECTORY=1` every test prints `SKIPPED` and passes, so a
plain `cargo test` needs no containers. With it set, a missing secrets
directory or an unreachable server is a **failure** that names the command above;
the suite never skips quietly once you asked for it.

`AXIAM_E2E_DIRECTORY_ONLY=openldap` (or `samba`, or both comma-separated) runs
one server's tests, which is what to use when only one container is up. The
suite is repeatable against the same running containers: whatever a test changes
in a directory it creates itself, under a fresh name.

`AXIAM_E2E_DIRECTORY_DIR` points at a secrets directory other than
`docker/.secrets/directory`.

## What is where

| Path | What |
|---|---|
| `docker/docker-compose.directory.yml` | both servers, on a network of their own with fixed addresses |
| `docker/directory/openldap/` | `config.ldif.tmpl` (cn=config: TLS 1.2 floor, no plaintext simple bind, ppolicy, a read-only service account), `data.ldif.tmpl` (the seed), `entrypoint.sh`, `e2e-mutate.sh` |
| `docker/directory/samba/` | `entrypoint.sh` (provisions `EXAMPLE.TEST`, installs the run's TLS material, seeds), `e2e-mutate.sh` |
| `scripts/gen-directory-e2e-secrets.sh` | the CA, the two certificates, the passwords |

### Why the servers are where they are

`172.28.77.10` (OpenLDAP) and `172.28.77.11` (Samba), on a bridge network of
their own, nothing published on the host. AXIAM's address guard (T23.3.7)
always refuses loopback, so a published port on `127.0.0.1` would be a
configuration the product rightly rejects; it refuses a private range unless
the operator lists it, so the harness sets
`AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS` to the subnet exactly as an
operator does. The addresses are fixed so the certificates, generated before
either container exists, can name them (`IP:` subject alternative names; the
tests connect by address and rustls checks the URL's host against them). If the
subnet collides with something on your machine, set
`DIRECTORY_E2E_SUBNET`, `DIRECTORY_E2E_OPENLDAP_IP` and `DIRECTORY_E2E_SAMBA_IP`
when you run the secrets script.

### What each directory contains

The same shape on both, so one scenario runs against either.

| Entry | Purpose |
|---|---|
| `alice` | member of `staff`, and of `admins` (a directory group nobody maps) |
| `bob` | member of `devs`; `devs` is a member of `staff`, so bob reaches `staff` only by nesting |
| `adminuser` | a name that is a unique prefix of nobody else's: `adminu*` selects exactly this entry if a login name ever reaches a filter unescaped |
| `odd*(name)\z` (OpenLDAP), `odd(name)` (AD) | a name holding filter metacharacters (Active Directory does not allow `*` or `\` in a `sAMAccountName`) |
| `dave` | disabled: OpenLDAP `pwdAccountLockedTime: 000001010000Z` (ppolicy's permanent lock, D-31 as amended), AD `userAccountControl` bit `0x2` |
| `reader` | the read-only bind account the tenant is configured with |

Tests that need a person to appear, be disabled or vanish create one under a
fresh name through `e2e-mutate.sh` (`docker exec`, the directory's own
administrator over `ldapi` or the DC's local `sam.ldb`; no password crosses the
command line from the test).

## Images

Both are third-party images **pinned by digest** and used only as a pinned
binary: each service replaces the image's own bootstrap with a script from this
directory, so the `cn=config`, the domain, the TLS settings and the seed are
the ones in this repository.

| Service | Image | Notes |
|---|---|---|
| `openldap` | `osixia/openldap:1.5.0` | Debian's slapd 2.4.57 (GnuTLS). `bitnami/openldap:2.6` no longer exists on Docker Hub. |
| `samba` | `instantlinux/samba-dc:latest` | Samba 4.23 on Alpine. NT ACLs are kept in `posix:eadb` rather than extended attributes, so the container needs no added capability. |

Own Dockerfiles were written first and dropped: building them needs the distro's
package mirror, and a fixture that cannot be built in every environment that has
to run it cannot be verified there. To move to a newer image, change the digest
in `docker-compose.directory.yml` and run the suite; the suite is the check.

## What the suite does not cover

* Kerberos / SPNEGO (out of scope for G-3, D-1) and AD's primary group
  (`primaryGroupID`, noted in T23.3.4).
* A tenant directory on a public address (the harness uses the private network
  the allow-list was built for).
* Replication, referrals to other domain controllers (the domain-root search
  against Samba does return a search reference to the Configuration partition,
  which the connector ignores; that is exercised, not asserted separately).
