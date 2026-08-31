# Running the AXIAM prod stack on a Raspberry Pi 5 at `axiam-iam.duckdns.org`, with HTTPS and "Sign in with Google"

**Status:** operator runbook — written 2026-08-31 against `1.0.0-beta07`.
**Audience:** one person deploying AXIAM on their own Pi to exercise OIDC federation
end to end against Google as the external IdP.

Everything below is derived from what is actually in this repository at this
commit: [`docker/docker-compose.prod.yml`](../docker/docker-compose.prod.yml),
the `prod-up` recipe in [`justfile`](../justfile),
[`crates/axiam-api-rest/src/handlers/federation.rs`](../crates/axiam-api-rest/src/handlers/federation.rs),
[`crates/axiam-federation/src/oidc.rs`](../crates/axiam-federation/src/oidc.rs) and
[`frontend/src/pages/federation/FederationPage.tsx`](../frontend/src/pages/federation/FederationPage.tsx).
Where the code and a plausible expectation disagree, the code wins and the
disagreement is called out.

---

## 0. Read this first — the one gap in the flow

The admin UI can **create and manage** the Google federation config
(`Federation` page), and the backend implements the **complete** first-time-SSO
flow. But the SPA has **no "Sign in with Google" button** and **no SSO callback
route**:

- `frontend/src/pages/LoginPage.tsx` renders org slug / tenant slug / username /
  password / MFA only — nothing calls `/api/v1/auth/federation/oidc/start`.
- `frontend/src/router.tsx` has no `/auth/sso/callback` route.
- `frontend/src/services/federation.ts` exposes CRUD on `federation-configs`
  and `federation-links` — no `start`/`callback` calls.

So the honest shape of this exercise is:

| Step | Where it happens |
| --- | --- |
| Configure the provider | **AXIAM frontend** → Federation page (§7) |
| Kick off the Google login | `curl` against the public start endpoint (§8) |
| Approve at Google | **Browser** |
| Complete the login | `curl` against the public callback endpoint (§8) |
| Inspect the result | AXIAM frontend → Users, and the API (§9) |

That exercises the backend federation path exactly as a real SPA would: the
browser really does go to Google, Google really does return a code to your
domain, and AXIAM really does exchange it, verify the ID token against Google's
JWKS, JIT-provision the user and set session cookies. Only the two HTTP calls
that a login button would have made are made by hand.

If you want the button, that is a frontend change (a start-call on the login
page plus a callback route that POSTs `code`/`state`) — out of scope here, but
§10 sketches what it would need.

---

## 1. What you need before you start

**Hardware / OS**

- Raspberry Pi 5, **8 GB recommended** (4 GB is tight: the stack runs
  SurrealDB + RabbitMQ + Vault + axiam-server + nginx). Boot from SSD/NVMe if
  you can — SurrealDB's `surrealkv` engine on an SD card is miserable.
- Raspberry Pi OS (64-bit) or Ubuntu Server 24.04 arm64. **64-bit is
  mandatory** — the released images are built for `linux/amd64` and
  `linux/arm64` only (`.github/workflows/release.yml`, the `platform` matrix).
- At least ~15 GB free disk.

**Network**

- The DuckDNS name `axiam-iam.duckdns.org` pointing at your public IP, kept
  current by the DuckDNS updater (§3).
- Router port-forwards **TCP 80 and 443** to the Pi. Port 80 is needed for
  Let's Encrypt's HTTP-01 challenge; if your ISP blocks it, use the DNS-01
  alternative in §4.3.
- **Do not** forward 8090, 50051, 8200, 5671 or 15672. §5.3 rebinds them to
  loopback so a mistake in the router UI cannot expose them.

**Software on the Pi**

```bash
sudo apt update
sudo apt install -y git curl python3 openssl
# Docker Engine + Compose plugin (official convenience script)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # log out and back in
docker compose version            # need v2.24.0+ for the `!override` in §5.3
# `just` — Debian/RPi OS trixie has it; otherwise: cargo install just
sudo apt install -y just || true
```

**Accounts**

- A Google account with access to the [Google Cloud Console](https://console.cloud.google.com/).
- The AXIAM repo cloned on the Pi:

```bash
git clone https://github.com/ilpanich/axiam.git ~/axiam
cd ~/axiam
```

You do **not** need a Rust toolchain: `just prod-up` pulls the released
multi-arch images from `ghcr.io/ilpanich/axiam/*` rather than building.

---

## 2. How the pieces fit together

```
                  Internet
                     │  443 (TLS, Let's Encrypt)
                     ▼
        ┌────────────────────────────┐
        │  Caddy (host, systemd)     │   axiam-iam.duckdns.org
        └────────────┬───────────────┘
                     │  http → 127.0.0.1:8081
                     ▼
        ┌────────────────────────────┐
        │ axiam-frontend (nginx:8080)│  SPA + reverse proxy:
        │                            │   /api      → axiam-server:8090
        │                            │   /oauth2/  → axiam-server:8090
        │                            │   /.well-known → axiam-server:8090
        └────────────┬───────────────┘
                     ▼
        ┌────────────────────────────┐
        │ axiam-server (REST + gRPC) │──► SurrealDB, RabbitMQ (AMQPS), Vault
        └────────────────────────────┘
```

Two consequences that matter for the rest of this guide:

1. **One origin does everything.** `docker/nginx.conf` already proxies `/api`,
   `/oauth2/` and `/.well-known` to the backend, so
   `https://axiam-iam.duckdns.org` serves both the admin UI and the API. You do
   **not** need to configure CORS (`AXIAM__SERVER__CORS_ALLOWED_ORIGINS` stays
   empty) and you do not need a second hostname for the API.
2. **TLS terminates at Caddy.** `axiam-server`'s own TLS listener stays off —
   that is the documented posture (`ServerConfig::tls`, "the recommended
   deployment terminates TLS at the proxy/load-balancer layer"). Caddy sets
   `X-Forwarded-Proto: https`, nginx forwards it.

---

## 3. DuckDNS

1. Sign in at <https://www.duckdns.org/>, create the subdomain `axiam-iam`,
   copy your token.
2. Install the updater on the Pi:

```bash
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh <<'EOF'
#!/usr/bin/env bash
curl -fsS "https://www.duckdns.org/update?domains=axiam-iam&token=YOUR_DUCKDNS_TOKEN&ip=" -o ~/duckdns/duck.log
EOF
chmod 700 ~/duckdns/duck.sh
~/duckdns/duck.sh && cat ~/duckdns/duck.log   # expect: OK
( crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/duckdns/duck.sh >/dev/null 2>&1" ) | crontab -
```

3. Verify from **outside** your LAN (phone on mobile data, or
   `dig +short axiam-iam.duckdns.org @1.1.1.1`) that the name resolves to your
   public IP. Let's Encrypt validates from the internet, not from your LAN, and
   a NAT-loopback-only setup fails at exactly this point.

---

## 4. HTTPS with Let's Encrypt (Caddy)

Caddy is the least-effort option: it obtains and renews the certificate itself,
redirects `:80` → `:443`, and needs a four-line config.

### 4.1 Install

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

### 4.2 Configure (HTTP-01 — the default)

```bash
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
axiam-iam.duckdns.org {
	encode zstd gzip

	# The AXIAM frontend container. It serves the SPA and reverse-proxies
	# /api, /oauth2/ and /.well-known to axiam-server itself, so this is the
	# only upstream Caddy needs.
	reverse_proxy 127.0.0.1:8081

	# Federation and OAuth2 responses set session cookies; never cache them.
	header /api/* Cache-Control "no-store"
}
EOF
sudo systemctl restart caddy
sudo systemctl enable caddy
journalctl -u caddy -n 50 --no-pager    # look for "certificate obtained successfully"
```

Nothing is listening on 8081 yet, so you will get a 502 until §5 — that is
expected. The certificate is issued regardless, because ACME does not care what
is behind the proxy.

### 4.3 If port 80 is blocked (DNS-01 alternative)

Some ISPs block inbound 80. DuckDNS supports DNS-01 through a Caddy plugin, but
it is **not** in the stock Debian package — you must build Caddy with it:

```bash
# Needs Go 1.22+ on the Pi (apt install golang-go, or a tarball from go.dev)
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
~/go/bin/xcaddy build --with github.com/caddy-dns/duckdns
sudo install -m0755 ./caddy /usr/bin/caddy
sudo systemctl restart caddy
```

then in the Caddyfile, inside the site block:

```
tls {
	dns duckdns {env.DUCKDNS_API_TOKEN}
}
```

and put `DUCKDNS_API_TOKEN=…` in `/etc/default/caddy` (or a systemd drop-in
`Environment=` line). With DNS-01 you still need **443** forwarded; only 80
becomes optional.

---

## 5. The AXIAM prod stack

### 5.1 What `just prod-up` already does for you

Read the recipe once (`justfile`, `prod-up`) — it is doing real work and knowing
what is where saves you when something breaks:

1. Mints SurrealDB and RabbitMQ credentials into
   `docker/.secrets/stack-credentials.env` (mode 600, gitignored) **on first run
   only** — they are tied to the data volumes and cannot be re-minted later.
2. Generates the AMQPS broker CA/cert (`scripts/gen-broker-tls.sh`) and Vault's
   listener cert (`scripts/gen-vault-tls.sh`).
3. Generates an Ed25519 JWT signing keypair under `docker/.secrets/`.
4. Starts Vault, **initialises** it (writing the unseal key + root token to
   `docker/.secrets/vault-init.json` — this file *is* your Vault), **unseals**
   it, and **seeds** every secret AXIAM needs via `scripts/vault-seed.sh`.
   That seeding is what makes federation work at all: it mints
   `federation_encryption_key`, without which
   `POST /api/v1/federation-configs` fails with *"federation encryption key not
   configured"*.
5. Sets `AXIAM_IMAGE_TAG` from the workspace version in `Cargo.toml`
   (`1.0.0-beta07` at this commit) and runs `docker compose up -d`. There is no
   `:latest` tag in the registry — every AXIAM release so far is a pre-release —
   so the tag is mandatory and `prod-up` is the supported way to supply it.

### 5.2 The environment variables you must set yourself

`docker-compose.prod.yml` is written for `localhost`. Three families of settings
need to change for a real domain. Note the **double underscore** after `AXIAM`:
`load_config()` in `crates/axiam-server/src/main.rs` calls
`.with_prefix("AXIAM").separator("__")`, so `__` is both the prefix separator
and the nesting separator. `AXIAM_DB_URL` is silently ignored;
`AXIAM__DB__URL` is not.

**(a) WebAuthn — already parameterised in the compose file, just export them**

| Variable | Value | Why |
| --- | --- | --- |
| `AXIAM_WEBAUTHN_RP_ID` | `axiam-iam.duckdns.org` | Bare registrable domain. Passkeys are bound to it; changing it later invalidates every passkey already enrolled. |
| `AXIAM_WEBAUTHN_RP_ORIGIN` | `https://axiam-iam.duckdns.org` | Must match the browser's address bar **exactly**. The built-in default is `https://localhost`; leaving it there makes every passkey registration fail with a 401 that looks like a session bug. |

These feed `AXIAM__AUTH__WEBAUTHN_RP_ID` / `..._RP_ORIGIN` in the compose file.
Not strictly required for the Google flow — but if you sign in to the admin UI
with a passkey, they are required, and getting them wrong is the single most
confusing failure in this stack.

**(b) Issuer identity — needs a compose override (§5.3)**

| Variable | Value | Why |
| --- | --- | --- |
| `AXIAM__AUTH__JWT_ISSUER` | `https://axiam-iam.duckdns.org` | The `iss` claim on AXIAM's own tokens. Default is the literal string `axiam`. |
| `AXIAM__AUTH__OAUTH2_ISSUER_URL` | `https://axiam-iam.duckdns.org` | What `/.well-known/openid-configuration` advertises. Falls back to `jwt_issuer` when empty; OIDC compliance wants a real URL. Validated at startup when set. |

Neither is needed to make *Google* federation work — AXIAM is the relying party
there, not the issuer — but a deployment on a real domain that advertises
`iss: "axiam"` is a deployment you will have to fix later, so fix it now.

**(c) Bootstrap gate — needs the same override, or use the setup token**

| Variable | Value | Why |
| --- | --- | --- |
| `AXIAM_BOOTSTRAP_ADMIN_EMAIL` | your admin email | `POST /api/v1/admin/bootstrap` is fail-closed: it refuses unless this is set **and matches** the request's email, or the request carries the one-time setup token. |

If you would rather not touch the compose file for this, skip it — §6 shows the
setup-token path, which needs no env var at all.

**Already correct, do not change:** `AXIAM__AUTH__COOKIE_SECURE` defaults to
`true` (`crates/axiam-auth/src/config.rs`), which is what you want behind HTTPS.
`AXIAM__SERVER__CORS_ALLOWED_ORIGINS` stays empty — single origin.

### 5.3 The Pi override file

Create `docker/docker-compose.pi.yml` in the checkout:

```yaml
# Pi-specific overrides for docker-compose.prod.yml.
#   docker compose -f docker/docker-compose.prod.yml -f docker/docker-compose.pi.yml up -d
# `!override` on `ports` REPLACES the base list instead of appending to it
# (Docker Compose v2.24+). Without it you would keep the 0.0.0.0 bindings.
services:
  axiam-server:
    environment:
      AXIAM__AUTH__JWT_ISSUER: "https://axiam-iam.duckdns.org"
      AXIAM__AUTH__OAUTH2_ISSUER_URL: "https://axiam-iam.duckdns.org"
      AXIAM_BOOTSTRAP_ADMIN_EMAIL: "${AXIAM_BOOTSTRAP_ADMIN_EMAIL:-}"
    ports: !override
      - "127.0.0.1:8090:8090"
      - "127.0.0.1:50051:50051"

  axiam-frontend:
    ports: !override
      - "127.0.0.1:8081:8080"
```

Loopback-only bindings mean the containers are reachable from Caddy and from
`curl` on the Pi, and from nowhere else — even if the router forwards a port by
mistake. (If your Compose predates `!override`, edit the `ports:` lists in
`docker-compose.prod.yml` directly and drop that key.)

### 5.4 Bring it up

`just prod-up` hard-codes `-f docker/docker-compose.prod.yml`, so the override
is applied by a second compose call that reuses the environment `prod-up` built.
Create `~/axiam-up.sh`:

```bash
#!/usr/bin/env bash
# Bring up (or restart, or unseal after a reboot) the AXIAM prod stack on the Pi.
set -euo pipefail
cd "$HOME/axiam"

# --- Domain-dependent settings the base compose file already reads ---------
export AXIAM_WEBAUTHN_RP_ID="axiam-iam.duckdns.org"
export AXIAM_WEBAUTHN_RP_ORIGIN="https://axiam-iam.duckdns.org"
# --- Read by the override file in §5.3 ------------------------------------
export AXIAM_BOOTSTRAP_ADMIN_EMAIL="you@example.com"

# 1. Mint secrets, init/unseal/seed Vault, start the stack (base file only).
#    Idempotent: existing credentials, keys and Vault data are left alone, and
#    a sealed Vault (e.g. after a reboot) is unsealed here.
just prod-up

# 2. Re-apply with the Pi override. Same environment `_prod-compose` builds —
#    Compose interpolates the WHOLE file, so every `${VAR:?}` must resolve.
# shellcheck source=/dev/null
source docker/.secrets/stack-credentials.env
export AXIAM_IMAGE_TAG="${AXIAM_IMAGE_TAG:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}"
export AXIAM__AUTH__JWT_PRIVATE_KEY_PEM="$(cat docker/.secrets/jwt_ed25519.pem)"
export AXIAM__AUTH__JWT_PUBLIC_KEY_PEM="$(cat docker/.secrets/jwt_ed25519.pub.pem)"
export AXIAM__AUTH__VAULT_TOKEN="$(python3 -c 'import json;print(json.load(open("docker/.secrets/vault-init.json"))["root_token"])')"

docker compose -f docker/docker-compose.prod.yml -f docker/docker-compose.pi.yml up -d
docker compose -f docker/docker-compose.prod.yml -f docker/docker-compose.pi.yml ps
```

```bash
chmod 700 ~/axiam-up.sh
~/axiam-up.sh
```

Wait for `axiam-server` to report `healthy`, then:

```bash
# Liveness lives at the server root (`/health`), which nginx does NOT proxy —
# it only forwards /api, /oauth2/ and /.well-known. So probe it on the Pi,
# against the loopback binding from §5.3:
curl -fsS http://127.0.0.1:8090/health && echo OK

# Through the public front door — this exercises Caddy, nginx and the backend:
curl -fsS https://axiam-iam.duckdns.org/.well-known/openid-configuration | head -20
```

Open `https://axiam-iam.duckdns.org` — you should get the AXIAM login page over
a valid Let's Encrypt certificate.

### 5.5 Reboots — the thing that will bite you

Vault runs the `file` storage backend with **no auto-unseal**. After a reboot
the containers restart (`restart: unless-stopped`), Vault comes back **sealed**,
and `axiam-server` crash-loops because it cannot read a single secret. Docker
does not re-evaluate `depends_on: service_healthy` on restart, so it will not
wait for you.

The fix is to re-run the script — `prod-up` checks `sys/seal-status` and unseals
from `docker/.secrets/vault-init.json`:

```bash
sudo tee /etc/systemd/system/axiam-stack.service >/dev/null <<EOF
[Unit]
Description=AXIAM stack (unseal Vault and start containers)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=$USER
WorkingDirectory=$HOME/axiam
ExecStart=$HOME/axiam-up.sh

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable axiam-stack.service
```

**Back up `docker/.secrets/` off the Pi.** It holds the only copy of the Vault
unseal key and root token, the datastore credentials, and the JWT signing key.
Lose `vault-init.json` and the Vault is unrecoverable — including the OPAQUE
setup key, which means a password reset for every user in every tenant.
`just prod-clean` deletes the volumes *and* those state files; it is the
"start over" button, not a restart.

---

## 6. First-run bootstrap: organization, tenant, admin

`POST /api/v1/admin/bootstrap` creates the organization, its
**organization-scope tenant** (slug `organization`), seeds permissions and
default roles, and creates the super-admin. It is one-shot — a
`bootstrap_lock:global` uniqueness invariant means a second call gets a 409.

Note what it does **not** do any more: it does not create an ordinary tenant.
`tenant_name` / `tenant_slug` in the request are accepted and ignored. The
super-admin it creates is organization-level, so it administers every tenant the
organization ever has.

**Option A — via the UI.** Browse to
`https://axiam-iam.duckdns.org/bootstrap` and fill in the form. Requires
`AXIAM_BOOTSTRAP_ADMIN_EMAIL` to match the email you type (you set it in §5.4).

**Option B — via the API with the setup token.** If you did not set the env var,
the server minted a one-time token at first boot and logged it once:

```bash
docker logs axiam-server 2>&1 | grep -m1 setup_token
```

```bash
curl -fsS -X POST https://axiam-iam.duckdns.org/api/v1/admin/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{
        "organization_name": "Home Lab",
        "organization_slug": "homelab",
        "email": "you@example.com",
        "username": "admin",
        "password": "<a long unique password>",
        "setup_token": "<token from the log>"
      }' | tee bootstrap.json
```

The response tells you `tenant_id` and `tenant_slug` — the latter is
`organization`. Keep both.

**Sign in** at `https://axiam-iam.duckdns.org/login`:

- **Organization slug:** `homelab`
- **Tenant slug:** leave blank (that signs you in at organization level) or type
  `organization`
- **Username / password:** as above

### Which tenant will the Google config live in?

`handlers::federation::create` writes the config with
`tenant_id: user.tenant_id` — **the tenant of whoever is signed in**. As the
bootstrap super-admin that is the organization-scope tenant (`organization`).
That is fine for this test, and it is the tenant you will name in §8.

If you would rather federate into a normal tenant, create one first
(`POST /api/v1/organizations/{org_id}/tenants`, or the Tenants page in the UI),
then sign in with a user *in that tenant* before creating the federation config
— otherwise the config lands in the organization tenant and the login flow in
§8, which names a tenant explicitly, will not find it.

---

## 7. Google side

All of this is in the [Google Cloud Console](https://console.cloud.google.com/).

### 7.1 Project

**Select a project → New Project** → name it e.g. `axiam-homelab` → Create.
Make sure it is the selected project for every step below.

### 7.2 OAuth consent screen (Google Auth Platform → Branding / Audience)

1. **APIs & Services → OAuth consent screen** (newer consoles: **Google Auth
   Platform**).
2. **User type: External.** (Internal is only available with Google Workspace.)
3. App name: `AXIAM`. User support email: yours. Developer contact: yours.
4. **Authorized domains:** add `duckdns.org`. Google wants the registrable
   domain, not the full hostname — `axiam-iam.duckdns.org` will be rejected here.
5. **Scopes:** add exactly the three AXIAM requests — `openid`,
   `.../auth/userinfo.email`, `.../auth/userinfo.profile`. These are
   non-sensitive, so **no Google verification is required**. AXIAM hard-codes
   `scope=openid email profile` in `build_authorization_url`
   (`crates/axiam-federation/src/oidc.rs`) — there is no setting to change it,
   so do not add anything Google would consider sensitive.
6. **Test users:** while the app is in *Testing*, only listed accounts can sign
   in. Add the Google account(s) you will test with. This is the right place to
   stay for a home lab — do **not** press *Publish app*; a published external
   app with these scopes is fine but pointless here.

### 7.3 OAuth client

**APIs & Services → Credentials → Create Credentials → OAuth client ID**

- **Application type:** Web application
- **Name:** `AXIAM (Pi)`
- **Authorized JavaScript origins:** `https://axiam-iam.duckdns.org`
- **Authorized redirect URIs:** `https://axiam-iam.duckdns.org/login`

> **This value is load-bearing — read this before you pick a different one.**
>
> AXIAM sends the `redirect_uri` you pass to
> `POST /api/v1/auth/federation/oidc/start` **straight through to Google** as
> the OAuth `redirect_uri`, and echoes the same string at the token exchange
> (`oidc_start_public` → `build_authorization_url`; `oidc_callback_public` →
> `handle_callback`, "we built the authorize URL using the SPA redirect_uri …
> so we must echo the same value here"). Google requires a byte-exact match
> against a registered URI. So **whatever you register here must be exactly
> what you send in §9 step 1** — same scheme, host, path, no trailing slash
> difference.
>
> `/login` is chosen because the SPA has a real route there, so the browser
> lands on a rendered page with `?code=…&state=…` visible in the address bar,
> which is what you need for the manual step. AXIAM itself only requires that
> the URI be absolute HTTPS (`validate_redirect_uri`, which allows plain HTTP
> for `localhost` alone).

Copy the **Client ID** (`…apps.googleusercontent.com`) and the **Client
secret**. The secret is shown once; treat it like a password.

### 7.4 Nothing else

No API needs enabling — OIDC sign-in works off the discovery document. Google's
endpoints are all published at
`https://accounts.google.com/.well-known/openid-configuration`, with issuer
`https://accounts.google.com` and RS256-signed ID tokens.

---

## 8. Configure the federation in the AXIAM frontend

Sign in as the super-admin, then **Federation** in the sidebar → **Add
Federation Config**.

| Field | Value | Notes |
| --- | --- | --- |
| **Provider \*** | `Google` | Free-text display name. |
| **Protocol \*** | `OIDC` | Sent as `OidcConnect`. |
| **Client ID \*** | `…apps.googleusercontent.com` | From §7.3. Also becomes the expected `aud` on Google's ID tokens. |
| **Client Secret \*** | the secret from §7.3 | AES-256-GCM-encrypted before it reaches the database (`encrypt_client_secret`, SEC-045); never returned by the API and never rendered again. |
| **Metadata URL** | `https://accounts.google.com/.well-known/openid-configuration` | Must be HTTPS (`validate_metadata_url`). Required for OIDC — without it the flow fails with *"No metadata URL configured"*. |
| **Attribute Map (JSON)** | leave blank | See the note below. |

**IdP Signing Certificate** and **Allowed Algorithms** only appear for SAML.
For OIDC the server defaults `allowed_algorithms` to `["RS256"]`
(`crates/axiam-db/src/repository/federation_config.rs`), which is exactly what
Google signs with — nothing to do.

**On Attribute Map:** the field is stored, but the OIDC provisioning path does
not consult it. `provision_new_user` takes the username and email from the
ID token's `email` claim directly (falling back to
`federated-<config_id>-<sub>` / `<sub>.<config_id>@federated.local` when Google
sends no email). Leave it blank rather than writing a mapping that will not be
applied.

Save. The row appears with **Enabled** — the repository sets `enabled = true` on
create; there is no separate activation step.

**Get the config's UUID** (you need it in §9):

```bash
# Sign in and keep the cookies
curl -fsS -c /tmp/axiam.cookies -X POST https://axiam-iam.duckdns.org/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"org_slug":"homelab","username":"admin","password":"<password>"}' >/dev/null

curl -fsS -b /tmp/axiam.cookies https://axiam-iam.duckdns.org/api/v1/federation-configs \
  | python3 -m json.tool
```

Note the `id` of the `Google` row.

---

## 9. Run the "Sign in with Google" flow

Three steps. Run them from anywhere that can reach the domain — your laptop is
easier than the Pi because step 2 needs a browser.

### Step 1 — start the flow

```bash
CONFIG_ID="<uuid from §8>"

curl -fsS -X POST https://axiam-iam.duckdns.org/api/v1/auth/federation/oidc/start \
  -H 'Content-Type: application/json' \
  -d "{
        \"org_slug\": \"homelab\",
        \"tenant_slug\": \"organization\",
        \"federation_config_id\": \"$CONFIG_ID\",
        \"redirect_uri\": \"https://axiam-iam.duckdns.org/login\"
      }" | tee /tmp/start.json | python3 -m json.tool
```

You get back `authorize_url`, `state` and `expires_in_secs: 600`.

What just happened server-side: AXIAM generated a 256-bit `state` and a 256-bit
`nonce`, stored them in `federation_login_state` with a 10-minute TTL, fetched
Google's discovery document, and built the authorize URL with
`response_type=code`, your `client_id`, that `redirect_uri`, `scope=openid email
profile`, `state` and `nonce`. **The nonce is deliberately not returned** — it
stays server-side and is read back from the state row at callback time, so a
caller cannot supply one.

`tenant_slug` must name the tenant the config lives in (§6). `org_slug` /
`tenant_slug` can be replaced by `org_id` / `tenant_id` if you prefer UUIDs. A
slug that does not resolve returns **401**, not 404 — deliberately, so the
endpoint does not enumerate tenants.

### Step 2 — approve at Google

```bash
python3 -c 'import json;print(json.load(open("/tmp/start.json"))["authorize_url"])'
```

Open that URL in a browser, sign in with a Google account listed as a test user,
and consent. Google redirects to:

```
https://axiam-iam.duckdns.org/login?state=<state>&code=<code>&scope=...&authuser=0&prompt=consent
```

The AXIAM login page renders and ignores the query string (this is the missing
frontend piece from §0). **Copy `code` and `state` out of the address bar.**
URL-decode `code` if it contains `%2F`.

The code is single-use and short-lived — do step 3 promptly.

### Step 3 — complete the login

```bash
curl -isS -X POST https://axiam-iam.duckdns.org/api/v1/auth/federation/oidc/callback \
  -H 'Content-Type: application/json' \
  -c /tmp/google.cookies \
  -d '{"state":"<state from the URL>","code":"<code from the URL>"}'
```

A success looks like `200 OK`, three `Set-Cookie` headers
(`axiam_access`, `axiam_refresh`, `axiam_csrf`, all `Secure`), an
`X-CSRF-Token` response header, and a body:

```json
{"user_id":"…","session_id":"…","expires_in":900,"redirect_uri":"https://axiam-iam.duckdns.org/login"}
```

Everything the backend does here is real: the state row is consumed atomically
(single-use — replaying the same `state` returns 401), the code is exchanged at
Google's token endpoint with the decrypted client secret, the ID token is
verified against Google's JWKS by `kid` with `alg` checked against the
allow-list, `iss`/`aud`/`exp`/`iat` validated with 60 s leeway, the `nonce`
compared against the stored one, the `login.post_auth` reactor gate fired, the
user JIT-provisioned and linked, and a session issued.

**Both endpoints are CSRF-exempt** by design (`CSRF_EXEMPT_SUFFIXES` in
`middleware/csrf.rs`) — the caller has no prior session and therefore no CSRF
cookie to echo. You do not need a CSRF header for either call.

### Step 4 — use the session (optional)

```bash
CSRF=$(python3 - <<'EOF'
import http.cookiejar
jar = http.cookiejar.MozillaCookieJar('/tmp/google.cookies'); jar.load(ignore_discard=True)
print(next(c.value for c in jar if c.name == 'axiam_csrf'))
EOF
)
curl -fsS -b /tmp/google.cookies -H "X-CSRF-Token: $CSRF" \
  https://axiam-iam.duckdns.org/api/v1/auth/me | python3 -m json.tool
```

Or paste the three cookies into a browser on the domain and load the SPA — the
Google-provisioned user will be signed in, with whatever roles that user has
(by default: none, so most pages will be empty. That is correct — federation
authenticates, it does not authorize).

---

## 10. Verify what AXIAM created

As the super-admin:

- **Users page** — a new user whose username and email are the Google account's
  email address, with `metadata` recording
  `{"provisioned_by":"oidc_federation","federation_config_id":…,"external_subject":…}`.
- **Federation links** — the API is
  `GET /api/v1/federation-links/user/{user_id}` (permission `federation:list`);
  `DELETE /api/v1/federation-links/{id}` (permission `federation:delete`)
  revokes the ability of that Google account to sign in as that AXIAM user.

```bash
USER_ID="<user_id from the callback response>"
curl -fsS -b /tmp/axiam.cookies \
  "https://axiam-iam.duckdns.org/api/v1/federation-links/user/$USER_ID" | python3 -m json.tool
```

- **Second login is a link, not a provision.** Repeat §9 with the same Google
  account: `provision_or_link_user` finds the existing link by
  `(tenant, config, sub)` and reuses the user — no duplicate is created.
- **Server logs** — `docker logs axiam-server` shows
  `Built OIDC authorization URL`, then
  `OIDC callback: token exchange and verification successful`.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Google: `Error 400: redirect_uri_mismatch` | The `redirect_uri` you sent in §9 step 1 is not byte-identical to a registered one. | Make them match exactly. Trailing slash, `http` vs `https` and path case all count. |
| Google: `Error 403: access_denied` while in Testing | The signing-in account is not a listed test user. | Add it under OAuth consent screen → Test users. |
| Start returns `401` | `org_slug` or `tenant_slug` did not resolve. | Check the slugs from the bootstrap response. The org tenant's slug is `organization`. |
| Start returns `400 metadata_url must use HTTPS` / discovery fails | Typo'd discovery URL. | `https://accounts.google.com/.well-known/openid-configuration` |
| Start/create returns `federation encryption key not configured` | `federation_encryption_key` missing from Vault, or the server started before seeding. | Re-run `~/axiam-up.sh` (re-seeds idempotently), then `docker restart axiam-server`. |
| Callback returns `401 state not found or expired` | >10 min elapsed, or the state was already consumed (it is single-use). | Redo §9 from step 1. |
| Callback returns an ID-token validation error | Clock skew on the Pi, or an `aud`/`iss` mismatch. | `timedatectl` — NTP must be on; verify the Client ID in the config matches the one that issued the code. |
| Callback returns `Nonce mismatch` / `Missing nonce in ID token` | The authorize URL was hand-edited, or `code` came from a different `state`. | Use the `authorize_url` verbatim, and pair each `code` with its own `state`. |
| Whole site 502 after a reboot | Vault came back sealed; `axiam-server` is crash-looping. | `~/axiam-up.sh` (see §5.5). Confirm with `docker logs axiam-vault`. |
| Caddy never gets a certificate | Port 80 not reachable from the internet, or DuckDNS points at the wrong IP. | Test from outside the LAN; otherwise use DNS-01 (§4.3). |
| Passkey enrolment fails with 401 | `AXIAM_WEBAUTHN_RP_ORIGIN` does not match the address bar. | Set it to `https://axiam-iam.duckdns.org` and restart the server. |
| `docker compose` refuses to start, `image tag required` etc. | Raw `docker compose` without the environment `prod-up` builds. Compose interpolates the *whole* file on every invocation. | Use `~/axiam-up.sh`, or `just prod-down` / `just prod-clean` which go through `_prod-compose`. |

---

## 12. Before you call this production

This stack is explicitly documented as *production-shaped*, not production. On a
Pi in a home lab, at minimum:

- **Vault has no auto-unseal** and its unseal key sits next to it on disk. A
  real deployment uses a KMS/transit seal and Shamir shares — see
  [`docs/deployment/vault.md`](../docs/deployment/vault.md).
- **Back up `docker/.secrets/` and the `vault-data` volume**, off the device.
- **Do not forward 8090/50051/8200/5671/15672.** §5.3 binds them to loopback;
  keep it that way.
- **Rotate the Google client secret** if it was ever pasted into a shell that
  writes history.
- The **`k8s/` manifests** are the supported production path; `docker-compose.prod.yml`
  says so in its own header comment.
- Consider putting the admin UI behind Caddy basic-auth or a VPN/Tailscale, and
  exposing only what actually needs to be public.

**What a real "Sign in with Google" button would need** (frontend work, not
covered here): a login-page action that POSTs to
`/api/v1/auth/federation/oidc/start` with the org/tenant the user chose, a
`redirect_uri` of a dedicated SPA route (say `/auth/sso/callback`), stores
nothing client-side beyond letting the browser navigate to `authorize_url`;
plus that route, which reads `code` and `state` from the query string, POSTs
them to `/api/v1/auth/federation/oidc/callback`, and on 200 routes to the
`redirect_uri` the response echoes back. Both endpoints are already public and
CSRF-exempt, so nothing on the server needs to change — and the Google-side
config would then register `https://axiam-iam.duckdns.org/auth/sso/callback`
instead of `/login`.
