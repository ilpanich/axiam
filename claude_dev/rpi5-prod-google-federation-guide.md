# Running AXIAM on a Raspberry Pi 5 at `axiam-iam.duckdns.org`, with its own TLS and "Sign in with X"

**Status:** operator runbook — rewritten 2026-09-01 against `1.0.0-beta07`;
§14 (gRPC on the public edge) and the release pin added 2026-09-04 against
`1.0.0-beta10`.
**Audience:** one person deploying AXIAM on their own Pi, exercising federated
login end to end against real identity providers.

Everything below is derived from what is in this repository at this commit.
Where the code and a plausible expectation disagree, the code wins and the
disagreement is called out.

The topology, and the reasoning behind every choice in it, is
[`claude_dev/public-backend-tls-design.md`](public-backend-tls-design.md). This
file is how to build it; that file is why it is shaped this way.

---

## 0. What changed, if you followed the previous version of this guide

| Then | Now | Why |
| --- | --- | --- |
| Caddy → nginx → backend, all of `/` | Caddy routes **by path**: `/` to the SPA, `/api`, `/oauth2`, `/.well-known` to the backend | The middle hop bought nothing and broke rate limiting. §2 |
| Backend spoke **plaintext** on the Docker network | Backend terminates its **own TLS 1.3**, same Let's Encrypt leaf | No cleartext password or bearer token anywhere, including inside the host |
| Caddy obtained the certificate | **certbot** obtains it; Caddy and the backend both consume it | Two consumers need the same leaf, and Caddy's storage layout is not an API |
| `AXIAM__RATE_LIMIT__TRUSTED_HOPS` unset (0) with **two** proxies | Explicitly `0`, with **one** proxy — and now correct | With two hops, 0 keyed every request on the internet to Caddy's address: one global bucket, `/auth/login` included. §6.3 |
| Vault: `file` storage, unseal key beside the data | **Raft**, a real 5-of-3 Shamir init, auto-unseal before go-live, a **read-only** token for the server | §7 |
| Sign-in: two `curl` calls by hand | **Click the button.** The SPA has the buttons and the callback route | §11 |
| Google only | Google, GitHub, Facebook, Apple, Microsoft | §10 |
| gRPC loopback-only, full stop | Loopback by default, **optionally published through the edge** on 443 | The services are authenticated now; SEC-003's reason for the blanket rule is gone. §14 |
| Google redirect URI `…/login` | `https://axiam-iam.duckdns.org/auth/sso/callback` | There is a real callback route now |

If you are upgrading a running Pi, read §15 before changing anything: the Vault
storage change is not automatic.

---

## 1. What you need before you start

**Hardware / OS**

- Raspberry Pi 5, **8 GB recommended** (4 GB is tight: the stack runs SurrealDB
  + RabbitMQ + Vault + axiam-server + nginx). Boot from SSD/NVMe if you can —
  SurrealDB's `surrealkv` engine on an SD card is miserable.
- Raspberry Pi OS (64-bit) or Ubuntu Server 24.04 arm64. **64-bit is
  mandatory** — the released images are built for `linux/amd64` and
  `linux/arm64` only (`.github/workflows/release.yml`, the `platform` matrix).
- At least ~15 GB free disk.

**Network**

- The DuckDNS name `axiam-iam.duckdns.org` pointing at your public IP, kept
  current by the updater (§3).
- Router port-forwards **TCP 80 and 443** to the Pi, and nothing else. Port 80
  is needed for Let's Encrypt's HTTP-01 challenge; if your ISP blocks it, use
  DNS-01 (§4.4).
- **Do not** forward 8090, 50051, 8200, 5671 or 15672. The compose file binds
  them to `127.0.0.1` so a mistake in the router UI cannot expose them, but do
  not rely on that alone. This holds even if you publish gRPC (§14): that route
  arrives on 443 like everything else and 50051 stays loopback-bound.

**Software on the Pi**

```bash
sudo apt update
sudo apt install -y git curl python3 openssl certbot
# Docker Engine + Compose plugin (official convenience script)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # log out and back in
docker compose version            # need v2.24.0+
sudo apt install -y just || true  # otherwise: cargo install just
```

**Accounts** — one or more of Google, GitHub, Facebook, Apple Developer
(**paid**, $99/yr — Sign in with Apple is not available on a free account) and
Microsoft Entra. Plus the repo:

```bash
git clone https://github.com/ilpanich/axiam.git ~/axiam
cd ~/axiam
git checkout v1.0.0-beta10        # the current release — see below
```

You do **not** need a Rust toolchain: `just prod-up` pulls released multi-arch
images from `ghcr.io/ilpanich/axiam/*`.

**Deploy a tag, not `main`.** `just prod-up` defaults `AXIAM_IMAGE_TAG` to the
*workspace* version — it reads `version` out of the root `Cargo.toml` — and the
images carry the released version with the leading `v` stripped
(`.github/workflows/release.yml`: the tag `v1.0.0-beta10` publishes the image
`1.0.0-beta10`, `linux/amd64` and `linux/arm64` under one manifest list). On a
checked-out tag the two agree by construction. On `main` they agree only until
someone bumps the version ahead of a release, and then compose fails on an image
tag that was never published. That failure is the harmless outcome. The harmful
one is the reverse: a working tree whose compose file, `.proto` files and
`justfile` describe a build the running image is not.

Pre-releases deliberately get **no** moving tags — no `latest`, no `1.0` — so
there is nothing to drift under you. Upgrading later is `git checkout v<next>`
followed by `~/axiam-up.sh`; check `CHANGELOG.md` between the two tags first.

---

## 2. How the pieces fit together

```
                         Internet
                            │
                            │ 443/TLS 1.3 — Let's Encrypt leaf
                            ▼
              ┌──────────────────────────────┐
              │  Caddy (host, systemd)       │  the only public listener
              └───┬──────────────────────┬───┘
                  │                      │
   /.well-known/acme-challenge/*         │  everything else, BY PATH
                  │                      │
                  ▼                      ├── /              → 127.0.0.1:8081
        /var/www/certbot                 │                    axiam-frontend
        (certbot's webroot)              │                    (nginx, SPA only)
                                         │
                                         ├── /api/*         ─┐
                                         ├── /oauth2/*      ─┼ 443/TLS 1.3 →
                                         ├── /.well-known/* ─┘ 127.0.0.1:8090
                                         │                     axiam-server
                                         │                     (same leaf)
                                         │
                                         └── /axiam.v1.*    ── HTTP/2 over TLS →
                                             (optional, §14)   127.0.0.1:50051
                                                               axiam-server gRPC
                                                               (the same leaf again)

   /health, /ready, /health/jobs — NOT routed. Probe them on the loopback.
```

Four consequences that matter for everything below.

1. **One origin.** The SPA at `https://axiam-iam.duckdns.org/` and the API at
   `…/api` are the same scheme, host and port, so no browser ever issues a
   preflight. `AXIAM__SERVER__CORS_ALLOWED_ORIGINS` stays **empty**. (It looks
   like it should need CORS — two processes, two containers — but origin is not
   about processes.)

2. **One proxy in front of the backend**, not two. This is what makes
   `TRUSTED_HOPS=0` correct; see §6.3, and do not change it without re-reading
   that section. It has to stay one on the gRPC route too — that route exists
   *because* of this property, not in spite of it (§14.2).

3. **The backend terminates its own TLS.** Nothing on this host carries an
   AXIAM password or bearer token in cleartext, not even between containers.

4. **Health endpoints are deliberately not public.** `/health/jobs` reports
   per-job scheduler state — names, last-run times, consecutive failures —
   which is a free map of what you run and what is currently broken in it.
   Caddy does not route it, so it lands on the SPA route and returns
   `index.html`. Probe it on the loopback instead (§8).

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
   public IP. Let's Encrypt validates from the internet, and a
   NAT-loopback-only setup fails at exactly this point.

---

## 4. One certificate, two consumers

Caddy can obtain certificates by itself, and the previous version of this guide
let it. That no longer works, because **the backend needs the same leaf** and
Caddy's certificate storage layout is an internal detail nothing should parse.

So: **certbot owns ACME. Caddy and `axiam-server` both read
`/etc/letsencrypt/live/axiam-iam.duckdns.org/`.**

### 4.1 Install Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

### 4.2 Issue the certificate

Caddy has to be serving the ACME webroot before certbot can validate, and Caddy
will not start without a certificate — so bootstrap with `--standalone` once,
with Caddy stopped, then switch to the webroot for renewals.

```bash
sudo mkdir -p /var/www/certbot
sudo systemctl stop caddy 2>/dev/null || true

sudo certbot certonly --standalone \
    -d axiam-iam.duckdns.org \
    --agree-tos -m you@example.com --no-eff-email

sudo ls -l /etc/letsencrypt/live/axiam-iam.duckdns.org/
# fullchain.pem  privkey.pem  cert.pem  chain.pem
```

### 4.3 The Caddyfile

```bash
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
axiam-iam.duckdns.org {
	encode zstd gzip

	# Our own certificate. Caddy's ACME is never engaged — certbot owns it,
	# because axiam-server needs the same files.
	tls /etc/axiam/tls/fullchain.pem /etc/axiam/tls/privkey.pem

	# ORDER IS LOAD-BEARING. This must come before the /.well-known route
	# below: AXIAM answers /.well-known/openid-configuration and certbot
	# needs /.well-known/acme-challenge/, and they share a prefix.
	handle /.well-known/acme-challenge/* {
		root * /var/www/certbot
		file_server
	}

	# Headers a client must never be able to assert for itself.
	#
	# X-Client-Certificate is device identity on the backend's proxy path; a
	# certificate is public data, so anyone who can set this header could
	# otherwise authenticate as any enrolled device. The backend refuses it
	# by default too (AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT), and neither
	# half should be the only defence.
	#
	# X-Real-IP is deleted so the value Caddy sets is the only one present.
	# X-Forwarded-For is NOT deleted: Caddy appends the real peer to the
	# right of whatever arrived, and the rate limiter reads from the right.
	# See §6.3.
	request_header -X-Client-Certificate
	request_header -X-Real-IP

	# The API, straight to the backend over TLS. No second proxy.
	@api path /api/* /oauth2/* /.well-known/*
	handle @api {
		reverse_proxy https://127.0.0.1:8090 {
			transport http {
				# The backend presents the public leaf, so verify it
				# against the public roots — with the name overridden,
				# because we are dialling a loopback address. This is a
				# real verification, not a bypass.
				tls_server_name axiam-iam.duckdns.org
			}
		}
		header Cache-Control "no-store"
	}

	# Everything else is the SPA.
	handle {
		reverse_proxy 127.0.0.1:8081
	}
}
EOF
```

Note what is **absent**: no route to `/health`, `/ready` or `/health/jobs`.
That is deliberate (§2). Also absent: gRPC. If you want it public, §14 adds one
`handle` block to this file — do the rest of the guide first and come back.

### 4.4 If port 80 is blocked (DNS-01)

Some ISPs block inbound 80. Use certbot's manual DNS hook against DuckDNS:

```bash
sudo tee /usr/local/bin/duckdns-auth.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
curl -fsS "https://www.duckdns.org/update?domains=axiam-iam&token=$DUCKDNS_TOKEN&txt=$CERTBOT_VALIDATION"
sleep 30
EOF
sudo tee /usr/local/bin/duckdns-cleanup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
curl -fsS "https://www.duckdns.org/update?domains=axiam-iam&token=$DUCKDNS_TOKEN&txt=removed&clear=true"
EOF
sudo chmod 700 /usr/local/bin/duckdns-{auth,cleanup}.sh

sudo DUCKDNS_TOKEN=your-token certbot certonly --manual \
    --preferred-challenges dns \
    --manual-auth-hook /usr/local/bin/duckdns-auth.sh \
    --manual-cleanup-hook /usr/local/bin/duckdns-cleanup.sh \
    -d axiam-iam.duckdns.org --agree-tos -m you@example.com
```

You still need **443** forwarded; only 80 becomes optional. Put
`DUCKDNS_TOKEN=` in `/etc/environment` or a systemd drop-in so renewals have it.

### 4.5 The deploy hook — where renewal actually lands

Let's Encrypt issues for 90 days and certbot renews at 60. Three things have to
happen when it does, and this hook is all of them:

```bash
sudo mkdir -p /etc/axiam/tls
# Written with an UNquoted heredoc so $HOME expands now, into the script.
sudo tee /etc/letsencrypt/renewal-hooks/deploy/axiam.sh >/dev/null <<EOF
#!/usr/bin/env bash
# Install the renewed leaf where Caddy and axiam-server can read it, then tell
# both to pick it up. Runs as root, only after a successful renewal.
set -euo pipefail

SRC="/etc/letsencrypt/live/axiam-iam.duckdns.org"
AXIAM_TLS="$HOME/axiam/docker/.secrets/server-tls"

# 1. Caddy's copy. Caddy starts as root and reads the files before dropping.
install -m 0644 "\$SRC/fullchain.pem" /etc/axiam/tls/fullchain.pem
install -m 0600 "\$SRC/privkey.pem"   /etc/axiam/tls/privkey.pem
systemctl reload caddy

# 2. The container's copy. axiam-server runs as a non-root user in a distroless
#    image, so instead of loosening the mode on a private key, match the owner:
#    65532 is the distroless nonroot uid.
install -o 65532 -g 65532 -m 0644 "\$SRC/fullchain.pem" "\$AXIAM_TLS/fullchain.pem"
install -o 65532 -g 65532 -m 0600 "\$SRC/privkey.pem"   "\$AXIAM_TLS/privkey.pem"

# 3. Tell the server. It re-reads the pair on SIGHUP and installs it behind an
#    ArcSwap that rustls consults per handshake, so the very next connection
#    uses the new certificate — no restart, no dropped request. If the container
#    happens to be down, the hourly poll picks it up instead; see
#    AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS.
docker kill -s HUP axiam-server 2>/dev/null || true
EOF
sudo chmod 700 /etc/letsencrypt/renewal-hooks/deploy/axiam.sh
```

Check the rendered script before trusting it — `$SRC` and `$AXIAM_TLS` must
still be `$`-prefixed variables, and `$HOME` must have become a real path:

```bash
sudo cat /etc/letsencrypt/renewal-hooks/deploy/axiam.sh
```

Run it once by hand so the files exist before anything starts:

```bash
sudo mkdir -p ~/axiam/docker/.secrets/server-tls
sudo /etc/letsencrypt/renewal-hooks/deploy/axiam.sh
```

Then switch renewals to the webroot (skip if you used DNS-01 in §4.4) and prove
the whole thing works **before** you depend on it:

```bash
sudo sed -i 's/^authenticator = standalone/authenticator = webroot\nwebroot_path = \/var\/www\/certbot,/' \
    /etc/letsencrypt/renewal/axiam-iam.duckdns.org.conf
sudo systemctl start caddy && sudo systemctl enable caddy

sudo certbot renew --dry-run     # must succeed
```

`certbot.timer` is enabled by the Debian package and runs twice a day; there is
nothing else to schedule.

> **Verify the hook fires.** A deploy hook that was never exercised is the
> commonest cause of a certificate that expires on a running server. After the
> first real renewal, `docker logs axiam-server | grep 'leaf certificate'`
> should show `TLS leaf certificate reloaded`.

> **If you publish gRPC (§14), this hook needs a fourth step.** The gRPC
> listener has no SIGHUP path and no poll — it reads its certificate once, at
> startup. §14.5 has the replacement.

---

## 5. Bring the stack up

### 5.1 What `just prod-up` does for you

Read the recipe once (`justfile`, `prod-up`). It:

1. Mints SurrealDB and RabbitMQ credentials into
   `docker/.secrets/stack-credentials.env` (mode 600, gitignored) **on first run
   only** — they are tied to the data volumes and cannot be re-minted later.
2. Generates the AMQPS broker CA/cert and Vault's listener cert.
3. Generates an Ed25519 JWT signing keypair under `docker/.secrets/`.
4. Starts Vault, initialises it, unseals it, seeds every secret AXIAM needs,
   **writes the read-only `axiam` policy, and issues a scoped token** for the
   server. That seeding is what makes federation work at all: it mints
   `federation_encryption_key`, without which `POST /api/v1/federation-configs`
   fails with *"federation encryption key not configured"*.
5. Sets `AXIAM_IMAGE_TAG` from the workspace version and runs `docker compose`.

**Its Vault ceremony is a laptop ceremony, not a production one** — it writes a
single unseal key to `docker/.secrets/vault-init.json`, i.e. next to the sealed
data. §7 replaces that. Do §7 before you put real users on this.

### 5.2 The settings you must supply

Note the **double underscore** after `AXIAM`: `load_config()` calls
`.with_prefix("AXIAM").separator("__")`, so `__` is both the prefix separator
and the nesting separator. `AXIAM_DB_URL` is silently ignored; `AXIAM__DB__URL`
is not. Three variables are read from the OS environment directly instead —
`AXIAM_BOOTSTRAP_ADMIN_EMAIL`, `AXIAM_HEALTHCHECK_URL` and
`AXIAM__RATE_LIMIT__TRUSTED_HOPS` — but their names are the same either way.

| Variable | Value | Why |
| --- | --- | --- |
| `AXIAM_WEBAUTHN_RP_ID` | `axiam-iam.duckdns.org` | Bare registrable domain. Passkeys bind to it; changing it later invalidates every passkey already enrolled. |
| `AXIAM_WEBAUTHN_RP_ORIGIN` | `https://axiam-iam.duckdns.org` | Must match the browser's address bar **exactly**. The built-in default is `https://localhost`; leaving it there makes every passkey registration fail with a 401 that looks like a session bug. |
| `AXIAM__AUTH__JWT_ISSUER` | `https://axiam-iam.duckdns.org` | The `iss` on AXIAM's own tokens. Default is the literal string `axiam`. |
| `AXIAM__AUTH__OAUTH2_ISSUER_URL` | `https://axiam-iam.duckdns.org` | **Load-bearing, not cosmetic.** It is what `/.well-known/openid-configuration` advertises *and* the base URL from which AXIAM builds the redirect URIs it hands to Apple and to SAML IdPs. Get it wrong and those two providers fail with a mismatch that points nowhere useful. Validated as a URL at startup. |
| `AXIAM_BOOTSTRAP_ADMIN_EMAIL` | your admin email | `POST /api/v1/admin/bootstrap` is fail-closed: it refuses unless this is set **and matches** the request's email, or the request carries the one-time setup token. |
| `AXIAM_TLS_ENABLED` | `true` | Makes the backend terminate its own TLS from the certificate §4.5 installs. |

`AXIAM__SERVER__CORS_ALLOWED_ORIGINS` stays **empty** — single origin (§2).
`AXIAM__AUTH__COOKIE_SECURE` defaults to `true`, which is what you want.

### 5.3 The bring-up script

```bash
cat > ~/axiam-up.sh <<'EOF'
#!/usr/bin/env bash
# Bring up (or restart) the AXIAM stack on the Pi.
set -euo pipefail
cd "$HOME/axiam"

export AXIAM_WEBAUTHN_RP_ID="axiam-iam.duckdns.org"
export AXIAM_WEBAUTHN_RP_ORIGIN="https://axiam-iam.duckdns.org"
export AXIAM_BOOTSTRAP_ADMIN_EMAIL="you@example.com"

# The backend terminates its own TLS from the certbot-installed leaf.
export AXIAM_TLS_ENABLED="true"
# `optional` only if you enrol IoT devices and read §13 first; otherwise `off`.
export AXIAM_TLS_CLIENT_AUTH="off"

# One proxy (Caddy) in front of /api. See §6.3 before changing this.
export AXIAM__RATE_LIMIT__TRUSTED_HOPS="0"

# Nothing routes through the frontend's nginx on this topology, but keep it
# consistent with the backend anyway so reaching the container directly works.
export AXIAM_BACKEND_ORIGIN="https://axiam-server:8090"
export AXIAM_BACKEND_SNI="axiam-iam.duckdns.org"

just prod-up
EOF
chmod 700 ~/axiam-up.sh
```

`prod-up` reads `AXIAM__AUTH__JWT_ISSUER` and `AXIAM__AUTH__OAUTH2_ISSUER_URL`
from a compose override, so add one:

```bash
cat > ~/axiam/docker/docker-compose.pi.yml <<'EOF'
# Pi-specific overrides. Applied automatically by `just prod-up`? No — add it
# with COMPOSE_FILE, see below.
services:
  axiam-server:
    environment:
      AXIAM__AUTH__JWT_ISSUER: "https://axiam-iam.duckdns.org"
      AXIAM__AUTH__OAUTH2_ISSUER_URL: "https://axiam-iam.duckdns.org"
EOF
```

and put this above `just prod-up` in `~/axiam-up.sh`:

```bash
export COMPOSE_FILE="docker/docker-compose.prod.yml:docker/docker-compose.pi.yml"
```

> `just prod-up` passes `-f docker/docker-compose.prod.yml` explicitly, which
> **overrides** `COMPOSE_FILE` for its own calls. If your `just` version does
> not pick the override up, add the two variables to the `environment:` block in
> `docker-compose.prod.yml` directly. Raw `docker compose` against that file is
> not a supported path — it interpolates the whole file on every invocation and
> every `${VAR:?}` must resolve, which is what `prod-up` exists to arrange.

Then:

```bash
~/axiam-up.sh
```

Wait for `axiam-server` to report `healthy`, then check each layer separately —
when something is wrong, knowing *which* hop failed saves an hour:

```bash
# 1. The backend's own TLS listener, bypassing Caddy. --resolve keeps the
#    certificate name honest instead of turning verification off.
curl -fsS --resolve axiam-iam.duckdns.org:8090:127.0.0.1 \
     https://axiam-iam.duckdns.org:8090/health && echo " ← backend OK"

# 2. Through the public front door: Caddy → backend.
curl -fsS https://axiam-iam.duckdns.org/.well-known/openid-configuration \
  | python3 -m json.tool | head -20

# 3. The SPA.
curl -fsS -o /dev/null -w '%{http_code}\n' https://axiam-iam.duckdns.org/
```

Open `https://axiam-iam.duckdns.org` — the AXIAM login page over a valid
certificate.

> If step 1 fails with a TLS error, the container cannot read the key. Check
> `docker logs axiam-server` for `failed to open TLS key file` and re-run the
> deploy hook (§4.5) — the ownership is the usual culprit.

---

## 6. Three settings worth understanding, not just copying

### 6.1 Why the backend has a certificate at all

Because the alternative is cleartext. With TLS off, every password on its way to
`/api/v1/auth/login`, every session cookie and every OAuth2 client secret
crosses the Docker bridge in plaintext, readable by anything that can join that
network or read the host's network namespace. On a Pi that also runs your other
containers, that is not hypothetical.

### 6.2 Why certbot and not Caddy's ACME

Because two processes need the same leaf, and Caddy's storage layout is an
implementation detail. One ACME client means one renewal to monitor and one
place to look when it fails.

### 6.3 `TRUSTED_HOPS`, and how to derive it for your own topology

A proxy appends **the address it received the request from**, not its own.
nginx's `proxy_add_x_forwarded_for` is `$http_x_forwarded_for, $remote_addr`;
Caddy and ingress-nginx do the same. So the nearest proxy never appears in the
header the server reads — it is the socket peer. Therefore:

> **`TRUSTED_HOPS` = (number of reverse proxies between the client and the
> server) − 1.**

| Your topology | Header the server sees | Set |
| --- | --- | --- |
| This guide: Caddy → backend | `<client>` | **0** |
| Caddy → nginx → backend (the old shape) | `<client>, <caddy>` | **1** |
| Cloudflare → Caddy → backend | `<client>, <cf-edge>` | **1** |
| LB → ingress → mesh → backend | `<client>, <lb>, <ingress>` | **2** |

Get it **too high** and `trusted_hops >= hops.len()`, so the extractor discards
the header entirely and keys on `peer_addr()` — the proxy's address. Every
client on the internet then shares one bucket, including on `/auth/login`, which
is deliberately always keyed per-IP so an attacker cannot lock out a victim.
Collapsed, it does the opposite: one attacker's flood exhausts the bucket
everybody shares.

Get it **too low** and you key off a proxy instead of the client, which fails
the same way.

Behind exactly one appending proxy, `0` selects the real client whether or not
the client sends a forged `X-Forwarded-For` of its own — the proxy appends the
real peer to the right of the forgery, and the extractor reads from the right.
That property is why `0` is the default and not merely the convenient answer.

**Check it after any topology change:**

```bash
docker logs axiam-server 2>&1 | grep -i 'rate.limit' | head
# and from two different external IPs, confirm they get separate buckets:
for i in $(seq 1 40); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST \
    https://axiam-iam.duckdns.org/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"org_slug":"nope","username":"nope","password":"nope"}'
done; echo
```

You should see `401`s turning into `429` after the configured budget **per
source address**. If a second device on a different network is throttled the
instant the first one is, the value is wrong.

---

## 7. Vault, properly

`just prod-up` leaves you a working Vault with a **single unseal key sitting on
the same disk as the sealed data**. That is not Shamir's scheme with the shares
stored badly — it is no seal at all. Anyone who can read the disk can unseal.

This section replaces it. Do it before real users exist.

### 7.1 Auto-unseal first — the decision nobody should defer

`docs/deployment/vault.md` §5.3 calls this "the single most important production
step and the one most often deferred", and it is right: without it, every
restart — a power cut, an `apt upgrade`, an OOM kill — leaves Vault sealed and
`axiam-server` crash-looping, because Docker does not re-evaluate
`depends_on: service_healthy` on restart.

Vault OSS's seal types all need something **outside the box**. Honestly, for a
home lab:

| Option | What it costs | Verdict |
| --- | --- | --- |
| `seal "gcpckms"` | GCP Cloud KMS, **~$0.06/key/month** plus a fraction of a cent in operations | **Recommended.** Cheapest by an order of magnitude, works fine from a home connection, and the only cloud footprint is one key. |
| `seal "awskms"` | AWS KMS, ~$1/key/month | Fine, same shape, pricier. |
| `seal "azurekeyvault"` | Azure Key Vault | Fine. |
| `seal "transit"` | A **second** Vault, **elsewhere**, already unsealed | Reasonable if you already run one. A second Vault on the same Pi solves nothing — it needs unsealing too. |
| `seal "pkcs11"` (HSM/TPM) | Vault **Enterprise** licence | **Not available.** Vault OSS cannot auto-unseal from a TPM, whatever hardware the Pi has. |
| A script that unseals from keys on the disk | nothing | **This is not auto-unseal.** It is what `prod-up` does and what this section exists to replace. |

If you will do none of these, then say so out loud in your own notes: **you are
running a manually-unsealed Vault, every reboot needs a human with three shares,
and this is not a production deployment.** That is a legitimate choice for a
home lab. What is not legitimate is leaving the shares on the box and calling
the problem solved.

Assuming GCP KMS: create a key ring and key, give the Pi a service account with
`roles/cloudkms.cryptoKeyEncrypterDecrypter`, mount the JSON key, and uncomment
the `gcpckms` block in `docker/vault/vault.hcl`.

### 7.2 Start clean and initialise for real

```bash
cd ~/axiam
just prod-down
docker volume rm docker_vault-raft-data 2>/dev/null || true
rm -f docker/.secrets/vault-init.json

docker compose -f docker/docker-compose.prod.yml up -d vault
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="$PWD/docker/.secrets/vault-tls/ca.pem"

docker exec -e VAULT_ADDR -it axiam-vault \
    vault operator init -key-shares=5 -key-threshold=3
```

**That output is printed once and cannot be recovered.** Five shares and a root
token.

- Give each share to a **different person**, or at minimum to five different
  places that do not fail together. Three of five must cooperate to unseal —
  that is the entire point. Do not put all five in one password manager, and do
  not put any of them where the root token is.
- With auto-unseal configured (§7.1) you will rarely use them. Keep them anyway:
  they are what re-key and seal-migration need.

Unseal three times (once, if auto-unseal is on you skip this entirely):

```bash
docker exec -e VAULT_ADDR -it axiam-vault vault operator unseal   # x3
```

### 7.3 KV v2, the read-only policy, and a token that is not root

```bash
export VAULT_TOKEN="<root token from 7.2>"
docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault \
    vault secrets enable -path=secret -version=2 kv || true

docker exec -e VAULT_ADDR -e VAULT_TOKEN -i axiam-vault \
    vault policy write axiam - <<'EOF'
# Read-only, scoped to exactly one path. A leaked AXIAM token must not be a key
# to the rest of your Vault.
path "secret/data/axiam" {
  capabilities = ["read"]
}
path "secret/metadata/axiam" {
  capabilities = ["read"]
}
EOF
```

Seed with a **separate, short-lived** token that has write — the seeding
credential and the serving credential are not the same thing:

```bash
SEED_TOKEN=$(docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault \
    vault token create -policy=root -ttl=30m -field=token)
VAULT_TOKEN="$SEED_TOKEN" \
JWT_PRIVATE_KEY_PEM="$(cat docker/.secrets/jwt_ed25519.pem)" \
JWT_PUBLIC_KEY_PEM="$(cat docker/.secrets/jwt_ed25519.pub.pem)" \
    bash scripts/vault-seed.sh
docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault vault token revoke "$SEED_TOKEN"
```

Then issue the server's token and **revoke the root token**:

```bash
AXIAM_TOKEN=$(docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault \
    vault token create -policy=axiam -period=768h -field=token)
echo "$AXIAM_TOKEN" > docker/.secrets/vault-server-token
chmod 600 docker/.secrets/vault-server-token

docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault vault token revoke "$VAULT_TOKEN"
```

Add to `~/axiam-up.sh`, before `just prod-up`:

```bash
export AXIAM__AUTH__VAULT_TOKEN="$(cat docker/.secrets/vault-server-token)"
```

`prod-up` re-runs the whole Vault ceremony on **every** invocation — it unseals,
waits for the node to become active, re-seeds, rewrites the policy and issues a
fresh scoped token — and then overrides `AXIAM__AUTH__VAULT_TOKEN` with that
token. That is safe rather than merely tolerable: seeding preserves every
existing secret and refuses to write at all when it cannot read what is there
(`docs/deployment/vault.md` §5.5), and the policy write is idempotent. Exporting
`AXIAM__AUTH__VAULT_TOKEN` in `~/axiam-up.sh` still works — it is what a raw
`docker compose` needs — but it does not suppress the ceremony.

### 7.4 Prove the scope is what you think it is

Writing a policy and *attaching* it are two steps, and nothing inside AXIAM can
tell a scoped token from a root one — both read the secret successfully.

```bash
just vault-status
```

```
  token scope (T-180):
    ok           secret/data/axiam: read
    ok           secret/metadata/axiam: read
```

Anything beyond `read` is reported as `OVER-SCOPED`. If you see that, the server
is still holding a token it should not have.

### 7.5 Back it up

```bash
docker exec -e VAULT_ADDR -e VAULT_TOKEN axiam-vault \
    vault operator raft snapshot save /tmp/vault.snap
docker cp axiam-vault:/tmp/vault.snap ./vault-$(date +%F).snap
```

Raft snapshots are consistent and can be taken while Vault runs — one of the
reasons this stack no longer uses the `file` backend. **Copy them, and
`docker/.secrets/`, off the Pi.** Losing the Vault loses the OPAQUE setup key,
which means a password reset for every user in every tenant.

---

## 8. Reboots

With auto-unseal (§7.1) the stack comes back on its own and you only need the
containers started. Without it, a human must unseal after every reboot — that is
the cost of skipping §7.1, and it is the reason to not skip it.

```bash
sudo tee /etc/systemd/system/axiam-stack.service >/dev/null <<EOF
[Unit]
Description=AXIAM stack
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

Health probes, which are not routed publicly (§2):

```bash
curl -fsS --resolve axiam-iam.duckdns.org:8090:127.0.0.1 \
     https://axiam-iam.duckdns.org:8090/health/jobs | python3 -m json.tool
```

---

## 9. First-run bootstrap

`POST /api/v1/admin/bootstrap` creates the organization, its
**organization-scope tenant** (slug `organization`), seeds permissions and
default roles, and creates the super-admin. One-shot — a `bootstrap_lock:global`
uniqueness invariant means a second call gets a 409.

It does **not** create an ordinary tenant. `tenant_name` / `tenant_slug` in the
request are accepted and ignored. The super-admin is organization-level, so it
administers every tenant the organization ever has.

**Option A — the UI.** Browse to `https://axiam-iam.duckdns.org/bootstrap`.
Requires `AXIAM_BOOTSTRAP_ADMIN_EMAIL` to match the email you type.

**Option B — the setup token**, logged once at first boot:

```bash
docker logs axiam-server 2>&1 | grep -m1 setup_token

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

Sign in at `https://axiam-iam.duckdns.org/login` with organization slug
`homelab`, tenant slug blank (organization level) or `organization`.

### Which tenant will the provider configs live in?

`handlers::federation::create` writes `tenant_id: user.tenant_id` — **the tenant
of whoever is signed in**. As the bootstrap super-admin that is the
organization-scope tenant.

That is usually what you want now, because a config in the organization tenant
with **Allow tenant inheritance** set is visible to every tenant beneath it. If
you would rather federate into one ordinary tenant only, create it first, then
sign in as a user *in that tenant* before adding the config.

---

## 10. The five providers

Every one of them needs the **same redirect URI**:

```
https://axiam-iam.duckdns.org/auth/sso/callback
```

That is a real SPA route (`frontend/src/router.tsx`), which is what changed
since the previous version of this guide. Apple is the exception and is called
out in §10.4.

### 10.1 Google

[Google Cloud Console](https://console.cloud.google.com/).

1. **New Project**, e.g. `axiam-homelab`. Keep it selected.
2. **APIs & Services → OAuth consent screen** (newer consoles: *Google Auth
   Platform*): User type **External**; app name `AXIAM`; support and developer
   contact emails.
3. **Authorized domains:** `duckdns.org` — the *registrable* domain.
   `axiam-iam.duckdns.org` is rejected here.
4. **Scopes:** `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`.
   Non-sensitive, so **no Google verification is required**.
5. **Test users:** while the app is in *Testing*, only listed accounts can sign
   in. Add yours. Stay in Testing for a home lab.
6. **Credentials → Create Credentials → OAuth client ID → Web application**:
   - Authorized JavaScript origins: `https://axiam-iam.duckdns.org`
   - Authorized redirect URIs: `https://axiam-iam.duckdns.org/auth/sso/callback`

Copy the Client ID and secret. No API needs enabling — OIDC works off discovery
at `https://accounts.google.com/.well-known/openid-configuration`.

### 10.2 GitHub

**Settings → Developer settings → OAuth Apps → New OAuth App.**

- Homepage URL: `https://axiam-iam.duckdns.org`
- Authorization callback URL: `https://axiam-iam.duckdns.org/auth/sso/callback`

Generate a client secret.

> **GitHub is not OIDC.** It publishes no discovery document and issues no ID
> token, so AXIAM uses the plain-**OAuth2** protocol variant: authentication is
> "the access token we just obtained, at a token endpoint we configured, with a
> secret only we hold, works against a userinfo endpoint we configured". There
> is no signature, no `nonce` and no `aud` to check. That is a weaker trust
> statement than OIDC — deliberately a separate protocol in AXIAM so the
> difference is visible everywhere, not a flag on OIDC. See
> `claude_dev/federation-sso-login-design.md` §3.
>
> Scope `user:email` is needed as well as `read:user`, because GitHub does not
> return a private email from `/user` — AXIAM falls back to `/user/emails` and
> picks the primary verified address.

### 10.3 Facebook

[developers.facebook.com](https://developers.facebook.com/) → **Create App** →
*Authenticate and request data from users with Facebook Login* → add the
**Facebook Login** product.

- Valid OAuth Redirect URIs: `https://axiam-iam.duckdns.org/auth/sso/callback`
- App ID = client ID; App Secret = client secret.

Also OAuth2 rather than OIDC: Facebook's web authorization-code flow returns
only an access token to a confidential client. While the app is in *Development*
mode only accounts with a role on the app can sign in — which is the right place
for a home lab.

### 10.4 Apple — read this one before you start

Sign in with Apple requires a **paid** Apple Developer account ($99/yr).

1. **Certificates, Identifiers & Profiles → Identifiers →** register an **App
   ID**, enable *Sign in with Apple*.
2. Register a **Services ID** (this is your `client_id`, e.g.
   `org.example.axiam.web`). Configure it:
   - Domains: `axiam-iam.duckdns.org`
   - Return URLs: **`https://axiam-iam.duckdns.org/api/v1/auth/federation/oidc/callback/form`**
3. **Keys →** create a key with *Sign in with Apple* enabled. Download the
   `.p8` **once**. Note the 10-character **Key ID** and your **Team ID**.

Three things are different about Apple, all of them consequences of how Apple
works rather than choices AXIAM made:

- **The return URL is a backend endpoint, not the SPA route.** Requesting the
  `name` scope forces `response_mode=form_post`, so Apple returns by a
  cross-site form POST. Cookies on that response would be `SameSite=Strict` and
  the browser would refuse to send them, so AXIAM answers `303` with a
  single-use handoff code and the SPA redeems it. That is why this one provider
  registers a different URL.
- **You paste the `.p8`, not a client secret.** Apple's client secret is an
  ES256 JWT that expires within six months. AXIAM mints a fresh 5-minute one per
  token exchange from your `.p8`, so there is no secret to rotate and no outage
  on a Tuesday six months from now. The `.p8` is stored AES-256-GCM-encrypted at
  rest like any other client secret.
- **The user's name arrives exactly once**, in the `user` field of that first
  POST — never in the ID token, and never again. AXIAM reads it at provisioning
  time. If you delete the user and re-provision, the name will be missing.

Apple's scope default is `name email`. It rejects `profile`.

### 10.5 Microsoft Entra ID

[Azure Portal](https://portal.azure.com/) → **Microsoft Entra ID → App
registrations → New registration**.

- Redirect URI: **Web**, `https://axiam-iam.duckdns.org/auth/sso/callback`
- Supported account types: your choice — this decides §10.5's wrinkle.
- **Certificates & secrets → New client secret.** Copy the *value*, not the ID.

**The templated-issuer wrinkle.** A `common` or `organizations` authority
publishes

```
issuer = https://login.microsoftonline.com/{tenantid}/v2.0
```

with `{tenantid}` literal. AXIAM supports it, but the config must list which
Entra tenants you accept (`allowed_issuer_tenants`), and **a templated issuer
with an empty list is refused at save time**. That refusal is the point:
Microsoft signs every tenant's tokens at `common` with the same keys, so
"accept anything" means every Microsoft account on earth can sign into your
workspace — occasionally what someone wants, never what they want by accident.

Two ways out, both fine:

- Use a **tenant-specific authority**
  `https://login.microsoftonline.com/<your-tenant-guid>/v2.0/.well-known/openid-configuration`,
  which publishes a concrete issuer and needs no list; or
- keep `common` and list the Entra tenant GUIDs you accept.

---

## 11. Configure them in the admin UI, and sign in

Sign in as the super-admin → **Federation** → **Add Federation Config**.

| Field | What to put |
| --- | --- |
| **Provider kind** | `Google` / `GitHub` / `Facebook` / `Apple` / `Microsoft`. This prefills protocol, scopes, endpoints and algorithms — all of which are still sent explicitly, so the server never guesses. |
| **Provider** | Display name on the button, e.g. `Google`. |
| **Protocol** | Prefilled: OIDC for Google/Apple/Microsoft, **OAuth2** for GitHub/Facebook. |
| **Client ID** | From §10. For Apple this is the **Services ID**. |
| **Client Secret** | From §10. For Apple, paste the **`.p8` contents**. AES-256-GCM-encrypted before it reaches the database; never returned by the API and never rendered again. |
| **Metadata URL** | OIDC only. Google: `https://accounts.google.com/.well-known/openid-configuration`. Apple: `https://appleid.apple.com/.well-known/openid-configuration`. Microsoft: see §10.5. Must be HTTPS. |
| **Authorization / Token / Userinfo endpoint** | OAuth2 only; prefilled for GitHub and Facebook. |
| **Scopes** | Prefilled per kind. Apple is `name email` — do not add `profile`, Apple rejects it. |
| **Apple Team ID / Key ID** | Apple only, from §10.4. |
| **Allowed issuer tenants** | Microsoft with a `common` authority only. §10.5. |
| **Allow tenant inheritance** | On, if you want tenants beneath the organization to use this config. |
| **Allowed algorithms** | OIDC only; `RS256` is prefilled and correct for all four OIDC providers here. |
| **Attribute map** | Leave blank unless you need it. Defaults per kind already map subject, email and name. |

Save. The row appears **Enabled** — the repository sets `enabled = true` on
create; there is no separate activation step.

### Now sign in with it

1. Open `https://axiam-iam.duckdns.org/login` in a **private window**.
2. Type the organization slug (`homelab`) and submit the workspace step.
3. The **"Sign in with …" buttons appear**, one per enabled config.

> They appear *after* the workspace step, not on page load, and that is
> deliberate: the page does not know which organization you mean until you say,
> and `GET /api/v1/auth/federation/providers` returns `200` with an empty list
> for an unknown organization exactly so that it cannot be used to enumerate
> organization slugs. An empty provider section rendered before you have asked
> would be a lie.

4. Click one. You are sent to the provider, you approve, and you land back on
   `/auth/sso/callback`, which completes the exchange and drops you into the
   admin UI signed in.

That is the whole flow. No `curl`.

What happened server-side, for the OIDC providers: AXIAM generated a 256-bit
`state` and `nonce` and stored them with a 10-minute TTL; the `state` row is
consumed atomically at callback (replaying it returns 401); the code was
exchanged with the decrypted client secret; the ID token was verified against
the provider's JWKS by `kid`, with `alg` checked against the allow-list and
`iss`/`aud`/`exp`/`iat` checked with 60 s leeway; the `nonce` was compared to
the stored one; the `login.post_auth` reactor gate fired; and the user was
JIT-provisioned and linked. For GitHub and Facebook everything except the ID
token verification happens — there is no ID token — and identity comes from the
userinfo call instead.

A federated user has **no roles**, so most pages will be empty. That is correct:
federation authenticates, it does not authorize. Assign roles from the Users
page.

---

## 12. Verify what AXIAM created

- **Users page** — a new user whose email is the provider account's, with
  `metadata` recording `provisioned_by`, `federation_config_id` and
  `external_subject`.
- **Second sign-in is a link, not a provision.** Sign out and back in with the
  same account: `provision_or_link_user` finds the existing link by
  `(tenant, config, subject)` and reuses the user. No duplicate.
- **Federation links:**

```bash
curl -fsS -b /tmp/axiam.cookies \
  "https://axiam-iam.duckdns.org/api/v1/federation-links/user/$USER_ID" \
  | python3 -m json.tool
```

  `DELETE /api/v1/federation-links/{id}` (permission `federation:delete`) revokes
  that provider account's ability to sign in as that AXIAM user.

- **Logs** — `docker logs axiam-server` shows `Built OIDC authorization URL`,
  then `OIDC callback: token exchange and verification successful`.

---

## 13. Optional: IoT devices and mTLS

**Client certificates cannot reach the backend through Caddy.** Caddy terminates
TLS, so a certificate a device presents is verified by Caddy and never seen by
rustls. AXIAM's device identity comes from the *rustls-verified* peer
certificate, and the `X-Client-Certificate` header fallback is **off by
default** — a certificate is public data, so a header carrying one proves
nothing about who sent it, and on an internet-reachable backend trusting it
would let anyone holding a copy of an enrolled certificate authenticate as that
device. Do not turn `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` on to work around
this.

The supported answer is a **second hostname that Caddy does not touch**:

1. Add `axiam-iam-api` on DuckDNS, pointing at the same IP.
2. Reissue the certificate with both names:
   `sudo certbot certonly ... -d axiam-iam.duckdns.org -d axiam-iam-api.duckdns.org`
3. Forward a second public port (say 8443) straight to the Pi's `127.0.0.1:8090`,
   or bind axiam-server's published port to the LAN address instead of loopback.
4. Set `AXIAM_TLS_CLIENT_AUTH=optional` in `~/axiam-up.sh` — `optional` so the
   one listener serves both Caddy (which presents no certificate) and devices
   (which do).
5. Flag the organization CA as an mTLS trust anchor in the admin UI. The server
   writes the client-CA bundle and reloads its trust anchors without a restart.

Browsers keep using `https://axiam-iam.duckdns.org/api` — same origin, so still
no CORS. The second name exists for devices and SDK clients, which are not
subject to the same-origin policy.

**One hazard to close.** On that direct route there is no proxy, so a client can
send its own `X-Forwarded-For`. With `TRUSTED_HOPS=0` and a single-entry header
the extractor would select the client's own value and it could mint a fresh
rate-limit bucket per request. Strip the header at your firewall or router for
that port, or do not publish the second hostname if you have no devices.

---

## 14. Optional: gRPC on the public internet

The gRPC listener is off the internet by default, and the default was not
timidity: `docker-compose.prod.yml` binds 50051 to `127.0.0.1`, and
`k8s/ingress.yml` records that its public route was removed under **SEC-003** —
filed when `UserService` and `TokenService` had no authentication at all.

That hole is closed. All five services are built with
`with_interceptor(AuthInterceptor)` (`crates/axiam-api-grpc/src/server.rs`), so a
call carrying no valid AXIAM access token is refused before it reaches a handler,
and each service derives tenant and subject from the **verified** claims rather
than from the request body. Publishing the surface is a defensible choice today.
It is still a choice, and its shape matters more than the fact of it.

### 14.1 What is on the wire, and what is not

Five services, every method **unary** — nothing here holds a connection open.
`Server::builder()` caps each call at a 4 MiB frame and 30 seconds, and each
connection at 256 in-flight calls.

| Service | Methods | Bucket, per source IP |
| --- | --- | --- |
| `axiam.v1.AuthorizationService` | `CheckAccess`, `BatchCheckAccess` | authz — 100/s |
| `axiam.v1.UserInfoService` | `GetUserInfo` | identity — 500/s |
| `axiam.v1.TokenService` | `ValidateToken`, `IntrospectToken` | identity — 500/s |
| `axiam.v1.UserService` | `GetUser`, `ValidateCredentials` | admin — 10/s |
| `axiam.v1.ReactorAdminService` | reactor CRUD, `ListReactorEvents` | authz — 100/s |

Those are the shipped defaults. Identity derives as 5x the authz ceiling; the
admin ceiling is an absolute 10/s that no profile raises (SEC-079), because
`ValidateCredentials` runs a real Argon2id verification and that ceiling is a CPU
guard on an online-guessing surface, not a throughput setting.

**Not** on the wire: server reflection and the gRPC health service. `server.rs`
registers exactly the five above and nothing else, so the listener cannot be
enumerated and a client needs `proto/axiam/v1/*.proto` or generated stubs. Keep
it that way — a public reflection endpoint is a free map of your API, for the
same reason `/health/jobs` is not routed (§2).

One asymmetry to weigh before publishing: `ReactorAdminService` is an
administrative surface sized like the hot path, because
`GrpcMethodFamily::from_path` classifies everything it does not recognise as
authz traffic (`middleware/rate_limit.rs`). Every one of its methods does check a
permission — `reactors:list`, `reactors:create` and so on, against the same
authorization engine REST uses, for the caller's own tenant — so the ceiling is
not the only control. But a ceiling is not a permission either, which is why
§14.3 publishes an allowlist rather than the whole `axiam.v1` package.

### 14.2 Through the edge, never a second port-forward

The obvious way to publish gRPC is to forward a public port straight at 50051 and
let the backend's own TLS terminate it. **Do not.** §13's closing hazard is the
reason, and on this surface it is worse.

`GrpcTrustedHopsKeyExtractor` reads `X-Forwarded-For` before it falls back to the
verified connection peer, exactly as the REST extractor does. With no proxy in
front, nothing appends the real peer to that header — so with `TRUSTED_HOPS=0` a
client that sends a single-entry `X-Forwarded-For` of its own is keyed on the
value **it chose**, and a value it varies per call is a fresh rate-limit bucket
per call. Every ceiling in the table above becomes decorative.

No setting closes that. For any `TRUSTED_HOPS = n`, a client that sends `n+1`
entries selects the leftmost one it wrote; a client that sends fewer falls back
to the peer address. The header is trustworthy only because a proxy *you* run
appends to the right of whatever arrived (§6.3), and a direct port-forward has no
such proxy.

So gRPC goes through Caddy, on 443, beside everything else. That costs nothing
you were keeping: Caddy already speaks HTTP/2 to the client, it re-encrypts to
the backend's own gRPC listener, and it appends the real peer to
`X-Forwarded-For` on this route exactly as it does on `/api`. `TRUSTED_HOPS`
stays `0` and stays correct for **both** protocols — which is fortunate, because
both sides read the one `AXIAM__RATE_LIMIT__TRUSTED_HOPS`
(`trusted_hops_from_env` on the gRPC side, `XForwardedForKeyExtractor` on the
REST side) and there is no way to give them different values.

Two things this does not buy. **gRPC-Web**: nothing here translates it and AXIAM
serves no grpc-web endpoint, so browsers keep using REST — that is what REST is
for. **mTLS on the gRPC path**: same reason as §13, the handshake ends at Caddy,
and the gRPC listener has no client-CA configuration at all (`ServerTlsConfig` is
built with an identity and nothing else). gRPC clients authenticate with a bearer
token, full stop.

### 14.3 The Caddy route

Add this to `/etc/caddy/Caddyfile`, **above** the `handle @api` block of §4.3 —
`handle` blocks are evaluated in source order:

```caddyfile
	# gRPC, published one service at a time. Anything under /axiam.v1.*
	# that is not listed here falls through to the SPA handler and gets
	# HTML back: a confusing refusal, but a safe one.
	@grpc path /axiam.v1.AuthorizationService/* /axiam.v1.UserInfoService/* /axiam.v1.TokenService/*
	handle @grpc {
		reverse_proxy https://127.0.0.1:50051 {
			transport http {
				# Same leaf, same real verification as the /api route.
				# The name is overridden because we dial loopback.
				tls_server_name axiam-iam.duckdns.org
				# gRPC is HTTP/2 end to end. Pin it: HTTP/1.1 carries no
				# trailers, and every RPC's status travels in a trailer.
				versions 2
			}
		}
	}
```

`sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy`
— validate first, always: a Caddyfile that fails to load takes the SPA and the
API down with it, not just the route you were adding.

`versions 2` is belt and braces. Caddy's HTTP transport offers `1.1 2` by
default and tonic's ALPN offers only `h2`, so the negotiation lands on HTTP/2
either way; pinning it means a future default cannot quietly downgrade the one
hop whose trailers carry every RPC's status. If your Caddy build rejects the
sub-directive, `caddy validate` says so before you reload — drop the line and
re-validate.

**Publish only what a remote client needs.** The three services above are the
read-side surface a service-mesh or SDK client actually calls. Add
`/axiam.v1.UserService/*` only if something remote needs `GetUser` or
`ValidateCredentials` — the latter is a password check, and publishing it puts an
online guessing surface on the internet, held by a 10/s per-IP ceiling and the
account lockout it accrues (both real, neither free). Add
`/axiam.v1.ReactorAdminService/*` only if you administer reactors remotely; §14.1
says why it is the one to think hardest about.

Nothing else in §4.3 needs to move. `/axiam.v1.*` cannot collide with `/api/*`,
`/oauth2/*` or `/.well-known/*`, and `encode zstd gzip` leaves these responses
alone — Caddy's default encode matcher covers text and JSON content types, not
`application/grpc`. The site-wide `request_header -X-Client-Certificate` and
`-X-Real-IP` apply here too, which is what you want.

### 14.4 Turning the listener's TLS on

The gRPC listener has its **own** TLS switch, and it is not part of the
`AXIAM__SERVER__TLS__*` family. `server.rs` reads two flat variables straight out
of the process environment and enables TLS when **both** are set. Add them to the
Pi override from §5.3:

```bash
cat > ~/axiam/docker/docker-compose.pi.yml <<'EOF'
services:
  axiam-server:
    environment:
      AXIAM__AUTH__JWT_ISSUER: "https://axiam-iam.duckdns.org"
      AXIAM__AUTH__OAUTH2_ISSUER_URL: "https://axiam-iam.duckdns.org"
      # gRPC TLS (§14). Both or neither: TLS is enabled only when both are
      # set, and the server PANICS at startup if either names a file it
      # cannot read. That is deliberate — a typo is a failed boot, never a
      # listener that quietly came up in cleartext.
      #
      # These are the same two files the deploy hook (§4.5) installs for the
      # REST listener. There is no second certificate and there must not be.
      AXIAM__GRPC_TLS_CERT_PATH: "/etc/axiam/server-tls/fullchain.pem"
      AXIAM__GRPC_TLS_KEY_PATH: "/etc/axiam/server-tls/privkey.pem"
      # A listener anyone can reach should not honour a token for up to 15
      # minutes after its session is gone. §14.6.
      AXIAM__GRPC__STRICT_REVOCATION: "true"
EOF
```

Note the underscores: `AXIAM__GRPC_TLS_CERT_PATH`, **not**
`AXIAM__GRPC__TLS__CERT_PATH`. This pair predates the nested config surface and
is read with `std::env::var`, so the `AXIAM__`-prefixed config layer never sees
it and a wrong name is not an error — it is silence, and a plaintext listener.
The log line is the only witness:

```bash
~/axiam-up.sh
docker logs axiam-server 2>&1 | grep -i 'grpc.*TLS'
# want: gRPC server TLS enabled (AXIAM__GRPC_TLS_CERT_PATH)
# not:  gRPC TLS is DISABLED — set AXIAM__GRPC_TLS_CERT_PATH + …
```

**Both listeners are TLS 1.3 only** (since beta12 / R-1). They were not always:
the gRPC leg used to be 1.3-*capable* but 1.2-negotiable, because tonic's
`ServerTlsConfig` exposed no protocol-version knob. It no longer terminates TLS
— the listener does the handshake itself over `tokio-rustls` and hands tonic an
already-encrypted stream — so the same `with_protocol_versions(&[&TLS13])` pin
the REST listener has always had now applies here too. Nothing to configure and
nothing to work around.

Pinning `protocols tls1.3` inside the `tls` directive of §4.3 is still worth
doing, for a different reason: that governs the **public** half of the
connection, which is Caddy's own TLS and has nothing to do with either backend
listener. It applies to the whole site, browsers included — every browser
released since late 2018 speaks TLS 1.3, so the practical cost is nil.

### 14.5 Renewal: nothing extra to do (since beta12)

**`SIGHUP` now covers both listeners.** Until beta12 it did not: `server.rs`
read both PEM files once at startup and handed them to tonic, with no reload
path and no poll anywhere in that crate, so the gRPC leg kept serving the old
leaf after certbot renewed at day 60 and started failing handshakes at day 90 —
while REST kept working, which made it present as a gRPC bug. This section
therefore carried a fourth hook step that restarted the container.

R-1 removed the need for it. The gRPC listener resolves its leaf through the
**same** `ReloadableCertResolver` the REST listener uses, because both are
pointed at the same two files (that is the topology this guide sets up — "there
is no second certificate and there must not be", §14.4). One `SIGHUP` reaches
both, as does the hourly poll. The deploy hook of §4.5 needs **no gRPC-specific
step**:

```bash
# 3. Tell the server. Both listeners re-read the pair on SIGHUP and install it
#    behind an ArcSwap that rustls consults per handshake — no restart, no
#    dropped request, on REST and on gRPC alike.
docker kill -s HUP axiam-server 2>/dev/null || true
```

If your hook still carries the `docker restart axiam-server` line from an
earlier edition of this guide, it is now redundant rather than wrong: delete it
and save yourself ~15 seconds of downtime every 60 days. If you would rather not
touch a hook that works, leaving it costs only that.

Rehearse whatever you end up with — `sudo /etc/letsencrypt/renewal-hooks/deploy/axiam.sh`,
then re-run the §14.7 call. A hook whose steps have never run is the same trap
the note in §4.5 warns about.

### 14.6 The two settings this changes

**`AXIAM__GRPC__STRICT_REVOCATION=true`.** By default the gRPC data plane
validates a token's signature and expiry and stops there — the right trade for a
mesh you own, and a documented one, not an oversight. It means a session revoked
by logout, password change or admin sign-out keeps passing gRPC authorization
until the access token expires: up to 15 minutes. REST re-checks on every
request. On a listener the internet can reach, take REST's semantics. The cost on
a single-replica Pi is one datastore read per call;
`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5` turns most of them into a
process-local cache hit, and since every session-deleting path invalidates that
cache in the same call, a logout on a single replica still takes effect
immediately. (Across replicas it would not — that is the cache's documented
window, and this Pi has one replica.)

**Per source IP is not per client.** Behind a NAT — an office, a mobile carrier,
a cloud egress address — every client sharing an address shares the bucket. The
gRPC limiter has no client identity to key on: both rate-limit layers are
`Server::builder()`-wide and run *before* tonic resolves the caller's claims, the
same structural reason REST keeps `/auth/login` per-IP. If you publish gRPC to a
fleet behind one address, size it on purpose —
`AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, or the `gateway` / `mesh` presets of
`AXIAM__RATE_LIMIT__PROFILE`, which move the REST and gRPC families together.
`docs/deployment/rate-limit-sizing.md` has the numbers.

### 14.7 Prove it

`grpcurl` needs the `.proto` files — there is no reflection to ask. A gRPC caller
is a service, so get a token the way a service does, with the client-credentials
grant:

```bash
# From anywhere, with the repo checked out at the tag you deployed.
TOKEN=$(curl -fsS "https://axiam-iam.duckdns.org/oauth2/token?tenant_id=$TENANT_ID" \
  -d grant_type=client_credentials \
  -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

grpcurl -import-path proto -proto axiam/v1/authorization.proto \
  -H "authorization: Bearer $TOKEN" \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"action\":\"read\",\"resource_id\":\"$RESOURCE_ID\"}" \
  axiam-iam.duckdns.org:443 axiam.v1.AuthorizationService/CheckAccess
```

`subject_id` is omitted on purpose: over gRPC the field can only ever restate the
caller, so an empty value means "the subject the verified token carries", and a
non-empty one that disagrees with the token is refused (SEC-003).

Four failures worth recognising on sight:

| What you see | What it is |
| --- | --- |
| `Unauthenticated` / missing-or-invalid authorization header | No bearer token, the wrong prefix (it must be `Bearer `), or an expired one. |
| A protocol error mentioning `text/html` | The path is not in the §14.3 allowlist — a typo in the service name, or Caddy was never reloaded. You reached the SPA. |
| `ResourceExhausted` | The bucket for that method's family (§14.1). Check *which* family before raising anything. |
| `Unavailable`, or a bare 502 from Caddy | The client's own leg is fine; Caddy could not dial the backend. Either the listener came up in plaintext (grep the `DISABLED` line, §14.4) or, on a deployment predating beta12, its leaf is stale (§14.5). `journalctl -u caddy -n 50` names which. |

Then re-run the §6.3 per-IP check. Adding a route is exactly the kind of
topology change that section says to re-verify after, and gRPC now shares the
same `TRUSTED_HOPS` derivation.

---

## 15. Upgrading a Pi that ran the previous version of this guide

In this order:

1. **Snapshot or export your Vault first.** The storage backend changed from
   `file` to Raft and uses a **new volume**, so your old `vault-data` volume is
   untouched but is not what the new stack reads. The simplest honest path on a
   home lab is to re-seed a fresh Vault (§7) and accept that OPAQUE-registered
   users must reset their passwords — which is why §7.5 exists. To avoid that,
   read `docs/deployment/vault.md` §5 and migrate before upgrading.
2. `git pull`, then redo §4 (certbot now owns ACME; Caddy's own certificate
   store becomes unused and can be left alone).
3. Replace `/etc/caddy/Caddyfile` with §4.3 — the path split is the change.
4. Add `AXIAM_TLS_ENABLED=true` and the `AXIAM_BACKEND_*` variables to
   `~/axiam-up.sh` (§5.3).
5. **Re-derive `TRUSTED_HOPS`** (§6.3). If you kept the old Caddy → nginx →
   backend routing, it must be `1`, not `0`; with the new routing it is `0`.
6. Re-register the redirect URI at every provider:
   `https://axiam-iam.duckdns.org/auth/sso/callback`, replacing `…/login`.
7. If you used proxy-terminated mTLS, read §13 — the header path is now off by
   default and will refuse.
8. Nothing about gRPC changes on an upgrade: it stays loopback-bound unless you
   go and publish it. §14 is new, opt-in, and independent of everything above.

---

## 16. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Provider: `redirect_uri_mismatch` | The registered URI is not byte-identical. | `https://axiam-iam.duckdns.org/auth/sso/callback` — trailing slash, scheme and path case all count. Apple uses the `/oidc/callback/form` URL instead (§10.4). |
| Google `403 access_denied` in Testing | Account is not a listed test user. | Add it under OAuth consent screen → Test users. |
| No "Sign in with" buttons appear | You have not submitted the workspace step, or the org slug does not resolve, or no config is enabled/inherited. | Type the org slug and submit. `GET /api/v1/auth/federation/providers?org_slug=homelab` returns `200 []` for an unknown org by design. |
| Saving a Microsoft config fails on the issuer | `common` authority with an empty `allowed_issuer_tenants`. | List your Entra tenant GUIDs, or use a tenant-specific authority (§10.5). |
| Apple `invalid_client` | Team ID, Key ID or `.p8` wrong. Never a stale secret — AXIAM mints a 5-minute one per exchange. | Re-check the three values in the config. |
| `federation encryption key not configured` | `federation_encryption_key` missing from Vault, or the server started before seeding. | Re-seed (§7.3), then `docker restart axiam-server`. |
| Callback: `state not found or expired` | >10 min elapsed, or the state was already consumed (single-use). | Start again from the login page. |
| Callback: ID-token validation error | Clock skew, or a client-ID mismatch. | `timedatectl` — NTP must be on. |
| Backend `curl` fails TLS on :8090 | The container cannot read the key. | `docker logs axiam-server \| grep 'TLS key'`; re-run the deploy hook (§4.5) — ownership is usually it. Never work around this with `-k` or by disabling verification. |
| Certificate expired on a running server | The deploy hook never fired. | `sudo certbot renew --dry-run`; check `/etc/letsencrypt/renewal-hooks/deploy/axiam.sh` is executable and mode 700. The hourly poll should have caught it — check `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS` is not `0`. |
| Everyone rate-limited at once | `TRUSTED_HOPS` too high for your hop count. | §6.3. One proxy means `0`. |
| Whole site 502 after a reboot | Vault came back sealed. | Configure auto-unseal (§7.1). Until then, unseal by hand with three shares. |
| Login answers `500` — `Cryptography error: AES-GCM decrypt: aead::Error` — after a `just prod-up` on a stack that worked | A key in Vault no longer matches the one the datastore was sealed with. The commonest cause was the seeder reading a Vault that had been unsealed but had not yet taken leadership, treating the refused read as an empty Vault, and minting a full set of new keys over the live ones. The seeder now refuses instead, and `prod-up` waits for an active node. | The old key is almost certainly still in Vault — KV v2 keeps ten versions. `docs/deployment/vault.md` §8.1 has the `vault kv metadata get` / `vault kv patch` recovery, which needs no password resets. |
| Caddy never gets a certificate | Port 80 unreachable, or DuckDNS points at the wrong IP. | Test from outside the LAN; otherwise DNS-01 (§4.4). |
| `/health` returns the SPA HTML | Working as designed (§2). | Probe on the loopback (§8). |
| Passkey enrolment fails with 401 | `AXIAM_WEBAUTHN_RP_ORIGIN` does not match the address bar. | Set it to `https://axiam-iam.duckdns.org` and restart. |
| `docker compose` refuses to start | Raw `docker compose` without the environment `prod-up` builds. | Use `~/axiam-up.sh`, or `just prod-down` / `just prod-clean`. |
| gRPC call returns HTML, or a protocol error naming `text/html` | The path is not in the §14.3 allowlist, or Caddy was not reloaded. The SPA handler answered. | Check the service name character for character, `caddy validate`, reload. |
| gRPC fails TLS while REST is fine, ~60 days after the last renewal | A server predating beta12: the gRPC listener read its certificate once at startup and had no reload path. Since R-1 both listeners share one reloadable resolver and one `SIGHUP` renews both. | Upgrade, or `docker restart axiam-server` once by hand; §14.5. |
| `docker logs axiam-server` says `gRPC TLS is DISABLED` although the variables are set | The name. It is `AXIAM__GRPC_TLS_CERT_PATH`, not `AXIAM__GRPC__TLS__CERT_PATH`, and the wrong name is silently ignored. | §14.4. Both variables, or neither. |
| One gRPC client throttles every other client | Per-IP buckets and a shared NAT or egress address — or a topology where nothing appends `X-Forwarded-For`. | §14.6 for sizing; §14.2 if you forwarded a port at 50051 instead of routing through Caddy. |

---

## 17. Before you call this production

- **Auto-unseal (§7.1).** If you skipped it, you do not have a production
  deployment — you have one that needs a human awake after every power cut. This
  is the single most important item on this list.
- **The root token is revoked** and the server holds the read-only `axiam`
  token. `just vault-status` says `ok`, not `OVER-SCOPED` (§7.4).
- **Unseal shares are off the Pi**, in three places that do not fail together,
  and not with the root token.
- **Raft snapshots and `docker/.secrets/` are backed up off the device** (§7.5).
- **Only 80 and 443 are forwarded.** Everything else is loopback-bound; keep it
  that way — publishing gRPC (§14) does not change this, and if it did for you,
  you published it the wrong way (§14.2).
- **`certbot renew --dry-run` passes**, and you have seen
  `TLS leaf certificate reloaded` in the logs at least once.
- **If gRPC is public (§14):** the log says `gRPC server TLS enabled`, the
  deploy hook has its fourth step and has been run once by hand,
  `AXIAM__GRPC__STRICT_REVOCATION` is `true`, and the Caddy allowlist names only
  the services you meant to publish — not `axiam.v1.*`.
- **Client secrets rotated** if any was ever pasted into a shell with history.
- **You are running a released tag**, not `main`: `git describe --tags` names
  the release whose images you pulled (§1).
- **`k8s/`, not `docker-compose.prod.yml`, is the supported production path** —
  the compose file says so in its own header.
- Consider putting the admin UI behind a VPN or Tailscale and exposing only what
  actually needs to be public. The API surface a login page needs is small.
