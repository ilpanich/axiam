# 802.1X with an AXIAM-issued Device certificate

**Milestone:** `1.0.1`
**Last verified:** 2026-10-13, against FreeRADIUS 3.2.8 and `eapol_test` from
`wpa_supplicant` 2.10 (see [What the end-to-end test proves](#what-the-end-to-end-test-proves))

A recipe for admitting devices to a switch port, an access point or a VPN
gateway with a certificate that AXIAM issued, where FreeRADIUS terminates RADIUS
and EAP-TLS and AXIAM is the certificate authority. **AXIAM does not speak
RADIUS.** The G-11 spike
([decision record](../../claude_dev/radius-eap-tls-spike-2026-10-06.md))
declined a native front end and recorded this route — option B — for the
adopter who needs it. This page is that route's guide; the files it describes
are in [`docker/radius/`](../../docker/radius/README.md) and
[`docker/docker-compose.radius.yml`](../../docker/docker-compose.radius.yml), and
`crates/axiam-server/tests/radius_e2e.rs` runs it against a real FreeRADIUS on
every change to them.

See also: [PKI guide](README.md) (issuing, binding, revoking and the
[revocation lists](README.md#certificate-revocation-lists) this recipe consumes),
[Admin Guide](../admin/README.md).

## What this is, and is not

| | |
|---|---|
| **Is** | EAP-TLS only, TLS 1.3 only, for devices that hold a certificate the tenant's signing CA issued. A device is admitted only if its certificate chains to that CA, is not on the CA's revocation list, **and** is in a placement table you keep. |
| **Is not** | A password service. There is no PAP, CHAP, MS-CHAP or EAP-MD5 path in this configuration, and AXIAM's password store (Argon2id) could not serve the last three. |
| **Is not** | A real-time check. FreeRADIUS does not call AXIAM when a device authenticates. A revocation reaches it as a certificate revocation list, on the schedule you set — [the lag is stated below](#the-revocation-lag). |
| **Is not** | Accounting, dynamic authorization (CoA, Disconnect-Request) or a RADIUS proxy. |
| **Is not** | Shipped FreeRADIUS. The compose file *references* the upstream image by digest; this repository contains configuration files and nothing of FreeRADIUS (GPLv2). |

## The shape

```
 device ──EAP-TLS── NAS (switch, AP, VPN) ──RADIUS (UDP, or RadSec)── FreeRADIUS
   │                                                                      │
   │ leaf, issued by AXIAM                       trusts: the TENANT signing CA
   │                                             reads:  its CRL, fetched from AXIAM
   ▼                                             keeps:  the placement table
 organization CA ──signs──▶ tenant signing CA ──signs──▶ Device certificate
                                   │                          │
                                   └── GET /pki/v1/{org}/ca/{ca}/crl ◀── your fetch job
```

Three things carry the security of this recipe, and each is a line in the
configuration rather than something AXIAM enforces for you:

1. **FreeRADIUS trusts the tenant signing CA, and only that.** Not the
   organization CA. A tenant's devices chain to that tenant's signing CA; the
   organization's other tenants, and every other organization, do not.
2. **Revocation is a file you keep fresh.** AXIAM publishes it; fetching it is
   your job.
3. **A valid certificate is not enough.** The device must also be in the
   placement table, which is where its VLAN comes from.

## 1. Issue and bind

All of this is the [PKI guide](README.md); the commands are repeated here in
the order this recipe needs them. CA operations need an
[organization-level principal](README.md#which-ca-a-caller-may-issue-under);
the leaf calls are a tenant administrator's.

```bash
# An organization CA (once), and a signing CA beneath it for the tenant whose
# devices this FreeRADIUS serves. 364 days: a signing CA may not outlive its parent.
curl -X POST https://axiam.example.com/api/v1/organizations/$ORG/ca-certificates \
  -H "Authorization: Bearer $ORG_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"subject":"Plant A root","key_algorithm":"Ed25519","validity_days":365}'

curl -X POST https://axiam.example.com/api/v1/organizations/$ORG/tenants/$TENANT/signing-cas \
  -H "Authorization: Bearer $ORG_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"parent_ca_id":"'$ROOT_CA'","subject":"Plant A line 1 devices","key_algorithm":"Ed25519","validity_days":364}'

# A Device certificate. The private key is in this response and nowhere else.
curl -X POST https://axiam.example.com/api/v1/certificates \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"issuer_ca_id":"'$SIGNING_CA'","subject":"press-07","cert_type":"Device",
       "key_algorithm":"Ed25519","validity_days":30}'

# Bind it to the service account that is the device in AXIAM.
curl -X POST https://axiam.example.com/api/v1/service-accounts \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"press-07"}'
curl -X POST https://axiam.example.com/api/v1/service-accounts/$SA/bind-certificate \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"certificate_id":"'$CERT'"}'
```

What each choice does for this recipe:

- **`cert_type: Device`** gives the leaf `clientAuth` and `digitalSignature`
  ([what every leaf may be used for](README.md#what-every-leaf-may-be-used-for)),
  which is what an EAP-TLS peer certificate needs. Its subject is the common
  name; choose one that is unique in the tenant (`press-07`). The placement
  table does **not** key on it ([below](#the-key-is-the-serial)).
- **A short `validity_days`** is the only bound that does not depend on a list
  being fresh. A device that is replaced every month cannot be admitted for
  longer than a month by a missed revocation.
- **Ed25519 or RSA-4096** both authenticate: the end-to-end test uses Ed25519
  for the signing CA, the leaves and the lists. AXIAM returns an Ed25519 private
  key as PKCS#8 **version 1** (RFC 8410: the seed alone), which is the form
  OpenSSL 3.0 — the library behind `wpa_supplicant` on Ubuntu 24.04, and so
  behind `eapol_test` — reads, so the returned `private_key_pem` is written to
  the key file as it is, with no re-encoding ([why](README.md#the-form-of-a-returned-private-key)).
  A key issued by AXIAM before 1.1.0 is in the longer RFC 5958 form, which that
  library refuses (`DECODER routines::unsupported`); re-issue the certificate
  rather than converting the key. Check your supplicant's TLS library before
  choosing; some older ones do not support Ed25519 certificates at all.
- **Binding** is how AXIAM knows which service account a device is. FreeRADIUS
  does not read it. It matters for two things: it is the list you build the
  placement table from (below), and revoking the certificate in AXIAM ends the
  device's AXIAM-side sign-in at once, which a RADIUS check cannot do.

## 2. Export the CA

```bash
curl -s https://axiam.example.com/api/v1/organizations/$ORG/ca-certificates/$SIGNING_CA \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" | jq -r .public_cert_pem > ca.pem
```

`ca.pem` is the **tenant signing CA's** certificate. Put that, and only that, in
FreeRADIUS's `ca_file`.

FreeRADIUS (through OpenSSL's partial-chain flag) accepts a chain that ends at
a CA it trusts directly, so the organization CA above it is not needed. Leaving
it out is the point: a certificate issued by another tenant's signing CA — even
one of the same organization, under the same root — leads to a CA this server
does not hold, and is refused with `unable to get local issuer certificate`, or
with `self-signed certificate in certificate chain` when the device also sends
the root. The end-to-end test issues both tenants' signing CAs under one
organization CA and checks exactly that, with the other tenant's device
presenting its leaf, its leaf and signing CA, and its whole chain up to the
shared root; the tenant's own device presenting its whole chain is admitted.

**One tenant per trust anchor.** The boundary is that `ca_file` holds one tenant's
signing CA. A FreeRADIUS server that serves two tenants needs two trust
configurations (two servers, or two virtual servers on separate listeners), not
two CAs in one file: with both in `ca_file`, a device of either tenant is admitted
through any NAS the server answers.

The cost is stated plainly: with the signing CA as the trust anchor nothing above
it is looked at, so **a revoked signing CA is not noticed by FreeRADIUS**. The
organization CA's list is what names it, and this configuration does not load
that list (`check_all_crl = no`). When you revoke a signing CA, remove or
replace `ca.pem` and restart FreeRADIUS; the devices under it should be
re-issued under a new one in any case ([Revoke a
certificate](README.md#revoke-a-certificate)).

## 3. The FreeRADIUS configuration

The recipe is five files, mounted over the image's own
([`docker/radius/raddb/`](../../docker/radius/raddb/)). They are short on
purpose; what follows is every setting that carries a security decision.

### `mods-available/eap` — TLS 1.3, EAP-TLS, the tenant CA, the lists

```
eap {
	default_eap_type = tls
	ignore_unknown_eap_types = no

	tls-config tls-common {
		private_key_file = /etc/freeradius/axiam/server.key
		certificate_file = /etc/freeradius/axiam/server.pem
		ca_file          = /etc/freeradius/axiam/ca.pem
		ca_path          = /etc/freeradius/axiam/capath
		ca_path_reload_interval = 300
		check_crl     = yes
		check_all_crl = no
		tls_min_version = "1.3"
		tls_max_version = "1.3"
		cache { enable = no }
	}
	tls {
		tls = tls-common
		virtual_server = check-eap-tls
	}
}
```

- **`tls_min_version = "1.3"` and `tls_max_version = "1.3"`: TLS 1.3 only.**
  FreeRADIUS's own configuration warns that many supplicants do not handle
  TLS 1.3 for EAP properly. The test passes with `wpa_supplicant` 2.10 on
  OpenSSL 3 (`tls_disable_tlsv1_3=0`); it refuses a supplicant that offers only
  TLS 1.2. **Try your supplicants before rolling out.** If a fleet cannot do 1.3,
  lowering `tls_min_version` to `"1.2"` is a deliberate downgrade for that fleet,
  not a setting to leave at its default.
- **Only the `tls` method is defined.** There is no `md5`, `peap`, `ttls` or
  `mschapv2` block, and `ignore_unknown_eap_types = no`, so a supplicant that
  answers with another method gets an EAP-Failure instead of a negotiation. The
  test sends EAP-MD5 and checks that.
- **`ca_file` is the tenant signing CA** (section 2). The server certificate in
  `certificate_file` is *not* issued by it and has nothing to do with it: it is
  what the supplicant validates the server by, from your own PKI or any CA the
  supplicants trust.
- **`check_crl = yes`** makes OpenSSL require a list for the device's issuer and
  refuse a certificate on it. A missing list is a rejection of every device, not
  an admission of every device — the failure mode you want, and the reason to
  [monitor the fetch](#the-revocation-lag).
- **`cache { enable = no }`**: no TLS session cache. A resumed session skips the
  certificate check, so a revoked device could be admitted again from a ticket.
- **`ca_path_reload_interval = 300`** is how FreeRADIUS re-reads the lists
  ([below](#4-keep-the-revocation-list-fresh)). FreeRADIUS raises any smaller
  value to 300.

### `clients.conf` — who may send requests, and what they must send

```
client nas-line-1 {
	ipaddr = 192.0.2.10
	secret = $ENV{RADIUS_SHARED_SECRET}
	require_message_authenticator = yes
}
```

- **A request from an address that is not a `client` here is dropped without an
  answer.** List each NAS by its own address, not a subnet, outside a test.
- **`require_message_authenticator = yes`** on every client. A request without a
  verifying `Message-Authenticator` is discarded, and every response carries
  one. This is the mitigation for the "Blast-RADIUS" forgery (CVE-2024-3596,
  RFC 9765), which turns an Access-Reject into an Access-Accept by an MD5
  collision, on any exchange where that attribute is absent or unchecked. Set it
  per client, **and** set it globally: `security { require_message_authenticator = yes }` in
  `radiusd.conf` (the shipped default is `auto`, which switches itself off for a
  client whose first packet lacks the attribute). With it set to `yes`,
  `limit_proxy_state` is ignored, which is what you want behind a wireless
  controller that acts as a proxy and adds `Proxy-State`.
- **The shared secret** is per NAS, at least 128 bits from a CSPRNG
  (`openssl rand -base64 24`), and not in a file you commit — FreeRADIUS reads
  `$ENV{...}`. The secret keys the MD5 constructs described under
  [RadSec](#radsec-where-the-nas-allows), which is why it matters.

### `sites-available/default` — nothing but EAP

The only virtual server that answers the network accepts an `Access-Request` that
carries an `EAP-Message` and rejects every other kind (PAP, CHAP, a request with
no credential). This server holds no passwords, so there is nothing a password
request could be checked against.

### `sites-enabled/check-eap-tls` and the placement table — a valid certificate is not enough

```
server check-eap-tls {
	authorize {
		update control { Tmp-String-0 := &TLS-Client-Cert-Serial }
		axiam_placement            # the table below, keyed on the serial
		if (!ok) { reject }        # fail closed: no entry, or a module failure
		update control { Auth-Type := Accept }
	}
}
```

The table is a `files` module over a plain text file, one entry per placed
certificate, named by the certificate's serial as FreeRADIUS spells
`TLS-Client-Cert-Serial` (lowercase hex):

```
# certificate 6f1c2a90-3d4e-4b7a-9c1d-2e5f8a7b6c01
1b5e0c9a47d2f3086e4a1c7b9d0e2f5a6c8b3d41
	Tunnel-Type = VLAN,
	Tunnel-Medium-Type = IEEE-802,
	Tunnel-Private-Group-Id = "20",
	Session-Timeout = 3600,
	Termination-Action = RADIUS-Request
```

- **An unplaced device is rejected**, not dropped onto the NAS's default VLAN.
  The test issues a valid, unrevoked, unbound certificate from the trusted CA and
  checks that it is refused.
- **Build the table from AXIAM's own list of bound devices**: the tenant's
  active `Device` certificates whose `bound_service_account_id` is set
  (`GET /api/v1/certificates`), each keyed on its serial
  ([the generator below](#generate-the-table)). The test generates it exactly
  that way. A certificate that is revoked, expired or unbound then has no entry
  the next time you regenerate it. (The `files` module re-reads its file on
  `HUP`; the EAP module's lists need the interval in section 4.)
- **The VLAN is the three attributes RFC 3580 §3.31 prescribes**: `Tunnel-Type =
  VLAN`, `Tunnel-Medium-Type = IEEE-802`, `Tunnel-Private-Group-Id` a decimal
  string between `1` and `4094` with tag `0`. Use these and no other attributes
  in a placement: the reply-profile design note
  ([`radius-reply-profile-design.md`](../../claude_dev/radius-reply-profile-design.md))
  keeps the set closed so that a hand-written table here is already an instance
  of the model a later AXIAM-side profile would serve. **Do not put the
  `Tunnel-Password` or any `MS-MPPE-*` attribute in it**; FreeRADIUS adds the
  EAP-TLS keys itself.
- **`Session-Timeout` with `Termination-Action = RADIUS-Request`** makes the NAS
  re-authenticate the device when the session ends, instead of disconnecting it.
  It is the bound on how long a revoked or de-listed device keeps a port it
  already has ([below](#the-revocation-lag)). The value is yours; an hour is a
  starting point, not a recommendation.

#### The key is the serial

The table is keyed on the certificate's **serial**, not its common name, and the
shipped `check-eap-tls` sets the key from `TLS-Client-Cert-Serial`. Three reasons,
the first of which is the one that matters:

- **A subject is chosen by whoever requests the certificate, and the `files`
  module reads some names as something else.** An entry named `DEFAULT` matches
  **every** key, and a certificate whose name is missing is looked up as `NONE`.
  AXIAM accepts `DEFAULT` as a subject, and a subject with spaces or a newline.
  A table keyed on the subject therefore lets one bound certificate named
  `DEFAULT` place every certificate the tenant signing CA ever issued — bound or
  not, listed or not — and, if that entry comes first, move every device onto
  its VLAN; a subject with a newline breaks the file or writes an entry of its
  own. A serial is hex: it cannot spell `DEFAULT` or `NONE`, and holds no space.
- **AXIAM assigns the serial; the requester does not choose it.** AXIAM draws
  it from 20 random octets for every certificate it signs, so an entry places
  the one certificate AXIAM listed as bound, and no other (a second certificate
  over the same key, from a CSR signed again, carries a serial of its own).
  Keyed on a name, whoever can obtain a certificate from the tenant signing CA
  with `press-07` as its subject gets `press-07`'s VLAN.
  *Correction (2026-10-14, #653):* up to 1.0.1 the serial was derived from the
  public key, so a second certificate over the same key carried the same serial
  and an entry placed both. Certificates issued before 1.1.0 keep that serial; a
  pair that already shares one is still placed together, and both belong to the
  holder of one key.
- **This server trusts one issuing CA** (section 2), so the serial needs no
  issuer beside it.

The cost: the entry changes when the device is re-issued with a new key, so
regenerate the table on every re-issue — which regenerating it from AXIAM's list
on a schedule does.

**If you must key on the common name** (a table you write by hand, say), set
`Tmp-String-0` from `TLS-Client-Cert-Common-Name` and make whatever writes the
table refuse every name outside `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and
`DEFAULT` and `NONE` in any letter case; on a name that fails, write nothing,
keep the table you have and alert. Whoever can obtain a certificate with a
listed name then gets that name's VLAN; that is the authority the tenant signing
CA represents.

#### Generate the table

```sh
#!/bin/sh
# Run after every issue, bind, unbind, revoke or re-issue, or on a timer.
set -eu
DIR=/etc/freeradius/axiam
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

curl -fsS --max-time 20 -o "$tmp/list.json" \
  -H "Authorization: Bearer $TENANT_ADMIN_TOKEN" \
  "https://axiam.example.com/api/v1/certificates?offset=0&limit=200"
# One page; page on, or refuse, when there are more.
[ "$(jq '.total == (.items | length)' "$tmp/list.json")" = true ]

jq -r '.items[] | select(.cert_type == "Device" and .status == "Active"
                         and .bound_service_account_id != null) | .id' \
  "$tmp/list.json" > "$tmp/ids"
while read -r id; do
  case "$id" in *[!0-9a-f-]*|'') echo "unexpected id: $id" >&2; exit 1 ;; esac
  jq -r --arg id "$id" '.items[] | select(.id == $id) | .public_cert_pem' \
    "$tmp/list.json" > "$tmp/cert.pem"
  serial=$(openssl x509 -in "$tmp/cert.pem" -noout -serial | sed 's/^serial=//' \
    | tr 'A-F' 'a-f')
  # A serial is lowercase hex and nothing else; anything else stops the run.
  case "$serial" in *[!0-9a-f]*|'') echo "certificate $id: bad serial" >&2; exit 1 ;; esac
  printf '# certificate %s\n%s\n' "$id" "$serial"
  printf '\tTunnel-Type = VLAN,\n\tTunnel-Medium-Type = IEEE-802,\n'
  printf '\tTunnel-Private-Group-Id = "20",\n\tSession-Timeout = 3600,\n'
  printf '\tTermination-Action = RADIUS-Request\n\n'
done < "$tmp/ids" > "$tmp/placement"

install -m 0644 "$tmp/placement" "$DIR/.placement"
mv "$DIR/.placement" "$DIR/placement"      # atomic: never a half-written table
pkill -HUP -x freeradius                     # the files module re-reads on HUP
```

The comment line names the certificate by AXIAM's id, never by its subject: a
subject may hold a newline, which would end the comment. Every device here goes
on one VLAN; if yours differ, map the certificate id (or the service account it
is bound to) to a VLAN in your own inventory, not the subject.

## 4. Keep the revocation list fresh

AXIAM publishes each issuing CA's list at
`GET /pki/v1/{org_id}/ca/{ca_id}/crl` — unauthenticated, signed by the CA,
`application/pkix-crl`, `nextUpdate` a day after `thisUpdate` by default
(`AXIAM__PKI__CRL_NEXT_UPDATE_SECS`, 300 to 604800 seconds). The URL is in every
certificate AXIAM signs, as its CRL distribution point. Details:
[Certificate revocation lists](README.md#certificate-revocation-lists).

FreeRADIUS reads lists from files. Fetch the tenant signing CA's list on a
schedule, convert it, check that the CA you trust signed it, and move it into
`ca_path` under the name OpenSSL looks it up by (`<issuer-name-hash>.r0`):

```sh
#!/bin/sh
# Run from cron or a systemd timer every 5 minutes.
set -eu
URL="https://axiam.example.com/pki/v1/$ORG/ca/$SIGNING_CA/crl"
DIR=/etc/freeradius/axiam/capath
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

curl -fsS --max-time 20 -o "$tmp/crl.der" "$URL"
openssl crl -inform DER -in "$tmp/crl.der" -outform PEM -out "$tmp/crl.pem"
# Never install a list the trusted CA did not sign.
openssl crl -in "$tmp/crl.pem" -CAfile /etc/freeradius/axiam/ca.pem -noout -verify
hash=$(openssl crl -in "$tmp/crl.pem" -noout -hash)
install -m 0644 "$tmp/crl.pem" "$DIR/.incoming"
mv "$DIR/.incoming" "$DIR/$hash.r0"          # atomic: never a half-written list
```

Use HTTPS. The signature check stops a list the CA did not sign; it does not
stop a replay of an older, validly signed one, so a script that holds the CRL number
should also refuse a list whose number is lower than the one on disk.

The cron interval does not need to be less than the list's refresh epoch: AXIAM
re-signs at most every half `nextUpdate` interval and answers a repeat request
with `304` (send `If-None-Match`), and the route's limiter is 60 requests a minute
per address.

### The revocation lag

A revoked device keeps being admitted until each of these has happened, in
order:

1. **AXIAM publishes it.** At once: the next response from the CRL route names the
   serial. The test checks this.
2. **Your job fetches the list.** At most the fetch interval.
3. **FreeRADIUS reads it.** OpenSSL does not re-read `ca_path` by itself. With
   `ca_path_reload_interval`, FreeRADIUS replaces its certificate store at the
   first *new* EAP conversation after the interval has elapsed, and the new store
   reads the list afresh. **The smallest interval FreeRADIUS accepts is 300
   seconds**, so this step is up to five minutes, plus whatever time passes
   before the next device authenticates. A restart does it at once.
4. **The device's current session ends.** A device that is already connected
   stays connected until `Session-Timeout`. Neither AXIAM nor this recipe can end
   a session: that needs dynamic authorization (RFC 5176), which is not part
   of it.

So a revoked device can keep its port for as long as **the fetch interval, plus
300 seconds, plus the `Session-Timeout`** — with the figures above, roughly an
hour and ten minutes in the worst case, and a few minutes for a device that is not
connected. The end-to-end test shows the middle of that: it revokes a device,
shows AXIAM serving the new list, shows FreeRADIUS **still admitting the device**
because it holds the old one, and then times the refusal after the list is in
`ca_path`.

If your answer to that is "too long", the levers are the three numbers (a
`Session-Timeout` of ten minutes and a two-minute fetch cost you more
authentications, not more risk), a shorter `validity_days` on devices, and — if it
is not enough — the real-time check described [at the end](#what-this-does-not-do-and-what-would).

Two ways this goes wrong:

- **The fetch stops.** Once a list is past its `nextUpdate`, OpenSSL treats it as
  an error and FreeRADIUS refuses **every** device of the tenant, because
  `allow_expired_crl` is left at its default, `no`. That is fail-closed, and a
  full outage a day later. Alert when the file in `capath` is older than half
  the list's lifetime.
- **FreeRADIUS is not restarted after you replace `ca.pem`.** The file is read
  at start-up, and the lists are the only thing the interval re-reads.

## RadSec, where the NAS allows

RADIUS over UDP carries its secrets and the EAP-TLS key (`MS-MPPE-Send-Key` and
`Recv-Key` hold the Wi-Fi session key) obfuscated with MD5 and the shared secret.
Anyone who captures the traffic and learns or guesses the secret recovers the
key. Where the NAS supports RADIUS over TLS (RadSec, RFC 6614), use it:

```
listen {
	ipaddr = *
	port = 2083
	type = auth
	proto = tcp
	virtual_server = default
	clients = radsec-nas
	tls {
		private_key_file = /etc/freeradius/axiam/radsec/server.key
		certificate_file = /etc/freeradius/axiam/radsec/server.pem
		ca_file          = /etc/freeradius/axiam/radsec/nas-ca.pem
		tls_min_version  = "1.3"
		require_client_cert = yes
	}
}
clients radsec-nas {
	client nas-line-1 {
		ipaddr = 192.0.2.10
		proto = tls
		secret = radsec
	}
}
```

This is the shape of the image's own `sites-available/tls`, with TLS 1.3 asked
for. Three cautions:

- **Not exercised by the end-to-end test.** `eapol_test` speaks UDP only; the
  block above is a starting point to adapt, not a tested configuration.
- **`nas-ca.pem` is not the device CA.** It is the CA that issues your **NAS**
  certificates. If it were the tenant signing CA, every device certificate would
  be accepted as a NAS.
- **`secret = radsec` is not a secret.** RFC 6614 fixes it, and the MD5 constructs
  stay in the packets, keyed with a public string. TLS is the only protection
  there. RADIUS/1.1 (RFC 9765), which removes them, is not part of this recipe.

## What the end-to-end test proves

`crates/axiam-server/tests/radius_e2e.rs`, run by
[`.github/workflows/radius-e2e.yml`](../../.github/workflows/radius-e2e.yml) and
locally as [`docker/radius/README.md`](../../docker/radius/README.md) describes.
It drives AXIAM's own routes, writes the CA, the list and the placement table
they produce into the shipped FreeRADIUS configuration, and authenticates with
`eapol_test`:

| Case | What it asserts |
|---|---|
| **issue** | an organization CA, two tenants' signing CAs beneath it and a `Device` certificate are issued; the leaf carries `clientAuth` and its issuer's CRL distribution point; the CA is exported |
| **bind** | the certificate is bound to a service account and listed as bound; the placement table generated from that list is keyed on the bound certificates' serials, and no entry on anything else |
| **accept** | the bound device is admitted, with `Tunnel-Type`, `Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, `Session-Timeout` and `Termination-Action` in the Accept |
| **wrong CA** | a device of another tenant of the same organization — whose signing CA is under the same organization CA as the trusted one — is refused presenting its leaf, its leaf and signing CA (`unable to get local issuer certificate`) and its whole chain up to the shared root (`self-signed certificate in certificate chain`); a device of another organization is refused; the tenant's own device presenting its whole chain is admitted |
| **revoked after the CRL refresh** | a revoked device is still admitted while FreeRADIUS holds the old list; once AXIAM's list is in `ca_path` and FreeRADIUS has read it, the device is refused with `certificate revoked` and another device is not |
| unplaced | a valid, unrevoked, unbound device is refused, although the table also holds a bound certificate whose subject is `DEFAULT` (which is admitted, as itself) |
| TLS 1.2 | a supplicant offering only TLS 1.2 is refused |
| EAP-MD5 | a supplicant that asks for EAP-MD5 gets an EAP-Failure |
| `Message-Authenticator` | an `Access-Request` without one is discarded and unanswered |

A missing `docker`, `eapol_test` or FreeRADIUS is a failure when
`AXIAM_E2E_RADIUS=1` is set, never a skip.

Not covered, and said so: RadSec (above); supplicants other than `eapol_test`;
a NAS that proxies; the lag of step 4 (the session) — the test does not connect a
session and revoke it under it; and anything about performance. The latency
figures in [§6.3 of the reply-profile note](../../claude_dev/radius-reply-profile-design.md)
that compare this recipe with the designs that would replace it are read from the
defaults (a list valid for a day), not measured; this page's bound, with a
five-minute fetch, is tighter.

## Which threat-model entries this covers

The threat model ([STRIDE model, §5.10](../../claude_dev/threat-model-stride.md))
holds the RADIUS entries the declined native front end was written for. Four of
them are mitigated by this recipe's configuration, with the end-to-end test above
as their test: **T-449** (`Message-Authenticator` required), **T-456** (EAP-TLS
only, TLS 1.3 only), **T-459** (one tenant's signing CA as the only anchor) and
**T-454** (the recipe references an upstream image by digest and vendors
nothing). Two are **open** for the recipe, as residuals the operator carries
(model 2.41.0, 2026-10-14): **T-450** (on plain UDP the EAP-TLS keys travel under
MD5 obfuscation; use [RadSec](#radsec-where-the-nas-allows)) and **T-462** (the
[revocation lag](#the-revocation-lag) above, and no way to end a session already
admitted). The remaining fifteen stay *not applicable*, each saying why: they
are about code AXIAM would have to write, or about a FreeRADIUS control this
recipe does not test.

## Operating notes

- **FreeRADIUS's logs are personal data.** Common names, MAC addresses
  (`Calling-Station-Id`) and user names are written to them. They are yours, not
  AXIAM's: set their retention and erasure as you would for any other log of
  who was on the network.
- **Duplicate and retransmitted requests** are FreeRADIUS's to detect (RFC 5080);
  this recipe changes nothing about that.
- **Licence.** FreeRADIUS is GPLv2 (with LGPLv2 for `src/lib`). The compose file
  names the upstream image and its digest; nothing is built from source here or
  redistributed from this repository.
- **Upgrades.** The digest in
  [`docker-compose.radius.yml`](../../docker/docker-compose.radius.yml) is the
  3.2.8 tag's manifest. Moving it is a decision: re-run the test.

## What this does not do, and what would

This recipe has no real-time check, and that is a decision, not an omission. The
spike recorded a second piece of option B — an authorize endpoint for
FreeRADIUS's `rlm_rest` module, which would post a certificate's fingerprint and
the NAS's identity to AXIAM at every authentication and take `{allow, reply
attributes}` back — and scheduled it only if this recipe showed the revocation
lag or the placement table inadequate.

**That endpoint is not in `1.0.1` and is not scheduled.** It would be a new
authenticated surface in AXIAM (a dedicated permission, a token bound to the
caller's own certificate, a limiter keyed on the authenticated caller, an audit
row for every decision, and a contract section) and it would need the
reply-profile model of the design note built first. What it would close:
the CRL lag becomes the `Session-Timeout`, and VLAN policy moves from the
FreeRADIUS administrator to AXIAM's RBAC. If the lag above is not acceptable to
you, or you need that policy in AXIAM, say so on [#563](https://github.com/ilpanich/axiam/issues/563),
which stays open with this as its remaining item.
