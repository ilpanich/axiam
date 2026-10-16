# 802.1X with an AXIAM-issued Device certificate

**Milestone:** `1.0.1`; [section 5, the decision per authentication](#5-the-decision-per-authentication-d4),
`1.1.0`
**Last verified:** 2026-10-15 (sections 1 to 5), against
FreeRADIUS 3.2.8 and `eapol_test` from `wpa_supplicant` 2.10 (see [What the
end-to-end test proves](#what-the-end-to-end-test-proves) and [What the D4 test
proves](#what-the-d4-test-proves))

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
every change to them. It has two profiles: **D3**, sections 1 to 4, where
FreeRADIUS keeps a placement table and a revocation list you refresh; and **D4**,
section 5, where FreeRADIUS asks AXIAM about every authentication and the table
and the lag go away.

See also: [PKI guide](README.md) (issuing, binding, revoking and the
[revocation lists](README.md#certificate-revocation-lists) this recipe consumes),
[Admin Guide](../admin/README.md).

## What this is, and is not

| | |
|---|---|
| **Is** | EAP-TLS only, TLS 1.3 only, for devices that hold a certificate the tenant's signing CA issued. A device is admitted only if its certificate chains to that CA, is not on the CA's revocation list, **and** is in a placement table you keep. |
| **Is not** | A password service. There is no PAP, CHAP, MS-CHAP or EAP-MD5 path in this configuration, and AXIAM's password store (Argon2id) could not serve the last three. |
| **Is not** | A real-time check, in the D3 profile (sections 1 to 4). FreeRADIUS does not call AXIAM when a device authenticates. A revocation reaches it as a certificate revocation list, on the schedule you set — [the lag is stated below](#the-revocation-lag). [Section 5](#5-the-decision-per-authentication-d4) is the profile that does call AXIAM, once per authentication. |
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
  name; choose one that is unique in the tenant (`press-07`) and matches
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (AXIAM refuses control characters and more
  than 64 characters; this narrower pattern is the recommendation, not a check).
  The placement table does **not** key on it ([below](#the-key-is-the-serial)).
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
replace `ca.pem` ([as below](#replacing-or-removing-capem)) and restart
FreeRADIUS, so that the old trust is gone at once and not at the next reload;
the devices under it should be re-issued under a new one in any case ([Revoke a
certificate](README.md#revoke-a-certificate)).

### Replacing or removing `ca.pem`

`ca_path_reload_interval` ([below](#4-keep-the-revocation-list-fresh)) makes
FreeRADIUS build a new certificate store from `ca_file` **and** `ca_path`, so a
reload re-reads `ca.pem` as well as the lists. Three consequences:

- **Replace `ca.pem` atomically.** Write the new file in the same directory under
  another name and `mv` it over `ca.pem` (a rename within one filesystem is
  atomic). A `cp`, or a redirect that truncates the file in place, can be read
  half written by a reload that fires in between, and that reload then fails.
- **Never delete `ca.pem`, or leave it unreadable, without restarting
  FreeRADIUS.** A reload that cannot read it fails, logs `Error replacing X509
  store`, and **keeps the old store, which still trusts the CA you removed**; it
  retries at every new EAP conversation until the process restarts. Removing the
  file does not withdraw the trust.
- **A logged `Error replacing X509 store` means the old trust is still in force**:
  the CA, and the lists, that FreeRADIUS last read successfully. It is not a
  harmless warning, so alert on it. What you do is repair the file (put the
  intended `ca.pem` back, or the new one) and restart FreeRADIUS, which reads
  everything at once; after any change to the trusted CA, a restart is the only
  way to be sure which one is trusted.

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
- **`ca_path_reload_interval = 300`** is how FreeRADIUS re-reads what it trusts:
  it rebuilds the store from `ca_file` **and** `ca_path`, so a replaced `ca.pem`
  and the lists are read afresh ([below](#4-keep-the-revocation-list-fresh); how to
  replace `ca.pem` is [above](#replacing-or-removing-capem)). FreeRADIUS raises
  any smaller value to 300.

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
- **The NAS must do its half.** The forgery is of the *response*, so FreeRADIUS
  requiring and sending the attribute protects nothing on a NAS that does not
  check it. For each NAS, confirm that its firmware has the Blast-RADIUS fix
  (CVE-2024-3596): it sends `Message-Authenticator` in every Access-Request and
  **requires and verifies** it in every Access-Accept, Access-Reject and
  Access-Challenge. The setting's name differs by vendor. A NAS whose vendor has no
  such firmware is not protected by anything in this recipe: serve it over
  [RadSec](#radsec-where-the-nas-allows), or keep an on-path attacker away from
  the segment between it and FreeRADIUS.
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
	Tunnel-Type:0 = VLAN,
	Tunnel-Medium-Type:0 = IEEE-802,
	Tunnel-Private-Group-Id:0 = "20",
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
  string between `1` and `4094`. Each is written with the tag `:0`, FreeRADIUS 3's
  spelling of a tagged attribute (RFC 2868 §3.1). On the wire that is a `0x00` tag
  octet in front of the two integers' values; the string carries **no** tag
  octet, because FreeRADIUS 3.2.8 encodes tag `0` on a string exactly as it
  encodes no tag, and RFC 2868 §3.6 reads a first octet above `0x1F` (every digit
  is) as the start of the string. The test reads the octets from the Accept
  (`00 00 00 0d`, `00 00 00 06`, `32 30`). A tag other than `0` puts another octet
  in front of the VLAN, which a NAS reads as one tunnel of several; do not write
  one. Use these and no other attributes
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
  AXIAM accepts `DEFAULT` as a subject, and a subject with spaces. Until 1.1.0 it
  also accepted a newline or a tab; since #649 a control character, other
  whitespace, a bidirectional or zero-width character, or more than 64
  characters is a `400` ([the rules](README.md#issue-an-organization-ca-certificate)),
  which closes the newline but not `DEFAULT`, `NONE` or a space: certificates
  issued before 1.1.0 keep the names they have, and the narrower pattern below
  is still yours to enforce.
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
- **Serials are unique per issuer, and this server trusts one issuing CA**
  (section 2). AXIAM refuses to record a second certificate under a serial its
  issuer already used (`idx_certificate_issuer_serial`, #653), so the serial
  needs no issuer beside it.

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
  printf '\tTunnel-Type:0 = VLAN,\n\tTunnel-Medium-Type:0 = IEEE-802,\n'
  printf '\tTunnel-Private-Group-Id:0 = "20",\n\tSession-Timeout = 3600,\n'
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

FreeRADIUS reads lists from files. [`docker/radius/fetch-crl.sh`](../../docker/radius/fetch-crl.sh)
fetches the tenant signing CA's list, checks it, and moves it into `ca_path` under
the name OpenSSL looks it up by (`<issuer-name-hash>.r0`). The file is the recipe:
this page does not copy it, so that what you read cannot drift from what the
end-to-end test runs. Run it from cron or a systemd timer, every five minutes:

```sh
fetch-crl.sh "https://axiam.example.com/pki/v1/$ORG/ca/$SIGNING_CA/crl" \
    /etc/freeradius/axiam/ca.pem /etc/freeradius/axiam/capath
```

It installs a list only if all of these hold, and otherwise exits 1, says why on
stderr and leaves the installed list alone:

- **The CA you trust signed it.** The check is the *text* `openssl crl -verify`
  prints, which must be exactly `verify OK`, not its exit status: OpenSSL 3.0
  prints `verify failure` and exits **0** when a list names the CA but another key
  signed it, so a script that trusts the exit status installs a list forged under
  the CA's name (R101W6-04, [#643](https://github.com/ilpanich/axiam/issues/643))
  — and FreeRADIUS then refuses the whole tenant, with the genuine list gone from
  disk.
  ```sh
  out=$(openssl crl -in "$work/crl.pem" -CAfile "$ca_file" -noout -verify 2>&1) || rc=$?
  { [ "$rc" -eq 0 ] && [ "$out" = "verify OK" ]; } || fail "…not signed by $ca_file"
  ```
- **Its CRL number is not lower than the installed list's.** A validly signed
  but older list is a replay that would undo a revocation. A number is compared
  as the hex integer it is (`openssl crl -noout -crlnumber`); an equal number is
  accepted, since the same list again is not a replay.
  **Expect this refusal once after AXIAM's list interval
  (`AXIAM__PKI__CRL_NEXT_UPDATE_SECS`) changes.** AXIAM's CRL number is derived
  from the refresh epoch, and a new interval cuts new epochs, so the number can
  step back once; the lower list withdraws nothing the installed one revoked,
  only entries that expired. The script then exits 1 with `its CRL number … is
  lower than the installed list's` and keeps the installed list, and if the
  interval followed the [PKI guide's rule](README.md#certificate-revocation-lists)
  (lower it in one step; raise it to at most twice the current value at a time)
  AXIAM serves a greater number again before the installed list's `nextUpdate`,
  and the next run installs it. A refusal that lasts until the installed list
  expires means the interval was raised in one larger step, and FreeRADIUS then
  refuses every device of the tenant (`check_crl`) until AXIAM's number passes
  the installed one, up to half the new interval: raise it in steps.
- **The server said `200`.** The script sends the `ETag` of the list it
  installed as `If-None-Match`; a `304` whose own `ETag` is the tag it sent means
  "unchanged", and nothing is touched. The tag is stored (in `ca_path`, as
  `.fetch-crl.*`, a name OpenSSL never looks up) only after its list is in place,
  only if it is one entity-tag (`"…"` or `W/"…"`: never `*`, which AXIAM's route
  matches against every list, and never a list of tags), and beside the SHA-256 of
  the file it was installed as. The script fetches the whole list, with no
  `If-None-Match`, when the file in `ca_path` is no longer that one (replaced,
  deleted, corrupted) and when a `304` carries another tag or none; a `304` to
  that request is refused. A tag stored as `*` would otherwise make every later
  run read "unchanged" for as long as the list lasts, after whoever answered one
  fetch was gone (R110W5-01).

and it installs atomically: written beside its destination, then renamed, so
FreeRADIUS never reads a half-written list.

It runs one at a time per URL. The whole run, from reading the stored tag to
writing it, holds a lock in `ca_path` (`flock` on `.fetch-crl.*.lock` where
`flock` exists; otherwise a directory of that name plus `.d`, which a later run
breaks when its owner is gone or it is older than 120 seconds). A run that finds
the lock held prints that, exits **0** and touches nothing: it is not a failure,
so a timer that overlaps its own previous run, a manual run beside the cron entry
or a Kubernetes CronJob left at `concurrencyPolicy: Allow` raises no alert. Without
the lock, two runs that fetch different lists can leave the older one in place
under the newer one's tag, and a revocation then waits until AXIAM's list next
changes, up to half its lifetime, with a file fresh enough to silence the
age alert below (R110W5-02). The lock file stays in `ca_path`; OpenSSL never
looks it up.

Use HTTPS, and the script holds you to it: the URL must start with `https://`,
and an `http://` URL is refused unless `FETCH_CRL_ALLOW_HTTP=1` is set in the
script's environment. The list is signed, so plain HTTP costs no integrity, which
is why there is a switch at all (a lab, or a loopback stand-in, as the
end-to-end test uses); but the signature check stops a list the CA did not sign,
and the number check a replay of an older one, and neither stops whoever answers
the fetch from serving the genuine current list again after a newer one exists,
which only lengthens [the lag](#the-revocation-lag). Over HTTP anyone on the path
can do that; over HTTPS only the server and anything that terminates TLS for it
can. Any other scheme (`file:`, `ftp:`, ...) is refused, and so is a URL that
starts with `-`.

The script's `curl` runs as `curl -q … --url <url>`: `-q` so that it does not read
the `~/.curlrc` of the user whose cron job this is (a `location` or `insecure`
line there would turn a refused redirect into a followed one, or TLS verification
off), `--proto` pinned to the URL's scheme, and no redirect followed (a `3xx` is
reported as the status it is and the installed list stays). Before curl 8.4,
`--max-filesize` does not stop a chunked body without a declared size; only
`--max-time` (20 seconds) does (R110W5-03).

The alert on a list that is older than half its lifetime
([below](#the-revocation-lag)) is what catches a fetch that no longer moves.

The cron interval does not need to be less than the list's refresh epoch: AXIAM
re-signs at most every half `nextUpdate` interval and answers a repeat request
with `304` (the script sends `If-None-Match`), and the route's limiter is 60
requests a minute per address.

### The revocation lag

A revoked device keeps being admitted until each of these has happened, in
order:

1. **AXIAM publishes it.** At once: the next response from the CRL route names the
   serial. The test checks this.
2. **Your job fetches the list.** At most the fetch interval, **provided it
   fetches AXIAM directly, or through a cache told `no-cache`**. The CRL route
   answers `Cache-Control: public, max-age=N`, with N running to the next
   scheduled re-sign: at most half of `nextUpdate`, twelve hours by default. A
   shared cache or CDN on the path may therefore serve the list from before the
   revocation for that long. Leave one out, or have it revalidate every request;
   that is cheap, because [`fetch-crl.sh`](../../docker/radius/fetch-crl.sh) sends
   the `ETag` of the list it installed as `If-None-Match`, so a revalidation that
   finds nothing new costs a `304` and no list body.
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
300 seconds, plus the `Session-Timeout`, plus any shared cache's `max-age`** — with
the figures above and no cache on the fetch path, roughly an hour and ten minutes
in the worst case, and a few minutes for a device that is not connected. The end-to-end test shows the middle of that: it revokes a device,
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
- **`ca.pem` is replaced non-atomically, or deleted without a restart.** The
  reload re-reads it as well as the lists; a reload that cannot read it logs `Error
  replacing X509 store` and leaves the old trust in force
  ([above](#replacing-or-removing-capem)).

## 5. The decision per authentication (D4)

**Milestone `1.1.0`** (RADIUS D4, [#563](https://github.com/ilpanich/axiam/issues/563)).
The profile in which AXIAM, and not a file, decides where a device goes. For
every authentication FreeRADIUS asks `POST /api/v1/network/decide` whether the
certificate it has just verified belongs to a device that is placed on this
site, and copies the answer into the Access-Accept. The placement table of
section 3 does not exist in this profile; the revocation list stays (below).
The design is the [reply-profile note](../../claude_dev/radius-reply-profile-design.md)
(the segments and profiles in section 3, the decision in 4.3, this caller in 6.3).

| | D3 (sections 1 to 4) | D4 (this section) |
|---|---|---|
| Who owns VLAN policy | whoever writes the placement table on FreeRADIUS | AXIAM: segments, reply profiles and `network:join` grants, with its audit trail |
| A revoked certificate stops | when the list reaches FreeRADIUS ([the lag](#the-revocation-lag)), then at `Session-Timeout` | at the **next authentication**; a device already connected keeps its port until `Session-Timeout` |
| A quarantine takes effect | when someone edits the table, then at `Session-Timeout` | at the next authentication; a connected device at `Session-Timeout` |
| FreeRADIUS needs AXIAM | to fetch a file, now and then | **for every authentication**: AXIAM unreachable is every new device refused |
| New on the AXIAM side | none | one route, a service account, a certificate for it |

### What you set up in AXIAM

The [PKI guide](README.md) has each step; this is the order D4 needs.

1. **The tenant's segments and profiles** (`/api/v1/network/segments`,
   `/api/v1/network/profiles`): an `access` segment per VLAN with its `rank`, the
   `quarantine` segment if you want one, each with a reply profile. A device is
   placed on the lowest-ranked access segment on which its service account may
   `network:join`, else on a quarantine segment it may join, else it is refused
   ([4.3](../../claude_dev/radius-reply-profile-design.md#43-how-a-profile-is-chosen)).
   Quarantine is a **deny** of `network:join` on the access branch
   ([4.4](../../claude_dev/radius-reply-profile-design.md#44-quarantine-by-deny-override)):
   deny-override makes it beat every allow, so granting more cannot release a
   device. Assign each device's account `network:join` on its segment, and a
   baseline `network:join` on the quarantine segment if a deny should land it
   there instead of refusing it.
2. **The devices**, as in section 1: a `Device` certificate from the tenant
   signing CA, bound to a service account.
3. **FreeRADIUS's own identity**: a service account for this server (one per
   server), a **`Service` certificate** from the same signing CA bound to it, and
   **`network:decide` on both nodes of each site it serves**, `zones/<site>` and
   `quarantine/<site>`. A stolen FreeRADIUS credential for one site answers
   nothing about another: the route is a `403`, audited, for a site the caller
   was not given.
4. **The organization CA flagged as an mTLS trust anchor**, and AXIAM's own listener
   asking for client certificates
   ([Turn on mutual TLS](README.md#turn-on-mutual-tls-using-a-ca-axiam-generated)).
   FreeRADIUS's certificate and the devices' both chain to it.

### The connection: mutual TLS that ends at AXIAM

**FreeRADIUS must reach AXIAM over a TLS connection that AXIAM itself ends.**
The route accepts a service-account token only if the token is bound to a
certificate (RFC 8705, `cnf` with `x5t#S256`) *and* the connection it arrives on
presented that certificate, verified by AXIAM's own listener. A proxy, load
balancer, ingress or service-mesh sidecar that terminates TLS and tells AXIAM who
the client was in a header (`X-Client-Certificate`, with
`AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT`) cannot stand in: the token AXIAM issues
behind it is not bound, because AXIAM could not check the binding again later, and
the decision route refuses every token that is not bound with a `401`, so every
device is refused. A layer-4 proxy that passes the TLS connection through
untouched is fine. The same holds for the token request in the next paragraph.

**Expose that listener to the FreeRADIUS servers only.** AXIAM has one listener,
and it serves every route, not just the decision. Reached without an appending
proxy in front (directly, or through a layer-4 pass-through), nothing appends to
`X-Forwarded-For`, so every per-address rate limiter — `/auth/login`'s,
`/auth/device`'s, the decision route's per-address backstop, `/oauth2/token`'s —
keys on whatever entry a caller writes there, also at the default
`AXIAM__RATE_LIMIT__TRUSTED_HOPS = 0` ([the deployment guide's
table](../deployment/README.md#deriving-trusted_hops)), and a caller who
rotates the header gets a fresh bucket per request. Per-account lockout, the
decision route's own allowance (keyed on the authenticated service account) and
the per-client limits are not affected. So let a firewall or a network policy
admit only the FreeRADIUS servers to the native listener, and keep the HTTP
ingress, with its appending proxy, for every other client. A setting that names
the proxies whose header is honoured is planned for `1.1.x`
([#711](https://github.com/ilpanich/axiam/issues/711); T-212, T-486).

**How FreeRADIUS gets its token.** It logs in as the service account the way a
device does: `POST /api/v1/auth/device` over that mutual TLS connection, with its
`Service` certificate and no secret. The answer is an access token (15 minutes
by default, `expires_in`) bound to the certificate, which the decision request
then presents with `Authorization: Bearer`. There is no client secret and no
OAuth2 client in this flow; the decision route takes a service account's token
and no other kind. The recipe keeps the token in memory for **half of
`expires_in`** and logs in again when the entry is gone (a restart or `HUP`
clears it), so a login is one in many authentications, not one in each; the
device-login limiter (`AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, per address) is
therefore not what a storm spends.

### The FreeRADIUS configuration

The D4 profile changes the D3 files as little as it can: the base compose file
and the files of section 3 stay, and
[`docker-compose.radius-d4.yml`](../../docker/docker-compose.radius-d4.yml)
**overrides** the one service (`docker compose -f docker-compose.radius.yml -f
docker-compose.radius-d4.yml up`). It names no image: the digest is pinned once, in
the base file.

| File ([`docker/radius/raddb/d4/`](../../docker/radius/raddb/d4/)) | What it does |
|---|---|
| `clients.conf` | the D3 clients, each with `shortname` set to the **AXIAM site key** |
| `check-eap-tls` | the decision: the call, and the mapping into the Access-Accept |
| `axiam_d4` | the modules: two `rest` instances (the token, the decision), the token cache, the `exec` the fingerprint comes through |
| `verify.conf` | the `verify` hook of the `eap` module (`eap` includes it with `$-INCLUDE`, which D3, with no such file, ignores) |
| `axiam-d4.sh` | what the hook and the decision run to carry the certificate's fingerprint from one to the other |

**The site key is the client's `shortname`.** `clients.conf` is the one place a
site key comes from: `sites-enabled/check-eap-tls` posts `%{client:shortname}`,
never anything from the packet, so a NAS cannot ask about another site. Set
`shortname` on **every** `client` of a site to that site's key in AXIAM
(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`; FreeRADIUS defaults it to the client's name,
which is only right if you named the clients so).

**The body is two values.** `{"site": …, "fingerprint": …}`: the site key and the
SHA-256 of the certificate EAP-TLS verified, 64 hex digits. The route's body is
closed; there is no place for a `Calling-Station-Id` or a `User-Name`, which stay
in FreeRADIUS's logs ([operating notes](#operating-notes)). AXIAM writes one audit
row for every decision with the fingerprint, the site and the reason, never the
certificate's subject.

**Where the certificate comes from, and why there is a helper script.**
FreeRADIUS 3.2.8 does not offer the configuration the client certificate, or its
fingerprint, in any attribute. It writes the certificate to a PEM file for the
`verify { client = … }` hook and deletes the file when the hook returns, and it
does not show the file's name to the virtual server that makes the decision. The
shipped `verify.conf` runs `axiam-d4.sh stash` there: it computes the SHA-256 of
the DER and leaves it under the certificate's **serial**; `check-eap-tls` reads it
back with `axiam-d4.sh take <serial>` a moment later. The serial is what both
sides can see, and it is a sound key for the reason section 3 already gives
([the key is the serial](#the-key-is-the-serial)): serials are unique per issuer
(AXIAM's `idx_certificate_issuer_serial` refuses a second certificate under one
issuer's serial) and this FreeRADIUS server trusts one issuer, so a serial names
one certificate (a pair issued before 1.1.0 may still share one, over one key;
see the correction there). A fingerprint is
used only if it is younger than two EAP timers; both halves run as the `freerad`
user against a `tmpfs` that is gone with the container. A hook that fails fails
the certificate. A newer FreeRADIUS that puts the certificate in an attribute
makes the helper unnecessary; check before you rely on this one.

```
update control {
	Tmp-String-1 := "%{client:shortname}"
	Tmp-String-0 := "%{axiam_take:/bin/sh /etc/freeradius/axiam-d4/axiam-d4.sh take %{TLS-Client-Cert-Serial}}"
}
```

**The decision runs in `post-auth` of `check-eap-tls`**, the virtual server
`eap` calls once the certificate is verified, because the attributes of the
client certificate (`TLS-Client-Cert-*`) exist only while that server runs and
FreeRADIUS 3.2.8 does not carry them to `default`'s `post-auth`. The reply
attributes set there are the ones the NAS gets, and a `reject` there is the
Access-Reject ("Certificate rejected by the virtual server"), with nothing else
on the wire. The calls themselves are `rlm_rest`, with FreeRADIUS's certificate
as its TLS client certificate:

```
rest axiam_decide {
	connect_uri = "$ENV{AXIAM_D4_URL}"
	tls {
		ca_info_file     = /etc/freeradius/axiam/axiam-ca.pem   # the CA of AXIAM's own certificate
		certificate_file = /etc/freeradius/axiam/rest-chain.pem  # FreeRADIUS's Service certificate, then its signing CA
		private_key_file = /etc/freeradius/axiam/rest.key
		check_cert    = yes
		check_cert_cn = yes
	}
	post-auth {
		uri    = "${..connect_uri}/api/v1/network/decide"
		method = 'post'
		body   = 'json'
		data   = '{"site":"%{control:Tmp-String-1}","fingerprint":"%{control:Tmp-String-0}"}'
		force_to = 'plain'
		tls = ${..tls}
	}
}
```

`rest-chain.pem` is the leaf **followed by the signing CA**: AXIAM's listener
trusts the organization CA above both, and a client that sends only its leaf
cannot be chained to it. `rest.key` needs the re-encoding of section 1 where
FreeRADIUS's TLS library is OpenSSL 3.0, as for a supplicant. `check_cert` and
`check_cert_cn` stay `yes`: they are what stops anything but AXIAM answering,
and a decision from anything else would be a placement.

### The response: only the dictionary's attributes

AXIAM answers `{"allow": false}` with no reason, or `{"allow": true, "reply":
{"dictionary": "axiam-radius-reply/1", "attributes": […]}}`, the attributes
rendered from the segment's profile with `Session-Timeout` clamped to the tenant's
cap. The array is not the shape `rlm_rest` reads into attributes, and the
recipe does not want it to be: **FreeRADIUS never copies an attribute because
AXIAM named it.** `force_to = 'plain'` keeps the body whole, and `check-eap-tls`
looks for each attribute of the dictionary by name, number and shape and sets that
attribute itself. Everything else in the body is never read.

| Attribute | In the body | Set in the reply as | Missing or malformed |
|---|---|---|---|
| `Tunnel-Type` | `13` (VLAN), `"tag": 0` | `Tunnel-Type:0 := VLAN` | reject |
| `Tunnel-Medium-Type` | `6` (802), `"tag": 0` | `Tunnel-Medium-Type:0 := IEEE-802` | reject |
| `Tunnel-Private-Group-Id` | a decimal string, `1` to `4094`, no sign or leading zero, **no `tag` key** | `Tunnel-Private-Group-Id:0 := "<vlan>"` | reject |
| `Session-Timeout` | at least 100 seconds (AXIAM's floor is 300) | `Session-Timeout := <n>` | reject: it is the only bound on a placement that outlives the decision |
| `Termination-Action` | `0` or `1` | `Termination-Action := <n>` | reject |
| `Idle-Timeout` | when present, a positive integer | `Idle-Timeout := <n>` | present and malformed: reject |
| `Filter-Id` | when present, an identifier of at most 63 characters | `Filter-Id := "<id>"` | present and malformed: reject. An ACL silently dropped would widen the placement |
| `Service-Type` | when present, `2` (`Framed-User`) | `Service-Type := Framed-User` | present with any other value, the administrative ones included: reject |
| anything else — `Reply-Message`, `Class`, `Tunnel-Password`, a vendor attribute | | **never copied** | ignored |

The tags are the ones RFC 2868 and FreeRADIUS 3.2.8 put on the wire, measured by
the end-to-end test: `Tunnel-Type` and `Tunnel-Medium-Type` carry the tag octet
(`0x00`) in front of the integer, `00 00 00 0d` and `00 00 00 06`, whether or not
`:0` is written; `Tunnel-Private-Group-Id` written `:0` carries **no** tag octet
(RFC 2868 section 3.6 makes it optional for a string whose first octet is above
`0x1F`, which a decimal VLAN's is): `"20"` is `32 30`. Only a non-zero tag adds an
octet. The dictionary name is checked too: a body that names another version is
refused, so a dictionary that grows is a deliberate change to this file, not a
silent one.

**The mapping reads AXIAM's JSON with regular expressions**, because FreeRADIUS
3.2.8 has no JSON-path or JSON-decoding facility to put there. They accept the
members of an attribute in the order AXIAM writes them (`name`, `number`,
`value`, `tag`) and any whitespace between tokens. A change to that order is a
change to this file, and until it is made every device is refused: the failure
is closed, and `radius_e2e.rs` is what notices it.

**Every failure is a refusal, and a comparison on a missing attribute is not
one.** FreeRADIUS evaluates a comparison against an attribute that does not exist
as *false*, whichever way it reads, so `if (&X !~ /re/) { reject }` does **not**
reject when `X` is absent. A first draft of this recipe admitted an answer with
no content for exactly that reason (found against a stand-in server). The version
shipped copies the body with an expansion, which always sets the attribute, and
`check-eap-tls` also gives every attribute it checks a value that matches nothing
before any step that might set it, so that a later edit cannot reopen the hole.
Keep both when you adapt the file. What is refused: AXIAM unreachable or
slow (a 4-second timeout), a certificate AXIAM does not accept, a status other than
`2xx` (`401`, `403` — a site the caller was not given — `429`, `5xx`), a body
that is not exactly the allow described above, a fingerprint the hook did not
leave. There is no fallback placement and no cached decision.

### Latency: what D4 changes, and what it does not

Design note 6.3's last column, as measured by the test:

- **Revocation**: AXIAM refuses a revoked certificate **at the next
  authentication**, with no wait for the list. `check_crl = yes` stays, as a
  second check with its own lag; the decision is the one that does not lag. The
  certificate's row is read for every decision, not cached.
- **Quarantine, and any change to a role assignment, a segment or a profile**:
  at the next authentication. The authorization decision cache is off by default;
  if you turn it on, a grant or a deny written on one AXIAM replica reaches the
  decisions of another after `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (5 seconds by
  default) unless the broadcast is on ([admin
  guide](../admin/README.md#authorization-decision-cache-optional-d7)). The test
  runs with it off.
- **A device that is already connected keeps its port until `Session-Timeout`**,
  the profile's value (at least 300 seconds, at most the tenant's cap, 86 400 at
  the ceiling), and then re-authenticates under `Termination-Action =
  RADIUS-Request` and meets the decision. **Nothing ends a session**: that is
  dynamic authorization (RFC 5176, CoA and Disconnect-Request), which FreeRADIUS
  and your NAS own and this recipe does not configure. A short `Session-Timeout`
  costs authentications, which D4 meters; it is the lever.
- **The price is availability.** In D3 AXIAM could be away for a day and every
  placed device was admitted from the table. In D4 a new authentication, and a
  re-authentication at `Session-Timeout`, is refused while AXIAM is. The pool
  starts empty (`start = 0`) so FreeRADIUS itself starts without AXIAM, and
  refuses every device until it is back; run AXIAM as the service the network
  depends on.

### Limits

`POST /api/v1/network/decide` is metered **per authenticated caller**, the
service account (`AXIAM__RATE_LIMIT__NETWORK_DECIDE_PER_MIN`, **6 000 a minute**
by default, in the `gateway` and `mesh` profiles too): a hundred authentications
a second, which is what a site's power-restore storm asks for. A caller over it
gets a `429`, which the recipe turns into a refusal; the NAS retries. A second
bound, ten times the first, applies per address to a token that does not
authenticate. Size it from your largest site
([rate-limit sizing](../deployment/rate-limit-sizing.md)); a server per site, each with
its own service account, keeps one site's storm out of another's bucket.

### What the D4 test proves

The second test of `radius_e2e.rs` runs this profile. AXIAM is the real thing in
the test process behind its real TLS listener (TLS 1.3, client certificates
verified against the flagged organization CA, the production route table and
connection hook); FreeRADIUS is the pinned image with the files above; `eapol_test`
is the supplicant.

| Case | What it asserts |
|---|---|
| **placement from a profile** | the device is admitted onto the VLAN of the segment AXIAM chose, with that profile's `Session-Timeout`, `Idle-Timeout`, `Filter-Id` and `Service-Type`; the Access-Accept carries `Tunnel-Type` `0000000d`, `Tunnel-Medium-Type` `00000006` and `Tunnel-Private-Group-Id` `3230`; the body posted is exactly the site key and the fingerprint; the audit row names the same fingerprint |
| **the token is cached** | the second authentication does not log in again |
| **an unbound certificate** | valid for EAP-TLS, refused by the decision |
| **revocation at the next authentication** | the device is revoked in AXIAM and refused at once while FreeRADIUS still holds the old list (no `certificate revoked` from the TLS layer); another device is admitted |
| **quarantine** | a deny of `network:join` on the access branch moves the device from VLAN 20 to the quarantine segment's VLAN 999 and profile; a device with the deny and no baseline is refused |
| **a wrong site key** | a client whose `shortname` names a site the caller was not given: a `403`, one `network_decision.refused` row, an Access-Reject, no decision asked |
| **AXIAM unreachable** | refused |
| **no free attribute copy** | against a server that answers whatever the test tells it to: a body with `Reply-Message`, `Class`, `Tunnel-Password` and vendor attributes is admitted with the five dictionary attributes and none of those; eighteen answers that are not exactly the allow above (an administrative `Service-Type`, VLAN `0`, `4095` and `020`, no `Session-Timeout`, another dictionary version, members in another order, no reply, `allow` as a string, not JSON, no content, `403`, `500`, …) are each refused, while the same body with whitespace between its tokens is admitted |

Not covered: a proxy in front of AXIAM (the guide says it does not work; it is not
exercised), more than one site, a NAS that retransmits, and anything about speed.

### What D4 leaves to you

- **mTLS to AXIAM with nothing in between that ends it**, and AXIAM's availability.
- **Who else reaches that listener**: the FreeRADIUS servers only
  ([above](#the-connection-mutual-tls-that-ends-at-axiam)).
- **FreeRADIUS's own certificate**: issue it short-lived, renew it before it ends,
  restart FreeRADIUS to use the new one (the token cache goes with the restart),
  and revoke it in AXIAM if the server is compromised: the next request is a
  `401` and every device is refused. Its key is a file on the FreeRADIUS host,
  readable by `freerad` and by no one else.
- **The site key in every `client`'s `shortname`**, and one service account per
  FreeRADIUS server with `network:decide` on its sites only.
- **The helper and its `tmpfs`**: `/var/run/axiam-d4` must be a `tmpfs` of the
  `freerad` user's; fingerprints and the hook's PEM files live there, and a
  persistent directory would keep personal data you did not mean to keep.
- **The mapping**, when AXIAM's dictionary or the shape of its answer changes:
  AXIAM's change comes with a new `axiam-radius-reply/N` and this file changes with
  it.
- **Logs**: `-X` prints each request and response body, fingerprints included.
  Production runs `freeradius -f -l stdout` and treats the logs as personal data,
  as before.
- **Sessions**: `Session-Timeout`, and CoA if you need a session ended, not
  waited out.
- **The revocation list**, unless you decide the decision is enough: with
  `check_crl = yes` a list that is not fetched is every device refused, as in
  section 4.

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
		require_message_authenticator = yes
	}
}
```

This is the shape of the image's own `sites-available/tls`, with TLS 1.3 asked
for. `require_message_authenticator = yes` stands on this client as on every
other, and the NAS-firmware point under [`clients.conf`](#clientsconf--who-may-send-requests-and-what-they-must-send)
applies to it equally. Three cautions:

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
| **accept** | the bound device is admitted, with `Tunnel-Type`, `Tunnel-Medium-Type`, `Tunnel-Private-Group-Id`, `Session-Timeout` and `Termination-Action` in the Accept; the octets of the three VLAN attributes are read from it: tag `0x00` before each integer, none before the VLAN string |
| **wrong CA** | a device of another tenant of the same organization — whose signing CA is under the same organization CA as the trusted one — is refused presenting its leaf, its leaf and signing CA (`unable to get local issuer certificate`) and its whole chain up to the shared root (`self-signed certificate in certificate chain`); a device of another organization is refused; the tenant's own device presenting its whole chain is admitted |
| **revoked after the CRL refresh** | a revoked device is still admitted while FreeRADIUS holds the old list; once AXIAM's list is in `ca_path` and FreeRADIUS has read it, the device is refused with `certificate revoked` and another device is not |
| **the fetch script** | the revocation list reaches `ca_path` through [`fetch-crl.sh`](../../docker/radius/fetch-crl.sh) itself, run on the host against a local stand-in for the CRL route. A list another key signed under the CA's name (with a higher number, so only its signature can stop it) is refused, although `openssl crl -verify` exits 0 on it; a list the CA signed with a lower CRL number is refused; a `304` to the stored `ETag` leaves the list alone; each refusal leaves the installed list byte for byte as it was |
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
that compare this recipe with the designs that would replace it are reasoned from
the mechanism above, not measured.

## Which threat-model entries this covers

The threat model ([STRIDE model, §5.10](../../claude_dev/threat-model-stride.md),
model 2.42.0) holds the RADIUS entries the declined native front end was written
for, and since 1.1.0 the entries of the D4 profile. For the **D3 profile**, four
are mitigated by this recipe: **T-449** (`Message-Authenticator` required),
**T-456** (EAP-TLS only, TLS 1.3 only) and **T-459** (one tenant's signing CA as
the only anchor), each with the end-to-end test above as its test, and **T-454**
(the recipe references an upstream image by digest and vendors nothing), whose
tests are `scripts/check-radius-vendors-nothing.py` and `cargo-deny`'s licence
list, not the end-to-end. Two are **open** for the recipe, as residuals the
operator carries (since model 2.41.0, 2026-10-14): **T-450** (on plain UDP the
EAP-TLS keys travel under MD5 obfuscation; use
[RadSec](#radsec-where-the-nas-allows)) and **T-462** (the
[revocation lag](#the-revocation-lag) above, and no way to end a session already
admitted).

The **D4 profile** ([section 5](#5-the-decision-per-authentication-d4)) adds a
route, a caller and a write surface to AXIAM, and the model states them (1.1.0):
**T-468** (the decision route answers only a certificate-bound FreeRADIUS
service account), **T-457** (one negative answer, whatever the cause), **T-461**
(the bounded reply-profile model), **T-463** (one audit row per decision) and
**T-464** (no MAC address or user name reaches AXIAM) are mitigated for the
route; **T-459** gains the route's own tenant check; **T-487** (only the
dictionary's attributes reach the Accept) is mitigated for this recipe by the D4
test; the segment and profile write surface is **T-478** … **T-480**, **T-482**
and **T-485**. Open for D4: **T-462** keeps its D4 column (refused at the next
authentication; a connected session lasts until `Session-Timeout`), **T-486**
(AXIAM unavailable, or reached through a proxy that ends TLS, refuses every
device — the operator's to carry, with the listener exposed to the FreeRADIUS
servers only, [above](#the-connection-mutual-tls-that-ends-at-axiam)), and three
Low residuals of the write gate (**T-481**, **T-483**, **T-484**). The remaining
ten entries stay *not applicable*, each saying why: they are about the native
listener, EAP state machine and NAS registry AXIAM would have to write, or about
a decision surface D4 does not build. *(Corrected 2026-10-16: this paragraph
said all four mitigated entries had the end-to-end as their test, true of three
since 2026-10-15, and that the guide claimed no D4 mitigation the model did not
yet state — the model states them since W6.6.)*

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
  3.2.8 tag's manifest, for both profiles (the D4 override names no image).
  Moving it is a decision: re-run both tests.

## What this does not do, and what would

The D3 profile (sections 1 to 4) has no real-time check, and that is a decision,
not an omission; [section 5](#5-the-decision-per-authentication-d4) is the profile
that has one. It is the second piece of option B that the
[spike](../../claude_dev/radius-eap-tls-spike-2026-10-06.md) recorded: an authorize
endpoint for FreeRADIUS's `rlm_rest`, taking a certificate's fingerprint and the
NAS's site and returning `{allow, reply attributes}`. It closes what the D3
profile leaves: the revocation lag becomes the `Session-Timeout`, and VLAN policy
moves from the FreeRADIUS administrator to AXIAM's RBAC.

Neither profile does these, and what would:

- **End a session that is already admitted.** That is dynamic authorization (CoA,
  Disconnect-Request, RFC 5176), which FreeRADIUS and the NAS own; `Session-Timeout`
  is the bound both profiles have.
- **Speak RADIUS from AXIAM.** The spike declined a native front end (option A); its
  reopen condition is in the decision record.
- **Hand AXIAM the device's MAC address or user name.** The decision route's body
  is closed on purpose, so that neither reaches AXIAM's audit trail.
