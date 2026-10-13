# Security review — release 1.0.1, wave W6 (F4)

**Date:** 2026-10-13.
**Against:** `claude/release-1.0.1-w6`, the whole wave diff `55c3e3072..b8fa66fbd`
(3 commits, 21 files, 3 095 lines added and 122 removed): `9b8b4dc2c` (W6.1, the
reply-profile design note, D5), `3f9f82079` (W6.2, the FreeRADIUS recipe, D3) and
`b8fa66fbd` (W6.2, T-449 / T-454 / T-456 / T-459 Not applicable → Mitigated).
Every commit carries a signature (`gpgsig` present on all three; the sandbox has
no `allowedSignersFile`, so `%G?` reads `N` and cannot verify them here).
**Scope:** W6.1 and W6.2 of the release plan (§7) under D-2 (W6 ships D3 and D5;
#563 stays open with D4): `claude_dev/radius-reply-profile-design.md`,
`docs/pki/freeradius.md`, `docker/docker-compose.radius.yml`, `docker/radius/**`,
`crates/axiam-server/tests/radius_e2e.rs`, `.github/workflows/radius-e2e.yml`, the
website, comparison and CHANGELOG lines, and the four threat-model copies the
flip touched.
**Method:** the guide's security wording read against the spike's §4.2 (the MD5
table and its consequence), §5.2 (B-2) and §6; the four flips against §6, §7 and
the plan's §9 rule ("nothing enters without the test its mitigation names; a
correction is recorded as a correction, dated, in the entry's own text"); every
FreeRADIUS behaviour the guide or an entry asserts read in the FreeRADIUS
**`release_3_2_8`** sources (`src/main/tls.c`, `src/main/listen.c`,
`src/main/client.c`, `src/lib/radius.c`, `src/modules/rlm_files/rlm_files.c`,
`raddb/radiusd.conf.in`, `raddb/mods-available/eap`, `raddb/sites-available/tls`,
fetched from `raw.githubusercontent.com`); the RFC claims of the note's §1 against
RFC copies (2548, 2865, 2866, 2868, 2869, 3579, 3580, 3748, 5080, 5176, 6613, 6614,
6929); the image digest against Docker Hub's tag record; three OpenSSL 3.0.13
probes (§11). The e2e itself was **not** run (no `dockerd` here, and no cargo
build on the shared disk), and the workflow has not run in CI. This review fixes
nothing: every finding has its evidence, a proposed fix and an issue body (§12).
The three Medium findings are proposed for a fix inside the wave; the rest for
`1.0.x` or for W7.3.

---

## 0. Summary

**Three Medium findings: one flipped entry whose test does not exercise the case
it names, one way the recipe's third security pillar is lost through data AXIAM
serves, and one leak in the design note's delegation bound.**

* **R101W6-01 (Medium, T-459).** The wrong-CA case meant to prove the tenant
  boundary inside one organization does not share the organization CA:
  `signing_ca()` mints a **new organization root on every call**, so the
  "other tenant of the same organization" device chains to a different root than
  the tenant FreeRADIUS trusts. The test exercises the different-root case twice.
  T-459's text, the guide's §2 ("even one of the same organization, under the
  same root … The end-to-end test issues such a device and checks exactly that")
  and spike R9 (the risk *is* the shared organization CA) all name the case the
  test does not build. The supplicant also sends only its leaf, never the chain an
  attacker would send.
* **R101W6-02 (Medium, the recipe's pillar 3; T-461 for option B).** The guide
  tells the operator to build the placement table from AXIAM's list of bound
  `Device` certificates, keyed on the common name, "exactly" as the test does —
  by pasting the `subject` into a FreeRADIUS `files` entry unescaped. AXIAM
  accepts a subject of `DEFAULT`, and `rlm_files` matches a `DEFAULT` entry for
  **every** key. A tenant certificate administrator who issues and binds one such
  certificate makes every certificate the tenant CA ever issued — bound or not,
  listed or not — placed, and, if that entry precedes the others, re-places every
  device onto its VLAN. A bare subject with whitespace or a newline (also
  accepted) breaks the file or injects an entry.
* **R101W6-03 (Medium, T-461 design).** The note's §5.3 bounds the
  role-assignment side because "joining is a role assignment", but placement
  also follows the **certificate → service-account binding**: whoever holds
  `certificates:generate` and `certificates:bind` (tenant-wide, on `Uuid::nil()`)
  can issue a certificate for a device they hold and bind it to a service account
  that already has `network:join` on a privileged segment. That confers placement
  without `network:grant` — the leak §5.3 exists to close, by another door.

Nine Low and five Informational findings follow.

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R101W6-01** | The "same organization" wrong-CA case issues the other tenant's signing CA under a fresh root, so the shared-root case T-459 and the guide claim is never run; the supplicant sends no chain. | **Medium** | `radius_e2e.rs:631-689, 990-992, 1093-1106` → T-459 | wave (W6.2) | **Fix in wave** |
| **R101W6-02** | A bound certificate with subject `DEFAULT` (or with whitespace / a newline) turns the generated placement table into "place everyone" or breaks it; the guide's generator recipe does not validate or escape the key. | **Medium** | `freeradius.md:272-296`, `radius_e2e.rs:807-830`, `rlm_files.c:263, 382-410` → pillar 3, T-461 (option B) | wave (W6.2) | **Fix in wave** |
| **R101W6-03** | The design's delegation bound misses the certificate-binding path: `certificates:generate` + `certificates:bind` confer a segment's placement without `network:grant`. | **Medium** | `radius-reply-profile-design.md` §5.1, §5.3, §4.3 → T-461 | wave (W6.1) | **Fix in wave** (text) |
| R101W6-04 | The fetch script's "never install a list the trusted CA did not sign" does not hold: `openssl crl -verify` exits 0 on a signature failure when the issuer name matches (probed, OpenSSL 3.0.13). Fail-closed, but a forged same-name list replaces the genuine one and refuses the whole tenant; the test never runs the step. | Low | `freeradius.md:311-330`, `radius_e2e.rs:836-850` | wave | Reported |
| R101W6-05 | The guide says `ca_path_reload_interval` re-reads only the lists; FreeRADIUS rebuilds the whole store and re-reads `ca_file` too. A **removed** `ca.pem` makes every reload fail and keeps the old trust live until a restart. | Low | `freeradius.md:146-152, 376-377`; `tls.c:595-623, 3558-3585` | wave | Reported |
| R101W6-06 | The stated revocation lag omits HTTP caching (`Cache-Control: public, max-age` up to half `nextUpdate`, 12 h by default); the note's §6.3 states a different, looser bound than the guide. | Low | `freeradius.md:337-367`; `crl.rs:46-53, 114-117`; note §6.3 | wave | Reported |
| R101W6-07 | The RadSec block's client has no `require_message_authenticator = yes` (spike §4.2: "RadSec classic: same"), and the guide never tells the operator the NAS must require and verify the attribute in responses — the other half of the Blast-RADIUS mitigation. | Low | `freeradius.md:221-236, 386-421` → T-449 | wave | Reported |
| R101W6-08 | The key re-encoding snippet leaves the device's raw Ed25519 seed in `seed.bin`, mode `0644` under the default umask (probed), and never removes it. | Low | `freeradius.md:109-114` | wave | Reported |
| R101W6-09 | Modelling: four Mitigated entries sit on elements still flagged out of scope as "the specification any future build starts from"; T-450 and T-462 stay Not applicable although the shipped recipe exhibits their residuals. | Low | `Axiam.json` (§5.10 elements), STRIDE §5.10 | wave (W6.2) | Reported (W7.3, maintainer) |
| R101W6-10 | T-453's correction (the RFC 5080 cache key) is found and deferred, not recorded in the entry's text as §9 asks. | Low | STRIDE `:4475-4480` and copies → T-453 | wave | Reported (W7.3) |
| R101W6-11 | T-454's named test does not test its mitigation: the e2e pulls the digest but asserts nothing about vendoring; the crate half is held by `cargo-deny`'s licence list, which the entry does not cite. | Low | T-454 (all copies), `deny.toml:121ff` | wave | Reported |
| R101W6-12 | `subject_common_name` accepts any bare subject without `=`: control characters, newlines, runs of whitespace, `DEFAULT`. The root of R101W6-02, and a hazard for any consumer that renders a CN into configuration. | Low | `crates/axiam-pki/src/subject.rs:30-55` | pre-existing, made reachable | Reported (`1.0.x`) |
| R101W6-13 | The workflow's path filter misses files the e2e depends on (`axiam-pki/src/crypto.rs` — the key encoding the test re-encodes byte for byte — `subject.rs`, the route table). | Informational | `radius-e2e.yml:31-44` | wave | Reported |
| R101W6-14 | The workflow has not run; the plan's oracle ("the five `eapol_test` cases green in the workflow") rests on the executor's local run. | Informational | `radius-e2e.yml`; plan D-7 | wave | Gate item (W7.1 / W7.5) |
| R101W6-15 | AXIAM's Ed25519 private keys are PKCS#8 v2, which OpenSSL 3.0 cannot read (confirmed by probe). Every OpenSSL-3.0 client of an AXIAM Ed25519 leaf needs the guide's workaround. | Informational | `axiam-pki` key encoding | pre-existing | Reported (`1.0.x`) |
| R101W6-16 | Stale or inconsistent copies: `security.ts` still says nothing on the RADIUS diagram is built and all its entries are not applicable; `FINDINGS.md` attributes 476 / 442 / 17 / 17 to `Axiam.json`, which holds 477 / 443 / 17 / 17; the area title says "not built" over four Mitigated entries. | Informational | `website/src/security.ts:120,136,624`; `docs/compliance/FINDINGS.md:37` | wave / W7.3 | Reported (W7.3) |
| R101W6-17 | The placement table writes `Tunnel-Private-Group-Id` without an explicit tag while the guide and the note say "tag 0"; the wire encoding is unasserted. | Informational | `freeradius.md:260-283`, note §3.2 | wave | Reported (not verified) |

The points of the brief that are **not** findings: the workflow is safe (§3); the
image is pinned by a digest that is the tag's manifest and nothing of FreeRADIUS is
vendored (§4); a missing server is a failure (§3); the shipped configuration has no
default secret and fails closed on an empty one (§5); T-449, T-456 carry tests that
exercise their mitigations (§6); the note meets R17's four clauses for profile
writes and its RFC corrections are right (§8); T-449's correction is dated in its
own text (§7); the threat-model arithmetic differs only by T-477 (§9).

---

## 1. What was reviewed, and how

| Question of the brief | Where answered |
|---|---|
| Does every flipped threat carry a test that exercises its mitigation? | §6 (T-449, T-456 yes; T-459 R101W6-01; T-454 R101W6-11) |
| Does the workflow make a missing server a failure and run the five cases? | §3 |
| Is the workflow safe (permissions, SHA pins, secrets, trigger, paths)? | §3, R101W6-13 |
| Is the image pinned by digest; is nothing of FreeRADIUS vendored? | §4 |
| Does the guide's security wording match spike §4.2? | §2, R101W6-04 … 08 |
| Are shipped configs safe defaults? | §5, R101W6-02 |
| Does the test leak keys or leave containers? | §5 |
| Does the note meet R17 / T-461; are its RFC corrections right? | §8, R101W6-03 |
| Are dated corrections recorded as corrections? | §7, R101W6-10 |
| The four out-of-scope elements, and the 442 / 476 vs 443 / 477 arithmetic | §9, R101W6-09, R101W6-16 |

---

## 2. The guide against spike §4.2 and B-2

| Spike §4.2 / B-2 item | The guide | Verdict |
|---|---|---|
| TLS 1.3 only | `tls_min_version = tls_max_version = "1.3"` (`eap:49-50`); a 1.2 fallback named "a deliberate downgrade" (`freeradius.md:186-192`). EAP-TLS passes `allow_tls13 = true` (`rlm_eap_tls.c:111`), so the FAST/PEAP clamp to 1.2 (`tls.c:635-657`) does not apply. | Holds; tested |
| EAP-MD5, CHAP, MS-CHAP off; a NAK is a refusal | only `tls` defined, `ignore_unknown_eap_types = no`, `default` rejects anything without `EAP-Message` | Holds; EAP-MD5 tested |
| `require_message_authenticator` on every client | per client in `clients.conf:21,30`, and globally advised (`security { }`, confirmed as the section in `radiusd.conf.in:547, 786`); "auto switches itself off" matches `radiusd.conf.in:739-745`; "`limit_proxy_state` ignored with `yes`" matches `:798-800` | Holds for UDP; the RadSec client lacks it and the NAS side is unstated (**R101W6-07**) |
| Response carries `Message-Authenticator`, first | FreeRADIUS's own (`src/lib/radius.c:1932-1936`) | Holds (not asserted by the test, said so in T-449) |
| `MS-MPPE-*` on UDP is the weakest profile, RadSec preferred | §"RadSec" explains the MD5 obfuscation and the key recovery; RadSec "where the NAS allows", untested, said so | Holds as wording. RADIUS/1.1, which B-2 also lists, is declined without a reason (FreeRADIUS 3.2.8 has it only under the compile-time `WITH_RADIUSV11`, `listen.c:894`) — not a finding |
| Fixed `radsec` secret is no secret | `freeradius.md:419-421`, RFC 6614 §2.3 item 4 (read) | Holds |
| CRL refresh and the lag | four steps, fetch + 300 s + `Session-Timeout`; the reload is lazy, at the first new conversation after the interval (`tls.c:595-623`, read) — the guide says exactly that; `allow_expired_crl` default `no` makes an expired list fail closed (`tls.c:3188-3194`) | Holds, except caching (**R101W6-06**) and what the reload re-reads (**R101W6-05**) |
| Tenant boundary | the tenant signing CA as the only anchor; FreeRADIUS sets `X509_V_FLAG_PARTIAL_CHAIN` on every store it builds (`tls.c:3581-3583, 4066-4067`), so a chain ending at a non-self-signed anchor verifies, and the organization CA is not needed; "one tenant per trust anchor" stated | Holds as configuration; the test does not run the shared-root case (**R101W6-01**) |
| A revoked signing CA | stated as not noticed, with the reason (`check_all_crl` would need the organization CA's list and the organization CA as the CRL issuer, which a partial chain does not contain) | Holds; W6.2's finding (2) is right |
| Wrong CA | "`unable to get local issuer certificate`", asserted for both foreign devices | Holds for the cases built |

---

## 3. The workflow

* **Trigger and permissions.** `pull_request` (not `pull_request_target`) and
  `workflow_dispatch`; `permissions: contents: read`; no `secrets.` reference; no
  output of the PR's code reaches a privileged context. Same shape as
  `directory-e2e.yml`.
* **Pins.** `actions/checkout@3d3c42e5…`, `dtolnay/rust-toolchain@7e38f4b4…`,
  `Swatinem/rust-cache@6323deb1…` — the same SHAs `directory-e2e.yml` pins.
* **A missing server is a failure.** With `AXIAM_E2E_RADIUS=1`, `gate()` asserts
  that `docker`, `openssl` and `eapol_test` can be spawned (`radius_e2e.rs:104-140`);
  `Stack::up` asserts `docker compose up -d --wait` succeeded and prints the
  container log when it did not (`:243-256`); the workflow also has its own
  `command -v eapol_test` step and a pull step that exits 1 after four attempts.
  A spawn check alone would pass with `docker` present and its daemon down, but
  `up` then fails, so no path skips.
* **The five cases.** issue (`:989-1012`: clientAuth and the CRL distribution
  point asserted), bind (`:1014-1027`: exactly the bound devices listed), accept
  (`:1059-1090`: the five reply attributes asserted), wrong CA (`:1092-1122`; see
  R101W6-01), revoked after the refresh (`:1171-1284`: still admitted while the
  old list is held, refused with `certificate revoked` after, and another device
  still admitted). The refresh in CI is the reload interval, not a restart
  (`AXIAM_E2E_RADIUS_REFRESH` is unset), which is the mechanism the guide
  recommends.
* **Path filter.** Present and on the recipe; gaps are R101W6-13. The header's
  argument that a non-required check may use a workflow-level `paths:` holds.
* **Teardown.** `if: always()` brings the stack down with `-v` when the env file
  exists; the test's `Drop` does the same unless `AXIAM_E2E_RADIUS_KEEP=1`.

---

## 4. The image and the licence

* `freeradius/freeradius-server:3.2.8@sha256:af6fd34a5b7826b6245008732f43fbc0432eb23d23e5de7106371b2941e70a4b`.
  Docker Hub's tag record for `3.2.8` gives that digest, for its only image
  (`linux/amd64`), as the compose comment says. The workflow pulls the string the
  compose file names, so tag and digest cannot drift apart in CI.
* Nothing is vendored. `docker/radius/raddb/` holds five short files (7 to 53
  non-empty lines) written for the recipe; their comments and structure are not
  the upstream `raddb` files' (which `COPYRIGHT` §3.1 puts under GPLv2). There is
  no Dockerfile, no `FROM`, no FreeRADIUS source and no RADIUS crate in
  `Cargo.lock`. The guide's RadSec block is a dozen setting lines in the shape of
  `sites-available/tls`, which is configuration vocabulary, not a copy.

---

## 5. Shipped configuration, and the test's hygiene

* **No default secret.** `clients.conf` reads `$ENV{RADIUS_SHARED_SECRET}`; the
  image's own `clients.conf` (with `testing123`) is mounted over. An unset
  variable expands empty and FreeRADIUS refuses to start ("secret must be at
  least 1 character long", `client.c:1119-1146`) — fail closed. A one-character
  secret is accepted; T-466 stays Not applicable and says so.
* **`e2e-nas` is a /24 and `e2e-local` is loopback**, both commented as test-only
  ("in production list each NAS by its own address"; "Drop this client in
  production"). A copy-paste deployment keeps a /24 of the compose network, which
  is not a routable production range. Acceptable.
* **`default`**: EAP or reject; `Post-Auth-Type REJECT` runs
  `attr_filter.access_reject`, so a reject carries no reply attributes.
* **`check-eap-tls`**: `if (!ok) { reject }` also covers `rlm_files` answering
  `noop` when nothing matched (`rlm_files.c:458`). An empty key is looked up as
  `NONE` (`rlm_files.c:375`), so a certificate without a CN matches an entry named
  `NONE` — part of R101W6-02's fix.
* **`cache { enable = no }`** sets `allow_session_resumption = false`
  (`tls.c:863`). Holds.
* **`-X` in the compose file** logs every attribute of an Accept, the
  `MS-MPPE-*` keys included, to a CI log. They are per-run keys of a throwaway
  session; the compose comment says to run `-f -l stdout` in production. Not a
  finding.
* **Keys.** Device keys, the server CA key and the server key are written under
  `docker/.secrets/radius/` (gitignored, `.gitignore:34`) and left there after
  the run (the directory is wiped at the *start* of the next run). The shared
  secret is passed to `eapol_test` on its command line (`-s`). Both are per-run
  throwaways on an ephemeral runner; locally they sit in a gitignored directory.
  Not a finding. No key or secret is committed (`git ls-files docker/.secrets`
  is empty; the only `BEGIN PRIVATE KEY` in the diff is the re-encoder's header
  string).
* **Containers.** `up` runs `down -v` first (an aborted run's fixed address);
  `Drop` runs on unwinding; the workflow tears down on `always()`. Only a killed
  local process leaves the stack up, and the next run removes it.

---

## 6. The four flips against §6 and §7

| Entry (risk) | Spike requirement | Test | Verdict |
|---|---|---|---|
| **T-449** (R2) | `Message-Authenticator` required in every request, present in every response | `bare_access_request` (`:417-440`) sends a `User-Name`-only request from the listed client and asserts no answer and FreeRADIUS's own "does not contain required Message-Authenticator" (`src/lib/radius.c:2863`). Without `yes` the same request would draw an Access-Reject from `default`, so the assertion distinguishes. | **Exercised.** Responses and the forged-attribute case unasserted, and the entry says so. RadSec and the NAS side: R101W6-07 |
| **T-456** (R15) | EAP allow-list `TLS`; TLS 1.3; no RADIUS/1.1 fallback | TLS 1.2-only supplicant refused with `protocol_version`; EAP-MD5 answered with EAP-Failure | **Exercised.** RADIUS/1.1 does not arise, said so |
| **T-459** (R9) | a valid certificate under tenant B's signing CA, of the **same organization CA**, refused through tenant A's server | the "same organization" device's signing CA is under a different, freshly minted root | **Not exercised as named** (**R101W6-01**) |
| **T-454** (R25) | reference, do not ship; review any crate | the e2e pulls the digest the compose file names | **The named test does not test "vendors nothing"** (**R101W6-11**) |

T-459's mitigation is right by reading: with `PARTIAL_CHAIN` the store must contain
some certificate of the chain, and a foreign tenant's leaf chains through a signing
CA and a root that are not in `ca.pem`. The finding is that the test, which §9 makes
the entry's admission ticket, runs a weaker case than the one the entry and the
guide describe.

---

## 7. Corrections recorded as corrections

* **T-449**: "**Corrected 2026-10-13 (W6.1's re-read, RFC 2865 §5.33):** this entry
  said that `Proxy-State` in a request is refused …", and the option-A paragraph
  now reads "`Proxy-State` is returned unmodified, as RFC 2865 §5.33 requires, not
  refused (corrected 2026-10-13, above)". Dated, in the entry's own text, in
  `Axiam.json` and the STRIDE copy. Holds.
* **T-453**: the W6.2 note says "The text correction W6.1 found (the cache key) is
  left for the model reconciliation (W7.3)"; the requirement still reads
  "(NAS, Identifier, Request Authenticator)" (`threat-model-stride.md:4480`).
  R101W6-10.
* The guide carries no dated correction and needs none (it is new).

---

## 8. The design note (W6.1)

**R17 / T-461's four clauses, for profile writes:** the attribute set is a closed,
typed, versioned dictionary with every attribute bounded (§3.2–§3.4) — met; the
profile's own permission `network:profiles_write` (H1) and an audit row for every
write *and* refusal (§5.4) — met; quarantine by an inherited deny on a fixed
two-branch tree that an allow cannot undo (§4.4, against `deny-override-design.md`
§2.1 and §2.2 row 4) — met, and the reserved subtree and the generic routes'
refusal of `network_*` types close the "move it out from under the deny" path;
"cannot grant more than its writer holds" — defined (H1–H6) and extended to the
role-assignment side (§5.3) — met **except** the binding path (**R101W6-03**).

**The eleven claims.** Every verdict I could check holds against the RFC copies:
1h (RFC 3580 §3.31, the decimal string, 1–4094, tag zero) — `rfc3580.txt:767-801`;
1j (RFC 5080 §2.2.2: matched on "source address, source port, RADIUS Identifier,
and receiving socket", a differing Request Authenticator purges, invalid
`Message-Authenticator` packets "MUST NOT affect the cache") — `rfc5080.txt:546-575`;
5b (RFC 2865 §5.33: `Proxy-State` "MUST be returned unmodified") —
`rfc2865.txt:2932-2949`, and FreeRADIUS's `limit_proxy_state` text —
`radiusd.conf.in:789-840`; 6 (silent discard, port 1812, "at least 16 octets", "MUST
NOT be empty", TCP/2083) — `rfc2865.txt:298, 868-871`, `rfc6614.txt:244`; 2 ("MUST
be "radsec"") — `rfc6614.txt:372`; the dictionary lines of §3.2 — FreeRADIUS
`dictionary.rfc2865` / `.rfc2868`, all eight exact. 5a is right to stay
"reference implementation's practice" (`src/lib/radius.c:1932-1936`). One nuance
on 1j: a duplicate still requires an *equal* Request Authenticator (a different
one purges the entry), so the spike's key was short of source port and receiving
socket rather than wrong to include the authenticator; the correction's substance
stands. RFC 9765, 9190 and 5216 were unreachable here too (`rfc-editor.org` 403),
so claims 3 and 8 stay as the note left them.

**The checklist (§11)** is honest about what is deferred to D4. §6.3's latency
table disagrees with the guide (R101W6-06).

---

## 9. Threat-model copies and arithmetic

* `Axiam.json` before the wave: 477 entries, 439 / 17 / 21; after: 477, 443 / 17 / 17.
  The four status changes are exactly T-449, T-454, T-456, T-459 (a title-keyed
  diff of the two files).
* The prose copies (STRIDE header, the write-up, `FINDINGS.md`) said 476, 438 / 17 / 21
  and now say 476, 442 / 17 / 17. The only difference from the JSON is **T-477**
  (W2, Mitigated), present in `Axiam.json` and in the STRIDE table
  (`threat-model-stride.md:1694`) but not in the prose totals — before and after
  this wave. So the arithmetic delta is that one entry; W7.3 reconciles it.
* `node website/scripts/gen-threat-model.mjs`, run on a copy of the tree, produces
  `threatModel.ts` and `threatModelSummary.ts` byte-identical to the committed ones
  (477, 443 / 17 / 17).
* **The out-of-scope elements.** All four flipped entries sit on elements whose
  `reasonOutOfScope` still reads "Not built … this element and its threats are the
  specification any future build starts from". Each entry now carries both halves,
  "Mitigated for option B" and "Option A, unchanged and not built". That is
  readable, but the model loses the property its §2 states for these entries —
  that the commit which builds an element moves them — because they already read
  Mitigated. My judgement is that the recipe deserves its own element, a
  "FreeRADIUS (operator-run, option B)" process outside AXIAM's boundary, carrying
  the four option-B mitigations, with T-449 / T-454 / T-456 / T-459 back to Not
  applicable for option A (R101W6-09). It is a W7.3 or maintainer decision; it
  changes the counts by four.

---

## 10. Documentation and CHANGELOG claims

* The CHANGELOG entry matches the diff, says AXIAM speaks no RADIUS and D4 is not
  in 1.0.1. The authentik row reads "recipe, not native", as the plan asks, and the
  history row removes the stale "no CRL" caveat with a date.
* `website/src/docs/operate.ts` links the guide from the PKI section; the PKI
  README links it from the CRL section.
* The guide's statement of the lag is the strongest part of it, and the honest
  "not covered" paragraph (RadSec, other supplicants, a proxying NAS, the session
  step, performance) is right.
* The guide's "Last verified 2026-10-13 against FreeRADIUS 3.2.8 and wpa_supplicant
  2.10" rests on the local run (R101W6-14).

---

## 11. Checks run

| Check | Result |
|---|---|
| `docker compose -f docker/docker-compose.radius.yml config` (dummy secret) | valid; the mounts and the fixed address resolve as described |
| YAML parse of the workflow and the compose file | valid |
| Docker Hub `v2/repositories/freeradius/freeradius-server/tags/3.2.8` | digest `sha256:af6fd34a…` = the compose file's; one image, `linux/amd64` |
| `gen-threat-model.mjs` on a copy | byte-identical output |
| Status diff of `Axiam.json` at `55c3e3072` and `b8fa66fbd` | four changes, T-449 / 454 / 456 / 459 |
| Probe: `openssl crl -verify` (OpenSSL 3.0.13), a CRL from a *different-name* CA | "Error getting CRL issuer certificate", **exit 1** |
| Probe: the same, a CRL signed by a *same-name* CA with another key | "**verify failure**", **exit 0** (R101W6-04) |
| Probe: OpenSSL 3.0.13 reading an RFC 8410 PKCS#8 v2 Ed25519 key (83 bytes) | "ossl_store_handle_load_result:unsupported" (R101W6-15) |
| Probe: the guide's `sed … | tail -c +17 | head -c 32` re-encoder on that key | produces a key with the same public key; output `0600`; `seed.bin` left at `0644` (R101W6-08) |
| FreeRADIUS `release_3_2_8` sources read | `tls.c`, `listen.c`, `client.c`, `src/lib/radius.c`, `rlm_files.c`, `rlm_eap_tls.c`, `radiusd.conf.in`, `mods-available/eap`, `sites-available/tls`, `clients.conf` |
| Not run | the e2e (no `dockerd`, no cargo build on the shared disk); the workflow (never dispatched) |

---

## 12. Issue bodies

### R101W6-01 (Medium) — the "same organization" wrong-CA case does not share the organization CA

`radius_e2e.rs::signing_ca` (`crates/axiam-server/tests/radius_e2e.rs:631-689`)
issues a new organization CA (`POST …/ca-certificates`, subject "`{subject} root`")
on every call, so `line1` and `line2` (`:990-991`) are signing CAs of the same
organization under **two different roots**. The wrong-tenant case (`:1093-1106`)
therefore proves the same thing as the wrong-organization case: a chain to a root
the server does not hold is refused. The case T-459 names ("chains to the same root
but to a CA this server does not hold"), the guide claims (`docs/pki/freeradius.md:133-138`:
"under the same root … The end-to-end test issues such a device and checks exactly
that") and spike R9 describes (the organization CA is shared, so a chain check
alone does not separate tenants) is not run. The supplicant's `client_cert` holds
the leaf only (`:361`), so the case where the peer supplies its whole chain —
what an attacker in another tenant would send — is not run either.
**Proposed fix:** issue one organization CA per organization and both of Plant A's
signing CAs beneath it; write `gate-03`'s `client_cert` as leaf + line-2 signing CA
+ the shared root; assert refusal with `unable to get local issuer certificate`;
add the positive control that `press-07` presenting leaf + line-1 CA + root is
still admitted. Re-word T-459's test sentence in the four copies to describe what
then runs.

### R101W6-02 (Medium) — a `DEFAULT` subject makes the generated placement table place every certificate

The guide's third pillar is "a valid certificate is not enough"
(`docs/pki/freeradius.md:53-55, 245-296`), and it tells the operator to build the
placement table from `GET /api/v1/certificates` — bound, active `Device`
certificates — "exactly" as the test does: by writing the `subject` as the `files`
entry key (`radius_e2e.rs:807-830`). FreeRADIUS's `files` module treats an entry
named `DEFAULT` as matching every key and walks entries in file order
(`src/modules/rlm_files/rlm_files.c:263, 382-410`, `release_3_2_8`). AXIAM accepts
`DEFAULT` as a subject (`crates/axiam-pki/src/subject.rs:30-55` refuses only `=`,
and `,` / `+` after a `CN=` prefix). A holder of `certificates:generate` and
`certificates:bind` who issues and binds one certificate with subject `DEFAULT`
makes the next generated table admit every certificate the tenant CA issued —
bound or unbound, listed or not — and, if that entry is earlier in the file than a
device's own, puts that device on its VLAN instead. A bare subject with spaces
or a newline (accepted) breaks the file's parse or injects a further entry
(`x\nDEFAULT`). A certificate with no CN is looked up as `NONE` (`rlm_files.c:375`).
**Proposed fix:** the guide's default key becomes `TLS-Client-Cert-Serial`
(AXIAM-generated, not chosen by the issuer) — it already documents that option; a
CN key is allowed only through a generator that requires
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, refuses `DEFAULT` and `NONE` case-insensitively,
writes nothing when a subject fails, and alerts. The test's generator does the
same, and a new case binds a certificate with subject `DEFAULT` and asserts the
unbound `press-08` is still refused. Name the residual in T-461's option-B
sentence.

### R101W6-03 (Medium) — the delegation bound misses the certificate-binding path

`claude_dev/radius-reply-profile-design.md` §5.3 holds the role-assignment side to
`network:grant` because "a profile is inert until a device may join its segment,
and joining is a role assignment". Placement (§4.3 step 1) is decided for "the
service account the presented certificate is bound to", and that binding is a
second way to confer it: `POST /service-accounts/{id}/bind-certificate` checks
only `certificates:bind` on `Uuid::nil()` (`crates/axiam-api-rest/src/handlers/certificates.rs:527`),
and issuance only `certificates:generate` (`:168, :292`). A certificate
administrator without any `network:` permission can issue a certificate for a
device they hold and bind it to a service account that already holds `network:join`
on a privileged segment — or re-bind that account — and the device is placed.
**Proposed fix (text, in-wave):** add to §5.3 a row "bind a certificate to, or
issue one bound to, a service account that holds any `network:join` allow at `N`:
`W` holds `network:grant` at every such `N`"; add bind and issuance to §5.1's
enumerated write paths and to H6's spirit (a device cannot bind itself); add the
binding path to the §11 checklist's T-461 row and to residual 7's scope.

### R101W6-04 (Low) — the fetch script's signature check does not stop a forged list

`docs/pki/freeradius.md:321-322` runs `openssl crl -in crl.pem -CAfile ca.pem -noout
-verify` under `set -eu` as "Never install a list the trusted CA did not sign".
OpenSSL 3.0.13 prints `verify failure` and **exits 0** when the list's issuer name
matches `ca.pem` but its signature does not (probed); only a different issuer name
exits 1. A list forged under the CA's name — by whoever can answer the fetch: a
TLS-intercepting proxy, a compromised mirror — is installed over the genuine one.
FreeRADIUS then fails the CRL signature on every handshake and refuses the whole
tenant (fail closed, an outage, and the genuine revocations are gone from disk).
The test's `refresh_crl` (`radius_e2e.rs:836-850`) skips the step, so the guide's
line is untested.
**Proposed fix:** `out=$(openssl crl -in "$tmp/crl.pem" -CAfile … -noout -verify 2>&1)`
and `[ "$out" = "verify OK" ] || exit 1`; also refuse a list whose CRL number is
lower than the installed one (the guide already says to); ship the script as a file
(`docker/radius/fetch-crl.sh`) and have the test run it.

### R101W6-05 (Low) — `ca_path_reload_interval` re-reads `ca_file` too; a removed `ca.pem` keeps the old trust

The guide says "The file is read at start-up, and the lists are the only thing the
interval re-reads" (`docs/pki/freeradius.md:376-377`). FreeRADIUS 3.2.8 replaces the
store with `fr_init_x509_store(conf)` (`src/main/tls.c:595-623`), which calls
`X509_STORE_load_locations(store, ca_file, ca_path)` (`:3558-3585`): a replaced
`ca.pem` takes effect at the next reload. A **removed** (or unreadable) `ca.pem`
makes that call fail; FreeRADIUS logs "Error replacing X509 store" and keeps the old
store — still trusting the removed CA — and retries at every new conversation until
a restart. The guide's instruction (§2: "remove or replace `ca.pem` and restart") is
the safe one; its reason is wrong.
**Proposed fix:** "the reload re-reads `ca_file` and the lists; replace `ca.pem`
atomically (`mv`), never delete it without a restart, and treat a logged store
replacement error as the old trust still in force".

### R101W6-06 (Low) — the revocation lag omits HTTP caching; the note states a different bound

The CRL route answers `Cache-Control: public, max-age=` up to the next scheduled
re-sign, at most half `nextUpdate` (`crates/axiam-api-rest/src/handlers/crl.rs:46-53,
114-117`; 12 h with the default day). A fetch job behind a caching proxy or CDN can
be served the pre-revocation list for that long. The guide's step 2 ("At most the
fetch interval", `docs/pki/freeradius.md:344`) and its total (`:356-358`) assume a
direct fetch. The design note's §6.3 table gives the 1.0.1 column as "CRL refresh
(`nextUpdate` ≤ 1 day by default) + `Session-Timeout`", which is neither the
guide's figure nor the mechanism (AXIAM publishes at once; the fetch cadence sets
the lag).
**Proposed fix:** the guide says to fetch AXIAM directly or through a cache told
`no-cache`, and adds "+ any shared cache's `max-age`" to the bound; the script sends
`If-None-Match` as the text recommends; the note's §6.3 cell reads "fetch interval +
`ca_path_reload_interval` (≥ 300 s) + `Session-Timeout`", with a dated correction.

### R101W6-07 (Low) — RadSec client without `require_message_authenticator`; the NAS side unstated

The guide's rule is "`require_message_authenticator = yes` on every client"
(`docs/pki/freeradius.md:223`), and spike §4.2 requires it on classic RadSec
("RadSec classic: same"), but the RadSec block's `client nas-line-1`
(`:402-408`) omits it; only the global setting the guide also recommends would
cover it. Separately, the guide states the server half of the Blast-RADIUS fix and
not the client half: the NAS must be on firmware that sends the attribute and
**requires and verifies** it in Access-Accept / Reject / Challenge (spike §4.1:
"the client include … and the server require it").
**Proposed fix:** add the line to the RadSec client; add one bullet: "Check that
each NAS's firmware has the Blast-RADIUS fix and requires `Message-Authenticator`
in responses; FreeRADIUS sending it protects nothing on a NAS that does not check
it."

### R101W6-08 (Low) — the re-encoding snippet leaves the private seed on disk

`docs/pki/freeradius.md:111-113` writes the device's 32-byte Ed25519 seed to
`seed.bin` and never removes it; with the default umask `022` the file is `0644`
(probed). The private key is "in this response and nowhere else" (`:75`), and the
recipe copies it into a world-readable scratch file.
**Proposed fix:** `( umask 077; … )` and a pipe without the intermediate file, e.g.
`{ printf '…'; sed '/^-----/d' press-07.key.pem | base64 -d | tail -c +17 | head -c 32; } | openssl pkey -inform DER -out press-07.key`,
then remove the version-2 file once the device holds its key.

### R101W6-09 (Low) — modelling: Mitigated entries on not-built elements; T-450 and T-462 left Not applicable

The four flipped entries stay on elements flagged `outOfScope` with the reason
"Not built … the specification any future build starts from". A future option-A
build starts from entries that already read Mitigated, so the model's rule that
"the commit that builds an element moves its entries" no longer fires for them.
Conversely T-450 (the EAP-TLS keys under MD5 obfuscation on UDP — the recipe's
only tested transport) and T-462 (a revoked device keeps its port for fetch + 300 s
+ `Session-Timeout`) describe residuals the shipped recipe exhibits, yet stay Not
applicable, a status the model defines as "not exposed".
**Proposed fix (W7.3, maintainer decision):** add a "FreeRADIUS (operator-run,
option B recipe)" process outside AXIAM's boundary carrying the four option-B
mitigations (and T-450 / T-462 for the recipe as Open, accepted, with the guide's
bound), and return T-449 / T-454 / T-456 / T-459 to Not applicable for option A —
or keep the current shape and add an explicit "Option A status: Not applicable"
sentence to each, and say in §5.10 why T-450 / T-462 stay Not applicable.

### R101W6-10 (Low) — T-453's correction deferred

W6.1 found T-453's duplicate-cache key short of RFC 5080 §2.2.2 (source address,
source port, Identifier, receiving socket; a differing Request Authenticator purges;
a failing `Message-Authenticator` must not touch the cache). The plan's §9 records a
correction "dated, in the entry's own text"; T-453 got a 1.0.1 sentence that defers
it ("left for the model reconciliation (W7.3)", `claude_dev/threat-model-stride.md:4480`),
and the requirement still reads "(NAS, Identifier, Request Authenticator)".
**Proposed fix:** a "**Corrected 2026-10-13 (W6.1's re-read, RFC 5080 §2.2.2)**"
sentence in T-453 in the four copies, in T-449's shape.

### R101W6-11 (Low) — T-454's named test does not test "vendors nothing"

T-454 names `radius_e2e.rs` as its test: it pulls the digest and runs. Nothing it
asserts would fail if FreeRADIUS sources or a built image entered the tree, or if a
RADIUS crate entered `Cargo.lock`. The crate half is in fact held by `cargo-deny`'s
licence allow-list (`deny.toml:121ff`; a GPL crate fails unless named), which the
entry does not cite.
**Proposed fix:** cite `cargo-deny` (licences) for the crate half; add to the
Architecture Invariants job a check that `docker/radius/` contains no Dockerfile
and no `FROM`, and that the compose file's `image:` carries `@sha256:`; name both as
T-454's tests.

### R101W6-12 (Low) — certificate subjects accept control characters and whitespace

`subject_common_name` (`crates/axiam-pki/src/subject.rs:30-55`) returns any trimmed
bare subject that contains no `=`: newlines, tabs, other control characters and
internal runs of spaces pass, as do `DEFAULT` and `NONE`. AXIAM itself is not hurt,
but every consumer that renders a CN into configuration (the recipe's placement
table, R101W6-02; `files` users, ACL files, log lines) inherits it.
**Proposed fix:** refuse control characters (`char::is_control`) and require a
printable subject of bounded length; consider documenting a recommended device-name
pattern. Test: a subject with `\n` or `\t` is `400`.

### R101W6-13 (Informational) — the workflow's path filter misses files the e2e depends on

`radius-e2e.yml:31-44` filters on the CRL, cert, CA and three handler files. The
e2e also depends on `crates/axiam-pki/src/crypto.rs` (the PKCS#8 encoding the test
re-encodes byte for byte, `radius_e2e.rs:697-730`), `subject.rs`, and the route table
and limiter in `crates/axiam-api-rest/src/server.rs`. A change there does not run
it. **Proposed fix:** add those paths.

### R101W6-14 (Informational) — the workflow has not run

The plan's W6.2 oracle is "the five `eapol_test` cases green in the workflow". The
workflow has never been dispatched; the evidence is the executor's local run.
**Proposed fix:** dispatch under D-7 before W7.5, or let the release PR's
`pull_request` run (the workflow file is in its own path filter) and treat a red
run as blocking.

### R101W6-15 (Informational) — Ed25519 keys as PKCS#8 v2 are unreadable by OpenSSL 3.0

AXIAM returns Ed25519 private keys in the RFC 8410 version-2 form (seed + public
key). OpenSSL 3.0.13 refuses it (`ossl_store_handle_load_result:unsupported`,
probed), so every OpenSSL-3.0 client of an AXIAM-issued Ed25519 leaf — not only
`wpa_supplicant` — needs the guide's workaround. **Proposed fix (1.0.x):** return
version 1 by default (it carries the same seed), or add a `key_format` choice; keep
the guide's note until then.

### R101W6-16 (Informational) — stale or inconsistent copies

`website/src/security.ts:136` still says of the RADIUS diagram "Nothing on it is
built, so its threats are recorded not applicable", and `:120, :624` describe not
applicable as the only status there; `docs/compliance/FINDINGS.md:37` attributes
"476 threats, 442 / 17 / 17" to `Axiam.json`, which holds 477 / 443 / 17 / 17 (T-477;
pre-existing off-by-one); the summary's area title "RADIUS front end — not built"
now covers four Mitigated entries. **Proposed fix:** W7.3.

### R101W6-17 (Informational) — `Tunnel-Private-Group-Id` tag

The guide (`docs/pki/freeradius.md:278-280`) and the note (§3.2) require tag `0`
(RFC 3580 §3.31); the placement table writes `Tunnel-Private-Group-Id = "20"` with no
tag, and the test asserts only the attribute's presence. Whether FreeRADIUS emits a
zero tag octet for an untagged `has_tag` string was not verified here. **Proposed
fix:** write `Tunnel-Private-Group-Id:0 = "20"` (and `:0` on the two integers), or
assert the octets in the e2e.

---

## 13. Invariants

* **No AXIAM surface is added.** The wave adds no route, schema, permission or
  setting; AXIAM speaks no RADIUS. The CRL route it consumes is unchanged.
* **No secret or key is committed**; the recipe has no default secret and fails
  closed on an empty one.
* **Fail-closed where it matters**: a missing or expired list refuses every device;
  an unplaced device is refused; an empty secret stops the server — except the
  placement table's `DEFAULT` key (R101W6-02).
* **GPLv2**: nothing of FreeRADIUS is in the tree; the image is referenced by digest.
* **Threat model**: 477 entries in `Axiam.json`, 443 / 17 / 17; the prose copies one
  behind (T-477) as before the wave; version 2.40.0 left for W7.3; T-459 rests on a
  test that does not run its case (R101W6-01).
