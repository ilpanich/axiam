# Security review — release 1.1.0, wave W5 (F4)

**Date:** 2026-10-15.
**Against:** `claude/release-1.1.0-w5`, the whole wave diff `3d011573e..63fc3d7d2`
(4 commits, 10 files, 1 073 lines added and 90 removed): `384d2c772` (W5.1, #643,
`docker/radius/fetch-crl.sh`), `8a91f9c38` (W5.2, #644 … #647, the guide),
`d215a644b` (W5.3, #648 #650, the vendors-nothing check and the path filter) and
`63fc3d7d2` (W5.4, #652, the tagged VLAN attributes). Every commit carries a
`gpgsig` header (the sandbox has no `allowedSignersFile`, so `%G?` cannot verify).
**Scope:** W5 of the release plan (§6): `docker/radius/**`, `docs/pki/freeradius.md`,
`crates/axiam-server/tests/radius_e2e.rs`, `scripts/check-radius-vendors-nothing.py`,
`.github/workflows/{ci,radius-e2e}.yml`, `claude_dev/radius-reply-profile-design.md`
§6.3, and the threat-model entries the wave edited (T-454, T-462).
**Method:** every commit message and the full diff read; `fetch-crl.sh` run
adversarially under `dash` against a local stand-in server implementing AXIAM's
`If-None-Match` matching (`crates/axiam-pki/src/crl.rs:282-288`), with a CA, a
same-name CA over another key and CRLs of chosen numbers (§11); the guide's
FreeRADIUS claims read in the **`release_3_2_8`** sources (`src/main/tls.c`,
`tls_listen.c`, `listen.c`, `client.c`, `src/lib/radius.c`,
`src/include/libradius.h`) and run in the pinned image
(`freeradius/freeradius-server@sha256:af6fd34a…`, `-XC` and `-X`); the vendors-nothing
check probed with nine synthetic trees; trial merges of this branch against W1 … W4
in a scratch clone. **No cargo was run** (the e2e ran green three times locally and
in CI: `radius-e2e.yml` run **38761953931**, `workflow_dispatch` on `63fc3d7d2`,
**success**). This review fixes nothing.

---

## 0. Summary

**No Critical, High or Medium finding.** The wave does what its rows say: the fetch
script refuses a list forged under the CA's name and an older list the CA signed,
and the e2e runs the script; the guide's reload, cache and Blast-RADIUS text match
FreeRADIUS 3.2.8; T-454 gains a CI check; the tag encoding is now asserted on the
wire. Four Low findings are all in what the wave *added*: the `ETag` revalidation
can be turned into a persistent freeze, overlapping runs can roll a list back, the
`curl` call inherits the operator's `~/.curlrc` and any scheme, and T-454's
correction claims more for the new check than it checks.

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| R110W5-01 | A stored `ETag` is not validated: one answer carrying `ETag: *` (or a list containing `*`) makes every later run send `If-None-Match: *`, which AXIAM's route matches, so the script reads `304 unchanged` and exits 0 **after the attacker has gone**, until the list expires. A 304 is also trusted without checking its `ETag`. Probed. | Low | `fetch-crl.sh:99, 106-118, 159-163`; `crl.rs:282-288` → T-462 | wave (W5.1) | Reported (cheap; may be folded in-wave) |
| R110W5-02 | No lock: two overlapping runs can install the older of two lists after the number check passed (check-then-`mv`), and pair the newer list's `ETag` with it, so the next runs get `304` and keep the older list — a revocation lost for up to half `nextUpdate`, with a fresh file (no staleness alert). | Low | `fetch-crl.sh:139-172` → T-462 | wave (W5.1) | Reported (confirms the executor's follow-up) |
| R110W5-03 | `curl` reads the cron user's `~/.curlrc` (probed: `location` there makes the script follow a redirect it otherwise refuses), takes a `-`-prefixed URL as an option, and accepts any scheme although the guide says "Use HTTPS"; `--max-filesize` is not enforced on unsized bodies before curl 8.4. | Low | `fetch-crl.sh:105-110` | wave (W5.1) | Reported |
| R110W5-04 | T-454's correction says the two tests catch "FreeRADIUS sources or a built image"; the new check skips every binary file and every text file without an upper-case `FROM`, and looks only at `docker/radius/` and one compose file. Probed: sources (text or `.tar.gz`), a `docker save` tarball, an ELF binary, `from debian:12`, a flow-mapping, `include:` or env-overridable `image:` all pass. | Low | `scripts/check-radius-vendors-nothing.py:53-114`; T-454 (both copies) | wave (W5.3) | Reported (confirms and widens the executor's follow-up) |
| R110W5-05 | The guide's RadSec block does not start FreeRADIUS 3.2.8 (`tls_min_version '1.3' must be <= tls_max_version '(null)'`); `require_message_authenticator` on a `proto = tls` client parses but the TLS listener never consults it (`tls_listen.c:719`); W5.2's evidence (`-XC` "prints it") does not show parsing — `-XC` accepts `= bogus`. | Informational | `freeradius.md:547-576` | pre-existing block; wave text | Reported |
| R110W5-06 | `dash` does not run the `EXIT` trap on a signal (probed), so a run killed by cron or a systemd timeout leaves its temporary directory and an `.incoming.*` file in `ca_path`. Harmless to OpenSSL. | Informational | `fetch-crl.sh:58-64` | wave (W5.1) | Reported |
| R110W5-07 | Staleness is left to an mtime alert that measures the wrong thing: a healthy list is replaced only at each refresh epoch (half its lifetime), so "file older than half the lifetime" fires at every epoch boundary; and the script exits 0 on a `304` however old the list is. | Informational | `fetch-crl.sh:113-118`; `freeradius.md:479-481, 530-534` | wave text over 1.0.1 text | Reported |
| R110W5-08 | The fetch request sends no `Cache-Control: no-cache`, so step 2 of the lag holds behind a shared cache only if the operator configures it (the guide says so). One header makes a compliant cache revalidate by itself. | Informational | `fetch-crl.sh:105` | wave | Reported (confirms the executor's follow-up) |
| R110W5-09 | The e2e path filter still misses what the CRL and the bind depend on: `Cargo.lock` (dependabot crypto bumps), `axiam-db/src/repository/{certificate,ca_certificate}.rs`, `axiam-pki/src/{ca_key_store,config,lib}.rs`, `handlers/service_accounts.rs`. | Informational | `radius-e2e.yml:34-49` | wave (W5.3, partial) | Reported |
| R110W5-10 | Stale or inconsistent text: the reply-profile note's §3.2 row for `Tunnel-Private-Group-Id` (`:178`) says tag `0x00` on the wire — **W6's to correct** (D4 renders replies); the guide's reason against a non-zero tag ("one tunnel of several") is imprecise; `radius_e2e.rs:557-560` stacks two doc summaries on `crl_tagged` and leaves `crl` undocumented; W5.3's own deferral (STRIDE `:4409, :4646`, guide `:618`). | Informational | as listed | wave | Reported (W6 / W8.3) |

The brief's points that are **not** findings: the signature check (`verify OK`
exact, exit 0 required, `LC_ALL=C`; any other wording fails closed); the CRL-number
comparison (§2.2); equal-number acceptance, which AXIAM's number design makes
harmless (§2.3); CR/LF or any non-graphic octet in an `ETag` (dropped on read and on
write, probed); temporary-file placement and modes (§2.5); redirects (refused, since
no `-L`); the guide's reload and Blast-RADIUS claims (§3); the tag encoding (§5); the
threat-model copies (§6). The merge with W1 meets **one** conflict, and W1 wins it (§9).

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| 1. `fetch-crl.sh` adversarially (arguments, `set -eu`, temp files, `verify OK`, CRL numbers, `ETag`, curl options, MITM, equal-number replay) | §2; R110W5-01 … 03, 06 … 08 |
| 2. The guide vs FreeRADIUS 3.2.8 (reload, store error, RadSec option, the #647 snippet) | §3; R110W5-05 |
| 3. W5.3's check and the path filter | §4; R110W5-04, R110W5-09 |
| 4. The tag finding and NAS interop; the note's "tag 0x00" | §5; R110W5-10 |
| 5. T-462 ×2, T-454: text vs code, copies agree, T-450 / T-462 stay Open | §6 |
| 6. Merge foresight against W1 | §9 |
| Executors' follow-ups (no lock; `no-cache`; upper-case `FROM` only) | §7 |

---

## 2. `docker/radius/fetch-crl.sh`

### 2.1 Arguments, shell and files

* **Quoting.** Every expansion is quoted; nothing is `eval`ed; `shellcheck -s sh` is
  clean. A URL with spaces or `;$()` reaches `curl` and `openssl dgst` as one argument.
* **`-`-prefixed arguments.** `ca.pem` and `capath` reach `openssl` only as option
  *values* (`-CAfile "$ca_file"`, `-in "$1"`), which is safe; `mktemp "$capath/…"`
  with a `capath` of `-x` would be parsed as an option (fails closed). The URL is
  the last argument to `curl` with no `--url`: `fetch-crl.sh '-K/path' …` makes curl
  read a config file (probed: "no URL specified", exit 1). Operator-supplied, so
  not an attacker's input; folded into R110W5-03.
* **`set -eu`.** Covers the script; the `read` pair is explicitly `|| true`; the
  `key=` pipeline takes `cut`'s status (an `openssl dgst` failure yields the state
  name `.fetch-crl.`, harmless). `hash=$(…)` fails without a message under `-e`
  (exit 1, cosmetic).
* **Temporary files.** `$work` is `mktemp -d` (0700) in `TMPDIR`; the staged list
  and state are `mktemp` in `ca_path` (0600), `chmod 0644`, then `mv` — atomic, and
  a list is public. Cleanup runs on every `exit` path; **not** on a signal under
  `dash` (R110W5-06).

### 2.2 The two checks

* **Signature.** `out=$(openssl crl … -verify 2>&1)`; installed only if the exit
  status is 0 **and** `out` is exactly `verify OK`. Reproduced: on OpenSSL 3.0.13 a
  list signed by another key under the CA's name prints `verify failure`, exits 0,
  and the script refuses it (`not signed by`). OpenSSL 1.1/3.x and LibreSSL print
  `verify OK` on stderr; with `-noout` nothing else is printed; a future wording
  change refuses every list — fail-closed, and the non-zero exit is the alert.
  `LC_ALL=C` is exported (OpenSSL does not localise this text anyway).
* **CRL number.** `openssl crl -noout -crlnumber` prints `crlNumber=0x` + upper-case
  hex octets (`i2a_ASN1_INTEGER`), or `crlNumber=<NONE>`. The script strips `0x`,
  upper-cases, strips leading zeros (`0x0A` → `A`, `0x0080` → `80`), refuses any
  non-hex residue, and compares by length then by `sort` under `LC_ALL=C` (digits
  sort below `A`–`F`, so lexical is numeric at equal length). Probed: `0x0A` vs
  `0x10` refused, `0xFF00` vs `0x10` and `0x10000` vs `0xFF00` installed. **No
  number on the new list:** refused. **None on the installed one:** replaced with a
  warning (only a hand-placed file can lack one; AXIAM always writes it). A negative
  number (`-…`) or one over 35 octets (OpenSSL breaks the line) is refused — RFC 5280
  §5.2.3 caps the number at 20 octets, and AXIAM's is a `u64`.

### 2.3 Equal numbers

Accepted by design. AXIAM's number is `thisUpdate << 24 | entries`
(`crl.rs:682-720`), a function of the list's contents and epoch, and both CA key
types sign deterministically: an equal number is the same list, byte for byte
(`crl_test.rs:1030`), up to the 2^24-entry saturation. Replaying it lengthens the
lag only, which T-462's amendment states. W1.1 (#615) adds that the number can step
back **once** when the interval is changed, and around an epoch boundary when
replicas' clocks disagree; the script then refuses the lower list (exit 1) until the
number passes the held one — safe (a lower number never lacks a revocation, W1's
`docs/pki/README.md` "Changing the interval"), but an alert the guide does not
explain (§9, item 4).

### 2.4 The `ETag` and the request

* Read back from the state only if every octet is `[:graph:]`, and written only
  under the same test: CR, LF, space and control octets are dropped (probed with
  `"a b"`, `"ab"\x01x`), so no header can be injected into the next request or a
  second line into the state file. The installed name is checked as `[0-9a-f.r]`.
* **But the grammar is not checked**: `*` and comma lists pass, and the route
  treats `*` as matching any list (R110W5-01).
* `curl -sS --max-time 20 --max-filesize 16 MiB`, no `-L` (a 3xx is "answered HTTP
  302", exit 1), no `-k` (TLS verified with the system store), status checked
  explicitly (so `--fail` is not needed). Missing: `-q`, `--proto`, `--url`
  (R110W5-03), `Cache-Control: no-cache` (R110W5-08).

### 2.5 Who answers the fetch

Over HTTP or through a TLS-intercepting proxy or a compromised mirror, an attacker
**cannot** install a forged list or an older one (both probed). It **can** withhold
updates — refuse (exit 1, alerted), answer `304` (exit 0, caught only by the
staleness alert), or replay the current list — and, through R110W5-01, make the
withholding outlive its presence. The guide's "Use HTTPS" is the control; the
script does not enforce it (R110W5-03).

---

## 3. The guide against FreeRADIUS 3.2.8

| Claim (W5.2) | Source / probe | Verdict |
|---|---|---|
| The reload rebuilds the store from `ca_file` **and** `ca_path` | `tls.c:595-623` calls `fr_init_x509_store` (`:3558-3585`: `X509_STORE_load_locations(store, ca_file, ca_path)`) | Holds |
| A failed reload logs `Error replacing X509 store` and keeps the old store | `tls.c:601-602` (the full text is "…, out of memory (?)", after "Error reading Trusted root CA list") | Holds |
| … and retries at every new conversation until a restart | `ca_path_last_reload` advances only on success (`:623`) | Holds |
| A half-written `ca.pem` fails the reload | an empty or truncated PEM makes `X509_STORE_load_locations` return 0 | Holds |
| Smaller intervals are raised to 300 | `tls.c:4081-4083` | Holds |
| `require_message_authenticator = yes` "parses on a `proto = tls` client (`freeradius -XC` prints it)" | `-XC` does not parse a listener's `clients` section: the same block with `= bogus` passes `-XC`; under `-X` the option parses (`= bogus` → "Invalid value"). The TLS listener calls `rad_packet_ok(packet, 0, NULL)` (`tls_listen.c:719`) and never reads `client->require_ma`; `Message-Authenticator` is still required on every packet carrying `EAP-Message` (`radius.c:2755-2766`) | The option is accepted and **inert** on RadSec; the evidence cited does not show what it says (R110W5-05) |
| The RadSec block as printed | `freeradius -XC` in the pinned image: `tls_min_version '1.3' must be <= tls_max_version '(null)'`; with `tls_max_version = "1.3"` added, "Configuration appears to be OK" | Does not start (R110W5-05; pre-existing since 1.0.1, the guide calls it untested) |
| NAS half of Blast-RADIUS | spike §4.1; RFC 9765 | Holds; "applies to [the RadSec client] equally" contradicts the same section's remedy (RadSec for an unpatched NAS) — R110W5-05 |
| #647: `umask 077`, no seed on disk, octal escapes for `dash`, delete the v2 key | probed under `dash`: the octal prefix is `30 2e 02 01 00 … 04 20`, the key's public half matches, a new file is `0600`, nothing else written. A **pre-existing** `press-07.key` keeps its mode (0644 probed): `umask` acts only on creation | Holds for a fresh run; superseded by W1.10 at the merge (§9), so no issue is proposed |

---

## 4. W5.3: the vendors-nothing check and the path filter

The check (`--self-test`: 18 cases OK; on the tree: exit 0, 7 files) fails on a
`Dockerfile*` / `Containerfile*` / `*.dockerfile` name, an upper-case `FROM` line
in any UTF-8 file under `docker/radius/`, an `image:` line without `@sha256:<64
hex>`, a `build:` key, or no `image:` at all. Probed past it (each **0 findings**):

| Tree | Result |
|---|---|
| `radius.build` with `from debian:12` (Docker instructions are case-insensitive) | passes |
| FreeRADIUS sources as `.c` text, or as `freeradius-3.2.8.tar.gz` | passes |
| a `docker save` tarball; an ELF binary | passes (binary files are skipped) |
| compose: `g: {image: busybox:latest}`; `include: [other.yml]`; `image: ${IMG:-x@sha256:…}` | passes |
| compose: `image: >-` block scalar | refused (fails closed) |

And it does not look outside `docker/radius/`: `docker/Dockerfile.server` (AXIAM's
own image) or `docker-compose.prod.yml` could gain a FreeRADIUS stage or service
unseen. An attacker with commit rights edits the gate too, so this is a guard
against accident, and severity stays Low; but T-454's correction rests on it
(R110W5-04).

The path filter now has `crypto.rs`, `subject.rs`, `server.rs` and the script, as
#650 asked. Read against `radius_e2e.rs` (routes it drives: org and tenant
signing-CA issuance, `/api/v1/certificates` issue/list/revoke,
`/service-accounts` create and `bind-certificate`, the CRL route) the filter still
misses the revocation listing that fills the CRL
(`axiam-db/src/repository/{certificate,ca_certificate}.rs`), the CA key load
(`axiam-pki/src/ca_key_store.rs`), the CRL configuration (`axiam-pki/src/config.rs`),
`handlers/service_accounts.rs`, and `Cargo.lock` — a dependabot bump of the X.509 or
Ed25519 crates changes the bytes FreeRADIUS reads and never runs the job
(R110W5-09). The workflow stays non-required, as its header says.

---

## 5. W5.4: the tag

`src/include/libradius.h:152-156`: `TAG_VALID(x)` is `0 < x < 0x20` and
`TAG_NONE` is 0; `src/lib/radius.c:1003` writes the integer's first octet as the
tag or `0x00`; `:1022` writes a string's tag octet only when `TAG_VALID`. So `:0` on
`Tunnel-Private-Group-Id` emits **no** octet, exactly as W5.4 observed on the wire,
and the e2e's `3230` pins it (a `:1` gives `013230`, run by the executor). RFC 2868
§3.6 reads a first octet above `0x1F` as the string's start, and RFC 3580 §3.31
asks nothing more; a decimal VLAN always starts above `0x1F`. **The guide's new
text is correct and safe for a compliant NAS.** Two refinements, both
Informational (R110W5-10): "a NAS reads it as one tunnel of several" is not why — a
consistent `:1` on all three attributes is one valid tunnel; the reason to keep `:0`
is that the note's closed set and the e2e pin it, and that a string tag on one
attribute only would split the group. And a NAS that strips the first octet
unconditionally (non-compliant) would read `"120"` as `"20"`: the guide could tell
the operator to confirm the VLAN their NAS applies from a test Accept.

**For the orchestrator, W6's to correct:** `claude_dev/radius-reply-profile-design.md:178`
(§3.2, the `Tunnel-Private-Group-Id` row) says tag `0x00` on the wire. `:176-177`
(the two integers, `0x00`) are right, and `:83` and `:722` say "tag 0", which is
right as a value. D4 renders replies through `rlm_rest`, which FreeRADIUS encodes
the same way, so W6 should correct `:178` with a dated correction and give W6.5's
e2e the same octet assertion.

---

## 6. Threat-model entries

* **Copies agree.** The `mitigation` text of T-454, T-462 and T-450 in
  `ThreatDragonModels/Axiam/Axiam.json` occurs verbatim in
  `claude_dev/threat-model-stride.md`; T-462's register row (`:4613`) carries the
  same two amendments in short. `check-remediation-evidence.py`: 37 verified, 0
  failed.
* **Status.** T-450 and T-462 stay **Open** (Q9): T-450 untouched, T-462's two
  amendments each end "Status unchanged: Open". T-454 stays Mitigated.
* **T-462 text vs code.** The 2026-10-15 (W5.1) amendment matches the script line
  for line: exact `verify OK`, number not lower, 200 only, atomic, `If-None-Match`,
  304 changes nothing; "each case fails when its check is removed" is the
  executor's run and consistent with my probes. It says an equal-number replay
  "lengthens the lag and is not otherwise caught" — true, and R110W5-01 / -02 are
  two more ways to the same end that should be added when they are fixed or filed.
  The W5.2 amendment (cache `max-age`, failed reload) claims no test, correctly.
* **T-454 text vs code.** The test sentence for the script matches it. The
  correction's reason — the e2e "would not fail if FreeRADIUS sources or a built
  image entered the tree … the two tests above do" — is not true of test (1) for
  sources or a built image (§4; R110W5-04). The crate half holds: `deny.toml`'s
  allow-list names no GPL licence; its only GPL exception is `actix-governor`.
* **Dated, in the entry's own text.** Both entries record their corrections as
  corrections, dated 2026-10-15, per §10.

---

## 7. The executors' follow-ups

| Follow-up | Verdict |
|---|---|
| `fetch-crl.sh` has no lock (overlapping cron runs) | **Confirmed**, and worse than overlap noise: R110W5-02 (a rollback that the `ETag` pairing then keeps) |
| it could send `Cache-Control: no-cache` | **Confirmed**, Informational (R110W5-08) |
| the vendors-nothing check matches only upper-case `FROM` | **Confirmed** and widened: binaries, sources, scope, compose forms (R110W5-04) |

---

## 8. Documentation claims

* The guide's §4 excerpt of the script (`:461-462`) is the script's line 129-131.
* The guide's limiter claim ("60 requests a minute per address") matches
  `config/rate_limit.rs:813`; the `304` and `Cache-Control: public, max-age` claims
  match `handlers/crl.rs:100-125`.
* "Last verified 2026-10-15" rests on the local runs and CI run 38761953931; after
  the merge with W1 (new key encoding, random serials) it needs the release PR's
  run, which the widened filter triggers (`crypto.rs`, `subject.rs`).
* `docker/radius/README.md` lists the script and the `curl` prerequisite.

---

## 9. Merge foresight

Trial merge in a scratch clone: plan branch + W1, then W5. W2, W3, W4 each merge
with W5 pairwise without conflict (they conflict among themselves in
`cleanup.rs`, the threat model and the spec, which is not W5's).

1. **`docs/pki/freeradius.md`, the "Ed25519 or RSA-4096" bullet (W5 `:100-126`, W1
   `:100-111`) — the only conflict. W1 wins.** W1.10 returns version-1 keys and
   replaces the workaround with "re-issue rather than converting the key"; W5.2's
   #647 snippet (umask, pipe, octal escapes) and its "delete the version-2 key"
   paragraph are dropped. #647 is then closed by the removal.
2. **The W1.9 serial bullet and W1.11's CN rules** in the same file auto-merge (W5
   did not touch those lines); keep W1's text.
3. **`radius_e2e.rs` auto-merges:** W1 deletes `supplicant_readable_key` and writes
   the key as returned; W5 adds the fetch stand-in, the script cases and
   `attribute_octets`. Checked on the merged file: no reference to the removed
   function remains. The merged test must run once (release PR).
4. **Semantic, no conflict:** W1.1's `docs/pki/README.md` says the CRL number can
   step back once on an interval change and around an epoch boundary under clock
   skew. The script refuses that lower list (exit 1, "lower than the installed")
   until the number passes the held one. After the merge, the guide's §4 should
   link README "Changing the interval" and say this refusal is expected then.
5. **Threat model** auto-merges (W1 touches other entries).
6. **W6** (empty so far) will touch the guide, the e2e, the compose file and
   `raddb/`: W6.5 should fetch through `fetch-crl.sh` and keep the octet assertion;
   W6 corrects the note's `:178` (§5).

---

## 10. Checks run

| Check | Result |
|---|---|
| `shellcheck -s sh docker/radius/fetch-crl.sh` (koalaman/shellcheck:stable) | clean, exit 0 |
| `actionlint` `radius-e2e.yml`, `ci.yml` | `radius-e2e.yml` clean; `ci.yml`'s four SC2015/SC2034 notes at `:533`, `:1006` are the base's `:523`, `:996` (pre-existing) |
| `check-radius-vendors-nothing.py --self-test` / on the tree | 18 cases OK / exit 0 |
| `check-remediation-evidence.py`; `check-doc-links.sh` | 37 verified, 0 failed; 506 links OK |
| T-454 / T-462 / T-450 copies (`Axiam.json` vs STRIDE) | verbatim; statuses Mitigated / Open / Open |
| `fetch-crl.sh` under `dash`, stand-in with AXIAM's `If-None-Match` matching | 200 installs; 304 keeps; forged (same name, other key, higher number) refused while `openssl crl -verify` says `verify failure`, exit 0; `0x0A` < `0x10` refused; equal accepted; `<NONE>` refused; `ETag: *` then a newer list → `304 unchanged`, exit 0, list frozen at the old number (R110W5-01); space/control in `ETag` not stored; comma list stored |
| `~/.curlrc` with `location`; URL `-K…` | redirect followed (exit 0, list from `/elsewhere`); without it `HTTP 302`, exit 1; `-K…` read as an option |
| `dash` / `bash`: `trap … EXIT` then `kill -TERM $$` | `dash` does not run it; `bash` does |
| #647 snippet under `dash` | correct key; fresh file 0600; pre-existing file keeps 0644 |
| FreeRADIUS 3.2.8 image: guide's RadSec block, `-XC` | refused: `tls_max_version '(null)'`; with it: OK; `= bogus` passes `-XC`, fails `-X` |
| FreeRADIUS `release_3_2_8` sources read | `tls.c`, `tls_listen.c`, `listen.c`, `client.c`, `src/lib/radius.c`, `libradius.h`, `radiusd.conf.in` |
| `radius-e2e.yml` on the branch | run 38761953931, `workflow_dispatch`, `63fc3d7d2`, **success** |
| Trial merges (scratch clone) | W5 vs W1: 1 conflict (`freeradius.md`); vs W2, W3, W4: none |
| Not run | cargo (another executor holds the build); the e2e locally |

---

## 11. Issue bodies

### R110W5-01 (Low) — a stored `ETag` of `*` freezes the fetch after the attacker has gone

`docker/radius/fetch-crl.sh` stores the `ETag` of an installed list if every octet
is printable (`:159-163`) and sends it as `If-None-Match` (`:106-108`); a `304`
is "unchanged", exit 0 (`:115-118`). The tag's grammar is not checked, and AXIAM's
CRL route treats `*` (alone or in a list) as matching any list
(`crates/axiam-pki/src/crl.rs:282-288`, RFC 9110 semantics). Whoever answers one
fetch — plain HTTP, a TLS-intercepting proxy, a compromised mirror or cache —
serves the genuine current list (it passes both checks) with `ETag: *`. From then on
every run asks AXIAM `If-None-Match: *`, AXIAM answers `304`, and the script keeps
the old list and exits 0, **with the attacker gone**, until the list's `nextUpdate`
(fail-closed outage) or the staleness alert. Probed: after `ETag: *` on `0xFF00`,
AXIAM-style matching against a newer `0x10000` gives two `unchanged (304)` runs and
the installed number stays `0xFF00`. The script also trusts any `304` without
comparing its `ETag` to the one it sent.
**Proposed fix:** store a tag only if it matches `^(W/)?"[!#-~]*"$` (one entity-tag:
no `*`, no comma, no inner quote); on a `304`, require the response's `ETag` to equal
the tag sent, else re-run the request without `If-None-Match`; store the SHA-256 of
the installed file beside the tag and, on a `304`, re-fetch unconditionally if the
file no longer matches. **Test:** in `fetch_script_cases`, serve the current list
with `ETag: *`, then a newer list: the newer list is installed.
T-462's amendment gains the case.

### R110W5-02 (Low) — overlapping runs can roll the list back and keep it

`fetch-crl.sh` compares the CRL number with the installed list (`:139-149`) and later
renames its list into place (`:152-156`), then writes the state (`:164-169`), with no
lock. Two runs A and B (a manual run during the timer, a cron entry beside a systemd
timer, a Kubernetes CronJob with the default `concurrencyPolicy: Allow`): A fetches
L1, a revocation happens, B fetches L2; both pass the check against L0; B renames L2,
**A renames L1 over it**; A writes tag T1, **B writes tag T2**. The installed list is
L1 and the state says T2, so the next runs send `If-None-Match: T2`, AXIAM answers
`304`, and L1 stays until AXIAM's list changes (the next revocation or epoch, up to
half `nextUpdate`, twelve hours by default) — with a fresh file, so the mtime alert
is silent.
**Proposed fix:** a POSIX lock around the whole run (`mkdir "$capath/.fetch-crl.$key.lock"`,
removed by the cleanup trap, with the holder's PID inside and a stale lock broken
after, say, 120 s; `flock` where present); re-read the installed number under the lock
immediately before the rename; R110W5-01's file hash also catches the mis-pairing.
**Test:** a shell test that runs two instances against a stand-in that delays the
first response; the newer list is installed and the state names it.

### R110W5-03 (Low) — the fetch's `curl` call inherits configuration and accepts any scheme

`fetch-crl.sh:105-110` runs `curl -sS --max-time 20 --max-filesize … "$url"`. curl
reads `~/.curlrc` unless `-q` is its first argument: probed, a `location` line there
makes the script follow a redirect it otherwise refuses (`insecure` would turn TLS
verification off the same way). A URL starting with `-` is parsed as an option
(probed with `-K…`). No `--proto`: `http://`, `file://`, `ftp://` are fetched although
the guide says "Use HTTPS" (`docs/pki/freeradius.md:476`). `--max-filesize` bounds an
unsized (chunked) body only from curl 8.4; before, `--max-time` alone bounds it.
**Proposed fix:** `curl -q --proto =https --max-redirs 0 … --url "$url"`, with an
explicit opt-in (`FETCH_CRL_ALLOW_HTTP=1`, the e2e's loopback stand-in sets it) that
widens `--proto` to `=https,http`; state the curl ≥ 8.4 note in the header.
**Test:** with `HOME` holding a `.curlrc` of `location` and a stand-in answering
`302`, the script exits 1; an `http://` URL without the opt-in exits 1.

### R110W5-04 (Low) — T-454's check misses sources, built images and everything outside `docker/radius/`

`scripts/check-radius-vendors-nothing.py` skips non-UTF-8 files (`:78-81`), matches
`FROM` case-sensitively (`:57`), reads only `docker/radius/` and
`docker/docker-compose.radius.yml`, and parses `image:` line by line (`:59, :100-111`).
Probed, each passes with 0 findings: `from debian:12` in `radius.build`; FreeRADIUS
sources as `.c` text and as a `.tar.gz`; a `docker save` tarball; an ELF binary; a
flow-mapping `image: busybox:latest`; `include:`; `image: ${IMG:-…@sha256:…}`. A
FreeRADIUS stage in `docker/Dockerfile.server` or a service in
`docker-compose.prod.yml` is never looked at. T-454's correction says the e2e fails
to catch "FreeRADIUS sources or a built image … the two tests above do"; for sources
and images the script does not.
**Proposed fix:** make `docker/radius/` an allow-list (`README.md`, `fetch-crl.sh`,
`raddb/{clients.conf,eap,default,check-eap-tls,axiam_placement}`; any other file, or a
binary, fails); match `FROM` case-insensitively as an instruction
(`^\s*from\s+(--\S+\s+)*[\w./:@-]+(\s+as\s+\S+)?\s*$`, `re.I | re.M`); scan every
tracked `Dockerfile*` and `docker-compose*.yml` for a `freeradius` image and refuse a
build of it or an unpinned reference; refuse `include:`/`extends:` and `${` in an
`image:` of the RADIUS compose file; parse it with a YAML loader if one is available
in the job. Re-word T-454 (both copies) to what is then checked, dated.
**Test:** the nine probes above as `--self-test` cases.

### R110W5-05 (Informational) — the RadSec block does not start, and its `require_message_authenticator` is inert

`docs/pki/freeradius.md:547-571` sets `tls_min_version = "1.3"` without
`tls_max_version`; FreeRADIUS 3.2.8 (the pinned image) refuses it:
`tls_min_version '1.3' must be <= tls_max_version '(null)'`. With
`tls_max_version = "1.3"` it passes. The client's `require_message_authenticator =
yes` is accepted (`-X` rejects `= bogus`), but the TLS listener checks packets with
`rad_packet_ok(packet, 0, NULL)` (`src/main/tls_listen.c:719`) and never reads the
per-client flag; `Message-Authenticator` is required anyway on every packet carrying
`EAP-Message` (`src/lib/radius.c:2755-2766`), and TLS carries integrity, so nothing is
exposed. W5.2's evidence ("`freeradius -XC` prints it") does not show parsing:
`-XC` does not parse a listener's client section (`= bogus` passes it). The sentence
"the NAS-firmware point … applies to it equally" (`:574-576`) contradicts the bullet
that offers RadSec as the remedy for a NAS without the fix (`:276-279`).
**Proposed fix:** add `tls_max_version = "1.3"`; say the option is harmless and
inert on a RadSec client in 3.2.8 (TLS protects the exchange), and that the firmware
point is for UDP. **Test:** none (RadSec is outside the e2e); `freeradius -XC` with
the block.

### R110W5-06 (Informational) — a killed run leaves its temporary files

`fetch-crl.sh:64` sets `trap cleanup EXIT`; `dash` does not run an `EXIT` trap when
the shell dies of a signal (probed with `kill -TERM $$`; `bash` does). A run killed
by a cron or systemd timeout leaves `$work` in `TMPDIR` and possibly
`$capath/.incoming.*` (OpenSSL never reads that name).
**Proposed fix:** `trap 'exit 1' HUP INT TERM` beside the `EXIT` trap.

### R110W5-07 (Informational) — staleness is measured on the file, and a `304` exits 0 at any age

The guide tells the operator to alert when the file in `capath` is older than half
the list's lifetime (`docs/pki/freeradius.md:479-481, 533-534`). AXIAM re-signs once
per refresh epoch, which is half the lifetime, so a healthy file reaches that age at
every epoch boundary plus up to one fetch interval: the alert flaps. Meanwhile the
script exits 0 on a `304` however close the held list is to `nextUpdate`, which is
the case R110W5-01 and -02 produce.
**Proposed fix:** the script reads the installed list's `nextUpdate`
(`openssl crl -noout -nextupdate`) and exits 3 ("installed list expires in …") when
less than a quarter of its lifetime remains, after a `304` as after a refusal; the
guide's alert becomes "exit status non-zero", one rule.

### R110W5-08 (Informational) — the fetch does not ask a cache to revalidate

The guide's lag bound holds behind a shared cache only if the cache is "told
`no-cache`" (`docs/pki/freeradius.md:495-503`). The request can say it itself:
`Cache-Control: no-cache` obliges a compliant cache to revalidate with the origin
(RFC 9111 §5.2.1.4), which the `ETag` makes a cheap `304`.
**Proposed fix:** `-H 'Cache-Control: no-cache'` on the request; the guide keeps its
advice for caches that ignore request directives.

### R110W5-09 (Informational) — the e2e path filter still misses CRL and binding inputs

`.github/workflows/radius-e2e.yml:34-49` does not list
`crates/axiam-db/src/repository/certificate.rs` and `ca_certificate.rs` (the revoked
listings that fill the CRL), `crates/axiam-pki/src/ca_key_store.rs` (the signing key),
`crates/axiam-pki/src/config.rs` and `lib.rs`,
`crates/axiam-api-rest/src/handlers/service_accounts.rs`, or `Cargo.lock` — so a
dependabot bump of the X.509 or Ed25519 crates never runs the job.
**Proposed fix:** add the paths, or (cheaper than `Cargo.lock` on every bump) a weekly
`schedule:` trigger.

### R110W5-10 (Informational) — stale or inconsistent text

(a) `claude_dev/radius-reply-profile-design.md:178` says the
`Tunnel-Private-Group-Id` tag is `0x00` on the wire; FreeRADIUS 3 emits none for tag
0 (`radius.c:1022`) — **W6** corrects it, dated, and W6.5's e2e asserts the octets.
(b) `docs/pki/freeradius.md:337-339`: a non-zero tag is not "one tunnel of several"
when all three carry it; the reason to keep `:0` is the closed set and the pinned
encoding; and a non-compliant NAS that always strips a first octet would misread a
three-digit VLAN — tell the operator to confirm the applied VLAN from a test Accept.
(c) `crates/axiam-server/tests/radius_e2e.rs:557-560`: `crl`'s old doc summary now sits
above `crl_tagged`'s, and `crl` has none. (d) W5.3's own deferral: the STRIDE section
summaries (`:4409, :4646`) and `docs/pki/freeradius.md:622-627` still give T-454 the
e2e "as [its] test" — W8.3.

---

## 12. Invariants

* **No AXIAM surface is added.** No route, schema, permission or setting; the CRL
  route is read, unchanged.
* **No secret or key is committed.** The e2e's material stays in
  `docker/.secrets/radius/` (gitignored); the forgery helper mints its key per run.
* **Fail-closed where it matters:** a forged, older, numberless or unparsable list
  is refused and the installed one left byte for byte; a wording change in OpenSSL
  refuses every list; an expired list refuses every device. The exceptions are the
  withholding paths of R110W5-01 / -02, which fail *stale*, bounded by `nextUpdate`.
* **GPLv2:** nothing of FreeRADIUS is in the tree; the image is referenced by digest.
* **Threat model:** T-450 and T-462 Open (Q9), T-454 Mitigated; the two copies agree;
  every correction is dated in the entry's own text.
