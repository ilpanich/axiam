# Security review — release 1.1.1, wave W5 (F4)

**Date:** 2026-10-19.
**Against:** `claude/release-1.1.1-w5`, the whole wave diff `origin/main..8450bc255`
(8 commits, 58 files, 684 lines added and 274 removed): `b930db33b` (W5.1, D-1, the
rename), `2dab9f647` (W5.2, #693), `b915783bb` (W5.3, #694), `64cf8ced0` (W5.4, #695),
`742439215` (W5.5, #696), `c90c8c13d` (W5.6, #697 #713), `4cd4a10c9` (W5.7, #707) and
`8450bc255` (W5.8, #698 (b) (c), #711's sentence). Every commit carries a `gpgsig`
header (the sandbox has no `allowedSignersFile`, so `%G?` cannot verify).
**Scope:** W5 of the release plan (§6): `docker/radius/**`,
`docker/docker-compose.radius*.yml`, `docs/pki/freeradius.md`,
`crates/axiam-server/tests/radius_e2e.rs`, `.github/workflows/radius-e2e.yml`,
`website/src/docs/operate.ts`, `website/src/security.ts`, the rename's comment edits in
other crates, the regenerated spec, registry and `apiIndex.ts`, and T-486 (both copies),
with T-450, T-454 and T-462 read against the code.
**Method:** every commit message and the full diff read, each claim checked against the
tree; the `401` retry read against the FreeRADIUS **`release_3_2_8`** sources
(`src/modules/rlm_rest/rlm_rest.c` `mod_common`, `rest.c` `rest_request_perform`,
`src/modules/rlm_cache/rlm_cache.c` `mod_cache_it`), and `rlm_cache`'s behaviour
**probed** in the pinned image (`freeradius/freeradius-server:3.2.8@sha256:af6fd34a…`)
with a throwaway virtual server driven by `radclient` (§3.2); `freeradius -XC` on both
profiles and on the guide's RadSec block, with and without `tls_max_version` (§4);
`epoch_of` checked against GNU `date` on 309 dates under `dash` and `bash` (§2.1);
`fetch-crl-test.sh` under both shells; `shellcheck` 0.11.0, `actionlint` 1.7.12; the
repository's own checks; the rename's exit `grep`. This review fixes nothing.

---

## 0. Summary

**No Critical, High or Medium finding.** The rename is total where an operator meets the
name, and fails closed where an upgrade misses it (§5). The RadSec block now starts
(W5.2, re-probed). The signal trap cleans up under `dash` (W5.3). The exit-3 date
arithmetic is exact, and the dates it reads come from a list the CA signed (W5.4). The
`no-cache` header is on every request (W5.5). The filter carries the twelve paths the two
issues listed (W5.6). The `401` retry happens only on a `401`, at most once, and cannot
admit on a stale decision or loop (W5.7). The guide's `TRUSTED_PROXIES` sentence matches
W2.1's code (W5.8).

One **Low** finding is in what the wave added. `rlm_cache` treats `Cache-TTL := 0` on an
entry that is not there as "insert with the module's TTL". It also treats a store on an
entry that *is* there as "hand back the cached value". So two authentications that get a
`401` at the same moment (a rotation under load) can put the refused token back into the
cache and decide with it. Each such request is rejected, which is fail-closed, and the
next lone request heals the cache. Under load, T-486's "one extra login" does not hold.
The fix is two attributes. Five Informational findings cover text, tests and coverage.

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| R111W5-01 | Concurrent `401`s re-insert the refused token. `Cache-TTL := 0` on an absent entry **inserts** the current `Tmp-String-2` (with `ttl = 600`), and the retry's store, finding an entry, **merges it over** the token just fetched. That request decides with the old token, gets a `401` and is rejected, and the cache holds the old token again. Probed. | Low | `raddb/live/check-eap-tls:128-132, 158-162`; T-486 (both copies); guide §5 | wave (W5.7) | Filed #720 |
| R111W5-02 | A lock-busy run exits `0` without the age check, so a holder that never finishes (stopped, or hung on the file system) silences exit 3 until the list expires. And exit 3 *replaces* exit 1, so an alert that routes by code files a refused list (a forged one included) under "list ageing". | Informational | `fetch-crl.sh:92-96, 200-203`; guide §4 | wave (W5.4) | Filed #721 (confirms the executor's follow-up) |
| R111W5-03 | The `401` path's text and tests claim more than they show. The comment says a `403` "still ends the section", but in `post-auth` `rlm_rest` maps **every** 4xx to `invalid`, so a 403 now continues and is rejected by the status test (correct, but not as written). The stand-in "401 that the new token gets too" does not assert that the retry ran, so it passes on 1.1.0's file too. `healed.log.contains("401")` matches any substring. | Informational | `check-eap-tls:103-109`; `radius_e2e.rs:3180-3192, 3382-3385`; T-486's test sentence | wave (W5.7) | Filed #722 |
| R111W5-04 | The filter still misses files the Live case runs through: `crates/axiam-server/src/tls.rs` (the test calls `build_rustls_server_config` and `lift_verified_client_certificate`, the certificate binding the new `401` case rests on), `axiam-api-rest/src/extractors/auth.rs` (the bearer extractor that checks `cnf`), `axiam-auth/src/token.rs` (`cnf` itself), `axiam-api-rest/src/network_decide_guard.rs` and `axiam-api-rest/src/network_gate.rs`. The weekly schedule bounds the gap to a week, on `main` only. | Informational | `radius-e2e.yml:41-78` | wave (W5.6, beyond #697/#713's lists) | Filed #723 |
| R111W5-05 | Hygiene: two `D4` comments the rename missed (`axiam-core/src/models/network.rs:752`, `axiam-api-rest/tests/network_decide_test.rs:775`). W5.3's body credits the trap to `3da7e0c`; it came in with `f0fe8b064`. `shellcheck` 0.11.0 now reports SC2329 (info, exit 1) on `cleanup`, where `main` was clean. The header's "only SIGKILL leaves them" leaves out the other untrapped signals (QUIT, ALRM, USR1, PIPE). | Informational | as listed | wave (W5.1, W5.3, W5.4) | Filed #724 |
| R111W5-06 | For W8.3 and W8.4: T-462 (both copies) is not amended for exit 3 (W5.4) or the `no-cache` request header (W5.5), and still says "a cache told `no-cache`" and "the age alert". The CHANGELOG must say that the rename fails closed: an `eap` file and a `raddb/live/` set from different releases, or an unrenamed `AXIAM_D4_URL`, reject every device. | Informational | `threat-model-stride.md` T-462; `Axiam.json` #462; `CHANGELOG.md` | wave (W5.4, W5.5, W5.1) | Filed #725 (W8.3 / W8.4) |

What the brief asked and is **not** a finding: the retry's trigger, bound, token handling
and stale-decision case (§3.1); the date parsing and the attacker's reach over
`nextUpdate` (§2.1, §2.2); the e2e's assertions after the rename (§6); the threat-model
copies (§7); the spec delta (§5).

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| Every commit message against the code; every §10 rule | §8 |
| The recipe's security wording after the rename | §4, §5; R111W5-05, R111W5-06 |
| The e2e's assertions after the rename (vacuous cases?) | §6; R111W5-03 |
| The `401` retry: loop, other statuses, token leak, stale decision | §3; R111W5-01, R111W5-03 |
| Exit 3: date parsing in `sh`, attacker `nextUpdate`, lock-busy exit 0 | §2; R111W5-02 |
| The path filter's completeness | §2.4; R111W5-04 |
| The rename's leftovers | §5; R111W5-05 |
| T-450, T-454, T-462, T-486 against the code; the copies agree | §7; R111W5-06 |
| The executors' follow-ups | §9 |
| The tool runs | §10 |

---

## 2. `docker/radius/fetch-crl.sh` (W5.3, W5.4, W5.5) and the filter (W5.6)

### 2.1 `epoch_of`: civil-date arithmetic in plain `sh`

`epoch_of` splits `openssl crl -lastupdate/-nextupdate`'s text
(`Oct  9 12:00:00 2026 GMT`) on `IFS` and maps the month by name; any other token
returns 1. It refuses a non-digit field, strips leading zeros, so `08` is never read as
octal by `$(( ))`, and runs Hinnant's days-from-civil. It is called in `$( )`, so its
globals do not leak. **Probed:** 9 edge dates (1970-01-01, 2000-02-28/03-01,
2028-02-29, 2049/2050 across the UTCTime/GeneralizedTime switch, 2100-03-01,
9999-09-30) and 300 random epochs in [0, 2³³) match `date -u -d` exactly under `dash`
and `bash`. `NONE` (a list without `nextUpdate`) and an unknown month return 1, so
`near_expiry` is false and the run keeps its own status. AXIAM always writes
`nextUpdate`, so that is a list AXIAM does not issue.

### 2.2 Who controls the dates

`near_expiry` reads only the **installed** file, `<capath>/<subject_hash of ca.pem>.r0`.
That is the same name the install writes (`openssl crl -hash` of a list whose issuer is
that CA). A file reaches it only after `verify OK` against `ca.pem` and the CRL-number
check, so `lastUpdate` and `nextUpdate` are the CA's. Someone who answers the fetch can
neither shorten them (a false exit 3) nor stretch them (a missed one). They can withhold
a newer list, and that is exactly the case exit 3 now reports a quarter-life ahead. A
garbage file in place makes `openssl crl` fail, so the check is false and the refusal
stays exit 1 (tested: "an unreadable installed list does not turn a refusal into exit
3"). `fail` is never called inside `$( )`, so `exit 3` always leaves the script, and the
`EXIT` trap keeps the status (tested). The `armed` guard keeps exit 3 off failures that
happen before the lock (bad URL, unreadable CA), which are configuration errors.

### 2.3 The lock-busy run, and what exit 3 replaces (R111W5-02)

`busy()` (`:200-203`) exits 0 before `armed=1`, and the guide says so (`:547-548`). With
`flock`, the lock lasts as long as its holder. A holder that is stopped, or blocked on a
`capath` over a dead network file system, keeps every later run at exit 0 with no age
check, until FreeRADIUS refuses the whole tenant at `nextUpdate`. Exit 3 was added to
give at least a quarter of the lifetime of warning, and this case gets none. The check
is read-only and installs are atomic `mv`, so it can run without the lock. Separately,
exit 3 *replaces* exit 1 after a refusal. The guide says "alert on any non-zero exit",
which is sufficient, but an operator who routes 3 to a "list ageing" runbook files a
refused list (forged, older, or not a CRL) under it. Informational: it needs a wedged
holder, or an alert that routes by code.

### 2.4 The `no-cache` header and the filter

`-H 'Cache-Control: no-cache'` is in the fixed argument list, so every request carries
it: the first one, the revalidation, and the re-request after a mismatched `304` (all
three tested). The filter (`radius-e2e.yml:41-78`) holds every path #697 and #713 list
(twelve; the plan's "eleven" is a miscount, and the commit says so), all of them exist,
and `docker/radius/**` covers `raddb/live/`. `config.rs` and `lib.rs` read as
axiam-pki's is the natural reading of #697, which lists them after `ca_key_store.rs`.
**R111W5-04:** the Live case also runs through files neither issue named. The test calls
`axiam_server::tls::build_rustls_server_config` and `lift_verified_client_certificate`,
the production listener and the certificate binding the new `401` case exists to
exercise. The `cnf` check is in `axiam-api-rest/src/extractors/auth.rs` and
`axiam-auth/src/token.rs`. The decision route's guard and gate are
`axiam-api-rest/src/network_decide_guard.rs` and `network_gate.rs`. The weekly schedule
(`17 3 * * 1`, which GitHub runs on the default branch only) catches a regression within
a week of its merge, but not on the pull request that makes it.

---

## 3. The `401` retry (W5.7, #707)

### 3.1 What holds

- **Only a `401` retries.** In `post-auth`, `rlm_rest` runs `mod_common`
  (`rlm_rest.c:562-608`): 2xx → `ok`/`updated`, 5xx → `fail`, **every other code →
  `invalid`**. `invalid = 1` makes all 4xx continue. The retry then reads
  `reply:REST-HTTP-Status-Code`, which `rest_request_perform` sets on every completed
  request (`rest.c:2425`) and which the recipe clears after each call, and it rejects
  unless the code is exactly `401` (`/^401$/`). A transport failure is `fail` and still
  ends the section. A status left over from an earlier call cannot be read, because the
  token call's status is cleared first.
- **Once, and no loop.** `Tmp-Integer-1` is 1 only when this authentication fetched the
  token, and then a `401` rejects after the drop. The second `axiam_decide` has no
  `invalid = 1`, so a second `401` ends the section with `invalid` (a reject). There is
  no unlang loop construct in the path.
- **No stale decision.** The first call's body and status are deleted before the retry,
  and the mapping reads `reply:REST-HTTP-Body` only after the second call returns
  `ok`/`updated`. A failed second call never reaches the mapping.
- **No new exposure of the token.** The retry stores the token where the first fetch
  does (`control:Tmp-String-2`, the `Authorization` header, `Tmp-String-4` for the
  body). Nothing reaches the reply. The `-X` log shows the header, as it did in 1.1.0.

### 3.2 R111W5-01: concurrent `401`s put the refused token back (Low)

`mod_cache_it` (`rlm_cache.c:436-…`), release_3_2_8:

- an entry that is **absent**, with `Cache-TTL` 0, goes to `insert` with
  `ttl = inst->ttl` ("If there's no existing cache entry, go and create a new one");
- an entry that is **present**, with a positive `Cache-TTL`, gets its expiry reset and is
  then **merged into the request**: `cache_merge` overwrites `control:Tmp-String-2`.

The retry's drop (`:128-132`) assumes the first rule never applies. Its store
(`:158-162`) assumes the second rule never applies. After a rotation, the FreeRADIUS
threads that read the cached token before the drop all get a `401`:

1. Thread A drops the entry.
2. Thread B's drop now finds no entry and **inserts B's refused token**, with `ttl = 600`.
3. A and B each fetch a new token. Each store finds B's entry, resets its expiry to half
   the new token's life, and merges the **refused** token over the new one.
4. Both decide with it, get a `401`, and are rejected. The cache again holds a token
   AXIAM refuses.

A later lone request heals the cache (its drop finds the entry; its store finds none).
Under sustained concurrency, though, each wave of `401`s can re-poison it.

**Probed** in the pinned image, one request, sequentially (`radclient` against a virtual
server with a `cache` instance shaped like `axiam_token_cache`):
`Tmp-String-2 := "OLD"`, `Cache-TTL := 0` on an empty cache, then a status-only lookup:
**found** ("Creating new cache entry"). Then `Tmp-String-2 := "NEW"`,
`Cache-TTL := 450`, store: the request carries **`OLD`** ("Merging cache entry into
request").

Impact: fail-closed (each such request is rejected), on the rotation path #707 exists to
fix. T-486's amendment and the guide (§5) promise "one extra login", which holds without
concurrency only. Low.

**Proposed fix** (both probed in the same image): on the drop, add
`Cache-Read-Only := yes` beside `Cache-TTL := 0`, so an absent entry is not created
(probe: not inserted). On the retry's store, use a negative TTL,
`Cache-TTL := "%{expr:0 - %{1} / 2}"`, which expires whatever is there and inserts this
request's token (probe: the later read returns `FRESH`). The first-fetch store
(`:88-90`) can keep its positive TTL: merging another thread's *fresh* token there is
harmless.

**Test:** in the rotation step, run two `eapol_test` attempts concurrently after the
listener restart, then assert that both are accepted and that the next attempt finds the
new token (`Found entry` and no `/api/v1/auth/device`). Against the current file, one or
both concurrent attempts are refused. The test could be flaky on interleaving. The
deterministic witness is the probe above, which could ship as a `radclient` case under
`docker/radius/tests/`.

### 3.3 R111W5-03: the text and the tests of the `401` path (Informational)

- `check-eap-tls:105-106`: "Every other result keeps its own action, so a 403 or a 5xx
  still ends the section as before." A 5xx does. A 403, a 404 or a 400 is `invalid` in
  `post-auth` (§3.1), so it now *continues*, and the status test rejects it. The
  behaviour is right and the sentence is wrong. Say "every 4xx continues and anything
  but a `401` is rejected below; a 5xx or a transport failure ends the section".
- `radius_e2e.rs:3382-3385`, "a 401 that the new token gets too": the stub answers `401`
  to every decision. The token in the cache is the stub's, so the retry runs, but the
  case asserts only the refusal. 1.1.0's file, with no retry, is refused too, so the
  case does not show that the retry is bounded at one. Count the stub's decision calls
  (exactly two).
- `radius_e2e.rs:3183`: `healed.log.contains("401")` matches any `401` in the log (a
  port, a serial). The rotation case is **not** vacuous: an accept after
  `Found entry for "axiam-decide-caller"`, behind a restarted listener that presents
  only the new certificate, can only come from the retry. Still, the sub-assertion should
  read `REST-HTTP-Status-Code` … `401`.
- T-486 (both copies) says the stand-in `401` "is refused after the one retry". The test
  shows the refusal, not the retry.

---

## 4. The recipe's security wording (W5.2, W5.8) and both profiles

- **RadSec (#693).** Re-probed: the guide's block (`freeradius.md:961-986`) under the
  pinned image is `-XC` **exit 0** with `tls_max_version = "1.3"`, and **exit 1**
  without it (`tls_min_version '1.3' must be <= tls_max_version '(null)'`). The two
  bullets (`require_message_authenticator` is inert on `proto = tls`; the firmware point
  is for UDP) match R110W5-05's source reading, and the contradiction with the bullet
  that offers RadSec as the remedy is resolved.
- **Both profiles:** `freeradius -XC` **exit 0** on the Static profile (with an empty
  `placement`; the log reads "Not including file /etc/freeradius/axiam-live/verify.conf")
  and on the Live profile (the hook included, `tmpdir = /var/run/axiam-live`).
- **The tag paragraph (#698 b).** The three-digit case is the one that lands a device on
  *another valid* VLAN (`120` read as `20`). A two-digit value becomes `0`, which a NAS
  refuses or leaves untagged. The paragraph is accurate.
- **`TRUSTED_PROXIES` (#711's sentence).** It matches W2.1 (`d1c97b6ee` on
  `claude/release-1.1.1-w2`): CIDRs, comma-separated; an empty list reads every peer's
  header and logs one `WARN` with native TLS on. It documents a setting this branch alone
  does not ship, so W5 must not reach a release without W2.1. Plan §1 has them on the
  same release branch.
- **The `401` paragraph** (`:707-714`) is right apart from the concurrency of
  R111W5-01.
- **Exit 3 in the guide and the site** (`:537-548`, the lag bullet, `operate.ts`) say the
  same as the script, including the lock-busy exit 0.

---

## 5. The rename (W5.1)

`grep -rn -E '\bD[34]\b'` over the tree, less `.planning/`, the DCR/CIMD `D3`/`D4`
(`pages/settings/`, `services/settings.ts`, and their back-end namesakes in
`axiam-oauth2`, the `cimd`/`dcr` tests, `external_consent.rs`), the FIDO MDS "D4 step n",
the benchmark plan's D-items, `infra/rpi5-k3s`, and the sites left on purpose
(`docs/compliance/FINDINGS.md:64`, `website/src/data.ts:501` and `:611`, both release
notes, `sdks/CONTRACT.md` §36 for W7.1, the threat model and `threatModelSummary.ts` for
W8.3, the schema's v100 history at `schema.rs:4880, 7029`). What remains is **two
comments: R111W5-05**. Neither is in a `ToSchema` doc, and the spec carries no "D4's
caller". `d4` as an identifier survives only in the DCR test names
(`d4_an_administrators_client_…`) and image digests.

The paths agree end to end: `eap`'s `$-INCLUDE /etc/freeradius/axiam-live/verify.conf`,
the compose mounts at `/etc/freeradius/axiam-live/`, `verify.conf`'s `tmpdir` and
`axiam-live.sh`'s `DIR` at `/var/run/axiam-live` (the tmpfs), the `axiam_take` command,
and `AXIAM_LIVE_URL`/`AXIAM_LIVE_SITE`. **A mismatch fails closed.** Without the hook
there is no stash, `axiam_take` prints nothing, and `Tmp-String-0` fails its regex. With
an empty `connect_uri`, `rlm_rest` fails. Either way every device is rejected, never
admitted. That is an outage an upgrading operator must be told about (R111W5-06). The
spec, registry and `apiIndex.ts` delta is the four doc strings plus the two digests, and
`check-spec-digest.py` agrees.

---

## 6. The e2e's assertions after the rename

No assertion reads a renamed string: the module names, the `axiam-live` paths and the
override's file are in the setup, not in a `contains`. The negative assertions
(`!…log.contains("/api/v1/auth/device")`, `"certificate revoked"`) name strings that
exist in the current files, so none passes because of the rename. `Stack::live` mounts
the renamed override. The thread name and the log lines changed with it. The two doc
summaries (#698 c) sit on their own functions. `serve_axiam_on` retries the bind only on
a fixed port, 50 × 100 ms, and panics after that, so it cannot hang. The weak points of
the new case are in R111W5-03.

---

## 7. The threat model

**T-486:** the two copies' 2026-10-19 amendments are byte-identical (compared by script).
The text matches the code except for "one extra login" under concurrency (R111W5-01)
and the test sentence (R111W5-03). Status **Open** is unchanged, rightly: the outage is
still the operator's. **T-462:** not edited by the wave. Its mitigation still describes
the fetch alert and the cache advice as of 1.1.0 (R111W5-06). The fetch-script and
Live-column statements it makes still hold, and it stays **Open**. **T-450:** the RadSec
remedy it points to now starts (§4), and it stays Open (UDP remains the operator's
choice). **T-454:** untouched by the wave; `check-radius-vendors-nothing.py` and its
`--self-test` pass.

---

## 8. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `b930db33b` | `git mv`; spec, registry, `apiIndex.ts` regenerated; DCR/CIMD untouched; listed leftovers on purpose | true; two comments missed (R111W5-05) |
| `2dab9f647` | `tls_max_version`; inert setting; UDP firmware | true (re-probed) |
| `b915783bb` | trap already present "since `3da7e0c`" | trap present; the commit is `f0fe8b064` (R111W5-05). Its note "shellcheck not run" stands; 0.11.0 now reports SC2329 (info) |
| `64cf8ced0` | exit 3 below a quarter, after 200, 304 and refusal; lock-busy exit 0 | true |
| `742439215` | `no-cache` on every request | true |
| `c90c8c13d` | twelve paths; weekly schedule; `Cargo.lock` not in the filter | true |
| `4cd4a10c9` | `invalid = 1`; retry once when the token came from the cache; T-486 amended | true, except the concurrency case (R111W5-01) and the 403 sentence (R111W5-03) |
| `8450bc255` | tag paragraph; `TRUSTED_PROXIES`; doc summaries | true |

§10: every commit is signed. No `sdks/CONTRACT.md` edit. No new route, migration or
crate. Each row's tests are in its own commit. The threat-model correction is dated in
its entry's text. From W5.1 on, every new text says Static and Live. W5 regenerated the
spec in-wave.

---

## 9. The executors' follow-ups

| Executor's note | Verdict |
|---|---|
| W5.3: INT untested (a background shell ignores SIGINT) | **Confirmed** as a test limit; the trap names INT, and HUP/TERM prove the mechanism |
| W5.4: a lock-busy run exits 0 | **Confirmed, and widened**: R111W5-02 |
| W5.6: twelve paths, not eleven; `config.rs`/`lib.rs` taken as axiam-pki's | **Confirmed**; and further files: R111W5-04 |
| W5.7: Static not re-run after the last change | **Closed** by this review's local run (§10) |
| W5.8: `TRUSTED_PROXIES` depends on W2.1 | **Confirmed**; wording matches W2.1 (§4) |

---

## 10. Tool runs (each tool's own exit code)

| Command | Exit |
|---|---|
| `bash docker/radius/tests/fetch-crl-test.sh dash` | 0 (85 passed, 0 failed) |
| `bash docker/radius/tests/fetch-crl-test.sh bash` | 0 (85 passed, 0 failed) |
| `shellcheck -s sh docker/radius/fetch-crl.sh` (0.11.0) | 1 — SC2329 *info* on `cleanup` (trap-invoked; false positive); `-S warning`: 0; `main`'s file: 0 |
| `shellcheck -s sh docker/radius/raddb/live/axiam-live.sh` | 0 |
| `actionlint .github/workflows/radius-e2e.yml` (1.7.12) | 0 |
| `freeradius -XC`, Static profile | 0 |
| `freeradius -XC`, Live profile | 0 |
| `freeradius -XC`, guide RadSec block / without `tls_max_version` | 0 / 1 |
| `rlm_cache` probe (`radclient`, §3.2) | Access-Accept; `A:…INSERTED`, `B:…=OLD`, `C:…not-inserted`, `D:…=FRESH` |
| `python3 scripts/check-radius-vendors-nothing.py --self-test` / plain | 0 / 0 |
| `bash scripts/check-doc-links.sh` | 0 (534 links, 78 files) |
| `python3 scripts/check-remediation-evidence.py` | 0 (5 verified, 0 failed) |
| `python3 scripts/check-spec-digest.py` | 0 |
| `python3 scripts/check-crate-layering.py` | 0 |
| `AXIAM_E2E_RADIUS=1 cargo test -p axiam-server --no-default-features --test radius_e2e` (local, Docker) | 0 — both tests passed (Static and Live; "Live cases passed in 97s"; 422.76 s in all) |
| `radius-e2e.yml` run 39306303259 (`workflow_dispatch`, `8450bc255`) | **success** (completed 19:03 UTC; the run before it, 39302612696 on `c90c8c13d`, success) |

---

## 11. Issue bodies

Filed on `ilpanich/axiam`, milestone `1.1.x`; each issue's body is the finding as
stated above, with its proposed fix and test, and ends with the attribution footer. A
search found no duplicate (#707 and #713 are the issues this wave closes).

| ID | Issue |
|---|---|
| R111W5-01 | [#720](https://github.com/ilpanich/axiam/issues/720) |
| R111W5-02 | [#721](https://github.com/ilpanich/axiam/issues/721) |
| R111W5-03 | [#722](https://github.com/ilpanich/axiam/issues/722) |
| R111W5-04 | [#723](https://github.com/ilpanich/axiam/issues/723) |
| R111W5-05 | [#724](https://github.com/ilpanich/axiam/issues/724) |
| R111W5-06 | [#725](https://github.com/ilpanich/axiam/issues/725) |
