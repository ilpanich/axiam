# Security review — release 1.1.2, wave W5 (F4)

**Date:** 2026-10-22.
**Against:** `claude/release-1.1.2-w5`, the whole wave diff `dc5bfd4..df6ad20` (6 commits,
16 files, 199 lines added and 35 removed): `0c876d7` (W5.1, #720, D-10), `bcf4cbb` (W5.2,
#721), `047e65d` (W5.3, #722), `ec21338` (W5.4, #723), `4a518e2` (W5.5, #724, #758 (b) code)
and `df6ad20` (W5.6, #725, D-9). Every commit carries one `gpgsig` header (SSH signing; the
sandbox has no `allowedSignersFile`, so `%G?` cannot verify).
**Scope:** plan §6 (W5's files: `docs/pki/freeradius.md`, `docker/radius/**`,
`crates/axiam-server/tests/radius_e2e.rs`, `.github/workflows/radius-e2e.yml`,
`website/src/docs/operate.ts`), the three comment edits in other crates
(`axiam-core/src/models/network.rs`, `axiam-api-rest/tests/network_decide_test.rs`,
`axiam-db/src/schema.rs`), T-462 and T-486 (both copies), the regenerated
`website/src/threatModel*.ts`, and `claude_dev/release-1.1.2-upgrade-notes.md`.
**Method:** every commit message and the full diff read, each claim checked against the
tree. The `rlm_cache` semantics W5.1 rests on were read from the FreeRADIUS
**`release_3_2_8`** sources, fetched from `raw.githubusercontent.com` into the scratchpad:
`src/modules/rlm_cache/rlm_cache.c` (`mod_cache_it` :436-570, `cache_insert` :243-358,
`cache_find` :165-213), `drivers/rlm_cache_rbtree/rlm_cache_rbtree.c` (the mutex),
`src/main/modcall.c` (`defaultactions`, post-auth), `src/modules/rlm_expr/rlm_expr.c`
(operator precedence), `src/modules/rlm_rest/rest.c` (the status-code debug line) and
`share/dictionary.freeradius.internal` (the `Cache-*` types). **No Docker daemon** exists in
this sandbox (the CLI is there, `/var/run/docker.sock` is not), so nothing was probed in the
pinned image and `freeradius -XC` was not run; the two `radius-e2e.yml` dispatches the
orchestrator made were read through the GitHub API instead (§6). `fetch-crl-test.sh` under
both shells, `shellcheck` 0.11.0, `actionlint` 1.7.12, the threat-model generator and the
repository's own checks were run (§9). This review fixes nothing.

---

## 0. Summary

**No Critical, High or Medium finding.** The two attributes W5.1 adds do what its commit
says, read off the 3.2.8 source rather than inferred from probes: `Cache-Read-Only` stops
the drop from creating an entry, and a negative `Cache-TTL` expires what is there and inserts
this request's token (§2.1). The lock-held run now reports a list near its end (W5.2), the
`401` path's comment and its stand-in test say what the code does (W5.3), the five paths are
in the filter (W5.4), the rename's last code comments are gone (W5.5) and T-462 carries its
amendment (W5.6). Both e2e dispatches ran the Live case and passed the strengthened
assertions (§6).

One **Low** finding is in the file W5.1 fixed, and it makes W5.1's own claim ("not a
re-poisoned cache") incomplete. The cache *read* is still two calls, a status-only probe and
then a plain call. When another thread drops the entry between the two, the second call
**inserts** an entry holding the sentinel `-`, which the token check accepts. A thread that
has just logged in then merges that `-` over its fresh token and is rejected with no retry.
The window is narrow and the failure is closed, but it is the same class as R111W5-01. Three
Informational findings cover the concurrency test (it does not force the race and cannot fail
on 1.1.1's file unless the timing happens to line up), text, and hygiene.

| ID | Finding | Severity | Surface / threat | Origin | Issue | Model for the fix |
|---|---|---|---|---|---|---|
| R112W5-01 | The cache read (`check-eap-tls:60-94`) is a status-only probe followed by a plain call. A drop by another thread between the two makes the plain call **insert** `Tmp-String-2`, still the sentinel `-`, with the module's 600 s TTL. `-` passes the token regex at `:95`, contrary to `:30-34`. A first-fetch store (`:87-90`, positive TTL) that then finds this entry merges `-` over the token just fetched; with `Tmp-Integer-1 = 1` the `401` that follows is a reject with no retry. | Low | `raddb/live/check-eap-tls:35-44, 60-97`; T-486 | pre-existing (1.1.0's read; widened by #707's drop), in the file W5.1 claims to have closed | [#764](https://github.com/ilpanich/axiam/issues/764) | **Opus 5.5** |
| R112W5-02 | The concurrent rotation step neither forces the interleaving nor checks that it happened. It passes on 1.1.1's file unless thread B's drop falls inside thread A's login, and it passes too when the two attempts do not overlap at all: the log window is shared, so one thread's `401` satisfies the assertions. D-10's fallback (a deterministic case) was not shipped. `log_has_status_code` also accepts a bare `401` token on any line naming the attribute, which the `(N)` request-number prefix of `-X` can supply. | Informational | `radius_e2e.rs:2709-2723, 3197-3246` | wave (W5.1, W5.3) | [#765](https://github.com/ilpanich/axiam/issues/765) | **Opus 5.5** |
| R112W5-03 | Text behind the code: the guide's lock paragraph still says a lock-held run "raises no alert", although it now exits 3; T-486's W5.1 amendment names the inner `decision_per_authentication`, not the test; its W5.3 amendment says the two decision calls start "with the cached or fetched token", but a fetched token is never retried; the upgrade-note draft names a module `axiam_d4`/`axiam_live` that does not exist (the file holds four modules and is mounted as `mods-enabled/axiam_placement`). | Informational | `freeradius.md:509-512`; T-486 (both copies); `release-1.1.2-upgrade-notes.md` | wave (W5.2, W5.1, W5.3, W5.6) | [#766](https://github.com/ilpanich/axiam/issues/766) | Sonnet 5.5 |
| R112W5-04 | Hygiene. `schema.rs:7217`'s `(D4 —` is not "runtime text", as W5.5's body says. It is the failure message of the `#[test]` `every_migration_version_is_unique_and_ordered`, so W5.5's own acceptance `grep` still finds a RADIUS `D4` in `crates/`. The lock-held `mkdir` case does not assert "no request" as the four `flock` cases do. `fetch-crl.sh:75` was left at 124 columns. | Informational | `axiam-db/src/schema.rs:7217`; `fetch-crl-test.sh:339-341`; `fetch-crl.sh:75` | wave (W5.5, W5.2) | [#767](https://github.com/ilpanich/axiam/issues/767) | Sonnet 5.5 |

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| W5.1's `rlm_cache` semantics against the 3.2.8 source; how verified | §2.1 |
| W5.1's concurrent step against the old recipe; is D-10's probe needed | §2.3; R112W5-02 |
| Anything else in the Live file under concurrency | §2.2; R112W5-01 |
| W5.3's `log_has_status_code` against a real `-X` log; the dispatched runs | §3, §6; R112W5-02 |
| W5.2 `busy()` and its tests | §4 |
| W5.4 filter | §5 |
| W5.5 and the `(D4 —` at `schema.rs:7217` | §7; R112W5-04 |
| T-462 and T-486 copies; the website's generated files | §8 |
| W5.6's upgrade-note draft | §7; R112W5-03 |
| Every commit message against the code; §10 | §10 |
| Tool runs | §9 |

---

## 2. The Live token cache (W5.1, #720)

### 2.1 What `rlm_cache` 3.2.8 does: verified from the source

`mod_cache_it` (`rlm_cache.c:436-570`), in order:

1. `cache_find` (`:165-213`): a hit whose `expires < request->timestamp` is expired in the
   driver and reported as a miss.
2. `Cache-Status-Only` set: return `ok`/`notfound`, touch nothing (`:470-475`).
3. `ttl = inst->ttl`, overridden by `Cache-TTL` when present (`:479-480`; the attribute is
   `signed`, dictionary.freeradius.internal:269).
4. **No entry:** `ttl` 0 → `inst->ttl`, `ttl < 0` → `-ttl`, then `goto insert` (`:485-494`).
5. **An entry, `Cache-TTL` present:** 0 → expire, return `ok` (`:499-504`); `< 0` →
   expire, then `goto insert` with `-ttl` (`:506-511`); `> 0` → reset the expiry, fall through.
6. **An entry otherwise:** `cache_merge` it into the request, return `ok` (`:520-525`).
7. `insert:` if `Cache-Read-Only` is set, return `notfound` with nothing inserted
   (`:530-534`); else `cache_insert` (`:243-358`), which builds the entry from the module's
   `update` map, i.e. from **this request's** `control:Tmp-String-2`, merges it back (a no-op
   on the request's own values) and returns `updated`.
8. `finish:` **`Cache-TTL`, `Cache-Status-Only`, `Cache-Read-Only` and `Cache-Merge` are
   removed from `control`** (`:548-560`).

The rbtree driver takes `driver->mutex` in `acquire` and releases it in `release`
(`rlm_cache_rbtree.c:304-320`), so one `mod_cache_it` call is atomic; two calls by one thread
are not.

Against the file:

- **The drop (`:134-139`)**, `Cache-Read-Only := yes` and `Cache-TTL := 0`. Present → rule 5,
  expired, `ok`. Absent → rule 4 sends it to `insert`, and rule 7 returns `notfound` without
  inserting. `notfound` in post-auth is action `1` (continue; `modcall.c` `defaultactions`,
  post-auth group), so the section carries on to `:140`. **Holds.**
- **The retry's store (`:169-173`)**, `Cache-TTL := "%{expr:0 - %{1} / 2}"`. `rlm_expr`
  binds `/` (precedence 4) tighter than `-` (3) (`rlm_expr.c:167-172, 438-490`), so this is
  `-(expires_in / 2)`, at least `-50` given the `[1-9][0-9]{2,5}` capture. Present → rule 5,
  expire, insert this request's token. Absent → rule 4, insert it. Read-only cannot be set
  (step 8 already removed it). The request keeps its own `Tmp-String-2`. **Holds.** The CI
  run on `0c876d7` passed through this store and was admitted (§6), so the expression parses
  in the pinned image.
- `Cache-Read-Only !* ANY` (`:170`) and `Cache-Status-Only !* ANY` (`:135`) are redundant,
  because step 8 already cleared both. They are harmless defence, and the W5.1 body's "is
  cleared again" is accurate.

How verified: source reading of `release_3_2_8`, not a probe. It agrees with the 1.1.1
review's probe results (`A:…INSERTED`, `B:…=OLD`, `C:…not-inserted`, `D:…=FRESH`), and the CI
Live case exercised both new lines.

### 2.2 R112W5-01: the cache read can insert the sentinel (Low)

Step 2 of the recipe reads the token in **two** calls (`:60-63`, then `:93`):

```
update control { Cache-Status-Only := yes }
axiam_token_cache                 # found / notfound, touches nothing
if (notfound) { … fetch, store with a positive TTL … }
else { axiam_token_cache }        # a plain call: merge if present, INSERT if absent
```

By rule 8 the second call carries no `Cache-*` attribute. When another thread's drop (`:139`)
removes the entry between the two calls, the second call takes rule 4 with `ttl = 600`
(`axiam_live:105`) and **inserts** this request's `control:Tmp-String-2`. That value is still
the sentinel `-` from `:38`. And `-` passes `:95`, `/^[A-Za-z0-9._~+\/=-]+$/`, because `-` is
in the class. This breaks the invariant `:30-34` states ("given a value that matches nothing
first"): it holds for Tmp-String-0, -1, -3, -4 and -5, not for -2.

What follows, with A the thread that got the `401` and dropped:

- **X, the thread that inserted it**, sends `Authorization: Bearer -`, gets a `401`, has
  `Tmp-Integer-1 = 0`, and drops and retries: admitted, at one extra login.
- **Y, any thread that reads it**, does the same: admitted, at one extra login.
- **C, a thread that missed** (its probe ran after A's drop) and logged in has
  `Tmp-Integer-1 = 1`. Its store (`:87-90`, **positive** TTL) finds X's entry and takes rule 5
  (reset expiry) then rule 6, **merging `-` over the token it just fetched**. C decides with
  `-`, gets a `401`, and `:140` rejects it **with no retry**. A valid device is refused.

The cache heals at the next drop or the next negative store, so the end state is not a
lasting poison. In the transient state, though, a `-` entry is served, and W5.1's sentence
"a rotation under load costs one extra login per thread, not a re-poisoned cache" (commit
body, guide §5, T-486) does not hold for C. The same two-call window exists at plain TTL
expiry: a thread with a later `request->timestamp` expires the entry between another
thread's probe and its call. That makes it pre-existing since 1.1.0, but the drop of #707
added a second, explicit way to open it.

The first-fetch store has a related gap. Even with no sentinel, rule 6 merges *another*
thread's token over C's own, so `Tmp-Integer-1 = 1` ("this authentication fetched the token
it uses") is false for C. If that other token is refused (it was fetched just before a
rotation), C is rejected without the retry it would have earned.

Likelihood: the window between two consecutive module calls of one thread is microseconds.
It needs a drop or an expiry to land in it, and a fetching thread to store before the next
drop. Impact: one valid authentication refused (the NAS retries), and a `Bearer -` sent to
AXIAM. Fail-closed. **Low**, as R111W5-01 was.

**Proposed fix** (`check-eap-tls`; every attribute named here is read off §2.1):

1. Make the read **one read-only call**:
   `update control { Cache-Read-Only := yes }` then `axiam_token_cache`, then
   `if (notfound) { … fetch … }`. Present → merged; absent → `notfound`, nothing inserted.
   This removes the probe, the `else` branch and the window between them.
2. Store the **first fetch with the negative TTL too**
   (`Cache-TTL := "%{expr:0 - %{1} / 2}"` at `:88`), so the token a request decides with when
   `Tmp-Integer-1 = 1` is always the one it fetched. Another thread's fresh entry is replaced
   by an equally fresh one.
3. Give `Tmp-String-2` a sentinel the token regex refuses (e.g. `!`), so `:30-34`'s rule holds
   for every attribute, and add a comment saying so.
4. Guide §5 and T-486 (dated, both copies): no call on `axiam_token_cache` can create an
   entry that does not hold a token this request fetched.

**Test:** the D-10 fallback, made deterministic. Add `docker/radius/tests/` cases that drive
`axiam_token_cache`, shaped exactly as `axiam_live:102-109`, through the recipe's call
sequences in the pinned image with `radclient`: an empty cache read read-only → `notfound`,
and a later status probe → `notfound` (nothing inserted); a first-fetch store over an
existing entry → the request keeps its own token. Run the cases in `radius-e2e.yml` beside
`fetch-crl.sh cases`. Add a static check (a few lines of Python in `scripts/`, with
`--self-test`) that every `axiam_token_cache` call in `raddb/live/check-eap-tls` is preceded,
in the same `update control`, by `Cache-Read-Only := yes` or a negative `Cache-TTL`. Against
today's file the static check fails at `:63`/`:93` and `:90`.

### 2.3 R112W5-02: the concurrent step does not witness #720 (Informational)

Under 1.1.1's file the refused token comes back only if **B's drop falls strictly between A's
drop and A's store**, i.e. while A's `/api/v1/auth/device` call is in flight. Only then does
B's `Cache-TTL := 0` find no entry and insert, and A's positive store merge it. In every other
interleaving the old file admits both:

- **Serialized** (B's post-auth after A's store): B reads A's new token, gets no `401`, and is
  admitted.
- **B drops after A stored:** B expires A's token, logs in, stores into an empty slot, and is
  admitted.
- **B reads after A's drop:** B misses, logs in, and its positive store merges A's (valid)
  token. Admitted.

The two `eapol_test` processes start in the same tick (`tokio::join!`, each after its own
1.1 s sleep), but a full EAP-TLS handshake each, plus AXIAM serving both on the test's single
runtime, leaves the order of the post-auth sections to chance. The assertions read
`healed.log`, which is `docker logs --since <second>` and so **shared by both attempts**. One
thread's `401`, login and two decisions satisfy them all. Nothing shows that both attempts
read the old token. The test therefore cannot tell a serialized run from a raced one, and on
1.1.1's file it fails only in the one interleaving above. The commit body and T-486 say so
honestly ("fails on the old file only when the two overlap"). D-10's default was "the e2e,
the probe as fallback" where the e2e cannot be made deterministic, and no probe was shipped.

Separately, `log_has_status_code` (`:2709-2723`) splits a line that names
`REST-HTTP-Status-Code` on non-digits and accepts any `401` token. `rest.c:2428` writes
`Adding reply:REST-HTTP-Status-Code = "%d"`, and `-X` prefixes each line with the request
number `(N) `, so a `200` written by request 401 also matches. The other assertions of the
rotation step keep it from being vacuous today (about a hundred requests have run by then),
but the doc comment's "a bare `401` elsewhere … is not the answer" is broader than the code.

**Proposed fix (test only):** force the race in the e2e. For the rotation step, wrap the app of
`serve_axiam_on` with an `actix_web` `wrap_fn` holding two barriers, each released at two
arrivals or after 10 s:

- hold every `POST /api/v1/network/decide` answer until two have arrived, so both threads
  have read the old token before either drops;
- hold every `POST /api/v1/auth/device` until two have arrived, so both drops precede both
  stores.

The pools allow it (`max = 8` on both `rest` modules; FreeRADIUS's default thread pool). On
1.1.1's file the second drop then always finds no entry and inserts the refused token, and
both attempts are rejected. On W5.1's file both are admitted. Also assert the step's log
holds two `/api/v1/auth/device` and two `401`s, and match `REST-HTTP-Status-Code = "401"`
exactly (or the `EXPAND` / `--> 401` pair). The `radclient` cases of R112W5-01 are the
deterministic witness of the cache rules themselves.

---

## 3. The `401` path's comment and tests (W5.3, #722)

- **The comment (`:103-108`)** matches `rlm_rest.c` `mod_common` as the 1.1.1 review read
  it. In post-auth every 4xx is `invalid`, `invalid = 1` continues, `:127` rejects anything
  but `401`, and a 5xx (`fail`) or a transport failure ends the section. **Holds.**
- **The decision counter** (`Stub::decisions`, `fetch_add` per `/api/v1/network/decide`) is
  read before and after each refused answer. The `401` stand-in is the **last** of the
  nineteen. The stub's `expires_in` is 900, so the cached entry lives 450 s, and the step
  takes about 48 s in CI. The token is therefore cached when the `401` arrives, the retry runs,
  and the count is 2. 1.1.0's file asks once and fails; a looping retry asks more than twice
  and fails. Every other answer is asked once, because a non-`401` 4xx is rejected at `:127`
  before the drop. **Holds.** The test relies on the `401` not being the first answer after a
  cold cache, where the count is 1 by design. A comment there would help, and R112W5-03(b) is
  about the matching T-486 sentence.
- **`log_has_status_code`:** the line `rest.c:2428` writes names the attribute and the
  status, so the first branch matches it; the second branch covers the `EXPAND` of `:121`. The
  CI run on `047e65d` passed the rotation assertion that uses it (§6). It is broader than its
  comment: R112W5-02.

---

## 4. `fetch-crl.sh`'s lock-held run (W5.2, #721)

`busy()` (`:202-210`) prints the lock line, runs `near_expiry`, and exits 3 or 0. `armed` is
still unset, so this is the only place a lock-held run can turn into 3. `near_expiry` reads
only `$ca_file` and `$capath/<hash>.r0`, both set before the lock (`:164-165`), and touches
nothing. Installs are an atomic `mv`, so the list it reads is whole. Both callers of `busy`,
the `flock -n` failure and the directory lock's "not stale" and "five tries" exits, now
report the age. The five new cases pass under `dash` and `bash` (90/90). The commit's
"with the script change stashed … 87 passed, 3 failed" fits: the near-end, expired and
`mkdir` cases need the change, while the healthy and no-list cases pass either way. The guide
(`:540-547`), the header (`:68-76`) and `operate.ts` say the same as the code. The leftover
"raises no alert" sentence is R112W5-03(a), and the case gaps are R112W5-04.

R111W5-02's second half (exit 3 replacing exit 1 for an alert that routes by code) is
answered as the plan asked: the guide says exit 3 can carry a refusal whose reason is on
stderr, and to alert on any non-zero exit.

---

## 5. The filter (W5.4, #723)

The five paths are in `pull_request.paths` (`radius-e2e.yml:73-80`) and all five exist. The
workflow has no `push` trigger, so this is the only filter, as the commit says. The file
itself, `docker/radius/**` (the new `tests/` cases included) and the guide are listed.
`yaml.safe_load` and `actionlint` pass. **Holds.**

---

## 6. The two `radius-e2e.yml` dispatches

Read through the GitHub API (`actions_list` / `get_job_logs`):

| Run | Head | Job | `RADIUS e2e` step | Evidence the Live case ran |
|---|---|---|---|---|
| 39758001237 | `0c876d7` | 119754815991 | success, 09:48:31-09:59:44 | `[radius-e2e] rotation … two concurrent authentications each got the 401 …` at 09:53:10; `mapping 19 answers … every one refused`; `done Live cases passed in 110s`; `2 passed` |
| 39764913490 | `047e65d` | 119777657668 | success, 10:42:56-10:50:44 | the job env shows `AXIAM_E2E_RADIUS: 1`; `rotation …` at 10:49:33; `mapping 19 answers …` at 10:50:44; `done Live cases passed in 101s`; `2 passed`. The `fetch-crl.sh cases` step passed too |

`say(...)` runs after the assertions of its step, so the `rotation` and `mapping` lines show
that the concurrent step, `log_has_status_code`, and the per-answer decision count all
**executed and held** on `047e65d`. What the logs do **not** show is the FreeRADIUS `-X` log
itself: the job prints it only on failure, and `--nocapture` does not include
`Attempt::log`. So *which* branch of the matcher matched, and whether the two attempts
interleaved, cannot be read from them (R112W5-02). No dispatch ran on the wave head
`df6ad20`. The three later commits change no recipe or test logic: `ec21338` changes the
filter, `4a518e2` comments, the README and `fetch-crl.sh`'s comments, and `df6ad20` text.
This review re-ran `fetch-crl-test.sh` on the head (§9).

---

## 7. W5.5 and W5.6

- **The three D4 comments** now read "the Live profile". The v100 banner (`schema.rs:4899`)
  is a site the 1.1.1 review had listed as history left on purpose. Rewording a migration's
  banner is not a dated pass description, so §10 allows it.
- **`schema.rs:7217`.** It sits inside `#[cfg(test)]`, in the message of the
  `assert_eq!(versions.last(), Some(&109), …)` of `every_migration_version_is_unique_and_ordered`.
  It is printed only when that test fails and ships in no binary. It is not "runtime text",
  and nothing asserts on its content. Leaving it keeps W5.5's acceptance `grep` from being
  true. W3 will bump this assertion's head (v110, if W3.1 takes it) about 25 lines above, which
  is not a merge conflict for a one-word change at `:7217`. R112W5-04.
- **`shellcheck` SC2329** is silenced with its reason, and `shellcheck -s sh` exits 0. The
  header now names the untrapped signals. **The README history note** is accurate:
  `f0fe8b064` added `trap 'exit 1' HUP INT TERM` beside the `trap cleanup EXIT` of
  `384d2c772`, and `3da7e0c` is the contract 1.62 conformance review.
- **The upgrade-note draft (W5.6).** Every old and new name was checked against `v1.1.0` and
  the head: `docker-compose.radius-d4.yml`, `raddb/d4/`, `axiam-d4.sh`, `AXIAM_D4_URL`/`SITE`,
  `/var/run/axiam-d4` and the `$-INCLUDE` path all moved as listed. The row "the module
  `axiam_d4`" is wrong in kind. The file `axiam_d4` (now `axiam_live`) defines `rest
  axiam_token`, `rest axiam_decide`, `cache axiam_token_cache` and `exec axiam_take`, whose
  names did not change, and it is mounted as `mods-enabled/axiam_placement` in both
  releases. The same applies to "the `axiam_live` module's `connect_uri`". R112W5-03(c). The
  fail-closed reasoning matches the 1.1.1 review's §5.

---

## 8. The threat model and the website's generated copies

- **T-462** (one 2026-10-22 amendment, 2 734 characters) and **T-486** (two, W5.1 and W5.3)
  are found **verbatim** in `Axiam.json`'s `mitigation`: each STRIDE paragraph was extracted
  and searched for in the decoded JSON string by script. Both stay **Open**, with no model
  version bump, as W8.3 expects.
- The T-462 amendment's test names were checked against `fetch-crl-test.sh`: all sixteen
  exist with that exact text.
- T-486's W5.1 amendment names `radius_e2e.rs::decision_per_authentication`. That is the inner
  `async fn` (`:2755`); the test is `a_decision_per_authentication_places_revokes_and_quarantines`
  (`:2744`), as the 2026-10-19 amendment names it. Its W5.3 amendment says the two calls
  start "with the cached or fetched token", but a fetched token gets one call (`:140`).
  R112W5-03(b).
- `node website/scripts/gen-threat-model.mjs` on the head exits 0 and leaves
  `website/src/threatModel.ts` and `threatModelSummary.ts` byte-identical. The generated
  copies are consistent with `Axiam.json`.

---

## 9. Checks run (each tool's own exit code)

| Command | Exit |
|---|---|
| `bash docker/radius/tests/fetch-crl-test.sh dash` | 0 (90 passed, 0 failed) |
| `bash docker/radius/tests/fetch-crl-test.sh bash` | 0 (90 passed, 0 failed) |
| `shellcheck -s sh docker/radius/fetch-crl.sh` (0.11.0) | 0 |
| `shellcheck -s sh docker/radius/raddb/live/axiam-live.sh` | 0 |
| `shellcheck -S warning docker/radius/tests/fetch-crl-test.sh` | 0 |
| `actionlint .github/workflows/radius-e2e.yml` (1.7.12) | 0 |
| `python3 -c 'yaml.safe_load(…radius-e2e.yml)'` | 0 |
| `cargo fmt -p axiam-server -p axiam-core -p axiam-db -p axiam-api-rest -- --check` | 0 |
| `npx tsc -b` (website) | 0 |
| `node website/scripts/gen-threat-model.mjs`, then `git status` | 0; no diff |
| `bash scripts/check-doc-links.sh` | 0 (537 links, 78 files) |
| `python3 scripts/check-remediation-evidence.py` | 0 (0 verified, 37 skipped: no network to the evidence hosts) |
| `python3 scripts/check-radius-vendors-nothing.py` / `--self-test` | 0 / 0 (18 cases) |
| `python3 scripts/check-crate-layering.py` | 0 |
| `python3 scripts/check-spec-digest.py` | 0 |
| T-462 / T-486 copy comparison (script, §8) | all three amendments found verbatim |
| `git cat-file -p <c> \| grep -c gpgsig`, six commits | 1 each |
| `radius-e2e.yml` run 39758001237 (`0c876d7`), 39764913490 (`047e65d`) | success / success (§6) |
| `freeradius -XC`, the Live e2e locally, `rlm_cache` probes | **not run**: no Docker daemon |

---

## 10. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `0c876d7` | read-only drop; negative TTL on the retry's store; two concurrent attempts; guide and T-486 | the two attributes do what is said (§2.1); "not a re-poisoned cache" is incomplete (R112W5-01); the step does not witness the fix (R112W5-02, stated honestly in the body) |
| `bcf4cbb` | `busy()` exits 3 near the end; five cases; 85 → 90 | true (§4); one text leftover (R112W5-03 a) |
| `047e65d` | comment; decision count; status-code matcher; T-486 | true (§3); matcher broader than its comment (R112W5-02); T-486 wording (R112W5-03 b) |
| `ec21338` | five paths; no `push` trigger | true |
| `4a518e2` | three comments; SC2329; header; README note; `:7217` "runtime text" left | true, except the characterisation of `:7217` (R112W5-04) |
| `df6ad20` | T-462 amended; website regenerated; upgrade-note draft | true; one wrong row in the draft (R112W5-03 c) |

§10: every commit is signed. There is no `sdks/CONTRACT.md` edit, no new route, migration or
crate, and no change to the spec. Each row's test is in its own commit (W5.2 extends the
script's own test; W5.1 and W5.3 the e2e; W5.4, W5.5 and W5.6 are text or CI and name their
checkers). Threat-model corrections are dated in their entries, and older sentences stay as
history. No test message interpolates a token or a secret: the new assertions print
`attempt.report()` and the FreeRADIUS log, which carry the `Authorization: Bearer` header of
the test's own stub or test tokens, as 1.1.1's did. The `say` lines carry none.

---

## 11. What could not be verified

- **Nothing was executed in the pinned FreeRADIUS image** (no Docker daemon): no `-XC`, no
  `radclient` probe, no local Live run. The `rlm_cache` behaviour of §2.1 and R112W5-01 is
  read from the `release_3_2_8` source. That the image was built from that tag is taken from
  its tag (`3.2.8`) and the 1.1.1 review's probes, which agree with this reading.
- **Whether the two concurrent attempts interleaved** in either CI run, and which branch of
  `log_has_status_code` matched: the job does not print the `-X` log on success (§6).
- **That the old (1.1.1) file fails the new concurrent step** was not measured; §2.3 argues
  from the source that it fails in only one interleaving.

---

## 12. For later tasks

- **W8.3:** T-486 receives the R112W5-01 fix's amendment and the R112W5-03(b) corrections
  (dated, both copies). T-462 is already consistent. Regenerate `threatModel*.ts` after.
- **W8.4:** take the upgrade-note draft with R112W5-03(c)'s correction. The CHANGELOG
  sentence for #720 should say "one extra login per thread" only once R112W5-01 is fixed.
- **W7.1:** nothing. No contract surface moved.

---

## 13. Issues

Filed on `ilpanich/axiam`, milestone `1.1.x` (#23). Each body is the finding's subsection
and ends with the attribution footer. Searches for the cache, the concurrency test and the
lock-held run found only #720 … #725, which this wave closes, so there are no duplicates.

| ID | Issue |
|---|---|
| R112W5-01 | [#764](https://github.com/ilpanich/axiam/issues/764) |
| R112W5-02 | [#765](https://github.com/ilpanich/axiam/issues/765) |
| R112W5-03 | [#766](https://github.com/ilpanich/axiam/issues/766) |
| R112W5-04 | [#767](https://github.com/ilpanich/axiam/issues/767) |

### R112W5-03 (Informational): text behind the code

(a) `docs/pki/freeradius.md:509-512`: "A run that finds the lock held prints that and
touches nothing: it is not a failure (it exits **0**, or **3** when the installed list is
near its end, below), so a timer that overlaps … raises no alert." An exit 3 *is* an alert, by
the guide's own "alert on any non-zero exit", so "raises no alert" now holds only for a
healthy list. Say: "an overlap alone raises no alert; a list near its end does, as below."
(b) T-486, both copies: the W5.1 amendment names `radius_e2e.rs::decision_per_authentication`
(the inner `async fn`, `:2755`); name the test,
`a_decision_per_authentication_places_revokes_and_quarantines`. The W5.3 amendment says the
two decision calls are "the first with the cached or fetched token". A fetched token is never
retried (`check-eap-tls:140`), so the count is two only because the stand-in's token is
cached. Say "the first with the cached token", and add a line at the stand-in in
`radius_e2e.rs` saying it must not be the first answer after a cold cache. (c)
`claude_dev/release-1.1.2-upgrade-notes.md`: the row "the module `axiam_d4`
(`raddb/d4/axiam_d4`) → the module `axiam_live`" and the bullet "the `axiam_live` module's
`connect_uri` is empty" name a module that does not exist. The file defines `rest
axiam_token`, `rest axiam_decide`, `cache axiam_token_cache` and `exec axiam_take`, whose names
did not change, and the compose override mounts it as `mods-enabled/axiam_placement` in both
releases. Say "the module file `raddb/d4/axiam_d4` → `raddb/live/axiam_live` (mounted as
`mods-enabled/axiam_placement`; the module names inside are unchanged)" and "the `rest`
modules' `connect_uri`". Test: none (text); `check-doc-links.sh`,
`check-remediation-evidence.py`, and `gen-threat-model.mjs` with no diff after T-486.

### R112W5-04 (Informational): hygiene

(a) `crates/axiam-db/src/schema.rs:7217`, "v100 was #563 (D4 — …": this is the failure
message of the `#[test]` `every_migration_version_is_unique_and_ordered`, compiled only under
`#[cfg(test)]`, not runtime text as `4a518e2`'s body says. So the W5.5 acceptance `grep -rn -E
'\bD[34]\b'` over `crates/` still finds a RADIUS `D4`. Replace `D4 —` with `the Live RADIUS
profile —`. W3's bump of the same assertion edits its head, about 25 lines above, so the two
do not conflict. (b) `docker/radius/tests/fetch-crl-test.sh:339-341`: the lock-held `mkdir`
case does not assert `[ "$(reqs)" = 0 ]`, which the four `flock` cases do; add it. Also add the
healthy-list case for the directory lock, so that both lock kinds cover both outcomes. (c)
`docker/radius/fetch-crl.sh:75` was left at 124 columns by `bcf4cbb`; re-wrap it like its
neighbours. Test: `fetch-crl-test.sh` under `dash` and `bash`; `shellcheck`; `cargo test -p
axiam-db --lib every_migration_version_is_unique_and_ordered`; the acceptance `grep`.
