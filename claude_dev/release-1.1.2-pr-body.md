# Release 1.1.2

Patch release after 1.1.1. It adds no route and no migration. It closes the
Low and Informational findings the 1.1.1 reviews filed, the three contract
questions the maintainer answered on 2026-10-20 (contract **1.64**), and every
finding the 1.1.2 wave reviews filed, each fixed in its own wave. Plan:
[`claude_dev/release-1.1.2-plan.md`](claude_dev/release-1.1.2-plan.md);
the full account is the `[1.1.2]` section of `CHANGELOG.md`.

## Summary by wave

### W1 — erasure path, PKI, Vault

Exclusive, leased erasure claims (#738); a cut erasure is recovered with its proof and second revocation (#737); refresh-token rows deleted at erasure and swept in bounded batches (#753, #781); CRL cache no longer refuses a list dated ahead of the clock (#736); Vault-reason sanitiser masks a token after an escape (#740); erasure pseudonymizes `grantee.id` and records `network_role.unassigned` once (#758, #792); the wave review's sweep (#780 … #785): a stalled unit no longer overwrites its successor (#784).

### W2 — client address, rate limits, audit rows

One carrier rule for the request row (#751); audit IPs follow `TRUSTED_PROXIES` and record `forwarded_for_claimed` (#752); the principal bucket is keyed only by admitted tokens, refunds on 401/403 and skips revoked sessions (#754, #786); boot WARN and non-UTF-8 handling (#731, #732); `TRUSTED_PROXIES=none` (#758); `metadata.ingested_via = "amqp"` (#741); pins and scans (#733, #735, #788, #790); the `authenticated` verdict for every extractor (#787); text (#734, #789).

### W3 — schema runner, OAuth2 clients, spec

A real migration lease, no v110 (#755); refusal of out-of-order non-additive migrations (#729) with a recovery procedure (#771); two `422` codes on the admin client `PUT` (#746) and CIMD's own redirect bound (#768); four refusals declared in the spec (#756, #772); probe and test sweep (#769, #770, #773); text and the v109 `EXPLAIN` pin (#747).

### W4 — network policy

A cleared network write's row is written by a spawned task the handler awaits (#726), the stop waits for it (#776), and the revocation's flush follows it (#775); `network_role.deleted` row (#727); reconcile skips an unresolved tenant's network half (#728) and organization actions (#777); row content and text (#730, #778, #779); the decision cache refuses a pre-revocation insert (#791).

### W5 — FreeRADIUS recipe

The Live cache neither re-poisons (#720) nor inserts the sentinel (#764); lock-held `fetch-crl.sh` runs the age check (#721); a concurrent rotation step on a threaded server (#765); filter, comments, hygiene and text (#722, #723, #724, #725, #766, #767, #774).

### W6 — CI, tooling, maintainer-dependent issues

Test messages without tokens or bodies (#757); `bench-quick` and `apiIndex.ts` guards, the v109 note (#758); run-6 runbook re-pinned to 1.1.1 and the certification package re-checked, with comments on #561 and #513, which stay open.

### W7 — contract 1.64 and the eleven SDKs

Contract 1.64 (§34.8) answers the maintainer's three questions (#750, #760): the recovered erasure row's `certificates_revoked: null`, device polling through `429 rate_limit_exceeded`, relaxed C163-10 wording; two in-wave amendments (a 5xx is not terminal; the in-attempt retry test). Eleven SDK PRs, each closing its issue. Conformance review C164-01 … -59 across seven fix rounds.

### W8 — release readiness

Version 1.1.2 (`fb92ec4`), this CHANGELOG section, the roadmap row, the upgrade notes and this body. The regression gate (W8.1), the combined review (W8.2) and the threat-model reconciliation (W8.3) run on their own branches.

#### Upgrading to 1.1.2 — read before you upgrade

- **There is no migration, and the "roll replicas one at a time" note of 1.1.1 is
  withdrawn.** The runner now takes a real lease: the row `_migration_lock:startup`
  holds a `holder` and an `expires` on the datastore's clock (five minutes,
  refreshed every minute while it migrates). A replica that finds a live lease
  waits and logs `Another instance holds the migration lease; waiting for it`;
  the lease's holder deletes only its own row, and a migration another replica
  recorded first is read as "applied by another instance" and the boot
  continues. A rolling update or a scale-out from zero needs no special
  ordering. The lease's two fields are part of the setup DDL
  (`MIGRATION_TABLE_DDL`, `IF NOT EXISTS`), so no v110 was taken. **Give a
  starting replica time to wait:** the HTTP listener, and `/health` with it,
  is bound after the migrations, so a replica waiting for the lease answers no
  probe. The shipped `k8s/server/deployment.yml` gains a `startupProbe` on
  `/health` (10 s period, 60 failures); an orchestrator of your own needs the
  same allowance, or its liveness probe kills the waiting replica. A 1.1.1
  replica still running during the roll ignores the lease; that costs nothing
  from 1.1.1 to 1.1.2, which adds no migration (#755, #770, #769, #773).
- **The runner refuses an out-of-order application of a non-additive
  migration.** A migration missing below the newest one recorded (a datastore
  that ran a branch build) is still applied late with a `WARN`, but only if
  every statement is a `DEFINE … IF NOT EXISTS`; otherwise the replica stops
  with a boot error naming the version (`Migration vN '…' is not recorded but
  vM is, and vN is not additive …`) and has changed nothing. A released build
  never leaves such a gap. The procedure is in the deployment guide,
  "Recovering from a refused migration gap" (#729, #771).
- **`AXIAM__RATE_LIMIT__TRUSTED_PROXIES=none`** (case-insensitive, the whole
  value) now means "no proxy sits in front": no peer's `X-Forwarded-For` is
  read, every request is keyed on its peer on both listeners, and the boot logs
  no `WARN`. `none` beside other entries stops the boot. An empty value keeps
  its 1.1.1 meaning (every peer's header is read) and logs one `WARN` when
  either the REST or the gRPC listener has native TLS on. A value that is not
  valid UTF-8 stops the boot instead of being read as empty (#758, #731, #732,
  #790).
- **Audit rows' `ip_address` is now derived by the limiters' rule.** The
  request row's `ip_address`, the `ip_address` of the handlers' own rows and
  the `http.client_ip` log field are the transport peer unless it is listed in
  `TRUSTED_PROXIES`, then the rightmost untrusted hop; they no longer follow
  the leftmost `X-Forwarded-For` entry. The request row gains
  `metadata.forwarded_for_claimed`, the leftmost entry as the caller wrote it,
  when it differs. A query or an alert that read `ip_address` as the claimed
  address must read `forwarded_for_claimed` (#752).
- **AMQP-ingested audit rows carry `metadata.ingested_via = "amqp"`,** set by the
  server after the message's metadata is merged, so a producer's own
  `ingested_via` is overwritten; the server's own rows carry none. The console
  shows it and the export carries it. **Rows ingested before 1.1.2 carry
  none**, so the absence of the key does not prove a server wrote an older row
  (#741, #789).
- **An erased user's refresh-token rows are deleted at erasure,** after their
  revocation and in the same unit, and the cleanup task's `oauth2_refresh_token`
  job deletes every row expired more than seven days ago, revoked or not, at
  most 5 000 per tick. The first run after the upgrade works through the backlog
  over as many ticks as it needs. The replay record of a rotated token
  (`oauth2.refresh_token_replayed`, T-254) lasts as long as its row (#753,
  #781, #783).
- **Two new `422` codes on the admin client `PUT`.** On a client whose
  `managed_by` is `dcr` or `cimd`, `422 resource_exceeds_registration_policy`
  refuses an `allowed_resources` entry outside the tenant's
  `external_client_allowed_resources`, and `422
  redirect_exceeds_registration_policy` refuses a redirect host outside the
  registration policy (DCR's `dcr_allowed_redirect_hosts`, CIMD's own policy).
  A value the row already holds still saves. A console or script that widened
  such a client must narrow its request (#746, #768).
- **A role delete that releases a `network:` grant writes one
  `network_role.deleted` audit row,** with the role's id and name and its
  `network:` permissions (action, effect) as the gate read them. Delete a role
  with no `network:` grant and no row is written. An alert on
  `network_role.*` should include it (#727).
- **Upgrading from 1.1.0 directly.** 1.1.1 renamed the FreeRADIUS recipe's
  profiles (D3 is now **Static**, D4 is now **Live**), and the rename moved
  files and variable names. An operator who goes from 1.1.0 straight to 1.1.2
  replaces the recipe as one set:

  | 1.1.0 | 1.1.1 and later |
  |---|---|
  | `docker/docker-compose.radius-d4.yml` | `docker/docker-compose.radius-live.yml` |
  | `docker/radius/raddb/d4/` | `docker/radius/raddb/live/` |
  | `raddb/d4/axiam-d4.sh` | `raddb/live/axiam-live.sh` |
  | the modules file `raddb/d4/axiam_d4` | the modules file `raddb/live/axiam_live` |
  | `AXIAM_D4_URL`, `AXIAM_D4_SITE` | `AXIAM_LIVE_URL`, `AXIAM_LIVE_SITE` |
  | `/var/run/axiam-d4` | `/var/run/axiam-live` |
  | `$-INCLUDE /etc/freeradius/axiam-d4/verify.conf` in `raddb/eap` | `$-INCLUDE /etc/freeradius/axiam-live/verify.conf` |

  **The rename fails closed:** a mixed set (an `eap` file from one release beside
  a `raddb/live/` set from another, or an unrenamed `AXIAM_D4_URL`) makes
  FreeRADIUS reject every device and never admit one on a stale file. That is an
  outage, not an exposure. Replace the whole `docker/radius/raddb/` set and the
  compose override together, rename the two variables, mount
  `/var/run/axiam-live` where `/var/run/axiam-d4` was, and restart FreeRADIUS. A
  deployment that runs only the Static profile needs no change beyond taking
  the new `raddb` set whole. Also: `docker/radius/fetch-crl.sh` exits **3** when
  the installed list has less than a quarter of its lifetime left or has expired
  and, since 1.1.2, when it finds the lock held; alert on any non-zero exit. The
  Live compose override now starts FreeRADIUS as `freeradius -f -xx -l stdout`
  (it was `-X`, which serves one request at a time) (#725, #721, #765).



## SDK pull requests (contract 1.64)

Each is a draft on `claude/contract-1.64` and closes its own issue in its own
repository; the maintainer tags the SDK releases.

- ilpanich/axiam-typescript-sdk#150
- ilpanich/axiam-rust-sdk#138
- ilpanich/axiam-python-sdk#103
- ilpanich/axiam-c-sdk#77
- ilpanich/axiam-cplusplus-sdk#80
- ilpanich/axiam-csharp-sdk#111
- ilpanich/axiam-go-sdk#103
- ilpanich/axiam-java-sdk#121
- ilpanich/axiam-kotlin-sdk#80
- ilpanich/axiam-php-sdk#87
- ilpanich/axiam-swift-sdk#78

## Issues closed

Closes #720
Closes #721
Closes #722
Closes #723
Closes #724
Closes #725
Closes #726
Closes #727
Closes #728
Closes #729
Closes #730
Closes #731
Closes #732
Closes #733
Closes #734
Closes #735
Closes #736
Closes #737
Closes #738
Closes #739
Closes #740
Closes #741
Closes #746
Closes #747
Closes #750
Closes #751
Closes #752
Closes #753
Closes #754
Closes #755
Closes #756
Closes #757
Closes #758
Closes #760
Closes #764
Closes #765
Closes #766
Closes #767
Closes #768
Closes #769
Closes #770
Closes #771
Closes #772
Closes #773
Closes #774
Closes #775
Closes #776
Closes #777
Closes #778
Closes #779
Closes #780
Closes #781
Closes #782
Closes #783
Closes #784
Closes #785
Closes #786
Closes #787
Closes #788
Closes #789
Closes #790
Closes #791
Closes #792

### Issues that stay open

- **#513** (OpenID Basic OP and FAPI 2.0 certification submissions): W6.4 ticked
  T23.1.4 … T23.1.7 with the commits that executed them and re-checked the
  review judgements and the submission package against the 1.1.1 tree. Fresh
  runs of both plans on the `1.1.1` image, the submission and the website mark
  are the maintainer's; the issue closes with the submission.
- **#561** (benchmark run 6): W6.3 re-pinned the runbook to the `1.1.1` image
  and re-checked the target versions (Keycloak 26.8.1, Zitadel v4.19.5,
  authentik 2026.8.5). The run and its numbers are the maintainer's, and W6b
  did not run (no `benchmarks/results/run6/`); the issue closes with W6b's merge.

## Issue by issue

One line per closed issue; the `[1.1.2]` section of `CHANGELOG.md` has the entry.

| Issue | Wave | What it was |
|---|---|---|
| #720 | W5 | concurrent 401s put the refused token back in the Live cache |
| #721 | W5 | a lock-busy fetch-crl run skips the age check |
| #722 | W5 | the 401 retry's comment and tests claim more than they show |
| #723 | W5 | the e2e filter misses five paths |
| #724 | W5 | rename leftovers and hygiene |
| #725 | W5 | T-462 text and the upgrade note after W5 |
| #726 | W4 | a cleared network write's success row can be lost |
| #727 | W4 | deleting a role with a network: deny leaves no row |
| #728 | W4 | the reconcile revokes from a tenant whose kind it failed to read |
| #729 | W3 | the runner applies an older non-additive migration out of order |
| #730 | W4 | text and audit-row content after W4 |
| #731 | W2 | the empty-TRUSTED_PROXIES WARN ignores the gRPC listener's TLS |
| #732 | W2 | a non-UTF-8 TRUSTED_PROXIES is read as empty |
| #733 | W2 | the audit-wrap scan and the gRPC sweep pin less than they read |
| #734 | W2 | T-212 and T-428 name the removed public-client bucket |
| #735 | W2 | the bucket-name scan misses increment_by keys |
| #736 | W1 | the CRL cache refuses its own list while the datastore clock leads |
| #737 | W1 | an erasure cut between anonymization and record is recovered without its proof or second revocation |
| #738 | W1 | two replicas run one erasure at once |
| #739 | W1 | text behind the code after W1 (verified, no change needed) |
| #740 | W1 | the Vault-reason sanitiser misses a token after an escape |
| #741 | W2 | an AMQP-ingested audit row is indistinguishable from a server-written one |
| #746 | W3 | the admin PUT widens a self-registered client's resources and redirects |
| #747 | W3 | text and hygiene after W3; the v109 EXPLAIN pin |
| #750 | W7 | contract 1.63 text the SDK ports contradict (C163-10, C163-11) |
| #751 | W2 | a junk Authorization header detaches a cookie request from its user in the request row |
| #752 | W2 | audit and log IPs ignore the TRUSTED_PROXIES rule |
| #753 | W1 | an erased user's refresh-token rows are revoked, never deleted |
| #754 | W2 | the principal rate-limit key trusts a token the extractor refuses |
| #755 | W3 | the _migration_lock is never checked |
| #756 | W3 | the spec does not declare four refusals |
| #757 | W6 | test messages CodeQL flags |
| #758 | W1, W2, W5, W6, W8.3 | text and hygiene after the 1.1.1 merges |
| #760 | W7 | contract 1.64: recovered erasure row's null count; a device poll waits out 429 |
| #764 | W5 | the Live token cache's read can insert the - sentinel |
| #765 | W5 | the concurrent rotation step neither forces nor checks its race |
| #766 | W5 | text after W5 |
| #767 | W5 | hygiene after W5 |
| #768 | W3 | the admin PUT bounds a CIMD client's redirects by the DCR list |
| #769 | W3 | the migration lease's refresh and own-row release are untested |
| #770 | W3 | the k8s liveness probe kills a replica waiting on the lease |
| #771 | W3 | the non-additive gap refusal has no procedure |
| #772 | W3 | the hash gate's 503 undeclared on password change and reset confirm |
| #773 | W3 | text and hygiene after W3 |
| #774 | W5 | check-token-cache.py misses the action-block and optional call forms |
| #775 | W4 | a revocation's flush and stale-claim row still ride the handler's future |
| #776 | W4 | an orderly stop does not wait for a cleared write's task |
| #777 | W4 | the reconcile still revokes organization actions from an unresolved tenant |
| #778 | W4 | refusal_of reads index names as substrings |
| #779 | W4 | text after W4 |
| #780 | W1 | W1.6 turns network_gate_enumeration_test red |
| #781 | W1 | the refresh-token sweep is one unbounded DELETE |
| #782 | W1 | two audit_log reads on the erasure path scan the tenant's trail |
| #783 | W1 | T-254 on replay records after #753 |
| #784 | W1 | a unit stalled past the lease still scrubs the erased account |
| #785 | W1 | text and hygiene after W1 |
| #786 | W2 | a revoked-session token still spends its user's principal allowance |
| #787 | W2 | the D-12 verdict is left by some extractors only |
| #788 | W2 | the action-grammar pin misses pub(crate) and &'static str constants |
| #789 | W2 | "no ingested_via means server-written" is false before 1.1.2 |
| #790 | W2 | the gRPC address rule is a hand-copied twin; no gRPC test of none |
| #791 | W4 | the decision cache can insert a decision computed before a flush |
| #792 | W1 | a stalled unit's role pass can write a second network_role.unassigned row |

## Open after two sweeps

_None._ (To be filled by the orchestrator only if W9.4's review files anything.)

## W9 sweep

_Placeholder._ The issues filed by W8.2's combined review are added here when
W9 runs, each with its `Closes #N` line, and the CHANGELOG gains an entry for
each.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
