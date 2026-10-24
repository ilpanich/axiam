# Release 1.1.2 — upgrade-note drafts for W8.4

Drafts for the `[1.1.2]` section of `CHANGELOG.md`, written by W5.6 (#725) and
carried into the file by **W8.4**. Per maintainer decision D-9 of
[`release-1.1.2-plan.md`](release-1.1.2-plan.md) the released `[1.1.1]` entry is not
rewritten; its one-sentence version of this note stays as it is, and the paragraph
below is the full statement.

## Upgrading from 1.1.0 directly (#725)

Release 1.1.1 renamed the FreeRADIUS recipe's two profiles: D3 is now **Static** and
D4 is now **Live**. The rename moved files and variable names, so an operator who goes
from 1.1.0 straight to 1.1.2 must replace the recipe as one set. The names that moved:

| 1.1.0 | 1.1.1 and later |
|---|---|
| `docker/docker-compose.radius-d4.yml` | `docker/docker-compose.radius-live.yml` (the compose override) |
| `docker/radius/raddb/d4/` | `docker/radius/raddb/live/` |
| `raddb/d4/axiam-d4.sh` | `raddb/live/axiam-live.sh` |
| the modules file `raddb/d4/axiam_d4` | the modules file `raddb/live/axiam_live` (its four modules, `axiam_token`, `axiam_decide`, `axiam_token_cache` and `axiam_take`, keep their names; the compose override mounts it as `mods-enabled/axiam_placement` in both releases) |
| `AXIAM_D4_URL`, `AXIAM_D4_SITE` | `AXIAM_LIVE_URL`, `AXIAM_LIVE_SITE` |
| `/var/run/axiam-d4` | `/var/run/axiam-live` |
| `$-INCLUDE /etc/freeradius/axiam-d4/verify.conf` in `raddb/eap` | `$-INCLUDE /etc/freeradius/axiam-live/verify.conf` |

The new names are all in the tree (`git grep` finds `AXIAM_LIVE_URL`, `AXIAM_LIVE_SITE`,
`axiam-live.sh`, `axiam_live`, `raddb/live` and `/var/run/axiam-live` in the recipe,
the guide and the end-to-end test); the old ones survive only in historical text
(`CHANGELOG.md`, the release plans and review records, and the 1.1.0 entries of the
threat model).

**The rename fails closed.** The `eap` file includes the Live profile's `verify.conf`
by path, and the `axiam_live` module reads `AXIAM_LIVE_URL`. Therefore:

- an `eap` file from one release beside a `raddb/live/` set from another, or
- an unrenamed `AXIAM_D4_URL` (the `axiam_token` and `axiam_decide` modules' `connect_uri`, in `raddb/live/axiam_live`, is empty, so
  they fail, and the policy treats a module failure as a reject; FreeRADIUS may also
  refuse to start),

makes FreeRADIUS **reject every device**; it never admits one on the strength of a
stale file. That is an outage, not an exposure, but the operator must expect it. To
upgrade: replace the whole `docker/radius/raddb/` set and the compose override together
with the 1.1.2 files, rename the two environment variables in the deployment, mount
`/var/run/axiam-live` where `/var/run/axiam-d4` was, and restart FreeRADIUS. A
deployment that runs only the Static profile (no decision route) carries none of these
names and needs no change beyond taking the new `raddb` set whole.

Also worth restating in the same entry, because it changes what to alert on:
`docker/radius/fetch-crl.sh` exits **3** when the installed list has less than a
quarter of its lifetime left or has expired, and, since 1.1.2, a run that finds the lock
held reports it too (R111W5-02). Alert on any non-zero exit (T-462, amended
2026-10-22).

The Live compose override now starts FreeRADIUS as `freeradius -f -xx -l stdout` (it was
`-X`, which serves one request at a time): same debug output, with the thread pool. An
operator who copied the override's `command` gets threaded authentication from the new
file; one who runs without debug output is unaffected.

**Mixed-version rolls and the erasure claim.** A 1.1.1 replica's non-exclusive `claim_tx` ignores the exclusive claim 1.1.2 takes on an erasure. During a mixed-version roll one erasure can therefore still run twice (#738's 1.1.1 behaviour: one erasure record, a doubled SSF `account_purged` notification), bounded by the rollout window; once every replica runs 1.1.2 the claim is exclusive.
