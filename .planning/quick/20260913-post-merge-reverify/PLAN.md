---
task: Re-verify benchmarks and conformance after the 2026-09-12/13 merge wave
date: 2026-09-13
---

# Post-merge re-verification

Three asks from the user:

1. **PR #443 open-vs-merged discrepancy** — diagnose why GitHub shows it open.
2. **Pull `main`** in the server repo and all eleven SDK repos.
3. **Re-run** the base benchmarks, the SDK benchmarks, and the OIDC Basic OP +
   FAPI 2.0 conformance plans against the merged code.

## Baseline to beat

From the 2026-09-11 pre-tag verification (memory + `benchmarks/VERIFICATION-2026-09-11.md`):

| Run | Baseline |
|---|---|
| Base benchmarks | 22 PASS / 0 WARN / 6 SKIP / 0 FAIL (3m36s) |
| SDK benchmarks | 11 PASS / 0 FAIL (4m43s), all reporting `1.0.0-beta12` |
| Basic OP (35) | 30 PASS / 4 REVIEW / 1 SKIP / 0 FAIL |
| FAPI2 mtls (37) | 26 PASS / 10 REVIEW / 1 WARNING / 0 FAIL |
| FAPI2 self-signed (37) | 26 PASS / 10 REVIEW / 1 WARNING / 0 FAIL |
| FAPI2 private-key-jwt (56) | 44 PASS / 10 REVIEW / 1 SKIP / 1 WARNING / 0 FAIL |

**REVIEW is a terminal verdict, not a failure** — those modules are decided by
screenshot and signed off by a certification reviewer.

## What changed under the runs

- Server `main`: 45 non-merge commits since `d9b201611`, 105 files, +12 605 lines.
  Touches `axiam-api-rest` (`handlers/oauth2.rs`, `handlers/sessions.rs`,
  `error.rs`, `server.rs`), `axiam-amqp`, `axiam-api-grpc/middleware/strict_revocation.rs`,
  `axiam-server` (`cleanup.rs`, `main.rs`), and a large frontend test wave.
- All eleven SDKs moved from **contract 1.42 to 1.44**: §10.4 revocation feed,
  §21.3.1 alias refusal, §16 T-262 retry pin.

The 2026-09-11 report's "no harness drift" finding was reached against 1.42, so it
does not carry over unexamined.

## Standing operational rules (learned the hard way)

- `BENCH_TLS_PORT=18443` — 8443 is sage-gui.
- Bench certs are 30-day and rot **silently** (k6 skips TLS verify). Check dates first.
- Bench lockout policy lives in the ORG settings row, not the compose env var.
- Conformance `SUITE_PORT` is **8442**, not 8443.
- **One browser driver, ever.** Two deliver two callbacks and the suite throws
  `runInBackground called after runFinalisationTaskInBackground()`.
- `cargo clean` between plan steps; never during a run. Disk guard at 8 GB free.
- Server builds need `--no-default-features` (no system libxml2) and
  `SWAGGER_UI_DOWNLOAD_URL` pointing at the cached placeholder.

## Steps

1. [x] Diagnose PR #443.
2. [x] Pull all twelve repos (`--ff-only`).
3. [ ] Base benchmarks: `bench-certs` → `bench-up` → `bench-seed` → `bench-dry-run`.
4. [ ] SDK benchmarks: `sdk-dry-run` across all eleven languages.
5. [ ] Conformance: `conformance-up` → `serve-axiam` → register → drive →
       `conformance-run-basic` + `conformance-run`.
6. [ ] Write SUMMARY.md with the measured deltas against the baseline above.
