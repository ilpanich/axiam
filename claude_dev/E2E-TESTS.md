# Local E2E prompt — full RBAC / PKI matrix against a working-tree prod stack

Run this in a **fresh session on your PC**, in the `axiam` checkout, on a branch
off the merged `main`. It needs Docker, `just`, `caddy`, `node`, and the Rust
toolchain.

---

Bring up the **production-like stack built from this working tree** (not the
published images), bootstrap it, then drive the entire admin surface through
Playwright as several principals with different grants, and assert at every step
that each one can do exactly what its roles allow and **nothing more**. Fix every
defect you find, frontend or backend.

**Work in waves, not one bug at a time.** The backend image is Rust and rebuilds
slowly, so a run that stops at its first failure buys you one finding per image
build. Instead: run the full matrix to the end collecting *every* failure, fix
the whole batch, rebuild once, run again — until a wave comes back clean.
Section 5 is how to do that, and it governs the rest of this prompt.

## 0. Stack — from local source, with HTTPS

`just prod-up` pulls `ghcr.io/ilpanich/axiam/*` by default. You need the working
tree instead, so first:

1. In `docker/docker-compose.prod.yml`, for **both** `axiam-server` and
   `axiam-frontend`: comment out the `image:` line and uncomment the `build:`
   block beneath it.
2. Bring it up with a build: `docker compose -f docker/docker-compose.prod.yml up --build -d`
   (or restore `--build` in the `prod-up` recipe and run `just prod-up`).
3. **Leave host port 8080 alone — SAGE is on it.** The prod compose does not
   want it: it publishes **8090** (REST API), **8081** (frontend), **50051**
   (gRPC) and **127.0.0.1:8200** (Vault). So there is no conflict as shipped.

   One line looks like a conflict and is not:
   ```yaml
   - "8081:8080"   # host 8081 -> container 8080
   ```
   The right-hand `8080` is inside the container's own network namespace. It
   never binds on the host and must not be "fixed". If you change or add a
   mapping, keep the host side off 8080.

   Check before you bring anything up, and again if a service fails to start:
   ```
   ss -ltnp | grep -E ':(8080|8081|8090|50051|8200)\b'
   ```
   Caddy below takes :80 and :443, which are also clear of SAGE.

4. Front it with HTTPS, because cookie behaviour differs on plain HTTP —
   `SameSite`/`Secure` attributes are the whole point of testing this stack
   rather than the dev one:
   ```
   sudo caddy reverse-proxy --from https://localhost --to :8081
   ```
   Point Playwright at `https://localhost` (`E2E_BASE_URL`), not `:8081`.

Do **not** revert those compose edits until the run is finished; do not commit
them.

Then bootstrap the organization and its super-admin (`scripts/e2e-bootstrap.sh`
does the first two steps, or drive `POST /api/v1/admin/bootstrap` directly). The
super-admin bootstrap creates is **organization-level** — it lives in the
organization's reserved tenant, signs in naming no tenant, and is the principal
that administers every tenant.

Verify the mail consumer actually started: without
`AXIAM__EMAIL_ENCRYPTION_KEY` the server logs an error and **no transactional
mail is ever delivered**, which silently breaks every reset and verification
flow you are about to test.

## 1. Fixture to build — through the UI wherever the UI can do it

Build this as the org super-admin, using the admin UI (that is what is under
test); fall back to the REST API only where no UI path exists, and note each
such gap as a finding.

1. **At least one tenant**, created from the organization. Two is better: it
   makes cross-tenant isolation assertable rather than assumed.
2. **A tenant-level super-admin** in it, plus **at least three less-privileged
   users** with deliberately different reach — e.g. one `admin`, one `viewer`,
   one with a single narrowly-scoped custom role.
3. **A resource hierarchy of depth 4–6** (`/`→`a`→`b`→`c`→`d`…). Depth is the
   point: role assignments cascade to descendants, and a two-level tree cannot
   distinguish inheritance from coincidence.
4. **Several roles** operating on those resources — a mix of global roles and
   roles scoped to a *specific* node partway down the tree.
5. **Groups**, each carrying a different subset of those roles.
6. **Users and service accounts as group members.** Both kinds: a service
   account inherits a group's roles exactly as a person does, and that path is
   newly implemented — exercise it rather than assuming it.
7. **PKI:**
   - an organization CA certificate,
   - that CA enabled as an **mTLS trust anchor**,
   - **tenant signing CAs** (intermediates) beneath it,
   - end-entity certificates issued under those,
   - certificates **bound to service accounts** (`bind-certificate`).

## 2. The matrix — the actual point of the exercise

For **every** principal you created, and **every** operation reachable from the
frontend, assert both directions:

- what its roles allow, it **can** do and **can** see;
- what its roles do not allow, it **cannot** do and **cannot** see.

"Cannot see" matters as much as "cannot do": a page that renders a control the
server would refuse is a bug, and so is one that hides a control the server
would allow. The second is the one that hides silently — check for it
explicitly.

Walk the whole navigation: users, groups, roles, permissions, resources, scopes,
service accounts, certificates, CA certificates, settings, webhooks, reactors,
audit, federation, OAuth2 clients, SCIM tokens, PGP keys, notifications,
privacy/GDPR, organizations and tenants.

Include specifically:

- **Resource-scoped grants:** a role granted on node `b` reaches `c` and `d`
  beneath it and does **not** reach a sibling of `b`.
- **Deny grants.** The engine is default-deny with **deny-override**: an
  explicit `effect: "deny"` beats every allow, at any depth and at equal
  specificity. Assert that a deny on an ancestor masks an allow granted lower
  down, and that a scoped deny narrows only the scopes it names.
- **Cross-tenant isolation:** a tenant principal of tenant A sees and reaches
  nothing of tenant B, by any route the UI offers.
- **Organization-level reach:** the org super-admin can act on every tenant via
  the tenant switcher, and its *own* password change and `/auth/me` keep working
  while a child tenant is selected.
- **Group inheritance in both directions:** adding a principal to a group grants
  immediately; removing it revokes immediately (the decision cache is flushed
  per subject, so a stale allow surviving a revoke is a real bug).
- **Service-account authorization:** a machine identity's client-credentials
  token carries the permissions of the roles assigned to it, directly and
  through its groups.

## 3. Email — verify by log, not by inbox

You have no mailbox. Every mail assertion in this run is made against the
server's own log, which is enough: what is being tested is that AXIAM *sends*,
not that a provider delivers.

**First, before any mail flow, confirm the consumer is alive.** At startup the
server logs exactly one of:

```
Mail consumer spawned
Mail consumer NOT spawned — AXIAM__EMAIL_ENCRYPTION_KEY is missing. NO transactional mail will be delivered...
```

If it is the second, stop and set `AXIAM__EMAIL_ENCRYPTION_KEY`. Nothing is
delivered without it, and — this is the trap — the API still looks healthy:
`POST /auth/reset` answers `{"sent": true}` for every outcome by design (D-15),
so an operator gets a working-looking endpoint and a silent inbox. Every mail
assertion you make against a server in that state passes vacuously.

**Then watch the log while you drive each flow:**

```
docker compose -f docker/docker-compose.prod.yml logs -f axiam-server \
  | grep -E 'sending email|Mail consumer|mail'
```

A send attempt appears as an `info` line `sending email` carrying a `provider`
field. That line is the signal — assert on its presence, its `provider`, and the
absence of an accompanying `error!` from the mail consumer.

**Flows to exercise, each asserted at the log:**

- **Password reset at organization level** — the reported bug. The reset link on
  an organization-level sign-in carries an org slug and no tenant; that used to
  resolve to nothing and return `{"sent": true}` having queued nothing at all.
  One `sending email` line must appear.
- **Password reset at tenant level**, for contrast.
- **Email verification** on user creation, in the organization scope and in a
  child tenant.
- **GDPR export notice**, if you exercise the privacy pages.

**Assert the silences too.** The enumeration-safe contract means a reset for an
address that does not exist, and one naming an unknown organization, must *also*
answer `{"sent": true}` — and must produce **no** `sending email` line. The log
is the only place that difference is visible, which is exactly why the bug
survived. A test that only checks the response body cannot tell the two apart.

**Distinguish attempted from delivered.** With no real SMTP endpoint the provider
call will likely fail after the attempt is logged. That is fine and is not a
finding: assert the attempt. If you want to assert on subject lines and rendered
bodies, point the SMTP provider at a local catcher (Mailpit or MailHog) on a free
port — not 8080 — and read the messages there. Optional, but it is the only way
to catch a template that renders `{{tenant_name}}` literally.

## 4. mTLS and certificate-based authentication (do this if you can)

From an **external client** — outside the browser — confirm the PKI actually
works end to end:

- a client presenting a certificate issued under the trusted org CA (or a tenant
  signing CA beneath it) authenticates over mTLS;
- the service account it is **bound to** is the principal the server resolves,
  and its authorization matches that account's roles;
- a certificate from an untrusted CA, a revoked certificate, and a certificate
  bound to no service account are each **refused**;
- revoking the binding, or the certificate, takes effect.

`curl --cert/--key` against the API, or a small Rust program using
`axiam-sdk`'s §6.1 mTLS client, is enough. This is the one area where a green
browser suite proves nothing.

## 5. How to run it — batch the findings, rebuild once per wave

**The backend image is Rust and takes a long time to rebuild. Structure the whole
exercise around that fact.** Do not run discover-one-bug → fix → rebuild →
rerun; that loop costs an image build per defect and will not finish.

Work in **waves**:

1. **Discover.** Run the entire matrix to completion and record *every* failure.
   Do not stop at the first one, and do not fix anything mid-run.
2. **Triage.** Turn the recorded failures into a written findings list, each with
   its root cause and the layer it lives in (frontend, backend, or both).
3. **Fix everything in the list at once**, including the defects you already know
   how to fix and the ones that only reproduce after an earlier one is out of the
   way.
4. **Rebuild once**, bring the stack back up, and run the whole matrix again.
5. Repeat from 1 until a wave produces no findings.

### Making a wave actually reach the end

A run that aborts at the first failure collects one finding per image build,
which is the thing to avoid. So:

- **Never `--bail`.** Run with `--max-failures=0` (Playwright's default) so one
  broken spec does not cancel the rest of the suite.
- **Use `expect.soft(...)` for matrix assertions.** A permission check that fails
  should record the failure and let the test keep walking the rest of that
  principal's surface. Reserve hard `expect(...)` for preconditions that make the
  remaining steps meaningless (the fixture failed to build, the login failed).
- **Make the fixture resilient and idempotent.** Build it in a Playwright `setup`
  project; if one fixture step fails, record it and continue building the rest,
  so a broken CA-creation step does not cost you the entire RBAC matrix in that
  wave. Make it re-runnable against a stack that already has some of it, so a
  second wave does not need a wiped database.
- **Isolate by principal**, one spec (or one `describe`) per principal, so a
  principal whose login is broken loses only its own block.

### Some big defect really does block a whole area

Some findings poison everything downstream — a broken tenant switcher hides every
child-tenant assertion behind it. When that happens:

- record it as a finding **and** record what it blocked, explicitly, as
  "unverified — blocked by finding N", not as a pass;
- work around it for the rest of the wave where a workaround exists (drive the
  blocked setup through the REST API instead of the UI, and note that the UI path
  is itself the finding), so the wave still measures everything behind it;
- where no workaround exists, move on to the areas it does not touch. The point
  of the wave is breadth.

Never weaken or delete an assertion to get past a failure, and never mark a
blocked area green. An honest "unverified" is worth more than a pass that was not
measured.

### Rebuild only what changed

Not every fix costs a Rust build:

- **Frontend-only fix** → rebuild the frontend image alone
  (`docker compose -f docker/docker-compose.prod.yml up -d --build axiam-frontend`),
  or point Playwright at `npm run dev` in `frontend/` and skip the image entirely
  while iterating on UI defects.
- **Backend fix** → this is the expensive one. Batch every backend change in the
  wave into a single
  `docker compose -f docker/docker-compose.prod.yml up -d --build axiam-server`.
  Keep the build cache warm: do not `docker builder prune`, and do not touch
  `Cargo.toml`/`Cargo.lock` unless a fix genuinely needs it — a dependency change
  invalidates the whole dependency layer and turns a two-minute rebuild into a
  full one.
- Before spending a rebuild, **validate the backend fixes on the host** with the
  narrow test commands (`cargo test -p <crate> --test <name>`,
  `cargo clippy -p <crate>`). A rebuild that ships a fix which does not compile
  or does not work costs a whole wave.

### The findings log

Keep a running `claude_dev/e2e-findings.md` (or similar) through the whole
exercise, one entry per defect: what you did, what you expected, what happened,
the layer, the root cause once you have it, and the fix. It is the record the
waves are built on and the raw material for the PR description. Update it as you
go — reconstructing it at the end from scrollback loses findings.

## 6. Fixing what you found

Fix each finding in the frontend, the backend, or both, with a test that fails
before the fix and passes after. Do not paper over a backend defect in the UI,
and do not weaken an assertion to make a suite green.

Two rules for the tests you write:

- **Never lower coverage.** `frontend/vitest.config.ts` enforces a line
  threshold; the backend has its own gates. Add tests, do not move floors.
- Put the browser specs in `frontend/e2e/`. `org-scope.spec.ts` and
  `service-account-rbac.spec.ts` are already there and cover a slice of this —
  extend them rather than duplicating, and add new spec files per area.

Then commit on a feature branch, push, open a PR describing what was broken and
what each fix does, and drive it to green.

## 7. Context you will want

- `docs/admin/organization-scope.md` — organization vs tenant principals, what
  tenants inherit, the acting-vs-principal tenant distinction, the OPAQUE
  `required` coverage gate.
- `docs/admin/README.md` — role/permission/group model, deny grants, and the
  service-account role and group endpoints.
- `claude_dev/deny-override-design.md` — the precedence table, and why
  deny-override rather than most-specific-wins.
- `frontend/e2e/helpers/auth.ts` — `loginAsAdmin` (tenant-level) and
  `loginAsOrgAdmin` (organization-level, signs in naming no tenant).

A note on scale: this is a large matrix, and you will run it several times over.
Build the fixture once in a Playwright `setup` project and reuse it via
`storageState` per principal rather than re-logging in for every assertion — an
Argon2id verify per test will otherwise dominate the runtime of every wave.
