# Vendored Zitadel proto (minimal, D4)

Pinned source version: **Zitadel `v4.15.2`** — matches the image tag benched in
`benchmarks/targets/zitadel/docker-compose.yml`
(`ghcr.io/zitadel/zitadel:v4.15.2`, see that file's `services.zitadel.image`).
If the benched Zitadel tag ever changes, re-fetch and re-diff these files
against the new tag before trusting the gRPC scenario's numbers.

Upstream repo: https://github.com/zitadel/zitadel — Apache License 2.0. These
files are a **derived, trimmed** copy of upstream `.proto` sources, not a
verbatim vendor drop.

## What's here and why

```
zitadel/
├── auth.proto     -- AuthService.GetMyUser only  (upstream: 1653 lines, ~90 RPCs)
├── user.proto      -- User envelope + UserState   (upstream: 1021 lines)
└── object.proto    -- ObjectDetails                (upstream: 105 lines, kept ~whole)
```

This benchmark needs exactly one RPC: `zitadel.auth.v1.AuthService/GetMyUser`,
the gRPC counterpart to the REST `/oidc/v1/userinfo` scenario already covered
by `scenarios/userinfo.js` (see `scenarios/zitadel_userinfo_grpc.js`). Rather
than vendor the full upstream files — which would transitively require
`google/api/annotations.proto`, `google/api/field_behavior.proto`,
`zitadel/options.proto` (for `(zitadel.v1.auth_option)`),
`protoc-gen-openapiv2/options/annotations.proto` (for the swagger/operation
options), and, for `auth.proto`'s other ~89 RPCs, `zitadel/org.proto`,
`zitadel/change.proto`, `zitadel/policy.proto`, `zitadel/idp.proto`,
`zitadel/metadata.proto`, and `validate/validate.proto` — this vendors a
**hand-trimmed subset**:

1. **Fetched the real upstream files** at the `v4.15.2` tag (raw GitHub
   content was reachable from this environment) to read the authoritative
   RPC signature and message shapes rather than guessing them:
   - `proto/zitadel/auth.proto` → `AuthService.GetMyUser`,
     `GetMyUserRequest {}`, `GetMyUserResponse { User user = 1;
     google.protobuf.Timestamp last_login = 2; }`
   - `proto/zitadel/user.proto` → `User { string id = 1; ObjectDetails
     details = 2; UserState state = 3; string user_name = 4; repeated
     string login_names = 5; string preferred_login_name = 6; oneof type {
     Human human = 7; Machine machine = 8; } }` + the 7-value `UserState`
     enum.
   - `proto/zitadel/object.proto` → `ObjectDetails { uint64 sequence = 1;
     Timestamp creation_date = 2; Timestamp change_date = 3; string
     resource_owner = 4; }`
2. **Copied every field number verbatim** for every field kept below — this
   matters because k6's gRPC client needs exact field numbers for wire
   compatibility (a mismatched number silently decodes the wrong field).
3. **Cut everything not required to call and decode `GetMyUser`:**
   - `auth.proto`: dropped all ~89 other RPCs and every custom option
     (`google.api.http`, `zitadel.v1.auth_option`, the
     `protoc-gen-openapiv2` swagger/operation blocks). These select REST
     gateway routing and generated docs, never the gRPC wire format — the
     k6 scenario calls `AuthService/GetMyUser` directly over gRPC, never
     through Zitadel's REST/JSON gateway, so none of this affects what's
     being benchmarked.
   - `user.proto`: dropped the `human`/`machine` oneof (upstream fields 7/8)
     entirely, along with the `Human`/`Machine`/`Profile`/`Email`/`Phone`
     message definitions those fields pull in. This is *safe*, not lossy in
     a way that matters here: protobuf decoders silently skip unknown field
     numbers on the wire, so a real Zitadel response carrying a populated
     `human` payload still decodes cleanly against this trimmed message —
     those bytes are just never surfaced to the k6 script. The benchmark
     only asserts the RPC succeeds and the identity envelope
     (`id`/`state`/`user_name`) decodes; it does not assert on profile
     contents, so there is no need to vendor the profile sub-messages.
   - Every remaining field-level `protoc-gen-openapiv2` annotation across
     all three files was stripped for the same reason as the RPC options —
     documentation metadata, not wire shape.
4. **`google.protobuf.Timestamp` is referenced but not vendored.** k6's
   `k6/net/grpc` client bundles the standard protobuf well-known types
   (`google/protobuf/{any,duration,empty,struct,timestamp,wrappers}.proto`)
   internally, so `import "google/protobuf/timestamp.proto";` resolves
   without a file on disk — nothing to vendor there.

Net result: 3 files, ~90 lines total, vs. ~2700 lines and 9+ additional
transitive proto files upstream — everything needed for
`AuthService/GetMyUser` to encode/decode correctly on the wire, nothing else.

## Session service — not vendored

The plan for this task (`claude_dev/benchmark-improvement-plan.md`, D4) also
asks for "auth + session services" and an optional
`zitadel_introspect_equivalent` scenario "only if a comparable RPC genuinely
exists." `proto/zitadel/session/v2/session_service.proto` was fetched and
inspected at the same `v4.15.2` tag; `SessionService` exposes
`ListSessions`/`GetSession`/`CreateSession`/`SetSession`/`DeleteSession`.
None of these are a comparable RPC to either of this repo's existing
REST session/token operations:

* `GetSession` takes a **session ID + session token** (Zitadel's own
  session-object identity), not a bearer OAuth2 access/refresh token — it
  cannot serve as an "introspect this token" equivalent to RFC 7662
  `token_introspection.js`, which checks whether a given *token* is active.
* `CreateSession` is the gRPC counterpart to the **login** flow, not
  introspection or userinfo — out of scope for D4, and it is task D5's
  concern (`benchmarks/scenarios/lib/targets.js`'s `zitadel.login()`), not
  this one's.

So no `session_service.proto` is vendored and no
`zitadel_introspect_equivalent.js` scenario was added — forcing one would
mean benchmarking a different logical operation under a misleading label,
which is exactly what `docs/methodology.md`'s comparability rules (and this
plan item) say not to do.

## Comparability labeling

`AuthService/GetMyUser` over gRPC is the **protocol-efficiency** pairing for
Zitadel's own REST `/oidc/v1/userinfo` (`scenarios/userinfo.js`) — same
logical operation (return the authenticated user's identity claims), two
wire protocols, same vendor. It is **not** compared head-to-head against
AXIAM's or Keycloak's REST `userinfo.js` cells in the cross-vendor winner
tables (neither of those targets exposes this RPC at all), and it is not
compared against AXIAM's `authz_check_grpc.js`/`authz_batch_grpc.js` either
(those measure a service-mesh authorization decision, a different logical
operation). See `docs/methodology.md` §3 and `runner/report.py`'s
`NON_COMPARATIVE_SCENARIOS` handling for how this is enforced in the
generated report.

## Regenerating / re-verifying

```bash
# Re-fetch upstream at the pinned tag to diff against this trimmed copy:
curl -sS https://raw.githubusercontent.com/zitadel/zitadel/v4.15.2/proto/zitadel/auth.proto
curl -sS https://raw.githubusercontent.com/zitadel/zitadel/v4.15.2/proto/zitadel/user.proto
curl -sS https://raw.githubusercontent.com/zitadel/zitadel/v4.15.2/proto/zitadel/object.proto

# If buf or protoc is available, lint/compile-check this vendored set:
buf lint scenarios/proto/zitadel
protoc --proto_path=scenarios/proto/zitadel --descriptor_set_out=/dev/null zitadel/auth.proto
```
