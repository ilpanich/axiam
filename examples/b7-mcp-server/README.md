# B7 — an MCP server fronted by AXIAM

**What this demonstrates.** A minimal MCP server on the official
[`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
streamable-HTTP transport, playing the **resource server** role in the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization):
it publishes an RFC 9728 protected-resource metadata document, emits the RFC
6750 `WWW-Authenticate` challenge that starts an MCP client's discovery, and
checks that an inbound token's `aud` is actually addressed at it — fronted by
AXIAM as the OAuth 2.0 **authorization server**, in each of the three ways a
client can obtain that token: pre-registered, dynamic client registration
(RFC 7591), and Client ID Metadata Documents. The full narrative is
[`docs/api/mcp.md`](../../docs/api/mcp.md); this tree is its runnable half.

## Layout

| File | Is |
| --- | --- |
| [`src/resource-server.ts`](src/resource-server.ts) | The §28 operations — `protected_resource_metadata`, `serve_protected_resource_metadata`, `bearer_challenge` — plus the `aud`-checking guard and the scope check, hand-written against `jose` |
| [`src/server.ts`](src/server.ts) | The MCP server itself: two tools (`list_widgets`, `reset_widgets`, the second scope-gated), the session-per-`initialize` streamable-HTTP wiring, and the guard from `resource-server.ts` in front of `/mcp` |
| [`walkthrough.sh`](walkthrough.sh) | 401 → discovery → registration → PKCE + `resource` → token → tool call, in each of the three modes, over plain curl |
| [`smoke-test.sh`](smoke-test.sh) | The narrower "does the built server actually run" proof, one mode, matching `examples/b5-rp-logout-app`'s pattern |
| `requests-*.md` | Request-shape fragments deposited by the earlier tasks in the phase this example closes out (T21.2–T21.6, T21.9); `requests-client-id-metadata-documents.md` was mined from `crates/axiam-api-rest/tests/cimd_test.rs` because T21.5 did not deposit one |

## Why this doesn't depend on the published `axiam-sdk` package

As of this writing, `axiam-sdk`'s published npm package (`1.0.0-beta15`, the
latest on the registry when this example was written) does not yet export
the §28 resource-server helpers — the TypeScript reference implementation
(T21.9b) had not been published there yet. `resource-server.ts` is therefore
hand-written against `jose`, implementing `sdks/CONTRACT.md` §28 directly,
for the same reason `examples/b5-rp-logout-app/src/oidc.ts` hand-rolls
CONTRACT §12 instead of depending on the SDK: it can never drift from what
the wire actually does, and it is a from-scratch reference for anyone
integrating an MCP server in a language with no SDK helper yet.

**Once `axiam-sdk` publishes §28**, `resource-server.ts` should be deleted in
favor of:

```ts
import {
  protectedResourceMetadata,
  serveProtectedResourceMetadata,
  bearerChallenge,
} from "axiam-sdk/middleware";
```

and `server.ts`'s guard should build on `axiamMiddleware`'s already-published
`expectedAudience` option plus the `resource_metadata_url` option §28.5 adds.
Every function in `resource-server.ts` is named and shaped after its §28
canonical operation for exactly this reason — the eventual diff should be
small.

## What it requires

- Node.js 20+ and npm, `curl`, `jq`, `openssl`, and (for the CIMD leg of
  `walkthrough.sh`, which stands up a throwaway publisher) `python3`.
- A running, bootstrapped AXIAM instance:

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh
```

Then, from this directory:

```bash
npm ci
npm run build
AXIAM_URL=http://localhost:8090 ./walkthrough.sh          # all three modes
AXIAM_URL=http://localhost:8090 MODE=dcr ./walkthrough.sh # one mode
AXIAM_URL=http://localhost:8090 ./smoke-test.sh
```

Both scripts build and start the MCP server themselves (on `MCP_PORT`,
default `8091` / `8092`) and tear it down on exit; neither needs `npm start`
run separately.

## Configuring MCP Inspector, Claude Code and VS Code

Every value below, and why it is what it is, is in
[`docs/api/mcp.md`](../../docs/api/mcp.md#tenant-settings-translated-from-keycloaks-guide).
Once this server is running and its tenant has one of the three modes turned
on:

**MCP Inspector** — point it at `http://127.0.0.1:8091/mcp`. On the tenant's
`dynamic_registration: "anonymous"`, it registers itself with no further
configuration.

**Claude Code** — add an entry to its MCP server configuration naming this
server's URL. Claude Code's OAuth client registers `http://localhost/callback`
(the host `localhost`, not `127.0.0.1`) — enable it in
`dcr_allowed_redirect_hosts` if you have narrowed that list beyond the
always-allowed loopback hosts (the default, empty list already allows it).

**VS Code** — same shape, registering `http://127.0.0.1/callback` instead
(the other loopback host — see
[Public clients § `localhost` and `127.0.0.1` are not
interchangeable](../../docs/admin/public-clients.md#localhost-and-127001-are-not-interchangeable)
for why both exist and neither substitutes for the other).

## Verification status

**Typechecked and built** (`npm run typecheck`, `npm run build`) against the
real, published `@modelcontextprotocol/sdk`, `express`, `jose` and
`typescript` versions this tree's `package.json` pins. Both shell scripts are
`bash -n` and `shellcheck` clean.

**The resource-server half — everything in `resource-server.ts` and the
MCP-facing parts of `server.ts` — has been run end to end**, against a real
build of this server, with tokens signed by a locally generated Ed25519
keypair standing in for AXIAM (a throwaway HTTP server serving a fake
`/.well-known/openid-configuration` and `/oauth2/jwks`, since no AXIAM
instance or Docker daemon was available in the environment this example was
written in). Every one of the following was observed, not assumed:

- the unauthenticated `401` carries the exact RFC 6750 challenge with no
  `error` parameter, and the RFC 9728 document is reachable with no
  credential;
- `initialize` → `tools/list` → `tools/call list_widgets` succeeds with a
  valid, correctly audienced token;
- `tools/call reset_widgets` is refused `403 insufficient_scope` (with the
  challenge naming the scope) for a token that authenticated but was never
  granted `mcp:tools`, and succeeds for one that was;
- a token whose `aud` is a different resource (`axiam:user`, AXIAM's own
  general-purpose audience) and an expired token are both refused `401
  invalid_token`, indistinguishably, with the challenge.

**The AXIAM-facing half of `walkthrough.sh` and `smoke-test.sh` — the admin
API calls, the three registration modes, the PKCE authorize/redeem
sequence — has been written against the exact request and response shapes
each earlier task's own integration test exercises** (linked from each
fragment this tree carries), reviewed for internal consistency, and passed
`bash -n` and `shellcheck`, but **has not been run against a real AXIAM**:
this environment had no Docker daemon and therefore no way to bring up
`docker/docker-compose.e2e.yml`. That run is what
`.github/workflows/examples-smoke.yml`'s `runtime-smoke` job does on every
PR touching this tree, the same way it already does for `b1`, `b2`, `b3`,
`b5` and `b6`.

An honest "written and partially verified, not run end to end here, because
no Docker daemon" is the standard the rest of this example tree holds itself
to (see [`examples/README.md`](../README.md)'s own "Verification status of
this tree" section) — this page states plainly which half of that applies to
which part of B7.
