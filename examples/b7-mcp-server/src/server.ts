// server.ts — a minimal MCP server on the official streamable-HTTP
// transport, fronted by AXIAM as its OAuth 2.0 authorization server.
//
// Two tools, deliberately different in what they require, so the walkthrough
// can show both the audience check (§10.1 rule 6 / I3) and the scope check
// (§28.5 rule 5) actually deciding something:
//
//   - `list_widgets`   — any request whose token is valid and addressed at
//                        this resource.
//   - `reset_widgets`  — additionally requires the `mcp:tools` scope, so a
//                        token that has authenticated but was never granted
//                        that scope gets 403 `insufficient_scope` rather than
//                        a silent 401.
//
// See README.md for how to run this against a bootstrapped AXIAM, and for
// what MCP Inspector / Claude Code / VS Code need to point at it.

import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { Response } from "express";
import * as z from "zod";
import {
  protectedResourceMetadata,
  serveProtectedResourceMetadata,
  requireBearerAuth,
  requireScope,
  type McpRequest,
} from "./resource-server.js";

const AXIAM_URL = requireEnv("AXIAM_URL");
const AXIAM_TENANT_ID = requireEnv("AXIAM_TENANT_ID");
const MCP_HOST = process.env["MCP_HOST"] ?? "127.0.0.1";
const MCP_PORT = Number(process.env["MCP_PORT"] ?? "8091");
const MCP_REQUIRED_SCOPE = process.env["MCP_REQUIRED_SCOPE"] ?? "mcp:tools";
// A loopback resource is what this example actually runs as; a real
// deployment sets this to the public https URL the MCP server is reachable
// at (resource-server.ts's https-or-loopback rule is what enforces the
// distinction — CONTRACT §28.2 rule 2).
const MCP_RESOURCE = process.env["MCP_RESOURCE"] ?? `http://${MCP_HOST}:${MCP_PORT}/mcp`;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set — see README.md`);
  }
  return value;
}

interface DiscoveryDocument {
  issuer: string;
  jwks_uri: string;
  [key: string]: unknown;
}

async function discover(): Promise<DiscoveryDocument> {
  const url = `${AXIAM_URL}/.well-known/openid-configuration?tenant_id=${encodeURIComponent(AXIAM_TENANT_ID)}`;
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`discovery failed: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as DiscoveryDocument;
}

interface Widget {
  id: string;
  name: string;
}

// Module-scoped, not per-session: every MCP session talks to the same two
// widgets, which is what makes `reset_widgets` from one session visible to
// `list_widgets` from another — closer to what a real MCP server backs onto.
const widgets: Widget[] = [
  { id: "w1", name: "left-flange" },
  { id: "w2", name: "right-flange" },
];

function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "b7-mcp-server", version: "0.1.0" });

  server.registerTool(
    "list_widgets",
    { description: "List every widget this MCP server knows about.", inputSchema: {} },
    async () => ({
      content: [{ type: "text", text: JSON.stringify(widgets) }],
    }),
  );

  server.registerTool(
    "reset_widgets",
    {
      description: `Delete every widget. Requires the '${MCP_REQUIRED_SCOPE}' scope — enforced by the guard in front of this route, not by this handler.`,
      inputSchema: { confirm: z.boolean().describe("must be true") },
    },
    async ({ confirm }) => {
      if (!confirm) {
        return { content: [{ type: "text", text: "pass confirm: true to actually reset" }], isError: true };
      }
      widgets.length = 0;
      return { content: [{ type: "text", text: "widgets reset" }] };
    },
  );

  return server;
}

async function main(): Promise<void> {
  const discovery = await discover();

  const metadata = protectedResourceMetadata({
    resource: MCP_RESOURCE,
    authorizationServers: [discovery.issuer],
    scopesSupported: ["mcp:read", MCP_REQUIRED_SCOPE],
  });

  const app = createMcpExpressApp({ host: MCP_HOST });
  app.get("/health", (_req, res) => res.status(200).json({ status: "ok" }));

  const resourceMetadataUrl = serveProtectedResourceMetadata(app, metadata);
  console.log(`protected-resource metadata served at ${resourceMetadataUrl}`);

  const guard = requireBearerAuth({
    jwksUri: discovery.jwks_uri,
    issuer: discovery.issuer,
    expectedAudience: MCP_RESOURCE,
    resourceMetadataUrl,
  });
  const scopeGuard = requireScope(MCP_REQUIRED_SCOPE, resourceMetadataUrl);

  // Session-per-`initialize`, exactly the shape the SDK's own
  // `examples/server/simpleStreamableHttp.ts` uses: the first request from a
  // client (carrying no `Mcp-Session-Id`) MUST be `initialize`, which mints a
  // session and a transport that every later request on that session reuses.
  // A per-request-fresh transport (the "stateless" example) rejects every
  // call after the first with "Server not initialized", because the MCP
  // streamable-HTTP protocol itself — not this guard — requires the
  // handshake once per session.
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const mcpPostHandler = async (req: McpRequest, res: Response) => {
    const sessionId = req.headers["mcp-session-id"];
    const body = req.body as { method?: string; params?: { name?: string } } | undefined;

    // `reset_widgets` alone needs the scope check; every JSON-RPC method on
    // this session's one transport reaches this same handler, so the gate
    // has to look at the body rather than at a second route.
    if (body?.method === "tools/call" && body.params?.name === "reset_widgets") {
      let denied = false;
      await new Promise<void>((resolve) => {
        scopeGuard(req, res, () => resolve());
        if (res.headersSent) {
          denied = true;
          resolve();
        }
      });
      if (denied) return; // scopeGuard already answered 403
    }

    let transport = typeof sessionId === "string" ? transports.get(sessionId) : undefined;
    if (!transport) {
      if (typeof sessionId === "string" || !isInitializeRequest(body)) {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Bad Request: No valid session ID provided" },
          id: null,
        });
        return;
      }
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          transports.set(newSessionId, transport!);
        },
      });
      transport.onclose = () => {
        const sid = transport?.sessionId;
        if (sid) transports.delete(sid);
      };
      const mcpServer = buildMcpServer();
      await mcpServer.connect(transport);
    }
    await transport.handleRequest(req, res, req.body);
  };

  app.post("/mcp", guard, mcpPostHandler);

  app.listen(MCP_PORT, () => {
    console.log(`b7-mcp-server listening on http://${MCP_HOST}:${MCP_PORT} (resource: ${MCP_RESOURCE})`);
  });
}

main().catch((err: unknown) => {
  console.error("b7-mcp-server failed to start:", err);
  process.exit(1);
});
