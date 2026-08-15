// server.ts — a minimal relying-party (RP) app exercising three pieces of
// B5 against AXIAM: "Login with AXIAM" (authorization_code + PKCE, itself
// pushed through PAR), RP-Initiated Logout, and Back-Channel Logout.
//
// This is intentionally small: one in-memory session store, one in-memory
// pending-authorization store, three routes for the OIDC dance and one for
// the back-channel receiver. A real RP would replace the in-memory Maps
// with a real session store and a real "was this jti already processed"
// table, and would run over HTTPS — see README.md "Not covered" for the
// full list of things this deliberately leaves out.

import express, { type NextFunction, type Request, type Response } from "express";
import { randomBytes } from "node:crypto";
import {
  authorizeUrlFromRequestUri,
  beginAuthorization,
  discover,
  exchangeCode,
  logoutUrl,
  pushAuthorizationRequest,
  verifyBackchannelLogoutToken,
  type OidcDiscoveryDocument,
} from "./oidc.js";

const PORT = Number(process.env.PORT ?? 9999);
const AXIAM_URL = process.env.AXIAM_URL ?? "http://localhost:8090";
const TENANT_ID = process.env.AXIAM_TENANT_ID ?? "";
const CLIENT_ID = process.env.AXIAM_CLIENT_ID ?? "";
const CLIENT_SECRET = process.env.AXIAM_CLIENT_SECRET ?? "";
const REDIRECT_URI = process.env.AXIAM_REDIRECT_URI ?? `http://localhost:${PORT}/callback`;
const POST_LOGOUT_REDIRECT_URI =
  process.env.AXIAM_POST_LOGOUT_REDIRECT_URI ?? `http://localhost:${PORT}/`;
const SCOPE = process.env.AXIAM_SCOPE ?? "openid profile";
// RFC 9126 (B5) — push the authorization request instead of sending its
// parameters through the browser. Toggle off to see the plain redirect.
const USE_PAR = process.env.AXIAM_USE_PAR !== "false";

interface PendingAuth {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
}

interface RpSession {
  sub: string;
  sid: string | undefined;
  idToken: string;
  createdAt: number;
}

const pendingByState = new Map<string, PendingAuth>();
const sessionsByCookie = new Map<string, RpSession>();
// sid -> cookie value, so a back-channel logout token (which names a `sid`,
// never a local cookie) can find the session to end (§12.7.3: "when sid is
// present, end THAT session only").
const cookieBySid = new Map<string, string>();
const seenLogoutJti = new Set<string>();

let discoveryCache: OidcDiscoveryDocument | undefined;
async function getDiscovery(): Promise<OidcDiscoveryDocument> {
  discoveryCache ??= await discover(AXIAM_URL);
  return discoveryCache;
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

function requireConfig(_req: Request, res: Response, next: NextFunction): void {
  if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
    res
      .status(500)
      .send(
        "Missing AXIAM_TENANT_ID / AXIAM_CLIENT_ID / AXIAM_CLIENT_SECRET — see README.md " +
          '"Run it" for how to register this app as an AXIAM OAuth2 client first.',
      );
    return;
  }
  next();
}

const app = express();
app.use(express.urlencoded({ extended: false })); // for the back-channel logout POST

/**
 * Minimal fixed-window rate limiter.
 *
 * Every route below either performs authorization or accepts an
 * attacker-reachable token, so none of them should be callable in an
 * unbounded loop. Kept dependency-free and in-memory deliberately: this is a
 * single-process example. A real RP should use a shared store (Redis) so the
 * limit holds across replicas — see `docs/api/rate-limiting.md`.
 */
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 60;
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

app.use((req: Request, res: Response, next: NextFunction) => {
  const key = req.ip ?? "unknown";
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    next();
    return;
  }
  if (bucket.count >= RATE_LIMIT_MAX) {
    res
      .status(429)
      .type("text/plain")
      .set("Retry-After", String(Math.ceil((bucket.resetAt - now) / 1000)))
      .send("rate limit exceeded");
    return;
  }
  bucket.count += 1;
  next();
});

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true });
});

// Smoke-test-only introspection: how many back-channel logout tokens this
// process has verified and acted on. Off by default — this is a debugging
// aid for examples-smoke.yml (which cannot otherwise observe an in-memory
// server's state from the outside), not part of the RP surface a real
// deployment exposes.
if (process.env.AXIAM_ENABLE_DEBUG_ENDPOINT === "true") {
  app.get("/internal/backchannel-log", (_req, res) => {
    res.status(200).json({ verified_jti_count: seenLogoutJti.size });
  });
}

app.get("/", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const session = cookies["rp_session"] ? sessionsByCookie.get(cookies["rp_session"]) : undefined;
  if (session) {
    res.type("text/plain").send(
      `Logged in as sub=${session.sub} sid=${session.sid ?? "(none)"}\n\n` +
        "GET /logout to end this session at AXIAM (RP-Initiated Logout).\n",
    );
    return;
  }
  res.type("text/plain").send("Not logged in.\n\nGET /login to sign in with AXIAM.\n");
});

app.get("/login", requireConfig, async (_req, res, next) => {
  try {
    const discovery = await getDiscovery();
    const authReq = beginAuthorization({
      discovery,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scope: SCOPE,
    });
    pendingByState.set(authReq.state, {
      state: authReq.state,
      nonce: authReq.nonce,
      codeVerifier: authReq.codeVerifier,
      createdAt: Date.now(),
    });

    if (USE_PAR) {
      const { requestUri } = await pushAuthorizationRequest({
        axiamUrl: AXIAM_URL,
        tenantId: TENANT_ID,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        authReq,
        redirectUri: REDIRECT_URI,
        scope: SCOPE,
      });
      const url = authorizeUrlFromRequestUri({ discovery, clientId: CLIENT_ID, requestUri });
      res.redirect(url);
      return;
    }

    res.redirect(authReq.url);
  } catch (err) {
    next(err);
  }
});

app.get("/callback", requireConfig, async (req, res, next) => {
  try {
    const code = typeof req.query["code"] === "string" ? req.query["code"] : undefined;
    const state = typeof req.query["state"] === "string" ? req.query["state"] : undefined;
    const error = typeof req.query["error"] === "string" ? req.query["error"] : undefined;
    if (error) {
      // Never interpolate an OP-supplied value into an HTML response body:
      // Express infers text/html for a string, which would make this a
      // reflected-XSS sink. RFC 6749 §4.1.2.1 restricts `error` to %x20-21 /
      // %x23-5B / %x5D-7E, so anything outside that is not a real OAuth2
      // error code and is not worth echoing at all.
      const safe = /^[\x20-\x21\x23-\x5B\x5D-\x7E]{1,64}$/.test(error)
        ? error
        : "(unprintable error code)";
      res.status(400).type("text/plain").send(`AXIAM returned an error: ${safe}`);
      return;
    }
    if (!code || !state) {
      res.status(400).send("callback missing code/state");
      return;
    }
    const pending = pendingByState.get(state);
    pendingByState.delete(state); // single-use, whether or not the exchange succeeds
    if (!pending) {
      res.status(400).send("unknown or already-used state");
      return;
    }

    const discovery = await getDiscovery();
    const { tokens, idClaims } = await exchangeCode({
      axiamUrl: AXIAM_URL,
      tenantId: TENANT_ID,
      discovery,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      code,
      codeVerifier: pending.codeVerifier,
      expectedNonce: pending.nonce,
    });

    const cookieValue = randomBytes(24).toString("base64url");
    const sid = idClaims.sid;
    const session: RpSession = {
      sub: String(idClaims.sub ?? ""),
      sid,
      idToken: tokens.id_token as string,
      createdAt: Date.now(),
    };
    sessionsByCookie.set(cookieValue, session);
    if (sid) cookieBySid.set(sid, cookieValue);

    res.setHeader(
      "Set-Cookie",
      `rp_session=${encodeURIComponent(cookieValue)}; HttpOnly; Path=/; SameSite=Lax`,
    );
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.get("/logout", requireConfig, async (req, res, next) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const cookieValue = cookies["rp_session"];
    const session = cookieValue ? sessionsByCookie.get(cookieValue) : undefined;
    if (!session) {
      res.redirect("/");
      return;
    }

    const discovery = await getDiscovery();
    const state = randomBytes(12).toString("base64url");
    const url = logoutUrl({
      discovery,
      idToken: session.idToken,
      postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI,
      state,
    });

    // Ending the LOCAL session here is this application's own choice, not
    // something AXIAM's RP-Initiated Logout does for it (§12.7.2 rule 4) —
    // a backend holding an unrelated service-account session must not lose
    // it just because a user logged out. This app has nothing else to keep,
    // so it clears eagerly.
    if (cookieValue) sessionsByCookie.delete(cookieValue);
    if (session.sid) cookieBySid.delete(session.sid);

    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

// The back-channel receiver: AXIAM POSTs here when a session this app
// participated in ends anywhere — including a user logging out of a
// DIFFERENT device, or an admin force-ending the session. See
// docs/api/logout.md "Back-channel logout".
app.post("/backchannel-logout", requireConfig, async (req, res) => {
  const logoutToken = typeof req.body?.logout_token === "string" ? req.body.logout_token : undefined;
  if (!logoutToken) {
    res.status(400).send("missing logout_token");
    return;
  }

  try {
    const discovery = await getDiscovery();
    const result = await verifyBackchannelLogoutToken({
      discovery,
      clientId: CLIENT_ID,
      logoutToken,
    });

    // Delivery is at-least-once (docs/api/logout.md "jti is the dedup
    // key"): a valid token arriving twice is a retry, not an attack, and
    // MUST NOT be treated as an error (§12.7.3 rule 7/8's "MUST NOT dedup
    // internally [in the SDK], but MUST make the key available" — here,
    // the RP application itself owns the dedup decision).
    if (!seenLogoutJti.has(result.jti)) {
      seenLogoutJti.add(result.jti);
      if (result.sid) {
        // §12.7.3: "When sid is present, the RP MUST end that session
        // only" — never every session for the sub.
        const cookieValue = cookieBySid.get(result.sid);
        if (cookieValue) {
          sessionsByCookie.delete(cookieValue);
          cookieBySid.delete(result.sid);
        }
      } else if (result.sub) {
        for (const [cookieValue, session] of sessionsByCookie) {
          if (session.sub === result.sub) {
            sessionsByCookie.delete(cookieValue);
            if (session.sid) cookieBySid.delete(session.sid);
          }
        }
      }
    }

    // No response body: the OP does not read one, and echoing anything
    // token-derived back into a 200 would be pointless exposure.
    res.status(200).end();
  } catch (err) {
    // §12.7.3 rule 8: failure is a typed error, never a partial result, and
    // MUST NOT echo the token. AXIAM's own delivery retries a non-2xx per
    // docs/api/logout.md "Delivery" (up to 3 attempts), so refusing here is
    // safe — a transient failure gets a legitimate second chance.
    // Log the detail server-side; return a fixed string. Echoing the
    // exception text would both reinterpret it as HTML and leak validator
    // internals to whoever posted the token.
    console.error("back-channel logout rejected:", err);
    res.status(400).type("text/plain").send("invalid logout_token");
  }
});

app.listen(PORT, () => {
  console.log(`b5-rp-logout-app listening on http://localhost:${PORT}`);
  console.log(`AXIAM_URL=${AXIAM_URL} USE_PAR=${USE_PAR}`);
});
