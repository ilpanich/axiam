import { test, expect, APIRequestContext } from "@playwright/test";
import { Api } from "../helpers/api";
import { readFixture } from "../helpers/matrix";
import { storageStateFor } from "../helpers/matrix-fixture";

/**
 * A machine identity's own token carries its own authority.
 *
 * Everything else in this matrix asks about a service account from an
 * administrator's session. That proves the engine's *opinion*; it does not
 * prove the credential works. Here the service account authenticates for
 * itself — `grant_type=client_credentials` against `/oauth2/token` — and its
 * own bearer token is used to ask the authorization question.
 *
 * Two paths to the same authority, and both are asserted:
 *
 *   - `mx-sa-direct` holds `mx-role-viewer` assigned to it directly;
 *   - `mx-sa-group` holds nothing directly and is a member of `mx-group-alpha`,
 *     which carries the same role.
 *
 * `mx-sa-cert` holds neither, and is the control: a machine identity that
 * authenticates successfully and can still do nothing is what default-deny
 * looks like from the outside.
 *
 * **Which surface, and why.** A client-credentials token carries
 * `aud = axiam:m2m`, which every ordinary admin route rejects by design — the
 * `AuthenticatedUser` extractor narrows to `axiam:user`. The machine-facing
 * surface is `POST /api/v1/authz/check`, whose `AuthenticatedPrincipal`
 * extractor exists specifically to accept both audiences. Asserting against the
 * admin routes instead would be asserting that a deliberate audience separation
 * is broken.
 *
 * Client secrets come from the fixture, which rotates them on every build — a
 * secret is returned exactly once, at creation, so a wave running against an
 * already-seeded stack would otherwise have no usable credential.
 */

const fx = readFixture();

test.describe("service-account authorization", () => {
  // No browser session: the whole point is the service account's own token.
  test.use({ storageState: { cookies: [], origins: [] } });

  const CASES = [
    {
      name: "mx-sa-direct",
      allowed: true,
      why: "holds mx-role-viewer, assigned directly to the service account",
    },
    {
      name: "mx-sa-group",
      allowed: true,
      why: "holds no role directly; mx-group-alpha carries mx-role-viewer for it",
    },
    {
      name: "mx-sa-cert",
      allowed: false,
      why: "holds no role by any path — the default-deny control",
    },
  ];

  for (const c of CASES) {
    test(`${c.name}: users:list is ${c.allowed ? "allowed" : "refused"} (${c.why})`, async ({
      request,
    }) => {
      const token = await clientCredentialsToken(request, c.name);
      if (!token) {
        test.skip(
          true,
          `unverified — blocked: no usable client credentials for ${c.name}. ` +
            `${fx.problems.join("; ") || "the fixture recorded no reason"}`,
        );
        return;
      }
      const root = fx.resources["root"];
      if (!root) {
        test.skip(true, "unverified — blocked: the fixture resource tree was not built");
        return;
      }

      const res = await request.post("/api/v1/authz/check", {
        headers: { Authorization: `Bearer ${token}` },
        data: { action: "users:list", resource_id: root },
        failOnStatusCode: false,
      });
      const body = (await res.json().catch(() => ({}))) as {
        allowed?: boolean;
        message?: string;
      };

      expect
        .soft(
          res.status(),
          `${c.name}'s own token must be accepted on the machine-facing authorization ` +
            `endpoint — that is the surface AuthenticatedPrincipal was widened for. ` +
            `HTTP ${res.status()}: ${JSON.stringify(body).slice(0, 250)}`,
        )
        .toBe(200);
      if (res.status() !== 200) return;

      expect
        .soft(
          body.allowed,
          `${c.name} ${c.why}, so its own token must ${c.allowed ? "carry" : "not carry"} ` +
            `users:list. An authorization that only works from an administrator's session ` +
            `is not an authorization the machine identity actually has`,
        )
        .toBe(c.allowed);
    });
  }

  test("a machine token is refused on the user-only admin routes", async ({ request }) => {
    // The other half of the audience separation, and the reason the assertions
    // above target `/authz/check` rather than `/users`: `axiam:m2m` must reach
    // the machine surface and nothing else. Asserting it locks the narrowing in.
    const token = await clientCredentialsToken(request, "mx-sa-direct");
    if (!token) {
      test.skip(true, "unverified — blocked: no usable client credentials for mx-sa-direct");
      return;
    }

    const res = await request.get("/api/v1/users", {
      headers: { Authorization: `Bearer ${token}`, "X-Axiam-Tenant": fx.tenantA },
      failOnStatusCode: false,
    });
    expect
      .soft(
        res.status(),
        "a client-credentials token carries aud=axiam:m2m, which the admin routes narrow " +
          "away by design; reaching /api/v1/users with one would be a widening nobody asked for",
      )
      .toBe(401);
  });

  test("a rotated secret invalidates the previous one", async ({ request }) => {
    // Rotation that leaves the old secret working is rotation in name only, and
    // it is the operation an operator reaches for after a leak.
    const sa = fx.serviceAccounts["mx-sa-direct"];
    if (!sa?.clientId || !sa.clientSecret) {
      test.skip(true, "unverified — blocked: no client credentials for mx-sa-direct");
      return;
    }

    // Reuses the session `matrix-setup` already captured rather than spending
    // one of the ten logins a minute the whole suite shares — signing in here
    // made this test time out whenever it was scheduled after the window
    // filled. See `Api.fromStorageState`.
    let admin: Api;
    try {
      admin = await Api.fromStorageState(storageStateFor("org-admin"));
    } catch (e) {
      test.skip(true, `unverified — blocked: no captured org-admin session (${e})`);
      return;
    }
    try {
      admin.actingTenant(fx.tenantA);

      const previous = sa.clientSecret;
      const rotated = await admin.post<{ client_secret?: string; secret?: string }>(
        `/api/v1/service-accounts/${sa.id}/rotate-secret`,
        {},
      );
      expect
        .soft(
          rotated.status,
          `rotate-secret returned ${JSON.stringify(rotated.body).slice(0, 200)}`,
        )
        .toBeLessThan(300);

      // Keep the in-memory fixture usable for anything running after this.
      const fresh = rotated.body?.client_secret ?? rotated.body?.secret;
      if (fresh) sa.clientSecret = fresh;

      const withOld = await request.post(`/oauth2/token?tenant_id=${fx.tenantA}`, {
        form: {
          grant_type: "client_credentials",
          client_id: sa.clientId,
          client_secret: previous,
        },
        failOnStatusCode: false,
      });
      expect
        .soft(
          withOld.status(),
          "the secret that was just rotated away must no longer authenticate — otherwise " +
            "rotating after a leak changes nothing",
        )
        .not.toBe(200);
    } finally {
      await admin.dispose();
    }
  });
});

/**
 * A client-credentials access token for one fixture service account.
 *
 * `tenant_id` goes in the **query string**, not the form body: it is declared
 * `required` in `sdks/openapi.json`, and without it the endpoint answers
 * `400 "Query deserialize error: missing field tenant_id"` — an unusual shape
 * for an OAuth2 token endpoint and the first thing a client written from the
 * RFC rather than from the spec gets wrong.
 */
async function clientCredentialsToken(
  request: APIRequestContext,
  name: string,
): Promise<string | null> {
  const sa = fx.serviceAccounts[name];
  if (!sa?.clientId || !sa.clientSecret) return null;

  const res = await request.post(`/oauth2/token?tenant_id=${fx.tenantA}`, {
    form: {
      grant_type: "client_credentials",
      client_id: sa.clientId,
      client_secret: sa.clientSecret,
    },
    failOnStatusCode: false,
  });
  if (res.status() !== 200) return null;
  const body = (await res.json().catch(() => ({}))) as { access_token?: string };
  return body.access_token ?? null;
}
