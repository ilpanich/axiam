import { test, expect } from "@playwright/test";
import { NAV_DESTINATIONS } from "../helpers/matrix";

/**
 * Every SPA route must be served by the SPA, not swallowed by an API proxy.
 *
 * This is a *server*-level assertion and deliberately carries no session: it is
 * about which component answers the request, not about what the answer contains
 * or who is allowed to see it. A route that the reverse proxy hands to the
 * backend never reaches React at all, so no permission assertion downstream can
 * tell the difference between "correctly refused" and "unreachable".
 *
 * It exists because of a defect only a production-image run could find:
 * `docker/nginx.conf.template` proxied `location /oauth2` — a *prefix* match, which also
 * captured the admin UI's own `/oauth2-clients` route and sent it to a backend
 * with no such endpoint. The page was a blank 404 for every principal.
 * `frontend/vite.config.ts` had already been taught to exclude that path
 * (`^/oauth2(/|\?|$)`), so the dev server and `vite preview` — which is what CI
 * runs the E2E suite against — were both correct and the shipped image was not.
 *
 * The general shape is what earns this its place: any future proxy prefix
 * (`/api`, `/.well-known`, the next one) can silently capture any future SPA
 * route, and this fails the moment it does.
 */

test.describe("SPA routing through the front door", () => {
  // No storageState: an unauthenticated request still has to be answered by the
  // SPA — the app decides where to send it, and the proxy must not decide first.
  test.use({ storageState: { cookies: [], origins: [] } });

  // Every route the app registers, not only the ones the sidebar links to:
  // a bookmark, a redirect or an email link can land on any of them.
  const ROUTES = [
    ...NAV_DESTINATIONS.map((d) => d.path),
    "/login",
    "/bootstrap",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/verify-email",
    "/auth/mfa-setup",
    "/profile/change-password",
    "/profile/mfa",
    "/settings/webauthn-attestation-policy",
  ];

  test("every SPA route is served the application document", async ({ request }) => {
    for (const route of ROUTES) {
      const res = await request.get(route, { failOnStatusCode: false });
      expect
        .soft(
          res.status(),
          `${route} must be answered by the SPA fallback. A non-200 here means a ` +
            `reverse-proxy location captured the path and forwarded it to a backend ` +
            `that does not serve it — the page is then blank for every principal, ` +
            `whatever their permissions.`,
        )
        .toBe(200);

      const contentType = res.headers()["content-type"] ?? "";
      expect
        .soft(
          contentType,
          `${route} must be served as the HTML application document, not as an API response`,
        )
        .toContain("text/html");
    }
  });
});
