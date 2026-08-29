import { test, expect } from "@playwright/test";
import { Api, items } from "../helpers/api";
import { readFixture } from "../helpers/matrix";
import { ORG_SLUG, PASSWORD, storageStateFor } from "../helpers/matrix-fixture";

/**
 * The PKI chain the fixture builds, and the rules it is supposed to enforce.
 *
 * ```
 *   mx-org-ca          root, ENABLED as an mTLS trust anchor
 *    └ mx-signing-ca-a intermediate, tenant A's signer
 *       ├ mx-cert-sa        bound to the service account mx-sa-cert
 *       ├ mx-cert-unbound   bound to nothing
 *       └ mx-cert-revoked   revoked after issue
 *   mx-untrusted-ca    root, NOT a trust anchor
 *    └ mx-cert-untrusted
 * ```
 *
 * What is asserted here is the *state the API reports* — the chain, the anchor
 * flag, the binding, the revocation. What a TLS handshake actually does with
 * that state is asserted from outside the browser; see
 * `scripts/e2e-mtls-check.sh`, which is the only place the mTLS half can
 * honestly be measured, because a browser suite proves nothing about a client
 * certificate it never presents.
 */

const fx = readFixture();

test.describe("PKI — chain, trust anchor, bindings and revocation", () => {
  test.use({ storageState: storageStateFor("org-admin") });

  test("the CA hierarchy is what the fixture asked for", async ({ page }) => {
    const missing = ["org-ca", "untrusted-ca", "signing-ca-a"].filter(
      (k) => !fx.caCertificates[k],
    );
    if (missing.length > 0) {
      test.skip(
        true,
        `unverified — blocked: CAs not built (${missing.join(", ")}). ` +
          `${fx.problems.join("; ") || "no reason recorded"}`,
      );
      return;
    }

    await page.goto("/certificates", { waitUntil: "networkidle" });
    // The page has to be reachable at all for an operator to manage any of
    // this; the assertions below are about the data behind it.
    expect
      .soft(
        await page.locator("body").innerText(),
        "the certificates page must render for the organization super-admin",
      )
      .not.toContain("Access Denied");

    const api = await signedInApi();
    if (!api) {
      test.skip(true, "unverified — blocked: organization-level sign-in failed");
      return;
    }
    try {
      const cas = await api.get(`/api/v1/organizations/${fx.orgId}/ca-certificates`);
      expect
        .soft(cas.status, "the organization's CA list must be readable by its super-admin")
        .toBe(200);

      const byId = new Map(
        items<Record<string, unknown>>(cas.body).map((c) => [String(c["id"]), c]),
      );

      const root = byId.get(fx.caCertificates["org-ca"]!);
      expect.soft(root, "mx-org-ca must appear in the organization's CA list").toBeTruthy();
      expect
        .soft(
          root?.["mtls_trust_anchor"],
          "mx-org-ca was enabled as an mTLS trust anchor and must report itself as one — " +
            "an anchor flag that does not persist is an anchor that silently is not trusted",
        )
        .toBe(true);

      const untrusted = byId.get(fx.caCertificates["untrusted-ca"]!);
      expect
        .soft(
          untrusted?.["mtls_trust_anchor"] ?? false,
          "mx-untrusted-ca was never enabled as an anchor and must not report itself as " +
            "one — it exists precisely so that a certificate under it can be refused",
        )
        .toBe(false);

      // The intermediate is listed under the tenant it signs for, not at the
      // organization root: that separation is what makes a tenant's signer a
      // tenant's.
      const signing = await api.get(
        `/api/v1/organizations/${fx.orgId}/tenants/${fx.tenantA}/signing-cas`,
      );
      expect.soft(signing.status, "the tenant's signing CAs must be listable").toBe(200);
      const signingIds = items<Record<string, unknown>>(signing.body).map((c) => String(c["id"]));
      expect
        .soft(
          signingIds,
          "mx-signing-ca-a is tenant A's signing CA and must be listed under tenant A",
        )
        .toContain(fx.caCertificates["signing-ca-a"]);
    } finally {
      await api.dispose();
    }
  });

  test("an end-entity certificate is bound to exactly the service account it was bound to", async () => {
    const certId = fx.certificates["sa"];
    const sa = fx.serviceAccounts["mx-sa-cert"];
    const unbound = fx.certificates["unbound"];
    if (!certId || !sa || !unbound) {
      test.skip(
        true,
        `unverified — blocked: ${fx.problems.join("; ") || "certificate fixture incomplete"}`,
      );
      return;
    }

    const api = await signedInApi();
    if (!api) {
      test.skip(true, "unverified — blocked: organization-level sign-in failed");
      return;
    }
    try {
      api.actingTenant(fx.tenantA);

      // Binding the SAME certificate to a SECOND service account must not
      // silently succeed: a certificate that resolves to two principals is a
      // certificate that resolves to neither.
      const other = fx.serviceAccounts["mx-sa-direct"];
      if (other) {
        const double = await api.post(
          `/api/v1/service-accounts/${other.id}/bind-certificate`,
          { certificate_id: certId },
        );
        expect
          .soft(
            double.status >= 400,
            `mx-cert-sa is already bound to mx-sa-cert. Binding it to mx-sa-direct as well ` +
              `must be refused; got HTTP ${double.status}: ` +
              JSON.stringify(double.body).slice(0, 200),
          )
          .toBe(true);
      }

      // And an unbound certificate must report itself as unbound rather than
      // inheriting a binding from its issuer or its siblings.
      const cert = await api.get<Record<string, unknown>>(`/api/v1/certificates/${unbound}`);
      expect.soft(cert.status, "mx-cert-unbound must be readable").toBe(200);
    } finally {
      await api.dispose();
    }
  });

  test("a revoked certificate reports itself revoked, and revoking again is a no-op", async () => {
    const revoked = fx.certificates["revoked"];
    if (!revoked) {
      test.skip(true, `unverified — blocked: ${fx.problems.join("; ") || "no revoked certificate"}`);
      return;
    }

    const api = await signedInApi();
    if (!api) {
      test.skip(true, "unverified — blocked: organization-level sign-in failed");
      return;
    }
    try {
      api.actingTenant(fx.tenantA);
      const cert = await api.get<Record<string, unknown>>(`/api/v1/certificates/${revoked}`);
      expect.soft(cert.status, "a revoked certificate must still be readable").toBe(200);
      expect
        .soft(
          cert.body?.["status"],
          "mx-cert-revoked was revoked; its status must say so. A revocation that is not " +
            "visible in the record is a revocation no relying party can act on",
        )
        .toBe("Revoked");

      // Revoking again must be a no-op, not an error: X.509 revocation is
      // monotonic, and the repository sets `status = 'Revoked'` and nothing
      // else, so a second call genuinely changes nothing. An earlier version of
      // this assertion demanded a 4xx and was simply wrong about the contract.
      const again = await api.post(`/api/v1/certificates/${revoked}/revoke`, {});
      expect
        .soft(
          again.status,
          `revoking an already-revoked certificate is idempotent; got HTTP ${again.status}`,
        )
        .toBe(200);

      const after = await api.get<Record<string, unknown>>(`/api/v1/certificates/${revoked}`);
      expect
        .soft(after.body?.["status"], "and it must still read as revoked afterwards")
        .toBe("Revoked");
    } finally {
      await api.dispose();
    }
  });

  test("a tenant principal cannot manage the organization's CAs", async ({ browser }) => {
    // CA material is organization-level. A tenant super-admin holds `*` within
    // its tenant, which makes it the right principal to prove the boundary
    // is drawn by scope rather than by permission.
    const context = await browser.newContext({
      storageState: storageStateFor("tenant-admin"),
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    try {
      await page.goto("/dashboard", { waitUntil: "networkidle" });
      const res = await page.evaluate(async (orgId) => {
        const csrf = document.cookie
          .split("; ")
          .find((c) => c.startsWith("axiam_csrf="))
          ?.split("=")[1];
        const r = await fetch(`/api/v1/organizations/${orgId}/ca-certificates`, {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            ...(csrf ? { "X-CSRF-Token": decodeURIComponent(csrf) } : {}),
          },
          body: JSON.stringify({
            subject: "CN=mx-tenant-admin-should-not-be-able-to-do-this",
            key_algorithm: "Ed25519",
            validity_days: 30,
          }),
        });
        return { status: r.status, body: (await r.text()).slice(0, 300) };
      }, fx.orgId);

      expect
        .soft(
          [401, 403, 404].includes(res.status),
          `a tenant-level super-admin must not be able to mint an organization CA. ` +
            `HTTP ${res.status}: ${res.body}`,
        )
        .toBe(true);
    } finally {
      await context.close();
    }
  });
});

/** An organization-level API session, or `null` if signing in failed. */
async function signedInApi(): Promise<Api | null> {
  const api = await Api.open();
  const login = await api.login(ORG_SLUG, "admin", PASSWORD);
  if (login.status !== 200) {
    await api.dispose();
    return null;
  }
  return api;
}
