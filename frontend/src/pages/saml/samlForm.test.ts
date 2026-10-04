import { describe, it, expect } from "vitest";
import type { SamlServiceProvider, SamlServiceProviderInput } from "@/services/saml";
import {
  buildServiceProviderInput,
  certificateProblem,
  emptyForm,
  endpointProblem,
  formFromServiceProvider,
  importRequest,
  isSignatureWarning,
  newAcsRow,
  newMappingRow,
  parseValidityDays,
  validateForm,
  type SamlForm,
} from "./samlForm";
import { samlErrorMessage } from "./samlErrors";
import { certPem, pemBlock } from "@/test/pemFixture";

function stored(overrides: Partial<SamlServiceProvider> = {}): SamlServiceProvider {
  return {
    id: "sp1",
    tenant_id: "t1",
    enabled: true,
    display_name: "Wiki",
    entity_id: "https://wiki.example.com/sp",
    acs_urls: [
      { url: "https://wiki.example.com/acs", binding: "http_post", index: 0, is_default: true },
    ],
    slo_url: null,
    slo_binding: null,
    name_id_format: "persistent",
    sign_responses: true,
    encrypt_assertions: false,
    sp_signing_cert_pem: null,
    sp_encryption_cert_pem: null,
    want_authn_requests_signed: false,
    allow_idp_initiated: false,
    attribute_mappings: [],
    allowed_groups: [],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...overrides,
  };
}

function valid(overrides: Partial<SamlForm> = {}): SamlForm {
  return {
    ...emptyForm(),
    displayName: "Wiki",
    entityId: "https://wiki.example.com/sp",
    acs: [{ ...newAcsRow(), url: "https://wiki.example.com/acs" }],
    ...overrides,
  };
}

describe("emptyForm", () => {
  it("carries the server's defaults", () => {
    const form = emptyForm();
    expect(form).toMatchObject({
      enabled: true,
      nameIdFormat: "persistent",
      signResponses: true,
      wantAuthnRequestsSigned: false,
      allowIdpInitiated: false,
      allowedGroups: [],
      mappings: [],
    });
    expect(form.acs).toHaveLength(1);
    expect(form.acs[0]).toMatchObject({ binding: "http_post", index: "0", isDefault: true });
  });

  it("numbers a new ACS row past the indexes in use, and defaults only the first", () => {
    const first = newAcsRow();
    const second = newAcsRow([first]);
    const third = newAcsRow([first, { ...second, index: "2" }]);
    expect(second).toMatchObject({ index: "1", isDefault: false });
    expect(third.index).toBe("1");
  });
});

describe("buildServiceProviderInput", () => {
  it("carries every member of SamlServiceProviderInput, so a replacement resets nothing", () => {
    const body = buildServiceProviderInput(valid(), null);
    expect(Object.keys(body).sort()).toEqual(
      [
        "acs_urls",
        "allow_idp_initiated",
        "allowed_groups",
        "attribute_mappings",
        "display_name",
        "enabled",
        "encrypt_assertions",
        "entity_id",
        "name_id_format",
        "sign_responses",
        "slo_binding",
        "slo_url",
        "sp_encryption_cert_pem",
        "sp_signing_cert_pem",
        "want_authn_requests_signed",
      ].sort(),
    );
  });

  it("has no sign_assertions member: the assertion is signed always", () => {
    expect(buildServiceProviderInput(valid(), null)).not.toHaveProperty("sign_assertions");
  });

  it("never sends encrypt_assertions as true, whatever the form or the stored row says", () => {
    expect(buildServiceProviderInput(valid(), null).encrypt_assertions).toBe(false);
    const hostile = stored({ encrypt_assertions: true });
    const form = formFromServiceProvider(hostile);
    expect(buildServiceProviderInput(form, hostile).encrypt_assertions).toBe(false);
    // Not even a form object that was tampered with can carry it across.
    const tampered = { ...valid(), encryptAssertions: true } as SamlForm;
    expect(buildServiceProviderInput(tampered, null).encrypt_assertions).toBe(false);
  });

  it("sends an imported draft's encrypt_assertions as false too", () => {
    const draft: SamlServiceProviderInput = {
      display_name: "X",
      entity_id: "https://x.example.com",
      acs_urls: [{ url: "https://x.example.com/acs", binding: "http_post", index: 0 }],
      encrypt_assertions: true,
    };
    expect(buildServiceProviderInput(formFromServiceProvider(draft), null).encrypt_assertions).toBe(
      false,
    );
  });

  it("takes the entity id from the stored registration on an edit, never from the form", () => {
    const row = stored();
    const form = { ...formFromServiceProvider(row), entityId: "https://evil.example.com/sp" };
    expect(buildServiceProviderInput(form, row).entity_id).toBe("https://wiki.example.com/sp");
  });

  it("takes the typed entity id, trimmed, on create", () => {
    const form = valid({ entityId: "  https://new.example.com/sp  " });
    expect(buildServiceProviderInput(form, null).entity_id).toBe("https://new.example.com/sp");
  });

  it("sends null for a blank SLO URL and its binding together", () => {
    const body = buildServiceProviderInput(valid({ sloUrl: "  ", sloBinding: "" }), null);
    expect(body.slo_url).toBeNull();
    expect(body.slo_binding).toBeNull();
  });

  it("maps the ACS list with numeric indexes and the default flag", () => {
    const form = valid({
      acs: [
        { ...newAcsRow(), url: " https://a.example.com/acs ", index: " 3 ", isDefault: false },
        { ...newAcsRow(), url: "https://b.example.com/acs", binding: "http_redirect", index: "4", isDefault: true },
      ],
    });
    expect(buildServiceProviderInput(form, null).acs_urls).toEqual([
      { url: "https://a.example.com/acs", binding: "http_post", index: 3, is_default: false },
      { url: "https://b.example.com/acs", binding: "http_redirect", index: 4, is_default: true },
    ]);
  });

  it("maps attribute mappings, with an unset format as null", () => {
    const form = valid({
      mappings: [
        newMappingRow("mail", "email"),
        newMappingRow("groups", "groups", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
      ],
    });
    expect(buildServiceProviderInput(form, null).attribute_mappings).toEqual([
      { saml_name: "mail", name_format: null, source: "email" },
      {
        saml_name: "groups",
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        source: "groups",
      },
    ]);
  });

  it("sends a blank certificate as null, and a typed one trimmed with a closing newline", () => {
    const pem = certPem();
    const body = buildServiceProviderInput(
      valid({ spSigningCertPem: `\n  ${pem.trim()}  \n`, spEncryptionCertPem: "  " }),
      null,
    );
    expect(body.sp_signing_cert_pem).toBe(pem);
    expect(body.sp_encryption_cert_pem).toBeNull();
  });

  it("sends an untouched stored certificate byte for byte", () => {
    const pem = certPem().trimEnd();
    const row = stored({ sp_signing_cert_pem: pem });
    const body = buildServiceProviderInput(formFromServiceProvider(row), row);
    expect(body.sp_signing_cert_pem).toBe(pem);
  });

  it("round trips a stored registration to the same registration", () => {
    const pem = certPem();
    const row = stored({
      enabled: false,
      slo_url: "https://wiki.example.com/slo",
      slo_binding: "http_redirect",
      name_id_format: "email_address",
      sign_responses: false,
      sp_signing_cert_pem: pem,
      want_authn_requests_signed: true,
      allow_idp_initiated: true,
      attribute_mappings: [{ saml_name: "mail", name_format: null, source: "email" }],
      allowed_groups: ["g1", "g2"],
    });
    const expected: Record<string, unknown> = { ...row };
    for (const member of ["id", "tenant_id", "created_at", "updated_at"]) delete expected[member];
    expect(buildServiceProviderInput(formFromServiceProvider(row), row)).toEqual(expected);
  });
});

describe("formFromServiceProvider", () => {
  it("gives an imported draft that omits optional members the server's defaults", () => {
    const form = formFromServiceProvider({
      display_name: "X",
      entity_id: "https://x.example.com",
      acs_urls: [{ url: "https://x.example.com/acs", binding: "http_post", index: 0 }],
    });
    expect(form).toMatchObject({
      enabled: true,
      signResponses: true,
      nameIdFormat: "persistent",
      wantAuthnRequestsSigned: false,
      allowIdpInitiated: false,
      sloUrl: "",
      sloBinding: "",
      allowedGroups: [],
    });
    expect(form.acs[0].isDefault).toBe(false);
  });
});

describe("validateForm", () => {
  it("accepts the minimal valid form", () => {
    expect(validateForm(valid(), null)).toBeNull();
  });

  it.each<[string, Partial<SamlForm>, RegExp]>([
    ["a blank display name", { displayName: "  " }, /display name/i],
    ["a control character in the display name", { displayName: "a\u0007b" }, /control/i],
    ["an over-long display name", { displayName: "x".repeat(257) }, /256/],
    ["a blank entity id", { entityId: " " }, /entity ID/i],
    ["an over-long entity id", { entityId: "x".repeat(1025) }, /1024/],
    ["no ACS endpoint", { acs: [] }, /at least one/i],
    [
      "a wildcard ACS URL",
      { acs: [{ ...newAcsRow(), url: "https://*.example.com/acs" }] },
      /exactly|wildcard|\*/i,
    ],
    ["a plain-http ACS URL", { acs: [{ ...newAcsRow(), url: "http://sp.example.com/acs" }] }, /https/],
    ["an ACS URL with a fragment", { acs: [{ ...newAcsRow(), url: "https://sp.example.com/a#x" }] }, /fragment/],
    ["a relative ACS URL", { acs: [{ ...newAcsRow(), url: "/acs" }] }, /absolute/],
    [
      "a duplicate ACS URL",
      {
        acs: [
          { ...newAcsRow(), url: "https://sp.example.com/acs", isDefault: true },
          { ...newAcsRow(), url: "https://sp.example.com/acs", index: "1" },
        ],
      },
      /twice/,
    ],
    [
      "a duplicate ACS index",
      {
        acs: [
          { ...newAcsRow(), url: "https://a.example.com/acs", isDefault: true },
          { ...newAcsRow(), url: "https://b.example.com/acs", index: "0" },
        ],
      },
      /used twice/,
    ],
    [
      "an out-of-range ACS index",
      { acs: [{ ...newAcsRow(), url: "https://a.example.com/acs", index: "70000" }] },
      /0 to 65535/,
    ],
    [
      "two default endpoints",
      {
        acs: [
          { ...newAcsRow(), url: "https://a.example.com/acs", isDefault: true },
          { ...newAcsRow(), url: "https://b.example.com/acs", index: "1", isDefault: true },
        ],
      },
      /at most one/i,
    ],
    [
      "an unknown ACS binding",
      { acs: [{ ...newAcsRow(), url: "https://a.example.com/acs", binding: "soap" }] },
      /binding/,
    ],
    ["an SLO URL without a binding", { sloUrl: "https://sp.example.com/slo" }, /binding/],
    ["an SLO binding without a URL", { sloBinding: "http_post" }, /URL/],
    ["a wildcard SLO URL", { sloUrl: "https://*/slo", sloBinding: "http_post" }, /\*/],
    ["an unknown NameID format", { nameIdFormat: "transient" }, /NameID/],
    ["a private key as the signing certificate", { spSigningCertPem: pemBlock("PRIVATE KEY") }, /private key/i],
    ["two certificates in one box", { spSigningCertPem: certPem() + certPem() }, /exactly one/],
    ["text that is not a certificate", { spEncryptionCertPem: "hello" }, /exactly one/],
    ["required signed requests with no certificate", { wantAuthnRequestsSigned: true }, /signing certificate/],
    [
      "a blank attribute name",
      { mappings: [newMappingRow("", "email")] },
      /enter the attribute name/,
    ],
    [
      "a duplicate attribute name",
      { mappings: [newMappingRow("mail", "email"), newMappingRow("mail", "username")] },
      /used twice/,
    ],
    ["an attribute with no source", { mappings: [newMappingRow("mail", "")] }, /where the value/],
    [
      "an unknown attribute name format",
      { mappings: [newMappingRow("mail", "email", "urn:made:up")] },
      /name format/,
    ],
  ])("refuses %s", (_label, patch, message) => {
    expect(validateForm(valid(patch), null)).toMatch(message);
  });

  it("allows http for localhost, and an ECDSA-or-RSA PEM of the right shape", () => {
    expect(
      validateForm(
        valid({
          acs: [{ ...newAcsRow(), url: "http://localhost:8080/acs" }],
          spSigningCertPem: certPem(),
          wantAuthnRequestsSigned: true,
        }),
        null,
      ),
    ).toBeNull();
  });

  it("does not check the entity id on an edit, because it is not sent", () => {
    const row = stored();
    expect(validateForm(valid({ entityId: "" }), row)).toBeNull();
  });

  it("holds more than 64 mappings and 256 groups to the server's limits", () => {
    const many = Array.from({ length: 65 }, (_, i) => newMappingRow(`a${i}`, "email"));
    expect(validateForm(valid({ mappings: many }), null)).toMatch(/64/);
    const groups = Array.from({ length: 257 }, (_, i) => `g${i}`);
    expect(validateForm(valid({ allowedGroups: groups }), null)).toMatch(/256/);
  });
});

describe("endpointProblem and certificateProblem", () => {
  it("accepts https and the three loopback hosts over http", () => {
    expect(endpointProblem("https://sp.example.com/acs")).toBeNull();
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(endpointProblem(`http://${host}:9000/acs`)).toBeNull();
    }
    expect(endpointProblem("http://sp.example.com/acs")).not.toBeNull();
    expect(endpointProblem("javascript:alert(1)")).not.toBeNull();
  });

  it("accepts nothing, or exactly one certificate", () => {
    expect(certificateProblem("")).toBeNull();
    expect(certificateProblem(certPem())).toBeNull();
    expect(certificateProblem(`note\n${certPem()}`)).not.toBeNull();
  });
});

describe("importRequest", () => {
  it("builds exactly one member", () => {
    expect(importRequest("<EntityDescriptor/>", "")).toEqual({
      ok: true,
      body: { metadata_xml: "<EntityDescriptor/>" },
    });
    expect(importRequest("", " https://sp.example.com/md ")).toEqual({
      ok: true,
      body: { metadata_url: "https://sp.example.com/md" },
    });
  });

  it("refuses both, neither and a non-https URL before any request", () => {
    expect(importRequest("<a/>", "https://x")).toMatchObject({ ok: false });
    expect(importRequest(" ", " ")).toMatchObject({ ok: false });
    expect(importRequest("", "http://sp.example.com/md")).toMatchObject({
      ok: false,
      reason: expect.stringContaining("https"),
    });
  });
});

describe("isSignatureWarning", () => {
  it("recognises the server's warning and nothing else", () => {
    expect(isSignatureWarning("metadata signature not verified")).toBe(true);
    expect(isSignatureWarning("The metadata signature was not verified.")).toBe(true);
    expect(isSignatureWarning("more than one signing key; the first was taken")).toBe(false);
  });
});

describe("parseValidityDays", () => {
  it("accepts 1 to 730 and nothing else", () => {
    expect(parseValidityDays("365")).toEqual({ ok: true, days: 365 });
    expect(parseValidityDays("1")).toEqual({ ok: true, days: 1 });
    expect(parseValidityDays("730")).toEqual({ ok: true, days: 730 });
    for (const bad of ["0", "731", "-5", "1.5", "", "abc"]) {
      expect(parseValidityDays(bad)).toMatchObject({ ok: false });
    }
  });
});

describe("samlErrorMessage", () => {
  const failure = (status: number, error: string, message: string) => ({
    response: { status, data: { error, message } },
  });

  it("shows a 400 rule message verbatim, which the generic redactor would mangle", () => {
    const message = "sp_signing_cert_pem: private key not accepted; secret=must not be sent";
    expect(samlErrorMessage(failure(400, "validation_error", message))).toBe(message);
  });

  it("shows a 409 and a 404 verbatim", () => {
    expect(samlErrorMessage(failure(409, "conflict", "the active slot is occupied"))).toBe(
      "the active slot is occupied",
    );
    expect(samlErrorMessage(failure(404, "not_found", "ca not found"))).toBe("ca not found");
  });

  it("blanks a private-key block even in a verbatim message", () => {
    const key = pemBlock("PRIVATE KEY");
    const shown = samlErrorMessage(failure(400, "validation_error", `bad: ${key}`));
    expect(shown).not.toContain(key.split("\n")[1]);
    expect(shown).toContain("redacted");
  });

  it("sends anything else through the generic path, with the fallback", () => {
    expect(samlErrorMessage(new Error("network down"), "Save failed.")).toBeTruthy();
    expect(samlErrorMessage({}, "Save failed.")).toBe("Save failed.");
  });
});
