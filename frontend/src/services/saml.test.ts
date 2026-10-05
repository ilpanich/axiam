import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  samlService,
  serviceProvidersPath,
  type SamlServiceProviderInput,
} from "./saml";

const TENANT = "11111111-1111-1111-1111-111111111111";
const SP = "22222222-2222-2222-2222-222222222222";
const CRED = "33333333-3333-3333-3333-333333333333";
const BASE = `/api/v1/tenants/${TENANT}/saml`;

const input: SamlServiceProviderInput = {
  display_name: "Wiki",
  entity_id: "https://wiki.example.com/sp",
  acs_urls: [
    { url: "https://wiki.example.com/acs", binding: "http_post", index: 0, is_default: true },
  ],
  encrypt_assertions: false,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("samlService — the registry", () => {
  it("reads the IdP info", async () => {
    apiMock.get.mockResolvedValueOnce(res({ tenant_id: TENANT, saml_available: true }));
    expect(await samlService.getIdp(TENANT)).toMatchObject({ saml_available: true });
    expect(apiMock.get).toHaveBeenCalledWith(`${BASE}/idp`);
  });

  it("lists a page with offset, limit and a trimmed search, and omits a blank search", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 20, limit: 20 }));
    await samlService.listServiceProviders(TENANT, { offset: 20, limit: 20, search: "  wiki " });
    expect(apiMock.get).toHaveBeenLastCalledWith(serviceProvidersPath(TENANT), {
      params: { offset: 20, limit: 20, search: "wiki" },
    });
    await samlService.listServiceProviders(TENANT, { offset: 0, limit: 20, search: "   " });
    expect(apiMock.get).toHaveBeenLastCalledWith(serviceProvidersPath(TENANT), {
      params: { offset: 0, limit: 20 },
    });
  });

  it("creates with POST, and returns the registration", async () => {
    apiMock.post.mockResolvedValueOnce(res({ id: SP }));
    expect(await samlService.createServiceProvider(TENANT, input)).toEqual({ id: SP });
    expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/service-providers`, input);
  });

  it("reads one", async () => {
    apiMock.get.mockResolvedValueOnce(res({ id: SP }));
    await samlService.getServiceProvider(TENANT, SP);
    expect(apiMock.get).toHaveBeenCalledWith(`${BASE}/service-providers/${SP}`);
  });

  it("replaces with PUT, not PATCH", async () => {
    apiMock.put.mockResolvedValueOnce(res({ id: SP }));
    await samlService.updateServiceProvider(TENANT, SP, input);
    expect(apiMock.put).toHaveBeenCalledWith(`${BASE}/service-providers/${SP}`, input);
    expect(apiMock.patch).not.toHaveBeenCalled();
  });

  it("deletes with DELETE and resolves to nothing", async () => {
    apiMock.delete.mockResolvedValueOnce(res(undefined));
    expect(await samlService.deleteServiceProvider(TENANT, SP)).toBeUndefined();
    expect(apiMock.delete).toHaveBeenCalledWith(`${BASE}/service-providers/${SP}`);
  });

  it("parses metadata with exactly the one member it was given", async () => {
    apiMock.post.mockResolvedValue(res({ service_provider: input, warnings: [] }));
    await samlService.parseSpMetadata(TENANT, { metadata_url: "https://sp.example.com/md" });
    expect(apiMock.post).toHaveBeenLastCalledWith(`${BASE}/parse-sp-metadata`, {
      metadata_url: "https://sp.example.com/md",
    });
    await samlService.parseSpMetadata(TENANT, { metadata_xml: "<EntityDescriptor/>" });
    expect(apiMock.post).toHaveBeenLastCalledWith(`${BASE}/parse-sp-metadata`, {
      metadata_xml: "<EntityDescriptor/>",
    });
    // Both, or neither, is not a request this type can express.
    // @ts-expect-error — exactly one of metadata_xml and metadata_url.
    void samlService.parseSpMetadata(TENANT, { metadata_xml: "x", metadata_url: "y" });
    // @ts-expect-error — exactly one of metadata_xml and metadata_url.
    void samlService.parseSpMetadata(TENANT, {});
  });

  it("never writes on a parse", async () => {
    apiMock.post.mockResolvedValue(res({ service_provider: input, warnings: [] }));
    await samlService.parseSpMetadata(TENANT, { metadata_xml: "<EntityDescriptor/>" });
    expect(apiMock.put).not.toHaveBeenCalled();
    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(String(apiMock.post.mock.calls[0][0])).toContain("parse-sp-metadata");
  });
});

describe("samlService — the signing credential", () => {
  it("lists a plain array, not a page", async () => {
    apiMock.get.mockResolvedValueOnce(res([{ id: CRED }]));
    expect(await samlService.listIdpCredentials(TENANT)).toEqual([{ id: CRED }]);
    expect(apiMock.get).toHaveBeenCalledWith(`${BASE}/idp-credentials`);
  });

  it("issues with the slot and validity it was given", async () => {
    apiMock.post.mockResolvedValueOnce(res({ id: CRED }));
    await samlService.issueIdpCredential(TENANT, {
      issuer_ca_id: "ca1",
      slot: "next",
      validity_days: 90,
    });
    expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/idp-credentials`, {
      issuer_ca_id: "ca1",
      slot: "next",
      validity_days: 90,
    });
  });

  it("promotes and retires with POST and no body", async () => {
    apiMock.post.mockResolvedValue(res({ active: { id: CRED }, retired: null }));
    const promoted = await samlService.promoteIdpCredential(TENANT, CRED);
    expect(promoted.retired).toBeNull();
    expect(apiMock.post).toHaveBeenLastCalledWith(`${BASE}/idp-credentials/${CRED}/promote`);
    await samlService.retireIdpCredential(TENANT, CRED);
    expect(apiMock.post).toHaveBeenLastCalledWith(`${BASE}/idp-credentials/${CRED}/retire`);
  });

  it("surfaces a failure to the caller, untouched", async () => {
    const failure = { response: { status: 409, data: { error: "conflict", message: "slot occupied" } } };
    apiMock.post.mockRejectedValueOnce(failure);
    await expect(
      samlService.issueIdpCredential(TENANT, { issuer_ca_id: "ca1", slot: "active" }),
    ).rejects.toBe(failure);
  });
});
