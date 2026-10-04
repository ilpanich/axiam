import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  connectionMoved,
  directoryService,
  movedConnectionFields,
  type ConnectionFields,
  type DirectoryConfig,
} from "./directory";

const TENANT = "11111111-1111-1111-1111-111111111111";
const BASE = `/api/v1/tenants/${TENANT}/directory`;

const connection: ConnectionFields = {
  url: "ldaps://ldap.example.com",
  start_tls: false,
  bind_dn: "cn=svc,dc=example,dc=com",
  trust_anchors_pem: ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"],
};

function notFound() {
  return Promise.reject({ response: { status: 404 } });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("directoryService", () => {
  it("reads the configuration, and a 404 is null rather than an error", async () => {
    apiMock.get.mockResolvedValueOnce(res({ id: "d1" } as DirectoryConfig));
    expect(await directoryService.get(TENANT)).toEqual({ id: "d1" });
    expect(apiMock.get).toHaveBeenCalledWith(BASE);

    apiMock.get.mockImplementationOnce(notFound);
    expect(await directoryService.get(TENANT)).toBeNull();
  });

  it("lets any other failure through", async () => {
    apiMock.get.mockRejectedValueOnce({ response: { status: 500 } });
    await expect(directoryService.get(TENANT)).rejects.toMatchObject({
      response: { status: 500 },
    });
  });

  it("replaces with PUT, edits with PATCH and deletes with DELETE", async () => {
    apiMock.put.mockResolvedValueOnce(res({ id: "d1" }));
    await directoryService.set(TENANT, {
      enabled: true,
      kind: "open_ldap",
      url: "ldaps://ldap.example.com",
      start_tls: false,
      bind_dn: "cn=svc",
      base_dn: "dc=example",
      user_filter: "(uid={username})",
    });
    expect(apiMock.put).toHaveBeenCalledWith(BASE, expect.objectContaining({ enabled: true }));

    apiMock.patch.mockResolvedValueOnce(res({ id: "d1" }));
    await directoryService.update(TENANT, { enabled: false });
    expect(apiMock.patch).toHaveBeenCalledWith(BASE, { enabled: false });

    apiMock.delete.mockResolvedValueOnce(res(undefined));
    expect(await directoryService.remove(TENANT)).toBeUndefined();
    expect(apiMock.delete).toHaveBeenCalledWith(BASE);
  });

  it("links an account by id and sends nothing else", async () => {
    apiMock.post.mockResolvedValueOnce(
      res({
        user_id: "u1",
        directory_external_id: "e1",
        webauthn_credentials_deleted: 1,
        certificates_revoked: 0,
        was_already_linked: false,
      }),
    );
    const result = await directoryService.linkAccount(TENANT, "u1");
    expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/links`, { user_id: "u1" });
    expect(result.webauthn_credentials_deleted).toBe(1);
  });

  it("reads the sync status, null when there is no configuration", async () => {
    apiMock.get.mockResolvedValueOnce(
      res({
        last_result: null,
        last_attempt_at: null,
        last_full_run_at: null,
        full_required: false,
        has_watermark: false,
      }),
    );
    expect((await directoryService.getSyncStatus(TENANT))?.last_result).toBeNull();
    expect(apiMock.get).toHaveBeenCalledWith(`${BASE}/sync-status`);
    apiMock.get.mockImplementationOnce(notFound);
    expect(await directoryService.getSyncStatus(TENANT)).toBeNull();
  });
});

describe("connectionMoved (P23W2-01)", () => {
  it("is false for an identical connection", () => {
    expect(connectionMoved(connection, { ...connection })).toBe(false);
  });

  it.each([
    ["url", { url: "ldaps://other.example.com" }],
    ["start_tls", { start_tls: true }],
    ["bind_dn", { bind_dn: "cn=other,dc=example,dc=com" }],
    ["trust_anchors_pem", { trust_anchors_pem: [] }],
  ] as Array<[string, Partial<ConnectionFields>]>)("is true when %s changes", (_field, change) => {
    expect(connectionMoved(connection, { ...connection, ...change })).toBe(true);
  });

  it("compares anchors as an ordered list, byte for byte", () => {
    const two = ["a", "b"];
    expect(
      connectionMoved(
        { ...connection, trust_anchors_pem: two },
        { ...connection, trust_anchors_pem: ["b", "a"] },
      ),
    ).toBe(true);
    expect(
      connectionMoved(
        { ...connection, trust_anchors_pem: two },
        { ...connection, trust_anchors_pem: [...two] },
      ),
    ).toBe(false);
  });

  it("names what moved", () => {
    expect(
      movedConnectionFields(connection, {
        ...connection,
        url: "ldaps://x.example.com",
        trust_anchors_pem: [],
      }),
    ).toEqual(["URL", "trust anchors"]);
    expect(movedConnectionFields(connection, { ...connection })).toEqual([]);
  });
});
