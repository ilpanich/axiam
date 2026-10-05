import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  credentialRequiredFor,
  scimTargetService,
  validateHttpsUrl,
  validateScimTargetInput,
  type ScimTargetInput,
} from "./scimTargets";

beforeEach(() => vi.clearAllMocks());

const bearer = { base_url: "https://a.example.com/scim", auth: { type: "bearer" } } as const;
const oauth = {
  base_url: "https://a.example.com/scim",
  auth: {
    type: "oauth2_client_credentials",
    token_url: "https://a.example.com/token",
    client_id: "axiam",
  },
} as const;

function input(overrides: Partial<ScimTargetInput> = {}): ScimTargetInput {
  return {
    name: "HR",
    base_url: "https://a.example.com/scim",
    enabled: true,
    auth: { type: "bearer" },
    scope: { type: "all_users" },
    push_groups: false,
    user_name_from: "username",
    deprovision: "deactivate",
    ...overrides,
  };
}

describe("credentialRequiredFor (D-57, contract §31.3 rule 2)", () => {
  it("is not required when nothing that binds the credential changed", () => {
    expect(credentialRequiredFor(bearer, bearer)).toBeNull();
    expect(credentialRequiredFor(oauth, oauth)).toBeNull();
  });

  it("is required when a bearer target's base URL changes", () => {
    expect(
      credentialRequiredFor(bearer, { ...bearer, base_url: "https://b.example.com/scim" }),
    ).toBe("Changing the base URL");
  });

  it("is required when a client-credentials target's token URL changes, not its base URL", () => {
    expect(
      credentialRequiredFor(oauth, { ...oauth, base_url: "https://b.example.com/scim" }),
    ).toBeNull();
    expect(
      credentialRequiredFor(oauth, {
        ...oauth,
        auth: { ...oauth.auth, token_url: "https://b.example.com/token" },
      }),
    ).toBe("Changing the token URL");
  });

  it("is required when the authentication kind is switched, either way", () => {
    expect(credentialRequiredFor(bearer, oauth)).toBe("Switching the authentication kind");
    expect(credentialRequiredFor(oauth, bearer)).toBe("Switching the authentication kind");
  });
});

describe("validation mirrors the server's bounds", () => {
  it("accepts a plain https URL and refuses the rest", () => {
    expect(validateHttpsUrl("Base URL", "https://a.example.com/scim")).toBeNull();
    expect(validateHttpsUrl("Base URL", "")).toBe("Base URL is required.");
    expect(validateHttpsUrl("Base URL", "a.example.com")).toBe("Base URL must be an absolute URL.");
    expect(validateHttpsUrl("Base URL", "http://a.example.com")).toBe("Base URL must use https.");
    expect(validateHttpsUrl("Base URL", "https://u@a.example.com")).toBe(
      "Base URL must not carry credentials.",
    );
    expect(validateHttpsUrl("Base URL", "https://a.example.com/#x")).toBe(
      "Base URL must not carry a fragment.",
    );
    expect(validateHttpsUrl("Base URL", `https://a.example.com/${"x".repeat(2100)}`)).toMatch(
      /at most 2048 bytes/,
    );
  });

  it("bounds the name, the groups and the credential", () => {
    expect(validateScimTargetInput(input())).toBeNull();
    expect(validateScimTargetInput(input({ name: "  " }))).toBe("Name is required.");
    expect(validateScimTargetInput(input({ name: "n".repeat(129) }))).toMatch(/at most 128/);
    expect(
      validateScimTargetInput(input({ scope: { type: "groups", group_ids: [] } })),
    ).toBe("Select at least one group.");
    expect(
      validateScimTargetInput(
        input({
          scope: {
            type: "groups",
            group_ids: Array.from({ length: 101 }, (_, i) => `g${i}`),
          },
        }),
      ),
    ).toMatch(/at most 100/);
    expect(validateScimTargetInput(input({ credential: "x".repeat(4097) }))).toMatch(/at most 4096/);
    expect(validateScimTargetInput(input({ credential: "two words" }))).toBe(
      "A bearer token must not contain spaces.",
    );
    // A client secret may hold a space; a bearer token may not.
    expect(
      validateScimTargetInput(
        input({
          auth: {
            type: "oauth2_client_credentials",
            token_url: "https://a.example.com/token",
            client_id: "c",
          },
          credential: "two words",
        }),
      ),
    ).toBeNull();
  });
});

describe("scimTargetService", () => {
  it("calls the six routes of contract §31.1 with the documented verbs", async () => {
    apiMock.post.mockResolvedValue(res({}));
    apiMock.put.mockResolvedValue(res({}));
    apiMock.delete.mockResolvedValue(res(undefined));
    await scimTargetService.create(input());
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/scim-targets", expect.anything());
    await scimTargetService.update("s1", input());
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/scim-targets/s1", expect.anything());
    await scimTargetService.remove("s1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/scim-targets/s1");
    await scimTargetService.reconcile("s1");
    expect(apiMock.post).toHaveBeenLastCalledWith("/api/v1/scim-targets/s1/reconcile");
  });
});
