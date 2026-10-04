import { describe, it, expect } from "vitest";
import type { DirectoryConfig } from "@/services/directory";
import {
  buildSetPayload,
  buildUpdatePayload,
  currentAnchors,
  emptyForm,
  formFromConfig,
  newMappingRow,
  parseAnchors,
  secretRequired,
  validateForm,
  type DirectoryForm,
} from "./directoryForm";
import { directoryErrorMessage } from "./directoryErrors";

const PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const PEM_TWO = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";

/** A fresh value per call, from a CSPRNG: nothing here is a literal credential. */
function bindValue(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return `Bv${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}7`;
}

function stored(overrides: Partial<DirectoryConfig> = {}): DirectoryConfig {
  return {
    id: "d1",
    tenant_id: "t1",
    enabled: true,
    kind: "open_ldap",
    url: "ldaps://ldap.example.com",
    start_tls: false,
    bind_dn: "cn=svc,dc=example,dc=com",
    base_dn: "dc=example,dc=com",
    user_filter: "(uid={username})",
    user_attribute_map: {
      username: "uid",
      email: "mail",
      display_name: "displayName",
      external_id: "entryUUID",
    },
    group_base_dn: "ou=groups,dc=example,dc=com",
    group_filter: null,
    group_member_attribute: "member",
    group_nesting_depth: 5,
    group_mappings: [],
    sync_interval_secs: 3600,
    jit_provisioning: false,
    trust_anchors_pem: [PEM],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...overrides,
  };
}

describe("a form seeded from a stored configuration", () => {
  it("never carries a secret: the server returns none", () => {
    const form = formFromConfig(stored());
    expect(form.bindSecret).toBe("");
  });

  it("returns untouched trust anchors byte for byte", () => {
    const config = stored({ trust_anchors_pem: [PEM.trimEnd(), PEM_TWO] });
    const form = formFromConfig(config);
    expect(currentAnchors(form)).toBe(config.trust_anchors_pem);
    // So an unrelated edit does not read as a moved connection.
    expect(secretRequired(config, { ...form, userFilter: "(cn={username})" })).toBe(false);
  });

  it("parses retyped anchors into newline-terminated PEM blocks", () => {
    expect(parseAnchors(`${PEM}\n\n${PEM_TWO}`)).toEqual([PEM, PEM_TWO]);
    expect(parseAnchors("nothing here")).toEqual([]);
  });
});

describe("secretRequired", () => {
  it("is always true for a new configuration", () => {
    expect(secretRequired(null, emptyForm())).toBe(true);
  });

  it.each([
    ["the URL", (f: DirectoryForm) => ({ ...f, url: "ldaps://other.example.com" })],
    ["StartTLS", (f: DirectoryForm) => ({ ...f, startTls: true })],
    ["the bind DN", (f: DirectoryForm) => ({ ...f, bindDn: "cn=other" })],
    ["the trust anchors", (f: DirectoryForm) => ({ ...f, anchorsText: "" })],
  ])("is true once %s changes", (_what, change) => {
    const config = stored();
    expect(secretRequired(config, change(formFromConfig(config)))).toBe(true);
  });

  it.each([
    ["the filter", (f: DirectoryForm) => ({ ...f, userFilter: "(cn={username})" })],
    ["enabled", (f: DirectoryForm) => ({ ...f, enabled: false })],
    ["the sync interval", (f: DirectoryForm) => ({ ...f, syncIntervalSecs: "600" })],
    ["a mapping", (f: DirectoryForm) => ({ ...f, mappings: [newMappingRow("cn=a", "g1")] })],
  ])("is false when only %s changes", (_what, change) => {
    const config = stored();
    expect(secretRequired(config, change(formFromConfig(config)))).toBe(false);
  });
});

describe("validateForm", () => {
  const config = stored();
  const base = () => formFromConfig(config);

  it("accepts the stored configuration as it is", () => {
    expect(validateForm(config, base())).toBeNull();
  });

  it("asks for the secret again when the connection moved, and says why", () => {
    const form = { ...base(), url: "ldaps://other.example.com" };
    expect(validateForm(config, form)).toMatch(/bind secret again/);
    expect(validateForm(config, { ...form, bindSecret: bindValue() })).toBeNull();
  });

  it("needs a secret to create", () => {
    const form = { ...emptyForm(), url: "ldaps://ldap.example.com", bindDn: "cn=svc", baseDn: "dc=x" };
    expect(validateForm(null, form)).toBe("Enter the bind secret.");
    expect(validateForm(null, { ...form, bindSecret: bindValue() })).toBeNull();
  });

  it.each([
    ["no scheme", { url: "ldap.example.com" }, /ldaps:\/\/ or ldap:\/\//],
    ["ldaps with StartTLS", { startTls: true }, /already encrypted/],
    [
      "plaintext ldap",
      { url: "ldap://ldap.example.com", startTls: false },
      /Plaintext ldap/,
    ],
    ["a filter with no placeholder", { userFilter: "(uid=bob)" }, /exactly once/],
    ["two placeholders", { userFilter: "(|(uid={username})(cn={username}))" }, /exactly once/],
    ["a depth of 11", { groupNestingDepth: "11" }, /nesting depth/],
    ["an interval of 60", { syncIntervalSecs: "60" }, /Sync interval/],
    ["stray anchor text", { anchorsText: "not a certificate" }, /PEM certificates/],
    ["a mapping with no group", { mappings: [newMappingRow("cn=a", "")] }, /choose an AXIAM group/],
    ["a mapping with no DN", { mappings: [newMappingRow("", "g1")] }, /enter the directory group/],
  ] as Array<[string, Partial<DirectoryForm>, RegExp]>)("refuses %s", (_what, change, message) => {
    expect(validateForm(config, { ...base(), ...change })).toMatch(message);
  });
});

describe("payloads", () => {
  it("a PUT body carries every member, and the secret only when typed", () => {
    const form = formFromConfig(stored());
    const without = buildSetPayload(form);
    expect(without.bind_secret).toBeUndefined();
    expect(Object.keys(without).sort()).toEqual(
      [
        "base_dn",
        "bind_dn",
        "enabled",
        "group_base_dn",
        "group_filter",
        "group_member_attribute",
        "group_mappings",
        "group_nesting_depth",
        "jit_provisioning",
        "kind",
        "start_tls",
        "sync_interval_secs",
        "trust_anchors_pem",
        "url",
        "user_attribute_map",
        "user_filter",
      ].sort(),
    );
    expect(without.group_filter).toBeNull();
    const typed = bindValue();
    expect(buildSetPayload({ ...form, bindSecret: typed }).bind_secret).toBe(typed);
  });

  it("a PATCH body carries only what changed", () => {
    const config = stored();
    const form = formFromConfig(config);
    expect(buildUpdatePayload(config, form)).toEqual({});
    expect(buildUpdatePayload(config, { ...form, enabled: false })).toEqual({ enabled: false });

    const typed = bindValue();
    expect(
      buildUpdatePayload(config, {
        ...form,
        url: "ldaps://other.example.com",
        bindSecret: typed,
      }),
    ).toEqual({ url: "ldaps://other.example.com", bind_secret: typed });
  });

  it("clearing a nullable member sends an explicit null; leaving it sends nothing", () => {
    const config = stored({ group_filter: "(cn=*)" });
    const form = formFromConfig(config);
    expect(buildUpdatePayload(config, { ...form, groupFilter: "" })).toEqual({
      group_filter: null,
    });
    expect(buildUpdatePayload(config, form)).toEqual({});
    // And a member that was null stays absent when it stays empty.
    const unset = stored();
    expect(buildUpdatePayload(unset, formFromConfig(unset))).toEqual({});
  });

  it("sends the mapping table whole when it changes", () => {
    const config = stored();
    const form = formFromConfig(config);
    expect(
      buildUpdatePayload(config, { ...form, mappings: [newMappingRow(" cn=staff ", "g1")] }),
    ).toEqual({ group_mappings: [{ directory_group_dn: "cn=staff", group_id: "g1" }] });
  });
});

describe("directoryErrorMessage", () => {
  const failure = (status: number, error: string, message: string) => ({
    response: { status, data: { error, message } },
  });

  it("shows a 400 rule and a 409 conflict verbatim — even where the generic redactor would not", () => {
    // The generic redactor rewrites `secret: must…` into `secret=[redacted]`.
    const rule = "directory bind secret: must not be empty";
    expect(directoryErrorMessage(failure(400, "validation_error", rule), "")).toBe(rule);
    const conflict =
      "an enabled directory cannot coexist with opaque_mode `required`: lower it first";
    expect(directoryErrorMessage(failure(409, "conflict", conflict), "")).toBe(conflict);
  });

  it("blanks out the secret the operator just typed, whatever the server said", () => {
    const typed = bindValue();
    const message = directoryErrorMessage(
      failure(400, "validation_error", `an echo of ${typed} in a message`),
      typed,
    );
    expect(message).not.toContain(typed);
    expect(message).toContain("[redacted]");
  });

  it("sends anything else through the ordinary path", () => {
    expect(directoryErrorMessage({ response: { status: 503, data: { message: "unavailable" } } }, "")).toBe(
      "unavailable",
    );
    expect(directoryErrorMessage({}, "", "fallback text")).toBe("fallback text");
  });
});
