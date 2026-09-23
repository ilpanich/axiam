import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  certificateService,
  subjectAltNamesFromRows,
} from "@/services/certificates";

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── S-7b — the SAN list is checked for shape, and only for shape ─────────────

describe("subjectAltNamesFromRows", () => {
  it("maps each row to the server's externally tagged SubjectAltName, in order", () => {
    expect(
      subjectAltNamesFromRows([
        { kind: "dns", value: "api.lakeside.internal" },
        { kind: "ip", value: "10.0.0.5" },
        { kind: "dns", value: "*.lakeside.internal" },
      ])
    ).toEqual({
      names: [
        { dns: "api.lakeside.internal" },
        { ip: "10.0.0.5" },
        { dns: "*.lakeside.internal" },
      ],
    });
  });

  it("trims surrounding whitespace, as the subject is trimmed", () => {
    expect(
      subjectAltNamesFromRows([{ kind: "dns", value: "  api.lakeside.internal \t" }])
    ).toEqual({ names: [{ dns: "api.lakeside.internal" }] });
  });

  it("refuses an empty list: a Server certificate states at least one name", () => {
    const out = subjectAltNamesFromRows([]);
    expect(out).toEqual({ error: expect.stringMatching(/at least one subject alternative name/) });
  });

  it("refuses a blank row and names which one", () => {
    const out = subjectAltNamesFromRows([
      { kind: "dns", value: "api.lakeside.internal" },
      { kind: "ip", value: "   " },
    ]);
    expect(out).toEqual({ error: expect.stringMatching(/^Subject alternative name 2 is empty/) });
  });

  it("refuses a row whose kind is neither dns nor ip", () => {
    const out = subjectAltNamesFromRows([
      // A value the type forbids, as a stale or hand-edited form state could carry.
      { kind: "uri" as never, value: "https://x" },
    ]);
    expect(out).toEqual({ error: expect.stringMatching(/must be a DNS name or an IP address/) });
  });

  // The server is the one authority on names. Everything below is something it
  // refuses with a 400 naming the remedy; the form must pass it through as
  // typed rather than second-guess it, or the two matchers could disagree.
  it.each([
    ["a trailing dot", { kind: "dns", value: "api.lakeside.internal." }, { dns: "api.lakeside.internal." }],
    ["a Unicode U-label", { kind: "dns", value: "bücher.lakeside.internal" }, { dns: "bücher.lakeside.internal" }],
    ["a partial-label wildcard", { kind: "dns", value: "a*.lakeside.internal" }, { dns: "a*.lakeside.internal" }],
    ["an IPv4-mapped IPv6 address", { kind: "ip", value: "::ffff:10.0.0.5" }, { ip: "::ffff:10.0.0.5" }],
    ["upper case", { kind: "dns", value: "API.Lakeside.Internal" }, { dns: "API.Lakeside.Internal" }],
    ["an IP typed as a DNS name", { kind: "dns", value: "10.0.0.5" }, { dns: "10.0.0.5" }],
  ] as const)("does not judge %s — that is the server's to refuse", (_, row, expected) => {
    expect(subjectAltNamesFromRows([row])).toEqual({ names: [expected] });
  });
});

describe("certificateService — Server certificates", () => {
  it("posts subject_alt_names on generate exactly as given", async () => {
    apiMock.post.mockResolvedValue(res({ id: "c1", private_key_pem: "PK" }));
    await certificateService.generate({
      issuer_ca_id: "ca1",
      subject: "api.lakeside.internal",
      cert_type: "Server",
      key_algorithm: "Ed25519",
      validity_days: 90,
      subject_alt_names: [{ dns: "api.lakeside.internal" }, { ip: "10.0.0.5" }],
    });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/certificates", {
      issuer_ca_id: "ca1",
      subject: "api.lakeside.internal",
      cert_type: "Server",
      key_algorithm: "Ed25519",
      validity_days: 90,
      subject_alt_names: [{ dns: "api.lakeside.internal" }, { ip: "10.0.0.5" }],
    });
  });

  it("posts subject_alt_names on sign-csr exactly as given", async () => {
    apiMock.post.mockResolvedValue(res({ id: "c2" }));
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nreq\n-----END CERTIFICATE REQUEST-----";
    await certificateService.signCsr({
      issuer_ca_id: "ca1",
      csr_pem: csr,
      cert_type: "Server",
      validity_days: 90,
      subject_alt_names: [{ dns: "api.lakeside.internal" }],
    });
    expect(apiMock.post.mock.calls[0][0]).toBe("/api/v1/certificates/sign-csr");
    expect(apiMock.post.mock.calls[0][1]).toEqual({
      issuer_ca_id: "ca1",
      csr_pem: csr,
      cert_type: "Server",
      validity_days: 90,
      subject_alt_names: [{ dns: "api.lakeside.internal" }],
    });
  });

  it("I4 twin: a Device request carries no subject_alt_names key at all", async () => {
    apiMock.post.mockResolvedValue(res({ id: "c3", private_key_pem: "PK" }));
    await certificateService.generate({
      issuer_ca_id: "ca1",
      subject: "device-001",
      cert_type: "Device",
      key_algorithm: "Ed25519",
      validity_days: 90,
    });
    expect(apiMock.post.mock.calls[0][1]).not.toHaveProperty("subject_alt_names");
  });
});
