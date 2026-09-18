import { describe, it, expect } from "vitest";

import {
  DEFAULT_CIMD_POLICY,
  validateCimdPolicy,
  type CimdPolicy,
  type CimdPolicyViolation,
} from "./settings";

/**
 * T21.5 — `validateCimdPolicy` against `validate_cimd_policy`.
 *
 * One row per violation the server collects, and every expected string is the
 * server's own literal from `crates/axiam-core/src/models/settings.rs` with its
 * line continuations resolved. That is the whole point of the mirror: an
 * operator who meets the refusal in the form and an operator who meets it in a
 * `400` body must read the same sentence. If this file ever has to be edited to
 * make a test pass, the form has started answering for the server rather than
 * quoting it.
 */

/** Enabled, and otherwise valid — the baseline each case perturbs. */
function validPolicy(patch: Partial<CimdPolicy> = {}): {
  external_client_allowed_resources: string[];
  cimd: CimdPolicy;
} {
  return {
    external_client_allowed_resources: ["https://mcp.example.com/mcp"],
    cimd: {
      ...DEFAULT_CIMD_POLICY,
      enabled: true,
      trusted_client_id_domains: ["mcp.example.com"],
      ...patch,
    },
  };
}

const messages = (v: CimdPolicyViolation[]) => v.map((x) => x.message);

describe("validateCimdPolicy — the two interlocks", () => {
  it("D3 — refuses enabling while external_client_allowed_resources is empty", () => {
    const v = validateCimdPolicy({
      ...validPolicy(),
      external_client_allowed_resources: [],
    });
    expect(v).toContainEqual({
      field: "enabled",
      message:
        "cimd.enabled: client ID metadata documents cannot be enabled while " +
        "external_client_allowed_resources is empty (D3). A client materialised from a " +
        "stranger's document inherits that list as its allowed_resources, and an empty " +
        "list leaves it able to obtain only the axiam:user tokens AXIAM's own APIs " +
        "accept. Name the MCP servers this tenant fronts first",
    });
  });

  it("refuses enabling with no trusted publisher domain", () => {
    const v = validateCimdPolicy(validPolicy({ trusted_client_id_domains: [] }));
    expect(v).toContainEqual({
      field: "trusted_client_id_domains",
      message:
        "cimd.trusted_client_id_domains: client ID metadata documents cannot be enabled " +
        "with no trusted publisher domain. The document is fetched because an " +
        "unauthenticated request named its URL, so an unrestricted list is an outbound " +
        "fetch a stranger chooses the target of. Name the hosts whose documents this " +
        "tenant accepts (globs are allowed: *.example.com)",
    });
  });
});

describe("validateCimdPolicy — the wildcard refusal (MCP-03, #469)", () => {
  const wildcard = (entry: string, offence: string) =>
    `cimd.trusted_client_id_domains: "${entry}" ${offence}, which is the posture an ` +
    "empty list is refused for. The document is fetched because an " +
    "unauthenticated request named its URL, so the list has to name a publisher: " +
    "a host (mcp.example.com) or a wildcard over one (*.example.com)";

  it("refuses `*` in trusted_client_id_domains", () => {
    const v = validateCimdPolicy(
      validPolicy({ trusted_client_id_domains: ["*"] })
    );
    expect(messages(v)).toContain(wildcard("*", "matches every host"));
  });

  it("refuses a wildcard over a whole top-level domain", () => {
    const v = validateCimdPolicy(
      validPolicy({ trusted_client_id_domains: ["*.com"] })
    );
    expect(messages(v)).toContain(
      wildcard("*.com", "is a wildcard over a whole top-level domain")
    );
  });

  // A floor, not a public-suffix check: trusting shared hosting stays the
  // operator's decision, bounded by the per-tenant quota rather than by this.
  it("admits a wildcard over shared hosting", () => {
    expect(
      validateCimdPolicy(
        validPolicy({ trusted_client_id_domains: ["*.github.io"] })
      )
    ).toEqual([]);
  });

  it("admits `*` in trusted_redirect_domains, whose entries are not fetch targets", () => {
    expect(
      validateCimdPolicy(validPolicy({ trusted_redirect_domains: ["*"] }))
    ).toEqual([]);
  });
});

describe("validateCimdPolicy — entry shape", () => {
  it("refuses a URL in trusted_client_id_domains, with that field's advice", () => {
    const v = validateCimdPolicy(
      validPolicy({ trusted_client_id_domains: ["https://mcp.example.com"] })
    );
    expect(messages(v)).toContain(
      'cimd.trusted_client_id_domains: "https://mcp.example.com" is not a host pattern. ' +
        "Write a host (mcp.example.com) or a leftmost-label wildcard over one " +
        "(*.example.com) — not a URL, a path or a host:port"
    );
  });

  it("refuses a host:port in trusted_redirect_domains, with that field's advice", () => {
    const v = validateCimdPolicy(
      validPolicy({ trusted_redirect_domains: ["app.example.com:8443"] })
    );
    expect(messages(v)).toContain(
      'cimd.trusted_redirect_domains: "app.example.com:8443" is not a host pattern. ' +
        "Write a host (app.example.com), a leftmost-label wildcard (*.example.com) or * " +
        "— not a URL, a path or a host:port"
    );
  });

  it("refuses an entry carrying whitespace", () => {
    const v = validateCimdPolicy(
      validPolicy({ trusted_redirect_domains: ["a.example.com b.example.com"] })
    );
    expect(v).toHaveLength(1);
    expect(v[0].field).toBe("trusted_redirect_domains");
  });
});

describe("validateCimdPolicy — the three bounds", () => {
  it("refuses a cache floor below the deployment floor", () => {
    const v = validateCimdPolicy(validPolicy({ min_cache_secs: 30 }));
    expect(messages(v)).toContain(
      "cimd.min_cache_secs (30) must be >= 60: the cache " +
        "lifetime is what stands between one authorization request and one outbound " +
        "fetch"
    );
  });

  it("refuses a cache ceiling above the deployment ceiling", () => {
    const v = validateCimdPolicy(validPolicy({ max_cache_secs: 604_801 }));
    expect(messages(v)).toContain(
      "cimd.max_cache_secs (604801) must be <= 604800: a cached " +
        "document is a live client registration nobody here created"
    );
  });

  it("refuses a floor above its own ceiling", () => {
    const v = validateCimdPolicy(
      validPolicy({ min_cache_secs: 4_000, max_cache_secs: 3_000 })
    );
    expect(messages(v)).toContain(
      "cimd.min_cache_secs (4000) must be <= cimd.max_cache_secs (3000)"
    );
  });

  it("refuses a zero read cap", () => {
    const v = validateCimdPolicy(validPolicy({ max_metadata_bytes: 0 }));
    expect(messages(v)).toContain(
      "cimd.max_metadata_bytes (0) must be between 1 and " +
        "65536: an unbounded read of an attacker-chosen URL " +
        "is a memory-exhaustion primitive"
    );
  });

  it("refuses a read cap above the deployment ceiling", () => {
    const v = validateCimdPolicy(validPolicy({ max_metadata_bytes: 65_537 }));
    expect(messages(v)).toContain(
      "cimd.max_metadata_bytes (65537) must be between 1 and " +
        "65536: an unbounded read of an attacker-chosen URL " +
        "is a memory-exhaustion primitive"
    );
  });
});

describe("validateCimdPolicy — the disabled posture", () => {
  // The server returns early while `enabled` is false, so a tenant may stage a
  // posture it has not turned on. Refusing here would refuse a save the server
  // accepts, which is the one direction a mirror must never fail in.
  it("checks nothing at all while disabled, however broken the rest is", () => {
    expect(
      validateCimdPolicy({
        external_client_allowed_resources: [],
        cimd: {
          ...DEFAULT_CIMD_POLICY,
          enabled: false,
          trusted_client_id_domains: ["*"],
          min_cache_secs: 1,
          max_metadata_bytes: 0,
        },
      })
    ).toEqual([]);
  });

  it("accepts the shipped default posture once it is turned on properly", () => {
    expect(validateCimdPolicy(validPolicy())).toEqual([]);
  });
});
