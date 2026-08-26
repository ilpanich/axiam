import { beforeEach, describe, expect, it } from "vitest";

import {
  ACTIVE_TENANT_HEADER,
  getActiveTenant,
  setActiveTenant,
} from "@/lib/activeTenant";

describe("activeTenant", () => {
  beforeEach(() => setActiveTenant(null));

  it("starts unset, so an ordinary principal sends no header at all", () => {
    // The property that keeps every existing request byte-identical: a tenant
    // principal never switches, so the header is never present.
    expect(getActiveTenant()).toBeNull();
  });

  it("remembers the selected tenant", () => {
    setActiveTenant("tenant-a");
    expect(getActiveTenant()).toBe("tenant-a");
  });

  it("clears back to the caller's own tenant", () => {
    setActiveTenant("tenant-a");
    setActiveTenant(null);
    expect(getActiveTenant()).toBeNull();
  });

  it("names the header the server reads", () => {
    // Spelled here and in `extractors::auth::ACTIVE_TENANT_HEADER`; a mismatch
    // is a silently ignored header rather than an error, which is exactly the
    // failure worth pinning.
    expect(ACTIVE_TENANT_HEADER).toBe("X-Axiam-Tenant");
  });
});
