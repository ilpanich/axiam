import { describe, it, expect } from "vitest";
import {
  EMPTY_SEGMENT_FORM,
  createSegmentBody,
  describeSeconds,
  emptyProfileForm,
  parseFilterIds,
  parseWholeNumber,
  profileFormFrom,
  profileInputFrom,
  replaceSegmentBody,
  segmentFormFrom,
  segmentKindOf,
} from "./networkForm";
import type { NetworkReplyProfile, NetworkSegment } from "@/services/network";

const seg: NetworkSegment = {
  id: "s1",
  tenant_id: "t1",
  path: "/network/quarantine/hq/q",
  name: "q",
  site_key: "hq",
  kind: "quarantine",
  vlan_id: 999,
  filter_ids: ["a", "b"],
  rank: null,
  enabled: false,
  version: 2,
  created_by: "u",
  updated_by: "u",
  created_at: "",
  updated_at: "",
};

const prof: NetworkReplyProfile = {
  segment_id: "s1",
  tenant_id: "t1",
  dictionary: "axiam-radius-reply/1",
  session_timeout_secs: 900,
  session_timeout_clamped: false,
  termination_action: "default",
  idle_timeout_secs: null,
  filter_id: null,
  service_type: null,
  version: 1,
  created_by: "u",
  updated_by: "u",
  created_at: "",
  updated_at: "",
};

describe("parsing", () => {
  it("splits filter ids on commas and whitespace and drops empties", () => {
    expect(parseFilterIds(" a, b  c,\n,d ")).toEqual(["a", "b", "c", "d"]);
    expect(parseFilterIds("")).toEqual([]);
  });

  it("accepts digits only for a whole number", () => {
    expect(parseWholeNumber(" 42 ")).toBe(42);
    expect(parseWholeNumber("")).toBeNull();
    expect(parseWholeNumber("-1")).toBeNull();
    expect(parseWholeNumber("1.5")).toBeNull();
    expect(parseWholeNumber("1e3")).toBeNull();
    expect(parseWholeNumber("1234567890")).toBeNull();
  });

  it("reads an unknown kind as access, and describes seconds", () => {
    expect(segmentKindOf({ kind: "quarantine" })).toBe("quarantine");
    expect(segmentKindOf({ kind: "some-future-kind" })).toBe("access");
    expect(describeSeconds(45)).toBe("45 s");
    expect(describeSeconds(3600)).toBe("1 h");
    expect(describeSeconds(5430)).toBe("1 h 30 min 30 s");
    expect(describeSeconds(300)).toBe("5 min");
  });
});

describe("segment bodies", () => {
  it("builds a quarantine create without a rank, an access one with it", () => {
    const q = createSegmentBody({
      ...EMPTY_SEGMENT_FORM,
      kind: "quarantine",
      name: " q ",
      vlanId: "999",
      rank: "5",
    });
    expect(q).toEqual({
      ok: true,
      body: {
        kind: "quarantine",
        site_key: "default",
        name: "q",
        vlan_id: 999,
        filter_ids: [],
        enabled: true,
      },
    });
    const a = createSegmentBody({ ...EMPTY_SEGMENT_FORM, name: "n", vlanId: "10", rank: "3" });
    expect(a.ok && a.body.rank).toBe(3);
  });

  it("names what is missing", () => {
    expect(createSegmentBody(EMPTY_SEGMENT_FORM)).toEqual({ ok: false, error: "Name is required." });
    expect(createSegmentBody({ ...EMPTY_SEGMENT_FORM, name: "n", siteKey: " " })).toEqual({
      ok: false,
      error: "Site is required.",
    });
  });

  it("builds a replacement from a stored segment with the version it names", () => {
    const form = segmentFormFrom(seg);
    expect(form).toMatchObject({ kind: "quarantine", vlanId: "999", rank: "", filterIds: "a, b" });
    expect(replaceSegmentBody(form, 2)).toEqual({
      ok: true,
      body: { version: 2, vlan_id: 999, filter_ids: ["a", "b"], enabled: false },
    });
  });
});

describe("profile bodies", () => {
  it("starts a new profile at the cap", () => {
    expect(emptyProfileForm(1800)).toEqual({
      sessionTimeout: "1800",
      idleTimeout: "",
      filterId: "",
      serviceType: "",
      terminationAction: "radius_request",
    });
  });

  it("omits what is unset, and never sends null", () => {
    const form = profileFormFrom(prof);
    expect(form.terminationAction).toBe("default");
    expect(profileInputFrom(form)).toEqual({
      ok: true,
      body: { session_timeout_secs: 900, termination_action: "default" },
    });
  });

  it("does not re-send a value it decoded as unknown", () => {
    const form = profileFormFrom({
      ...prof,
      service_type: "administrative_user",
      termination_action: "something_new",
    });
    expect(form.serviceType).toBe("");
    expect(form.terminationAction).toBe("radius_request");
  });

  it("rejects timeouts that are not numbers", () => {
    expect(profileInputFrom({ ...emptyProfileForm(900), sessionTimeout: "x" }).ok).toBe(false);
    expect(profileInputFrom({ ...emptyProfileForm(900), idleTimeout: "x" })).toEqual({
      ok: false,
      error: "Idle-Timeout must be a whole number of seconds, or empty.",
    });
  });
});
