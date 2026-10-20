import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { NetworkAccessPage } from "./NetworkAccessPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import type {
  NetworkPolicy,
  NetworkReplyProfile,
  NetworkSegment,
} from "@/services/network";

const SEGMENTS = "/api/v1/network/segments";
const PROFILES = "/api/v1/network/profiles";
const POLICY = "/api/v1/network/policy";

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  org_id: "org1",
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

function as(...permissions: string[]) {
  useAuthStore.setState({ user: { ...adminUser, permissions } });
}

function segment(overrides: Partial<NetworkSegment> = {}): NetworkSegment {
  return {
    id: "seg-corp",
    tenant_id: "t1",
    path: "/network/zones/hq/corp",
    name: "corp",
    site_key: "hq",
    kind: "access",
    vlan_id: 10,
    filter_ids: ["corp-in", "corp-out"],
    rank: 15,
    enabled: true,
    version: 3,
    created_by: "u1",
    updated_by: "u1",
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-02T00:00:00Z",
    ...overrides,
  };
}

const corp = segment();
const iot = segment({
  id: "seg-iot",
  path: "/network/zones/hq/iot",
  name: "iot",
  vlan_id: 20,
  filter_ids: [],
  rank: 20,
  version: 1,
});
const lab = segment({
  id: "seg-lab",
  path: "/network/zones/branch/lab",
  name: "lab",
  site_key: "branch",
  vlan_id: 30,
  filter_ids: [],
  rank: 5,
  enabled: false,
});
const quarantine = segment({
  id: "seg-q",
  path: "/network/quarantine/hq/q",
  name: "q",
  kind: "quarantine",
  vlan_id: 999,
  filter_ids: [],
  rank: null,
  version: 7,
});
const SEGMENT_ROWS = [iot, corp, lab, quarantine];

const policy: NetworkPolicy = {
  tenant_id: "t1",
  session_timeout_max_secs: 3600,
  version: 0,
  updated_by: null,
  updated_at: null,
};

function profile(overrides: Partial<NetworkReplyProfile> = {}): NetworkReplyProfile {
  return {
    segment_id: "seg-corp",
    tenant_id: "t1",
    dictionary: "axiam-radius-reply/1",
    session_timeout_secs: 1800,
    session_timeout_clamped: false,
    termination_action: "radius_request",
    idle_timeout_secs: 600,
    filter_id: "corp-in",
    service_type: "framed_user",
    version: 4,
    created_by: "u1",
    updated_by: "u1",
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-02T00:00:00Z",
    ...overrides,
  };
}

function page<T>(items: T[]) {
  return res({ items, total: items.length, offset: 0, limit: 200 });
}

function rejection(status: number, data: Record<string, unknown>) {
  return Promise.reject({ response: { status, data } });
}

interface Mocks {
  segments?: NetworkSegment[];
  policy?: NetworkPolicy;
  /** The profile by segment id; a segment not listed has none (404). */
  profiles?: Record<string, NetworkReplyProfile>;
}

function mockGets({ segments = SEGMENT_ROWS, policy: pol = policy, profiles = {} }: Mocks = {}) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === SEGMENTS) return Promise.resolve(page(segments));
    if (url === POLICY) return Promise.resolve(res(pol));
    if (url.startsWith(`${PROFILES}/`)) {
      const found = profiles[url.slice(PROFILES.length + 1)];
      return found
        ? Promise.resolve(res(found))
        : rejection(404, { error: "not_found", message: "reply profile not found" });
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

function rowOf(name: string): HTMLElement {
  const row = screen.getByText(name, { selector: "span" }).closest("tr");
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    user: adminUser,
    tenantSlug: "acme",
    orgSlug: "acme-org",
    isAuthenticated: true,
    isInitializing: false,
  });
});

describe("NetworkAccessPage — list", () => {
  it("groups segments by kind and site, with VLAN, rank, filter ids and version", async () => {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    expect(await screen.findByText("corp")).toBeInTheDocument();

    const zones = screen.getByRole("region", { name: "Access zones" });
    const quarantineSection = screen.getByRole("region", { name: "Quarantine" });
    expect(within(zones).getByTestId("site-access-hq")).toHaveTextContent("Site hq");
    expect(within(zones).getByTestId("site-access-branch")).toHaveTextContent("Site branch");
    expect(within(quarantineSection).getByTestId("site-quarantine-hq")).toBeInTheDocument();

    // Sites sort by name, and a site's segments by rank.
    const sites = within(zones).getAllByRole("heading", { level: 4 });
    expect(sites.map((h) => h.getAttribute("data-testid"))).toEqual([
      "site-access-branch",
      "site-access-hq",
    ]);
    const hqRows = within(zones)
      .getAllByRole("row")
      .map((r) => r.textContent ?? "")
      .filter((t) => t.includes("/network/zones/hq/"));
    expect(hqRows[0]).toContain("corp");
    expect(hqRows[1]).toContain("iot");

    const corpRow = within(rowOf("corp"));
    expect(corpRow.getByText("/network/zones/hq/corp")).toBeInTheDocument();
    expect(corpRow.getByText("10")).toBeInTheDocument(); // VLAN
    expect(corpRow.getByText("15")).toBeInTheDocument(); // rank
    expect(corpRow.getByText("corp-in, corp-out")).toBeInTheDocument();
    expect(corpRow.getByText("3")).toBeInTheDocument();

    const qRow = within(rowOf("q"));
    expect(qRow.getByText("999")).toBeInTheDocument();
    expect(qRow.getByText("7")).toBeInTheDocument();
    // A disabled segment says so.
    expect(within(rowOf("lab")).getByText("Inactive")).toBeInTheDocument();
  });

  it("shows the empty state, and never asks for a placement decision", async () => {
    mockGets({ segments: [] });
    renderWithProviders(<NetworkAccessPage />);
    expect(await screen.findByText("No network segments configured.")).toBeInTheDocument();
    const urls = [
      ...apiMock.get.mock.calls,
      ...apiMock.post.mock.calls,
      ...apiMock.put.mock.calls,
    ].map((c) => String(c[0]));
    expect(urls.some((u) => u.includes("/decide"))).toBe(false);
  });

  it("passes the search to the server on every page", async () => {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    await screen.findByText("corp");
    await userEvent.type(screen.getByRole("searchbox", { name: "Search segments" }), "iot");
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith(
        SEGMENTS,
        expect.objectContaining({ params: expect.objectContaining({ search: "iot" }) }),
      ),
    );
  });

  it("shows the server's message when the list cannot be read", async () => {
    apiMock.get.mockImplementation((url: string) =>
      url === POLICY
        ? Promise.resolve(res(policy))
        : rejection(403, {
            error: "authorization_denied",
            message: "Permission denied",
            action: "network:read",
            resource_id: "root-node",
          }),
    );
    renderWithProviders(<NetworkAccessPage />);
    expect(
      await screen.findByText(/Permission denied Missing permission network:read on root-node\./),
    ).toBeInTheDocument();
  });

  it("hides every write control from a reader but keeps the profile view", async () => {
    as("network:read");
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    expect(await screen.findByText("corp")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New segment/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Edit segment/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete segment/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reply profile of corp" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change the cap" })).not.toBeInTheDocument();
  });
});

describe("NetworkAccessPage — create segment", () => {
  async function openCreate() {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: /New segment/ }));
    return screen.getByRole("dialog");
  }

  it("needs a name, a VLAN and, for an access segment, a rank, before any request", async () => {
    const dialog = await openCreate();
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();

    await userEvent.type(within(dialog).getByLabelText("Name *"), "guest");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("VLAN must be a whole number.")).toBeInTheDocument();

    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "40");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(
      await screen.findByText("An access segment needs a rank (a whole number)."),
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("creates an access segment with the exact closed body", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(segment({ id: "seg-new" })));
    await userEvent.clear(within(dialog).getByLabelText("Site *"));
    await userEvent.type(within(dialog).getByLabelText("Site *"), "hq");
    await userEvent.type(within(dialog).getByLabelText("Name *"), "guest");
    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "40");
    await userEvent.type(within(dialog).getByLabelText("Rank *"), "30");
    await userEvent.type(within(dialog).getByLabelText("Filter-Id names"), "guest-in, guest-out");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(SEGMENTS, {
        kind: "access",
        site_key: "hq",
        name: "guest",
        vlan_id: 40,
        filter_ids: ["guest-in", "guest-out"],
        rank: 30,
        enabled: true,
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("creates a quarantine segment without a rank member", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(quarantine));
    await userEvent.selectOptions(within(dialog).getByLabelText("Kind *"), "quarantine");
    expect(within(dialog).queryByLabelText("Rank *")).not.toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText("Name *"), "q2");
    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "998");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    const body = apiMock.post.mock.calls[0][1] as Record<string, unknown>;
    expect(body).toEqual({
      kind: "quarantine",
      site_key: "default",
      name: "q2",
      vlan_id: 998,
      filter_ids: [],
      enabled: true,
    });
    expect("rank" in body).toBe(false);
  });

  it("shows the server's 400 verbatim", async () => {
    const dialog = await openCreate();
    apiMock.post.mockImplementation(() =>
      rejection(400, {
        error: "validation_error",
        message: "Validation error: vlan_id must be between 1 and 4094",
      }),
    );
    await userEvent.type(within(dialog).getByLabelText("Name *"), "bad");
    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "5000");
    await userEvent.type(within(dialog).getByLabelText("Rank *"), "1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await within(dialog).findByText("Validation error: vlan_id must be between 1 and 4094"),
    ).toBeInTheDocument();
  });

  it("names the permission and the node a 403 says was missing", async () => {
    const dialog = await openCreate();
    apiMock.post.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:segments_write",
        resource_id: "node-1234",
      }),
    );
    await userEvent.type(within(dialog).getByLabelText("Name *"), "guest");
    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "40");
    await userEvent.type(within(dialog).getByLabelText("Rank *"), "1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(
      await within(dialog).findByText(
        "Permission denied Missing permission network:segments_write on node-1234.",
      ),
    ).toBeInTheDocument();
  });
});

describe("NetworkAccessPage — edit segment", () => {
  async function openEdit(name = "corp") {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: `Edit segment ${name}` }));
    return screen.getByRole("dialog");
  }

  it("fixes kind, site and name, and replaces with the version it was opened from", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(corp));
    expect(within(dialog).getByLabelText("Kind *")).toBeDisabled();
    expect(within(dialog).getByLabelText("Site *")).toBeDisabled();
    expect(within(dialog).getByLabelText("Name *")).toBeDisabled();
    expect(within(dialog).getByLabelText("VLAN *")).toHaveValue("10");

    await userEvent.clear(within(dialog).getByLabelText("VLAN *"));
    await userEvent.type(within(dialog).getByLabelText("VLAN *"), "11");
    await userEvent.click(within(dialog).getByLabelText("Enabled"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(`${SEGMENTS}/seg-corp`, {
        version: 3,
        vlan_id: 11,
        filter_ids: ["corp-in", "corp-out"],
        rank: 15,
        enabled: false,
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("says another administrator wrote first on a stale version, and reloads the list", async () => {
    const dialog = await openEdit();
    apiMock.put.mockImplementation(() =>
      rejection(409, { error: "conflict", reason_code: "stale_version", message: "version mismatch" }),
    );
    const readsBefore = apiMock.get.mock.calls.filter((c) => c[0] === SEGMENTS).length;
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await within(dialog).findByText(/Changed by someone else — reload and try again\./),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(apiMock.get.mock.calls.filter((c) => c[0] === SEGMENTS).length).toBeGreaterThan(
        readsBefore,
      ),
    );
  });

  it("shows the stranding 409 naming the profile and its filter id", async () => {
    const dialog = await openEdit();
    apiMock.put.mockImplementation(() =>
      rejection(409, {
        error: "conflict",
        reason_code: "strands_profile",
        message:
          "the segment's reply profile seg-corp uses filter_id 'corp-in', which the new filter_ids remove; change or delete the profile first",
      }),
    );
    await userEvent.clear(within(dialog).getByLabelText("Filter-Id names"));
    await userEvent.type(within(dialog).getByLabelText("Filter-Id names"), "corp-out");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("reply profile seg-corp");
    expect(alert).toHaveTextContent("filter_id 'corp-in'");
    // Not someone else's write: the server's sentence alone (§36.4).
    expect(alert).not.toHaveTextContent("Changed by someone else");
  });

  it("resolves the node a 403 names to the segment's path", async () => {
    const dialog = await openEdit();
    apiMock.put.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:segments_write",
        resource_id: "seg-corp",
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    expect(
      await within(dialog).findByText(
        "Permission denied Missing permission network:segments_write on /network/zones/hq/corp.",
      ),
    ).toBeInTheDocument();
  });
});

describe("NetworkAccessPage — delete segment", () => {
  async function openDelete() {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete segment corp" }));
    return screen.getByRole("dialog");
  }

  it("deletes with the version in the query string", async () => {
    const dialog = await openDelete();
    apiMock.delete.mockResolvedValue(res(undefined));
    expect(dialog).toHaveTextContent("Its reply profile is deleted with it");
    // A profiled segment's delete also needs the placing right (2026-10-16).
    expect(dialog).toHaveTextContent("also needs network:grant on it");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(`${SEGMENTS}/seg-corp`, {
        params: { version: 3 },
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("keeps the dialog open with the server's refusal on a 409", async () => {
    const dialog = await openDelete();
    apiMock.delete.mockImplementation(() =>
      rejection(409, {
        error: "conflict",
        reason_code: "has_children",
        message: "the segment still has child resources",
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("the segment still has child resources");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("names the missing permission on a 403", async () => {
    const dialog = await openDelete();
    apiMock.delete.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:segments_write",
        resource_id: "seg-corp",
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Missing permission network:segments_write on /network/zones/hq/corp.",
    );
  });
});

describe("NetworkAccessPage — reply profile", () => {
  async function openProfile(name: string, mocks: Mocks = {}) {
    mockGets(mocks);
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: `Reply profile of ${name}` }));
    return screen.findByRole("dialog");
  }

  it("shows the stored profile, the effective Session-Timeout and the clamped flag", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    expect(within(dialog).getByTestId("profile-effective-timeout")).toHaveTextContent("1800 s");
    expect(within(dialog).getByTestId("profile-stored-timeout")).toHaveTextContent(
      "1800 s (the same: not clamped)",
    );
    expect(within(dialog).getByTestId("profile-clamped")).toHaveTextContent("No");
    expect(within(dialog).getByTestId("profile-segment-path")).toHaveTextContent(
      "/network/zones/hq/corp — VLAN 10",
    );
    expect(within(dialog).getByLabelText("Session-Timeout (seconds) *")).toHaveValue("1800");
    expect(within(dialog).getByLabelText("Idle-Timeout (seconds)")).toHaveValue("600");
    expect(within(dialog).getByLabelText("Filter-Id")).toHaveValue("corp-in");
    expect(within(dialog).getByLabelText("Service-Type")).toHaveValue("framed_user");
    expect(within(dialog).getByLabelText("Termination-Action")).toHaveValue("radius_request");
  });

  it("says when the Session-Timeout is clamped to the tenant cap", async () => {
    const clamped = profile({ session_timeout_secs: 3600, session_timeout_clamped: true });
    const dialog = await openProfile("corp", { profiles: { "seg-corp": clamped } });
    await within(dialog).findByTestId("profile-clamped");
    expect(within(dialog).getByTestId("profile-clamped")).toHaveTextContent("Yes");
    expect(within(dialog).getByTestId("profile-effective-timeout")).toHaveTextContent("3600 s");
    expect(within(dialog).getByTestId("profile-stored-timeout")).toHaveTextContent(
      "above the cap of 3600 s",
    );
    expect(within(dialog).getByRole("status")).toHaveTextContent(
      "Saving this form stores the effective value",
    );
  });

  it("offers only the dictionary's typed attributes, and only the segment's own filter ids", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByLabelText("Service-Type");
    const serviceTypes = within(within(dialog).getByLabelText("Service-Type")).getAllByRole("option");
    expect(serviceTypes.map((o) => o.getAttribute("value"))).toEqual(["", "framed_user"]);
    const actions = within(within(dialog).getByLabelText("Termination-Action")).getAllByRole(
      "option",
    );
    expect(actions.map((o) => o.getAttribute("value"))).toEqual(["radius_request", "default"]);
    const filters = within(within(dialog).getByLabelText("Filter-Id")).getAllByRole("option");
    expect(filters.map((o) => o.getAttribute("value"))).toEqual(["", "corp-in", "corp-out"]);
    // No VLAN member and no free-form attribute.
    expect(within(dialog).queryByLabelText(/vlan/i)).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/attribute/i)).not.toBeInTheDocument();
  });

  it("creates a profile for a segment without one, naming the segment's version", async () => {
    const dialog = await openProfile("corp");
    await within(dialog).findByText(/no reply profile/);
    apiMock.post.mockResolvedValue(res(profile()));
    // The new-profile default is the tenant cap.
    expect(within(dialog).getByLabelText("Session-Timeout (seconds) *")).toHaveValue("3600");
    await userEvent.clear(within(dialog).getByLabelText("Session-Timeout (seconds) *"));
    await userEvent.type(within(dialog).getByLabelText("Session-Timeout (seconds) *"), "900");
    await userEvent.selectOptions(within(dialog).getByLabelText("Filter-Id"), "corp-out");
    await userEvent.selectOptions(within(dialog).getByLabelText("Service-Type"), "framed_user");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create profile" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(PROFILES, {
        segment_id: "seg-corp",
        segment_version: 3,
        profile: {
          session_timeout_secs: 900,
          termination_action: "radius_request",
          filter_id: "corp-out",
          service_type: "framed_user",
        },
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("omits optional members it was not given instead of sending null", async () => {
    const dialog = await openProfile("iot");
    await within(dialog).findByText(/no reply profile/);
    apiMock.post.mockResolvedValue(res(profile({ segment_id: "seg-iot" })));
    await userEvent.click(within(dialog).getByRole("button", { name: "Create profile" }));
    await waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    const body = apiMock.post.mock.calls[0][1] as { profile: Record<string, unknown> };
    expect(body.profile).toEqual({ session_timeout_secs: 3600, termination_action: "radius_request" });
  });

  it("replaces with both the profile's and the segment's version", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    apiMock.put.mockResolvedValue(res(profile()));
    await userEvent.clear(within(dialog).getByLabelText("Idle-Timeout (seconds)"));
    await userEvent.selectOptions(within(dialog).getByLabelText("Termination-Action"), "default");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save profile" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(`${PROFILES}/seg-corp`, {
        version: 4,
        segment_version: 3,
        profile: {
          session_timeout_secs: 1800,
          termination_action: "default",
          filter_id: "corp-in",
          service_type: "framed_user",
        },
      }),
    );
  });

  it("checks the numbers are numbers before any request", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    await userEvent.clear(within(dialog).getByLabelText("Session-Timeout (seconds) *"));
    await userEvent.type(within(dialog).getByLabelText("Session-Timeout (seconds) *"), "1h");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(
      await within(dialog).findByText("Session-Timeout must be a whole number of seconds."),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("shows the server's 400 on a value outside the bounds", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    apiMock.put.mockImplementation(() =>
      rejection(400, {
        error: "validation_error",
        message: "Validation error: session_timeout_secs must be between 300 and 3600",
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save profile" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "session_timeout_secs must be between 300 and 3600",
    );
  });

  it("names the permission and the node on a 403 (the envelope, H3)", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    apiMock.put.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:grant",
        resource_id: "seg-corp",
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save profile" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Missing permission network:grant on /network/zones/hq/corp.",
    );
  });

  it("says another administrator wrote first on a stale profile or segment version", async () => {
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    apiMock.put.mockImplementation(() =>
      rejection(409, { error: "conflict", reason_code: "stale_version", message: "the segment changed" }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Save profile" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Changed by someone else — reload and try again.",
    );
  });

  it("deletes after a confirmation, with the profile's version", async () => {
    await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await screen.findByTestId("profile-effective-timeout");
    apiMock.delete.mockResolvedValue(res(undefined));
    await userEvent.click(screen.getByRole("button", { name: "Delete profile" }));
    const confirm = await screen.findByRole("dialog");
    expect(confirm).toHaveTextContent("no placement candidate");
    await userEvent.click(within(confirm).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(`${PROFILES}/seg-corp`, {
        params: { version: 4 },
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows a delete refusal inside the confirmation", async () => {
    await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await screen.findByTestId("profile-effective-timeout");
    apiMock.delete.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:profiles_write",
        resource_id: "seg-corp",
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Delete profile" }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Delete" }));
    expect(await within(confirm).findByRole("alert")).toHaveTextContent(
      "Missing permission network:profiles_write",
    );
  });

  it("hides the editor, create and replace alike, from a holder of network:profiles_write without network:grant", async () => {
    // Create and replace take the placing right too, as the delete does: a
    // profile on a segment is what makes it a placement candidate (#709).
    as("network:read", "network:profiles_write");
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    expect(within(dialog).queryByLabelText("Session-Timeout (seconds) *")).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /save|create profile/i })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Delete profile" })).not.toBeInTheDocument();
  });

  it("hides the create form on a segment without a profile when network:grant is missing", async () => {
    as("network:read", "network:profiles_write");
    const dialog = await openProfile("corp", { profiles: {} });
    await within(dialog).findByText(/has no reply profile/);
    expect(within(dialog).queryByRole("button", { name: /create profile/i })).not.toBeInTheDocument();
  });

  it("shows the editor to a holder of network:profiles_write and network:grant", async () => {
    as("network:read", "network:profiles_write", "network:grant");
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    expect(within(dialog).getByRole("button", { name: "Save profile" })).toBeInTheDocument();
  });

  it("offers Delete profile to a holder of network:profiles_write and network:grant", async () => {
    as("network:read", "network:profiles_write", "network:grant");
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    expect(within(dialog).getByRole("button", { name: "Delete profile" })).toBeInTheDocument();
  });

  it("names network:grant when the server refuses a profile delete for it", async () => {
    await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await screen.findByTestId("profile-effective-timeout");
    apiMock.delete.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:grant",
        resource_id: "seg-corp",
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Delete profile" }));
    const confirm = await screen.findByRole("dialog");
    await userEvent.click(within(confirm).getByRole("button", { name: "Delete" }));
    expect(await within(confirm).findByRole("alert")).toHaveTextContent(
      "Missing permission network:grant on /network/zones/hq/corp.",
    );
  });

  it("shows a reader the profile and offers no editor", async () => {
    as("network:read");
    const dialog = await openProfile("corp", { profiles: { "seg-corp": profile() } });
    await within(dialog).findByTestId("profile-effective-timeout");
    expect(within(dialog).queryByLabelText("Session-Timeout (seconds) *")).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /save|create profile/i })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Close" })).toBeInTheDocument();
    expect(within(dialog).getByText("corp-in")).toBeInTheDocument();
  });

  it("shows the server's message when the profile cannot be read", async () => {
    mockGets();
    apiMock.get.mockImplementation((url: string) => {
      if (url === SEGMENTS) return Promise.resolve(page(SEGMENT_ROWS));
      if (url === POLICY) return Promise.resolve(res(policy));
      return rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:read",
        resource_id: "seg-corp",
      });
    });
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Reply profile of corp" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Missing permission network:read on /network/zones/hq/corp.",
    );
  });
});

describe("NetworkAccessPage — Session-Timeout cap", () => {
  it("shows the cap, its version, and what lowering and raising do", async () => {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    expect(await screen.findByTestId("network-cap-value")).toHaveTextContent("3600 s");
    expect(screen.getByText(/this tenant has not written one/)).toBeInTheDocument();
    expect(screen.getByText(/never rewrites a profile/)).toBeInTheDocument();
    expect(screen.getByText(/is audited as a raise/)).toBeInTheDocument();
    expect(screen.getByText(/from 300 to 86400/)).toBeInTheDocument();
  });

  it("replaces the cap with the version it read", async () => {
    mockGets({
      policy: { ...policy, session_timeout_max_secs: 1800, version: 2, updated_at: "2026-10-05T00:00:00Z" },
    });
    apiMock.put.mockResolvedValue(
      res({ ...policy, session_timeout_max_secs: 7200, version: 3, updated_at: "2026-10-06T00:00:00Z" }),
    );
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    const input = screen.getByLabelText("Cap in seconds");
    expect(input).toHaveValue("1800");
    await userEvent.clear(input);
    await userEvent.type(input, "7200");
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(POLICY, {
        session_timeout_max_secs: 7200,
        version: 2,
      }),
    );
    expect(await screen.findByText("Saved: the cap is now 7200 s.")).toBeInTheDocument();
  });

  it("sends version 0 for a tenant that has never written one", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(res({ ...policy, session_timeout_max_secs: 600, version: 1 }));
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    await userEvent.clear(screen.getByLabelText("Cap in seconds"));
    await userEvent.type(screen.getByLabelText("Cap in seconds"), "600");
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    await waitFor(() =>
      expect(apiMock.put).toHaveBeenCalledWith(POLICY, { session_timeout_max_secs: 600, version: 0 }),
    );
  });

  it("refreshes the profile views after a write, because the cap clamps them", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(res({ ...policy, session_timeout_max_secs: 600, version: 1 }));
    const { client } = renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    const spy = vi.spyOn(client, "invalidateQueries");
    await userEvent.clear(screen.getByLabelText("Cap in seconds"));
    await userEvent.type(screen.getByLabelText("Cap in seconds"), "600");
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalled());
    await waitFor(() =>
      expect(spy.mock.calls.map((c) => (c[0] as { queryKey: string[] }).queryKey[0])).toEqual(
        expect.arrayContaining(["network-policy", "network-profile"]),
      ),
    );
  });

  it("checks the cap is a number before any request", async () => {
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    await userEvent.clear(screen.getByLabelText("Cap in seconds"));
    await userEvent.type(screen.getByLabelText("Cap in seconds"), "an hour");
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    expect(
      await screen.findByText("The cap must be a whole number of seconds."),
    ).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("shows the server's 403 with the permission and the root it was checked on", async () => {
    mockGets();
    apiMock.put.mockImplementation(() =>
      rejection(403, {
        error: "authorization_denied",
        message: "Permission denied",
        action: "network:segments_write",
        resource_id: "root-node",
      }),
    );
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Permission denied Missing permission network:segments_write on root-node.",
    );
    // The editor stays open: nothing was written.
    expect(screen.getByLabelText("Cap in seconds")).toBeInTheDocument();
  });

  it("shows the server's 400 for a cap outside 300 to 86400", async () => {
    mockGets();
    apiMock.put.mockImplementation(() =>
      rejection(400, {
        error: "validation_error",
        message: "Validation error: session_timeout_max_secs must be between 300 and 86400",
      }),
    );
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("must be between 300 and 86400");
  });

  it("says someone else wrote first on a 409, without the server's wording", async () => {
    mockGets();
    apiMock.put.mockImplementation(() =>
      rejection(409, { error: "conflict", reason_code: "stale_version", message: "stale policy version 0" }),
    );
    renderWithProviders(<NetworkAccessPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Change the cap" }));
    await userEvent.click(screen.getByRole("button", { name: "Save the cap" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /^Changed by someone else — reload and try again\.$/,
    );
  });

  it("offers the editor only to a holder of network:segments_write", async () => {
    as("network:read", "network:profiles_write");
    mockGets();
    renderWithProviders(<NetworkAccessPage />);
    expect(await screen.findByTestId("network-cap-value")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change the cap" })).not.toBeInTheDocument();
  });

  it("shows the server's message when the cap cannot be read", async () => {
    apiMock.get.mockImplementation((url: string) =>
      url === SEGMENTS
        ? Promise.resolve(page(SEGMENT_ROWS))
        : rejection(403, {
            error: "authorization_denied",
            message: "Permission denied",
            action: "network:read",
            resource_id: "root-node",
          }),
    );
    renderWithProviders(<NetworkAccessPage />);
    expect(
      await screen.findByText(/Permission denied Missing permission network:read on root-node\./, {
        selector: "p",
      }),
    ).toBeInTheDocument();
  });
});
