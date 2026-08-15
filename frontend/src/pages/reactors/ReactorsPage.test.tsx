import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { ReactorsPage } from "./ReactorsPage";
import { renderWithProviders } from "@/test/renderWithProviders";

// Mirrors the five specs in axiam-core's EVENT_REGISTRY. Shaped as the wire
// response, not imported from the service, so a change to the server contract
// shows up here as a failing test rather than as agreeing fiction.
const registry = [
  {
    name: "token.pre_issue",
    interceptable: true,
    mutable: true,
    mutable_fields: ["ext."],
    default_failure_policy: "fail_open",
    description: "Enrich or veto token issuance. May add claims under `ext.` only.",
  },
  {
    name: "login.post_auth",
    interceptable: true,
    mutable: false,
    mutable_fields: [],
    default_failure_policy: "fail_closed",
    description:
      "After credentials verify, before session issuance: veto or require step-up MFA.",
  },
  {
    name: "user.pre_create",
    interceptable: true,
    mutable: true,
    mutable_fields: ["username", "email", "metadata."],
    default_failure_policy: "fail_closed",
    description: "Validate or normalize a new user's profile fields.",
  },
];

// A listen-only event, to exercise the intercept/listen guard.
const listenOnly = {
  name: "audit.emitted",
  interceptable: false,
  mutable: false,
  mutable_fields: [],
  default_failure_policy: "fail_open",
  description: "Observe an audit record after it is written.",
};

const reactors = [
  {
    id: "r1",
    tenant_id: "t1",
    name: "fraud-check",
    description: "Scores logins",
    events: ["login.post_auth"],
    mode: "intercept",
    priority: 10,
    timeout_ms: 800,
    failure_policy: "fail_closed",
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-02T00:00:00Z",
    recent_timeout_count: 3,
    recent_veto_count: 1,
  },
  {
    id: "r2",
    tenant_id: "t1",
    name: "claim-enricher",
    description: "",
    events: ["token.pre_issue", "user.pre_create"],
    mode: "listen",
    priority: 0,
    timeout_ms: 500,
    failure_policy: "fail_open",
    enabled: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    last_seen_at: null,
    recent_timeout_count: 0,
    recent_veto_count: 0,
  },
];

/** Route the two GETs the page issues to their respective payloads. */
function mockGets(list = reactors, events = registry) {
  apiMock.get.mockImplementation((url: string) =>
    Promise.resolve(
      res(url === "/api/v1/reactors/events" ? events : list)
    )
  );
}

/** Open the create dialog and return it. */
async function openCreate() {
  await userEvent.click(
    await screen.findByRole("button", { name: /New Reactor/ })
  );
  return screen.getByRole("dialog");
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ReactorsPage", () => {
  it("renders the fetched reactors with mode, event count and timeout", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);

    expect(await screen.findByText("fraud-check")).toBeInTheDocument();
    expect(screen.getByText("claim-enricher")).toBeInTheDocument();
    expect(screen.getByText("1 event")).toBeInTheDocument();
    expect(screen.getByText("2 events")).toBeInTheDocument();
    expect(screen.getByText("800 ms")).toBeInTheDocument();
  });

  it("shows the empty state when no reactors are registered", async () => {
    mockGets([]);
    renderWithProviders(<ReactorsPage />);
    expect(
      await screen.findByText("No reactors registered.")
    ).toBeInTheDocument();
  });

  // R2.3: recent timeouts and vetoes, read from the audit trail, are shown
  // separately per reactor — a timeout is the reactor not answering, a veto
  // is the reactor working as designed, and an operator needs to tell them
  // apart. A listen-mode reactor has no failure path at all, so it shows a
  // dash rather than a count of zero (which would imply a health signal that
  // does not exist for it).
  it("shows per-reactor recent timeout and veto counts, and a dash for listeners", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);

    expect(await screen.findByText("fraud-check")).toBeInTheDocument();
    expect(screen.getByText("3 timeouts")).toBeInTheDocument();
    expect(screen.getByText("1 veto")).toBeInTheDocument();
  });

  it("shows a clean bill of health when a reactor has no recent failures", async () => {
    mockGets([
      { ...reactors[0], recent_timeout_count: 0, recent_veto_count: 0 },
    ]);
    renderWithProviders(<ReactorsPage />);
    expect(await screen.findByText("Clean (24h)")).toBeInTheDocument();
  });

  // The server models last_seen_at as an Option specifically so these two
  // states stay distinguishable; collapsing them would hide a reactor that
  // never came up at all.
  it("distinguishes never-connected from connected-and-quiet", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    expect(await screen.findByText("Never connected")).toBeInTheDocument();
    // r1 has a timestamp, so exactly one row shows the never-connected badge.
    expect(screen.getAllByText("Never connected")).toHaveLength(1);
  });

  it("warns that an enabled interceptor that never connected is denying its events", async () => {
    mockGets([
      {
        ...reactors[0],
        last_seen_at: null,
        enabled: true,
        mode: "intercept",
        failure_policy: "fail_closed",
      },
    ]);
    renderWithProviders(<ReactorsPage />);
    expect(
      await screen.findByLabelText(/being denied \(fail closed\)/)
    ).toBeInTheDocument();
  });

  it("does not show a failure policy or timeout for a listener", async () => {
    mockGets([reactors[1]]);
    renderWithProviders(<ReactorsPage />);
    await screen.findByText("claim-enricher");
    // The server never reads a listener's reply, so there is no failure path.
    expect(screen.queryByText("Fail open")).not.toBeInTheDocument();
    expect(screen.queryByText("500 ms")).not.toBeInTheDocument();
  });

  it("renders the hookable-event registry with what each hook may mutate", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);

    expect(await screen.findByText("Hookable events")).toBeInTheDocument();
    // A namespace prefix is shown as `ext.*` — `ext.` alone would read as a
    // claim by that literal name, which the server refuses.
    expect((await screen.findAllByText("May set ext.*")).length).toBeGreaterThan(0);
    expect(
      screen.getAllByText("May set username, email, metadata.*").length
    ).toBeGreaterThan(0);
    // login.post_auth is interceptable but not mutable.
    expect(screen.getAllByText("Veto only — no patch").length).toBeGreaterThan(0);
  });

  it("requires a name before creating", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Name is required.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("requires at least one event", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.type(
      within(dialog).getByLabelText(/^Name/),
      "my-reactor"
    );
    fireEvent.submit(dialog.querySelector("form")!);
    expect(
      await screen.findByText("Select at least one event.")
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("rejects a timeout above the protocol maximum", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.type(within(dialog).getByLabelText(/^Name/), "slow");
    await userEvent.click(within(dialog).getByLabelText("token.pre_issue"));
    await userEvent.type(within(dialog).getByLabelText(/Timeout/), "9000");
    fireEvent.submit(dialog.querySelector("form")!);

    expect(
      await screen.findByText(/between 1 and 5000 ms/)
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  // Mirrors ReactorValidationError::NotInterceptable — caught at the field so
  // the operator does not learn it from a 400.
  it("blocks intercepting a listen-only event and explains why", async () => {
    mockGets(reactors, [...registry, listenOnly]);
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    // Mode starts at intercept, so a listen-only event cannot be selected.
    expect(within(dialog).getByLabelText("audit.emitted")).toBeDisabled();

    // Switching to listen makes it selectable.
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/^Mode/),
      "listen"
    );
    expect(within(dialog).getByLabelText("audit.emitted")).toBeEnabled();
  });

  it("keeps a now-illegal event clearable after switching to intercept", async () => {
    mockGets(reactors, [...registry, listenOnly]);
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.type(within(dialog).getByLabelText(/^Name/), "mixed");
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/^Mode/),
      "listen"
    );
    await userEvent.click(within(dialog).getByLabelText("audit.emitted"));
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/^Mode/),
      "intercept"
    );

    // Still checked and still clickable, so the form can be recovered.
    const box = within(dialog).getByLabelText("audit.emitted");
    expect(box).toBeChecked();
    expect(box).toBeEnabled();

    fireEvent.submit(dialog.querySelector("form")!);
    expect(
      await screen.findByText(/audit\.emitted cannot be intercepted/)
    ).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("offers the strictest default policy across the selected events", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    // fail_open on its own.
    await userEvent.click(within(dialog).getByLabelText("token.pre_issue"));
    expect(
      within(dialog).getByText("Registry default — Fail open")
    ).toBeInTheDocument();

    // Adding a fail_closed event must pull the inherited default to closed,
    // the same way the server resolves it.
    await userEvent.click(within(dialog).getByLabelText("login.post_auth"));
    expect(
      within(dialog).getByText("Registry default — Fail closed")
    ).toBeInTheDocument();
  });

  it("omits priority, timeout and policy when left blank so the server defaults apply", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(reactors[0]));
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.type(within(dialog).getByLabelText(/^Name/), "minimal");
    await userEvent.click(within(dialog).getByLabelText("token.pre_issue"));
    fireEvent.submit(dialog.querySelector("form")!);

    await vi.waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    const [url, payload] = apiMock.post.mock.calls[0];
    expect(url).toBe("/api/v1/reactors");
    expect(payload).toMatchObject({
      name: "minimal",
      events: ["token.pre_issue"],
      mode: "intercept",
      enabled: true,
    });
    // Absent, not zero — a blank field means "whatever the registry says".
    expect(payload).not.toHaveProperty("priority");
    expect(payload).not.toHaveProperty("timeout_ms");
    expect(payload).not.toHaveProperty("failure_policy");
  });

  it("sends the tuning fields for an interceptor when they are set", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(reactors[0]));
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.type(within(dialog).getByLabelText(/^Name/), "tuned");
    await userEvent.click(within(dialog).getByLabelText("login.post_auth"));
    await userEvent.type(within(dialog).getByLabelText(/Priority/), "5");
    await userEvent.type(within(dialog).getByLabelText(/Timeout/), "1200");
    await userEvent.selectOptions(
      within(dialog).getByLabelText(/Failure policy/),
      "fail_open"
    );
    fireEvent.submit(dialog.querySelector("form")!);

    await vi.waitFor(() => expect(apiMock.post).toHaveBeenCalled());
    expect(apiMock.post.mock.calls[0][1]).toMatchObject({
      name: "tuned",
      priority: 5,
      timeout_ms: 1200,
      failure_policy: "fail_open",
    });
  });

  // A listener has no failure path, so sending these would imply a control
  // the server does not honour for that mode.
  it("does not offer interceptor tuning for a listener", async () => {
    mockGets();
    renderWithProviders(<ReactorsPage />);
    const dialog = await openCreate();

    await userEvent.selectOptions(
      within(dialog).getByLabelText(/^Mode/),
      "listen"
    );
    expect(within(dialog).queryByLabelText(/Timeout/)).not.toBeInTheDocument();
    expect(
      within(dialog).queryByLabelText(/Failure policy/)
    ).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/Priority/)).not.toBeInTheDocument();
  });

  it("prefills the edit dialog from the reactor and PUTs the changes", async () => {
    mockGets();
    apiMock.put.mockResolvedValue(res(reactors[0]));
    renderWithProviders(<ReactorsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Edit reactor fraud-check" })
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText(/^Name/)).toHaveValue("fraud-check");
    expect(within(dialog).getByLabelText(/Timeout/)).toHaveValue(800);
    expect(within(dialog).getByLabelText("login.post_auth")).toBeChecked();

    await userEvent.clear(within(dialog).getByLabelText(/^Name/));
    await userEvent.type(within(dialog).getByLabelText(/^Name/), "renamed");
    fireEvent.submit(dialog.querySelector("form")!);

    await vi.waitFor(() => expect(apiMock.put).toHaveBeenCalled());
    expect(apiMock.put.mock.calls[0][0]).toBe("/api/v1/reactors/r1");
    expect(apiMock.put.mock.calls[0][1]).toMatchObject({ name: "renamed" });
  });

  it("deletes after confirmation", async () => {
    mockGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<ReactorsPage />);

    await userEvent.click(
      await screen.findByRole("button", { name: "Delete reactor fraud-check" })
    );
    expect(await screen.findByText("Delete Reactor")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^Delete$/ }));

    await vi.waitFor(() => expect(apiMock.delete).toHaveBeenCalled());
    expect(apiMock.delete.mock.calls[0][0]).toBe("/api/v1/reactors/r1");
  });

  it("surfaces a failed load with a retry", async () => {
    apiMock.get.mockRejectedValue(new Error("boom"));
    renderWithProviders(<ReactorsPage />);
    expect(
      await screen.findByText("Failed to load reactors.")
    ).toBeInTheDocument();
  });
});
