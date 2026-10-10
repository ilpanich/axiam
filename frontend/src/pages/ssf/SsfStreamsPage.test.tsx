import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { SsfStreamsPage } from "./SsfStreamsPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import { SSF_EVENT_TYPES, type SsfStream } from "@/services/ssf";

const STREAMS = "/api/v1/tenants/t1/ssf/streams";

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: "t1",
  org_id: "org1",
};

function as(...permissions: string[]) {
  useAuthStore.setState({ user: { ...adminUser, permissions } });
}

const [REVOKED, CREDENTIAL, , DISABLED] = SSF_EVENT_TYPES.map((e) => e.uri);

function stream(overrides: Partial<SsfStream> = {}): SsfStream {
  return {
    id: "st1",
    tenant_id: "t1",
    receiver_client_id: "siem-receiver",
    audience: "https://siem.example.com/",
    description: "Corporate SIEM",
    delivery_method: "push",
    endpoint_url: "https://siem.example.com/events",
    authorization_header_set: true,
    events_allowed: [REVOKED, CREDENTIAL, DISABLED],
    events_requested: [REVOKED, CREDENTIAL],
    events_delivered: [REVOKED, CREDENTIAL],
    subject_format: "iss_sub",
    status: "enabled",
    status_reason: null,
    status_actor: "admin",
    last_verification_at: null,
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    transmitter_active: true,
    ...overrides,
  };
}

const pollStream = stream({
  id: "st2",
  receiver_client_id: "poller",
  audience: "poller-audience",
  description: null,
  delivery_method: "poll",
  endpoint_url: null,
  authorization_header_set: false,
  status: "paused",
  status_reason: "incident 4711",
  status_actor: "admin",
  events_allowed: [REVOKED],
  events_requested: [REVOKED],
  events_delivered: [REVOKED],
});

function page<T>(items: T[]) {
  return res({ items, total: items.length, offset: 0, limit: 20 });
}

function mockGets(rows: SsfStream[] = [stream(), pollStream]) {
  apiMock.get.mockImplementation((url: string) => {
    if (url === STREAMS) return Promise.resolve(page(rows));
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

/** A header value made at run time: no literal secret in the test source. */
function headerValue() {
  return `Bearer h${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

function conflict(message: string) {
  return {
    response: {
      status: 409,
      data: { error: "conflict", message },
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({ user: adminUser, isAuthenticated: true, isInitializing: false });
});

describe("SsfStreamsPage — list", () => {
  it("lists receiver, audience, method, endpoint, status and who set it", async () => {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    expect(await screen.findByText("siem-receiver")).toBeInTheDocument();
    expect(screen.getByText("Corporate SIEM")).toBeInTheDocument();
    expect(screen.getByText("https://siem.example.com/")).toBeInTheDocument();
    expect(screen.getByText("Push (RFC 8935)")).toBeInTheDocument();
    expect(screen.getByText("https://siem.example.com/events")).toBeInTheDocument();
    expect(screen.getByText("Authorization header stored")).toBeInTheDocument();
    expect(screen.getByText("Poll (RFC 8936)")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
    expect(screen.getByText("paused")).toBeInTheDocument();
    expect(screen.getByText("Set by admin: incident 4711")).toBeInTheDocument();
  });

  it("shows events_delivered beside events_allowed", async () => {
    mockGets([stream()]);
    renderWithProviders(<SsfStreamsPage />);
    await screen.findByText("siem-receiver");
    const line = (label: string) =>
      screen.getByText(
        (_, el) => el?.tagName === "P" && el.textContent?.startsWith(`${label}:`) === true,
      );
    expect(line("Delivered")).toHaveTextContent(
      "Delivered: Session revoked, Credential change",
    );
    expect(line("Allowed")).toHaveTextContent(
      "Allowed: Session revoked, Credential change, Account disabled",
    );
    // Delivered is listed first, beside the ceiling it is a subset of.
    expect(
      line("Delivered").compareDocumentPosition(line("Allowed")) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("never renders the authorization header: not on a row, not in the edit dialog", async () => {
    const leaked = headerValue();
    // The server never returns it; a page that rendered unknown members would.
    mockGets([{ ...stream(), authorization_header: leaked } as SsfStream]);
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SSF stream siem-receiver" }),
    );
    const dialog = screen.getByRole("dialog");
    const field = within(dialog).getByLabelText(/^Authorization header/);
    expect(field).toHaveValue("");
    expect(field).toHaveAttribute("type", "password");
    expect(document.body.innerHTML).not.toContain(leaked);
  });

  it("says the transmitter is off when the tenant's ssf_enabled is", async () => {
    mockGets([
      stream({
        transmitter_active: false,
        transmitter_inactive_reason: "the tenant has ssf_enabled off",
      }),
    ]);
    renderWithProviders(<SsfStreamsPage />);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "the tenant has ssf_enabled off",
    );
    expect(screen.getByText("Carries nothing: transmitter off")).toBeInTheDocument();
  });

  it("shows the empty state", async () => {
    mockGets([]);
    renderWithProviders(<SsfStreamsPage />);
    expect(await screen.findByText("No SSF streams registered.")).toBeInTheDocument();
  });

  it("hides every write control from a reader", async () => {
    as("ssf_streams:read");
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    expect(await screen.findByText("siem-receiver")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New stream" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Edit SSF stream/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Delete SSF stream/ })).not.toBeInTheDocument();
  });
});

describe("SsfStreamsPage — edit", () => {
  async function openEdit(rows: SsfStream[] = [stream()]) {
    mockGets(rows);
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", {
        name: `Edit SSF stream ${rows[0].receiver_client_id}`,
      }),
    );
    return screen.getByRole("dialog");
  }

  it("keeps the stored header and the receiver's narrowing on a replacement that changes neither", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(stream()));
    await userEvent.type(within(dialog).getByLabelText("Status reason"), "maintenance");
    fireEvent.submit(dialog.querySelector("form")!);

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [url, body] = apiMock.put.mock.calls[0];
    expect(url).toBe(`${STREAMS}/st1`);
    expect(body).not.toHaveProperty("authorization_header");
    expect(body).not.toHaveProperty("clear_authorization_header");
    // An omitted `events_requested` would widen what the receiver narrowed.
    expect(body.events_requested).toEqual([REVOKED, CREDENTIAL]);
    expect(body).toMatchObject({
      receiver_client_id: "siem-receiver",
      delivery_method: "push",
      endpoint_url: "https://siem.example.com/events",
      status_reason: "maintenance",
    });
  });

  it("says moving the endpoint to another origin needs the header again, and sends it once entered", async () => {
    const dialog = await openEdit();
    expect(
      within(dialog).getByText(/Moving the push endpoint to another origin requires/),
    ).toBeInTheDocument();
    const endpoint = within(dialog).getByLabelText("Push endpoint URL *");
    await userEvent.clear(endpoint);
    await userEvent.type(endpoint, "https://other.example.net/events");
    expect(within(dialog).getByRole("alert")).toHaveTextContent(
      "This moves the endpoint to another origin",
    );

    // Refused before any request.
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText(/requires the authorization header/)).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();

    apiMock.put.mockResolvedValue(res(stream()));
    const value = headerValue();
    await userEvent.type(within(dialog).getByLabelText(/^Authorization header/), value);
    fireEvent.submit(dialog.querySelector("form")!);
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1]).toMatchObject({
      endpoint_url: "https://other.example.net/events",
      authorization_header: value,
    });
  });

  it("a 409 that is not about the audience reloads the list and says the stream changed", async () => {
    const dialog = await openEdit();
    apiMock.put.mockRejectedValue(
      conflict("the stream changed since it was read; read it again and retry"),
    );
    const before = apiMock.get.mock.calls.length;
    await userEvent.type(within(dialog).getByLabelText("Status reason"), "x");
    fireEvent.submit(dialog.querySelector("form")!);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This stream changed since you opened it",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("The list has been reloaded");
    // The stale form is gone and the list was fetched again.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(apiMock.get.mock.calls.length).toBeGreaterThan(before));
  });

  it("a 409 about the audience stays in the form with the server's sentence", async () => {
    const dialog = await openEdit();
    apiMock.put.mockRejectedValue(conflict("this audience is already used by an SSF stream"));
    await userEvent.type(within(dialog).getByLabelText("Status reason"), "x");
    fireEvent.submit(dialog.querySelector("form")!);

    expect(
      await within(dialog).findByText("this audience is already used by an SSF stream"),
    ).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.queryByText(/changed since you opened it/)).not.toBeInTheDocument();
  });

  it("sends clear_authorization_header, and no header, when the stored one is removed", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(stream()));
    await userEvent.click(
      within(dialog).getByLabelText("Remove the stored authorization header"),
    );
    fireEvent.submit(dialog.querySelector("form")!);
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const body = apiMock.put.mock.calls[0][1];
    expect(body.clear_authorization_header).toBe(true);
    expect(body).not.toHaveProperty("authorization_header");
  });

  it("switching a stream to disabled sends the status and its reason", async () => {
    const dialog = await openEdit();
    apiMock.put.mockResolvedValue(res(stream()));
    await userEvent.selectOptions(within(dialog).getByLabelText("Status"), "disabled");
    await userEvent.type(within(dialog).getByLabelText("Status reason"), "receiver compromised");
    fireEvent.submit(dialog.querySelector("form")!);
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1]).toMatchObject({
      status: "disabled",
      status_reason: "receiver compromised",
    });
  });
});

describe("SsfStreamsPage — create and delete", () => {
  it("registers a push stream with its header, write-only", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(stream({ id: "st3" })));
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "New stream" }));
    const dialog = screen.getByRole("dialog");
    const value = headerValue();
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "new-receiver");
    await userEvent.type(within(dialog).getByLabelText("Audience *"), "new-audience");
    await userEvent.type(
      within(dialog).getByLabelText("Push endpoint URL *"),
      "https://new.example.com/events",
    );
    await userEvent.type(within(dialog).getByLabelText(/^Authorization header/), value);
    fireEvent.submit(dialog.querySelector("form")!);

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    const [url, body] = apiMock.post.mock.calls[0];
    expect(url).toBe(STREAMS);
    expect(body).toMatchObject({
      receiver_client_id: "new-receiver",
      audience: "new-audience",
      delivery_method: "push",
      endpoint_url: "https://new.example.com/events",
      authorization_header: value,
      status: "enabled",
    });
    expect(body.events_allowed).toHaveLength(6);
    expect(body).not.toHaveProperty("events_requested");
  });

  it("refuses a plain-http endpoint before any request", async () => {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "New stream" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "r");
    await userEvent.type(within(dialog).getByLabelText("Audience *"), "a");
    await userEvent.type(
      within(dialog).getByLabelText("Push endpoint URL *"),
      "http://insecure.example.com",
    );
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Endpoint URL must use https.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("deletes a stream after a confirmation that names what it stops", async () => {
    mockGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete SSF stream siem-receiver" }),
    );
    expect(screen.getByText(/stops receiving events at once/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.delete).toHaveBeenCalledWith(`${STREAMS}/st1`));
  });
});

describe("SsfStreamsPage — form behaviour and failures", () => {
  async function openCreate() {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "New stream" }));
    return screen.getByRole("dialog");
  }

  it("a poll stream hides the push fields, and the event ceiling can be narrowed and widened", async () => {
    const dialog = await openCreate();
    expect(within(dialog).getByLabelText("Push endpoint URL *")).toBeInTheDocument();

    await userEvent.selectOptions(within(dialog).getByLabelText("Delivery method"), "poll");
    expect(within(dialog).queryByLabelText("Push endpoint URL *")).not.toBeInTheDocument();

    const first = SSF_EVENT_TYPES[0];
    const box = within(dialog).getByRole("checkbox", { name: first.label });
    expect(box).toBeChecked();
    await userEvent.click(box);
    expect(box).not.toBeChecked();
    await userEvent.click(box);
    expect(box).toBeChecked();
  });

  it("refuses a stream whose every event type was unticked, before any request", async () => {
    const dialog = await openCreate();
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "r");
    await userEvent.type(within(dialog).getByLabelText("Audience *"), "a");
    await userEvent.selectOptions(within(dialog).getByLabelText("Delivery method"), "poll");
    for (const event of SSF_EVENT_TYPES) {
      await userEvent.click(within(dialog).getByRole("checkbox", { name: event.label }));
    }
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Allow at least one event type.")).toBeInTheDocument();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("sends the description and the email subject format the administrator chose", async () => {
    const dialog = await openCreate();
    apiMock.post.mockResolvedValue(res(stream({ id: "st9" })));
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "poller-2");
    await userEvent.type(within(dialog).getByLabelText("Audience *"), "poller-2-aud");
    await userEvent.type(within(dialog).getByLabelText("Description"), "Nightly puller");
    await userEvent.selectOptions(within(dialog).getByLabelText("Delivery method"), "poll");
    await userEvent.selectOptions(within(dialog).getByLabelText("Subject format"), "email");
    fireEvent.submit(dialog.querySelector("form")!);
    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    expect(apiMock.post.mock.calls[0][1]).toMatchObject({
      description: "Nightly puller",
      delivery_method: "poll",
      subject_format: "email",
    });
  });

  it("keeps the dialog open with the server's sentence when registering fails", async () => {
    const dialog = await openCreate();
    apiMock.post.mockRejectedValue({
      response: { status: 400, data: { error: "bad_request", message: "audience is already registered" } },
    });
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "r");
    await userEvent.type(within(dialog).getByLabelText("Audience *"), "a");
    await userEvent.selectOptions(within(dialog).getByLabelText("Delivery method"), "poll");
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("audience is already registered")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("Cancel discards what was typed in the create dialog", async () => {
    const dialog = await openCreate();
    await userEvent.type(within(dialog).getByLabelText("Receiver client id *"), "half-typed");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "New stream" }));
    expect(
      within(screen.getByRole("dialog")).getByLabelText("Receiver client id *"),
    ).toHaveValue("");
  });

  it("Cancel closes the edit dialog without a request", async () => {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SSF stream siem-receiver" }),
    );
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("an edit that fails client-side validation shows the problem and sends nothing", async () => {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Edit SSF stream siem-receiver" }),
    );
    const dialog = screen.getByRole("dialog");
    await userEvent.clear(within(dialog).getByLabelText("Audience *"));
    fireEvent.submit(dialog.querySelector("form")!);
    expect(await screen.findByText("Audience is required.")).toBeInTheDocument();
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("backing out of the delete confirmation deletes nothing", async () => {
    mockGets();
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete SSF stream siem-receiver" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(apiMock.delete).not.toHaveBeenCalled();
    expect(screen.queryByText(/stops receiving events at once/)).not.toBeInTheDocument();
  });

  it("a failed delete closes the confirmation and says so in an alert", async () => {
    mockGets();
    apiMock.delete.mockRejectedValue({
      response: { status: 500, data: { error: "internal", message: "store unavailable" } },
    });
    renderWithProviders(<SsfStreamsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Delete SSF stream siem-receiver" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("store unavailable");
    expect(screen.queryByText(/stops receiving events at once/)).not.toBeInTheDocument();
  });
});
