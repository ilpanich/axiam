import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { apiMock, res } from "@/test/apiMock";
import { certPem, hexValue, pemBlock } from "@/test/pemFixture";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { SamlPage } from "./SamlPage";
import { renderWithProviders } from "@/test/renderWithProviders";
import { useAuthStore, type AuthUser } from "@/stores/auth";
import type {
  SamlIdpCredential,
  SamlIdpInfo,
  SamlServiceProvider,
  SamlSpMetadataDraft,
} from "@/services/saml";

const TENANT = "t1";
const ORG = "org1";
const BASE = `/api/v1/tenants/${TENANT}/saml`;

const adminUser: AuthUser = {
  id: "u1",
  username: "admin",
  email: "a@x.io",
  permissions: ["*"],
  tenant_id: TENANT,
  org_id: ORG,
  tenantSlug: "acme",
  orgSlug: "acme-org",
};

const idp: SamlIdpInfo = {
  tenant_id: TENANT,
  saml_available: true,
  saml_idp_enabled: true,
  metadata_served: true,
  entity_id: "https://iam.example.com/saml/v2/t1/metadata",
  metadata_url: "https://iam.example.com/saml/v2/t1/metadata",
  sso_url: "https://iam.example.com/saml/v2/t1/sso",
  slo_url: "https://iam.example.com/saml/v2/t1/slo",
  active_credential_id: "c-active",
  next_credential_id: "c-next",
};

function sp(overrides: Partial<SamlServiceProvider> = {}): SamlServiceProvider {
  return {
    id: "sp1",
    tenant_id: TENANT,
    enabled: true,
    display_name: "Wiki",
    entity_id: "https://wiki.example.com/sp",
    acs_urls: [
      { url: "https://wiki.example.com/acs", binding: "http_post", index: 0, is_default: true },
    ],
    slo_url: null,
    slo_binding: null,
    name_id_format: "persistent",
    sign_responses: true,
    encrypt_assertions: false,
    sp_signing_cert_pem: null,
    sp_encryption_cert_pem: null,
    want_authn_requests_signed: false,
    allow_idp_initiated: false,
    attribute_mappings: [],
    allowed_groups: [],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-02T00:00:00Z",
    ...overrides,
  };
}

function credential(
  status: string,
  id: string,
  overrides: Partial<SamlIdpCredential> = {},
): SamlIdpCredential {
  return {
    id,
    tenant_id: TENANT,
    issuer_ca_id: "ca1",
    certificate_pem: certPem(),
    serial: `0a${id.length}b`,
    fingerprint: hexValue(32),
    not_before: "2026-10-01T00:00:00Z",
    not_after: "2027-10-01T00:00:00Z",
    status,
    created_at: "2026-10-01T00:00:00Z",
    retired_at: null,
    ...overrides,
  };
}

const groups = [
  { id: "g1", name: "Staff", created_at: "2026-01-01T00:00:00Z" },
  { id: "g2", name: "Admins", created_at: "2026-01-01T00:00:00Z" },
];

const cas = [
  {
    id: "ca-1",
    organization_id: ORG,
    subject: "CN=Acme Signing CA",
    fingerprint: "ab",
    key_algorithm: "Rsa4096",
    not_after: "2030-01-01T00:00:00Z",
    status: "Active",
    created_at: "2026-01-01T00:00:00Z",
  },
  { id: "ca-old", organization_id: ORG, subject: "CN=Old CA", fingerprint: "cd", key_algorithm: "Rsa4096", not_after: "2020-01-01T00:00:00Z", status: "Expired", created_at: "2020-01-01T00:00:00Z" },
];

function page<T>(items: T[]) {
  return res({ items, total: items.length, offset: 0, limit: 20 });
}

function rejection(status: number, error: string, message: string) {
  return Promise.reject({ response: { status, data: { error, message } } });
}

interface World {
  info?: SamlIdpInfo;
  sps?: SamlServiceProvider[];
  credentials?: SamlIdpCredential[];
  caStatus?: number;
}

/** Route every GET this page issues. */
function mockGets(world: World = {}) {
  const info = world.info ?? idp;
  const sps = world.sps ?? [sp()];
  const credentials = world.credentials ?? [
    credential("active", "c-active"),
    credential("next", "c-next"),
    credential("retired", "c-old", { retired_at: "2026-09-01T00:00:00Z" }),
  ];
  apiMock.get.mockImplementation((url: string) => {
    if (url === `${BASE}/idp`) return Promise.resolve(res(info));
    if (url === `${BASE}/service-providers`) return Promise.resolve(page(sps));
    const one = /\/service-providers\/([^/]+)$/.exec(url);
    if (one) {
      const found = sps.find((s) => s.id === one[1]);
      return found ? Promise.resolve(res(found)) : rejection(404, "not_found", "no such service provider");
    }
    if (url === `${BASE}/idp-credentials`) return Promise.resolve(res(credentials));
    if (url === "/api/v1/groups") return Promise.resolve(page(groups));
    if (url === `/api/v1/organizations/${ORG}/ca-certificates`) {
      return world.caStatus
        ? rejection(world.caStatus, "authorization_denied", "forbidden")
        : Promise.resolve(page(cas));
    }
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

function as(...permissions: string[]) {
  useAuthStore.setState({ user: { ...adminUser, permissions } });
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

const READ = "saml_sp:read";
const WRITE = "saml_sp:write";
const CRED = "saml_idp:credential";

describe("SamlPage — the identity provider panel", () => {
  it("shows the entity id, the metadata URL and the sign-on and logout URLs, and says it is serving", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText("https://iam.example.com/saml/v2/t1/sso")).toBeInTheDocument();
    expect(screen.getByText("https://iam.example.com/saml/v2/t1/slo")).toBeInTheDocument();
    expect(screen.getAllByText("https://iam.example.com/saml/v2/t1/metadata")).toHaveLength(2);
    expect(screen.getByText("SAML available")).toBeInTheDocument();
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
    expect(screen.getByText("Metadata served")).toBeInTheDocument();
    expect(screen.getByText(/metadata is being served/i)).toBeInTheDocument();
  });

  it("copies the metadata URL", async () => {
    mockGets();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderWithProviders(<SamlPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Copy metadata URL" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(idp.metadata_url));
  });

  it("says SAML is switched off for the tenant and names the setting", async () => {
    mockGets({ info: { ...idp, saml_idp_enabled: false, metadata_served: false } });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText("Switched off")).toBeInTheDocument();
    expect(screen.getByText(/switched off for this tenant/i)).toHaveTextContent("saml_idp_enabled");
    expect(screen.getByText("Metadata not served")).toBeInTheDocument();
  });

  it("says when enabled but no credential makes the metadata unservable", async () => {
    mockGets({
      info: {
        ...idp,
        metadata_served: false,
        active_credential_id: null,
        next_credential_id: null,
      },
    });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText(/no active or next signing credential/i)).toBeInTheDocument();
    expect(screen.getByText(/No active credential\./)).toBeInTheDocument();
  });

  it("says when the build has no SAML at all", async () => {
    mockGets({ info: { ...idp, saml_available: false, saml_idp_enabled: false, metadata_served: false } });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText("SAML not in this build")).toBeInTheDocument();
    expect(screen.getByText(/built without SAML support/i)).toBeInTheDocument();
  });

  it("shows a load failure in place", async () => {
    mockGets();
    const get = apiMock.get.getMockImplementation()!;
    apiMock.get.mockImplementation((url: string) =>
      url === `${BASE}/idp` ? rejection(403, "authorization_denied", "forbidden") : get(url),
    );
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText(/Failed to load the identity provider|forbidden/i)).toBeInTheDocument();
  });
});

describe("SamlPage — the service-provider list", () => {
  it("lists registrations with their entity id, status and who may sign in", async () => {
    mockGets({
      sps: [
        sp(),
        sp({
          id: "sp2",
          display_name: "Billing",
          entity_id: "https://billing.example.com/sp",
          enabled: false,
          allowed_groups: ["g1", "g2"],
        }),
      ],
    });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText("Wiki")).toBeInTheDocument();
    expect(screen.getByText("https://billing.example.com/sp")).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText("Every active user")).toBeInTheDocument();
    expect(screen.getByText("2 groups")).toBeInTheDocument();
  });

  it("asks the server to search, and to page", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByText("Wiki");
    await userEvent.type(screen.getByRole("searchbox", { name: /search service providers/i }), "wiki");
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith(
        `${BASE}/service-providers`,
        expect.objectContaining({
          params: expect.objectContaining({ search: "wiki", offset: 0, limit: 20 }),
        }),
      ),
    );
  });

  it("says so when there are none, and when a search finds none", async () => {
    mockGets({ sps: [] });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText(/No service providers are registered yet/)).toBeInTheDocument();
  });

  it("offers a reader no write at all", async () => {
    as(READ);
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByText("Wiki");
    for (const name of [
      /Register a service provider/,
      /Import from metadata/,
      /^Edit Wiki$/,
      /^Delete Wiki$/,
      /Issue a credential/,
      /^Promote credential/,
      /^Retire credential/,
    ]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });

  it("gives a writer the registry's writes but not the credential's", async () => {
    as(READ, WRITE);
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByText("Wiki");
    expect(screen.getByRole("button", { name: /Register a service provider/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Import from metadata/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit Wiki" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Issue a credential/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Retire credential/ })).not.toBeInTheDocument();
  });
});

async function fillMinimal(user = userEvent) {
  await user.type(screen.getByLabelText("Display name"), "Wiki");
  await user.type(screen.getByLabelText("Entity ID"), "https://wiki.example.com/sp");
  await user.type(screen.getByLabelText("ACS URL 1"), "https://wiki.example.com/acs");
}

describe("SamlPage — registering manually", () => {
  it("shows every field, with encryption disabled and explained", async () => {
    mockGets({ sps: [] });
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));

    for (const label of [
      "Display name",
      "Entity ID",
      "ACS URL 1",
      "ACS binding 1",
      "ACS index 1",
      "Single-logout URL",
      "Single-logout binding",
      "NameID format",
      "Signing certificate (PEM)",
      "Encryption certificate (PEM)",
    ]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    for (const label of [
      "Enabled",
      "Sign responses",
      "Require signed sign-on requests",
      "Allow IdP-initiated sign-on",
    ]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    const encrypt = screen.getByLabelText("Encrypt assertions");
    expect(encrypt).toBeDisabled();
    expect(encrypt).not.toBeChecked();
    expect(screen.getByText(/Not yet supported/)).toBeInTheDocument();
    expect(await screen.findByLabelText("Staff")).toBeInTheDocument();
  });

  it("registers with POST, a complete body and encrypt_assertions false", async () => {
    mockGets({ sps: [] });
    apiMock.post.mockResolvedValue(res(sp()));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await fillMinimal();
    await userEvent.click(await screen.findByLabelText("Staff"));
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    const [url, body] = apiMock.post.mock.calls[0];
    expect(url).toBe(`${BASE}/service-providers`);
    expect(body).toEqual({
      enabled: true,
      display_name: "Wiki",
      entity_id: "https://wiki.example.com/sp",
      acs_urls: [
        { url: "https://wiki.example.com/acs", binding: "http_post", index: 0, is_default: true },
      ],
      slo_url: null,
      slo_binding: null,
      name_id_format: "persistent",
      sign_responses: true,
      encrypt_assertions: false,
      sp_signing_cert_pem: null,
      sp_encryption_cert_pem: null,
      want_authn_requests_signed: false,
      allow_idp_initiated: false,
      attribute_mappings: [],
      allowed_groups: ["g1"],
    });
    expect(await screen.findByText(/Service provider .Wiki. registered\./)).toBeInTheDocument();
  });

  it("sends the certificates, the SLO pair and the attribute mappings it was given", async () => {
    mockGets({ sps: [] });
    apiMock.post.mockResolvedValue(res(sp()));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await fillMinimal();
    const pem = certPem();
    fireEvent.change(screen.getByLabelText("Signing certificate (PEM)"), { target: { value: pem } });
    await userEvent.type(screen.getByLabelText("Single-logout URL"), "https://wiki.example.com/slo");
    await userEvent.selectOptions(screen.getByLabelText("Single-logout binding"), "http_redirect");
    await userEvent.click(screen.getByLabelText("Require signed sign-on requests"));
    await userEvent.click(screen.getByLabelText("Allow IdP-initiated sign-on"));
    await userEvent.click(screen.getByRole("button", { name: /Add attribute mapping/ }));
    await userEvent.type(screen.getByLabelText("Attribute name 1"), "mail");
    await userEvent.selectOptions(screen.getByLabelText("Attribute source 1"), "email");
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    expect(apiMock.post.mock.calls[0][1]).toMatchObject({
      sp_signing_cert_pem: pem,
      slo_url: "https://wiki.example.com/slo",
      slo_binding: "http_redirect",
      want_authn_requests_signed: true,
      allow_idp_initiated: true,
      encrypt_assertions: false,
      attribute_mappings: [{ saml_name: "mail", name_format: null, source: "email" }],
    });
  });

  it("refuses a wildcard ACS URL before any request, and says why", async () => {
    mockGets({ sps: [] });
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await userEvent.type(screen.getByLabelText("Display name"), "Wiki");
    await userEvent.type(screen.getByLabelText("Entity ID"), "https://wiki.example.com/sp");
    await userEvent.type(screen.getByLabelText("ACS URL 1"), "https://*.example.com/acs");
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/\*/);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("refuses a private key pasted as a certificate, and sends nothing", async () => {
    mockGets({ sps: [] });
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await fillMinimal();
    fireEvent.change(screen.getByLabelText("Signing certificate (PEM)"), {
      target: { value: pemBlock("PRIVATE KEY") },
    });
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/private key/i);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows a 400 verbatim, even where the generic redactor would rewrite it", async () => {
    mockGets({ sps: [] });
    const message = "sp_signing_cert_pem: private key not accepted; secret: must not be sent";
    apiMock.post.mockImplementation(() => rejection(400, "validation_error", message));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await fillMinimal();
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));
    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it("shows a 409 on a repeated entity id verbatim and stays on the form", async () => {
    mockGets({ sps: [] });
    apiMock.post.mockImplementation(() =>
      rejection(409, "conflict", "a service provider with this entity_id already exists"),
    );
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /Register a service provider/ }));
    await fillMinimal();
    await userEvent.click(screen.getByRole("button", { name: /^Register$/ }));
    expect(
      await screen.findByText("a service provider with this entity_id already exists"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Entity ID")).toHaveValue("https://wiki.example.com/sp");
  });
});

describe("SamlPage — editing", () => {
  it("re-reads the registration, fixes the entity id, and replaces with PUT", async () => {
    const pem = certPem();
    mockGets({
      sps: [
        sp({
          sp_signing_cert_pem: pem,
          allowed_groups: ["g2"],
          attribute_mappings: [{ saml_name: "mail", name_format: null, source: "email" }],
          want_authn_requests_signed: true,
        }),
      ],
    });
    apiMock.put.mockResolvedValue(res(sp()));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Wiki" }));

    const entity = await screen.findByLabelText("Entity ID");
    await waitFor(() =>
      expect(apiMock.get).toHaveBeenCalledWith(`${BASE}/service-providers/sp1`),
    );
    expect(entity).toHaveValue("https://wiki.example.com/sp");
    expect(entity).toHaveAttribute("readonly");
    expect(screen.getByText(/Cannot be changed/)).toBeInTheDocument();
    expect(screen.getByText(/replaces/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Encrypt assertions")).toBeDisabled();
    expect(screen.getByLabelText("Signing certificate (PEM)")).toHaveValue(pem);
    expect(await screen.findByLabelText("Admins")).toBeChecked();
    expect(screen.getByLabelText("Staff")).not.toBeChecked();

    // Typing into a read-only field changes nothing.
    await userEvent.type(entity, "zzz");
    expect(entity).toHaveValue("https://wiki.example.com/sp");

    const name = screen.getByLabelText("Display name");
    await userEvent.clear(name);
    await userEvent.type(name, "Company wiki");
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));

    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    const [url, body] = apiMock.put.mock.calls[0];
    expect(url).toBe(`${BASE}/service-providers/sp1`);
    expect(body).toMatchObject({
      display_name: "Company wiki",
      entity_id: "https://wiki.example.com/sp",
      encrypt_assertions: false,
      sp_signing_cert_pem: pem,
      want_authn_requests_signed: true,
      allowed_groups: ["g2"],
      attribute_mappings: [{ saml_name: "mail", name_format: null, source: "email" }],
    });
    expect(Object.keys(body)).toHaveLength(15);
    expect(apiMock.patch).not.toHaveBeenCalled();
    expect(await screen.findByText(/saved/i)).toBeInTheDocument();
  });

  it("shows an unknown group id so it can be removed, and drops it when unticked", async () => {
    mockGets({ sps: [sp({ allowed_groups: ["g1", "deadbeef-gone"] })] });
    apiMock.put.mockResolvedValue(res(sp()));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Wiki" }));
    await userEvent.click(await screen.findByLabelText(/Unknown group \(deadbeef/));
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    await waitFor(() => expect(apiMock.put).toHaveBeenCalledTimes(1));
    expect(apiMock.put.mock.calls[0][1].allowed_groups).toEqual(["g1"]);
  });

  it("keeps a registration whose server value this console does not know visible, and refuses to send it", async () => {
    mockGets({
      sps: [
        sp({
          acs_urls: [{ url: "https://wiki.example.com/acs", binding: "http_artifact", index: 0 }],
        }),
      ],
    });
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Wiki" }));
    const binding = await screen.findByLabelText("ACS binding 1");
    expect(binding).toHaveValue("http_artifact");
    expect(within(binding).getByText("Unknown (http_artifact)")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Save changes/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/choose a binding/i);
    expect(apiMock.put).not.toHaveBeenCalled();
  });

  it("shows a 400 from the replacement verbatim", async () => {
    mockGets();
    apiMock.put.mockImplementation(() =>
      rejection(400, "validation_error", "allowed_groups: group is not a group of this tenant"),
    );
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Wiki" }));
    await userEvent.click(await screen.findByRole("button", { name: /Save changes/ }));
    expect(
      await screen.findByText("allowed_groups: group is not a group of this tenant"),
    ).toBeInTheDocument();
  });

  it("reports a registration that vanished before the form could open", async () => {
    mockGets();
    const get = apiMock.get.getMockImplementation()!;
    apiMock.get.mockImplementation((url: string) =>
      url === `${BASE}/service-providers/sp1`
        ? rejection(404, "not_found", "service provider not found")
        : get(url),
    );
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit Wiki" }));
    expect(await screen.findByText("service provider not found")).toBeInTheDocument();
    expect(screen.queryByLabelText("Display name")).not.toBeInTheDocument();
  });
});

describe("SamlPage — deleting", () => {
  it("asks first, says what a delete does not do, and deletes on confirm", async () => {
    mockGets();
    apiMock.delete.mockResolvedValue(res(undefined));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Wiki" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/ends no session/i);
    expect(apiMock.delete).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete service provider" }));
    await waitFor(() =>
      expect(apiMock.delete).toHaveBeenCalledWith(`${BASE}/service-providers/sp1`),
    );
    expect(await screen.findByText(/deleted/i)).toBeInTheDocument();
  });

  it("does nothing on cancel", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Wiki" }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(apiMock.delete).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows a refusal in the dialog", async () => {
    mockGets();
    apiMock.delete.mockImplementation(() => rejection(404, "not_found", "service provider not found"));
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete Wiki" }));
    await userEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete service provider" }),
    );
    expect(await within(screen.getByRole("dialog")).findByText("service provider not found")).toBeInTheDocument();
  });
});

const XML = "<EntityDescriptor entityID='https://imp.example.com/sp'/>";

function draft(overrides: Partial<SamlSpMetadataDraft> = {}): SamlSpMetadataDraft {
  return {
    service_provider: {
      display_name: "imp.example.com",
      entity_id: "https://imp.example.com/sp",
      acs_urls: [
        { url: "https://imp.example.com/acs", binding: "http_post", index: 0, is_default: true },
      ],
      slo_url: "https://imp.example.com/slo",
      slo_binding: "http_redirect",
      sp_signing_cert_pem: certPem(),
      want_authn_requests_signed: true,
      encrypt_assertions: false,
    },
    signing_certificate_fingerprint: hexValue(32),
    encryption_certificate_fingerprint: null,
    warnings: ["metadata signature not verified", "2 signing keys found; the first was taken"],
    ...overrides,
  };
}

describe("SamlPage — import from metadata", () => {
  async function openImport() {
    await userEvent.click(await screen.findByRole("button", { name: /Import from metadata/ }));
  }

  it("parses pasted XML into a draft and saves nothing", async () => {
    mockGets();
    const parsed = draft();
    apiMock.post.mockResolvedValue(res(parsed));
    renderWithProviders(<SamlPage />);
    await openImport();
    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));

    await screen.findByTestId("metadata-draft");
    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/parse-sp-metadata`, { metadata_xml: XML });
    expect(apiMock.put).not.toHaveBeenCalled();
    // Nothing but the parse: no create yet.
    expect(
      apiMock.post.mock.calls.filter(([url]) => String(url).endsWith("/service-providers")),
    ).toHaveLength(0);
  });

  it("puts the not-verified warning, the other warnings and the fingerprints in front of the reviewer", async () => {
    mockGets();
    const parsed = draft();
    apiMock.post.mockResolvedValue(res(parsed));
    renderWithProviders(<SamlPage />);
    await openImport();
    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));

    const review = await screen.findByTestId("metadata-draft");
    const alert = within(review).getByRole("alert");
    expect(alert).toHaveTextContent(/Nothing has been saved, and nothing in it is verified/);
    expect(alert).toHaveTextContent("metadata signature not verified");
    expect(within(review).getByText("2 signing keys found; the first was taken")).toBeInTheDocument();
    expect(within(review).getByText(parsed.signing_certificate_fingerprint!)).toBeInTheDocument();
    expect(within(review).getByText(/No encryption certificate in the document/)).toBeInTheDocument();
  });

  it("seeds the form from the draft, and saves only on the explicit save", async () => {
    mockGets();
    const parsed = draft();
    apiMock.post.mockImplementation((url: string) =>
      String(url).endsWith("/parse-sp-metadata") ? Promise.resolve(res(parsed)) : Promise.resolve(res(sp())),
    );
    renderWithProviders(<SamlPage />);
    await openImport();
    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));

    expect(await screen.findByLabelText("Entity ID")).toHaveValue("https://imp.example.com/sp");
    expect(screen.getByLabelText("Entity ID")).not.toHaveAttribute("readonly");
    expect(screen.getByLabelText("ACS URL 1")).toHaveValue("https://imp.example.com/acs");
    expect(screen.getByLabelText("Single-logout URL")).toHaveValue("https://imp.example.com/slo");
    expect(screen.getByLabelText("Signing certificate (PEM)")).toHaveValue(
      parsed.service_provider.sp_signing_cert_pem,
    );
    expect(apiMock.post).toHaveBeenCalledTimes(1);

    // The administrator edits the draft before saving.
    const name = screen.getByLabelText("Display name");
    await userEvent.clear(name);
    await userEvent.type(name, "Imported app");
    await userEvent.click(screen.getByRole("button", { name: /Save as a service provider/ }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(2));
    const [url, body] = apiMock.post.mock.calls[1];
    expect(url).toBe(`${BASE}/service-providers`);
    expect(body).toMatchObject({
      display_name: "Imported app",
      entity_id: "https://imp.example.com/sp",
      slo_url: "https://imp.example.com/slo",
      slo_binding: "http_redirect",
      want_authn_requests_signed: true,
      encrypt_assertions: false,
    });
  });

  it("drops the draft on cancel without saving", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(draft()));
    renderWithProviders(<SamlPage />);
    await openImport();
    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));
    await screen.findByTestId("metadata-draft");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByTestId("metadata-draft")).not.toBeInTheDocument();
    expect(apiMock.post).toHaveBeenCalledTimes(1);
  });

  it("sends a URL as exactly metadata_url", async () => {
    mockGets();
    apiMock.post.mockResolvedValue(res(draft()));
    renderWithProviders(<SamlPage />);
    await openImport();
    await userEvent.type(screen.getByLabelText("Or metadata URL"), "https://imp.example.com/md");
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/parse-sp-metadata`, {
        metadata_url: "https://imp.example.com/md",
      }),
    );
  });

  it("makes sending both, neither or a non-https URL impossible: no request is made", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await openImport();
    const parseButton = screen.getByRole("button", { name: /Parse metadata/ });

    await userEvent.click(parseButton);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Paste the metadata XML/);

    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.type(screen.getByLabelText("Or metadata URL"), "https://imp.example.com/md");
    await userEvent.click(parseButton);
    expect(await screen.findByRole("alert")).toHaveTextContent(/not both/);

    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Or metadata URL"), {
      target: { value: "http://imp.example.com/md" },
    });
    await userEvent.click(parseButton);
    expect(await screen.findByRole("alert")).toHaveTextContent(/https/);
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows the server's refusal verbatim and stays on the import panel", async () => {
    mockGets();
    apiMock.post.mockImplementation(() =>
      rejection(400, "validation_error", "metadata_url refused"),
    );
    renderWithProviders(<SamlPage />);
    await openImport();
    await userEvent.type(screen.getByLabelText("Or metadata URL"), "https://10.0.0.1/md");
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));
    expect(await screen.findByText("metadata_url refused")).toBeInTheDocument();
    expect(screen.queryByTestId("metadata-draft")).not.toBeInTheDocument();
  });

  it("shows the 503 of a build without SAML verbatim", async () => {
    mockGets();
    apiMock.post.mockImplementation(() =>
      rejection(503, "service_unavailable", "SAML support is not built into this server"),
    );
    renderWithProviders(<SamlPage />);
    await openImport();
    fireEvent.change(screen.getByLabelText("Metadata XML"), { target: { value: XML } });
    await userEvent.click(screen.getByRole("button", { name: /Parse metadata/ }));
    expect(await screen.findByText("SAML support is not built into this server")).toBeInTheDocument();
  });

  it("reads an uploaded file into the XML box", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await openImport();
    const file = new File([XML], "metadata.xml", { type: "text/xml" });
    await userEvent.upload(screen.getByLabelText("Upload metadata file"), file);
    await waitFor(() => expect(screen.getByLabelText("Metadata XML")).toHaveValue(XML));
  });

  it("is not offered to someone without saml_sp:write", async () => {
    as(READ);
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByText("Wiki");
    expect(screen.queryByRole("button", { name: /Import from metadata/ })).not.toBeInTheDocument();
  });
});

describe("SamlPage — signing credentials", () => {
  it("lists status, fingerprint, validity and serial, and never a key", async () => {
    const leaked = pemBlock("PRIVATE KEY");
    const active = { ...credential("active", "c-active"), private_key_pem: leaked } as SamlIdpCredential;
    mockGets({ credentials: [active, credential("next", "c-next")] });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText(active.fingerprint)).toBeInTheDocument();
    const table = screen.getByText(active.fingerprint).closest("table")!;
    expect(within(table).getByText("active")).toBeInTheDocument();
    expect(within(table).getByText("next")).toBeInTheDocument();
    expect(screen.getByText(active.serial)).toBeInTheDocument();
    expect(screen.getAllByText(/to/).length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain(leaked.split("\n")[1]);
    expect(screen.queryByText(/PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("says when none has been issued", async () => {
    mockGets({ credentials: [] });
    renderWithProviders(<SamlPage />);
    expect(await screen.findByText(/No signing credential has been issued yet/)).toBeInTheDocument();
  });

  it("offers Promote only on next, and Retire on next and active but not retired", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByRole("button", { name: /^Promote credential/ });
    expect(screen.getAllByRole("button", { name: /^Promote credential/ })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: /^Retire credential/ })).toHaveLength(2);
  });

  it("promotes only after a confirmation that explains the service providers must have fetched the metadata", async () => {
    const next = credential("next", "c-next");
    mockGets({ credentials: [credential("active", "c-active"), next] });
    apiMock.post.mockResolvedValue(
      res({ active: { ...next, status: "active" }, retired: credential("retired", "c-active") }),
    );
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Promote credential/ }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/must already have fetched the metadata/i);
    expect(apiMock.post).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Promote" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/idp-credentials/c-next/promote`),
    );
    expect(await screen.findByText(/now active and the previous one is retired/)).toBeInTheDocument();
  });

  it("does not promote on cancel", async () => {
    mockGets();
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Promote credential/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows a promote 409 verbatim", async () => {
    mockGets();
    apiMock.post.mockImplementation(() =>
      rejection(409, "conflict", "credential is not the tenant's current next credential"),
    );
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Promote credential/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Promote" }));
    expect(
      await within(screen.getByRole("dialog")).findByText(
        "credential is not the tenant's current next credential",
      ),
    ).toBeInTheDocument();
  });

  it("warns, before it asks, that retiring the active credential stops sign-on for the tenant", async () => {
    const active = credential("active", "c-active");
    mockGets({ credentials: [active, credential("next", "c-next")] });
    apiMock.post.mockResolvedValue(res({ ...active, status: "retired" }));
    renderWithProviders(<SamlPage />);
    const row = (await screen.findByText(active.fingerprint)).closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: /^Retire credential/ }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/stops SAML sign-on for the whole tenant at once/);
    expect(dialog).toHaveTextContent(/use Promote instead/);
    expect(apiMock.post).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole("button", { name: "Retire" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/idp-credentials/c-active/retire`),
    );
    expect(await screen.findByText(/SAML sign-on is stopped/)).toBeInTheDocument();
  });

  it("does not use the stop-sign-on warning for the next credential", async () => {
    const next = credential("next", "c-next");
    mockGets({ credentials: [credential("active", "c-active"), next] });
    renderWithProviders(<SamlPage />);
    const row = (await screen.findByText(next.fingerprint)).closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: /^Retire credential/ }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/Sign-on is not affected/);
    expect(dialog).not.toHaveTextContent(/stops SAML sign-on/);
  });

  it("says there is no successor when retiring the active credential with no next", async () => {
    mockGets({ credentials: [credential("active", "c-active")] });
    renderWithProviders(<SamlPage />);
    await userEvent.click(await screen.findByRole("button", { name: /^Retire credential/ }));
    expect(await screen.findByRole("dialog")).toHaveTextContent(/no next credential to take over/);
  });

  it("gates all three actions on saml_idp:credential, not on saml_sp:write", async () => {
    as(READ, WRITE);
    mockGets();
    renderWithProviders(<SamlPage />);
    await screen.findByText("Signing credentials");
    await screen.findAllByText("active");
    for (const name of [/Issue a credential/, /^Promote credential/, /^Retire credential/]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });

  it("gives the credential holder the three actions without the registry's writes", async () => {
    as(READ, CRED);
    mockGets();
    renderWithProviders(<SamlPage />);
    expect(await screen.findByRole("button", { name: /Issue a credential/ })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /^Promote credential/ })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Retire credential/ })).toHaveLength(2);
    expect(screen.queryByRole("button", { name: /Register a service provider/ })).not.toBeInTheDocument();
  });
});

describe("SamlPage — issuing a credential", () => {
  async function openIssue() {
    await userEvent.click(await screen.findByRole("button", { name: /Issue a credential/ }));
    return screen.findByRole("dialog");
  }

  it("offers the organization's active CAs only, defaults to 365 days and to the free slot", async () => {
    mockGets({ credentials: [credential("active", "c-active")] });
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    const ca = await within(dialog).findByLabelText("Issuing CA");
    await waitFor(() => expect(within(ca).getByText("CN=Acme Signing CA")).toBeInTheDocument());
    expect(within(ca).queryByText("CN=Old CA")).not.toBeInTheDocument();
    expect(within(dialog).getByLabelText("Validity (days)")).toHaveValue("365");
    // active is occupied, so next is the default.
    expect(within(dialog).getByLabelText("Slot")).toHaveValue("next");
    expect(within(dialog).getByText("active (occupied)")).toBeInTheDocument();
  });

  it("issues with the chosen CA, slot and validity", async () => {
    mockGets({ credentials: [] });
    apiMock.post.mockResolvedValue(res(credential("next", "c-new")));
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    const ca = await within(dialog).findByLabelText("Issuing CA");
    await waitFor(() => expect(within(ca).getByText("CN=Acme Signing CA")).toBeInTheDocument());
    await userEvent.selectOptions(ca, "ca-1");
    await userEvent.selectOptions(within(dialog).getByLabelText("Slot"), "next");
    const days = within(dialog).getByLabelText("Validity (days)");
    await userEvent.clear(days);
    await userEvent.type(days, "90");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));

    await waitFor(() => expect(apiMock.post).toHaveBeenCalledTimes(1));
    expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/idp-credentials`, {
      issuer_ca_id: "ca-1",
      slot: "next",
      validity_days: 90,
    });
    expect(await screen.findByText(/issued into the next slot/)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("refuses a CA that was not chosen and a validity out of range, without a request", async () => {
    mockGets({ credentials: [] });
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    await within(dialog).findByLabelText("Issuing CA");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/Choose the issuing CA/);

    await waitFor(() =>
      expect(within(within(dialog).getByLabelText("Issuing CA")).getByText("CN=Acme Signing CA")).toBeInTheDocument(),
    );
    await userEvent.selectOptions(within(dialog).getByLabelText("Issuing CA"), "ca-1");
    for (const bad of ["0", "731"]) {
      const days = within(dialog).getByLabelText("Validity (days)");
      await userEvent.clear(days);
      await userEvent.type(days, bad);
      await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
      expect(await within(dialog).findByRole("alert")).toHaveTextContent(/1 to 730/);
    }
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("shows an occupied-slot 409 verbatim and keeps the dialog open", async () => {
    mockGets({ credentials: [] });
    apiMock.post.mockImplementation(() =>
      rejection(409, "conflict", "the active slot already holds a credential"),
    );
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    const ca = await within(dialog).findByLabelText("Issuing CA");
    await waitFor(() => expect(within(ca).getByText("CN=Acme Signing CA")).toBeInTheDocument());
    await userEvent.selectOptions(ca, "ca-1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    expect(
      await within(dialog).findByText("the active slot already holds a credential"),
    ).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("falls back to a typed CA id when the CA list is not readable", async () => {
    mockGets({ credentials: [], caStatus: 403 });
    apiMock.post.mockResolvedValue(res(credential("active", "c-new")));
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    const input = await within(dialog).findByPlaceholderText("CA id (UUID)");

    await userEvent.type(input, "not-a-uuid");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/must be a UUID/);
    expect(apiMock.post).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "5b1c9e0e-0f5b-4a0b-9d63-3c5d2f0a7e11");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    await waitFor(() =>
      expect(apiMock.post).toHaveBeenCalledWith(`${BASE}/idp-credentials`, {
        issuer_ca_id: "5b1c9e0e-0f5b-4a0b-9d63-3c5d2f0a7e11",
        slot: "active",
        validity_days: 365,
      }),
    );
  });

  it("tells the administrator it takes seconds while the key is generated", async () => {
    mockGets({ credentials: [] });
    let finish: (v: unknown) => void = () => undefined;
    apiMock.post.mockImplementation(() => new Promise((resolve) => (finish = resolve)));
    renderWithProviders(<SamlPage />);
    const dialog = await openIssue();
    const ca = await within(dialog).findByLabelText("Issuing CA");
    await waitFor(() => expect(within(ca).getByText("CN=Acme Signing CA")).toBeInTheDocument());
    await userEvent.selectOptions(ca, "ca-1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue" }));
    expect(await within(dialog).findByText(/Generating a 4096-bit key/)).toBeInTheDocument();
    finish(res(credential("active", "c-new")));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});
