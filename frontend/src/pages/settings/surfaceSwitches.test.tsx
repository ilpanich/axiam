import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { SurfaceSwitches } from "./surfaceSwitches";
import { surfaceLayer } from "@/services/settings";

const SAML = /SAML 2.0 identity provider/;
const SSF = /Shared Signals Framework transmitter/;

describe("surfaceLayer", () => {
  it("says where an effective false comes from, from the tenant's own override", () => {
    expect(surfaceLayer(true, undefined, true)).toBe("on");
    // Off with no tenant override saying so: the organization's value.
    expect(surfaceLayer(false, undefined, true)).toBe("organization");
    expect(surfaceLayer(false, null, true)).toBe("organization");
    // Off because this tenant's override says false.
    expect(surfaceLayer(false, false, true)).toBe("tenant");
    // Override unreadable: it must not claim either.
    expect(surfaceLayer(false, undefined, false)).toBe("unknown");
  });
});

describe("SurfaceSwitches", () => {
  it("sends the right patch when a switch is toggled at organization scope", async () => {
    const onChange = vi.fn();
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="organization"
        editing
        value={{ saml_idp_enabled: false, ssf_enabled: true }}
        onChange={onChange}
      />,
    );
    expect(screen.getByLabelText(SAML, { exact: false })).not.toBeChecked();
    expect(screen.getByLabelText(SSF, { exact: false })).toBeChecked();

    await userEvent.click(screen.getByLabelText(SAML, { exact: false }));
    expect(onChange).toHaveBeenLastCalledWith({ saml_idp_enabled: true });
    await userEvent.click(screen.getByLabelText(SSF, { exact: false }));
    expect(onChange).toHaveBeenLastCalledWith({ ssf_enabled: false });
  });

  it("shows 'disabled by the organization' and cannot enable what the organization disabled", async () => {
    const onChange = vi.fn();
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="tenant"
        editing
        value={{ saml_idp_enabled: false, ssf_enabled: true }}
        layers={{ saml_idp_enabled: "organization", ssf_enabled: "on" }}
        onChange={onChange}
      />,
    );
    const saml = screen.getByLabelText(SAML, { exact: false });
    expect(saml).toBeDisabled();
    expect(saml).not.toBeChecked();
    expect(screen.getByText(/Disabled by the organization/)).toBeInTheDocument();
    await userEvent.click(saml);
    expect(onChange).not.toHaveBeenCalled();
    // The surface the organization left on can be switched off by the tenant.
    const ssf = screen.getByLabelText(SSF, { exact: false });
    expect(ssf).toBeEnabled();
    await userEvent.click(ssf);
    expect(onChange).toHaveBeenCalledWith({ ssf_enabled: false });
  });

  it("lets a tenant that switched a surface off switch it back on, and says it was the tenant", () => {
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="tenant"
        editing
        value={{ saml_idp_enabled: true, ssf_enabled: false }}
        layers={{ ssf_enabled: "tenant" }}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText(SSF, { exact: false })).toBeEnabled();
    expect(screen.getByText(/Turned off for this tenant/)).toBeInTheDocument();
    expect(screen.queryByText(/Disabled by the organization/)).not.toBeInTheDocument();
  });

  it("does not claim who turned a surface off when the tenant override is unknown", () => {
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="tenant"
        editing
        value={{ saml_idp_enabled: false, ssf_enabled: false }}
        layers={{ saml_idp_enabled: "unknown", ssf_enabled: "unknown" }}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getAllByText(/If the organization has switched it off/)).toHaveLength(2);
    expect(screen.queryByText(/Disabled by the organization/)).not.toBeInTheDocument();
  });

  it("says an enabled transmitter is inactive, with the server's reason", () => {
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="organization"
        editing
        value={{ saml_idp_enabled: false, ssf_enabled: true }}
        ssfInactiveReason="the deployment serves no per-tenant issuers"
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "the deployment serves no per-tenant issuers",
    );
  });

  it("renders a read-only summary with no switch", () => {
    render(
      <SurfaceSwitches
        idPrefix="t"
        scope="tenant"
        editing={false}
        value={{ saml_idp_enabled: true, ssf_enabled: false }}
        layers={{ ssf_enabled: "organization" }}
      />,
    );
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText(/Disabled by the organization/)).toBeInTheDocument();
  });
});
