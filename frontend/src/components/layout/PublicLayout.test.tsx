import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";

import { PublicLayout } from "./PublicLayout";
import { renderWithProviders } from "@/test/renderWithProviders";

describe("PublicLayout", () => {
  it("renders the children, branding, and compliance footer with the default max width", () => {
    renderWithProviders(
      <PublicLayout>
        <p>panel content</p>
      </PublicLayout>
    );

    expect(screen.getByText("panel content")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "AXIAM" })).toBeInTheDocument();
    expect(screen.getByText("Identity & Access Management")).toBeInTheDocument();
    expect(screen.getByAltText("AXIAM")).toBeInTheDocument();
    expect(
      screen.getByText("Secured by AXIAM IAM · GDPR & ISO27001 compliant")
    ).toBeInTheDocument();

    // Default maxWidth class applied to the outer card wrapper.
    const card = screen.getByText("panel content").closest(".glass-card");
    expect(card).not.toBeNull();
    const wrapper = card?.parentElement;
    expect(wrapper?.className).toContain("max-w-md");
  });

  it("applies a custom maxWidth class when provided", () => {
    renderWithProviders(
      <PublicLayout maxWidth="max-w-lg">
        <p>wide content</p>
      </PublicLayout>
    );

    const card = screen.getByText("wide content").closest(".glass-card");
    const wrapper = card?.parentElement;
    expect(wrapper?.className).toContain("max-w-lg");
    expect(wrapper?.className).not.toContain("max-w-md");
  });
});
