import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { renderWithProviders } from "@/test/renderWithProviders";

describe("SearchBox", () => {
  it("names what it searches, so a page of roles does not say 'Search users'", () => {
    renderWithProviders(<SearchBox value="" onChange={vi.fn()} noun="roles" />);
    expect(
      screen.getByRole("searchbox", { name: "Search roles" }),
    ).toBeInTheDocument();
  });

  it("promises 'name or ID', which is what the server actually matches", () => {
    // Each repository searches its identifying columns plus `meta::id(id)`, so
    // an operator pasting a UUID out of a log line finds the row. The
    // placeholder has to keep that promise true.
    renderWithProviders(<SearchBox value="" onChange={vi.fn()} noun="users" />);
    expect(
      screen.getByPlaceholderText("Search users by name or ID…"),
    ).toBeInTheDocument();
  });

  it("reports every keystroke", async () => {
    const onChange = vi.fn();
    renderWithProviders(
      <SearchBox value="" onChange={onChange} noun="users" />,
    );
    await userEvent.type(screen.getByRole("searchbox"), "ab");
    expect(onChange).toHaveBeenCalledTimes(2);
  });

  it("offers a clear affordance only when there is something to clear", async () => {
    const onChange = vi.fn();
    const { rerender } = renderWithProviders(
      <SearchBox value="" onChange={onChange} noun="users" />,
    );
    expect(screen.queryByRole("button", { name: "Clear search" })).toBeNull();

    rerender(<SearchBox value="alice" onChange={onChange} noun="users" />);
    await userEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(onChange).toHaveBeenCalledWith("");
  });
});

describe("PaginationControls", () => {
  it("hides the pager for a single page but still gives the count", () => {
    // Disabled Previous/Next under every short list is noise that makes the
    // page look more complicated than it is; the count is the part an operator
    // actually wants.
    renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={1}
        total={3}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
    expect(screen.getByText("3 results")).toBeInTheDocument();
  });

  it("renders nothing at all when there is nothing to show", () => {
    const { container } = renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={1}
        total={0}
        onPageChange={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("singularises one result", () => {
    renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={1}
        total={1}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByText("1 result")).toBeInTheDocument();
  });

  it("shows the page and the count across pages", () => {
    renderWithProviders(
      <PaginationControls
        page={2}
        totalPages={5}
        total={97}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/Page 2 of 5/)).toBeInTheDocument();
    expect(screen.getByText(/97 results/)).toBeInTheDocument();
  });

  it("disables Previous on the first page and Next on the last", () => {
    const { rerender } = renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={3}
        total={50}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();

    rerender(
      <PaginationControls
        page={3}
        totalPages={3}
        total={50}
        onPageChange={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: "Previous" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("clamps at both ends, so no click can ask for page 0 or past the last", async () => {
    // The updater is applied to the current page by the caller, so the clamp
    // has to live in the updater itself — a request for page 0 returns an empty
    // page and looks like the list broke.
    const onPageChange = vi.fn();
    renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={3}
        total={50}
        onPageChange={onPageChange}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    const next = onPageChange.mock.calls[0][0] as (p: number) => number;
    expect(next(1)).toBe(2);
    expect(next(3)).toBe(3);
    expect(next(99)).toBe(3);
  });

  it("clamps Previous at page 1", async () => {
    const onPageChange = vi.fn();
    renderWithProviders(
      <PaginationControls
        page={2}
        totalPages={3}
        total={50}
        onPageChange={onPageChange}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    const prev = onPageChange.mock.calls[0][0] as (p: number) => number;
    expect(prev(2)).toBe(1);
    expect(prev(1)).toBe(1);
    expect(prev(0)).toBe(1);
  });

  it("shows the pager even for one page when asked", () => {
    renderWithProviders(
      <PaginationControls
        page={1}
        totalPages={1}
        total={2}
        onPageChange={vi.fn()}
        alwaysShow
      />,
    );
    expect(screen.getByRole("button", { name: "Next" })).toBeInTheDocument();
  });
});
