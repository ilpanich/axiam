import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ResourceTree } from "@/components/ResourceTree";
import type { Resource } from "@/services/resources";

function r(id: string, name: string, parent_id?: string, type = "api"): Resource {
  return { id, name, resource_type: type, parent_id, created_at: "t" };
}

const tree: Resource[] = [
  r("root", "Root API"),
  r("child1", "Child One", "root"),
  r("child2", "Child Two", "root", "iot_device"),
  r("grandchild", "Grandchild", "child1"),
  r("orphanParentMissing", "Orphan", "does-not-exist"),
];

describe("ResourceTree", () => {
  it("renders empty state when there are no resources", () => {
    render(<ResourceTree resources={[]} />);
    expect(screen.getByText("No resources defined yet.")).toBeInTheDocument();
  });

  it("builds a hierarchy and shows type labels (iot_device humanized)", () => {
    render(<ResourceTree resources={tree} />);
    expect(screen.getByText("Root API")).toBeInTheDocument();
    expect(screen.getByText("Grandchild")).toBeInTheDocument();
    expect(screen.getByText("IoT Device")).toBeInTheDocument();
    // A parent pointing at a missing id is treated as a root.
    expect(screen.getByText("Orphan")).toBeInTheDocument();
  });

  it("selects a node on click and on Enter", async () => {
    const onSelect = vi.fn();
    render(<ResourceTree resources={tree} onSelect={onSelect} selectedId="root" />);
    await userEvent.click(screen.getByText("Child One"));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "child1" }));
    const rootRow = screen.getByText("Root API").closest("[role='treeitem']")!;
    fireEvent.keyDown(rootRow, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "root" }));
  });

  it("collapses and expands children via the toggle button", async () => {
    render(<ResourceTree resources={tree} />);
    expect(screen.getByText("Grandchild")).toBeInTheDocument();
    // Collapse "Child One" (which owns Grandchild).
    const child1Row = screen.getByText("Child One").closest("[role='treeitem']")!;
    const toggle = child1Row.querySelector("button")!;
    await userEvent.click(toggle);
    expect(screen.queryByText("Grandchild")).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(screen.getByText("Grandchild")).toBeInTheDocument();
  });

  it("supports keyboard expand/collapse and arrow navigation", () => {
    render(<ResourceTree resources={tree} />);
    const rootRow = screen.getByText("Root API").closest("[role='treeitem']")! as HTMLElement;
    rootRow.focus();
    // ArrowLeft collapses an expanded node.
    fireEvent.keyDown(rootRow, { key: "ArrowLeft" });
    expect(screen.queryByText("Child One")).not.toBeInTheDocument();
    // ArrowRight expands it again.
    fireEvent.keyDown(rootRow, { key: "ArrowRight" });
    expect(screen.getByText("Child One")).toBeInTheDocument();
    // Arrow navigation moves focus without throwing.
    fireEvent.keyDown(rootRow, { key: "ArrowDown" });
    fireEvent.keyDown(rootRow, { key: "End" });
    fireEvent.keyDown(rootRow, { key: "Home" });
    fireEvent.keyDown(rootRow, { key: "ArrowUp" });
  });

  it("renders per-row action nodes", () => {
    render(
      <ResourceTree resources={[r("root", "Root API")]} actions={(res) => <button>del-{res.id}</button>} />
    );
    expect(screen.getByRole("button", { name: "del-root" })).toBeInTheDocument();
  });

  it("selects a node via the Space key", () => {
    const onSelect = vi.fn();
    render(<ResourceTree resources={[r("root", "Root API")]} onSelect={onSelect} />);
    const row = screen.getByText("Root API").closest("[role='treeitem']")!;
    fireEvent.keyDown(row, { key: " " });
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "root" }));
  });

  it("ignores expand/collapse arrows on a leaf node", () => {
    render(<ResourceTree resources={[r("leaf", "Leaf")]} />);
    const row = screen.getByText("Leaf").closest("[role='treeitem']")! as HTMLElement;
    row.focus();
    // No children → ArrowRight/ArrowLeft are no-ops (must not throw).
    fireEvent.keyDown(row, { key: "ArrowRight" });
    fireEvent.keyDown(row, { key: "ArrowLeft" });
    expect(screen.getByText("Leaf")).toBeInTheDocument();
  });

  it("auto-expands newly added nodes when the resources prop changes", () => {
    const { rerender } = render(<ResourceTree resources={[r("root", "Root")]} />);
    expect(screen.queryByText("Fresh Child")).not.toBeInTheDocument();
    rerender(
      <ResourceTree resources={[r("root", "Root"), r("fresh", "Fresh Child", "root")]} />
    );
    // The sync effect adds the new node to expandedIds; its child becomes visible.
    expect(screen.getByText("Fresh Child")).toBeInTheDocument();
  });
});
