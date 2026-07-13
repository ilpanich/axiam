import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { FormDialog } from "@/components/FormDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { SecretRevealModal } from "@/components/SecretRevealModal";

// ─── ConfirmDialog ─────────────────────────────────────────────────────────────

describe("ConfirmDialog", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <ConfirmDialog open={false} onClose={() => {}} onConfirm={() => {}} title="T" description="D" />
    );
    expect(container.firstChild).toBeNull();
  });

  it("shows title/description and fires confirm + cancel", async () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog open onClose={onClose} onConfirm={onConfirm} title="Delete user" description="Are you sure?" />
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Delete user")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(onConfirm).toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
  });

  it("uses custom labels and shows spinner while loading", () => {
    render(
      <ConfirmDialog
        open
        onClose={() => {}}
        onConfirm={() => {}}
        title="T"
        description="D"
        confirmLabel="Remove"
        cancelLabel="Back"
        isLoading
      />
    );
    expect(screen.getByRole("button", { name: "Back" })).toBeDisabled();
    // Confirm label text is replaced by the spinner while loading.
    expect(screen.queryByText("Remove")).not.toBeInTheDocument();
  });

  it("closes on Escape but not while loading", () => {
    const onClose = vi.fn();
    const { rerender } = render(
      <ConfirmDialog open onClose={onClose} onConfirm={() => {}} title="T" description="D" />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    rerender(
      <ConfirmDialog open isLoading onClose={onClose} onConfirm={() => {}} title="T" description="D" />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("clicking the backdrop closes when not loading", () => {
    const onClose = vi.fn();
    render(
      <ConfirmDialog open onClose={onClose} onConfirm={() => {}} title="T" description="D" />
    );
    // Backdrop is the aria-hidden overlay.
    const backdrop = document.querySelector('[aria-hidden="true"]') as HTMLElement;
    fireEvent.click(backdrop);
    expect(onClose).toHaveBeenCalled();
  });

  it("Tab wraps focus within the dialog", () => {
    render(
      <ConfirmDialog open onClose={() => {}} onConfirm={() => {}} title="T" description="D" />
    );
    const buttons = screen.getAllByRole("button");
    const last = buttons[buttons.length - 1];
    last.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(buttons[0]);
  });
});

// ─── FormDialog ────────────────────────────────────────────────────────────────

describe("FormDialog", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <FormDialog open={false} onClose={() => {}} onSubmit={() => {}} title="T">
        x
      </FormDialog>
    );
    expect(container.firstChild).toBeNull();
  });

  it("submits the form and focuses the first field on open", async () => {
    const onSubmit = vi.fn((e) => e.preventDefault());
    render(
      <FormDialog open onClose={() => {}} onSubmit={onSubmit} title="Create" submitLabel="Create">
        <input aria-label="Name" />
      </FormDialog>
    );
    expect(document.activeElement).toBe(screen.getByLabelText("Name"));
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(onSubmit).toHaveBeenCalled();
  });

  it("closes via the X button and Cancel", async () => {
    const onClose = vi.fn();
    render(
      <FormDialog open onClose={onClose} onSubmit={() => {}} title="T">
        <input aria-label="F" />
      </FormDialog>
    );
    await userEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("disables actions and shows spinner while loading", () => {
    render(
      <FormDialog open isLoading onClose={() => {}} onSubmit={() => {}} title="T" submitLabel="Save">
        <input aria-label="F" />
      </FormDialog>
    );
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close dialog" })).toBeDisabled();
  });

  it("Escape closes when not loading", () => {
    const onClose = vi.fn();
    render(
      <FormDialog open onClose={onClose} onSubmit={() => {}} title="T">
        <input aria-label="F" />
      </FormDialog>
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("Tab wraps from last to first focusable and Shift+Tab wraps back", () => {
    render(
      <FormDialog open onClose={() => {}} onSubmit={(e) => e.preventDefault()} title="T" submitLabel="Save">
        <input aria-label="F" />
      </FormDialog>
    );
    const focusables = Array.from(
      document.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), textarea:not([disabled])'
      )
    );
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    last.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(first);
    first.focus();
    fireEvent.keyDown(document, { key: "Shift", shiftKey: true }); // no-op key
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });
});

// ─── DataTable ─────────────────────────────────────────────────────────────────

interface Row {
  id: string;
  name: string;
  role: string;
}
const columns: Column<Row>[] = [
  { key: "name", header: "Name" },
  { key: "role", header: "Role", render: (r) => <em>{r.role.toUpperCase()}</em> },
];

describe("DataTable", () => {
  it("renders headers and rows, using custom render and raw values", () => {
    render(
      <DataTable
        columns={columns}
        data={[{ id: "1", name: "Alice", role: "admin" }]}
      />
    );
    expect(screen.getByText("Name")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("ADMIN")).toBeInTheDocument();
  });

  it("shows skeleton rows while loading", () => {
    const { container } = render(<DataTable columns={columns} data={[]} isLoading />);
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("shows the empty message when there is no data", () => {
    render(<DataTable columns={columns} data={[]} emptyMessage="Nothing here" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("uses getRowKey when provided", () => {
    const getRowKey = vi.fn((r: Row) => r.id);
    render(<DataTable columns={columns} data={[{ id: "9", name: "Z", role: "x" }]} getRowKey={getRowKey} />);
    expect(getRowKey).toHaveBeenCalled();
  });

  it("falls back to index/blank for rows without id and null cells", () => {
    const cols: Column<{ name?: string }>[] = [{ key: "name", header: "Name" }];
    render(<DataTable columns={cols} data={[{}]} />);
    // No id, no name → renders an empty cell without throwing.
    expect(screen.getByText("Name")).toBeInTheDocument();
  });
});

// ─── SecretRevealModal ─────────────────────────────────────────────────────────

describe("SecretRevealModal", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when closed", () => {
    const { container } = render(
      <SecretRevealModal open={false} onClose={() => {}} title="T" description="D" secrets={[]} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("lists secrets and acknowledges via the button", () => {
    const onClose = vi.fn();
    render(
      <SecretRevealModal
        open
        onClose={onClose}
        title="Client secret"
        description="Copy it now"
        secrets={[{ label: "Secret", value: "s3cr3t" }, { label: "ID", value: "id-1", mono: false }]}
      />
    );
    expect(screen.getByText("Client secret")).toBeInTheDocument();
    expect(screen.getByText("s3cr3t")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /I've saved/ }));
    expect(onClose).toHaveBeenCalled();
  });

  it("copies a secret to the clipboard and shows feedback", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(
      <SecretRevealModal
        open
        onClose={() => {}}
        title="T"
        description="D"
        secrets={[{ label: "Secret", value: "abc" }]}
      />
    );
    const copyBtn = screen.getByRole("button", { name: "Copy to clipboard" });
    fireEvent.click(copyBtn);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("abc"));
    // Feedback label flips to "Copied!".
    expect(await screen.findByRole("button", { name: "Copied!" })).toBeInTheDocument();
  });

  it("falls back to execCommand when the Clipboard API is unavailable", async () => {
    Object.assign(navigator, { clipboard: undefined });
    const execCommand = vi.fn().mockReturnValue(true);
    Object.assign(document, { execCommand });
    render(
      <SecretRevealModal
        open
        onClose={() => {}}
        title="T"
        description="D"
        secrets={[{ label: "Secret", value: "xyz" }]}
      />
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith("copy"));
  });

  it("swallows clipboard errors without crashing", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.assign(navigator, { clipboard: { writeText } });
    render(
      <SecretRevealModal
        open
        onClose={() => {}}
        title="T"
        description="D"
        secrets={[{ label: "Secret", value: "abc" }]}
      />
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    // No "Copied!" feedback since the write failed, and no crash.
    expect(screen.getByRole("button", { name: "Copy to clipboard" })).toBeInTheDocument();
  });
});
