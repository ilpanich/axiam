import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { SearchInput } from "@/components/SearchInput";
import { ForbiddenPage } from "@/components/ForbiddenPage";
import {
  ToggleField,
  SectionCard,
  InfoRow,
  ActionBadge,
} from "@/components/shared";
import {
  PasswordPolicyChecker,
  checkPasswordPolicy,
} from "@/components/PasswordPolicyChecker";

// ─── ui primitives ────────────────────────────────────────────────────────────

describe("Button", () => {
  it("renders a native button and handles clicks", async () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Go</Button>);
    await userEvent.click(screen.getByRole("button", { name: "Go" }));
    expect(onClick).toHaveBeenCalled();
  });
  it("renders as a child element (Slot) when asChild", () => {
    render(
      <Button asChild>
        <a href="/x">Link</a>
      </Button>
    );
    expect(screen.getByRole("link", { name: "Link" })).toHaveAttribute("href", "/x");
  });
  it("buttonVariants composes variant + size classes", () => {
    const cls = buttonVariants({ variant: "destructive", size: "sm" });
    expect(cls).toContain("bg-destructive");
    expect(cls).toContain("h-8");
  });
});

describe("Badge", () => {
  it("renders content with a variant", () => {
    render(<Badge variant="accent">New</Badge>);
    expect(screen.getByText("New")).toBeInTheDocument();
  });
});

describe("Card family", () => {
  it("renders all subcomponents", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Desc</CardDescription>
        </CardHeader>
        <CardContent>Body</CardContent>
        <CardFooter>Foot</CardFooter>
      </Card>
    );
    expect(screen.getByText("Title")).toBeInTheDocument();
    expect(screen.getByText("Desc")).toBeInTheDocument();
    expect(screen.getByText("Body")).toBeInTheDocument();
    expect(screen.getByText("Foot")).toBeInTheDocument();
  });
});

describe("Input / Textarea / Label", () => {
  it("Input forwards ref and value changes", async () => {
    render(<Input placeholder="email" />);
    const el = screen.getByPlaceholderText("email");
    await userEvent.type(el, "hi");
    expect(el).toHaveValue("hi");
  });
  it("Textarea renders", async () => {
    render(<Textarea placeholder="notes" />);
    await userEvent.type(screen.getByPlaceholderText("notes"), "x");
    expect(screen.getByPlaceholderText("notes")).toHaveValue("x");
  });
  it("Label associates with a control", () => {
    render(
      <>
        <Label htmlFor="f">Name</Label>
        <Input id="f" />
      </>
    );
    expect(screen.getByText("Name")).toBeInTheDocument();
  });
});

// ─── StatusBadge ──────────────────────────────────────────────────────────────

describe("StatusBadge", () => {
  it("capitalizes each status", () => {
    render(<StatusBadge status="active" />);
    expect(screen.getByText("Active")).toBeInTheDocument();
  });
  it("renders every status variant", () => {
    for (const s of ["active", "revoked", "inactive", "suspended"] as const) {
      const { unmount } = render(<StatusBadge status={s} />);
      expect(screen.getByText(s.charAt(0).toUpperCase() + s.slice(1))).toBeInTheDocument();
      unmount();
    }
  });
});

// ─── PageHeader ───────────────────────────────────────────────────────────────

describe("PageHeader", () => {
  it("renders title only", () => {
    render(<PageHeader title="Users" />);
    expect(screen.getByRole("heading", { name: "Users" })).toBeInTheDocument();
  });
  it("renders description and action when provided", () => {
    render(<PageHeader title="Users" description="Manage" action={<button>Add</button>} />);
    expect(screen.getByText("Manage")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
  });
});

// ─── SearchInput (debounce) ───────────────────────────────────────────────────

describe("SearchInput", () => {
  it("debounces onChange by 300ms", () => {
    vi.useFakeTimers();
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} placeholder="Find" />);
    const input = screen.getByLabelText("Find");
    fireEvent.change(input, { target: { value: "ab" } });
    expect(onChange).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(300));
    expect(onChange).toHaveBeenCalledWith("ab");
    vi.useRealTimers();
  });
  it("resets local state when the external value changes", () => {
    const { rerender } = render(<SearchInput value="a" onChange={() => {}} />);
    rerender(<SearchInput value="reset" onChange={() => {}} />);
    expect(screen.getByDisplayValue("reset")).toBeInTheDocument();
  });
  it("clears the pending timer on a second keystroke", () => {
    vi.useFakeTimers();
    const onChange = vi.fn();
    render(<SearchInput value="" onChange={onChange} placeholder="Find" />);
    const input = screen.getByLabelText("Find");
    fireEvent.change(input, { target: { value: "a" } });
    act(() => vi.advanceTimersByTime(100));
    fireEvent.change(input, { target: { value: "ab" } });
    act(() => vi.advanceTimersByTime(300));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith("ab");
    vi.useRealTimers();
  });
});

// ─── ForbiddenPage ────────────────────────────────────────────────────────────

describe("ForbiddenPage", () => {
  it("renders the 403 message and a dashboard link", () => {
    render(
      <MemoryRouter>
        <ForbiddenPage />
      </MemoryRouter>
    );
    expect(screen.getByRole("heading", { name: "Access Denied" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Back to Dashboard/ })).toHaveAttribute(
      "href",
      "/dashboard"
    );
  });
});

// ─── shared primitives ────────────────────────────────────────────────────────

describe("shared primitives", () => {
  it("ToggleField reflects checked state and reports changes", async () => {
    const onChange = vi.fn();
    render(<ToggleField id="t" label="Enable" checked={false} onChange={onChange} />);
    const cb = screen.getByRole("checkbox");
    expect(cb).not.toBeChecked();
    await userEvent.click(cb);
    expect(onChange).toHaveBeenCalledWith(true);
  });
  it("SectionCard renders title, action and children", () => {
    render(
      <SectionCard title="Members" action={<button>Add</button>}>
        <p>rows</p>
      </SectionCard>
    );
    expect(screen.getByText("Members")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
    expect(screen.getByText("rows")).toBeInTheDocument();
  });
  it("InfoRow renders label and value", () => {
    render(<InfoRow label="Email">a@x.io</InfoRow>);
    expect(screen.getByText("Email")).toBeInTheDocument();
    expect(screen.getByText("a@x.io")).toBeInTheDocument();
  });
  it("ActionBadge maps known actions and falls back for unknown ones", () => {
    const { rerender } = render(<ActionBadge action="read" />);
    expect(screen.getByText("read")).toBeInTheDocument();
    rerender(<ActionBadge action="frobnicate" />);
    expect(screen.getByText("frobnicate")).toBeInTheDocument();
  });
});

// ─── PasswordPolicyChecker ────────────────────────────────────────────────────

describe("checkPasswordPolicy", () => {
  it("passes a fully compliant password", () => {
    expect(checkPasswordPolicy("Abcdefgh1234!", 12, true)).toBe(true);
  });
  it("fails when too short", () => {
    expect(checkPasswordPolicy("Ab1!", 12, true)).toBe(false);
  });
  it("length-only mode ignores complexity", () => {
    expect(checkPasswordPolicy("alllowercaselong", 12, false)).toBe(true);
  });
});

describe("PasswordPolicyChecker", () => {
  it("lists all complexity rules and reflects which are met", () => {
    render(<PasswordPolicyChecker password="Abc1" minLength={12} requireComplexity />);
    expect(screen.getByText("At least 12 characters")).toBeInTheDocument();
    expect(screen.getByText("At least one uppercase letter")).toBeInTheDocument();
    expect(screen.getByText("At least one special character")).toBeInTheDocument();
  });
  it("length-only variant shows a single rule", () => {
    render(<PasswordPolicyChecker password="x" minLength={8} requireComplexity={false} />);
    expect(screen.getByText("At least 8 characters")).toBeInTheDocument();
    expect(screen.queryByText("At least one digit")).not.toBeInTheDocument();
  });
});
