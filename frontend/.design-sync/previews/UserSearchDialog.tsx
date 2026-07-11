import { useEffect, useRef, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
// NOT imported from "frontend": UserSearchDialog calls `useQuery`, which throws
// without a QueryClientProvider, and the bundle global exports components only —
// no provider, and no way to reach react-query's context from outside. Importing
// the component from source puts it and react-query in ONE esbuild graph, so the
// provider below is the same context its `useQuery` reads. This is the real
// component with its real data layer, not a lookalike.
import { UserSearchDialog } from "@/components/UserSearchDialog";
import type { User } from "@/services/users";

/**
 * UserSearchDialog renders `position: fixed; inset: 0`. The `transform` makes
 * this wrapper the containing block for fixed descendants (CSS Transforms spec),
 * trapping the dialog inside the cell instead of covering the whole sheet.
 */
function Stage({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        transform: "translateZ(0)",
        height: 480,
        width: "100%",
        overflow: "hidden",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.08)",
        background: "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)",
      }}
    >
      {children}
    </div>
  );
}

function user(id: string, username: string, email: string, display_name: string): User {
  return {
    id,
    username,
    email,
    display_name,
    mfa_enabled: true,
    email_verified: true,
    created_at: "2026-02-11T09:14:00Z",
    updated_at: "2026-06-30T16:02:00Z",
    status: "Active",
    is_locked: false,
    locked_until: null,
  } as User;
}

/**
 * The dialog keeps `searchTerm` in internal state and only queries at >= 2 chars,
 * so a static render can never show results by props alone. Two moves get there
 * honestly: seed react-query's cache for the exact key the dialog will build
 * (`["user-search", term]`, staleTime 10s → served fresh, no network), then drive
 * the real <input> with a native input event so React's onChange fires exactly as
 * it would for a human typing.
 */
function TypeSearch({ term }: { term: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const input = ref.current
      ?.closest("[data-stage]")
      ?.querySelector<HTMLInputElement>('input[type="search"]');
    if (!input) return;
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    )?.set;
    setter?.call(input, term);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, [term]);

  return <div ref={ref} hidden />;
}

const noop = () => {};
const noAction = async () => {};

function Dialog({
  term,
  seeded,
  actionLabel,
  title,
  existingIds,
  existingLabel,
}: {
  term?: string;
  seeded?: User[];
  actionLabel: string;
  title: string;
  existingIds?: Set<string>;
  existingLabel?: string;
}) {
  const client = useRef<QueryClient>();
  if (!client.current) {
    client.current = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    });
    if (term && seeded) {
      client.current.setQueryData(["user-search", term], {
        items: seeded,
        total: seeded.length,
        offset: 0,
        limit: 20,
      });
    }
  }

  return (
    <Stage>
      <div data-stage style={{ position: "absolute", inset: 0 }}>
        <QueryClientProvider client={client.current}>
          <UserSearchDialog
            open
            onClose={noop}
            onAction={noAction}
            title={title}
            actionLabel={actionLabel}
            existingIds={existingIds}
            existingLabel={existingLabel}
          />
          {term ? <TypeSearch term={term} /> : null}
        </QueryClientProvider>
      </div>
    </Stage>
  );
}

export function EmptySearchPrompt() {
  return <Dialog title="Add members to platform-operators" actionLabel="Add" />;
}

export function SearchResults() {
  return (
    <Dialog
      title="Add members to platform-operators"
      actionLabel="Add"
      term="ros"
      seeded={[
        user("u_01J8", "m.rossi", "m.rossi@acme-prod.example", "Marta Rossi"),
        user("u_02K4", "d.rosenberg", "d.rosenberg@acme-prod.example", "Dana Rosenberg"),
        user("u_03P9", "svc.rotator", "svc.rotator@acme-prod.example", "Key Rotation Bot"),
      ]}
    />
  );
}

export function AssignRoleWithExisting() {
  return (
    <Dialog
      title="Assign role tenant-admin"
      actionLabel="Assign"
      existingLabel="Assigned"
      existingIds={new Set(["u_01J8", "u_03P9"])}
      term="acme"
      seeded={[
        user("u_01J8", "m.rossi", "m.rossi@acme-prod.example", "Marta Rossi"),
        user("u_04X2", "l.moreau", "l.moreau@acme-prod.example", "Luc Moreau"),
        user("u_03P9", "svc.rotator", "svc.rotator@acme-prod.example", "Key Rotation Bot"),
      ]}
    />
  );
}
