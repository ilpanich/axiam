import { Topbar } from "frontend";
import { RouterProvider, createMemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuthStore } from "@/stores/auth";

// Topbar reads the signed-in principal + tenant context from the zustand auth
// store, builds its breadcrumb from `useMatches().handle.crumb` (which requires
// a DATA router — plain <MemoryRouter> exposes no matches), and calls
// useQueryClient() so sign-out can drop the cache.
useAuthStore.setState({
  user: {
    id: "9f1c2d4e-6a3b-4c88-9f2a-77d0e1b4c210",
    username: "e.panigati",
    email: "e.panigati@acme.example",
    permissions: ["*"],
    tenant_id: "3b7f0a19-2c54-4d6e-8f10-5a2b9c7e4d33",
  },
  tenantSlug: "acme-prod",
  orgSlug: "acme",
  isAuthenticated: true,
  isInitializing: false,
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

function TopbarAt({ crumbs, path }: { crumbs: string[]; path: string }) {
  const segments = path.split("/").filter(Boolean);
  // Nest one route per crumb so useMatches() yields the same chain the real
  // admin router produces (Users → Service Accounts, etc.).
  const leaf = {
    path: segments[segments.length - 1] ?? "",
    handle: { crumb: crumbs[crumbs.length - 1] },
    element: <Topbar onMenuClick={() => {}} />,
  };
  const router = createMemoryRouter(
    [
      segments.length > 1
        ? {
            path: segments[0],
            handle: { crumb: crumbs[0] },
            children: [leaf],
          }
        : { ...leaf, path: segments[0] ?? "/" },
    ],
    { initialEntries: [path] },
  );
  return (
    <QueryClientProvider client={queryClient}>
      <div className="rounded-lg overflow-hidden border border-primary/10">
        <RouterProvider router={router} />
      </div>
    </QueryClientProvider>
  );
}

export const OnUsers = () => <TopbarAt crumbs={["Users"]} path="/users" />;

export const NestedCrumb = () => (
  <TopbarAt
    crumbs={["Certificates", "Issue certificate"]}
    path="/certificates/issue"
  />
);
