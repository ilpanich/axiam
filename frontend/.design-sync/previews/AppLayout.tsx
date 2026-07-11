import {
  AppLayout,
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  PageHeader,
  Button,
} from "frontend";
import { RouterProvider, createMemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuthStore } from "@/stores/auth";

// AppLayout is the authenticated shell: it redirects to /login unless the auth
// store says we are signed in, mounts Sidebar + Topbar, and renders the routed
// page into an <Outlet/>. So it needs (a) a seeded auth store, (b) a DATA
// router — Topbar's breadcrumb comes from useMatches().handle.crumb — and
// (c) a QueryClient for the sign-out cache purge.
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

function ServiceAccountsScreen() {
  const accounts = [
    { name: "billing-sync", client: "sa_7f2c…", status: "Active" },
    { name: "iot-gateway-eu", client: "sa_1b90…", status: "Active" },
    { name: "audit-exporter", client: "sa_44de…", status: "Disabled" },
  ];
  return (
    <div className="space-y-6">
      <PageHeader
        title="Service Accounts"
        description="Machine-to-machine principals authenticating with client credentials or mTLS."
        action={<Button size="sm">New service account</Button>}
      />
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active principals</CardDescription>
            <CardTitle className="text-3xl text-primary">37</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              across 4 tenants in acme
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Client-credential grants</CardDescription>
            <CardTitle className="text-3xl text-primary">12,904</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">last 24 hours</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Certificates expiring</CardDescription>
            <CardTitle className="text-3xl text-primary">3</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">within 30 days</p>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Recently used</CardTitle>
          <CardDescription>
            Service accounts that obtained a token in the last hour.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {accounts.map((a) => (
            <div
              key={a.name}
              className="flex items-center justify-between border-b border-primary/10 pb-3 last:border-0 last:pb-0"
            >
              <div>
                <p className="text-sm text-foreground font-medium">{a.name}</p>
                <p className="text-xs font-mono text-muted-foreground">
                  {a.client}
                </p>
              </div>
              <Badge variant={a.status === "Active" ? "default" : "secondary"}>
                {a.status}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

const router = createMemoryRouter(
  [
    {
      path: "/",
      element: <AppLayout />,
      children: [
        {
          path: "service-accounts",
          handle: { crumb: "Service Accounts" },
          element: <ServiceAccountsScreen />,
        },
      ],
    },
  ],
  { initialEntries: ["/service-accounts"] },
);

export const AuthenticatedShell = () => (
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
  </QueryClientProvider>
);
