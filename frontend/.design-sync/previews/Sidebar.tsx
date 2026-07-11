import { Sidebar } from "frontend";
import { MemoryRouter } from "react-router-dom";
import { useAuthStore } from "@/stores/auth";

// The sidebar dims every nav target the signed-in principal cannot reach, so a
// preview with an empty permission set renders a wall of disabled links. Seed a
// realistic AXIAM session at module scope (zustand stores are module-level).
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

const TENANT_ADMIN_PERMISSIONS = ["*"];

// A tenant auditor: read-only over identity + audit, no infrastructure or
// developer surfaces. Exercises the disabled-item styling.
const AUDITOR_PERMISSIONS = [
  "users:list",
  "groups:list",
  "roles:list",
  "permissions:list",
];

function WithSession({
  permissions,
  route,
}: {
  permissions: string[];
  route: string;
}) {
  useAuthStore.setState({
    user: {
      id: "9f1c2d4e-6a3b-4c88-9f2a-77d0e1b4c210",
      username: permissions === TENANT_ADMIN_PERMISSIONS ? "e.panigati" : "s.auditor",
      email: "e.panigati@acme.example",
      permissions,
      tenant_id: "3b7f0a19-2c54-4d6e-8f10-5a2b9c7e4d33",
    },
    tenantSlug: "acme-prod",
    orgSlug: "acme",
    isAuthenticated: true,
    isInitializing: false,
  });
  return (
    <MemoryRouter initialEntries={[route]}>
      <div className="flex h-[760px] rounded-lg overflow-hidden border border-primary/10">
        <Sidebar />
      </div>
    </MemoryRouter>
  );
}

export const TenantAdmin = () => (
  <WithSession permissions={TENANT_ADMIN_PERMISSIONS} route="/users" />
);

export const AuditorRestricted = () => (
  <WithSession permissions={AUDITOR_PERMISSIONS} route="/audit-logs" />
);

export const MobileDrawer = () => {
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
  return (
    <MemoryRouter initialEntries={["/certificates"]}>
      <div className="flex h-[760px] rounded-lg overflow-hidden border border-primary/10">
        <Sidebar mobile onClose={() => {}} />
      </div>
    </MemoryRouter>
  );
};
