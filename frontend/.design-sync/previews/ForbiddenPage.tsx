import { ForbiddenPage } from "frontend";
import { MemoryRouter } from "react-router-dom";

// ForbiddenPage is the 403 body ProtectedRoute renders inside AppLayout's
// <Outlet/> when the signed-in principal lacks the route's permission (e.g. an
// auditor opening /certificates). It links back to /dashboard, so it needs a
// Router around it.

export const AccessDenied = () => (
  <MemoryRouter initialEntries={["/certificates"]}>
    <ForbiddenPage />
  </MemoryRouter>
);
