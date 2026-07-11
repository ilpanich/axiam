// AxiamSurface — the AXIAM app background, as a component.
//
// AXIAM is a dark-only design system: the gradient surface every component is
// designed against lives on `body` in src/index.css. Preview cards (and any
// standalone design) render on a white body, so components would sit on the
// wrong background and low-contrast variants (ghost buttons, muted text) would
// be unreadable. This reproduces that `body` rule verbatim so the DS is seen —
// and built with — on the surface it was designed for.
import type { ReactNode } from "react";

// ── Bundle-instance re-exports ───────────────────────────────────────────────
// _ds_bundle.js INLINES react-router, zustand and @tanstack/react-query. A preview
// that imports `react-router-dom` directly gets a SECOND copy of the library, with
// its own React context objects — so its <MemoryRouter> populates contexts the
// bundled Sidebar/Topbar/AppLayout never read, and they render blank or throw
// "useNavigate() may be used only in the context of a <Router>".
//
// This file is compiled INTO the bundle (cfg.extraEntries), so re-exporting from
// here hands previews the bundle's own instances. cfg.storyImports.shim redirects
// those specifiers here, which is why the previews can keep their natural imports.
export {
  MemoryRouter,
  RouterProvider,
  createMemoryRouter,
  Routes,
  Route,
  Outlet,
  Link,
  NavLink,
  Navigate,
  useMatches,
  useLocation,
  useNavigate,
} from "react-router-dom";
// The shim redirects the WHOLE react-query module here, so this must carry every
// part of its API that src/ uses — otherwise a bundled component's `useQuery`
// resolves to undefined ("ds_exports.useQuery is not a function").
export {
  QueryClient,
  QueryClientProvider,
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
export { useAuthStore } from "../src/stores/auth";
export { useToast, setToastDispatch } from "../src/hooks/useToast";

// Styling `body` (rather than wrapping in a sized div) is what src/index.css does,
// and it is the only way to paint the surface without adding a box that overflows
// its grid cell — a wrapper with negative margins / 100vh trips [GRID_OVERFLOW]
// on every card.
const SURFACE_CSS = `
  html { color-scheme: dark; }
  body {
    background: linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%) fixed;
    color: #f8fafc;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
`;

export function AxiamSurface({ children }: { children?: ReactNode }) {
  return (
    <>
      <style>{SURFACE_CSS}</style>
      {children}
    </>
  );
}
