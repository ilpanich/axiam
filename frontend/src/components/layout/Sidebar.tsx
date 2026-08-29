// `Link`, not `NavLink`, on purpose. `NavLink` sets `aria-current="page"`
// itself from its own internal prefix match, which cannot be told about
// `alsoMatches` and silently overrode the value computed here — a tenant detail
// page lit Organizations however `activeNavPath` answered. With `Link` the
// active state has exactly one source.
import { Link, useLocation } from "react-router";
import { cn } from "@/lib/utils";
import { usePermissions } from "@/hooks/usePermissions";
import { useCanActOnOrganization } from "@/lib/grantReach";
import { X, ChevronRight } from "lucide-react";
import { activeNavPath, navSections } from "@/components/layout/navSections";

interface SidebarProps {
  onClose?: () => void;
  mobile?: boolean;
}

export function Sidebar({ onClose, mobile = false }: SidebarProps) {
  const location = useLocation();
  const { can } = usePermissions();
  const canActOnOrganization = useCanActOnOrganization();

  // Exactly one entry is active, chosen by longest matching prefix — see
  // `activeNavPath`. Computing it once per render also means two entries can
  // never both light up, which the old per-item `startsWith` allowed.
  const activePath = activeNavPath(location.pathname);

  return (
    <aside
      className={cn(
        "flex flex-col h-full bg-[#0d0d2b]/90 backdrop-blur-xl border-r border-primary/10",
        "w-60 shrink-0"
      )}
      aria-label="Main navigation"
    >
      {/* Logo area */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-primary/10">
        <div className="flex items-center gap-3">
          <img
            src="/axiam_logo_mark.png"
            alt="AXIAM logo"
            className="h-8 w-8 rounded-full object-cover"
          />
          <span className="text-foreground font-bold text-lg tracking-tight">
            AXIAM
          </span>
        </div>
        {mobile && (
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded"
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {navSections.map((section) => (
          <div key={section.title}>
            <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              {section.title}
            </p>
            <ul className="space-y-0.5" role="list">
              {section.items.map((item) => {
                const isActive = activePath === item.to;
                const isDisabled =
                  (item.requiredPermission !== null &&
                    !can(item.requiredPermission)) ||
                  // A permission the principal holds is not enough for an
                  // organization-level section — see `navSections`'
                  // `organizationOnly`. Disabled rather than removed, the same
                  // way a missing permission is: the nav then reads the same
                  // for both reasons a section can be out of reach.
                  (item.organizationOnly === true && !canActOnOrganization);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      onClick={
                        isDisabled
                          ? (e) => e.preventDefault()
                          : mobile
                            ? onClose
                            : undefined
                      }
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 group",
                        isActive
                          ? "sidebar-item-active font-medium"
                          : "text-muted-foreground hover:text-foreground hover:bg-white/5 pl-3",
                        isDisabled &&
                          "opacity-40 cursor-not-allowed pointer-events-none"
                      )}
                      aria-current={isActive ? "page" : undefined}
                      aria-disabled={isDisabled ? "true" : undefined}
                      tabIndex={isDisabled ? -1 : undefined}
                    >
                      <span
                        className={cn(
                          "shrink-0 transition-colors",
                          isActive
                            ? "text-primary"
                            : "text-muted-foreground group-hover:text-foreground"
                        )}
                        aria-hidden="true"
                      >
                        {item.icon}
                      </span>
                      <span className="truncate">{item.label}</span>
                      {isActive && !isDisabled && (
                        <ChevronRight
                          size={14}
                          className="ml-auto text-primary"
                          aria-hidden="true"
                        />
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-primary/10">
        <p className="text-[10px] text-muted-foreground/50">
          AXIAM v1.0.0-beta04
        </p>
      </div>
    </aside>
  );
}
