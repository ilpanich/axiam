import { NavLink, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  Users,
  UsersRound,
  Shield,
  Lock,
  Database,
  Building2,
  Network,
  Award,
  Key,
  Webhook,
  Code2,
  ScrollText,
  UserCircle,
  Settings,
  X,
  ChevronRight,
  KeyRound,
  Globe,
  BellRing,
} from "lucide-react";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: "Overview",
    items: [
      {
        to: "/dashboard",
        label: "Dashboard",
        icon: <LayoutDashboard size={18} />,
      },
    ],
  },
  {
    title: "Identity",
    items: [
      { to: "/users", label: "Users", icon: <Users size={18} /> },
      { to: "/groups", label: "Groups", icon: <UsersRound size={18} /> },
      { to: "/roles", label: "Roles", icon: <Shield size={18} /> },
      { to: "/permissions", label: "Permissions", icon: <Lock size={18} /> },
      { to: "/resources", label: "Resources", icon: <Database size={18} /> },
      {
        to: "/service-accounts",
        label: "Service Accounts",
        icon: <KeyRound size={18} />,
      },
      { to: "/federation", label: "Federation", icon: <Globe size={18} /> },
    ],
  },
  {
    title: "Infrastructure",
    items: [
      {
        to: "/organizations",
        label: "Organizations",
        icon: <Building2 size={18} />,
      },
      { to: "/tenants", label: "Tenants", icon: <Network size={18} /> },
      {
        to: "/certificates",
        label: "Certificates",
        icon: <Award size={18} />,
      },
      { to: "/pgp-keys", label: "PGP Keys", icon: <Key size={18} /> },
      { to: "/webhooks", label: "Webhooks", icon: <Webhook size={18} /> },
    ],
  },
  {
    title: "Developers",
    items: [
      {
        to: "/oauth2-clients",
        label: "OAuth2 Clients",
        icon: <Code2 size={18} />,
      },
      {
        to: "/audit-logs",
        label: "Audit Logs",
        icon: <ScrollText size={18} />,
      },
      {
        to: "/notification-rules",
        label: "Notification Rules",
        icon: <BellRing size={18} />,
      },
    ],
  },
  {
    title: "Account",
    items: [
      { to: "/profile", label: "Profile", icon: <UserCircle size={18} /> },
      { to: "/settings", label: "Settings", icon: <Settings size={18} /> },
    ],
  },
];

interface SidebarProps {
  onClose?: () => void;
  mobile?: boolean;
}

export function Sidebar({ onClose, mobile = false }: SidebarProps) {
  const location = useLocation();

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
            src="/axiam_logo.png"
            alt="AXIAM logo"
            className="h-8 w-8 object-contain"
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
                const isActive =
                  location.pathname === item.to ||
                  (item.to !== "/dashboard" &&
                    location.pathname.startsWith(item.to));
                return (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      onClick={mobile ? onClose : undefined}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 group",
                        isActive
                          ? "sidebar-item-active font-medium"
                          : "text-muted-foreground hover:text-foreground hover:bg-white/5 pl-3"
                      )}
                      aria-current={isActive ? "page" : undefined}
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
                      {isActive && (
                        <ChevronRight
                          size={14}
                          className="ml-auto text-primary"
                          aria-hidden="true"
                        />
                      )}
                    </NavLink>
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
          AXIAM v0.1.0-dev
        </p>
      </div>
    </aside>
  );
}
