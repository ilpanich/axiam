import { useNavigate, Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";
import {
  Users,
  UsersRound,
  Shield,
  Award,
  UserPlus,
  FileBadge,
  Webhook,
  ScrollText,
  KeyRound,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthStore } from "@/stores/auth";
import { cn, formatRelativeTime, formatDate } from "@/lib/utils";
import { userService, groupService } from "@/services/users";
import { roleService } from "@/services/roles";
import { certificateService, type Certificate } from "@/services/certificates";
import { auditService, type AuditLog } from "@/services/audit";

// ─── Stat card ────────────────────────────────────────────────────────────────

type StatColor = "cyan" | "purple" | "amber" | "emerald";

interface StatCardProps {
  label: string;
  value: number | null;
  icon: React.ReactNode;
  color: StatColor;
  subLabel?: string;
  isLoading: boolean;
}

const statColorMap: Record<
  StatColor,
  { iconBg: string; iconText: string; border: string; glow: string }
> = {
  cyan: {
    iconBg: "bg-cyan-500/15",
    iconText: "text-cyan-400",
    border: "border-cyan-500/25",
    glow: "shadow-[0_0_14px_rgba(0,212,255,0.25)]",
  },
  purple: {
    iconBg: "bg-purple-500/15",
    iconText: "text-purple-400",
    border: "border-purple-500/25",
    glow: "shadow-[0_0_14px_rgba(168,85,247,0.25)]",
  },
  amber: {
    iconBg: "bg-amber-500/15",
    iconText: "text-amber-400",
    border: "border-amber-500/25",
    glow: "shadow-[0_0_14px_rgba(245,158,11,0.25)]",
  },
  emerald: {
    iconBg: "bg-emerald-500/15",
    iconText: "text-emerald-400",
    border: "border-emerald-500/25",
    glow: "shadow-[0_0_14px_rgba(52,211,153,0.25)]",
  },
};

function StatCard({
  label,
  value,
  icon,
  color,
  subLabel,
  isLoading,
}: StatCardProps) {
  const c = statColorMap[color];
  return (
    <div
      className={cn(
        "glass-card p-5 flex flex-col gap-3 transition-all duration-200 hover:-translate-y-0.5 hover:border-opacity-50",
        c.border
      )}
    >
      <div className="flex items-start justify-between">
        <p className="text-sm font-medium text-muted-foreground">{label}</p>
        <div
          className={cn(
            "h-9 w-9 rounded-lg flex items-center justify-center shrink-0",
            c.iconBg,
            c.glow
          )}
          aria-hidden="true"
        >
          <span className={c.iconText}>{icon}</span>
        </div>
      </div>
      {isLoading ? (
        <div className="h-9 w-20 bg-white/10 rounded animate-pulse" aria-label="Loading" />
      ) : (
        <p className="text-3xl font-bold text-foreground tracking-tight">
          {value ?? "—"}
        </p>
      )}
      {subLabel && !isLoading && (
        <p className="text-xs text-amber-400">{subLabel}</p>
      )}
    </div>
  );
}

// ─── Recent activity row ──────────────────────────────────────────────────────

function ActivityRow({ log }: { log: AuditLog }) {
  return (
    <li className="flex items-start gap-3 py-2.5 border-b border-white/5 last:border-0">
      <div className="mt-0.5 shrink-0">
        {log.outcome === "success" ? (
          <CheckCircle2 size={14} className="text-emerald-400" aria-hidden="true" />
        ) : (
          <XCircle size={14} className="text-red-400" aria-hidden="true" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-foreground/90 font-mono truncate">{log.action}</p>
        <p className="text-xs text-muted-foreground truncate">
          {log.actor_username ?? log.actor_id}
          {log.resource_type ? ` · ${log.resource_type}` : ""}
        </p>
      </div>
      <time
        className="text-xs text-muted-foreground shrink-0 whitespace-nowrap"
        dateTime={log.created_at}
      >
        {formatRelativeTime(log.created_at)}
      </time>
    </li>
  );
}

// ─── Quick action button ──────────────────────────────────────────────────────

interface QuickActionProps {
  icon: React.ReactNode;
  label: string;
  to: string;
  iconColor: string;
}

function QuickAction({ icon, label, to, iconColor }: QuickActionProps) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      onClick={() => navigate(to)}
      className="flex flex-col items-center gap-2 p-4 rounded-xl border border-white/8 bg-white/[0.03] hover:bg-white/[0.07] hover:border-primary/25 transition-all duration-150 group focus:outline-none focus:ring-2 focus:ring-primary/40 w-full"
      aria-label={label}
    >
      <span
        className={cn(
          "h-10 w-10 rounded-lg flex items-center justify-center transition-transform duration-150 group-hover:scale-110",
          iconColor
        )}
        aria-hidden="true"
      >
        {icon}
      </span>
      <span className="text-xs font-medium text-foreground/80 text-center leading-tight">
        {label}
      </span>
    </button>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export function DashboardPage() {
  const { user, tenantSlug, orgSlug } = useAuthStore();

  const results = useQueries({
    queries: [
      {
        queryKey: ["dashboard-users"],
        queryFn: () => userService.list(1, 1, ""),
      },
      {
        queryKey: ["dashboard-groups"],
        queryFn: () => groupService.list(),
      },
      {
        queryKey: ["dashboard-roles"],
        queryFn: () => roleService.list(),
      },
      {
        queryKey: ["dashboard-certs"],
        queryFn: () => certificateService.list(),
      },
      {
        queryKey: ["dashboard-audit"],
        queryFn: () => auditService.list({ page: 1, per_page: 8 }),
      },
    ],
  });

  const [usersQ, groupsQ, rolesQ, certsQ, auditQ] = results;

  // Derive expiring certs (active & expires within 30 days)
  const now = new Date();
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
  const expiringCerts: Certificate[] = (certsQ.data ?? []).filter((c) => {
    if (c.status !== "active") return false;
    const expiresAt = new Date(c.expires_at);
    return expiresAt.getTime() - now.getTime() < thirtyDaysMs;
  });

  const activeCertsCount = (certsQ.data ?? []).filter(
    (c) => c.status === "active"
  ).length;

  const certSubLabel =
    expiringCerts.length > 0
      ? `${expiringCerts.length} expiring soon`
      : undefined;

  return (
    <div className="space-y-8 max-w-6xl">
      {/* Welcome heading */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-foreground">
          Welcome back
          {user?.username ? (
            <>
              ,{" "}
              <span className="text-primary">{user.username}</span>
            </>
          ) : null}
        </h1>
        {(orgSlug || tenantSlug) && (
          <p className="text-muted-foreground text-sm mt-1">
            Workspace:{" "}
            <span className="font-mono text-xs text-primary/80">
              {orgSlug}/{tenantSlug}
            </span>
          </p>
        )}
      </div>

      {/* Stat cards */}
      <section aria-label="Key metrics">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard
            label="Users"
            value={usersQ.data?.total ?? null}
            icon={<Users size={18} />}
            color="cyan"
            isLoading={usersQ.isLoading}
          />
          <StatCard
            label="Groups"
            value={groupsQ.data?.length ?? null}
            icon={<UsersRound size={18} />}
            color="purple"
            isLoading={groupsQ.isLoading}
          />
          <StatCard
            label="Roles"
            value={rolesQ.data?.length ?? null}
            icon={<Shield size={18} />}
            color="amber"
            isLoading={rolesQ.isLoading}
          />
          <StatCard
            label="Certificates"
            value={certsQ.data != null ? activeCertsCount : null}
            icon={<Award size={18} />}
            color="emerald"
            subLabel={certSubLabel}
            isLoading={certsQ.isLoading}
          />
        </div>
      </section>

      {/* Certificate expiry warning */}
      {expiringCerts.length > 0 && (
        <section aria-label="Certificate expiry warnings">
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/8 p-4 space-y-3">
            <div className="flex items-center gap-2">
              <AlertTriangle size={16} className="text-amber-400 shrink-0" aria-hidden="true" />
              <p className="text-sm font-semibold text-amber-300">
                {expiringCerts.length}{" "}
                {expiringCerts.length === 1 ? "certificate" : "certificates"}{" "}
                expiring within 30 days
              </p>
            </div>
            <ul className="space-y-1">
              {expiringCerts.map((cert) => (
                <li
                  key={cert.id}
                  className="flex items-center justify-between text-xs text-amber-200/80"
                >
                  <span className="font-mono truncate">{cert.common_name}</span>
                  <span className="ml-4 shrink-0 text-amber-400">
                    Expires {formatDate(cert.expires_at)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}

      {/* Two-column: Recent Activity + Quick Actions */}
      <section
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        aria-label="Activity and actions"
      >
        {/* Recent Activity */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold">
                Recent Activity
              </CardTitle>
              <Link
                to="/audit-logs"
                className="text-xs text-primary hover:text-primary/80 transition-colors"
              >
                View all logs
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            {auditQ.isLoading ? (
              <ul className="space-y-2" aria-label="Loading recent activity">
                {Array.from({ length: 4 }).map((_, i) => (
                  <li key={i} className="flex items-center gap-3 py-2">
                    <div className="w-3.5 h-3.5 rounded-full bg-white/10 animate-pulse shrink-0" />
                    <div className="flex-1 space-y-2">
                      <div className="h-3 bg-white/10 rounded animate-pulse w-3/4" />
                      <div className="h-2.5 bg-white/10 rounded animate-pulse w-1/2" />
                    </div>
                    <div className="h-2.5 w-16 bg-white/10 rounded animate-pulse" />
                  </li>
                ))}
              </ul>
            ) : (auditQ.data?.data ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No activity recorded yet.
              </p>
            ) : (
              <ul aria-label="Recent audit events">
                {(auditQ.data?.data ?? []).map((log) => (
                  <ActivityRow key={log.id} log={log} />
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-semibold">
              Quick Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              className="grid grid-cols-3 gap-3"
              role="list"
              aria-label="Quick navigation actions"
            >
              <div role="listitem">
                <QuickAction
                  icon={<UserPlus size={20} />}
                  label="Create User"
                  to="/users"
                  iconColor="bg-cyan-500/15 text-cyan-400"
                />
              </div>
              <div role="listitem">
                <QuickAction
                  icon={<UsersRound size={20} />}
                  label="Create Group"
                  to="/groups"
                  iconColor="bg-purple-500/15 text-purple-400"
                />
              </div>
              <div role="listitem">
                <QuickAction
                  icon={<FileBadge size={20} />}
                  label="Generate Certificate"
                  to="/certificates"
                  iconColor="bg-emerald-500/15 text-emerald-400"
                />
              </div>
              <div role="listitem">
                <QuickAction
                  icon={<Webhook size={20} />}
                  label="Add Webhook"
                  to="/webhooks"
                  iconColor="bg-blue-500/15 text-blue-400"
                />
              </div>
              <div role="listitem">
                <QuickAction
                  icon={<ScrollText size={20} />}
                  label="View Audit Logs"
                  to="/audit-logs"
                  iconColor="bg-orange-500/15 text-orange-400"
                />
              </div>
              <div role="listitem">
                <QuickAction
                  icon={<KeyRound size={20} />}
                  label="OAuth2 Clients"
                  to="/oauth2-clients"
                  iconColor="bg-pink-500/15 text-pink-400"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
