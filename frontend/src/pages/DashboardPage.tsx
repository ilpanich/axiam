import { useNavigate } from "react-router-dom";
import {
  Users,
  UsersRound,
  Shield,
  Activity,
  UserPlus,
  ScrollText,
  ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/auth";
import { cn } from "@/lib/utils";

interface StatCard {
  label: string;
  value: string;
  icon: React.ReactNode;
  description: string;
  color: "cyan" | "purple" | "green" | "orange";
}

const stats: StatCard[] = [
  {
    label: "Users",
    value: "—",
    icon: <Users size={20} />,
    description: "Total registered users",
    color: "cyan",
  },
  {
    label: "Groups",
    value: "—",
    icon: <UsersRound size={20} />,
    description: "Active user groups",
    color: "purple",
  },
  {
    label: "Roles",
    value: "—",
    icon: <Shield size={20} />,
    description: "Defined roles",
    color: "green",
  },
  {
    label: "Active Sessions",
    value: "—",
    icon: <Activity size={20} />,
    description: "Currently active",
    color: "orange",
  },
];

const colorMap = {
  cyan: {
    bg: "bg-primary/10",
    border: "border-primary/20",
    icon: "text-primary",
    glow: "shadow-glow-cyan",
  },
  purple: {
    bg: "bg-accent/10",
    border: "border-accent/20",
    icon: "text-accent",
    glow: "shadow-glow-purple",
  },
  green: {
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    icon: "text-emerald-400",
    glow: "shadow-[0_0_12px_rgba(52,211,153,0.3)]",
  },
  orange: {
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
    icon: "text-orange-400",
    glow: "shadow-[0_0_12px_rgba(251,146,60,0.3)]",
  },
};

export function DashboardPage() {
  const navigate = useNavigate();
  const { user, tenantId, orgId } = useAuthStore();

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
        {(orgId || tenantId) && (
          <p className="text-muted-foreground text-sm mt-1">
            Workspace:{" "}
            <span className="font-mono text-xs text-primary/80">
              {orgId}/{tenantId}
            </span>
          </p>
        )}
      </div>

      {/* Stat cards */}
      <section aria-label="Key metrics">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {stats.map((stat) => {
            const colors = colorMap[stat.color];
            return (
              <Card
                key={stat.label}
                className="hover:border-primary/30 transition-all duration-200 hover:-translate-y-0.5"
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                      {stat.label}
                    </CardTitle>
                    <div
                      className={cn(
                        "h-8 w-8 rounded-md flex items-center justify-center",
                        colors.bg,
                        colors.glow
                      )}
                      aria-hidden="true"
                    >
                      <span className={colors.icon}>{stat.icon}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <p
                    className="text-3xl font-bold text-foreground"
                    aria-label={`${stat.label}: ${stat.value}`}
                  >
                    {stat.value}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {stat.description}
                  </p>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      {/* Quick actions */}
      <section aria-label="Quick actions">
        <h2 className="text-base font-semibold text-foreground mb-4">
          Quick actions
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Button
            onClick={() => navigate("/users")}
            variant="outline"
            className="h-auto py-4 flex-col gap-2 group"
          >
            <UserPlus
              size={22}
              className="text-primary group-hover:scale-110 transition-transform"
              aria-hidden="true"
            />
            <span>Create User</span>
          </Button>
          <Button
            onClick={() => navigate("/groups")}
            variant="outline"
            className="h-auto py-4 flex-col gap-2 group"
          >
            <UsersRound
              size={22}
              className="text-accent group-hover:scale-110 transition-transform"
              aria-hidden="true"
            />
            <span>Create Group</span>
          </Button>
          <Button
            onClick={() => navigate("/audit-logs")}
            variant="outline"
            className="h-auto py-4 flex-col gap-2 group"
          >
            <ScrollText
              size={22}
              className="text-emerald-400 group-hover:scale-110 transition-transform"
              aria-hidden="true"
            />
            <span>View Audit Logs</span>
          </Button>
        </div>
      </section>

      {/* Info card */}
      <section>
        <Card className="border-primary/20">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-foreground">
                Getting started
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                Explore users, roles, and permissions to manage your identity
                infrastructure.
              </p>
            </div>
            <Button
              onClick={() => navigate("/users")}
              size="sm"
              className="shrink-0 ml-4"
            >
              Get started
              <ArrowRight size={14} aria-hidden="true" />
            </Button>
          </div>
        </Card>
      </section>
    </div>
  );
}
