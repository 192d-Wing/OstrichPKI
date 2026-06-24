import { useQuery } from "@tanstack/react-query";
import {
  ClipboardCheck,
  CreditCard,
  FileCheck,
  FileText,
  Plus,
  ShieldCheck,
  ShieldX,
  Clock,
  type LucideIcon,
} from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchCertificates, type CertificateStatus } from "@/lib/ca";
import { cn } from "@/lib/utils";

function StatCard({
  title,
  value,
  sub,
  icon: Icon,
  tint,
}: {
  title: string;
  value: string;
  sub: string;
  icon: LucideIcon;
  tint: string;
}) {
  return (
    <Card className="transition-shadow hover:shadow-md">
      <CardContent className="flex items-center gap-4 p-6">
        <div
          className={cn(
            "flex size-12 shrink-0 items-center justify-center rounded-full",
            tint,
          )}
        >
          <Icon className="size-6" />
        </div>
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {title}
          </p>
          <p className="text-3xl font-bold tracking-tight">{value}</p>
          <p className="text-xs text-muted-foreground">{sub}</p>
        </div>
      </CardContent>
    </Card>
  );
}

const QUICK_ACTIONS: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/certificates", label: "Certificates", icon: Plus },
  { to: "/approvals", label: "Review Approvals", icon: ClipboardCheck },
  { to: "/audit", label: "View Audit Logs", icon: FileText },
  { to: "/scms", label: "Manage Tokens", icon: CreditCard },
];

export function DashboardPage() {
  // No dedicated stats endpoint yet: derive headline counts from the real
  // certificate inventory (same approach as the Yew dashboard). Trend/expiry/
  // approval metrics are left at zero until backing endpoints exist — better
  // empty than fabricated.
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard-certs"],
    queryFn: () => fetchCertificates("page=1&pageSize=1000"),
  });

  const count = (status: CertificateStatus) =>
    data?.certificates.filter((c) => c.status === status).length ?? 0;
  const fmt = (n: number) => (isLoading ? "…" : isError ? "—" : n.toLocaleString());

  return (
    <div className="mx-auto max-w-6xl space-y-8 p-6">
      <PageHeader
        title="Dashboard"
        description="Overview of the certificate inventory."
      />

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Active Certificates"
          value={fmt(count("active"))}
          sub="Currently valid"
          icon={ShieldCheck}
          tint="bg-blue-500/10 text-blue-600 dark:text-blue-400"
        />
        <StatCard
          title="Pending Approvals"
          value={fmt(0)}
          sub="No backing endpoint yet"
          icon={ClipboardCheck}
          tint="bg-yellow-500/10 text-yellow-600 dark:text-yellow-400"
        />
        <StatCard
          title="Expiring Soon"
          value={fmt(0)}
          sub="Within 30 days"
          icon={Clock}
          tint="bg-orange-500/10 text-orange-600 dark:text-orange-400"
        />
        <StatCard
          title="Revoked Certificates"
          value={fmt(count("revoked"))}
          sub="Total revoked"
          icon={ShieldX}
          tint="bg-red-500/10 text-red-600 dark:text-red-400"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {QUICK_ACTIONS.map((a) => (
                <Link
                  key={a.to}
                  to={a.to}
                  className="flex items-center gap-2 rounded-md border p-3 text-sm font-medium hover:bg-accent"
                >
                  <a.icon className="size-4 text-muted-foreground" />
                  {a.label}
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-lg">Recent Activity</CardTitle>
            <Link to="/audit" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <FileCheck className="size-4" />
              No recent activity to show.
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
