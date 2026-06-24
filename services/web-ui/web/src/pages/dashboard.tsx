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
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="mt-1 text-2xl font-bold">{value}</p>
          <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
        </div>
        <div className={cn("rounded-md p-2", tint)}>
          <Icon className="size-6" />
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
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Overview of the certificate inventory.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Active Certificates"
          value={fmt(count("active"))}
          sub="Currently valid"
          icon={ShieldCheck}
          tint="bg-blue-100 text-blue-700"
        />
        <StatCard
          title="Pending Approvals"
          value={fmt(0)}
          sub="No backing endpoint yet"
          icon={ClipboardCheck}
          tint="bg-yellow-100 text-yellow-700"
        />
        <StatCard
          title="Expiring Soon"
          value={fmt(0)}
          sub="Within 30 days"
          icon={Clock}
          tint="bg-orange-100 text-orange-700"
        />
        <StatCard
          title="Revoked Certificates"
          value={fmt(count("revoked"))}
          sub="Total revoked"
          icon={ShieldX}
          tint="bg-red-100 text-red-700"
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
