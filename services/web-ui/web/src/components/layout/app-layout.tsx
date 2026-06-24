import {
  Ban,
  ClipboardCheck,
  CreditCard,
  FileCheck,
  FileText,
  LayoutTemplate,
  LogOut,
  Server,
  Settings as SettingsIcon,
  SquareStack,
  Users,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { displayName, logoutUrl } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  permission: string | null;
}

// Mirrors the Yew sidebar (services/web-ui/src/client/components/layout/
// sidebar.rs): same labels, routes, and permission gates.
const NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: SquareStack, permission: null },
  { to: "/certificates", label: "Certificates", icon: FileCheck, permission: "view_certificates" },
  { to: "/crl", label: "Revocation Lists", icon: Ban, permission: "view_crl" },
  { to: "/profiles", label: "Profiles", icon: LayoutTemplate, permission: "view_config" },
  { to: "/est", label: "EST", icon: Server, permission: "generate_est_token" },
  { to: "/approvals", label: "Approvals", icon: ClipboardCheck, permission: "view_approvals" },
  { to: "/audit", label: "Audit Logs", icon: FileText, permission: "read_audit_log" },
  { to: "/scms", label: "Tokens", icon: CreditCard, permission: "view_tokens" },
  { to: "/users", label: "Users", icon: Users, permission: "manage_users" },
  { to: "/settings", label: "Settings", icon: SettingsIcon, permission: "view_config" },
];

export function AppLayout() {
  const { user, can } = useAuth();
  const items = NAV.filter((n) => !n.permission || can(n.permission));

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r bg-card">
        <div className="flex h-14 items-center px-4 text-lg font-semibold">
          OstrichPKI
        </div>
        <nav className="flex-1 space-y-1 overflow-auto p-2">
          {items.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium",
                  isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                )
              }
            >
              <n.icon className="size-4" />
              {n.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-end gap-3 border-b bg-card px-4">
          <span className="text-sm text-muted-foreground">{displayName(user)}</span>
          <Button asChild variant="outline" size="sm">
            <a href={logoutUrl()}>
              <LogOut className="size-4" />
              Logout
            </a>
          </Button>
        </header>
        <main className="flex-1 overflow-auto bg-muted/20">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
