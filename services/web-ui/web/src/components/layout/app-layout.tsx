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
  Shield,
  SquareStack,
  Users,
  type LucideIcon,
} from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { displayName, logoutUrl } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { config } from "@/lib/config";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  permission: string | null;
}

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

function initials(name: string): string {
  const parts = name.split(/[.\s@_-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").concat(parts[1]?.[0] ?? "").toUpperCase();
}

export function AppLayout() {
  const { user, can } = useAuth();
  const location = useLocation();
  const items = NAV.filter((n) => !n.permission || can(n.permission));
  const name = displayName(user);

  // Page title from the active nav item (longest path-prefix match).
  const active = [...NAV]
    .sort((a, b) => b.to.length - a.to.length)
    .find((n) => location.pathname.startsWith(n.to));
  const title = active?.label ?? "OstrichPKI";

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="flex w-64 shrink-0 flex-col border-r bg-card">
        <div className="flex h-16 items-center gap-2 border-b px-5">
          <div className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Shield className="size-5" />
          </div>
          <span className="text-lg font-semibold tracking-tight">OstrichPKI</span>
        </div>
        <nav className="flex-1 space-y-1 overflow-auto p-3">
          {items.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )
              }
            >
              <n.icon className="size-4 shrink-0" />
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t px-5 py-3 text-xs text-muted-foreground">
          v{config.version}
        </div>
      </aside>

      <div className="flex flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center justify-between border-b bg-card/80 px-6 backdrop-blur">
          <h1 className="text-lg font-semibold">{title}</h1>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2 px-2">
                  <span className="flex size-8 items-center justify-center rounded-full bg-primary/10 text-sm font-semibold text-primary">
                    {initials(name)}
                  </span>
                  <span className="hidden text-sm font-medium sm:inline">
                    {name}
                  </span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">{name}</span>
                    <span className="text-xs font-normal text-muted-foreground">
                      {user?.roles.join(", ") || "—"}
                    </span>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => {
                    window.location.href = logoutUrl();
                  }}
                >
                  <LogOut className="size-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
