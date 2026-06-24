import * as React from "react";
import {
  Ban,
  ChevronRight,
  ClipboardCheck,
  CreditCard,
  FileCheck,
  FileText,
  LayoutTemplate,
  LogOut,
  PanelLeft,
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

// Grouped navigation. Same labels/routes/perms as before, organized into
// sections for a clearer information architecture.
const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Overview",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: SquareStack, permission: null },
    ],
  },
  {
    label: "Certificates",
    items: [
      { to: "/certificates", label: "Certificates", icon: FileCheck, permission: "view_certificates" },
      { to: "/profiles", label: "Profiles", icon: LayoutTemplate, permission: "view_config" },
      { to: "/crl", label: "Revocation Lists", icon: Ban, permission: "view_crl" },
    ],
  },
  {
    label: "Enrollment",
    items: [
      { to: "/est", label: "EST", icon: Server, permission: "generate_est_token" },
      { to: "/approvals", label: "Approvals", icon: ClipboardCheck, permission: "view_approvals" },
      { to: "/scms", label: "Tokens", icon: CreditCard, permission: "view_tokens" },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/audit", label: "Audit Logs", icon: FileText, permission: "read_audit_log" },
      { to: "/users", label: "Users", icon: Users, permission: "manage_users" },
      { to: "/settings", label: "System", icon: SettingsIcon, permission: "admin" },
    ],
  },
];

const ALL_ITEMS = NAV_GROUPS.flatMap((g) =>
  g.items.map((i) => ({ ...i, group: g.label })),
);

const COLLAPSE_KEY = "ostrich-sidebar-collapsed";

function initials(name: string): string {
  const parts = name.split(/[.\s@_-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").concat(parts[1]?.[0] ?? "").toUpperCase();
}

export function AppLayout() {
  const { user, can } = useAuth();
  const location = useLocation();
  const name = displayName(user);

  const [collapsed, setCollapsed] = React.useState(
    () => localStorage.getItem(COLLAPSE_KEY) === "1",
  );
  const toggle = () => {
    setCollapsed((c) => {
      localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      return !c;
    });
  };

  // Breadcrumb: the active nav item (longest path-prefix match) + its group.
  const active = [...ALL_ITEMS]
    .sort((a, b) => b.to.length - a.to.length)
    .find((n) => location.pathname.startsWith(n.to));

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside
        className={cn(
          "flex shrink-0 flex-col border-r bg-card transition-[width] duration-200",
          collapsed ? "w-16" : "w-64",
        )}
      >
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Shield className="size-5" />
          </div>
          {!collapsed && (
            <span className="truncate text-lg font-semibold tracking-tight">
              OstrichPKI
            </span>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto size-8"
            onClick={toggle}
            aria-label="Toggle sidebar"
          >
            <PanelLeft className="size-4" />
          </Button>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto p-2">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter(
              (n) => !n.permission || can(n.permission),
            );
            if (items.length === 0) return null;
            return (
              <div key={group.label} className="space-y-1">
                {!collapsed && (
                  <p className="px-3 pb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground/70">
                    {group.label}
                  </p>
                )}
                {items.map((n) => (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    title={collapsed ? n.label : undefined}
                    className={({ isActive }) =>
                      cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                        collapsed && "justify-center px-0",
                        isActive
                          ? "bg-primary/10 text-primary"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      )
                    }
                  >
                    <n.icon className="size-4 shrink-0" />
                    {!collapsed && n.label}
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>

        {!collapsed && (
          <div className="border-t px-4 py-3 text-xs text-muted-foreground">
            v{config.version}
          </div>
        )}
      </aside>

      <div className="flex flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center justify-between border-b bg-card/80 px-6 backdrop-blur">
          <nav className="flex items-center gap-1.5 text-sm">
            <span className="text-muted-foreground">{active?.group ?? "OstrichPKI"}</span>
            <ChevronRight className="size-4 text-muted-foreground/50" />
            <span className="font-semibold">{active?.label ?? "OstrichPKI"}</span>
          </nav>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2 px-2">
                  <span className="flex size-8 items-center justify-center rounded-full bg-primary/10 text-sm font-semibold text-primary">
                    {initials(name)}
                  </span>
                  <span className="hidden text-sm font-medium sm:inline">{name}</span>
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
