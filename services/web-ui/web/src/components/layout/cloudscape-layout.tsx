import * as React from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import AppLayout from "@cloudscape-design/components/app-layout";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Spinner from "@cloudscape-design/components/spinner";
import SideNavigation, {
  type SideNavigationProps,
} from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";

import { useTheme } from "@/components/theme-provider";
import { displayName, logoutUrl } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

interface NavItem {
  to: string;
  label: string;
  permission: string | null;
}

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  { label: "Overview", items: [{ to: "/dashboard", label: "Dashboard", permission: null }] },
  {
    label: "Certificates",
    items: [
      { to: "/certificates", label: "Certificates", permission: "view_certificates" },
      { to: "/profiles", label: "Profiles", permission: "view_config" },
      { to: "/crl", label: "Revocation Lists", permission: "view_crl" },
    ],
  },
  {
    label: "Enrollment",
    items: [
      { to: "/est", label: "EST", permission: "generate_est_token" },
      { to: "/approvals", label: "Approvals", permission: "view_approvals" },
      { to: "/scms", label: "Tokens", permission: "view_tokens" },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/audit", label: "Audit Logs", permission: "read_audit_log" },
      { to: "/users", label: "Users", permission: "manage_users" },
      { to: "/settings", label: "System", permission: "admin" },
    ],
  },
];

const ALL_ITEMS = NAV_GROUPS.flatMap((g) =>
  g.items.map((i) => ({ ...i, group: g.label })),
);

export function CloudscapeLayout() {
  const { user, can } = useAuth();
  const { theme, setTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = React.useState(true);
  const name = displayName(user);

  // Client-side navigation for any Cloudscape link/breadcrumb follow.
  const follow = (e: CustomEvent<{ href?: string; external?: boolean }>) => {
    if (e.detail.href && !e.detail.external) {
      e.preventDefault();
      navigate(e.detail.href);
    }
  };

  const navItems: SideNavigationProps.Item[] = NAV_GROUPS.flatMap((g) => {
    const links = g.items
      .filter((i) => !i.permission || can(i.permission))
      .map<SideNavigationProps.Item>((i) => ({
        type: "link",
        text: i.label,
        href: i.to,
      }));
    return links.length
      ? [{ type: "section", text: g.label, items: links }]
      : [];
  });

  const active = [...ALL_ITEMS]
    .sort((a, b) => b.to.length - a.to.length)
    .find((n) => location.pathname.startsWith(n.to));

  const crumbs = active
    ? [
        { text: active.group, href: active.to },
        { text: active.label, href: location.pathname },
      ]
    : [{ text: "OstrichPKI", href: "/dashboard" }];

  return (
    <>
      <div id="top-nav">
        <TopNavigation
          identity={{ href: "/dashboard", title: "OstrichPKI", onFollow: follow }}
          utilities={[
            {
              type: "menu-dropdown",
              text: `Theme: ${theme}`,
              iconName: "settings",
              ariaLabel: "Theme",
              items: [
                { id: "light", text: "Light" },
                { id: "dark", text: "Dark" },
                { id: "system", text: "System" },
              ],
              onItemClick: (e) =>
                setTheme(e.detail.id as "light" | "dark" | "system"),
            },
            {
              type: "menu-dropdown",
              text: name,
              iconName: "user-profile",
              description: user?.roles.join(", ") || undefined,
              items: [{ id: "logout", text: "Log out" }],
              onItemClick: (e) => {
                if (e.detail.id === "logout") window.location.href = logoutUrl();
              },
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        toolsHide
        navigationOpen={navOpen}
        onNavigationChange={(e) => setNavOpen(e.detail.open)}
        navigation={
          <SideNavigation
            activeHref={active?.to}
            header={{ href: "/dashboard", text: "OstrichPKI" }}
            items={navItems}
            onFollow={follow}
          />
        }
        breadcrumbs={<BreadcrumbGroup items={crumbs} onFollow={follow} />}
        content={
          <React.Suspense
            fallback={
              <div style={{ display: "flex", justifyContent: "center", padding: "2rem" }}>
                <Spinner size="large" />
              </div>
            }
          >
            <Outlet />
          </React.Suspense>
        }
      />
    </>
  );
}
