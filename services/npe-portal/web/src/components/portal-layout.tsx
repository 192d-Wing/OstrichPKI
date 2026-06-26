import { type ReactNode, useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  AppLayout,
  SideNavigation,
  type SideNavigationProps,
  TopNavigation,
} from "@cloudscape-design/components";

import { ClassificationBanner } from "@/components/classification-banner";
import { config } from "@/lib/config";
import { logout, primaryRole, roleLabel } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { navGroupsForUser } from "@/lib/navigation";

async function handleOptionClick(id: string) {
  if (id === "logout") {
    await logout();
    globalThis.location.assign("/");
  }
}

export function PortalLayout({ children }: Readonly<{ children: ReactNode }>) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const role = primaryRole(user);
  // The CAA/RA/Administrator dropdown carries a Preferences item; a plain
  // Sponsor does not (NPE portal requirements §3).
  const showPreferences = role !== "pki_sponsor";

  const navItems: SideNavigationProps.Item[] = useMemo(
    () =>
      navGroupsForUser(user).map((group) => ({
        type: "section",
        text: group.text,
        items: group.items.map((link) => ({
          type: "link",
          text: link.text,
          href: link.href,
        })),
      })),
    [user],
  );

  const optionItems = [
    { id: "about", text: "About" },
    ...(showPreferences ? [{ id: "preferences", text: "Preferences..." }] : []),
    { id: "user-guide", text: "User Guide", href: "/user-guide", external: true },
    {
      id: "cyber-exchange",
      text: "DoD Cyber Exchange",
      href: "https://cyber.mil/",
      external: true,
    },
    { id: "logout", text: "Logout" },
  ];

  return (
    <>
      <ClassificationBanner />
      <TopNavigation
        identity={{
          href: "/",
          title: config.appName,
          onFollow: (e) => {
            e.preventDefault();
            navigate("/");
          },
        }}
        utilities={[
          {
            type: "button",
            text: "NPE System Status: UP",
            iconName: "status-positive",
          },
          {
            type: "menu-dropdown",
            text: user ? `Logged in as: ${user.commonName}` : "Not signed in",
            description: role ? roleLabel(role) : undefined,
            iconName: "user-profile",
            items: optionItems,
            onItemClick: (e) => {
              handleOptionClick(e.detail.id).catch(() => {});
            },
          },
        ]}
      />
      <AppLayout
        toolsHide
        navigation={
          <SideNavigation
            activeHref={location.pathname}
            header={{ href: "/", text: "NPE Portal" }}
            items={navItems}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                navigate(e.detail.href);
              }
            }}
          />
        }
        content={children}
      />
      <ClassificationBanner />
    </>
  );
}
