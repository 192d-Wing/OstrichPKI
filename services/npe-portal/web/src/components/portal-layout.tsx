import { type ReactNode, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  AppLayout,
  Box,
  Button,
  ColumnLayout,
  Modal,
  SideNavigation,
  type SideNavigationProps,
  SpaceBetween,
  Toggle,
  TopNavigation,
} from "@cloudscape-design/components";
import {
  applyDensity,
  applyMode,
  Density,
  Mode,
} from "@cloudscape-design/global-styles";

import { ClassificationBanner } from "@/components/classification-banner";
import { config } from "@/lib/config";
import { logout, primaryRole, roleLabel } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { navGroupsForUser } from "@/lib/navigation";

// Display preferences persist client-side only (presentation, no server state).
const PREF_DENSITY = "npe.pref.density";
const PREF_MODE = "npe.pref.mode";

function prefIsCompact(): boolean {
  return globalThis.localStorage?.getItem(PREF_DENSITY) === "compact";
}
function prefIsDark(): boolean {
  return globalThis.localStorage?.getItem(PREF_MODE) === "dark";
}

async function doLogout() {
  await logout();
  globalThis.location.assign("/");
}

export function PortalLayout({ children }: Readonly<{ children: ReactNode }>) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const role = primaryRole(user);
  // The CAA/RA/Administrator dropdown carries a Preferences item; a plain
  // Sponsor does not (NPE portal requirements §3).
  const showPreferences = role !== "pki_sponsor";

  const [activeModal, setActiveModal] = useState<null | "about" | "preferences">(
    null,
  );
  const [compact, setCompact] = useState(prefIsCompact);
  const [dark, setDark] = useState(prefIsDark);

  // Apply the display preferences on mount and whenever they change.
  useEffect(() => {
    applyDensity(compact ? Density.Compact : Density.Comfortable);
  }, [compact]);
  useEffect(() => {
    applyMode(dark ? Mode.Dark : Mode.Light);
  }, [dark]);

  function changeCompact(value: boolean) {
    setCompact(value);
    globalThis.localStorage?.setItem(
      PREF_DENSITY,
      value ? "compact" : "comfortable",
    );
  }
  function changeDark(value: boolean) {
    setDark(value);
    globalThis.localStorage?.setItem(PREF_MODE, value ? "dark" : "light");
  }

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
              const id = e.detail.id;
              if (id === "about") {
                setActiveModal("about");
              } else if (id === "preferences") {
                setActiveModal("preferences");
              } else if (id === "logout") {
                doLogout().catch(() => {});
              }
              // user-guide / cyber-exchange follow their href (external).
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

      <Modal
        visible={activeModal === "about"}
        onDismiss={() => setActiveModal(null)}
        header="About"
        footer={
          <Box float="right">
            <Button variant="primary" onClick={() => setActiveModal(null)}>
              Close
            </Button>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">{config.appName}</Box>
          <ColumnLayout columns={2} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Version</Box>
              <div>{config.version}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">Classification</Box>
              <div>{config.classificationBanner}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">Signed in as</Box>
              <div>{user?.commonName ?? "—"}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">Role</Box>
              <div>{role ? roleLabel(role) : "—"}</div>
            </div>
          </ColumnLayout>
          {user?.subjectDn ? (
            <div>
              <Box variant="awsui-key-label">Certificate subject</Box>
              <Box variant="code">{user.subjectDn}</Box>
            </div>
          ) : null}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={activeModal === "preferences"}
        onDismiss={() => setActiveModal(null)}
        header="Preferences"
        footer={
          <Box float="right">
            <Button variant="primary" onClick={() => setActiveModal(null)}>
              Done
            </Button>
          </Box>
        }
      >
        <SpaceBetween size="l">
          <Toggle
            checked={compact}
            onChange={(e) => changeCompact(e.detail.checked)}
          >
            Compact density
          </Toggle>
          <Toggle checked={dark} onChange={(e) => changeDark(e.detail.checked)}>
            Dark mode
          </Toggle>
        </SpaceBetween>
      </Modal>
    </>
  );
}
