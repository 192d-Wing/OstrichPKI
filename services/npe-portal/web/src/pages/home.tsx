import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Button,
  Checkbox,
  ColumnLayout,
  Container,
  ContentLayout,
  Header,
  KeyValuePairs,
  Link,
  Modal,
  SpaceBetween,
} from "@cloudscape-design/components";

import { hasPermission, primaryRole, roleLabel } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import { portalApi } from "@/lib/portal-api";

interface DashboardData {
  total: number;
  active: number;
  revoked: number;
  expired: number;
  expiringSoon: number;
  pending: number;
}

interface WidgetDef {
  id: string;
  label: string;
  value: (d: DashboardData) => number;
  href: string;
}

// Available dashboard widgets. Visibility is user-configurable (persisted
// client-side); the underlying counts are own-scoped for Sponsors.
const WIDGETS: readonly WidgetDef[] = [
  { id: "issued", label: "Issued Certificates", value: (d) => d.total, href: "/search" },
  { id: "active", label: "Active", value: (d) => d.active, href: "/search" },
  {
    id: "expiring",
    label: "Expiring in 90 Days",
    value: (d) => d.expiringSoon,
    href: "/certificates/expiring",
  },
  {
    id: "pending",
    label: "Pending Approval",
    value: (d) => d.pending,
    href: "/certificates/mine",
  },
  { id: "revoked", label: "Revoked", value: (d) => d.revoked, href: "/search" },
  { id: "expired", label: "Expired", value: (d) => d.expired, href: "/search" },
];

const PREF_KEY = "npe.dashboard.widgets";
const DEFAULT_VISIBLE = WIDGETS.map((w) => w.id);

function loadVisible(): string[] {
  try {
    const raw = globalThis.localStorage?.getItem(PREF_KEY);
    if (!raw) return DEFAULT_VISIBLE;
    const ids = JSON.parse(raw) as string[];
    // Keep only known widget ids, preserving the canonical order.
    return WIDGETS.filter((w) => ids.includes(w.id)).map((w) => w.id);
  } catch {
    return DEFAULT_VISIBLE;
  }
}

function MetricCard({
  label,
  value,
  loading,
  href,
}: Readonly<{ label: string; value: number; loading: boolean; href: string }>) {
  const navigate = useNavigate();
  return (
    <Container>
      <SpaceBetween size="xs">
        <Box variant="awsui-key-label">{label}</Box>
        <Box fontSize="display-l" fontWeight="bold">
          {loading ? "—" : value.toLocaleString()}
        </Box>
        <Link
          onFollow={(e) => {
            e.preventDefault();
            navigate(href);
          }}
        >
          View
        </Link>
      </SpaceBetween>
    </Container>
  );
}

export function HomePage() {
  const { user } = useAuth();
  const role = primaryRole(user);

  const [visible, setVisible] = useState<string[]>(loadVisible);
  const [customizing, setCustomizing] = useState(false);

  const canViewCerts = hasPermission(user, "view_certificate");

  const stats = useQuery({
    queryKey: ["certificate-stats"],
    queryFn: () => portalApi.certificateStats(),
    enabled: canViewCerts,
    staleTime: 60_000,
  });

  // Pending approval count comes from the approvals listing (own requests for a
  // Sponsor; the review queue for an RA).
  const approvals = useQuery({
    queryKey: ["approvals-pending"],
    queryFn: () => portalApi.listApprovalQueue(),
    staleTime: 60_000,
  });

  const data: DashboardData = useMemo(
    () => ({
      total: stats.data?.total ?? 0,
      active: stats.data?.active ?? 0,
      revoked: stats.data?.revoked ?? 0,
      expired: stats.data?.expired ?? 0,
      expiringSoon: stats.data?.expiringSoon ?? 0,
      pending:
        approvals.data?.requests.filter((r) => r.status === "pending").length ?? 0,
    }),
    [stats.data, approvals.data],
  );

  const shownWidgets = WIDGETS.filter((w) => visible.includes(w.id));
  const loading = stats.isLoading || approvals.isLoading;

  function toggle(id: string, checked: boolean) {
    const next = checked
      ? WIDGETS.filter((w) => visible.includes(w.id) || w.id === id).map((w) => w.id)
      : visible.filter((v) => v !== id);
    setVisible(next);
    globalThis.localStorage?.setItem(PREF_KEY, JSON.stringify(next));
  }

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Non-Person Entity certificate enrollment portal">
          Welcome
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container
          header={
            <Header
              variant="h2"
              actions={
                <Button iconName="settings" onClick={() => setCustomizing(true)}>
                  Customize
                </Button>
              }
            >
              Certificate overview
            </Header>
          }
        >
          {shownWidgets.length === 0 ? (
            <Box color="text-status-inactive">
              No widgets selected. Use <strong>Customize</strong> to add some.
            </Box>
          ) : (
            <ColumnLayout columns={3} variant="text-grid">
              {shownWidgets.map((w) => (
                <MetricCard
                  key={w.id}
                  label={w.label}
                  value={w.value(data)}
                  loading={loading}
                  href={w.href}
                />
              ))}
            </ColumnLayout>
          )}
        </Container>

        <Container header={<Header variant="h2">Your identity</Header>}>
          <KeyValuePairs
            columns={3}
            items={[
              { label: "Common Name", value: user?.commonName ?? "-" },
              { label: "Role", value: roleLabel(role) },
              { label: "Subject DN", value: user?.subjectDn ?? "-" },
            ]}
          />
        </Container>
        <Container header={<Header variant="h2">Getting started</Header>}>
          Use the navigation menu to submit certificate applications, manage EST enrollment
          passwords, or search your records. Available menus depend on your certificate role.
        </Container>
      </SpaceBetween>

      <Modal
        visible={customizing}
        onDismiss={() => setCustomizing(false)}
        header="Customize dashboard"
        footer={
          <Box float="right">
            <Button variant="primary" onClick={() => setCustomizing(false)}>
              Done
            </Button>
          </Box>
        }
      >
        <SpaceBetween size="s">
          <Box color="text-status-inactive">Choose which overview cards to show.</Box>
          {WIDGETS.map((w) => (
            <Checkbox
              key={w.id}
              checked={visible.includes(w.id)}
              onChange={(e) => toggle(w.id, e.detail.checked)}
            >
              {w.label}
            </Checkbox>
          ))}
        </SpaceBetween>
      </Modal>
    </ContentLayout>
  );
}
