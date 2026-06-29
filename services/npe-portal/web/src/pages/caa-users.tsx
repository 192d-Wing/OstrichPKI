import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ButtonDropdown,
  Container,
  ContentLayout,
  Form,
  FormField,
  Header,
  Input,
  Modal,
  Multiselect,
  type MultiselectProps,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { ASSIGNABLE_ROLES, portalApi, type PortalUser } from "@/lib/portal-api";

const ROLE_OPTIONS: MultiselectProps.Option[] = ASSIGNABLE_ROLES.map((r) => ({
  label: r.label,
  value: r.value,
}));

function roleLabel(value: string): string {
  return ASSIGNABLE_ROLES.find((r) => r.value === value)?.label ?? value;
}

export function CaaUsersPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["caa-users"],
    queryFn: portalApi.listUsers,
  });

  const [banner, setBanner] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Create form state.
  const [username, setUsername] = useState("");
  const [certSubject, setCertSubject] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [newRoles, setNewRoles] = useState<readonly MultiselectProps.Option[]>([]);
  const [createError, setCreateError] = useState<string | null>(null);

  // Edit-roles modal state.
  const [editing, setEditing] = useState<PortalUser | null>(null);
  const [editRoles, setEditRoles] = useState<readonly MultiselectProps.Option[]>([]);
  const [editError, setEditError] = useState<string | null>(null);

  function onMutationError(e: Error) {
    setBanner({ type: "error", text: e.message });
  }
  function afterChange(text: string) {
    setBanner({ type: "success", text });
    refetch();
  }

  const create = useMutation({
    mutationFn: () =>
      portalApi.createUser({
        username: username.trim(),
        certificateSubject: certSubject.trim(),
        displayName: displayName.trim() || undefined,
        email: email.trim() || undefined,
        roles: newRoles.map((o) => String(o.value)),
      }),
    onSuccess: (u) => {
      setUsername("");
      setCertSubject("");
      setDisplayName("");
      setEmail("");
      setNewRoles([]);
      setCreateError(null);
      afterChange(`Created user ${u.username}.`);
    },
    onError: (e: Error) => setCreateError(e.message),
  });

  const saveRoles = useMutation({
    mutationFn: () =>
      portalApi.setUserRoles(editing!.id, editRoles.map((o) => String(o.value))),
    onSuccess: (u) => {
      setEditing(null);
      afterChange(`Updated roles for ${u.username}.`);
    },
    onError: (e: Error) => setEditError(e.message),
  });

  const setStatus = useMutation({
    mutationFn: (v: { id: string; status: string }) => portalApi.setUserStatus(v.id, v.status),
    onSuccess: (u) => afterChange(`${u.username} is now ${u.status}.`),
    onError: onMutationError,
  });

  const remove = useMutation({
    mutationFn: (id: string) => portalApi.deleteUser(id),
    onSuccess: () => afterChange("User deleted."),
    onError: onMutationError,
  });

  function openEdit(u: PortalUser) {
    setEditing(u);
    setEditError(null);
    setEditRoles(
      u.roles
        .filter((r) => ASSIGNABLE_ROLES.some((a) => a.value === r))
        .map((r) => ({ label: roleLabel(r), value: r })),
    );
  }

  function onCreate() {
    if (!username.trim() || !certSubject.trim()) {
      setCreateError("Username and certificate subject are required.");
      return;
    }
    create.mutate();
  }

  const items = data ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Manage portal user accounts and role assignments."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          Manage Users &amp; Roles
        </Header>
      }
    >
      <SpaceBetween size="l">
        {banner && (
          <Alert
            type={banner.type}
            dismissible
            onDismiss={() => setBanner(null)}
            header={banner.type === "success" ? "Done" : "Action failed"}
          >
            {banner.text}
          </Alert>
        )}
        {isError && (
          <Alert type="error" header="Could not load users">
            {error?.message ?? "Request failed."}
          </Alert>
        )}

        <Table<PortalUser>
          loading={isLoading}
          items={items}
          variant="container"
          wrapLines
          columnDefinitions={[
            { id: "username", header: "Username", cell: (u) => u.username },
            {
              id: "roles",
              header: "Roles",
              cell: (u) => u.roles.map(roleLabel).join(", ") || "-",
            },
            { id: "status", header: "Status", cell: (u) => <StatusBadge status={u.status} /> },
            { id: "cert", header: "Certificate subject", cell: (u) => u.certificateSubject ?? "-" },
            {
              id: "actions",
              header: "",
              cell: (u) => (
                <ButtonDropdown
                  ariaLabel={`Manage ${u.username}`}
                  items={[
                    { id: "roles", text: "Edit roles" },
                    u.status === "active"
                      ? { id: "disable", text: "Disable" }
                      : { id: "enable", text: "Enable" },
                    { id: "delete", text: "Delete" },
                  ]}
                  onItemClick={(e) => {
                    if (e.detail.id === "roles") openEdit(u);
                    else if (e.detail.id === "disable") setStatus.mutate({ id: u.id, status: "disabled" });
                    else if (e.detail.id === "enable") setStatus.mutate({ id: u.id, status: "active" });
                    else if (e.detail.id === "delete") remove.mutate(u.id);
                  }}
                >
                  Manage
                </ButtonDropdown>
              ),
            },
          ]}
          empty="No users"
        />

        <Container header={<Header variant="h2">Create user</Header>}>
          <Form
            actions={
              <Button variant="primary" onClick={onCreate} loading={create.isPending}>
                Create user
              </Button>
            }
          >
            <SpaceBetween size="l">
              {createError && <Alert type="error">{createError}</Alert>}
              <FormField label="Username">
                <Input value={username} onChange={(e) => setUsername(e.detail.value)} />
              </FormField>
              <FormField
                label="Certificate subject DN"
                description="The mTLS certificate subject this account authenticates with."
              >
                <Input value={certSubject} onChange={(e) => setCertSubject(e.detail.value)} />
              </FormField>
              <FormField label="Display name (optional)">
                <Input value={displayName} onChange={(e) => setDisplayName(e.detail.value)} />
              </FormField>
              <FormField label="Email (optional)">
                <Input value={email} onChange={(e) => setEmail(e.detail.value)} type="email" />
              </FormField>
              <FormField label="Roles">
                <Multiselect
                  selectedOptions={newRoles}
                  onChange={(e) => setNewRoles(e.detail.selectedOptions)}
                  options={ROLE_OPTIONS}
                  placeholder="Choose roles"
                />
              </FormField>
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          onDismiss={() => setEditing(null)}
          header={`Edit roles for ${editing.username}`}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)} disabled={saveRoles.isPending}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={() => saveRoles.mutate()} loading={saveRoles.isPending}>
                  Save roles
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {editError && <Alert type="error">{editError}</Alert>}
            <FormField label="Roles">
              <Multiselect
                selectedOptions={editRoles}
                onChange={(e) => setEditRoles(e.detail.selectedOptions)}
                options={ROLE_OPTIONS}
                placeholder="Choose roles"
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
