import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Container,
  ContentLayout,
  Form,
  FormField,
  Header,
  Input,
  Modal,
  Select,
  type SelectProps,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { portalApi, type Namespace } from "@/lib/portal-api";

const EFFECTS: SelectProps.Option[] = [
  { label: "Allow", value: "allow" },
  { label: "Deny", value: "deny" },
];

export function CaaNamespacesPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["caa-namespaces"],
    queryFn: portalApi.listNamespaces,
  });

  const [pattern, setPattern] = useState("");
  const [effect, setEffect] = useState<SelectProps.Option>(EFFECTS[0]);
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      portalApi.createNamespace({
        pattern: pattern.trim(),
        allow: effect.value === "allow",
        description: description.trim() || undefined,
      }),
    onSuccess: () => {
      setPattern("");
      setDescription("");
      setFormError(null);
      refetch();
    },
    onError: (e: Error) => setFormError(e.message),
  });

  const [deleteTarget, setDeleteTarget] = useState<Namespace | null>(null);
  const remove = useMutation({
    mutationFn: (id: string) => portalApi.deleteNamespace(id),
    onSuccess: () => {
      setDeleteTarget(null);
      refetch();
    },
    onError: () => setDeleteTarget(null),
  });

  function onCreate() {
    if (!pattern.trim()) {
      setFormError("Enter a DNS pattern.");
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
          description="Allow or deny issuance for names matching DNS patterns (e.g. *.example.mil)."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          Namespaces &amp; Wildcards
        </Header>
      }
    >
      <SpaceBetween size="l">
        {isError && (
          <Alert type="error" header="Could not load namespaces">
            {error?.message ?? "Request failed."}
          </Alert>
        )}

        <Table<Namespace>
          loading={isLoading}
          items={items}
          variant="container"
          wrapLines
          columnDefinitions={[
            { id: "pattern", header: "Pattern", cell: (n) => n.pattern },
            { id: "effect", header: "Effect", cell: (n) => (n.allow ? "Allow" : "Deny") },
            { id: "description", header: "Description", cell: (n) => n.description ?? "-" },
            { id: "createdBy", header: "Created by", cell: (n) => n.createdBy },
            {
              id: "actions",
              header: "",
              cell: (n) => <Button onClick={() => setDeleteTarget(n)}>Delete</Button>,
            },
          ]}
          empty="No namespace rules"
        />

        <Container header={<Header variant="h2">Add rule</Header>}>
          <Form
            actions={
              <Button variant="primary" onClick={onCreate} loading={create.isPending}>
                Add rule
              </Button>
            }
          >
            <SpaceBetween size="l">
              {formError && <Alert type="error">{formError}</Alert>}
              <FormField label="DNS pattern" description="An exact name or a leading-* wildcard.">
                <Input
                  value={pattern}
                  onChange={(e) => setPattern(e.detail.value)}
                  placeholder="*.example.mil"
                />
              </FormField>
              <FormField label="Effect">
                <Select
                  selectedOption={effect}
                  onChange={(e) => setEffect(e.detail.selectedOption)}
                  options={EFFECTS}
                />
              </FormField>
              <FormField label="Description (optional)">
                <Input value={description} onChange={(e) => setDescription(e.detail.value)} />
              </FormField>
            </SpaceBetween>
          </Form>
        </Container>
      </SpaceBetween>

      {deleteTarget && (
        <Modal
          visible
          onDismiss={() => setDeleteTarget(null)}
          header="Delete namespace rule"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setDeleteTarget(null)} disabled={remove.isPending}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={() => remove.mutate(deleteTarget.id)} loading={remove.isPending}>
                  Delete rule
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <Alert type="warning" header="Confirm deletion">
            Delete the {deleteTarget.allow ? "allow" : "deny"} rule for{" "}
            <b>{deleteTarget.pattern}</b>?
          </Alert>
        </Modal>
      )}
    </ContentLayout>
  );
}
