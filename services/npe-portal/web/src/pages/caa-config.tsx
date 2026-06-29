import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ContentLayout,
  FormField,
  Header,
  Input,
  Modal,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { portalApi, type ConfigSetting } from "@/lib/portal-api";

export function CaaConfigPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["caa-config"],
    queryFn: portalApi.listConfig,
  });

  const [editing, setEditing] = useState<ConfigSetting | null>(null);
  const [value, setValue] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => portalApi.setConfig(editing!.key, value.trim()),
    onSuccess: () => {
      setEditing(null);
      refetch();
    },
    onError: (e: Error) => setFormError(e.message),
  });

  function openEdit(s: ConfigSetting) {
    setEditing(s);
    setValue(s.value);
    setFormError(null);
  }

  const items = data ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Operator-tunable system settings."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          System Configuration
        </Header>
      }
    >
      <SpaceBetween size="l">
        {isError && (
          <Alert type="error" header="Could not load configuration">
            {error?.message ?? "Request failed."}
          </Alert>
        )}
        <Table<ConfigSetting>
          loading={isLoading}
          items={items}
          variant="container"
          wrapLines
          columnDefinitions={[
            { id: "key", header: "Setting", cell: (s) => s.key },
            { id: "value", header: "Value", cell: (s) => s.value },
            { id: "description", header: "Description", cell: (s) => s.description ?? "-" },
            { id: "updated", header: "Updated by", cell: (s) => s.updatedBy },
            {
              id: "actions",
              header: "",
              cell: (s) => <Button onClick={() => openEdit(s)}>Edit</Button>,
            },
          ]}
          empty="No configuration settings"
        />
      </SpaceBetween>

      {editing && (
        <Modal
          visible
          onDismiss={() => setEditing(null)}
          header={`Edit ${editing.key}`}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setEditing(null)} disabled={mutation.isPending}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={() => mutation.mutate()} loading={mutation.isPending}>
                  Save
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            {editing.description && <Box color="text-body-secondary">{editing.description}</Box>}
            {formError && <Alert type="error">{formError}</Alert>}
            <FormField label="Value">
              <Input value={value} onChange={(e) => setValue(e.detail.value)} />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
