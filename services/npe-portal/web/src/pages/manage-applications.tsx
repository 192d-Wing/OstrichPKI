import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ButtonDropdown,
  ContentLayout,
  FormField,
  Header,
  Modal,
  SpaceBetween,
  Table,
  Textarea,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type ApplicationInfo } from "@/lib/portal-api";

type ActionKind = "approve" | "override" | "reject";

interface PendingAction {
  kind: ActionKind;
  item: ApplicationInfo;
}

const ACTION_LABEL: Record<ActionKind, string> = {
  approve: "Approve",
  override: "Approve with override",
  reject: "Reject",
};

export function ManageApplicationsPage() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["approval-queue"],
    queryFn: portalApi.listApprovalQueue,
  });

  const [action, setAction] = useState<PendingAction | null>(null);
  const [justification, setJustification] = useState("");
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  function openAction(kind: ActionKind, item: ApplicationInfo) {
    setAction({ kind, item });
    setJustification("");
    setReason("");
    setFormError(null);
  }

  function closeAction() {
    setAction(null);
    setFormError(null);
  }

  const mutation = useMutation({
    mutationFn: () => {
      if (!action) throw new Error("No action selected");
      const id = action.item.id;
      if (action.kind === "reject") {
        return portalApi.rejectApplication(
          id,
          reason.trim(),
          justification.trim() || "Rejected by Registration Authority",
        );
      }
      return portalApi.approveApplication(
        id,
        justification.trim() || "Approved by Registration Authority",
        action.kind === "override",
      );
    },
    onSuccess: (res) => {
      const verb = action?.kind === "reject" ? "rejected" : "approved";
      setFlash(`Application ${action?.item.id} ${verb} (status: ${res.updated_status}).`);
      closeAction();
      refetch();
    },
    onError: (e: Error) => setFormError(e.message),
  });

  function submit() {
    if (!action) return;
    // Reject requires a reason; an override requires a justification (the RA must
    // record WHY the validation advisories were waived).
    if (action.kind === "reject" && !reason.trim()) {
      setFormError("A rejection reason is required.");
      return;
    }
    if (action.kind === "override" && !justification.trim()) {
      setFormError("A justification is required to override validation.");
      return;
    }
    mutation.mutate();
  }

  const items = data?.requests ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Pending certificate applications awaiting Registration Authority review."
          actions={
            <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
              Refresh
            </Button>
          }
        >
          Manage Certificate Applications
        </Header>
      }
    >
      <SpaceBetween size="l">
        {flash && (
          <Alert type="success" dismissible onDismiss={() => setFlash(null)} header="Decision recorded">
            {flash}
          </Alert>
        )}
        <Table<ApplicationInfo>
          loading={isLoading}
          items={items}
          variant="container"
          wrapLines
          columnDefinitions={[
            { id: "id", header: "Request ID", cell: (i) => i.id },
            { id: "type", header: "Type", cell: (i) => i.request_type },
            { id: "requestor", header: "Requestor", cell: (i) => i.requestor_username },
            { id: "status", header: "Status", cell: (i) => <StatusBadge status={i.status} /> },
            { id: "created", header: "Submitted", cell: (i) => i.created_at },
            {
              id: "actions",
              header: "Actions",
              cell: (i) => (
                <ButtonDropdown
                  expandableGroups
                  ariaLabel={`Review application ${i.id}`}
                  items={[
                    { id: "approve", text: "Approve" },
                    { id: "override", text: "Approve with override" },
                    { id: "reject", text: "Reject" },
                  ]}
                  onItemClick={(e) => openAction(e.detail.id as ActionKind, i)}
                >
                  Review
                </ButtonDropdown>
              ),
            },
          ]}
          empty={
            <Box textAlign="center" color="inherit">
              <SpaceBetween size="xs">
                <b>Queue is empty</b>
                <span>There are no pending applications to review.</span>
              </SpaceBetween>
            </Box>
          }
        />
      </SpaceBetween>

      {action && (
        <Modal
          visible
          onDismiss={closeAction}
          header={`${ACTION_LABEL[action.kind]} application`}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={closeAction} disabled={mutation.isPending}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={submit}
                  loading={mutation.isPending}
                >
                  Confirm {ACTION_LABEL[action.kind]}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            <Box>
              Request <Box variant="code" display="inline">{action.item.id}</Box> from{" "}
              <b>{action.item.requestor_username}</b> ({action.item.request_type}).
            </Box>
            {action.kind === "override" && (
              <Alert type="warning" header="Overriding validation">
                You are approving this application despite its validation advisories. This requires
                the override privilege and is recorded against your identity in the decision record.
              </Alert>
            )}
            {formError && <Alert type="error">{formError}</Alert>}
            {action.kind === "reject" && (
              <FormField label="Rejection reason" description="Required. Shown to the requestor.">
                <Textarea
                  value={reason}
                  onChange={(e) => setReason(e.detail.value)}
                  rows={2}
                  placeholder="Why is this application being rejected?"
                />
              </FormField>
            )}
            <FormField
              label="Justification"
              description={
                action.kind === "override"
                  ? "Required. Record why the validation advisories are being waived."
                  : "Optional. Recorded in the decision history."
              }
            >
              <Textarea
                value={justification}
                onChange={(e) => setJustification(e.detail.value)}
                rows={3}
                placeholder="Justification for this decision"
              />
            </FormField>
          </SpaceBetween>
        </Modal>
      )}
    </ContentLayout>
  );
}
