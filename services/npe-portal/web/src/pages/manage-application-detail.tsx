import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  ColumnLayout,
  Container,
  ContentLayout,
  FormField,
  Header,
  Modal,
  SpaceBetween,
  Table,
  Textarea,
} from "@cloudscape-design/components";
import { useNavigate, useSearchParams } from "react-router-dom";

import { StatusBadge } from "@/components/status-badge";
import { SubmittedDetails } from "@/components/submitted-details";
import { portalApi } from "@/lib/portal-api";

type ActionKind = "approve" | "override" | "reject";

const ACTION_LABEL: Record<ActionKind, string> = {
  approve: "Approve",
  override: "Approve with override",
  reject: "Reject",
};

function ValueRow({ label, children }: Readonly<{ label: string; children: React.ReactNode }>) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <div>{children}</div>
    </div>
  );
}

export function ManageApplicationDetailPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const id = params.get("id") ?? "";

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["approval-request", id],
    queryFn: () => portalApi.getApplication(id),
    enabled: id.length > 0,
  });

  const [action, setAction] = useState<ActionKind | null>(null);
  const [justification, setJustification] = useState("");
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  function openAction(kind: ActionKind) {
    setAction(kind);
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
      if (action === "reject") {
        return portalApi.rejectApplication(
          id,
          reason.trim(),
          justification.trim() || "Rejected by Registration Authority",
        );
      }
      return portalApi.approveApplication(
        id,
        justification.trim() || "Approved by Registration Authority",
        action === "override",
      );
    },
    onSuccess: (res) => {
      const verb = action === "reject" ? "rejected" : "approved";
      setFlash(`Application ${verb} (status: ${res.updated_status}).`);
      closeAction();
      refetch();
    },
    onError: (e: Error) => setFormError(e.message),
  });

  function submit() {
    if (!action) return;
    if (action === "reject" && !reason.trim()) {
      setFormError("A rejection reason is required.");
      return;
    }
    if (action === "override" && !justification.trim()) {
      setFormError("A justification is required to override validation.");
      return;
    }
    mutation.mutate();
  }

  const request = data?.request;
  const decisions = data?.decisions ?? [];
  const details = request?.request_details;
  const isPending = request?.status?.toLowerCase() === "pending";

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Review a certificate application and record an approval decision."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
                Refresh
              </Button>
              <Button onClick={() => navigate("/ra/applications")}>Back to queue</Button>
            </SpaceBetween>
          }
        >
          Application {id}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {flash && (
          <Alert type="success" dismissible onDismiss={() => setFlash(null)} header="Decision recorded">
            {flash}
          </Alert>
        )}
        {!id && <Alert type="error" header="No application selected">A request ID is required.</Alert>}
        {isError && (
          <Alert type="error" header="Could not load the application">
            {error?.message ?? "Request failed."} Use Refresh to retry.
          </Alert>
        )}

        <Container
          header={
            <Header
              variant="h2"
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button
                    variant="primary"
                    disabled={!isPending}
                    onClick={() => openAction("approve")}
                  >
                    Approve
                  </Button>
                  <Button disabled={!isPending} onClick={() => openAction("override")}>
                    Approve with override
                  </Button>
                  <Button disabled={!isPending} onClick={() => openAction("reject")}>
                    Reject
                  </Button>
                </SpaceBetween>
              }
            >
              Request
            </Header>
          }
        >
          {isLoading ? (
            <Box>Loading…</Box>
          ) : request ? (
            <ColumnLayout columns={2} variant="text-grid">
              <ValueRow label="Request ID">
                <Box variant="code">{request.id}</Box>
              </ValueRow>
              <ValueRow label="Status">
                <StatusBadge status={request.status} />
              </ValueRow>
              <ValueRow label="Type">{request.request_type}</ValueRow>
              <ValueRow label="Requestor">{request.requestor_username}</ValueRow>
              <ValueRow label="Submitted">{request.created_at}</ValueRow>
              <ValueRow label="Expires">{request.expires_at}</ValueRow>
            </ColumnLayout>
          ) : (
            !isError && <Box>No such application.</Box>
          )}
          {!isLoading && request && !isPending && (
            <Box padding={{ top: "m" }} color="text-body-secondary">
              This application is <b>{request.status}</b>; no further decision can be recorded.
            </Box>
          )}
        </Container>

        <Container
          header={
            <Header variant="h2" description="What the requester submitted for this application.">
              Submitted details
            </Header>
          }
        >
          {isLoading ? (
            <Box>Loading…</Box>
          ) : (
            <SubmittedDetails details={details} cacheKey={id} />
          )}
        </Container>

        <Container header={<Header variant="h2">Decision history</Header>}>
          <Table
            items={decisions}
            variant="embedded"
            columnDefinitions={[
              { id: "decision", header: "Decision", cell: (d) => d.decision },
              { id: "approver", header: "Approver", cell: (d) => d.approver_username },
              { id: "reason", header: "Reason", cell: (d) => d.reason ?? "—" },
              { id: "justification", header: "Justification", cell: (d) => d.justification ?? "—" },
              { id: "decided", header: "Decided", cell: (d) => d.decided_at },
            ]}
            empty="No decisions recorded yet."
          />
        </Container>
      </SpaceBetween>

      {action && (
        <Modal
          visible
          onDismiss={closeAction}
          header={`${ACTION_LABEL[action]} application`}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={closeAction} disabled={mutation.isPending}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={submit} loading={mutation.isPending}>
                  Confirm {ACTION_LABEL[action]}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            <Box>
              Request <Box variant="code" display="inline">{id}</Box> from{" "}
              <b>{request?.requestor_username}</b> ({request?.request_type}).
            </Box>
            {action === "override" && (
              <Alert type="warning" header="Overriding validation">
                You are approving this application despite its validation advisories. This requires
                the override privilege and is recorded against your identity in the decision record.
              </Alert>
            )}
            {formError && <Alert type="error">{formError}</Alert>}
            {action === "reject" && (
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
                action === "override"
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
