import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Box,
  Button,
  ColumnLayout,
  Container,
  ContentLayout,
  FormField,
  Header,
  Input,
  KeyValuePairs,
  Modal,
  Pagination,
  Select,
  type SelectProps,
  SpaceBetween,
  Table,
} from "@cloudscape-design/components";

import { StatusBadge } from "@/components/status-badge";
import { portalApi, type AuditEvent, type ListAuditParams } from "@/lib/portal-api";

const PAGE_SIZE = 50;

const OUTCOME_OPTIONS: SelectProps.Option[] = [
  { label: "All outcomes", value: "" },
  { label: "Success", value: "success" },
  { label: "Failure", value: "failure" },
];

export function AuditLogPage() {
  // Filter inputs (typed) vs. applied filters (drive the query) — so we don't
  // fire a request on every keystroke.
  const [actorIn, setActorIn] = useState("");
  const [eventTypeIn, setEventTypeIn] = useState("");
  const [outcome, setOutcome] = useState<SelectProps.Option>(OUTCOME_OPTIONS[0]);
  const [applied, setApplied] = useState<ListAuditParams>({});
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const { data, isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ["audit-events", applied, page],
    queryFn: () =>
      portalApi.listAuditEvents({
        ...applied,
        page,
        pageSize: PAGE_SIZE,
        sort: "timestamp",
        order: "desc",
      }),
    retry: false,
  });

  // Integrity verification is on demand (it recomputes the whole chain).
  const verify = useQuery({
    queryKey: ["audit-verify"],
    queryFn: portalApi.verifyAuditChain,
    enabled: false,
    retry: false,
  });

  function applyFilters() {
    setPage(1);
    setApplied({
      actor: actorIn.trim() || undefined,
      eventType: eventTypeIn.trim() || undefined,
      outcome: outcome.value || undefined,
    });
  }
  function clearFilters() {
    setActorIn("");
    setEventTypeIn("");
    setOutcome(OUTCOME_OPTIONS[0]);
    setPage(1);
    setApplied({});
  }

  const events = data?.events ?? [];
  const total = data?.total ?? 0;
  const pagesCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Tamper-evident certificate-lifecycle audit trail (hash-chained, signed). NIAP FAU_SAR.1."
          counter={data ? `(${total})` : undefined}
          actions={
            <Button
              iconName="security"
              loading={verify.isFetching}
              onClick={() => verify.refetch()}
            >
              Verify integrity
            </Button>
          }
        >
          Audit Log
        </Header>
      }
    >
      <SpaceBetween size="l">
        {verify.data && (
          <Alert
            type={verify.data.intact ? "success" : "error"}
            header={
              verify.data.intact
                ? "Audit trail integrity verified"
                : "Audit trail integrity check FAILED"
            }
          >
            {verify.data.intact
              ? `The hash chain recomputes and all ${verify.data.signedRecords} signed records verify (${verify.data.totalRecords} records, checked ${verify.data.verifiedAt.slice(0, 19)}Z).`
              : "The hash chain or a signature did not verify — the audit trail may have been tampered with. Escalate immediately."}
          </Alert>
        )}
        {verify.isError && (
          <Alert type="error" header="Verification failed">
            {(verify.error as Error).message}
          </Alert>
        )}

        <Container header={<Header variant="h2">Filters</Header>}>
          <ColumnLayout columns={4}>
            <FormField label="Actor">
              <Input
                value={actorIn}
                onChange={(e) => setActorIn(e.detail.value)}
                onKeyDown={(e) => e.detail.key === "Enter" && applyFilters()}
                placeholder="username / service"
              />
            </FormField>
            <FormField label="Event type">
              <Input
                value={eventTypeIn}
                onChange={(e) => setEventTypeIn(e.detail.value)}
                onKeyDown={(e) => e.detail.key === "Enter" && applyFilters()}
                placeholder="e.g. certificate_issued"
              />
            </FormField>
            <FormField label="Outcome">
              <Select
                selectedOption={outcome}
                onChange={(e) => setOutcome(e.detail.selectedOption)}
                options={OUTCOME_OPTIONS}
              />
            </FormField>
            <FormField label=" ">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="primary" onClick={applyFilters}>
                  Apply
                </Button>
                <Button onClick={clearFilters}>Clear</Button>
              </SpaceBetween>
            </FormField>
          </ColumnLayout>
        </Container>

        {error && (
          <Alert type="error" header="Failed to load the audit log">
            {(error as Error).message}
          </Alert>
        )}

        <Table<AuditEvent>
          loading={isLoading || isFetching}
          items={events}
          variant="container"
          onRowClick={({ detail }) => setSelected(detail.item)}
          columnDefinitions={[
            { id: "timestamp", header: "Timestamp", cell: (e) => e.timestamp.replace("T", " ").slice(0, 19) },
            { id: "eventType", header: "Event", cell: (e) => e.eventType },
            { id: "actor", header: "Actor", cell: (e) => e.actor },
            { id: "target", header: "Target", cell: (e) => e.target },
            { id: "outcome", header: "Outcome", cell: (e) => <StatusBadge status={e.outcome} /> },
            {
              id: "signed",
              header: "Integrity",
              cell: (e) => <Badge color={e.signed ? "green" : "grey"}>{e.signed ? "Signed" : "Chained"}</Badge>,
            },
          ]}
          empty={
            <Box textAlign="center" color="inherit">
              <SpaceBetween size="xs">
                <b>No audit records</b>
                <span>No events match the current filters.</span>
              </SpaceBetween>
            </Box>
          }
          footer={
            <Box textAlign="center">
              <Pagination
                currentPageIndex={page}
                pagesCount={pagesCount}
                onChange={({ detail }) => setPage(detail.currentPageIndex)}
                disabled={isFetching}
              />
            </Box>
          }
          header={
            <Header counter={`(${total})`} actions={
              <Button iconName="refresh" loading={isFetching} onClick={() => refetch()}>
                Refresh
              </Button>
            }>
              Events
            </Header>
          }
        />
      </SpaceBetween>

      <Modal
        visible={selected !== null}
        onDismiss={() => setSelected(null)}
        header="Audit record"
        footer={
          <Box float="right">
            <Button variant="primary" onClick={() => setSelected(null)}>
              Close
            </Button>
          </Box>
        }
      >
        {selected && (
          <KeyValuePairs
            columns={2}
            items={[
              { label: "Record ID", value: selected.id },
              { label: "Timestamp", value: selected.timestamp },
              { label: "Event type", value: selected.eventType },
              { label: "Actor", value: selected.actor },
              { label: "Target", value: selected.target },
              { label: "Action", value: selected.action },
              { label: "Outcome", value: <StatusBadge status={selected.outcome} /> },
              { label: "IP address", value: selected.ipAddress ?? "—" },
              {
                label: "Integrity",
                value: selected.signed ? "AU-10 digital signature" : "AU-9 hash chain",
              },
            ]}
          />
        )}
      </Modal>
    </ContentLayout>
  );
}
