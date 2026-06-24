import * as React from "react";
import { useNavigate } from "react-router-dom";
import {
  useMutation,
  useQuery,
  useQueryClient,
  keepPreviousData,
} from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  CollectionPreferences,
  type CollectionPreferencesProps,
  ContentLayout,
  FormField,
  Header,
  Link,
  Modal,
  Pagination,
  Select,
  type SelectProps,
  SpaceBetween,
  StatusIndicator,
  Table,
  type TableProps,
  Textarea,
  TextFilter,
} from "@cloudscape-design/components";

import { ApiError } from "@/lib/api";
import {
  fetchCertificates,
  REVOCATION_REASONS,
  revokeCertificate,
  type CertificateStatus,
  type CertificateSummary,
  type RevocationReason,
} from "@/lib/ca";
import { useAuth } from "@/lib/auth-context";

const PAGE_SIZE_OPTIONS = [10, 20, 50].map((v) => ({ value: v, label: `${v}` }));

// Page size flows into the server query, so changing it re-fetches that many
// rows; column visibility is purely client-side over the current page.
const DEFAULT_PREFERENCES: CollectionPreferencesProps.Preferences = {
  pageSize: 20,
  contentDisplay: [
    { id: "serial", visible: true },
    { id: "subject", visible: true },
    { id: "issuer", visible: true },
    { id: "expires", visible: true },
    { id: "status", visible: true },
    { id: "actions", visible: true },
  ],
};

function statusIndicator(status: CertificateStatus) {
  switch (status) {
    case "active":
      return <StatusIndicator type="success">active</StatusIndicator>;
    case "revoked":
      return <StatusIndicator type="error">revoked</StatusIndicator>;
    case "expired":
      return <StatusIndicator type="warning">expired</StatusIndicator>;
    default:
      return <StatusIndicator type="pending">pending</StatusIndicator>;
  }
}

const STATUS_OPTIONS: SelectProps.Option[] = [
  { label: "All statuses", value: "" },
  { label: "active", value: "active" },
  { label: "revoked", value: "revoked" },
  { label: "expired", value: "expired" },
  { label: "pending", value: "pending" },
];

export function CertificatesPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { can } = useAuth();

  const [pageIndex, setPageIndex] = React.useState(0);
  const [search, setSearch] = React.useState("");
  const [statusOpt, setStatusOpt] = React.useState<SelectProps.Option>(
    STATUS_OPTIONS[0],
  );
  const [preferences, setPreferences] =
    React.useState<CollectionPreferencesProps.Preferences>(DEFAULT_PREFERENCES);
  const [sortingColumn, setSortingColumn] =
    React.useState<TableProps.SortingColumn<CertificateSummary>>();
  const [sortingDescending, setSortingDescending] = React.useState(true);
  const status = statusOpt.value ?? "";
  const pageSize = preferences.pageSize ?? 20;
  const sortField = sortingColumn?.sortingField;

  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(pageSize));
  if (status) query.set("status", status);
  if (search.trim()) query.set("search", search.trim());
  if (sortField) {
    query.set("sort", sortField);
    query.set("order", sortingDescending ? "desc" : "asc");
  }

  const { data, isFetching, isError } = useQuery({
    queryKey: [
      "certificates",
      pageIndex,
      pageSize,
      status,
      search.trim(),
      sortField ?? "",
      sortingDescending,
    ],
    queryFn: () => fetchCertificates(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pagesCount = Math.max(1, Math.ceil(total / pageSize));

  // Revoke modal.
  const [target, setTarget] = React.useState<CertificateSummary | null>(null);
  const [reason, setReason] = React.useState<RevocationReason>("Unspecified");
  const [notes, setNotes] = React.useState("");
  const [revokeError, setRevokeError] = React.useState<string | null>(null);
  const closeModal = () => {
    setTarget(null);
    setRevokeError(null);
  };
  const revoke = useMutation({
    mutationFn: () => revokeCertificate(target!.id, reason, notes),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["certificates"] });
      closeModal();
    },
    onError: (e) =>
      setRevokeError(e instanceof ApiError ? e.message : "Failed to revoke"),
  });
  function openRevoke(cert: CertificateSummary) {
    setTarget(cert);
    setReason("Unspecified");
    setNotes("");
    setRevokeError(null);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Issued certificate inventory."
          actions={
            can("issue_certificates") ? (
              <Button
                variant="primary"
                onClick={() => navigate("/certificates/issue")}
              >
                Issue certificate
              </Button>
            ) : undefined
          }
        >
          Certificates
        </Header>
      }
    >
      <Table<CertificateSummary>
        variant="container"
        loading={isFetching}
        loadingText="Loading certificates"
        items={data?.certificates ?? []}
        trackBy="id"
        resizableColumns
        stickyHeader
        columnDisplay={preferences.contentDisplay}
        sortingColumn={sortingColumn}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn(detail.sortingColumn);
          setSortingDescending(detail.isDescending ?? true);
          setPageIndex(0);
        }}
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load certificates." : "No certificates."}
          </Box>
        }
        columnDefinitions={[
          {
            id: "serial",
            header: "Serial",
            sortingField: "serial",
            cell: (c) => <Box fontSize="body-s">{c.serialNumber}</Box>,
          },
          { id: "subject", header: "Subject", sortingField: "subject", cell: (c) => c.subject },
          { id: "issuer", header: "Issuer", sortingField: "issuer", cell: (c) => c.issuer },
          { id: "expires", header: "Expires", sortingField: "expires", cell: (c) => c.validTo },
          {
            id: "status",
            header: "Status",
            cell: (c) => statusIndicator(c.status),
          },
          {
            id: "actions",
            header: "",
            cell: (c) => (
              <SpaceBetween direction="horizontal" size="xs">
                <Link onFollow={() => navigate(`/certificates/${c.id}`)}>
                  View
                </Link>
                {c.status === "active" && (
                  <Link
                    onFollow={() => openRevoke(c)}
                    variant="secondary"
                  >
                    Revoke
                  </Link>
                )}
              </SpaceBetween>
            ),
          },
        ]}
        filter={
          <SpaceBetween direction="horizontal" size="xs">
            <TextFilter
              filteringText={search}
              filteringPlaceholder="Search subject"
              onChange={({ detail }) => {
                setSearch(detail.filteringText);
                setPageIndex(0);
              }}
            />
            <Select
              selectedOption={statusOpt}
              options={STATUS_OPTIONS}
              onChange={({ detail }) => {
                setStatusOpt(detail.selectedOption);
                setPageIndex(0);
              }}
            />
          </SpaceBetween>
        }
        pagination={
          <Pagination
            currentPageIndex={pageIndex + 1}
            pagesCount={pagesCount}
            onChange={({ detail }) => setPageIndex(detail.currentPageIndex - 1)}
          />
        }
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={preferences}
            pageSizePreference={{ title: "Page size", options: PAGE_SIZE_OPTIONS }}
            contentDisplayPreference={{
              title: "Column visibility",
              options: [
                { id: "serial", label: "Serial" },
                { id: "subject", label: "Subject" },
                { id: "issuer", label: "Issuer" },
                { id: "expires", label: "Expires" },
                { id: "status", label: "Status" },
                { id: "actions", label: "Actions", alwaysVisible: true },
              ],
            }}
            onConfirm={({ detail }) => {
              setPreferences(detail);
              setPageIndex(0);
            }}
          />
        }
        header={<Header counter={`(${total})`}>All certificates</Header>}
      />

      <Modal
        visible={!!target}
        onDismiss={closeModal}
        header="Revoke certificate"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeModal}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={revoke.isPending}
                onClick={() => revoke.mutate()}
              >
                Revoke certificate
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box>
            This permanently revokes <b>{target?.subject}</b> (serial{" "}
            {target?.serialNumber}). It will appear on the next CRL/OCSP
            response.
          </Box>
          <FormField label="Reason">
            <Select
              selectedOption={{ label: reason, value: reason }}
              options={REVOCATION_REASONS.map((r) => ({
                label: r.label,
                value: r.value,
              }))}
              onChange={({ detail }) =>
                setReason(detail.selectedOption.value as RevocationReason)
              }
            />
          </FormField>
          <FormField label="Notes (optional)">
            <Textarea
              value={notes}
              onChange={({ detail }) => setNotes(detail.value)}
              placeholder="Context for the audit record"
            />
          </FormField>
          {revokeError && <Alert type="error">{revokeError}</Alert>}
        </SpaceBetween>
      </Modal>
    </ContentLayout>
  );
}
