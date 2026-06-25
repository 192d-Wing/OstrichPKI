import * as React from "react";
import { useNavigate } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Box,
  ContentLayout,
  Header,
  Link,
  Pagination,
  SpaceBetween,
  Table,
  TextFilter,
} from "@cloudscape-design/components";

import { fetchFqdns, type FqdnSummary } from "@/lib/fqdn";

const PAGE_SIZE = 25;

export function FqdnsPage() {
  const navigate = useNavigate();
  const [pageIndex, setPageIndex] = React.useState(0);
  const [search, setSearch] = React.useState("");

  const query = new URLSearchParams();
  query.set("page", String(pageIndex + 1));
  query.set("pageSize", String(PAGE_SIZE));
  if (search.trim()) query.set("search", search.trim());

  const { data, isFetching, isError } = useQuery({
    queryKey: ["fqdns", pageIndex, search.trim()],
    queryFn: () => fetchFqdns(query.toString()),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pagesCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Certificate history by fully-qualified domain name.">
          FQDNs
        </Header>
      }
    >
      <Table<FqdnSummary>
        variant="container"
        loading={isFetching}
        loadingText="Loading FQDNs"
        items={data?.fqdns ?? []}
        trackBy="fqdn"
        resizableColumns
        stickyHeader
        empty={
          <Box textAlign="center" color="inherit">
            {isError ? "Failed to load FQDNs." : "No FQDNs."}
          </Box>
        }
        columnDefinitions={[
          {
            id: "fqdn",
            header: "FQDN",
            cell: (f) => (
              <Link onFollow={() => navigate(`/fqdns/${encodeURIComponent(f.fqdn)}`)}>
                {f.fqdn}
              </Link>
            ),
          },
          {
            id: "count",
            header: "Certificates",
            cell: (f) => f.certificateCount,
          },
          { id: "firstSeen", header: "First seen", cell: (f) => f.firstSeen },
          { id: "lastIssued", header: "Last issued", cell: (f) => f.lastIssued },
        ]}
        filter={
          <TextFilter
            filteringText={search}
            filteringPlaceholder="Search FQDN"
            onChange={({ detail }) => {
              setSearch(detail.filteringText);
              setPageIndex(0);
            }}
          />
        }
        pagination={
          <Pagination
            currentPageIndex={pageIndex + 1}
            pagesCount={pagesCount}
            onChange={({ detail }) => setPageIndex(detail.currentPageIndex - 1)}
          />
        }
        header={
          <Header counter={`(${total})`} variant="h2">
            <SpaceBetween direction="horizontal" size="xs">
              <span>All FQDNs</span>
            </SpaceBetween>
          </Header>
        }
      />
    </ContentLayout>
  );
}
