import { Navigate, Route, Routes } from "react-router-dom";
import { Box, Spinner } from "@cloudscape-design/components";

import { ClassificationBanner } from "@/components/classification-banner";
import { ConsentModal } from "@/components/consent-modal";
import { PortalLayout } from "@/components/portal-layout";
import { useAuth } from "@/lib/auth-context";
import { HomePage } from "@/pages/home";
import { PlaceholderPage } from "@/pages/placeholder";

// Route table for the shell. Each entry renders a placeholder page; the real
// forms/grids land in later milestones. Titles match the NPE portal menu labels.
const ROUTES: { path: string; title: string; description: string }[] = [
  // Certificate Management (Sponsor / Administrator)
  { path: "/certificates/apply", title: "Submit Certificate Application", description: "Submit a PKCS #10 CSR for a new certificate." },
  { path: "/certificates/rekey", title: "Submit Certificate Rekey", description: "Re-key an existing certificate with a new key pair." },
  { path: "/certificates/status", title: "View Certificate Application Status", description: "Look up a single application by Request ID." },
  { path: "/certificates/mine", title: "View My Certificate Applications", description: "Applications you have submitted." },
  { path: "/certificates/bulk-status", title: "View Bulk Status", description: "Status for many applications at once." },
  { path: "/certificates/ca-details", title: "View Certificate Authorities Details", description: "Certificate authority key types, algorithms, and chains." },
  { path: "/certificates/bulk", title: "Submit Bulk", description: "Submit a ZIP of CSRs for asynchronous bulk enrollment." },
  // Password Management (EST)
  { path: "/passwords/single-use", title: "Generate Single-Use Token", description: "Mint a single-use EST enrollment password (8-hour expiry)." },
  { path: "/passwords/multi-use", title: "Generate Multi-Use Token", description: "Mint a multi-device EST enrollment password (8-hour expiry)." },
  // RA workspace
  { path: "/ra/applications", title: "Manage Certificate Applications", description: "Approve, reject, or override pending applications." },
  { path: "/ra/revoke", title: "Revoke Certificates", description: "Revoke issued certificates." },
  // CAA
  { path: "/caa/users", title: "User Management", description: "Manage CAA/RA users and role assignments." },
  { path: "/caa/namespaces", title: "Wildcard Management", description: "Manage certificate namespaces and wildcard policy." },
  { path: "/caa/config", title: "System Configuration", description: "Global portal and issuance configuration." },
  // Shared
  { path: "/search", title: "Search", description: "Search certificates and applications." },
];

function FullPageNotice({ title, body }: Readonly<{ title: string; body: string }>) {
  return (
    <>
      <ClassificationBanner />
      <Box padding="xxl" textAlign="center">
        <Box variant="h1" padding={{ bottom: "s" }}>
          {title}
        </Box>
        <Box variant="p" color="text-body-secondary">
          {body}
        </Box>
      </Box>
      <ClassificationBanner />
    </>
  );
}

export default function App() {
  const { isChecking, isAuthenticated, consentRequired } = useAuth();

  if (isChecking) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" />
      </Box>
    );
  }

  if (!isAuthenticated) {
    return (
      <FullPageNotice
        title="Client certificate required"
        body="No authorized client certificate was presented. Present your PKI/CAC certificate and reload this page."
      />
    );
  }

  return (
    <PortalLayout>
      {consentRequired && <ConsentModal />}
      <Routes>
        <Route path="/" element={<HomePage />} />
        {ROUTES.map((r) => (
          <Route
            key={r.path}
            path={r.path}
            element={<PlaceholderPage title={r.title} description={r.description} />}
          />
        ))}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </PortalLayout>
  );
}
