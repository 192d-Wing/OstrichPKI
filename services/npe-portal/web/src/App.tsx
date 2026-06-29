import { Navigate, Route, Routes } from "react-router-dom";
import { Box, Spinner } from "@cloudscape-design/components";

import { ClassificationBanner } from "@/components/classification-banner";
import { ConsentModal } from "@/components/consent-modal";
import { PortalLayout } from "@/components/portal-layout";
import { useAuth } from "@/lib/auth-context";
import { HomePage } from "@/pages/home";
import { PlaceholderPage } from "@/pages/placeholder";
import { SubmitApplicationPage } from "@/pages/submit-application";
import { SubmitRekeyPage } from "@/pages/submit-rekey";
import { MyApplicationsPage } from "@/pages/my-applications";
import { ApplicationStatusPage } from "@/pages/application-status";
import { BulkStatusPage } from "@/pages/bulk-status";
import { CaDetailsPage } from "@/pages/ca-details";
import { PasswordManagementPage } from "@/pages/password-management";
import { ManageApplicationsPage } from "@/pages/manage-applications";
import { RevokeCertificatesPage } from "@/pages/revoke-certificates";
import { SearchPage } from "@/pages/search";

// Routes still rendered as M-later placeholders (CAA, bulk enroll).
const PLACEHOLDER_ROUTES: { path: string; title: string; description: string }[] = [
  { path: "/certificates/bulk", title: "Submit Bulk", description: "Submit a ZIP of CSRs for asynchronous bulk enrollment." },
  { path: "/caa/users", title: "User Management", description: "Manage CAA/RA users and role assignments." },
  { path: "/caa/namespaces", title: "Wildcard Management", description: "Manage certificate namespaces and wildcard policy." },
  { path: "/caa/config", title: "System Configuration", description: "Global portal and issuance configuration." },
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
        {/* Certificate Management (Sponsor / Administrator) */}
        <Route path="/certificates/apply" element={<SubmitApplicationPage />} />
        <Route path="/certificates/rekey" element={<SubmitRekeyPage />} />
        <Route path="/certificates/status" element={<ApplicationStatusPage />} />
        <Route path="/certificates/mine" element={<MyApplicationsPage />} />
        <Route path="/certificates/bulk-status" element={<BulkStatusPage />} />
        <Route path="/certificates/ca-details" element={<CaDetailsPage />} />
        {/* Password Management (EST enrollment tokens) */}
        <Route path="/passwords/single-use" element={<PasswordManagementPage multi={false} />} />
        <Route path="/passwords/multi-use" element={<PasswordManagementPage multi />} />
        {/* Registration Authority */}
        <Route path="/ra/applications" element={<ManageApplicationsPage />} />
        <Route path="/ra/revoke" element={<RevokeCertificatesPage />} />
        {/* Search */}
        <Route path="/search" element={<SearchPage />} />
        {/* Later-milestone placeholders */}
        {PLACEHOLDER_ROUTES.map((r) => (
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
