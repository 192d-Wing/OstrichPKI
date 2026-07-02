import { Navigate, Route, Routes } from "react-router-dom";
import { Box, Spinner } from "@cloudscape-design/components";

import { ClassificationBanner } from "@/components/classification-banner";
import { ConsentModal } from "@/components/consent-modal";
import { PortalLayout } from "@/components/portal-layout";
import { SessionTimeout } from "@/components/session-timeout";
import { useAuth } from "@/lib/auth-context";
import { HomePage } from "@/pages/home";
import { SubmitApplicationPage } from "@/pages/submit-application";
import { SubmitRekeyPage } from "@/pages/submit-rekey";
import { MyApplicationsPage } from "@/pages/my-applications";
import { ExpiringCertificatesPage } from "@/pages/expiring-certificates";
import { CertificateDetailPage } from "@/pages/certificate-detail";
import { ApplicationStatusPage } from "@/pages/application-status";
import { BulkStatusPage } from "@/pages/bulk-status";
import { CaDetailsPage } from "@/pages/ca-details";
import { EstEnrollmentCatalogPage } from "@/pages/est-enrollment-catalog";
import { PasswordManagementPage } from "@/pages/password-management";
import { ManageApplicationsPage } from "@/pages/manage-applications";
import { RevokeCertificatesPage } from "@/pages/revoke-certificates";
import { AuditLogPage } from "@/pages/audit-log";
import { SubmitBulkPage } from "@/pages/submit-bulk";
import { CaaUsersPage } from "@/pages/caa-users";
import { CaaNamespacesPage } from "@/pages/caa-namespaces";
import { CaaConfigPage } from "@/pages/caa-config";
import { SearchPage } from "@/pages/search";
import { OcspCheckerPage } from "@/pages/ocsp-checker";
import { UserGuidePage } from "@/pages/user-guide";

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
      {!consentRequired && <SessionTimeout />}
      <Routes>
        <Route path="/" element={<HomePage />} />
        {/* Certificate Management (Sponsor / Administrator) */}
        <Route path="/certificates/apply" element={<SubmitApplicationPage />} />
        <Route path="/certificates/rekey" element={<SubmitRekeyPage />} />
        <Route path="/certificates/status" element={<ApplicationStatusPage />} />
        <Route path="/certificates/mine" element={<MyApplicationsPage />} />
        <Route path="/certificates/expiring" element={<ExpiringCertificatesPage />} />
        <Route path="/certificates/view" element={<CertificateDetailPage />} />
        <Route path="/certificates/bulk-status" element={<BulkStatusPage />} />
        <Route path="/certificates/ca-details" element={<CaDetailsPage />} />
        <Route path="/certificates/est-catalog" element={<EstEnrollmentCatalogPage />} />
        <Route path="/certificates/bulk" element={<SubmitBulkPage />} />
        {/* Password Management (EST enrollment tokens) */}
        <Route path="/passwords/single-use" element={<PasswordManagementPage multi={false} />} />
        <Route path="/passwords/multi-use" element={<PasswordManagementPage multi />} />
        {/* Registration Authority */}
        <Route path="/ra/applications" element={<ManageApplicationsPage />} />
        <Route path="/ra/revoke" element={<RevokeCertificatesPage />} />
        <Route path="/audit" element={<AuditLogPage />} />
        {/* Certificate Authority Admin (CAA) */}
        <Route path="/caa/users" element={<CaaUsersPage />} />
        <Route path="/caa/namespaces" element={<CaaNamespacesPage />} />
        <Route path="/caa/config" element={<CaaConfigPage />} />
        {/* Search */}
        <Route path="/search" element={<SearchPage />} />
        <Route path="/ocsp" element={<OcspCheckerPage />} />
        <Route path="/user-guide" element={<UserGuidePage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </PortalLayout>
  );
}
