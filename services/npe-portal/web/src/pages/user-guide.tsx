import type { ReactNode } from "react";
import {
  Box,
  Container,
  ContentLayout,
  Header,
  Link,
  SpaceBetween,
} from "@cloudscape-design/components";

import { config } from "@/lib/config";

interface Section {
  id: string;
  title: string;
  body: ReactNode;
}

// The guide is a single scrollable reference; each section has an id so the
// header dropdown (/user-guide) and form "?" help can deep-link to it
// (e.g. /user-guide#submit-application).
const SECTIONS: Section[] = [
  {
    id: "getting-started",
    title: "Getting started",
    body: (
      <SpaceBetween size="s">
        <Box>
          You sign in automatically with your PKI/CAC client certificate — there is no
          username or password. Your <strong>role</strong> (PKI Sponsor, Administrator,
          Registration Authority, CA Admin, or Auditor) is derived from your certificate and
          determines which menus you see.
        </Box>
        <Box>
          On first access you must accept the U.S. Government consent banner. For security,
          your session ends after 30 minutes of inactivity; a warning with a countdown appears
          shortly before, with a <strong>Stay signed in</strong> option so you don't lose a
          half-completed form.
        </Box>
      </SpaceBetween>
    ),
  },
  {
    id: "submit-application",
    title: "Submit a certificate application",
    body: (
      <SpaceBetween size="s">
        <Box>
          Open <strong>Certificate Management → Submit Certificate Application</strong>. Provide a
          notification email (status updates) and, optionally, ISSM and PM emails — those are also
          notified before the certificate expires.
        </Box>
        <Box variant="h4">Choosing how to supply the key</Box>
        <ul>
          <li>
            <strong>Paste or upload a CSR</strong> — a PKCS#10 request you generated elsewhere. Its
            Common Name and Subject Alternative Names are previewed and the SANs are added to the
            editable list below.
          </li>
          <li>
            <strong>Generate a key pair in your browser</strong> — expand that panel to create an
            RSA or ECDSA key + CSR locally (Web Crypto). <strong>Download the private key
            immediately</strong>; it is shown once and never sent to the server.
          </li>
          <li>
            <strong>EFS profile</strong> — the key is generated on the server and delivered as a
            one-time, password-protected PKCS#12; no CSR is needed.
          </li>
        </ul>
        <Box>
          Add Subject Alternative Names, key usage, and extended key usage as required. A TLS
          server profile is capped at 397 days (mainstream browsers reject longer). Sponsor
          submissions are queued for Registration Authority review and return a Request ID.
        </Box>
      </SpaceBetween>
    ),
  },
  {
    id: "rekey",
    title: "Rekey / renew a certificate",
    body: (
      <Box>
        Use <strong>Submit Certificate Rekey</strong>, or click <strong>Renew / Rekey</strong> on a
        row in <em>View Expiring Certificates</em> or on a certificate's detail page. The form is
        pre-filled with that certificate's current Subject Alternative Names — supply a fresh CSR
        (a new key) to complete the rekey.
      </Box>
    ),
  },
  {
    id: "track-requests",
    title: "Track requests & certificates",
    body: (
      <ul>
        <li>
          <strong>View Certificate Application Status</strong> — look up one request by its ID.
        </li>
        <li>
          <strong>View My Certificate Applications</strong> — all requests you have submitted.
        </li>
        <li>
          <strong>View Expiring Certificates</strong> — active certificates expiring within 90 days,
          each with a one-click Renew / Rekey.
        </li>
        <li>
          <strong>Search</strong> — filter your applications; export the results as CSV or PDF for
          reporting.
        </li>
      </ul>
    ),
  },
  {
    id: "certificate-detail",
    title: "Certificate details & downloads",
    body: (
      <Box>
        A certificate's detail page shows its subject, issuer, validity, serial, fingerprints,
        SANs, key usage, and extensions. The <strong>Download</strong> menu provides the certificate
        as <strong>PEM</strong>, <strong>DER</strong>, <strong>full chain (PEM)</strong>, or a
        certs-only <strong>PKCS#7 (.p7b)</strong>.
      </Box>
    ),
  },
  {
    id: "est",
    title: "Device (EST) enrollment",
    body: (
      <SpaceBetween size="s">
        <Box>
          For automated device enrollment over EST (RFC 7030):
        </Box>
        <ul>
          <li>
            <strong>Password Management → Generate Single/Multi-Use Token</strong> mints a
            time-limited enrollment password bound to a device identity.
          </li>
          <li>
            <strong>EST / Enrollment Catalog</strong> lists the available profiles and, where
            enabled, the label scheme, and builds a ready-to-run <code>openssl</code>/<code>curl</code>
            enrollment command for you to copy.
          </li>
        </ul>
      </SpaceBetween>
    ),
  },
  {
    id: "bulk",
    title: "Bulk enrollment (Administrator)",
    body: (
      <Box>
        Administrators can <strong>Submit Bulk</strong> — upload a ZIP of CSRs under one profile;
        each is queued as a request. Track progress under <strong>View Bulk Status</strong>.
      </Box>
    ),
  },
  {
    id: "ra",
    title: "Registration Authority",
    body: (
      <Box>
        Under <strong>Manage Certificate Applications</strong>, review the queue and approve or
        reject requests (with a reason and justification). An <strong>override</strong> can push a
        request past validation blocks (audited). <strong>Revoke Certificates</strong> revokes an
        issued certificate with an RFC 5280 reason code.
      </Box>
    ),
  },
  {
    id: "caa",
    title: "CA Administration",
    body: (
      <ul>
        <li>
          <strong>Manage Users &amp; Roles</strong> — create portal users and assign NPE roles (you
          cannot modify your own account).
        </li>
        <li>
          <strong>Namespaces &amp; Wildcards</strong> — allow/deny naming policy consulted during
          CSR validation.
        </li>
        <li>
          <strong>System Configuration</strong> — deployment settings (audited).
        </li>
      </ul>
    ),
  },
  {
    id: "audit",
    title: "Audit log (RA / CAA / Auditor)",
    body: (
      <Box>
        Under <strong>Compliance → Audit Log</strong>, review the tamper-evident
        certificate-lifecycle trail — filter by actor, event type, and outcome, and open a record
        for detail. <strong>Verify integrity</strong> recomputes the hash chain and checks the
        signatures; a green result means the trail has not been altered. Audit-log access is itself
        recorded.
      </Box>
    ),
  },
  {
    id: "ocsp",
    title: "Tools — OCSP status check",
    body: (
      <Box>
        <strong>Tools → OCSP Status Check</strong> looks up a certificate's live revocation status
        (RFC 6960). Paste a certificate (PEM) or enter its hex serial; the signed responder answer
        is verified against the issuing CA and shown as Good, Revoked, or Unknown — with the
        revocation time and reason when revoked.
      </Box>
    ),
  },
];

export function UserGuidePage() {
  return (
    <ContentLayout
      header={
        <Header variant="h1" description={`Help for the ${config.appName}.`}>
          User Guide
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Contents</Header>}>
          <ul>
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <Link href={`#${s.id}`}>{s.title}</Link>
              </li>
            ))}
          </ul>
        </Container>

        {SECTIONS.map((s) => (
          <div key={s.id} id={s.id}>
            <Container header={<Header variant="h2">{s.title}</Header>}>{s.body}</Container>
          </div>
        ))}
      </SpaceBetween>
    </ContentLayout>
  );
}
