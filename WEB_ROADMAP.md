# NPE Portal — Web Roadmap

Candidate enhancements for the NPE (Non-Person Entity) enrollment portal
(`services/npe-portal`). Grouped by theme; each notes rough effort and whether it
needs backend work. Status starts at `Proposed`.

**Already shipped:** mTLS auth + OID→role (Sponsor / Admin / RA / CAA), USG
consent gate, 30-min session, configurable dashboard, submit application
(CSR paste/upload, CN/SAN preview, CC/S/A, SAN editor, key-usage/EKU, ISSM/PM
emails), submit rekey, application status / my applications, bulk status / submit
bulk, CA details, EST password management, search, RA manage/override/revoke,
CAA user / namespace / system-config, About/Preferences, ACME auto-cert.

## Recommended next (top 3)
1. Expiry-notification emails (#1) — makes the ISSM/PM fields meaningful.
2. Expiring-soon drill-down + one-click renew (#2) — turns the dashboard metric into action.
3. In-browser CSR generation (#4) — biggest friction reducer for real enrollers.

---

## 🔑 Certificate lifecycle (highest impact)

### 1. Expiry-notification emails — `Deployed (2026-06-30)` · backend
**Decoupled subsystem live in `ostrich-pki`** (`services/notify-server` +
`deploy/kubernetes/notify/` + CA producer):
- CA producer (`NOTIFY_ENABLED`) scans expiring certs, resolves recipients from
  the approval request (requester + **ISSM** + **PM**), and publishes the agreed
  JSON schedule to NATS JetStream (`cert.expiry.notify`).
- **notify-scheduler** stores schedules in its own Postgres, ticks on
  day/time/frequency, publishes due emails to `email.send` (once per cadence
  period — day/ISO-week/month — with crash-safe re-drive of unsent windows).
- **notify-sender** delivers via SMTP (lettre; none/STARTTLS/implicit-TLS), with
  bounded redelivery + poison-message drop.

Future: per-cert frequency/days/time on the submit form (producer uses defaults
today); audit events on send/publish; `docs/compliance/` sweep for the subsystem.

### 2. Expiring-soon drill-down + one-click renew — `Built` · frontend + backend
The dashboard's "Expiring in 90 Days" card opens a filtered list
(`/certificates/expiring`); each row has a **Renew/Rekey** button that opens the
rekey form pre-filled with the certificate's current SANs. Backend: added an
`expiringInDays` filter to `GET /api/v1/certificates` (own-scoped, mirrors the
`expiring_soon` count exactly). Future: PEM/DER/PKCS#7 download from the row (#3).

### 3. Certificate detail + multi-format download — `Built` · frontend + backend
Full cert view at `/certificates/view?id=` (subject, issuer, validity, serial,
fingerprints, SKI/AKI, SANs, key usage/EKU, CRL/OCSP, extensions table) with a
Download dropdown: **PEM / DER / full chain (PEM) / PKCS#7 (.p7b)**. PEM/DER/chain
are derived client-side from the leaf PEM + CA chain; PKCS#7 is a new CA endpoint
`GET /api/v1/certificates/{id}/pkcs7` (own-scoped, certs-only leaf+CA). The
certs-only PKCS#7 builder was lifted from EST into shared `ostrich_x509::pkcs7`.
Reachable from the Expiring Certificates list (CN link).

## 🧰 Self-service helpers

### 4. In-browser CSR generator (WebCrypto) — `Proposed` · frontend
Generate a keypair + CSR in the browser, download the private key, auto-fill the
submit form. Removes the #1 enrollment blocker ("how do I make a CSR?").

### 5. EST / enrollment catalog — `Proposed` · frontend
List available CAs, profiles, and `PTptval-…` EST labels with copy-paste
`lego`/`curl` enrollment commands for device admins.

## 📋 Compliance & visibility (RA / CAA)

### 6. Audit log viewer — `Proposed` · frontend (CA `/api/v1/audit` exists)
Surface the CA audit trail (with hash-chain / signature verification) for RA/CAA.
Satisfies NIAP FAU_SAR.1.

### 7. Search export (CSV / PDF) — `Proposed` · frontend
Export search results for IA reporting (was in the original spec).

## ✨ UX / polish

### 8. Session-timeout warning modal — `Proposed` · frontend
"You'll be logged out in 2 min" prompt before the 30-min inactivity logout;
avoids losing a half-filled form.

### 9. Real User Guide / Help pages — `Proposed` · frontend
The **User Guide** dropdown item points at `/user-guide`, which 404s today.
Add in-app help content.

### 10. OCSP / revocation status checker — `Proposed` · frontend (calls OCSP)
Paste a serial or cert, get live revocation status from the OCSP responder.
