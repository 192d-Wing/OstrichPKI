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

### 1. Expiry-notification emails — `Built (deploy pending)` · backend
**Implemented as a decoupled subsystem** (`services/notify-server` +
`deploy/kubernetes/notify/` + CA producer):
- CA producer (`NOTIFY_ENABLED`) scans expiring certs, resolves recipients from
  the approval request (requester + **ISSM** + **PM**), and publishes the agreed
  JSON schedule to NATS JetStream (`cert.expiry.notify`).
- **notify-scheduler** stores schedules in its own Postgres, ticks on
  day/time/frequency, publishes due emails to `email.send` (dedup per cert/day).
- **notify-sender** delivers via SMTP (lettre; plain or STARTTLS).

Remaining: deploy (NATS + notify Postgres + scheduler/sender), point at an SMTP
relay, enable `NOTIFY_ENABLED` on the CA. Future: per-cert frequency/days/time on
the submit form (producer uses defaults today).

### 2. Expiring-soon drill-down + one-click renew — `Proposed` · frontend
The dashboard's "Expiring in 90 Days" card opens a filtered list; each row has a
**Renew/Rekey** button that pre-fills the submit form.

### 3. Certificate detail + multi-format download — `Proposed` · frontend (CA data exists)
Full cert view (subject, SANs, validity, serial, chain) with download as
**PEM / DER / PKCS#7 / full chain**. Table-stakes for retrieving issued certs.

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
