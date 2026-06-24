# Web UI (React `/next` console) — Roadmap

Scope: the React + AWS Cloudscape console served at `/next` by the web-ui BFF.
The legacy Yew SPA at `/` is a separate app and out of scope here.

> Repo-root `ROADMAP.md` is the project-wide (backend/compliance) roadmap — different scope.
> This file tracks only the React console.

## Done (shipped)

- **Full Cloudscape migration.** PR #106 (shell + Dashboard + CSP foundation), PR #107
  (all console pages → Cloudscape), PR #108 (remove Tailwind + shadcn, rebuild login +
  protected, prune deps). All merged to `main`.
- **Deployed & verified.** Image `sha-f4186bd` on `ostrich-pki/web-ui`; `/next` serves
  HTTP 200, new bundle hashes, CSP intact (`script-src` nonce-strict,
  `style-src 'self' 'unsafe-inline'`). typecheck + lint (0 warnings) + build green.
- Result: 0 shadcn/Tailwind deps remain in `services/web-ui/web`; pages use Cloudscape
  `Table`/`Cards`/`Form`/`Modal`/`KeyValuePairs`/`StatusIndicator`.

## Remaining UI work

### 1. Route-level code-splitting  — perf, biggest lever  [done]
Each page is now a `React.lazy` chunk loaded on demand, with `<Suspense>` fallbacks
(Cloudscape `Spinner`): a top-level boundary around `<Routes>` for login, and a nested
boundary around `<Outlet>` in `cloudscape-layout.tsx` so the shell stays mounted during
authenticated page transitions. `vite.config.ts` `manualChunks` splits the Cloudscape
vendor bundle from app code so it caches independently.
- Measured (`pnpm build`): initial load is app `index` 70 KB / **23 KB gzip** +
  `cloudscape` vendor 926 KB / **264 KB gzip** + `cloudscape` CSS **127 KB gzip** + app CSS
  **138 KB gzip**. Per-route chunks are 1–5 KB (gzip <2.2 KB) and load on navigation.
- The remaining Vite >500 KB warning is the Cloudscape vendor lib itself (one library, not
  splittable further); it's now isolated so it caches across app/route changes.
- Still TODO: verify `/next` lazy chunks serve under CSP `'self'` after deploy.

### 2. Drop stale "preview / P1" framing  — cosmetic  [done]
React console is the primary console, not a preview.
- `package.json` description/version already clean ("React + Vite + AWS Cloudscape"); no change needed.
- `services/web-ui/Dockerfile` — React build-step and runtime-copy comments reworded from
  "React (preview) SPA" / "P1" to "React console". Yew Tailwind step left untouched.
- `src/App.tsx` — stale "only EST is ported (P3)" comment updated to name the actual
  placeholders (Approvals / Tokens / Users).

### 3. Polish  — nice-to-have, partially done
- **Table preferences**: [done] `certificates.tsx` and `audit.tsx` now have
  `CollectionPreferences` (page-size selection wired into the server query + column
  visibility with `alwaysVisible` on the actions/timestamp anchors), `resizableColumns`,
  and `stickyHeader`.
- **Sortable columns**: [done] server-side sort across both tables. The CA accepts
  `sort`/`order` query params on `GET /api/v1/certificates` (keys: `serial`, `subject`,
  `issuer`, `expires`) and the audit list (keys: `timestamp`, `eventType`, `actor`,
  `target`, `action`, `outcome`); the repo `list_filtered` builds a whitelisted `ORDER BY`
  (column from a closed match, direction from a bool, `, id` tiebreaker for stable
  pagination — SI-10 safe). The web-ui proxy forwards the params; `certificates.tsx` /
  `audit.tsx` wire `sortingColumn`/`sortingDescending`/`onSortingChange` and reset to page 1
  on sort change. Status/`signed` columns are intentionally not sortable (derived values).
- **Cloudscape density / visual-refresh tokens**: [not started] currently default theme;
  consider enabling density + visual-refresh via `@cloudscape-design/global-styles`.

#### Mock pages — won't wire; gap to close in the backend first

Users, Tokens (SCMS), and Approvals are placeholder routes (`Placeholder` component) gated
by `manage_users` / `view_tokens` / `view_approvals`. We are **not** wiring them to stub or
mock data — they stay placeholders until the CA exposes real endpoints. To complete the gap
each was meant to serve, the backend needs:

- **Users** (`manage_users`): account-management REST on the CA — `GET /api/v1/users`
  (paged list: id, username, roles, status, created/last-login), `POST` (create),
  `PATCH /api/v1/users/{id}` (role/status changes), `DELETE`/disable. NIST AC-2 (account
  management) + audit events (AU-2) on every mutation. Then build a Cloudscape table + create/
  edit forms mirroring `certificates.tsx`.
- **Tokens / SCMS** (`view_tokens`): SCMS enrollment-token endpoints — `GET /api/v1/scms/tokens`
  (paged: id, device/subject, status, issued/expiry), issue + revoke actions. IA-5
  (authenticator management). Then a table + issue/revoke modals.
- **Approvals** (`view_approvals`): a dual-control request queue — `GET /api/v1/approvals`
  (pending requests: id, type, requester, payload summary, state), `POST
  /api/v1/approvals/{id}/approve|reject`. Maps to AC-3 / separation-of-duties; pairs with
  whichever operations require maker-checker. Then a queue table + approve/reject flow.

Until those endpoints exist, the nav entries remain permission-gated placeholders (no
broken/mock data shown to operators).

### 4. `/` → `/next` cutover  — full cutover, Yew retired  [done — source cleanup pending]
React is now the primary app served at `/`; the Yew SPA is retired.
- `server/template.rs`: single `serve_index` serves the React `index.html` with `basename:
  "/"` + per-request CSP nonce. Removed the embedded Yew template, `ClientConfig`, and
  `get_index_template`.
- `server/router.rs`: `/` (fallback) → React; legacy `/next` and `/next/{*rest}` →
  `301` redirect to `/` (sub-path preserved) so old bookmarks keep working.
- `Dockerfile`: replaced the Rust+trunk+Tailwind `wasm-builder` stage with a small
  Node-only `web-builder` (Vite only); runtime now copies the whole React `dist/` to
  `/app/static/` (index.html + hashed assets). No more Yew/WASM/Tailwind in the image.
- `web/src/lib/config.ts`: basename comment updated to reflect root mount.
- Verified: `cargo check -p ostrich-web-ui` clean; React typecheck/lint/build green.

**Follow-up cleanup (separate PR):** delete the now-dead Yew source tree
(`services/web-ui/src/client/`, `Trunk.toml`, `input.css`, `tailwind.config.js`, the Yew
`index.html`), prune its wasm/yew deps from `Cargo.toml`, and drop the `web-ui-wasm` CI job
(`.github/workflows/ci.yml`). The Yew client is `#[cfg(target_arch = "wasm32")]`-gated, so
it doesn't affect the native server build or the shipped image — it's just dead weight.

## Resume / verify cheatsheet

- Work dir: `services/web-ui/web`. pnpm at `/c/tmp/pnpmbin/pnpm` in this env.
- Checks: `pnpm typecheck`, `pnpm lint`, `pnpm build`.
- Deploy (after merge to `main`, docker-publish builds `ghcr.io/192d-wing/web-ui:sha-<commit>`):
  `KUBECONFIG=$PWD/ostrich.kubeconfig kubectl -n ostrich-pki set image deploy/web-ui \
   web-ui=ghcr.io/192d-wing/web-ui:sha-<commit>` — **prod deploy; get explicit sign-off first.**
- Verify: `curl -sk --resolve ca-ui.oopl.dev.mil:443:10.10.10.54 https://ca-ui.oopl.dev.mil/next`
  (expect HTTP 200 + hashed asset refs).

## Not UI (don't lose — tracked elsewhere)

EST mTLS reenroll (noded/TPM) `decrypt_error`: server-side rustls trace captured; analysis
in `c:\tmp\est-reenroll-analysis.md`; est-server reverted to `RUST_LOG=info`. Ball is with
the client/noded agent (verify the CertificateVerify ECDSA signature is canonical DER, not
raw TPM `r‖s`).
