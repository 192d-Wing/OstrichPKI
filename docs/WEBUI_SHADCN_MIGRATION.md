# Web UI Migration: Yew/WASM → React + Vite + shadcn/ui

**Status:** Proposed — plan for review
**Decision (agreed):** Replace **only** the frontend client with a React + Vite + TypeScript + Tailwind + **shadcn/ui** SPA. **Keep the existing Rust Axum server** (OIDC auth, session, CSP, audit, `/api` proxy, static serving) unchanged. The Axum server continues to serve the SPA and remains the security boundary.

---

## 1. Why / goals

The Yew client works, but the Rust UI component ecosystem is thin: rich tables (sort + per-column filter + pagination), forms, dialogs, command palettes, date pickers, etc. are hand-built each time. shadcn/ui + TanStack Table/Query gives those as first-class primitives, with a much larger talent pool and faster iteration.

**Goals**
- Feature parity with today's UI, then better UX (turnkey tables/forms/dialogs).
- **No change to the security-critical backend**: auth/session/proxy/CSP stay in audited Rust.
- Smallest possible blast radius and ATO/supply-chain delta.

**Non-goals**
- No backend rewrite. No Node BFF. No change to the EST/CA/ACME/OCSP services or their APIs.
- No change to the `/api` proxy contract — the React app calls the **same** endpoints the Yew app calls today.

---

## 2. Current state (verified)

```
services/web-ui/
  src/client/         # Yew WASM SPA  (cfg(target_arch="wasm32"))
    app.rs, router.rs # 13 routes
    pages/*.rs        # 13 pages, ~6,076 LOC
    components/       # auth/protected, common/{alert,badge,copy_button,data_table,
                      #   loading,modal,pagination}, layout/{navbar,sidebar}
    services/api.rs   # fetch wrapper, base_url "/api", get/post/delete
    types/api.rs
  src/server/         # Axum server  (cfg(not(wasm32)))  ← KEEP ALL OF THIS
    router.rs         # health/ready, /auth/*, /api proxy, ServeDir, SPA fallback
    proxy.rs          # /api/{ca,est,ocsp,...} → backends w/ session-bound token
    auth/             # oidc (PKCE), handlers (login/callback/internal-login/
                      #   logout/userinfo), session
    middleware/       # csp (per-request nonce), session, audit
    template.rs       # serves index.html with CSP-nonce + ClientConfig injection
  index.html          # Trunk entry
  input.css, tailwind.config.js, package.json  # Tailwind v3 already in the build
  Trunk.toml
  Dockerfile          # 3 stages: wasm-builder(trunk) → server-builder(chef) → runtime
```

**Build today (Dockerfile):**
1. `wasm-builder`: `npx tailwindcss -i input.css -o output.css` → `trunk build --release` → `dist/`.
2. `server-builder`: cargo-chef → `cargo build --release -p ostrich-web-ui`.
3. `runtime`: copy server binary + `dist/` → `/app/static/` + `index.html` → `/app/templates/index.html`.

**CI:** `Web UI (wasm32)` job = `cargo build -p ostrich-web-ui --target wasm32-unknown-unknown`. Server builds in the main `Build & test`.

**Auth/session model (important for parity):**
- Session is a cookie (`SameSite=Lax`, secure, httpOnly). The browser never sees a backend token; the **server proxy** injects the session-bound bearer when forwarding `/api/*`.
- Login: OIDC PKCE (`GET /auth/login` → Keycloak → `GET /auth/callback`), or `POST /api/v1/auth/login` internal-login when OIDC is disabled (dev).
- Current user + permissions: `GET /auth/userinfo`.
- The client calls `/api/...` same-origin; **no token handling in JS**.

**Routes (1:1 with pages):** `/`, `/certificates`, `/certificates/issue`, `/certificates/:id`, `/crl`, `/profiles`, `/est`, `/approvals`, `/audit`, `/scms`, `/users`, `/settings`, `/login`, `/404`.

---

## 3. Target state

```
services/web-ui/
  web/                       # NEW — React + Vite + TS + Tailwind + shadcn SPA
    index.html               # Vite entry (with nonce placeholder + config slot)
    src/
      main.tsx, App.tsx
      routes/                # react-router; one file per page (13)
      components/ui/         # shadcn components (owned, copied in)
      components/            # app components (DataTable, Protected, layout, …)
      lib/api.ts             # fetch wrapper → /api, credentials:"same-origin"
      lib/auth.ts            # userinfo, login redirect, permission gating
      hooks/                 # TanStack Query hooks per resource
    package.json, vite.config.ts, tsconfig.json, tailwind.config.ts, components.json
  src/server/                # UNCHANGED (the BFF)
  src/client/                # DELETED at cutover (kept until parity)
```

**Stack:** React 18, Vite 5, TypeScript, Tailwind v3 (matches current), shadcn/ui (Radix), **TanStack Table** (tables) + **TanStack Query** (data/cache), react-router v6, react-hook-form + zod (forms), lucide-react (icons).

**What stays exactly the same:** the Axum server, the `/api` proxy contract, OIDC/session/CSP, the deploy (`web-ui` Deployment, `ca-ui.oopl.dev.mil` ingress), the runtime container shape (server binary + static `dist/`).

**What changes:** Dockerfile **stage 1 only** (`trunk` → `vite build`, still emits `dist/`); the CI web-ui job (wasm build → node build/lint/typecheck); the static bundle.

---

## 4. The three integration points that need care

These are the only non-mechanical parts; everything else is page porting.

### 4.1 CSP nonce injection (SC-18) — highest-risk item
Today `server/template.rs` reads `index.html` and injects a **per-request CSP nonce** into `<script>/<style>` tags plus a `ClientConfig` JSON blob, and `middleware/csp.rs` sets the `Content-Security-Policy` header with that nonce.

Vite emits hashed module scripts (`<script type="module" src="/static/assets/index-[hash].js">`). Options:
- **(A, recommended) Nonce-injection, preserved.** Keep `serve_index`: parse the Vite-built `index.html` and add `nonce="<nonce>"` to every `<script>`/`<style>` tag (or replace a `__CSP_NONCE__` placeholder we configure Vite to emit). CSP stays `script-src 'nonce-…'`. Minimal policy change; keeps the SC-18 posture identical.
- **(B) `strict-dynamic` + hashes.** `script-src 'nonce-…' 'strict-dynamic'`; the entry nonce lets Vite's module loader pull the rest. Simplest with bundlers, but a meaningful CSP policy change to re-review.

Plan: **(A)**. Add a Vite post-build/transform (or a tiny `index.html` template with `__CSP_NONCE__`) so `serve_index`'s injection keeps working with one regex. Document the exact `script-src`/`style-src`/`connect-src` deltas (Vite dev uses inline; **production build only** — no dev server in the container).

### 4.2 Runtime config injection
`serve_index` injects `ClientConfig { apiBaseUrl, oidcClientId, oidcAuthUrl, appName, version }`. Keep this: inject `window.__CONFIG__ = {…}` (nonced inline script) into the served `index.html`; React reads `window.__CONFIG__` at startup. No new endpoint required; identical mechanism.

### 4.3 Auth/session + CSRF parity
- React `lib/api.ts`: `fetch(`/api${path}`, { credentials: "same-origin" })`; surface non-2xx as typed errors (mirror `ApiError`).
- Login page: OIDC → `window.location = "/auth/login"`; dev/internal → `POST /api/v1/auth/login`.
- `lib/auth.ts`: `GET /auth/userinfo` → user + permissions; a `<Protected permission="…">` wrapper and route guards mirror the Yew `Protected` component and the sidebar permission gates (e.g. `generate_est_token`).
- **CSRF (verified):** there is **no app-level CSRF token on `/api` today**. `proxy.rs` and `middleware/session.rs` enforce **no** CSRF token, Origin, or Referer check on mutations; `require_session` only validates the session cookie token against the server-side store. The session cookie is `HttpOnly` + `Secure` + **`SameSite=Lax`**, and the client sends no CSRF header. So protection rests entirely on `SameSite=Lax` (which does block cross-site POST/DELETE). **The React app inherits this unchanged** — `lib/api.ts` needs no CSRF header; same-origin `fetch` with `credentials:"same-origin"` is exact parity. The `oauth_state` cookie is OIDC-flow CSRF only, not `/api`.
  - **Defense-in-depth opportunity (optional, server-side):** `SameSite=Lax`-only is the common baseline but has no second layer. The migration is a natural moment to add an **Origin/Referer allowlist check** (or a double-submit token) in the Axum proxy. This is a **Rust-server enhancement, independent of the frontend** — recommend tracking it separately, not blocking the migration.

---

## 5. Component mapping

| Today (Yew) | shadcn/React |
|---|---|
| `common/alert` | `Alert` (+ `Sonner` toasts for transient) |
| `common/badge` | `Badge` (variants map 1:1) |
| `common/data_table` | shadcn `Table` + **TanStack Table** (sort, **per-column + global filter**, pagination, faceted filters built-in) |
| `common/pagination` | TanStack pagination + shadcn `Pagination` |
| `common/modal` | `Dialog` / `AlertDialog` |
| `common/loading` | `Skeleton` / `Spinner` |
| `common/copy_button` | trivial (`navigator.clipboard` + `Button`) |
| `layout/navbar`,`sidebar` | shadcn `Sidebar` + `NavigationMenu` |
| forms (issue, login, settings) | `Form` + react-hook-form + zod |

The **per-column filtering** we just hand-built for the EST token table becomes free via TanStack `columnFilters` for every table.

---

## 6. Page port order (13 pages, by risk → value)

1. **Scaffolding + EST page** (POC) — proves stack end-to-end against the live `/api`, incl. the token table via TanStack. *(588 LOC)*
2. **Login + auth/Protected/layout** — unblocks every authed page (OIDC + internal). *(140 + infra)*
3. **Dashboard** *(494)* — read-only, exercises charts/cards/Query.
4. **Certificates** *(1106)* + **Certificate detail/issue** *(238)* — biggest table + a form.
5. **Approvals** *(657)*, **Users** *(1071)* — tables + role/permission flows.
6. **SCMS / Token Management** *(964)*.
7. **Audit** *(289)*, **CRL** *(160)*, **Profiles** *(151)*, **Settings** *(164)*, **404** *(23)*.

Each page = its own PR. The Yew app stays the deployed bundle until **all** pages reach parity (single-bundle SPA can't be half-served cleanly).

---

## 7. Build / CI / container changes

**Dockerfile stage 1** (only): replace `trunk build` with
```
npm ci && npm run build      # vite build → services/web-ui/web/dist
```
and copy `web/dist` → `/app/static` (stages 2–3 unchanged). Tailwind already builds via Node here, so the toolchain delta is small.

**CI:** replace `Web UI (wasm32)` with a `web-ui-frontend` job: `npm ci` → `tsc --noEmit` → `eslint` → `vite build`. Add `npm audit --audit-level=high` (advisory, mirrors `cargo audit`). Server still builds in `Build & test`.

**Deploy:** no manifest change. New `web-ui` image rolls out exactly as today (same Deployment, same `ca-ui` ingress, same `web-ui:sha-…` pin convention).

---

## 8. ATO / supply-chain impact (must review)

This is the real cost of the decision and the reason to do it deliberately.

- **New supply chain:** npm adds a large transitive tree (React/Vite/Radix/TanStack). Mitigations: committed `package-lock.json`, `npm ci` (locked) in CI + Docker, `npm audit` gate, Dependabot/Renovate for JS, and **SBOM** extended to npm (CycloneDX) alongside the Rust SBOM. (SI-7, SA-12, RA-5, CM-2.)
- **shadcn is copy-in**, not a runtime dependency — its component source lives in our repo (`components/ui/`), so it's reviewable and pinned, not a moving dependency.
- **SC-18 (Mobile Code):** CSP nonce posture preserved (§4.1); document the exact policy diff.
- **No new runtime/container:** still one Rust binary serving static assets — **no Node in the runtime image**, only at build time. Attack surface of the running pod is unchanged.
- **Provenance/SI-7:** keep building the image from source in CI (already do); add JS build provenance to the existing flow.

Net: the *running* system's security surface is ~unchanged; the **build-time** governance surface grows (npm). That's the trade to sign off on.

---

## 9. Phases & milestones

- **P0 — Plan sign-off** (this doc): confirm architecture, CSP approach (§4.1-A), ATO owner ack of §8.
- **P1 — Stack POC:** scaffold `web/`, shadcn init, Vite↔Axum static/CSP/config wiring, port **EST page**, build it through a branch image, verify on cluster behind a temporary route. *Exit:* EST page works end-to-end via the real proxy with CSP intact.
- **P2 — Auth + shell:** login (OIDC + internal), `Protected`, layout/sidebar, `userinfo` gating, TanStack Query base.
- **P3 — Pages:** port the remaining 11 pages (one PR each), Yew still deployed.
- **P4 — Cutover:** flip Dockerfile stage 1 + CI to the React build, delete `src/client/`, ship `web-ui` image, verify parity checklist, keep the previous `web-ui:sha-…` for instant rollback.

---

## 10. Risks & mitigations

| Risk | Mitigation |
|---|---|
| CSP nonce + Vite hashed assets break inline/module scripts | §4.1-A placeholder injection; test CSP report-only first |
| Auth/CSRF parity regressions | Reuse the **same** server endpoints; verify `userinfo`/login/logout + any CSRF header before cutover |
| Half-migrated SPA can't serve cleanly | Build `web/` alongside; cut over only at full parity; Yew stays live until then |
| npm supply-chain/ATO drift | Locked installs, `npm audit` gate, npm SBOM, Dependabot (§8) |
| Scope creep (UX redesign mid-port) | Parity first; UX improvements as follow-ups |
| Rollback | Image is a static-bundle swap; redeploy previous `web-ui:sha-…` |

---

## 11. Rough effort

- P1 (POC + infra): ~2–4 days (the CSP/config/auth wiring is the bulk).
- P2 (auth + shell): ~2–3 days.
- P3 (11 pages): ~1–3 days each depending on size (certificates/users/scms are the large ones), several with shared table/form patterns → faster after the first few.
- P4 (cutover): ~1 day + parity testing.

Indicative total: **~4–6 focused weeks** for full parity, front-loaded by P1/P2; pages parallelize across contributors.

---

## 12. Sign-off decisions
1. CSP: **§4.1-A nonce-injection preserved.** ✅ decided.
2. ATO owner: ack the npm supply-chain expansion (§8) + the build-time controls (locked installs, `audit` gate, npm SBOM, Dependabot). ⏳ pending ack — see §8 checklist.
3. CSRF on `/api`: **verified — none today (`SameSite=Lax` only); React inherits unchanged.** ✅ resolved (§4.3). Optional server-side defense-in-depth tracked separately.
4. Login: **keep the dev internal-login path** alongside OIDC in the React login. ✅ decided.
5. Package manager: **pnpm vs npm** — ⏳ pending pick (recommend pnpm: strict dep isolation + corepack already present).
