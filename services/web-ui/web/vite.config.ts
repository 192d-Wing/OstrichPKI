import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The Rust Axum server serves these assets under STATIC_FILES_URL_PREFIX=/static
// and proxies /api + /auth to the backends. `base` must match that prefix so the
// built index.html references /static/assets/*. For local `pnpm dev`, the dev
// server proxies /api + /auth to a running web-ui server (default :8080).
export default defineConfig({
  base: "/static/",
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Stable, hashed asset names; the server injects the CSP nonce at serve time
    // into the emitted index.html (see docs/WEBUI_SHADCN_MIGRATION.md §4.1).
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the heavy Cloudscape vendor code from app code so it caches
        // independently of route chunks and our own source changes.
        // Function form (not the object map) — required by vite 8's rolldown
        // bundler, which rejects the Rollup object syntax.
        manualChunks(id) {
          if (id.includes("@cloudscape-design")) {
            return "cloudscape";
          }
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: false },
      "/auth": { target: "http://localhost:8080", changeOrigin: false },
    },
  },
});
