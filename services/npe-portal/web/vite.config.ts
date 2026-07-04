import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The Rust Axum server serves these assets under STATIC_FILES_URL_PREFIX=/static
// and proxies /api + /auth to the backends. `base` must match that prefix so the
// built index.html references /static/assets/*. For local `pnpm dev`, the dev
// server proxies /api + /auth to a running NPE portal server (default :8443).
export default defineConfig({
  base: "/static/",
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Function form (Vite 8 / Rolldown compatible): keep the large Cloudscape
        // vendor in its own chunk so the app bundle stays small.
        manualChunks(id) {
          if (id.includes("@cloudscape-design")) return "cloudscape";
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5174,
    proxy: {
      "/api": { target: "http://localhost:8443", changeOrigin: false },
      "/auth": { target: "http://localhost:8443", changeOrigin: false },
    },
  },
});
