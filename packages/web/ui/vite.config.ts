import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwind from "@tailwindcss/vite";

/*
 * Paths here are relative to `root`, which the package script passes as
 * `--root ui`. They are deliberately not derived from `import.meta.url`: Vite
 * transpiles this config into a temporary module before running it, so
 * `import.meta.url` points at the temp file rather than at this one.
 */
export default defineConfig({
  plugins: [react(), tailwind()],
  build: { outDir: "../dist-ui", emptyOutDir: true, sourcemap: true },
  server: {
    port: 5273,
    strictPort: true,
    host: "127.0.0.1",
    // The backend serves /api; in dev the UI is served by Vite and proxies to it.
    proxy: { "/api": { target: "http://127.0.0.1:7777" } }
  }
});
