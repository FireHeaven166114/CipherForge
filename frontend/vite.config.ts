import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The browser always talks to the API on its own origin. In development the
// Vite server forwards those paths to the backend; in Docker, nginx does.
const backendTarget = process.env.VITE_DEV_PROXY_TARGET ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/health": backendTarget,
      "/ready": backendTarget,
      "/api": backendTarget,
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
    unstubGlobals: true,
  },
});
