import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { defineConfig } from "@playwright/test";

// Ports are different from the development servers (8000, 5173), so both can run side by side.
const API_PORT = 8100;
const WEB_PORT = 4180;

const frontendDir = import.meta.dirname;
const backendDir = resolve(frontendDir, "..", "backend");

function backendPython(): string {
  if (process.env.E2E_PYTHON) return process.env.E2E_PYTHON;
  for (const candidate of [
    resolve(backendDir, ".venv", "Scripts", "python.exe"),
    resolve(backendDir, ".venv", "bin", "python"),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return "python";
}

// Microsoft Edge is already on most Windows machines, so locally no browser needs downloading.
// CI installs Chromium instead (see .github/workflows/ci.yml) and leaves the channel unset.
const channel = process.env.E2E_CHANNEL ?? (process.env.CI ? undefined : "msedge");

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  // The specs share one seeded database, so they run one after another.
  workers: 1,
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    channel,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "dark",
    serviceWorkers: "block",
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      // The real application with simulated providers and a freshly seeded throwaway database.
      command: `"${backendPython()}" -m uvicorn devtools.demo_server:create_demo_app --factory --host 127.0.0.1 --port ${API_PORT}`,
      cwd: backendDir,
      url: `http://127.0.0.1:${API_PORT}/ready`,
      env: {
        PYTHONPATH: ".",
        PYTHONUNBUFFERED: "1",
        CIPHERFORGE_DEMO_DB: resolve(backendDir, ".demo", "e2e.db"),
        CIPHERFORGE_DEMO_RESET: "1",
      },
      reuseExistingServer: false,
      timeout: 180_000,
    },
    {
      // The production build behind the nginx security headers (run `npm run build` first).
      command: "node e2e/harness/serve-dist.ts",
      cwd: frontendDir,
      url: `http://127.0.0.1:${WEB_PORT}/nginx-health`,
      env: {
        E2E_WEB_PORT: String(WEB_PORT),
        E2E_API_URL: `http://127.0.0.1:${API_PORT}`,
      },
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
