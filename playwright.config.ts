import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig } from "@playwright/test";

const PORT = 8790;
// One fresh database per run; workers inherit the env var so they open the same file.
process.env.PARLEY_E2E_DB ??= join(tmpdir(), `parley-e2e-${Date.now()}.sqlite`);
export const E2E_DB = process.env.PARLEY_E2E_DB;

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://localhost:${PORT}`,
    channel: process.env.PW_CHANNEL || undefined,
    trace: "retain-on-failure",
    // CI runners can't resolve the mDNS names Chromium uses to hide local IPs in ICE candidates.
    launchOptions: { args: ["--disable-features=WebRtcHideLocalIpsWithMdns"] },
  },
  webServer: {
    command: "node --disable-warning=ExperimentalWarning server/src/index.ts",
    url: `http://localhost:${PORT}/api/health`,
    reuseExistingServer: false,
    env: {
      PARLEY_PORT: String(PORT),
      PARLEY_DB: E2E_DB,
      PARLEY_STATIC_DIR: "web/dist",
      PARLEY_LOG_LEVEL: "warn",
    },
  },
});
